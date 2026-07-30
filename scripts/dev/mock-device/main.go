// Mock ZKBio device for local agent testing.
//
// Talks the same /iclock/* protocol a real ZKTeco PUSH 2.4 device does, so
// you can exercise the agent end-to-end on your Mac without LAN access to
// a real device.
//
// The device keeps in-memory state — users, fingerprint slots, face templates
// and comparison photos — so repeated runs are reproducible and a server
// repoint can be shown not to clear what the scanner already holds. Every
// synthetic template is derived deterministically from (PIN, slot, type, seed),
// so the same invocation always produces the same bytes.
//
// What it does, in a loop:
//  1. GET /iclock/cdata?SN=...&options=all  (handshake)
//  2. GET /iclock/getrequest?SN=...         (poll for cmds)
//  3. When the agent serves a command, dispatch:
//     - ENROLL_BIO PIN= TYPE= NO=  → POST a synthetic BioData upload
//     AND a /iclock/devicecmd Return=0
//     - DATA UPDATE FINGERTMP / BIODATA / BIOPHOTO → store and ack
//     - DATA DELETE BIODATA / FINGERTMP / BIOPHOTO → forget and ack
//     - DATA QUERY USERINFO / others    → POST /iclock/querydata
//     - anything else                   → POST /iclock/devicecmd Return=0
//
// Fault injection, all off by default, for certification-style runs:
//
//	-lost-ack-every N   drop every Nth acknowledgement (the agent must retry)
//	-mutate-ciphertext  corrupt one byte of each stored template
//	-finger-algorithm   report a different finger algorithm than templates use
//	-replay-token       re-send the previous acknowledgement ID once
//
// Override defaults via env: AGENT_URL, DEVICE_SN, POLL_INTERVAL_MS,
// DEVICE_PROFILE, TEMPLATE_SEED.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type config struct {
	agentURL        string
	deviceSN        string
	pollInterval    time.Duration
	profile         string
	templateSeed    string
	fingerAlgorithm string
	lostAckEvery    int
	mutateCipher    bool
	replayToken     bool
}

func loadConfig() config {
	c := config{
		agentURL:        getenvDefault("AGENT_URL", "http://127.0.0.1:8081"),
		deviceSN:        getenvDefault("DEVICE_SN", "MOCK0000000001"),
		pollInterval:    1500 * time.Millisecond,
		profile:         getenvDefault("DEVICE_PROFILE", "ta_push"),
		templateSeed:    getenvDefault("TEMPLATE_SEED", "plasmatix-mock-device"),
		fingerAlgorithm: getenvDefault("FINGER_ALGORITHM_VERSION", "12.0"),
	}
	if v := os.Getenv("POLL_INTERVAL_MS"); v != "" {
		if ms, err := strconv.Atoi(v); err == nil && ms > 0 {
			c.pollInterval = time.Duration(ms) * time.Millisecond
		}
	}
	flag.StringVar(&c.agentURL, "agent", c.agentURL, "Agent base URL (e.g. http://127.0.0.1:8081)")
	flag.StringVar(&c.deviceSN, "sn", c.deviceSN, "Device serial number to impersonate")
	flag.DurationVar(&c.pollInterval, "poll", c.pollInterval, "Polling interval for /iclock/getrequest")
	flag.StringVar(&c.profile, "profile", c.profile, "Device profile: ta_push or ac_push_3")
	flag.StringVar(&c.templateSeed, "seed", c.templateSeed, "Deterministic template seed")
	flag.StringVar(&c.fingerAlgorithm, "finger-algorithm", c.fingerAlgorithm,
		"Finger algorithm version this device reports (use a different value to inject a mismatch)")
	flag.IntVar(&c.lostAckEvery, "lost-ack-every", 0,
		"Drop every Nth acknowledgement so the agent must reconcile (0 disables)")
	flag.BoolVar(&c.mutateCipher, "mutate-ciphertext", false,
		"Corrupt one byte of every stored template to simulate tampering")
	flag.BoolVar(&c.replayToken, "replay-token", false,
		"Re-send the previous acknowledgement once to simulate a replayed delivery")
	flag.Parse()
	return c
}

func getenvDefault(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// slotKey identifies one biometric record held by the device.
type slotKey struct {
	PIN  string
	Type int
	Slot int
}

// deviceState is what the scanner "remembers". A server repoint replaces the
// agent URL only — this state is deliberately never cleared.
type deviceState struct {
	mu        sync.Mutex
	users     map[string]struct{}
	records   map[slotKey][]byte
	acks      int
	lastAckID string
}

func newDeviceState() *deviceState {
	return &deviceState{
		users:   make(map[string]struct{}),
		records: make(map[slotKey][]byte),
	}
}

func (s *deviceState) put(key slotKey, value []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[key.PIN] = struct{}{}
	s.records[key] = append([]byte(nil), value...)
}

func (s *deviceState) delete(pin string, bioType int, slot int, allSlots bool) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for key := range s.records {
		if key.PIN != pin || key.Type != bioType {
			continue
		}
		if !allSlots && key.Slot != slot {
			continue
		}
		delete(s.records, key)
		removed++
	}
	return removed
}

func (s *deviceState) summary() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.records) == 0 {
		return "no biometric records"
	}
	parts := make([]string, 0, len(s.records))
	for key, value := range s.records {
		parts = append(parts, fmt.Sprintf("pin=%s type=%d slot=%d bytes=%d",
			key.PIN, key.Type, key.Slot, len(value)))
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

// nextAck reports whether this acknowledgement should be delivered, and the ID
// to send. A dropped ack models a lost scanner response; a replayed token
// models the device re-sending an acknowledgement the agent already saw.
func (s *deviceState) nextAck(cfg config, id string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.acks++
	if cfg.lostAckEvery > 0 && s.acks%cfg.lostAckEvery == 0 {
		return "", false
	}
	if cfg.replayToken && s.lastAckID != "" && s.acks == 2 {
		replayed := s.lastAckID
		return replayed, true
	}
	s.lastAckID = id
	return id, true
}

type device struct {
	cfg    config
	client *http.Client
	state  *deviceState
}

func main() {
	cfg := loadConfig()
	d := &device{
		cfg:    cfg,
		client: &http.Client{Timeout: 10 * time.Second},
		state:  newDeviceState(),
	}

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Printf("mock-device starting: agent=%s sn=%s profile=%s poll=%s seed=%q",
		cfg.agentURL, cfg.deviceSN, cfg.profile, cfg.pollInterval, cfg.templateSeed)
	if cfg.lostAckEvery > 0 || cfg.mutateCipher || cfg.replayToken {
		log.Printf("fault injection: lost-ack-every=%d mutate-ciphertext=%v replay-token=%v",
			cfg.lostAckEvery, cfg.mutateCipher, cfg.replayToken)
	}

	if err := d.handshake(); err != nil {
		log.Fatalf("handshake failed: %v", err)
	}

	for {
		cmd, err := d.poll()
		if err != nil {
			log.Printf("poll error: %v", err)
			time.Sleep(d.cfg.pollInterval * 2)
			continue
		}
		if cmd != nil {
			d.dispatch(cmd)
		}
		time.Sleep(d.cfg.pollInterval)
	}
}

type adminCmd struct {
	id   string
	body string
}

func (d *device) handshake() error {
	if d.cfg.profile == "ac_push_3" {
		q := url.Values{"SN": {d.cfg.deviceSN}}
		res, err := d.client.Get(d.cfg.agentURL + "/iclock/registry?" + q.Encode())
		if err != nil {
			return err
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		log.Printf("← /iclock/registry GET status=%d body=%q", res.StatusCode, truncate(string(body), 200))
		return nil
	}
	q := url.Values{
		"SN":                     {d.cfg.deviceSN},
		"options":                {"all"},
		"pushver":                {"2.4.1"},
		"language":               {"4"},
		"FingerFunOn":            {"1"},
		"BiodataFun":             {"1"},
		"FaceFunOn":              {"1"},
		"BioPhotoFun":            {"1"},
		"FingerAlgorithmVersion": {d.cfg.fingerAlgorithm},
	}
	res, err := d.client.Get(d.cfg.agentURL + "/iclock/cdata?" + q.Encode())
	if err != nil {
		return err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	log.Printf("← /iclock/cdata GET (handshake) status=%d body=%q", res.StatusCode, truncate(string(body), 200))
	return nil
}

func (d *device) poll() (*adminCmd, error) {
	q := url.Values{"SN": {d.cfg.deviceSN}}
	res, err := d.client.Get(d.cfg.agentURL + "/iclock/getrequest?" + q.Encode())
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	body := strings.TrimSpace(string(raw))
	if body == "" || body == "OK" {
		return nil, nil
	}
	if !strings.HasPrefix(body, "C:") {
		log.Printf("← /iclock/getrequest unexpected body: %q", truncate(body, 200))
		return nil, nil
	}
	rest := strings.TrimPrefix(body, "C:")
	colon := strings.IndexByte(rest, ':')
	if colon < 0 {
		log.Printf("← /iclock/getrequest malformed cmd: %q", truncate(body, 200))
		return nil, nil
	}
	id := rest[:colon]
	cmd := rest[colon+1:]
	// Never log a served vault command verbatim — it carries template bytes.
	log.Printf("← /iclock/getrequest cmd id=%s head=%q", id, truncate(firstWord(cmd), 40))
	return &adminCmd{id: id, body: cmd}, nil
}

func (d *device) dispatch(c *adminCmd) {
	switch {
	case strings.HasPrefix(c.body, "ENROLL_FP"):
		d.handleEnrollFP(c)
	case strings.HasPrefix(c.body, "ENROLL_BIO"):
		d.handleEnrollBio(c)
	case strings.HasPrefix(c.body, "DATA UPDATE FINGERTMP"),
		strings.HasPrefix(c.body, "DATA FP"),
		strings.HasPrefix(c.body, "DATA UPDATE BIODATA"),
		strings.HasPrefix(c.body, "DATA UPDATE BIOPHOTO"),
		strings.HasPrefix(c.body, "DATA UPDATE FACE"):
		d.handleWrite(c)
	case strings.HasPrefix(c.body, "DATA DELETE"):
		d.handleDelete(c)
	case strings.HasPrefix(c.body, "DATA QUERY"):
		d.handleDataQuery(c)
	default:
		d.ackCmd(c, 0, c.body)
		log.Printf("→ ack generic id=%s Return=0", c.id)
	}
}

// handleWrite commits a pushed record into device state. The payload is
// deliberately never logged.
func (d *device) handleWrite(c *adminCmd) {
	fields := parseRecordFields(c.body)
	pin := fields["PIN"]
	if pin == "" {
		pin = fields["Pin"]
	}
	bioType := intOrDefault(firstNonEmpty(fields["TYPE"], fields["Type"]), 1)
	slot := intOrDefault(firstNonEmpty(fields["FID"], fields["NO"], fields["No"]), 0)
	encoded := firstNonEmpty(fields["TMP"], fields["Tmp"], fields["PHOTO"], fields["Photo"])
	if pin == "" || encoded == "" {
		log.Printf("write missing PIN or payload — refusing id=%s", c.id)
		d.ackCmd(c, -1, c.body)
		return
	}
	if strings.Contains(c.body, "BIOPHOTO") {
		bioType = 9
	}
	payload, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		log.Printf("write payload is not valid base64 — refusing id=%s", c.id)
		d.ackCmd(c, -1, c.body)
		return
	}
	if d.cfg.mutateCipher && len(payload) > 0 {
		payload[0] ^= 0xFF
	}
	key := slotKey{PIN: pin, Type: bioType, Slot: slot}
	d.state.put(key, payload)
	log.Printf("→ stored pin=%s type=%d slot=%d bytes=%d (state: %s)",
		pin, bioType, slot, len(payload), d.state.summary())
	d.ackCmd(c, 0, c.body)
}

func (d *device) handleDelete(c *adminCmd) {
	fields := parseRecordFields(c.body)
	pin := firstNonEmpty(fields["PIN"], fields["Pin"])
	bioType := intOrDefault(firstNonEmpty(fields["TYPE"], fields["Type"]), 1)
	if strings.Contains(c.body, "BIOPHOTO") {
		bioType = 9
	}
	slotText := firstNonEmpty(fields["FID"], fields["NO"], fields["No"])
	slot := intOrDefault(slotText, 0)
	removed := d.state.delete(pin, bioType, slot, slotText == "")
	log.Printf("→ deleted pin=%s type=%d slot=%q records=%d (state: %s)",
		pin, bioType, slotText, removed, d.state.summary())
	d.ackCmd(c, 0, c.body)
}

func (d *device) handleEnrollFP(c *adminCmd) {
	rest := strings.TrimSpace(strings.TrimPrefix(c.body, "ENROLL_FP"))
	pin, fid, _ := parseSpaceKVs(rest, "PIN", "FID")
	if pin == "" || fid == "" {
		log.Printf("ENROLL_FP missing PIN/FID in %q — skipping", firstWord(c.body))
		d.ackCmd(c, -1, c.body)
		return
	}
	slot := intOrDefault(fid, 0)
	raw := d.template(pin, 1, slot, 1024)
	d.state.put(slotKey{PIN: pin, Type: 1, Slot: slot}, raw)
	tmp := base64.StdEncoding.EncodeToString(raw)
	record := fmt.Sprintf(
		"PIN=%s\tFID=%s\tSize=%d\tValid=1\tTMP=%s",
		pin,
		fid,
		len(raw),
		tmp,
	)
	postURL := fmt.Sprintf(
		"%s/iclock/cdata?SN=%s&table=FINGERTMP",
		d.cfg.agentURL,
		url.QueryEscape(d.cfg.deviceSN),
	)
	if _, err := d.postPlain(postURL, record); err != nil {
		log.Printf("FINGERTMP upload failed: %v", err)
	} else {
		log.Printf("→ /iclock/cdata?table=FINGERTMP PIN=%s FID=%s bytes=%d", pin, fid, len(raw))
	}
	d.ackCmd(c, 0, c.body)
}

// ENROLL_BIO PIN=14<SP>TYPE=1<SP>NO=3 → real device captures finger via UI,
// uploads a synthetic BioData record, then acks the command. We mimic both
// halves so the agent's reflection path runs.
func (d *device) handleEnrollBio(c *adminCmd) {
	rest := strings.TrimSpace(strings.TrimPrefix(c.body, "ENROLL_BIO"))
	pin, no, typ := parseSpaceKVs(rest, "PIN", "NO", "TYPE")
	if pin == "" || typ == "" {
		log.Printf("ENROLL_BIO missing PIN/TYPE in %q — skipping", firstWord(c.body))
		d.ackCmd(c, -1, c.body)
		return
	}
	if no == "" {
		no = "0"
	}
	bioType := intOrDefault(typ, 1)
	slot := intOrDefault(no, 0)

	raw := d.template(pin, bioType, slot, 1024)
	d.state.put(slotKey{PIN: pin, Type: bioType, Slot: slot}, raw)
	tmp := base64.StdEncoding.EncodeToString(raw)

	major, minor := splitAlgorithmVersion(d.cfg.fingerAlgorithm)
	bioRecord := fmt.Sprintf(
		"PIN=%s\tNO=%s\tTYPE=%s\tMajorVer=%d\tMinorVer=%d\tTMP=%s",
		pin, no, typ, major, minor, tmp,
	)

	// 1. POST /iclock/cdata?type=BioData with the synthetic record.
	postURL := fmt.Sprintf("%s/iclock/cdata?SN=%s&type=BioData",
		d.cfg.agentURL, url.QueryEscape(d.cfg.deviceSN))
	if _, err := d.postPlain(postURL, bioRecord); err != nil {
		log.Printf("BioData upload failed: %v", err)
	} else {
		log.Printf("→ /iclock/cdata?type=BioData PIN=%s NO=%s TYPE=%s bytes=%d", pin, no, typ, len(raw))
	}

	// 2. POST /iclock/devicecmd to ack the ENROLL_BIO command itself.
	d.ackCmd(c, 0, c.body)
	log.Printf("→ ack ENROLL_BIO id=%s Return=0", c.id)
}

// DATA QUERY USERINFO PIN=14 → post a synthetic user record back via
// /iclock/querydata. The agent forwards this to the cloud as the cmd
// result on the final pack.
func (d *device) handleDataQuery(c *adminCmd) {
	pin := ""
	if rest := strings.SplitN(c.body, "PIN=", 2); len(rest) == 2 {
		pin = strings.TrimSpace(strings.SplitN(rest[1], " ", 2)[0])
	}
	if pin == "" {
		pin = "0"
	}
	row := fmt.Sprintf("user uid=1\tcardno=\tpin=%s\tpassword=\tname=mock-user\tprivilege=0\tdisable=0\tverify=0", pin)

	postURL := fmt.Sprintf("%s/iclock/querydata?SN=%s&type=tabledata&cmdid=%s&tablename=user&count=1&packcnt=1&packidx=1",
		d.cfg.agentURL, url.QueryEscape(d.cfg.deviceSN), url.QueryEscape(c.id))
	if _, err := d.postPlain(postURL, row); err != nil {
		log.Printf("querydata POST failed: %v", err)
		return
	}
	log.Printf("→ /iclock/querydata cmdid=%s tablename=user pin=%s", c.id, pin)
}

func (d *device) ackCmd(c *adminCmd, returnCode int, cmdEcho string) {
	id, deliver := d.state.nextAck(d.cfg, c.id)
	if !deliver {
		log.Printf("✗ dropping ack for id=%s (lost-ack injection)", c.id)
		return
	}
	if id != c.id {
		log.Printf("↺ replaying earlier ack id=%s instead of id=%s", id, c.id)
	}
	form := url.Values{
		"ID":     {id},
		"Return": {strconv.Itoa(returnCode)},
		"CMD":    {firstWord(cmdEcho)},
	}
	postURL := fmt.Sprintf("%s/iclock/devicecmd?SN=%s",
		d.cfg.agentURL, url.QueryEscape(d.cfg.deviceSN))
	_, err := d.postPlain(postURL, form.Encode())
	if err != nil {
		log.Printf("devicecmd ack failed: %v", err)
	}
}

// template derives a stable synthetic template so two runs with the same seed
// produce byte-identical uploads.
func (d *device) template(pin string, bioType, slot, size int) []byte {
	out := make([]byte, 0, size)
	counter := 0
	for len(out) < size {
		sum := sha256.Sum256(fmt.Appendf(
			nil, "%s|%s|%d|%d|%d", d.cfg.templateSeed, pin, bioType, slot, counter,
		))
		out = append(out, sum[:]...)
		counter++
	}
	return out[:size]
}

func (d *device) postPlain(u, body string) (string, error) {
	req, err := http.NewRequest(http.MethodPost, u, bytes.NewBufferString(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/push;charset=UTF-8")
	req.Header.Set("User-Agent", "iClock Proxy/1.09 (mock-device)")
	res, err := d.client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d: %s", res.StatusCode, strings.TrimSpace(string(raw)))
	}
	return string(raw), nil
}

func firstWord(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i]
	}
	return s
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func intOrDefault(value string, fallback int) int {
	number, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return fallback
	}
	return number
}

func splitAlgorithmVersion(value string) (int, int) {
	major, minor, ok := strings.Cut(strings.TrimSpace(value), ".")
	if !ok {
		return 12, 0
	}
	return intOrDefault(major, 12), intOrDefault(minor, 0)
}

// parseRecordFields reads tab or space separated Key=Value pairs, preserving
// the original key casing so both PUSH dialects resolve.
func parseRecordFields(s string) map[string]string {
	fields := make(map[string]string)
	for _, part := range strings.FieldsFunc(s, func(r rune) bool {
		return r == '\t' || r == '\n'
	}) {
		for token := range strings.SplitSeq(part, " ") {
			key, value, ok := strings.Cut(token, "=")
			if !ok {
				continue
			}
			fields[strings.TrimSpace(key)] = value
		}
	}
	return fields
}

func parseSpaceKVs(s string, keys ...string) (string, string, string) {
	got := map[string]string{}
	for _, part := range strings.Fields(s) {
		eq := strings.IndexByte(part, '=')
		if eq < 0 {
			continue
		}
		got[strings.ToUpper(part[:eq])] = part[eq+1:]
	}
	out := make([]string, 3)
	for i, k := range keys {
		if i >= 3 {
			break
		}
		out[i] = got[strings.ToUpper(k)]
	}
	return out[0], out[1], out[2]
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
