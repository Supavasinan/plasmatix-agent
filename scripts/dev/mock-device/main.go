// Mock ZKBio device for local agent testing.
//
// Talks the same /iclock/* protocol a real ZKTeco PUSH 2.4 device does, so
// you can exercise the agent end-to-end on your Mac without LAN access to
// a real device.
//
// What it does, in a loop:
//   1. GET /iclock/cdata?SN=...&options=all  (handshake)
//   2. GET /iclock/getrequest?SN=...         (poll for cmds)
//   3. When the agent serves a command, dispatch:
//        - ENROLL_BIO PIN= TYPE= NO=  → POST a synthetic BioData upload
//          AND a /iclock/devicecmd Return=0
//        - DATA UPDATE FINGERTMP / BIODATA → POST /iclock/devicecmd Return=0
//        - DATA QUERY USERINFO / others    → POST /iclock/querydata
//        - anything else                   → POST /iclock/devicecmd Return=0
//
// Override defaults via env: AGENT_URL, DEVICE_SN, POLL_INTERVAL_MS.
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type config struct {
	agentURL     string
	deviceSN     string
	pollInterval time.Duration
}

func loadConfig() config {
	c := config{
		agentURL:     getenvDefault("AGENT_URL", "http://127.0.0.1:8081"),
		deviceSN:     getenvDefault("DEVICE_SN", "MOCK0000000001"),
		pollInterval: 1500 * time.Millisecond,
	}
	if v := os.Getenv("POLL_INTERVAL_MS"); v != "" {
		if ms, err := strconv.Atoi(v); err == nil && ms > 0 {
			c.pollInterval = time.Duration(ms) * time.Millisecond
		}
	}
	flag.StringVar(&c.agentURL, "agent", c.agentURL, "Agent base URL (e.g. http://127.0.0.1:8081)")
	flag.StringVar(&c.deviceSN, "sn", c.deviceSN, "Device serial number to impersonate")
	flag.DurationVar(&c.pollInterval, "poll", c.pollInterval, "Polling interval for /iclock/getrequest")
	flag.Parse()
	return c
}

func getenvDefault(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

type device struct {
	cfg    config
	client *http.Client
}

func main() {
	cfg := loadConfig()
	d := &device{
		cfg:    cfg,
		client: &http.Client{Timeout: 10 * time.Second},
	}

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Printf("mock-device starting: agent=%s sn=%s poll=%s",
		cfg.agentURL, cfg.deviceSN, cfg.pollInterval)

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
	q := url.Values{
		"SN":       {d.cfg.deviceSN},
		"options":  {"all"},
		"pushver":  {"2.4.1"},
		"language": {"4"},
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
	log.Printf("← /iclock/getrequest cmd id=%s body=%q", id, truncate(cmd, 200))
	return &adminCmd{id: id, body: cmd}, nil
}

func (d *device) dispatch(c *adminCmd) {
	switch {
	case strings.HasPrefix(c.body, "ENROLL_BIO"):
		d.handleEnrollBio(c)
	case strings.HasPrefix(c.body, "DATA UPDATE FINGERTMP"),
		strings.HasPrefix(c.body, "DATA UPDATE BIODATA"),
		strings.HasPrefix(c.body, "DATA UPDATE FACE"):
		d.ackCmd(c, 0, c.body)
		log.Printf("→ ack DATA UPDATE id=%s Return=0 (mock matcher commits)", c.id)
	case strings.HasPrefix(c.body, "DATA QUERY"):
		d.handleDataQuery(c)
	default:
		d.ackCmd(c, 0, c.body)
		log.Printf("→ ack generic id=%s Return=0", c.id)
	}
}

// ENROLL_BIO PIN=14<SP>TYPE=1<SP>NO=3 → real device captures finger via UI,
// uploads a synthetic BioData record, then acks the command. We mimic both
// halves so the agent's reflection path runs.
func (d *device) handleEnrollBio(c *adminCmd) {
	rest := strings.TrimSpace(strings.TrimPrefix(c.body, "ENROLL_BIO"))
	pin, no, typ := parseSpaceKVs(rest, "PIN", "NO", "TYPE")
	if pin == "" || typ == "" {
		log.Printf("ENROLL_BIO missing PIN/TYPE in %q — skipping", c.body)
		d.ackCmd(c, -1, c.body)
		return
	}
	if no == "" {
		no = "0"
	}

	// Synthetic 1024-byte template, base64'd. Format/keys match what real
	// SenseFace 2A devices emit (uppercase keys, no version metadata).
	tmp := randomBase64(1024)
	bioRecord := fmt.Sprintf("PIN=%s\tNO=%s\tTYPE=%s\tTMP=%s", pin, no, typ, tmp)

	// 1. POST /iclock/cdata?type=BioData with the synthetic record.
	postURL := fmt.Sprintf("%s/iclock/cdata?SN=%s&type=BioData",
		d.cfg.agentURL, url.QueryEscape(d.cfg.deviceSN))
	if _, err := d.postPlain(postURL, bioRecord); err != nil {
		log.Printf("BioData upload failed: %v", err)
	} else {
		log.Printf("→ /iclock/cdata?type=BioData PIN=%s NO=%s TYPE=%s tmpLen=%d", pin, no, typ, len(tmp))
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
	form := url.Values{
		"ID":     {c.id},
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

func randomBase64(byteLen int) string {
	buf := make([]byte, byteLen)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failure is fatal in practice; fall back to zeros so
		// the test loop keeps running.
		for i := range buf {
			buf[i] = 0
		}
	}
	return base64.StdEncoding.EncodeToString(buf)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
