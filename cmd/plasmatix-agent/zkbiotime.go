package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	zk "github.com/Supavasinan/zkbiotime-go"
)

const zkbioTimeLayout = "2006-01-02 15:04:05"

var zkbioTimeLocation = time.FixedZone("Asia/Bangkok", 7*60*60)

// ZKBioTimeClient talks to a ZKBioTime / BioTime 8 server via the zkbiotime-go
// SDK. It is used when the agent runs in mode "zkbiotime". Credentials arrive in
// the generic zkbio_url/username/password config keys.
//
// The SDK uses HTTP Basic auth: BioTime's IsNotOpenAPI permission rejects
// token/JWT ("Open API") requests on /iclock/ and /personnel/ unless the API
// module is licensed (enable_api), which trial licenses lack. Basic auth leaves
// request.auth=None server-side, bypassing that gate, and also works on full
// licenses.
type ZKBioTimeClient struct {
	sdk *zk.Client
}

func newZKBioTimeClient(cfg Config) *ZKBioTimeClient {
	return newZKBioTimeClientWith(cfg.ZKBioURL, cfg.ZKBioUsername, cfg.ZKBioPassword, &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			// ZKBioTime on the LAN often uses a self-signed / internal cert.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	})
}

func newZKBioTimeClientWith(baseURL, username, password string, hc *http.Client) *ZKBioTimeClient {
	client, err := zk.New(zk.Options{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		Username:   username,
		Password:   password,
		HTTPClient: hc,
	})
	if err != nil {
		// zk.New only fails on empty BaseURL/Username; config validation guarantees
		// both in zkbiotime mode, so this is effectively unreachable.
		log.Printf("[zkbiotime] client init: %v", err)
	}
	return &ZKBioTimeClient{sdk: client}
}

// do delegates to the SDK's Raw escape hatch: an authenticated request returning
// the status code and the undecoded body (a non-2xx status is not an error).
func (c *ZKBioTimeClient) do(ctx context.Context, method, path string, query url.Values, payload any) (int, []byte, error) {
	return c.sdk.Raw(ctx, method, path, query, payload)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func atoiPtr(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, false
	}
	return n, true
}

// ── Employees ──────────────────────────────────────────────────────────────

// findEmployeeID returns the ZKBioTime employee id for an emp_code, if present.
func (c *ZKBioTimeClient) findEmployeeID(ctx context.Context, empCode string) (int, bool, error) {
	page, err := c.sdk.Employees.List(ctx, url.Values{"emp_code": {empCode}})
	if err != nil {
		return 0, false, err
	}
	for _, e := range page.Data {
		if e.EmpCode == empCode {
			return e.ID, true, nil
		}
	}
	if len(page.Data) > 0 {
		return page.Data[0].ID, true, nil
	}
	return 0, false, nil
}

// employeeBody builds the ZKBioTime employee payload from a flat string row.
func employeeBody(row map[string]string) map[string]any {
	b := map[string]any{
		"emp_code":   row["emp_code"],
		"first_name": row["first_name"],
		"last_name":  row["last_name"],
	}
	if dept, ok := atoiPtr(row["department"]); ok {
		b["department"] = dept
	}
	if area, ok := atoiPtr(row["area"]); ok {
		b["area"] = []int{area}
	}
	if pos, ok := atoiPtr(row["position"]); ok {
		b["position"] = pos
	}
	for _, k := range []string{"gender", "birthday", "email", "mobile", "hire_date"} {
		if v := row[k]; v != "" {
			b[k] = v
		}
	}
	return b
}

// upsertEmployee creates or updates an employee by emp_code. Returns true if
// it was newly created.
func (c *ZKBioTimeClient) upsertEmployee(ctx context.Context, row map[string]string) (created bool, err error) {
	empCode := row["emp_code"]
	id, found, err := c.findEmployeeID(ctx, empCode)
	if err != nil {
		return false, err
	}
	body := employeeBody(row)
	if found {
		code, resp, err := c.do(ctx, http.MethodPut,
			fmt.Sprintf("/personnel/api/employees/%d/", id), nil, body)
		if err != nil {
			return false, err
		}
		if code < 200 || code >= 300 {
			return false, fmt.Errorf("update (HTTP %d): %s", code, truncate(string(resp), 200))
		}
		return false, nil
	}
	code, resp, err := c.do(ctx, http.MethodPost, "/personnel/api/employees/", nil, body)
	if err != nil {
		return false, err
	}
	if code < 200 || code >= 300 {
		return false, fmt.Errorf("create (HTTP %d): %s", code, truncate(string(resp), 200))
	}
	return true, nil
}

// resign marks an employee as resigned in ZKBioTime. It returns ok=true only
// when an employee was found and actually resigned. An employee that doesn't
// exist in ZKBioTime (never pushed) is already in the desired absent state, so
// it's an idempotent no-op (ok=false, err=nil) rather than an error.
func (c *ZKBioTimeClient) resign(ctx context.Context, empCode, date, reason string) (bool, error) {
	id, found, err := c.findEmployeeID(ctx, empCode)
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	body := map[string]any{
		"employee":    id,
		"resign_date": date,
		"resign_type": 1, // 1 = resignation
		"reason":      reason,
	}
	code, resp, err := c.do(ctx, http.MethodPost, "/personnel/api/resigns/", nil, body)
	if err != nil {
		return false, err
	}
	if code < 200 || code >= 300 {
		return false, fmt.Errorf("resign (HTTP %d): %s", code, truncate(string(resp), 200))
	}
	return true, nil
}

// reinstate reverses a resignation (best-effort; a non-resigned employee is a
// no-op error that the caller ignores).
func (c *ZKBioTimeClient) reinstate(ctx context.Context, empCode string) error {
	id, found, err := c.findEmployeeID(ctx, empCode)
	if err != nil || !found {
		return err
	}
	body := map[string]any{"employees": []int{id}}
	code, resp, err := c.do(ctx, http.MethodPost, "/personnel/api/resigns/reinstatement/", nil, body)
	if err != nil {
		return err
	}
	if code < 200 || code >= 300 {
		return fmt.Errorf("reinstate (HTTP %d): %s", code, truncate(string(resp), 160))
	}
	return nil
}

// resyncToDevice pushes employees down to their area's scanners.
func (c *ZKBioTimeClient) resyncToDevice(ctx context.Context, empCodes []string) error {
	body := map[string]any{"emp_code": empCodes}
	code, resp, err := c.do(ctx, http.MethodPost, "/personnel/api/employees/resync_to_device/", nil, body)
	if err != nil {
		return err
	}
	if code < 200 || code >= 300 {
		return fmt.Errorf("resync_to_device (HTTP %d): %s", code, truncate(string(resp), 200))
	}
	return nil
}

// ── Reads ──────────────────────────────────────────────────────────────────

type idName struct {
	ID   any    `json:"id"`
	Name string `json:"name"`
}

func (c *ZKBioTimeClient) fetchPersonnelLists(ctx context.Context) (map[string]any, error) {
	depts, err := c.sdk.Departments.ListAll(ctx, nil)
	if err != nil {
		return nil, err
	}
	areas, err := c.sdk.Areas.ListAll(ctx, nil)
	if err != nil {
		return nil, err
	}
	positions, err := c.sdk.Positions.ListAll(ctx, nil)
	if err != nil {
		return nil, err
	}
	di := make([]idName, len(depts))
	for i, d := range depts {
		di[i] = idName{ID: d.ID, Name: d.DeptName}
	}
	ai := make([]idName, len(areas))
	for i, a := range areas {
		ai[i] = idName{ID: a.ID, Name: a.AreaName}
	}
	pi := make([]idName, len(positions))
	for i, p := range positions {
		pi[i] = idName{ID: p.ID, Name: p.PositionName}
	}
	return map[string]any{"departments": di, "areas": ai, "positions": pi}, nil
}

func (c *ZKBioTimeClient) fetchTerminals(ctx context.Context) (map[string]any, error) {
	terms, err := c.sdk.Terminals.ListAll(ctx, nil)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, len(terms))
	for i, t := range terms {
		areaName := t.AreaName
		if areaName == "" && t.Area.Object != nil {
			if n, ok := t.Area.Object["area_name"].(string); ok {
				areaName = n
			}
		}
		out[i] = map[string]any{
			"id":            t.ID,
			"sn":            t.SN,
			"alias":         t.Alias,
			"ip_address":    t.IPAddress,
			"area_name":     areaName,
			"last_activity": t.LastActivity,
		}
	}
	return map[string]any{"terminals": out}, nil
}

func (c *ZKBioTimeClient) fetchAttReport(ctx context.Context, start, end string) (map[string]any, error) {
	q := url.Values{"page_size": {"1000"}}
	if start != "" {
		q.Set("start_date", start)
	}
	if end != "" {
		q.Set("end_date", end)
	}
	rep, err := c.sdk.Reports.Get(ctx, "transactionReport", q)
	if err != nil {
		return nil, err
	}
	return map[string]any{"count": rep.Count, "data": rep.Data}, nil
}

// fetchTransactions pulls raw punches in a time window (paginated).
func (c *ZKBioTimeClient) fetchTransactions(ctx context.Context, start, end string) ([]map[string]any, error) {
	all := make([]map[string]any, 0)
	page := 1
	previousNext := ""
	const maxPages = 200
	for {
		q := url.Values{
			"start_time": {start},
			"end_time":   {end},
			"page":       {strconv.Itoa(page)},
			"page_size":  {"500"},
		}
		code, body, err := c.do(ctx, http.MethodGet, "/iclock/api/transactions/", q, nil)
		if err != nil {
			return nil, err
		}
		if code != http.StatusOK {
			return nil, fmt.Errorf("GET transactions (HTTP %d): %s", code, truncate(string(body), 160))
		}
		var envelope struct {
			Next string          `json:"next"`
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(body, &envelope); err != nil {
			return nil, err
		}
		if len(envelope.Data) == 0 || bytes.Equal(bytes.TrimSpace(envelope.Data), []byte("null")) {
			return nil, fmt.Errorf("GET transactions page %d has missing or null data", page)
		}
		var pageData []map[string]any
		if err := json.Unmarshal(envelope.Data, &pageData); err != nil {
			return nil, fmt.Errorf("decode transactions page %d data: %w", page, err)
		}
		if envelope.Next != "" && len(pageData) == 0 {
			return nil, fmt.Errorf("GET transactions page %d is empty while pagination continues", page)
		}
		if envelope.Next != "" && envelope.Next == previousNext {
			return nil, fmt.Errorf("GET transactions pagination stalled at page %d", page)
		}
		all = append(all, pageData...)
		if envelope.Next == "" {
			break
		}
		if page >= maxPages {
			return nil, fmt.Errorf("GET transactions exceeded %d pages; refusing to acknowledge a partial backlog", maxPages)
		}
		previousNext = envelope.Next
		page++
	}
	return all, nil
}

// ── Command handlers ─────────────────────────────────────────────────────────

func (a *Agent) zkClient() (*ZKBioTimeClient, error) {
	if a.zkbiotime == nil {
		return nil, fmt.Errorf("zkbiotime client unavailable: agent is not in zkbiotime mode")
	}
	return a.zkbiotime, nil
}

func (a *Agent) cmdSyncEmployees(ctx context.Context, params map[string]string) (any, error) {
	c, err := a.zkClient()
	if err != nil {
		return nil, err
	}
	var employees []map[string]string
	if s := params["employees"]; s != "" {
		if err := json.Unmarshal([]byte(s), &employees); err != nil {
			return nil, fmt.Errorf("parse employees: %w", err)
		}
	}
	var resignations []struct {
		EmpCode    string `json:"emp_code"`
		ResignDate string `json:"resign_date"`
		Reason     string `json:"reason"`
	}
	if s := params["resignations"]; s != "" {
		if err := json.Unmarshal([]byte(s), &resignations); err != nil {
			return nil, fmt.Errorf("parse resignations: %w", err)
		}
	}

	pushed, updated, resigned := 0, 0, 0
	errs := []map[string]string{}

	for _, row := range employees {
		created, err := c.upsertEmployee(ctx, row)
		if err != nil {
			errs = append(errs, map[string]string{"emp_code": row["emp_code"], "message": err.Error()})
			continue
		}
		// Ensure active employees are not in a resigned state (best-effort).
		_ = c.reinstate(ctx, row["emp_code"])
		if created {
			pushed++
		} else {
			updated++
		}
	}

	for _, r := range resignations {
		ok, err := c.resign(ctx, r.EmpCode, r.ResignDate, r.Reason)
		if err != nil {
			errs = append(errs, map[string]string{"emp_code": r.EmpCode, "message": err.Error()})
			continue
		}
		if ok {
			resigned++
		}
	}

	return map[string]any{
		"pushed":   pushed,
		"updated":  updated,
		"resigned": resigned,
		"failed":   len(errs),
		"errors":   errs,
	}, nil
}

func (a *Agent) cmdResyncToDevice(ctx context.Context, params map[string]string) (any, error) {
	c, err := a.zkClient()
	if err != nil {
		return nil, err
	}
	var empCodes []string
	if s := params["emp_codes"]; s != "" {
		if err := json.Unmarshal([]byte(s), &empCodes); err != nil {
			return nil, fmt.Errorf("parse emp_codes: %w", err)
		}
	}
	if len(empCodes) == 0 {
		return map[string]any{"resynced": 0, "failed": 0, "errors": []any{}}, nil
	}
	if err := c.resyncToDevice(ctx, empCodes); err != nil {
		return map[string]any{
			"resynced": 0,
			"failed":   len(empCodes),
			"errors":   []map[string]string{{"emp_code": "*", "message": err.Error()}},
		}, nil
	}
	return map[string]any{"resynced": len(empCodes), "failed": 0, "errors": []any{}}, nil
}

// ── Generic API passthrough (dev console) ────────────────────────────────────

// cmdZkbiotimeRequest issues an arbitrary method/path/query/body against the
// ZKBioTime server and returns {status, body}. It is confined to the configured
// base URL (path must be relative, starting with "/"), so it can only reach the
// org's own ZKBioTime. Drives the superadmin "Dev / API explorer" page.
func (a *Agent) cmdZkbiotimeRequest(ctx context.Context, params map[string]string) (any, error) {
	c, err := a.zkClient()
	if err != nil {
		return nil, err
	}
	method := strings.ToUpper(strings.TrimSpace(params["method"]))
	if method == "" {
		method = http.MethodGet
	}
	path := strings.TrimSpace(params["path"])
	if !strings.HasPrefix(path, "/") {
		return nil, fmt.Errorf("path must start with '/'")
	}
	q := url.Values{}
	if s := strings.TrimSpace(params["query"]); s != "" {
		var qm map[string]string
		if err := json.Unmarshal([]byte(s), &qm); err != nil {
			return nil, fmt.Errorf("query must be a JSON object of strings: %w", err)
		}
		for k, v := range qm {
			q.Set(k, v)
		}
	}
	var body any
	if s := strings.TrimSpace(params["body"]); s != "" {
		if err := json.Unmarshal([]byte(s), &body); err != nil {
			return nil, fmt.Errorf("body must be valid JSON: %w", err)
		}
	}
	code, respBody, err := c.do(ctx, method, path, q, body)
	if err != nil {
		return nil, err
	}
	var parsed any
	if json.Unmarshal(respBody, &parsed) != nil {
		parsed = string(respBody)
	}
	return map[string]any{"status": code, "body": parsed}, nil
}

// ── Transaction poll loop (Phase 0 pull) ─────────────────────────────────────

// runZKBioTimePollLoop periodically pulls new transactions and relays them to
// /api/agent-bridge/attlog as {type:"zkbiotime", data:[...]}. A sliding overlap
// + the server-side natural-key dedup make re-polls idempotent. The bridge owns
// the checkpoint so a host restart cannot lose an outage backlog.
func (a *Agent) runZKBioTimePollLoop(ctx context.Context) {
	c := a.zkbiotime
	if c == nil {
		return
	}
	const interval = 60 * time.Second

	var hwm time.Time
	checkpointLoaded := false
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	pull := func() {
		if !checkpointLoaded {
			checkpoint, ok, err := a.fetchZKBioTimeCheckpoint(ctx)
			if err != nil {
				log.Printf("[zkbiotime] fetch checkpoint: %v", err)
				return
			}
			if ok {
				hwm = checkpoint
			} else {
				hwm = time.Now().In(zkbioTimeLocation).Add(-24 * time.Hour)
			}
			checkpointLoaded = true
		}

		requestEnd := time.Now().In(zkbioTimeLocation)
		nextCheckpoint, err := a.pullZKBioTimeTransactions(ctx, c, hwm, requestEnd)
		if err != nil {
			log.Printf("[zkbiotime] pull window: %v", err)
			return
		}
		hwm = nextCheckpoint
	}

	pull()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pull()
		}
	}
}

func nextZKBioTimeCheckpoint(txns []map[string]any, requestEnd time.Time) time.Time {
	var next time.Time
	for _, txn := range txns {
		uploadTime, ok := txn["upload_time"].(string)
		if !ok {
			continue
		}
		parsed, err := time.ParseInLocation(zkbioTimeLayout, strings.TrimSpace(uploadTime), zkbioTimeLocation)
		if err != nil {
			continue
		}
		if next.IsZero() || parsed.After(next) {
			next = parsed
		}
	}
	if next.IsZero() {
		return requestEnd
	}
	return next
}

func (a *Agent) pullZKBioTimeTransactions(ctx context.Context, c *ZKBioTimeClient, hwm, requestEnd time.Time) (time.Time, error) {
	const overlap = 2 * time.Minute
	start := hwm.In(zkbioTimeLocation).Add(-overlap).Format(zkbioTimeLayout)
	end := requestEnd.In(zkbioTimeLocation).Format(zkbioTimeLayout)
	txns, err := c.fetchTransactions(ctx, start, end)
	if err != nil {
		return hwm, fmt.Errorf("pull transactions: %w", err)
	}

	nextCheckpoint := nextZKBioTimeCheckpoint(txns, requestEnd)
	if err := a.relayZKBioTimeTransactions(ctx, txns, nextCheckpoint); err != nil {
		return hwm, fmt.Errorf("relay attlog: %w", err)
	}
	if len(txns) > 0 {
		log.Printf("[zkbiotime] relayed %d transactions", len(txns))
	}
	return nextCheckpoint, nil
}

func (a *Agent) fetchZKBioTimeCheckpoint(ctx context.Context) (time.Time, bool, error) {
	checkpointURL := fmt.Sprintf("%s/api/agent-bridge/zkbiotime/checkpoint", a.config.PlamatixURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, checkpointURL, nil)
	if err != nil {
		return time.Time{}, false, err
	}
	req.Header.Set("X-API-Key", a.config.APIKey)

	client := &http.Client{Timeout: 30 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return time.Time{}, false, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		return time.Time{}, false, fmt.Errorf("checkpoint HTTP %d: %s", res.StatusCode, truncate(string(body), 200))
	}

	var response struct {
		CheckpointAt json.RawMessage `json:"checkpointAt"`
	}
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return time.Time{}, false, fmt.Errorf("decode checkpoint: %w", err)
	}
	if len(response.CheckpointAt) == 0 {
		return time.Time{}, false, fmt.Errorf("decode checkpoint: missing checkpointAt")
	}
	if bytes.Equal(bytes.TrimSpace(response.CheckpointAt), []byte("null")) {
		return time.Time{}, false, nil
	}
	var checkpointText string
	if err := json.Unmarshal(response.CheckpointAt, &checkpointText); err != nil {
		return time.Time{}, false, fmt.Errorf("decode checkpointAt: %w", err)
	}
	checkpoint, err := time.ParseInLocation(zkbioTimeLayout, strings.TrimSpace(checkpointText), zkbioTimeLocation)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("parse checkpoint: %w", err)
	}
	return checkpoint, true, nil
}

func (a *Agent) relayZKBioTimeTransactions(ctx context.Context, txns []map[string]any, checkpoint time.Time) error {
	payload := map[string]any{
		"type":         "zkbiotime",
		"data":         txns,
		"checkpointAt": checkpoint.In(zkbioTimeLocation).Format(zkbioTimeLayout),
	}
	body, _ := json.Marshal(payload)
	attURL := fmt.Sprintf("%s/api/agent-bridge/attlog", a.config.PlamatixURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, attURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", a.config.APIKey)

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(res.Body)
		return fmt.Errorf("attlog HTTP %d: %s", res.StatusCode, truncate(string(b), 200))
	}
	return nil
}
