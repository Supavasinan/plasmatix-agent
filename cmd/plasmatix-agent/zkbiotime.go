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
)

// ZKBioTimeClient talks to a ZKBioTime / BioTime 8 server over its REST API
// (HTTP Basic auth). It is used when the agent runs in mode "zkbiotime".
// Credentials arrive in the generic zkbio_url/username/password config keys.
type ZKBioTimeClient struct {
	baseURL    string
	username   string
	password   string
	httpClient *http.Client
}

func newZKBioTimeClient(cfg Config) *ZKBioTimeClient {
	return &ZKBioTimeClient{
		baseURL:  strings.TrimRight(cfg.ZKBioURL, "/"),
		username: cfg.ZKBioUsername,
		password: cfg.ZKBioPassword,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
			Transport: &http.Transport{
				// ZKBioTime on the LAN often uses a self-signed / internal cert.
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}
}

// do performs an authenticated JSON request using HTTP Basic auth, returning
// the status code and the raw body.
//
// Why Basic and not JWT: BioTime's IsNotOpenAPI permission rejects token/JWT
// ("Open API") requests on /iclock/ and /personnel/ unless the API module is
// licensed (enable_api), which trial licenses lack. HTTP Basic auth leaves
// request.auth=None server-side, so it bypasses that gate — and it also works
// on full licenses (where everything is allowed) — so we use it unconditionally.
func (c *ZKBioTimeClient) do(ctx context.Context, method, path string, query url.Values, payload any) (int, []byte, error) {
	u := c.baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var rdr io.Reader
	if payload != nil {
		b, _ := json.Marshal(payload)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(c.username, c.password)

	res, err := c.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res.StatusCode, body, nil
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
	q := url.Values{"emp_code": {empCode}}
	code, body, err := c.do(ctx, http.MethodGet, "/personnel/api/employees/", q, nil)
	if err != nil {
		return 0, false, err
	}
	if code != http.StatusOK {
		return 0, false, fmt.Errorf("lookup emp_code=%s (HTTP %d): %s", empCode, code, truncate(string(body), 160))
	}
	var out struct {
		Data []struct {
			ID      int    `json:"id"`
			EmpCode string `json:"emp_code"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return 0, false, err
	}
	for _, e := range out.Data {
		if e.EmpCode == empCode {
			return e.ID, true, nil
		}
	}
	if len(out.Data) > 0 {
		return out.Data[0].ID, true, nil
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

// resign marks an employee as resigned in ZKBioTime.
func (c *ZKBioTimeClient) resign(ctx context.Context, empCode, date, reason string) error {
	id, found, err := c.findEmployeeID(ctx, empCode)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("emp_code=%s not found", empCode)
	}
	body := map[string]any{
		"employee":    id,
		"resign_date": date,
		"resign_type": 1, // 1 = resignation
		"reason":      reason,
	}
	code, resp, err := c.do(ctx, http.MethodPost, "/personnel/api/resigns/", nil, body)
	if err != nil {
		return err
	}
	if code < 200 || code >= 300 {
		return fmt.Errorf("resign (HTTP %d): %s", code, truncate(string(resp), 200))
	}
	return nil
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

func (c *ZKBioTimeClient) fetchList(ctx context.Context, path, nameField string) ([]idName, error) {
	code, body, err := c.do(ctx, http.MethodGet, path, url.Values{"page_size": {"1000"}}, nil)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("GET %s (HTTP %d): %s", path, code, truncate(string(body), 160))
	}
	var out struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	list := make([]idName, 0, len(out.Data))
	for _, row := range out.Data {
		name, _ := row[nameField].(string)
		list = append(list, idName{ID: row["id"], Name: name})
	}
	return list, nil
}

func (c *ZKBioTimeClient) fetchPersonnelLists(ctx context.Context) (map[string]any, error) {
	depts, err := c.fetchList(ctx, "/personnel/api/departments/", "dept_name")
	if err != nil {
		return nil, err
	}
	areas, err := c.fetchList(ctx, "/personnel/api/areas/", "area_name")
	if err != nil {
		return nil, err
	}
	positions, err := c.fetchList(ctx, "/personnel/api/positions/", "position_name")
	if err != nil {
		return nil, err
	}
	return map[string]any{"departments": depts, "areas": areas, "positions": positions}, nil
}

func (c *ZKBioTimeClient) fetchTerminals(ctx context.Context) (map[string]any, error) {
	code, body, err := c.do(ctx, http.MethodGet, "/iclock/api/terminals/", url.Values{"page_size": {"1000"}}, nil)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("GET terminals (HTTP %d): %s", code, truncate(string(body), 160))
	}
	var out struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	terminals := make([]map[string]any, 0, len(out.Data))
	for _, t := range out.Data {
		areaName := ""
		if area, ok := t["area"].(map[string]any); ok {
			areaName, _ = area["area_name"].(string)
		}
		terminals = append(terminals, map[string]any{
			"id":            t["id"],
			"sn":            t["sn"],
			"alias":         t["alias"],
			"ip_address":    t["ip_address"],
			"area_name":     areaName,
			"last_activity": t["last_activity"],
		})
	}
	return map[string]any{"terminals": terminals}, nil
}

func (c *ZKBioTimeClient) fetchAttReport(ctx context.Context, start, end string) (map[string]any, error) {
	q := url.Values{"page_size": {"1000"}}
	if start != "" {
		q.Set("start_date", start)
	}
	if end != "" {
		q.Set("end_date", end)
	}
	code, body, err := c.do(ctx, http.MethodGet, "/att/api/transactionReport/", q, nil)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("GET att report (HTTP %d): %s", code, truncate(string(body), 160))
	}
	var out struct {
		Count int              `json:"count"`
		Data  []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return map[string]any{"count": out.Count, "data": out.Data}, nil
}

// fetchTransactions pulls raw punches in a time window (paginated).
func (c *ZKBioTimeClient) fetchTransactions(ctx context.Context, start, end string) ([]map[string]any, error) {
	var all []map[string]any
	page := 1
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
		var out struct {
			Next string           `json:"next"`
			Data []map[string]any `json:"data"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			return nil, err
		}
		all = append(all, out.Data...)
		if out.Next == "" || len(out.Data) == 0 {
			break
		}
		page++
		if page > 200 { // safety
			break
		}
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
		if err := c.resign(ctx, r.EmpCode, r.ResignDate, r.Reason); err != nil {
			errs = append(errs, map[string]string{"emp_code": r.EmpCode, "message": err.Error()})
			continue
		}
		resigned++
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

// ── Transaction poll loop (Phase 0 pull) ─────────────────────────────────────

// runZKBioTimePollLoop periodically pulls new transactions and relays them to
// /api/agent-bridge/attlog as {type:"zkbiotime", data:[...]}. A sliding overlap
// + the server-side natural-key dedup make re-polls idempotent.
func (a *Agent) runZKBioTimePollLoop(ctx context.Context) {
	c := a.zkbiotime
	if c == nil {
		return
	}
	const layout = "2006-01-02 15:04:05"
	const overlap = 2 * time.Minute
	const interval = 60 * time.Second

	hwm := time.Now().Add(-24 * time.Hour)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	pull := func() {
		now := time.Now()
		start := hwm.Add(-overlap).Format(layout)
		end := now.Format(layout)
		txns, err := c.fetchTransactions(ctx, start, end)
		if err != nil {
			log.Printf("[zkbiotime] pull transactions: %v", err)
			return
		}
		if len(txns) == 0 {
			hwm = now
			return
		}
		if err := a.relayZKBioTimeTransactions(ctx, txns); err != nil {
			log.Printf("[zkbiotime] relay attlog: %v", err)
			return
		}
		log.Printf("[zkbiotime] relayed %d transactions", len(txns))
		hwm = now
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

func (a *Agent) relayZKBioTimeTransactions(ctx context.Context, txns []map[string]any) error {
	payload := map[string]any{"type": "zkbiotime", "data": txns}
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
