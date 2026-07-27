package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestAtoiPtr(t *testing.T) {
	cases := []struct {
		in string
		n  int
		ok bool
	}{
		{"1", 1, true},
		{" 2 ", 2, true},
		{"", 0, false},
		{"abc", 0, false},
	}
	for _, c := range cases {
		n, ok := atoiPtr(c.in)
		if n != c.n || ok != c.ok {
			t.Errorf("atoiPtr(%q) = (%d,%v), want (%d,%v)", c.in, n, ok, c.n, c.ok)
		}
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("hello", 3); got != "hel" {
		t.Errorf("truncate cut = %q", got)
	}
	if got := truncate("hi", 5); got != "hi" {
		t.Errorf("truncate short = %q", got)
	}
}

func TestEmployeeBody(t *testing.T) {
	row := map[string]string{
		"emp_code":   "6",
		"first_name": "A",
		"last_name":  "B",
		"department": "3",
		"area":       "2",
		"position":   "5",
		"gender":     "M",
		"birthday":   "",
		"email":      "a@b.c",
	}
	got := employeeBody(row)
	want := map[string]any{
		"emp_code":   "6",
		"first_name": "A",
		"last_name":  "B",
		"department": 3,
		"area":       []int{2},
		"position":   5,
		"gender":     "M",
		"email":      "a@b.c",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("employeeBody mismatch:\n got=%#v\nwant=%#v", got, want)
	}
	// empty birthday must be omitted
	if _, ok := got["birthday"]; ok {
		t.Errorf("empty birthday should be omitted")
	}
}

func TestEmployeeBodyOmitsMissingIDs(t *testing.T) {
	got := employeeBody(map[string]string{"emp_code": "9", "first_name": "X", "last_name": "Y"})
	for _, k := range []string{"department", "area", "position"} {
		if _, ok := got[k]; ok {
			t.Errorf("expected %q omitted when unset", k)
		}
	}
}

// resign on an employee that doesn't exist in ZKBioTime is an idempotent no-op,
// not an error (they're already in the desired absent state).
func TestResignNoOpWhenNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/personnel/api/employees/") {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"data":[]}`)
			return
		}
		t.Errorf("unexpected %s %s (should not POST a resign when not found)", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newZKBioTimeClientWith(srv.URL, "x", "x", srv.Client())
	ok, err := c.resign(context.Background(), "999", "2026-06-07", "")
	if err != nil {
		t.Fatalf("expected no error for missing employee, got %v", err)
	}
	if ok {
		t.Fatalf("expected ok=false (no-op) for missing employee")
	}
}

// resign on an existing employee posts the resignation and reports ok=true.
func TestResignWhenFound(t *testing.T) {
	posted := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/personnel/api/employees/"):
			io.WriteString(w, `{"data":[{"id":42,"emp_code":"7"}]}`)
		case r.Method == http.MethodPost && r.URL.Path == "/personnel/api/resigns/":
			posted = true
			io.WriteString(w, `{}`)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	c := newZKBioTimeClientWith(srv.URL, "x", "x", srv.Client())
	ok, err := c.resign(context.Background(), "7", "2026-06-07", "quit")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("expected ok=true when employee found")
	}
	if !posted {
		t.Fatalf("expected POST to /personnel/api/resigns/")
	}
}

func TestFetchZKBioTimeLastTransactionID(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		want    int64
		wantErr bool
	}{
		{
			name: "stored cursor",
			body: `{"checkpointAt":"2026-07-27 17:19:11","lastTransactionId":172}`,
			want: 172,
		},
		{
			name: "null starts full backfill",
			body: `{"checkpointAt":"2026-07-27 17:19:11","lastTransactionId":null}`,
			want: 0,
		},
		{
			name:    "missing field fails closed",
			body:    `{"checkpointAt":"2026-07-27 17:19:11"}`,
			wantErr: true,
		},
		{
			name:    "negative cursor fails closed",
			body:    `{"lastTransactionId":-1}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.Header.Get("X-API-Key"); got != "test-key" {
					t.Fatalf("X-API-Key = %q, want test-key", got)
				}
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, tt.body)
			}))
			defer srv.Close()

			a := &Agent{config: Config{PlamatixURL: srv.URL, APIKey: "test-key"}}
			got, err := a.fetchZKBioTimeLastTransactionID(context.Background())
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Fatalf("cursor = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestFetchTransactionsAfterID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		if got := query.Get("last_id"); got != "172" {
			t.Errorf("last_id = %q, want 172", got)
		}
		if got := query.Get("ordering"); got != "id" {
			t.Errorf("ordering = %q, want id", got)
		}
		if got := query.Get("page_size"); got != "500" {
			t.Errorf("page_size = %q, want 500", got)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"next":null,"data":[{"id":173},{"id":174}]}`)
	}))
	defer srv.Close()

	c := newZKBioTimeClientWith(srv.URL, "x", "x", srv.Client())
	rows, err := c.fetchTransactionsAfterID(context.Background(), 172)
	if err != nil {
		t.Fatalf("fetch transactions: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("row count = %d, want 2", len(rows))
	}
}

func TestFetchTransactionsAfterIDRejectsMissingData(t *testing.T) {
	for _, body := range []string{`{"next":null}`, `{"next":null,"data":null}`} {
		t.Run(body, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.WriteString(w, body)
			}))
			defer srv.Close()

			c := newZKBioTimeClientWith(srv.URL, "x", "x", srv.Client())
			if _, err := c.fetchTransactionsAfterID(context.Background(), 172); err == nil {
				t.Fatal("expected invalid data error")
			}
		})
	}
}

func TestPrepareZKBioTimeBatch(t *testing.T) {
	rows := []map[string]any{
		{"id": float64(172)},
		{"id": float64(174), "punch_time": "2026-07-27 07:48:43"},
		{"id": float64(173), "punch_time": "2026-07-27 07:26:17"},
	}

	newer, next, err := prepareZKBioTimeBatch(rows, 172)
	if err != nil {
		t.Fatalf("prepare batch: %v", err)
	}
	if next != 174 {
		t.Fatalf("next cursor = %d, want 174", next)
	}
	gotIDs := []float64{newer[0]["id"].(float64), newer[1]["id"].(float64)}
	if !reflect.DeepEqual(gotIDs, []float64{173, 174}) {
		t.Fatalf("IDs = %v, want [173 174]", gotIDs)
	}

	none, unchanged, err := prepareZKBioTimeBatch(
		[]map[string]any{{"id": float64(172)}},
		172,
	)
	if err != nil {
		t.Fatalf("prepare inclusive cursor: %v", err)
	}
	if len(none) != 0 || unchanged != 172 {
		t.Fatalf("inclusive result = (%v, %d), want (empty, 172)", none, unchanged)
	}
}

func TestPrepareZKBioTimeBatchRejectsInvalidIDs(t *testing.T) {
	tests := []struct {
		name  string
		value any
	}{
		{name: "nil", value: nil},
		{name: "zero", value: float64(0)},
		{name: "negative", value: float64(-1)},
		{name: "fractional", value: 1.5},
		{name: "string", value: "188"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := prepareZKBioTimeBatch(
				[]map[string]any{{"id": tt.value}},
				172,
			)
			if err == nil {
				t.Fatalf("expected invalid ID error for %v", tt.value)
			}
		})
	}
}

func TestRelayZKBioTimeTransactionsIncludesID(t *testing.T) {
	var received struct {
		Type              string           `json:"type"`
		LastTransactionID int64            `json:"lastTransactionId"`
		Data              []map[string]any `json:"data"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/agent-bridge/attlog" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("X-API-Key"); got != "test-key" {
			t.Fatalf("X-API-Key = %q, want test-key", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	a := &Agent{config: Config{PlamatixURL: srv.URL, APIKey: "test-key"}}
	txns := []map[string]any{{"id": float64(173), "emp_code": "101", "punch_time": "2026-07-20 08:30:00"}}
	if err := a.relayZKBioTimeTransactions(context.Background(), txns, 173); err != nil {
		t.Fatalf("relay transactions: %v", err)
	}

	if received.Type != "zkbiotime" {
		t.Fatalf("type = %q, want zkbiotime", received.Type)
	}
	if received.LastTransactionID != 173 {
		t.Fatalf("lastTransactionId = %d, want 173", received.LastTransactionID)
	}
	if !reflect.DeepEqual(received.Data, txns) {
		t.Fatalf("data = %#v, want %#v", received.Data, txns)
	}
}

func TestCatchUpZKBioTimeTransactionsAdvancesAcrossBatches(t *testing.T) {
	zkServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch got := r.URL.Query().Get("last_id"); got {
		case "172":
			io.WriteString(w, `{"data":[{"id":174},{"id":173}]}`)
		case "174":
			io.WriteString(w, `{"data":[{"id":175}]}`)
		case "175":
			io.WriteString(w, `{"data":[]}`)
		default:
			t.Fatalf("unexpected last_id %q", got)
		}
	}))
	defer zkServer.Close()

	var acknowledged []int64
	relayServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			LastTransactionID int64 `json:"lastTransactionId"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode relay: %v", err)
		}
		acknowledged = append(acknowledged, payload.LastTransactionID)
		w.WriteHeader(http.StatusOK)
	}))
	defer relayServer.Close()

	a := &Agent{config: Config{PlamatixURL: relayServer.URL, APIKey: "test-key"}}
	c := newZKBioTimeClientWith(zkServer.URL, "x", "x", zkServer.Client())
	got, err := a.catchUpZKBioTimeTransactions(context.Background(), c, 172)
	if err != nil {
		t.Fatalf("catch up: %v", err)
	}
	if got != 175 {
		t.Fatalf("cursor = %d, want 175", got)
	}
	if !reflect.DeepEqual(acknowledged, []int64{174, 175}) {
		t.Fatalf("acknowledged = %#v, want [174 175]", acknowledged)
	}
}

func TestCatchUpZKBioTimeTransactionsRelayFailurePreservesAcknowledgedID(t *testing.T) {
	zkServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("last_id") {
		case "172":
			io.WriteString(w, `{"data":[{"id":173},{"id":174}]}`)
		case "174":
			io.WriteString(w, `{"data":[{"id":175}]}`)
		default:
			io.WriteString(w, `{"data":[]}`)
		}
	}))
	defer zkServer.Close()

	relayCalls := 0
	relayServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		relayCalls++
		if relayCalls == 2 {
			http.Error(w, "retry later", http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer relayServer.Close()

	a := &Agent{config: Config{PlamatixURL: relayServer.URL, APIKey: "test-key"}}
	c := newZKBioTimeClientWith(zkServer.URL, "x", "x", zkServer.Client())
	got, err := a.catchUpZKBioTimeTransactions(context.Background(), c, 172)
	if err == nil {
		t.Fatal("expected relay error")
	}
	if got != 174 {
		t.Fatalf("cursor = %d after relay failure, want 174", got)
	}
}
