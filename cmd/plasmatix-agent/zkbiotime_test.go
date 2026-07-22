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
	"time"
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

func TestFetchZKBioTimeCheckpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/agent-bridge/zkbiotime/checkpoint" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("X-API-Key"); got != "test-key" {
			t.Fatalf("X-API-Key = %q, want test-key", got)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"checkpointAt":"2026-07-20 08:30:00"}`)
	}))
	defer srv.Close()

	a := &Agent{config: Config{PlamatixURL: srv.URL, APIKey: "test-key"}}
	got, ok, err := a.fetchZKBioTimeCheckpoint(context.Background())
	if err != nil {
		t.Fatalf("fetch checkpoint: %v", err)
	}
	if !ok {
		t.Fatal("expected checkpoint to be present")
	}
	want := time.Date(2026, time.July, 20, 8, 30, 0, 0, zkbioTimeLocation)
	if !got.Equal(want) {
		t.Fatalf("checkpoint = %s, want %s", got, want)
	}
}

func TestFetchZKBioTimeCheckpointDistinguishesNullFromAbsent(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{name: "explicit null", body: `{"checkpointAt":null}`},
		{name: "absent field", body: `{}`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, tt.body)
			}))
			defer srv.Close()

			a := &Agent{config: Config{PlamatixURL: srv.URL, APIKey: "test-key"}}
			_, ok, err := a.fetchZKBioTimeCheckpoint(context.Background())
			if (err != nil) != tt.wantErr {
				t.Fatalf("fetch checkpoint error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && ok {
				t.Fatal("explicit null checkpoint should be accepted as absent")
			}
		})
	}
}

func TestNextZKBioTimeCheckpointUsesGreatestParseableUploadTime(t *testing.T) {
	requestEnd := time.Date(2026, time.July, 20, 9, 0, 0, 0, zkbioTimeLocation)
	txns := []map[string]any{
		{"upload_time": "2026-07-20 08:41:00"},
		{"upload_time": "not-a-time"},
		{"upload_time": "2026-07-20 08:52:00"},
		{"upload_time": "2026-07-20 08:47:00"},
		{"upload_time": 12345},
	}

	got := nextZKBioTimeCheckpoint(txns, requestEnd)
	want := time.Date(2026, time.July, 20, 8, 52, 0, 0, zkbioTimeLocation)
	if !got.Equal(want) {
		t.Fatalf("checkpoint = %s, want greatest upload_time %s", got, want)
	}
}

func TestNextZKBioTimeCheckpointFallsBackToRequestEnd(t *testing.T) {
	requestEnd := time.Date(2026, time.July, 20, 9, 0, 0, 0, zkbioTimeLocation)
	txns := []map[string]any{{"upload_time": "not-a-time"}}

	if got := nextZKBioTimeCheckpoint(txns, requestEnd); !got.Equal(requestEnd) {
		t.Fatalf("checkpoint = %s, want request end %s", got, requestEnd)
	}
	if got := nextZKBioTimeCheckpoint(nil, requestEnd); !got.Equal(requestEnd) {
		t.Fatalf("empty batch checkpoint = %s, want request end %s", got, requestEnd)
	}
}

func TestPullZKBioTimeTransactionsAcknowledgesEmptyBatch(t *testing.T) {
	zkServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"next":null,"data":[]}`)
	}))
	defer zkServer.Close()

	var received struct {
		CheckpointAt string           `json:"checkpointAt"`
		Data         []map[string]any `json:"data"`
	}
	relayServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatalf("decode relay: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer relayServer.Close()

	a := &Agent{config: Config{PlamatixURL: relayServer.URL, APIKey: "test-key"}}
	c := newZKBioTimeClientWith(zkServer.URL, "x", "x", zkServer.Client())
	prior := time.Date(2026, time.July, 20, 8, 0, 0, 0, zkbioTimeLocation)
	requestEnd := time.Date(2026, time.July, 20, 9, 0, 0, 0, zkbioTimeLocation)

	got, err := a.pullZKBioTimeTransactions(context.Background(), c, prior, requestEnd)
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if !got.Equal(requestEnd) {
		t.Fatalf("checkpoint = %s, want request end %s", got, requestEnd)
	}
	if received.CheckpointAt != "2026-07-20 09:00:00" {
		t.Fatalf("relayed checkpointAt = %q", received.CheckpointAt)
	}
	if received.Data == nil || len(received.Data) != 0 {
		t.Fatalf("relayed data = %#v, want empty JSON array", received.Data)
	}
}

func TestPullZKBioTimeTransactionsRelayFailurePreservesCheckpoint(t *testing.T) {
	zkServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"next":null,"data":[{"upload_time":"2026-07-20 08:45:00"}]}`)
	}))
	defer zkServer.Close()
	relayServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "retry later", http.StatusBadGateway)
	}))
	defer relayServer.Close()

	a := &Agent{config: Config{PlamatixURL: relayServer.URL, APIKey: "test-key"}}
	c := newZKBioTimeClientWith(zkServer.URL, "x", "x", zkServer.Client())
	prior := time.Date(2026, time.July, 20, 8, 0, 0, 0, zkbioTimeLocation)
	requestEnd := time.Date(2026, time.July, 20, 9, 0, 0, 0, zkbioTimeLocation)

	got, err := a.pullZKBioTimeTransactions(context.Background(), c, prior, requestEnd)
	if err == nil {
		t.Fatal("expected relay error")
	}
	if !got.Equal(prior) {
		t.Fatalf("checkpoint = %s after relay failure, want prior %s", got, prior)
	}
}

func TestFetchTransactionsFailsClosedOnInvalidPagination(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{
			name: "missing data",
			handler: func(w http.ResponseWriter, r *http.Request) {
				io.WriteString(w, `{"next":null}`)
			},
		},
		{
			name: "null data",
			handler: func(w http.ResponseWriter, r *http.Request) {
				io.WriteString(w, `{"next":null,"data":null}`)
			},
		},
		{
			name: "continuing page is empty",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("page") == "1" {
					io.WriteString(w, `{"next":"?page=2","data":[{"id":1}]}`)
					return
				}
				io.WriteString(w, `{"next":"?page=3","data":[]}`)
			},
		},
		{
			name: "continuing page is stalled",
			handler: func(w http.ResponseWriter, r *http.Request) {
				io.WriteString(w, `{"next":"?page=2","data":[{"id":1}]}`)
			},
		},
		{
			name: "next remains at page cap",
			handler: func(w http.ResponseWriter, r *http.Request) {
				io.WriteString(w, `{"next":"?page=`+r.URL.Query().Get("page")+`","data":[{"id":1}]}`)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()
			c := newZKBioTimeClientWith(srv.URL, "x", "x", srv.Client())

			got, err := c.fetchTransactions(context.Background(), "2026-07-20 08:00:00", "2026-07-20 09:00:00")
			if err == nil {
				t.Fatal("expected pagination error")
			}
			if got != nil {
				t.Fatalf("partial data returned on pagination failure: %#v", got)
			}
		})
	}
}

func TestRelayZKBioTimeTransactionsIncludesCheckpoint(t *testing.T) {
	var received struct {
		Type         string           `json:"type"`
		CheckpointAt string           `json:"checkpointAt"`
		Data         []map[string]any `json:"data"`
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
	checkpoint := time.Date(2026, time.July, 20, 8, 31, 0, 0, zkbioTimeLocation)
	txns := []map[string]any{{"emp_code": "101", "punch_time": "2026-07-20 08:30:00"}}
	if err := a.relayZKBioTimeTransactions(context.Background(), txns, checkpoint); err != nil {
		t.Fatalf("relay transactions: %v", err)
	}

	if received.Type != "zkbiotime" {
		t.Fatalf("type = %q, want zkbiotime", received.Type)
	}
	if received.CheckpointAt != "2026-07-20 08:31:00" {
		t.Fatalf("checkpointAt = %q", received.CheckpointAt)
	}
	if !reflect.DeepEqual(received.Data, txns) {
		t.Fatalf("data = %#v, want %#v", received.Data, txns)
	}
}
