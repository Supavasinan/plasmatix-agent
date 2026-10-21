package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// attlogCloud records every /api/agent-bridge/attlog request and answers with
// reply(payload), which returns the status code and body to send.
type attlogCloud struct {
	mu       sync.Mutex
	payloads []map[string]any
}

func newAttlogCloud(t *testing.T, reply func(map[string]any) (int, string)) (*attlogCloud, *httptest.Server) {
	t.Helper()
	recorded := &attlogCloud{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode attlog payload: %v", err)
		}
		recorded.mu.Lock()
		recorded.payloads = append(recorded.payloads, payload)
		recorded.mu.Unlock()
		status, body := reply(payload)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return recorded, server
}

func batchAck(payload map[string]any) (int, string) {
	rows, _ := payload["data"].([]any)
	return http.StatusOK, fmt.Sprintf(`{"ok":true,"received":%d,"inserted":%d,"skipped":0}`, len(rows), len(rows))
}

func taPushServer(cloudURL, sn string) *ADMSServer {
	tracker := newDeviceTracker()
	tracker.observeProtocol(sn, ProtocolObservation{Path: "/iclock/cdata", PushVersion: "2.4.1"})
	return &ADMSServer{agent: &Agent{config: Config{PlamatixURL: cloudURL}, devices: tracker}}
}

func postATTLOG(server *ADMSServer, sn, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/iclock/cdata?SN="+sn+"&table=ATTLOG", strings.NewReader(body))
	recorder := httptest.NewRecorder()
	server.handleCData(recorder, request)
	return recorder
}

const twoPunches = "7\t2026-10-16 07:58:01\t0\t1\t0\n8\t2026-10-16 08:02:44\t0\t15\t0\n"

func TestATTLOGIsAckedOnlyAfterPlasmatixStoresTheBatch(t *testing.T) {
	cloud, server := newAttlogCloud(t, batchAck)

	recorder := postATTLOG(taPushServer(server.URL, "TA1"), "TA1", twoPunches)

	if got := strings.TrimSpace(recorder.Body.String()); got != "OK:2" {
		t.Fatalf("ack = %q; want OK:2", got)
	}
	if len(cloud.payloads) != 1 || cloud.payloads[0]["type"] != "attlog_batch" {
		t.Fatalf("want one attlog_batch request, got %v", cloud.payloads)
	}
	rows := cloud.payloads[0]["data"].([]any)
	first := rows[0].(map[string]any)
	if first["userId"] != "7" || first["punchTime"] != "2026-10-16 07:58:01" || first["deviceSN"] != "TA1" {
		t.Fatalf("first row = %v", first)
	}
}

func TestATTLOGIsNotAckedWhenPlasmatixFails(t *testing.T) {
	for name, reply := range map[string]func(map[string]any) (int, string){
		"server error":    func(map[string]any) (int, string) { return http.StatusInternalServerError, `{"error":"db down"}` },
		"short count":     func(map[string]any) (int, string) { return http.StatusOK, `{"ok":true,"received":1}` },
		"no confirmation": func(map[string]any) (int, string) { return http.StatusOK, `` },
	} {
		t.Run(name, func(t *testing.T) {
			_, server := newAttlogCloud(t, reply)

			recorder := postATTLOG(taPushServer(server.URL, "TA1"), "TA1", twoPunches)

			if recorder.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d; want 503 so the scanner keeps the punches", recorder.Code)
			}
			if strings.HasPrefix(strings.TrimSpace(recorder.Body.String()), "OK") {
				t.Fatalf("scanner was told %q", recorder.Body.String())
			}
		})
	}
}

func TestATTLOGIsNotAckedWhenPlasmatixIsUnreachable(t *testing.T) {
	_, server := newAttlogCloud(t, batchAck)
	server.Close()

	recorder := postATTLOG(taPushServer(server.URL, "TA1"), "TA1", twoPunches)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d; want 503", recorder.Code)
	}
}

func TestATTLOGFallsBackToSingleRowsOnAnOlderPlasmatix(t *testing.T) {
	cloud, server := newAttlogCloud(t, func(payload map[string]any) (int, string) {
		if payload["type"] == "attlog_batch" {
			return http.StatusOK, `{"ok":true,"ignored":"attlog_batch"}`
		}
		return http.StatusOK, `{"ok":true}`
	})

	recorder := postATTLOG(taPushServer(server.URL, "TA1"), "TA1", twoPunches)

	if got := strings.TrimSpace(recorder.Body.String()); got != "OK:2" {
		t.Fatalf("ack = %q; want OK:2", got)
	}
	if len(cloud.payloads) != 3 || cloud.payloads[1]["type"] != "attlog" || cloud.payloads[2]["type"] != "attlog" {
		t.Fatalf("want batch then two single rows, got %v", cloud.payloads)
	}
}

func TestQueriedATTLOGReplyIsStored(t *testing.T) {
	cloud, server := newAttlogCloud(t, batchAck)
	admsServer := taPushServer(server.URL, "TA1")

	request := httptest.NewRequest(
		http.MethodPost,
		"/iclock/querydata?SN=TA1&type=tabledata&cmdid=12&tablename=ATTLOG&count=2&packcnt=1&packidx=1",
		strings.NewReader("pin=7\ttime=2026-10-16 07:58:01\tstatus=0\tverify=1\tworkcode=0\n"+
			"8\t2026-10-16 08:02:44\t0\t15\t0\n"),
	)
	recorder := httptest.NewRecorder()
	admsServer.handleQueryData(recorder, request)

	if got := strings.TrimSpace(recorder.Body.String()); got != "OK: 12" {
		t.Fatalf("ack = %q", got)
	}
	if len(cloud.payloads) != 1 {
		t.Fatalf("want one batch, got %v", cloud.payloads)
	}
	rows := cloud.payloads[0]["data"].([]any)
	if len(rows) != 2 {
		t.Fatalf("rows = %v", rows)
	}
	if first := rows[0].(map[string]any); first["userId"] != "7" || first["verifyMode"] != float64(1) {
		t.Fatalf("key=value row = %v", first)
	}
}

func TestParseATTLOGRowsDropsUnstorableLines(t *testing.T) {
	rows := parseATTLOGRows("TA1", []byte("\n7\t2026-10-16 07:58:01\t0\t1\t0\n\t\t\npin=\ttime=2026-10-16 08:00:00\nonlyonefield\n"))
	if len(rows) != 1 || rows[0].UserID != "7" || rows[0].DeviceSN != "TA1" {
		t.Fatalf("rows = %+v", rows)
	}
}
