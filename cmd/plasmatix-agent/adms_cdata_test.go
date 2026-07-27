package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A realtime "table=tabledata&tablename=user" push must be acknowledged with
// a bare "OK". ZAM70 / Push 3.0 firmware does not treat the count-style ack
// ("user=1") as success, so it never clears the record from its outbound
// buffer and re-uploads the same user row every few seconds indefinitely
// (observed in production: SN=NYU7253100765 spamming tablename=user pin=21).
// The "tablename=count" ack is only required by the biometric template/photo
// tables (see commit 1f6d695); standard realtime tables use plain "OK", same
// as ATTLOG, rtlog and ATTPHOTO.
func TestHandleCData_UserTableAckedWithOK(t *testing.T) {
	s := &ADMSServer{agent: &Agent{devices: newDeviceTracker()}}

	req := httptest.NewRequest(
		http.MethodPost,
		"/iclock/cdata?SN=NYU7253100765&table=tabledata&tablename=user",
		strings.NewReader("user pin=21\tname=test er\tprivilege=0\n"),
	)
	rec := httptest.NewRecorder()

	s.handleCData(rec, req)

	if got := strings.TrimSpace(rec.Body.String()); got != "OK" {
		t.Fatalf("tablename=user ack = %q; want \"OK\" (count-style ack makes the device re-push forever)", got)
	}
}

// ATTPHOTO already had this behavior (f895cd8); lock it in so a future refactor
// of the ack logic does not regress it back to the count-style body.
func TestHandleCData_AttPhotoAckedWithOK(t *testing.T) {
	s := &ADMSServer{agent: &Agent{devices: newDeviceTracker()}}

	req := httptest.NewRequest(
		http.MethodPost,
		"/iclock/cdata?SN=NYU7253100765&table=tabledata&tablename=ATTPHOTO",
		strings.NewReader("PIN=5\tphoto=...\n"),
	)
	rec := httptest.NewRecorder()

	s.handleCData(rec, req)

	if got := strings.TrimSpace(rec.Body.String()); got != "OK" {
		t.Fatalf("tablename=ATTPHOTO ack = %q; want \"OK\"", got)
	}
}

func TestHandleCDataTAPushAttendanceReturnsAcceptedCount(t *testing.T) {
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer cloud.Close()

	tracker := newDeviceTracker()
	tracker.observeProtocol("TA1", ProtocolObservation{
		Path:        "/iclock/cdata",
		PushVersion: "2.4.1",
	})
	server := &ADMSServer{agent: &Agent{
		config:  Config{PlamatixURL: cloud.URL},
		devices: tracker,
	}}
	request := httptest.NewRequest(
		http.MethodPost,
		"/iclock/cdata?SN=TA1&table=ATTLOG",
		strings.NewReader("1\t2026-07-27 08:00:00\t0\t1\t0\n"),
	)
	recorder := httptest.NewRecorder()

	server.handleCData(recorder, request)

	if got := strings.TrimSpace(recorder.Body.String()); got != "OK:1" {
		t.Fatalf("TA attendance ack = %q; want \"OK:1\"", got)
	}
}

func TestHandleCDataTAPushFingerTmpReportsMetadataWithoutTemplate(t *testing.T) {
	metadata := make(chan map[string]any, 1)
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode biometric metadata: %v", err)
		}
		metadata <- payload
		w.WriteHeader(http.StatusOK)
	}))
	defer cloud.Close()

	tracker := newDeviceTracker()
	tracker.observeProtocol("TA2", ProtocolObservation{
		Path:        "/iclock/cdata",
		PushVersion: "2.4.1",
	})
	server := &ADMSServer{agent: &Agent{
		config:  Config{PlamatixURL: cloud.URL},
		devices: tracker,
	}}
	request := httptest.NewRequest(
		http.MethodPost,
		"/iclock/cdata?SN=TA2&table=FINGERTMP",
		strings.NewReader("PIN=14\tFID=3\tSize=4\tValid=1\tTMP=SECRET_TEMPLATE\n"),
	)
	recorder := httptest.NewRecorder()

	server.handleCData(recorder, request)

	if got := strings.TrimSpace(recorder.Body.String()); got != "OK:1" {
		t.Fatalf("FINGERTMP ack = %q; want \"OK:1\"", got)
	}
	select {
	case payload := <-metadata:
		if payload["pin"] != "14" || payload["bioType"] != float64(1) ||
			payload["templateNo"] != float64(3) {
			t.Fatalf("metadata payload = %#v", payload)
		}
		encoded, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), "SECRET_TEMPLATE") ||
			strings.Contains(strings.ToUpper(string(encoded)), "\"TMP\"") {
			t.Fatalf("metadata leaked template data: %s", encoded)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for biometric metadata")
	}
}
