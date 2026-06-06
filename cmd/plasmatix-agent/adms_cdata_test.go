package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
