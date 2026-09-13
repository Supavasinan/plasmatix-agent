package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Importing templates already on a scanner: Plasmatix issues one labelled
// "DATA QUERY USERINFO PIN=x" per employee, and the templates in the reply
// must reach the vault tagged with that query — and nothing else may.

const (
	importQueryCloudID = "44444444-4444-4444-8444-444444444444"
	importQueryLabel   = "biometric-import:33333333-3333-4333-8333-333333333333"
)

type capturedUpload struct {
	pin       string
	commandID string
	slot      string
	body      []byte
}

func newImportTestServer(t *testing.T) (*ADMSServer, <-chan capturedUpload, func()) {
	t.Helper()
	uploads := make(chan capturedUpload, 16)
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.URL.Path == "/api/agent-bridge/biometric-vault/capture" {
			uploads <- capturedUpload{
				pin:       r.Header.Get("X-Personnel-ID"),
				commandID: r.Header.Get("X-Capture-Command-ID"),
				slot:      r.Header.Get("X-Slot-Index"),
				body:      body,
			}
			w.WriteHeader(http.StatusCreated)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	tracker := newDeviceTracker()
	tracker.observeProtocol("NYU1", ProtocolObservation{
		Path:        "/iclock/cdata",
		PushVersion: "2.4.1",
		Capabilities: map[string]string{
			"fingeralgorithmversion": "13.0",
			"facealgorithmversion":   "40.1",
		},
	})
	server := &ADMSServer{
		agent: &Agent{
			config:  Config{PlamatixURL: cloud.URL, APIKey: "secret"},
			devices: tracker,
		},
		cmdQueue:     make(map[string][]ADMSCommand),
		pendingCmd:   make(map[pendingCommandKey]ADMSCommand),
		cloudCmdID:   make(map[string]struct{}),
		queryBuffers: make(map[string][]byte),
	}
	return server, uploads, cloud.Close
}

// serveImportQuery puts the server in the state it is in right after handing
// the query to the device: pending, and remembered for capture.
func serveImportQuery(server *ADMSServer, localID int, pin, label string) {
	cmd := ADMSCommand{
		ID:      localID,
		Command: "DATA QUERY USERINFO PIN=" + pin,
		CloudID: importQueryCloudID,
		Label:   label,
	}
	server.mu.Lock()
	server.pendingCmd[pendingCommandKey{DeviceSN: "NYU1", LocalID: localID}] = cmd
	server.cloudCmdID[importQueryCloudID] = struct{}{}
	server.rememberBiometricCaptureCommandLocked("NYU1", cmd)
	server.mu.Unlock()
}

func postQueryData(server *ADMSServer, query, body string) {
	server.handleQueryData(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/iclock/querydata?SN=NYU1"+query, strings.NewReader(body)),
	)
}

func fingerprintRow(pin string, slot string) string {
	return "Pin=" + pin + "\tNo=" + slot + "\tIndex=0\tValid=1\tDuress=0\tType=1\tMajorVer=13\tMinorVer=0\tFormat=0\tTmp=QUJDRA=="
}

func expectUploads(t *testing.T, uploads <-chan capturedUpload, want int) []capturedUpload {
	t.Helper()
	got := make([]capturedUpload, 0, want)
	for len(got) < want {
		select {
		case upload := <-uploads:
			got = append(got, upload)
		case <-time.After(2 * time.Second):
			t.Fatalf("received %d uploads, want %d", len(got), want)
		}
	}
	return got
}

func expectNoUpload(t *testing.T, uploads <-chan capturedUpload) {
	t.Helper()
	select {
	case upload := <-uploads:
		t.Fatalf("unexpected upload for PIN=%q commandID=%q", upload.pin, upload.commandID)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestImportQueryReplyUploadsEveryFingerTaggedWithTheQuery(t *testing.T) {
	server, uploads, done := newImportTestServer(t)
	defer done()
	serveImportQuery(server, 1, "8", importQueryLabel)

	postQueryData(server, "&cmdid=1&tablename=BIODATA&packcnt=1&packidx=1",
		fingerprintRow("8", "0")+"\n"+fingerprintRow("8", "6"))

	got := expectUploads(t, uploads, 2)
	slots := map[string]bool{}
	for _, upload := range got {
		if upload.pin != "8" || upload.commandID != importQueryCloudID {
			t.Fatalf("upload PIN=%q commandID=%q; want PIN 8 tagged with the query", upload.pin, upload.commandID)
		}
		if string(upload.body) != "ABCD" {
			t.Fatalf("uploaded %q; want the decoded template bytes", upload.body)
		}
		slots[upload.slot] = true
	}
	if !slots["0"] || !slots["6"] {
		t.Fatalf("uploaded slots %v; want 0 and 6", slots)
	}
}

// The scanner must not be able to slip someone else's fingerprint into an
// import: only rows for the PIN the query named are sent to the vault.
func TestImportQueryReplyDropsTemplatesForOtherPeople(t *testing.T) {
	server, uploads, done := newImportTestServer(t)
	defer done()
	serveImportQuery(server, 1, "8", importQueryLabel)

	postQueryData(server, "&cmdid=1&tablename=BIODATA&packcnt=1&packidx=1",
		fingerprintRow("9", "0")+"\n"+fingerprintRow("8", "1"))

	got := expectUploads(t, uploads, 1)
	if got[0].pin != "8" {
		t.Fatalf("uploaded PIN=%q; want only the queried PIN 8", got[0].pin)
	}
	expectNoUpload(t, uploads)
}

func TestUserQueryNotIssuedByAnImportUploadsNothing(t *testing.T) {
	for _, label := range []string{"", "wake device", "biometric-import:"} {
		server, uploads, done := newImportTestServer(t)
		serveImportQuery(server, 1, "8", label)

		postQueryData(server, "&cmdid=1&tablename=BIODATA&packcnt=1&packidx=1", fingerprintRow("8", "0"))

		expectNoUpload(t, uploads)
		done()
	}
}

// A person the scanner does not know answers with a failed result; nothing
// may be captured under that query afterwards.
func TestFailedImportQueryAuthorisesNothing(t *testing.T) {
	server, uploads, done := newImportTestServer(t)
	defer done()
	serveImportQuery(server, 1, "8", importQueryLabel)

	server.handleDeviceCmd(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/iclock/devicecmd?SN=NYU1", strings.NewReader("ID=1&Return=-1&CMD=DATA")),
	)
	postQueryData(server, "&cmdid=1&tablename=BIODATA&packcnt=1&packidx=1", fingerprintRow("8", "0"))

	expectNoUpload(t, uploads)
}

func TestImportQueryReplyWaitsForTheFinalPack(t *testing.T) {
	server, uploads, done := newImportTestServer(t)
	defer done()
	serveImportQuery(server, 1, "8", importQueryLabel)

	postQueryData(server, "&cmdid=1&tablename=BIODATA&packcnt=2&packidx=1", fingerprintRow("8", "0")+"\n")
	expectNoUpload(t, uploads)

	postQueryData(server, "&cmdid=1&tablename=BIODATA&packcnt=2&packidx=2", fingerprintRow("8", "1"))
	got := expectUploads(t, uploads, 2)
	for _, upload := range got {
		if upload.commandID != importQueryCloudID {
			t.Fatalf("upload not tagged with the import query: %q", upload.commandID)
		}
	}
}

// Some firmwares answer a query by pushing the template table through cdata
// instead; those rows must be tagged the same way.
func TestCDataTemplatePushAnsweringAnImportQueryIsTagged(t *testing.T) {
	server, uploads, done := newImportTestServer(t)
	defer done()
	serveImportQuery(server, 1, "8", importQueryLabel)

	server.handleCData(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/iclock/cdata?SN=NYU1&table=tabledata&tablename=BIODATA", strings.NewReader(fingerprintRow("8", "3"))),
	)

	got := expectUploads(t, uploads, 1)
	if got[0].pin != "8" || got[0].commandID != importQueryCloudID {
		t.Fatalf("cdata upload PIN=%q commandID=%q; want tagged with the import query", got[0].pin, got[0].commandID)
	}
}

func TestImportQueryAuthorisationExpires(t *testing.T) {
	server, uploads, done := newImportTestServer(t)
	defer done()
	serveImportQuery(server, 1, "8", importQueryLabel)
	server.mu.Lock()
	for key, record := range server.importQuery {
		record.Recorded = time.Now().Add(-11 * time.Minute)
		server.importQuery[key] = record
	}
	server.mu.Unlock()

	postQueryData(server, "&cmdid=1&tablename=BIODATA&packcnt=1&packidx=1", fingerprintRow("8", "0"))

	expectNoUpload(t, uploads)
}

// The result reported back for a biometric query stays a constant marker.
// Importing must not start leaking template bytes into command results.
func TestImportQueryResultStaysRedacted(t *testing.T) {
	server, _, done := newImportTestServer(t)
	defer done()
	serveImportQuery(server, 1, "8", importQueryLabel)
	if got := trustedQueryResultBody("DATA QUERY USERINFO PIN=8", []byte(fingerprintRow("8", "0"))); strings.Contains(got, "QUJDRA") {
		t.Fatalf("query result leaked template bytes: %q", got)
	}
}
