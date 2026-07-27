package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type synchronizedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (buffer *synchronizedBuffer) Write(value []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.buffer.Write(value)
}

func (buffer *synchronizedBuffer) String() string {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.buffer.String()
}

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
	vaultRequests := make(chan struct{}, 1)
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/agent-bridge/biometric-vault/capture" {
			vaultRequests <- struct{}{}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"biometric_vault_disabled"}`))
			return
		}
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
		strings.NewReader("PIN=14\tFID=3\tSize=15\tValid=1\tTMP=U0VDUkVUX1RFTVBMQVRF\n"),
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
	select {
	case <-vaultRequests:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for vault feature probe")
	}
}

func TestHandleCDataDoesNotFallbackForOtherVaultErrors(t *testing.T) {
	metadataRequests := make(chan struct{}, 1)
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/agent-bridge/biometric-template" {
			metadataRequests <- struct{}{}
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`TMP=QUJDRA==`))
	}))
	defer cloud.Close()

	var logs synchronizedBuffer
	originalOutput := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(originalOutput) })

	tracker := newDeviceTracker()
	tracker.observeProtocol("TA3", ProtocolObservation{
		Path:         "/iclock/cdata",
		PushVersion:  "2.4.1",
		Capabilities: map[string]string{"fingeralgorithmversion": "10.0"},
	})
	server := &ADMSServer{agent: &Agent{
		config:  Config{PlamatixURL: cloud.URL},
		devices: tracker,
	}}
	request := httptest.NewRequest(
		http.MethodPost,
		"/iclock/cdata?SN=TA3&table=FINGERTMP",
		strings.NewReader("PIN=14\tFID=3\tTMP=QUJDRA==\n"),
	)

	server.handleCData(httptest.NewRecorder(), request)

	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(logs.String(), "vault capture failed") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	select {
	case <-metadataRequests:
		t.Fatal("metadata-only endpoint called for a non-disabled vault failure")
	default:
	}
	if strings.Contains(logs.String(), "QUJDRA") || strings.Contains(logs.String(), "ABCD") {
		t.Fatalf("logs leaked biometric bytes: %s", logs.String())
	}
}

func TestHandleCDataUploadsEveryBioDataRow(t *testing.T) {
	type upload struct {
		body    []byte
		headers http.Header
	}
	uploads := make(chan upload, 2)
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		uploads <- upload{body: body, headers: r.Header.Clone()}
		w.WriteHeader(http.StatusCreated)
	}))
	defer cloud.Close()

	tracker := newDeviceTracker()
	tracker.observeProtocol("AC1", ProtocolObservation{
		Path: "/iclock/registry",
		Capabilities: map[string]string{
			"fingeralgorithmversion": "12.1",
			"facealgorithmversion":   "7.4",
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
	request := httptest.NewRequest(
		http.MethodPost,
		"/iclock/cdata?SN=AC1&type=BioData",
		strings.NewReader(strings.Join([]string{
			"Pin=14\tNo=2\tType=1\tMajorVer=12\tMinorVer=1\tFormat=templatev12\tTmp=QUJDRA==",
			"Pin=15\tNo=0\tType=9\tMajorVer=7\tMinorVer=4\tFormat=facev7\tTmp=RUZHSA==",
		}, "\n")),
	)

	server.handleCData(httptest.NewRecorder(), request)

	seen := make(map[string][]byte)
	for range 2 {
		select {
		case captured := <-uploads:
			seen[captured.headers.Get("X-Personnel-ID")] = captured.body
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for all BIODATA uploads")
		}
	}
	if !bytes.Equal(seen["14"], []byte("ABCD")) || !bytes.Equal(seen["15"], []byte("EFGH")) {
		t.Fatalf("uploaded decoded byte sizes = %d/%d; want 4/4", len(seen["14"]), len(seen["15"]))
	}
}

func TestHandleCDataRejectsOversizedBiometricRequestBeforeUpload(t *testing.T) {
	uploads := make(chan struct{}, 1)
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		uploads <- struct{}{}
		w.WriteHeader(http.StatusCreated)
	}))
	defer cloud.Close()

	tracker := newDeviceTracker()
	server := &ADMSServer{agent: &Agent{
		config:  Config{PlamatixURL: cloud.URL},
		devices: tracker,
	}}
	body := &trackingZeroReader{remaining: 16 * 1024 * 1024}
	request := httptest.NewRequest(
		http.MethodPost,
		"/iclock/cdata?SN=AC2&type=BioPhoto",
		body,
	)

	server.handleCData(httptest.NewRecorder(), request)

	if body.read > 8*1024*1024+1 {
		t.Fatalf("read %d biometric request bytes; want a bounded read", body.read)
	}
	select {
	case <-uploads:
		t.Fatal("oversized biometric request reached the cloud")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestCaptureBiometricUploadsLimitsConcurrentRequests(t *testing.T) {
	var active atomic.Int32
	var maximum atomic.Int32
	started := make(chan struct{}, 8)
	finished := make(chan struct{}, 8)
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })

	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		current := active.Add(1)
		defer active.Add(-1)
		defer func() { finished <- struct{}{} }()
		for {
			observed := maximum.Load()
			if current <= observed || maximum.CompareAndSwap(observed, current) {
				break
			}
		}
		started <- struct{}{}
		<-release
		w.WriteHeader(http.StatusCreated)
	}))
	defer cloud.Close()

	tracker := newDeviceTracker()
	tracker.observeProtocol("TA4", ProtocolObservation{
		Path:         "/iclock/cdata",
		PushVersion:  "2.4.1",
		Capabilities: map[string]string{"fingeralgorithmversion": "10.0"},
	})
	server := &ADMSServer{agent: &Agent{
		config:  Config{PlamatixURL: cloud.URL},
		devices: tracker,
	}}
	rows := make([]string, 8)
	for index := range rows {
		rows[index] = "PIN=" + strconv.Itoa(index+1) + "\tFID=0\tTMP=QUJDRA=="
	}
	returned := make(chan struct{})
	go func() {
		server.captureBiometricUploads("TA4", "FINGERTMP", []byte(strings.Join(rows, "\n")))
		close(returned)
	}()

	for range 4 {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for initial bounded uploads")
		}
	}
	tooManyStarted := false
	select {
	case <-started:
		tooManyStarted = true
	case <-time.After(50 * time.Millisecond):
	}
	returnedPromptly := false
	select {
	case <-returned:
		returnedPromptly = true
	case <-time.After(50 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(release) })
	if !returnedPromptly {
		select {
		case <-returned:
		case <-time.After(2 * time.Second):
			t.Fatal("bounded upload dispatcher did not finish")
		}
	}
	for range 8 {
		select {
		case <-finished:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for biometric uploads to finish")
		}
	}
	if tooManyStarted {
		t.Fatal("more than four biometric uploads ran concurrently")
	}
	if !returnedPromptly {
		t.Fatal("biometric handler waited for upload capacity instead of using bounded admission")
	}
	if maximum.Load() > 4 {
		t.Fatalf("maximum concurrent uploads = %d; want at most 4", maximum.Load())
	}
}

func TestQueuedBiometricUploadResolvesCommandAfterFailedEnrollment(t *testing.T) {
	type observedCapture struct {
		pin       string
		commandID string
	}
	started := make(chan struct{}, 5)
	captured := make(chan observedCapture, 5)
	release := make(chan struct{})
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-release
		captured <- observedCapture{
			pin:       r.Header.Get("X-Personnel-ID"),
			commandID: r.Header.Get("X-Capture-Command-ID"),
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer cloud.Close()

	tracker := newDeviceTracker()
	tracker.observeProtocol("TA7", ProtocolObservation{
		Path:         "/iclock/cdata",
		PushVersion:  "2.4.1",
		Capabilities: map[string]string{"fingeralgorithmversion": "10.0"},
	})
	commandID := "11111111-1111-4111-8111-111111111111"
	key := biometricCaptureKey{DeviceSN: "TA7", PIN: "14", BioType: 1, Slot: 3}
	server := &ADMSServer{
		agent: &Agent{
			config:  Config{PlamatixURL: cloud.URL},
			devices: tracker,
		},
		captureCmd: map[biometricCaptureKey]pendingBiometricCapture{
			key: {CloudID: commandID, Recorded: time.Now()},
		},
	}
	body := strings.Join([]string{
		"PIN=1\tFID=0\tTMP=QUJDRA==",
		"PIN=2\tFID=0\tTMP=QUJDRA==",
		"PIN=3\tFID=0\tTMP=QUJDRA==",
		"PIN=4\tFID=0\tTMP=QUJDRA==",
		"PIN=14\tFID=3\tTMP=QUJDRA==",
	}, "\n")
	returned := make(chan struct{})
	go func() {
		server.captureBiometricUploads("TA7", "FINGERTMP", []byte(body))
		close(returned)
	}()
	for range 4 {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			close(release)
			t.Fatal("timed out filling biometric workers")
		}
	}

	server.mu.Lock()
	server.forgetBiometricCaptureCommandLocked(commandID)
	server.mu.Unlock()
	close(release)

	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("biometric capture dispatcher did not return")
	}
	var queued observedCapture
	for range 5 {
		select {
		case capture := <-captured:
			if capture.pin == "14" {
				queued = capture
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for queued capture")
		}
	}
	if queued.pin != "14" {
		t.Fatal("queued enrollment capture was not uploaded")
	}
	if queued.commandID != "" {
		t.Fatalf("queued capture used stale failed command ID %q", queued.commandID)
	}
}

func TestQueuedUncorrelatedBiometricUploadDoesNotBindNewerCommand(t *testing.T) {
	type observedCapture struct {
		pin       string
		commandID string
	}
	started := make(chan struct{}, 5)
	captured := make(chan observedCapture, 5)
	release := make(chan struct{})
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-release
		captured <- observedCapture{
			pin:       r.Header.Get("X-Personnel-ID"),
			commandID: r.Header.Get("X-Capture-Command-ID"),
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer cloud.Close()

	tracker := newDeviceTracker()
	tracker.observeProtocol("TA9", ProtocolObservation{
		Path:         "/iclock/cdata",
		PushVersion:  "2.4.1",
		Capabilities: map[string]string{"fingeralgorithmversion": "10.0"},
	})
	server := &ADMSServer{agent: &Agent{
		config:  Config{PlamatixURL: cloud.URL},
		devices: tracker,
	}}
	body := strings.Join([]string{
		"PIN=1\tFID=0\tTMP=QUJDRA==",
		"PIN=2\tFID=0\tTMP=QUJDRA==",
		"PIN=3\tFID=0\tTMP=QUJDRA==",
		"PIN=4\tFID=0\tTMP=QUJDRA==",
		"PIN=14\tFID=3\tTMP=QUJDRA==",
	}, "\n")
	server.captureBiometricUploads("TA9", "FINGERTMP", []byte(body))
	for range 4 {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			close(release)
			t.Fatal("timed out filling biometric workers")
		}
	}

	commandID := "11111111-1111-4111-8111-111111111111"
	server.mu.Lock()
	if server.captureCmd == nil {
		server.captureCmd = make(map[biometricCaptureKey]pendingBiometricCapture)
	}
	server.captureCmd[biometricCaptureKey{
		DeviceSN: "TA9",
		PIN:      "14",
		BioType:  1,
		Slot:     3,
	}] = pendingBiometricCapture{CloudID: commandID, Recorded: time.Now()}
	server.mu.Unlock()
	close(release)

	var queued observedCapture
	for range 5 {
		select {
		case capture := <-captured:
			if capture.pin == "14" {
				queued = capture
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for queued capture")
		}
	}
	if queued.pin != "14" {
		t.Fatal("queued enrollment capture was not uploaded")
	}
	if queued.commandID != "" {
		t.Fatalf("previously uncorrelated capture bound newer command ID %q", queued.commandID)
	}
}

func TestCaptureBiometricUploadsRejectsWorkBeyondBoundedQueue(t *testing.T) {
	started := make(chan struct{}, 32)
	finished := make(chan struct{}, 32)
	release := make(chan struct{})
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		started <- struct{}{}
		<-release
		w.WriteHeader(http.StatusCreated)
		finished <- struct{}{}
	}))
	defer cloud.Close()

	tracker := newDeviceTracker()
	tracker.observeProtocol("TA8", ProtocolObservation{
		Path:         "/iclock/cdata",
		PushVersion:  "2.4.1",
		Capabilities: map[string]string{"fingeralgorithmversion": "10.0"},
	})
	server := &ADMSServer{agent: &Agent{
		config:  Config{PlamatixURL: cloud.URL},
		devices: tracker,
	}}
	firstRows := make([]string, 4)
	for index := range firstRows {
		firstRows[index] = "PIN=" + strconv.Itoa(index+1) + "\tFID=0\tTMP=QUJDRA=="
	}
	server.captureBiometricUploads("TA8", "FINGERTMP", []byte(strings.Join(firstRows, "\n")))
	for range 4 {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			close(release)
			t.Fatal("timed out filling biometric workers")
		}
	}

	queuedRows := make([]string, 17)
	for index := range queuedRows {
		queuedRows[index] = "PIN=" + strconv.Itoa(index+10) + "\tFID=0\tTMP=QUJDRA=="
	}
	server.captureBiometricUploads("TA8", "FINGERTMP", []byte(strings.Join(queuedRows, "\n")))
	close(release)

	for range 20 {
		select {
		case <-finished:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out draining bounded biometric queue")
		}
	}
	select {
	case <-finished:
		t.Fatal("biometric queue admitted work beyond four active and sixteen queued uploads")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestBiometricUploadShutdownCancelsWorkersAndZeroesQueue(t *testing.T) {
	started := make(chan struct{}, maxConcurrentBiometricUploads)
	releaseHandlers := make(chan struct{})
	cloud := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		select {
		case <-r.Context().Done():
		case <-releaseHandlers:
		}
	}))
	t.Cleanup(func() {
		close(releaseHandlers)
		cloud.Close()
	})

	server := &ADMSServer{agent: &Agent{config: Config{PlamatixURL: cloud.URL}}}
	buffers := make([][]byte, maxConcurrentBiometricUploads+2)
	for index := range buffers {
		buffers[index] = []byte("ABCD")
		asset := CapturedBiometricAsset{
			DeviceSN:        "TA-SHUTDOWN",
			PIN:             strconv.Itoa(index + 1),
			BioType:         1,
			SlotIndex:       0,
			AssetKind:       "fingerprint_template",
			AlgorithmFamily: "zkfinger-v10",
			AlgorithmMajor:  10,
			AlgorithmMinor:  0,
			AssetFormat:     "templatev10",
			Bytes:           buffers[index],
		}
		if !server.enqueueBiometricUpload(biometricUploadJob{
			asset:    asset,
			metadata: asset.SafeMetadata(),
		}) {
			t.Fatal("initial shutdown test work was not admitted")
		}
	}
	for range maxConcurrentBiometricUploads {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for biometric workers")
		}
	}

	shutdownDone := make(chan struct{})
	go func() {
		server.shutdownBiometricUploads()
		close(shutdownDone)
	}()
	select {
	case <-shutdownDone:
	case <-time.After(2 * time.Second):
		t.Fatal("biometric worker shutdown did not cancel active uploads")
	}

	for index, buffer := range buffers {
		for _, value := range buffer {
			if value != 0 {
				t.Fatalf("buffer %d was not zeroed during shutdown", index)
			}
		}
	}
	rejected := CapturedBiometricAsset{Bytes: []byte("EFGH")}
	if server.enqueueBiometricUpload(biometricUploadJob{asset: rejected}) {
		t.Fatal("shutdown queue admitted new work")
	}
	zeroBytes(rejected.Bytes)
}

func TestBiometricUploadShutdownIsRaceSafeWithAdmission(t *testing.T) {
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		default:
			w.WriteHeader(http.StatusCreated)
		}
	}))
	defer cloud.Close()

	server := &ADMSServer{agent: &Agent{config: Config{PlamatixURL: cloud.URL}}}
	buffers := make([][]byte, 64)
	var admissions sync.WaitGroup
	for index := range buffers {
		buffers[index] = []byte("ABCD")
		admissions.Add(1)
		go func(index int) {
			defer admissions.Done()
			asset := CapturedBiometricAsset{
				DeviceSN:        "TA-RACE",
				PIN:             strconv.Itoa(index + 1),
				BioType:         1,
				SlotIndex:       0,
				AssetKind:       "fingerprint_template",
				AlgorithmFamily: "zkfinger-v10",
				AlgorithmMajor:  10,
				AlgorithmMinor:  0,
				AssetFormat:     "templatev10",
				Bytes:           buffers[index],
			}
			if !server.enqueueBiometricUpload(biometricUploadJob{
				asset:    asset,
				metadata: asset.SafeMetadata(),
			}) {
				zeroBytes(asset.Bytes)
			}
		}(index)
	}
	server.shutdownBiometricUploads()
	admissions.Wait()
	server.shutdownBiometricUploads()

	for index, buffer := range buffers {
		for _, value := range buffer {
			if value != 0 {
				t.Fatalf("buffer %d was not zeroed after concurrent shutdown", index)
			}
		}
	}
}

func TestHandleCDataCorrelatesServedEnrollmentCommand(t *testing.T) {
	captureCommandID := make(chan string, 1)
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/agent-bridge/commands":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"commands":[]}`))
		case "/api/agent-bridge/biometric-vault/capture":
			captureCommandID <- r.Header.Get("X-Capture-Command-ID")
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer cloud.Close()

	tracker := newDeviceTracker()
	tracker.observeProtocol("TA5", ProtocolObservation{
		Path:         "/iclock/cdata",
		PushVersion:  "2.4.1",
		Capabilities: map[string]string{"fingeralgorithmversion": "10.0"},
	})
	server := &ADMSServer{
		agent: &Agent{
			config:  Config{PlamatixURL: cloud.URL},
			devices: tracker,
		},
		cmdQueue:     make(map[string][]ADMSCommand),
		pendingCmd:   make(map[pendingCommandKey]ADMSCommand),
		cloudCmdID:   make(map[string]struct{}),
		queryBuffers: make(map[string][]byte),
	}
	commandID := "11111111-1111-4111-8111-111111111111"
	server.enqueueADMSCommand(
		"TA5",
		"ENROLL_BIO TYPE=1\tNO=3\tPIN=14",
		commandID,
		"enroll",
	)
	server.handleGetRequest(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/iclock/getrequest?SN=TA5", nil),
	)
	server.handleCData(
		httptest.NewRecorder(),
		httptest.NewRequest(
			http.MethodPost,
			"/iclock/cdata?SN=TA5&table=FINGERTMP",
			strings.NewReader("PIN=14\tFID=3\tTMP=QUJDRA=="),
		),
	)

	select {
	case got := <-captureCommandID:
		if got != commandID {
			t.Fatalf("capture command ID = %q; want %q", got, commandID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for correlated capture")
	}
}

func TestBiometricCaptureCommandCorrelationFailsClosed(t *testing.T) {
	validID := "11111111-1111-4111-8111-111111111111"
	matchingAsset := CapturedBiometricAsset{
		DeviceSN:  "TA6",
		PIN:       "14",
		BioType:   1,
		SlotIndex: 3,
	}
	tests := []struct {
		name    string
		cloudID string
		record  pendingBiometricCapture
		asset   CapturedBiometricAsset
	}{
		{
			name:    "expired",
			cloudID: validID,
			record: pendingBiometricCapture{
				CloudID:  validID,
				Recorded: time.Now().Add(-11 * time.Minute),
			},
			asset: matchingAsset,
		},
		{
			name:    "mismatched personnel",
			cloudID: validID,
			record: pendingBiometricCapture{
				CloudID:  validID,
				Recorded: time.Now(),
			},
			asset: func() CapturedBiometricAsset {
				asset := matchingAsset
				asset.PIN = "15"
				return asset
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := &ADMSServer{captureCmd: map[biometricCaptureKey]pendingBiometricCapture{
				{
					DeviceSN: "TA6",
					PIN:      "14",
					BioType:  1,
					Slot:     3,
				}: tt.record,
			}}
			if got := server.biometricCaptureCommandID(tt.asset); got != "" {
				t.Fatalf("capture command ID = %q; want no correlation", got)
			}
		})
	}

	server := &ADMSServer{
		captureCmd: make(map[biometricCaptureKey]pendingBiometricCapture),
	}
	server.rememberBiometricCaptureCommandLocked("TA6", ADMSCommand{
		Command: "ENROLL_BIO TYPE=1 NO=3 PIN=14",
		CloudID: "not-a-uuid",
	})
	if got := server.biometricCaptureCommandID(matchingAsset); got != "" {
		t.Fatalf("malformed capture command ID was correlated: %q", got)
	}
	server.rememberBiometricCaptureCommandLocked("TA6", ADMSCommand{
		Command: "ENROLL_BIO TYPE=1 NO=invalid PIN=14",
		CloudID: validID,
	})
	slotZeroAsset := matchingAsset
	slotZeroAsset.SlotIndex = 0
	if got := server.biometricCaptureCommandID(slotZeroAsset); got != "" {
		t.Fatalf("malformed enrollment metadata was correlated: %q", got)
	}

	key := biometricCaptureKey{DeviceSN: "TA6", PIN: "14", BioType: 1, Slot: 3}
	server = &ADMSServer{
		agent: &Agent{},
		pendingCmd: map[pendingCommandKey]ADMSCommand{
			{DeviceSN: "TA6", LocalID: 1}: {ID: 1, CloudID: validID},
		},
		cloudCmdID: map[string]struct{}{validID: {}},
		captureCmd: map[biometricCaptureKey]pendingBiometricCapture{
			key: {CloudID: validID, Recorded: time.Now()},
		},
	}
	server.handleDeviceCmd(
		httptest.NewRecorder(),
		httptest.NewRequest(
			http.MethodPost,
			"/iclock/devicecmd?SN=TA6",
			strings.NewReader("ID=1&Return=-1"),
		),
	)
	if got := server.biometricCaptureCommandID(matchingAsset); got != "" {
		t.Fatalf("failed enrollment command remained correlated: %q", got)
	}
}

func TestDeviceCommandResultBindsDeviceAndFailsClosedOnReturn(t *testing.T) {
	type reportedResult struct {
		ReturnCode int    `json:"returnCode"`
		ResultBody string `json:"resultBody"`
	}
	reported := make(chan reportedResult, 4)
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var result reportedResult
		if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
			t.Errorf("decode command result: %v", err)
		}
		reported <- result
		w.WriteHeader(http.StatusOK)
	}))
	defer cloud.Close()

	validID := "11111111-1111-4111-8111-111111111111"
	captureKey := biometricCaptureKey{DeviceSN: "TA6", PIN: "14", BioType: 1, Slot: 3}
	newServer := func() *ADMSServer {
		return &ADMSServer{
			agent: &Agent{config: Config{PlamatixURL: cloud.URL}},
			pendingCmd: map[pendingCommandKey]ADMSCommand{
				{DeviceSN: "TA6", LocalID: 1}: {ID: 1, CloudID: validID},
			},
			cloudCmdID: map[string]struct{}{validID: {}},
			captureCmd: map[biometricCaptureKey]pendingBiometricCapture{
				captureKey: {CloudID: validID, Recorded: time.Now()},
			},
		}
	}

	crossDevice := newServer()
	crossDevice.handleDeviceCmd(
		httptest.NewRecorder(),
		httptest.NewRequest(
			http.MethodPost,
			"/iclock/devicecmd?SN=OTHER",
			strings.NewReader("ID=1&Return=0"),
		),
	)
	if len(crossDevice.pendingCmd) != 1 || len(crossDevice.captureCmd) != 1 {
		t.Fatal("cross-device result mutated another device command")
	}
	select {
	case result := <-reported:
		t.Fatalf("cross-device result was reported: %#v", result)
	case <-time.After(50 * time.Millisecond):
	}

	tests := []struct {
		name       string
		body       string
		wantReturn int
	}{
		{name: "missing return", body: "ID=1", wantReturn: -1},
		{name: "malformed return", body: "ID=1&Return=not-an-int", wantReturn: -1},
		{name: "failing return", body: "ID=1&Return=-7", wantReturn: -7},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newServer()
			server.handleDeviceCmd(
				httptest.NewRecorder(),
				httptest.NewRequest(
					http.MethodPost,
					"/iclock/devicecmd?SN=TA6",
					strings.NewReader(tt.body+"&Template=QUJDRA==&arbitrary=plaintext"),
				),
			)
			if len(server.pendingCmd) != 0 || len(server.captureCmd) != 0 {
				t.Fatal("failed command result retained pending capture state")
			}
			select {
			case result := <-reported:
				if result.ReturnCode != tt.wantReturn {
					t.Fatalf("reported Return = %d; want %d", result.ReturnCode, tt.wantReturn)
				}
				if strings.Contains(result.ResultBody, "QUJDRA") ||
					strings.Contains(result.ResultBody, "plaintext") {
					t.Fatalf("reported unsafe command result body %q", result.ResultBody)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("timed out waiting for command result")
			}
		})
	}
}

func TestQueryResultReportsWholeMultilineJSONWithBiometricsRedacted(t *testing.T) {
	type reportedResult struct {
		ResultBody string `json:"resultBody"`
	}
	reported := make(chan reportedResult, 1)
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var result reportedResult
		if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
			t.Errorf("decode command result: %v", err)
		}
		reported <- result
		w.WriteHeader(http.StatusOK)
	}))
	defer cloud.Close()

	server := &ADMSServer{
		agent: &Agent{
			config:  Config{PlamatixURL: cloud.URL},
			devices: newDeviceTracker(),
		},
		pendingCmd: map[pendingCommandKey]ADMSCommand{
			{DeviceSN: "TA6", LocalID: 1}: {
				ID:      1,
				CloudID: "11111111-1111-4111-8111-111111111111",
			},
		},
		cloudCmdID: map[string]struct{}{
			"11111111-1111-4111-8111-111111111111": {},
		},
		queryBuffers: make(map[string][]byte),
	}
	body := `{
  "rows": [
    {"PIN":"14","template":"QUJDRA==","attackerField":"U0VDUkVU"},
    {"photo":{"raw":"RUZHSA=="}}
  ]
}`
	server.handleQueryData(
		httptest.NewRecorder(),
		httptest.NewRequest(
			http.MethodPost,
			"/iclock/querydata?SN=TA6&cmdid=1&tablename=BIODATA&packcnt=1&packidx=1",
			strings.NewReader(body),
		),
	)

	select {
	case result := <-reported:
		if strings.Contains(result.ResultBody, "QUJDRA==") ||
			strings.Contains(result.ResultBody, "RUZHSA==") ||
			strings.Contains(result.ResultBody, "U0VDUkVU") {
			t.Fatalf("query result leaked biometric content: %q", result.ResultBody)
		}
		if result.ResultBody != "[REDACTED:BIOMETRIC_QUERY_RESULT]" {
			t.Fatalf("query result = %q; want constant biometric marker", result.ResultBody)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for query result")
	}
}

func TestBiometricHandlersNeverLogRawQueryOrUnvalidatedCommandNumbers(t *testing.T) {
	var output synchronizedBuffer
	original := log.Writer()
	log.SetOutput(&output)
	t.Cleanup(func() { log.SetOutput(original) })

	secret := "U0VDUkVU"
	server := &ADMSServer{
		agent:    &Agent{devices: newDeviceTracker()},
		cmdQueue: make(map[string][]ADMSCommand),
		pendingCmd: map[pendingCommandKey]ADMSCommand{
			{DeviceSN: "TA6", LocalID: 1}: {ID: 1},
		},
		cloudCmdID:   make(map[string]struct{}),
		queryBuffers: make(map[string][]byte),
	}
	server.handleCData(
		httptest.NewRecorder(),
		httptest.NewRequest(
			http.MethodPost,
			"/iclock/cdata?table=UNKNOWN&SN="+strings.Repeat(secret, 12)+"&secret="+secret,
			nil,
		),
	)
	server.handleGetRequest(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/iclock/getrequest?secret="+secret, nil),
	)
	server.handleICLockFallback(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/iclock/unknown?secret="+secret, nil),
	)
	server.handleDeviceCmd(
		httptest.NewRecorder(),
		httptest.NewRequest(
			http.MethodPost,
			"/iclock/devicecmd?SN=TA6",
			strings.NewReader("ID="+secret+"&Return="+secret),
		),
	)

	if got := output.String(); strings.Contains(got, secret) {
		t.Fatalf("device-controlled query or command number reached logs: %q", got)
	}
}

func TestReflectBioDataLogsOnlyBoundedAllowlistedFieldNames(t *testing.T) {
	var output synchronizedBuffer
	original := log.Writer()
	log.SetOutput(&output)
	t.Cleanup(func() { log.SetOutput(original) })

	secret := strings.Repeat("U0VDUkVU", 20)
	server := &ADMSServer{
		cmdQueue:   make(map[string][]ADMSCommand),
		cloudCmdID: make(map[string]struct{}),
	}
	server.reflectBioData(
		"TA1",
		[]byte("Pin=14\tNo=3\tType=1\tTmp=QUJDRA==\t"+secret+"=ignored"),
	)
	server.reflectBioData(
		"TA1",
		[]byte("Pin=14\tNo=3\tType="+secret+"\tTmp=QUJDRA=="),
	)

	if got := output.String(); strings.Contains(got, secret) {
		t.Fatalf("reflectBioData logged arbitrary field name: %q", got)
	}
}

func TestFallbackBiometricMetadataRejectsUnsafeIdentityAndKeys(t *testing.T) {
	requests := make(chan []byte, 1)
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests <- body
		w.WriteHeader(http.StatusOK)
	}))
	defer cloud.Close()

	secret := strings.Repeat("U0VDUkVU", 20)
	server := &ADMSServer{agent: &Agent{config: Config{PlamatixURL: cloud.URL}}}
	server.reportBiometricTemplateUpload(
		context.Background(),
		secret,
		"14\r\n"+secret,
		1,
		3,
		1,
		4,
		[]string{"PIN", secret},
	)

	select {
	case body := <-requests:
		t.Fatalf("unsafe fallback metadata reached cloud: %s", body)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestDrainCloudCommandsDoesNotReturnArbitraryResponseBody(t *testing.T) {
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"template":"QUJDRA==","detail":"internal plaintext"}`))
	}))
	defer cloud.Close()

	server := &ADMSServer{agent: &Agent{config: Config{PlamatixURL: cloud.URL}}}
	_, err := server.drainCloudCommands("TA1")
	if err == nil {
		t.Fatal("expected command drain failure")
	}
	if strings.Contains(err.Error(), "QUJDRA") ||
		strings.Contains(err.Error(), "internal plaintext") {
		t.Fatalf("command drain returned arbitrary response body: %v", err)
	}
}

func TestSafeBiometricFieldKeysUsesBoundedAllowlist(t *testing.T) {
	hostileKey := strings.Repeat("QUJDRA", 200)
	got := safeBiometricFieldKeys(map[string]string{
		"PIN":      "14",
		"No":       "3",
		"Type":     "1",
		"MajorVer": "10",
		hostileKey: "plaintext-template",
	})

	for _, key := range got {
		if key == hostileKey || len(key) > 16 {
			t.Fatalf("reported untrusted field key %q", key)
		}
	}
	if strings.Join(got, ",") != "MajorVer,No,PIN,Type" {
		t.Fatalf("safe keys = %v; want bounded canonical allowlist", got)
	}
}

func TestLogTableDataPreviewDoesNotLogArbitraryFieldNamesOrValues(t *testing.T) {
	var output synchronizedBuffer
	original := log.Writer()
	log.SetOutput(&output)
	t.Cleanup(func() { log.SetOutput(original) })

	hostileKey := strings.Repeat("QUJDRA", 40)
	logTableDataPreview("TA1", "BIODATA", []byte(hostileKey+"=plaintext-template"))

	got := output.String()
	if strings.Contains(got, hostileKey) || strings.Contains(got, "plaintext-template") {
		t.Fatalf("preview logged arbitrary biometric field: %q", got)
	}
}

func TestHandleCDataBioDataDoesNotUseGenericUnsafePreview(t *testing.T) {
	var output synchronizedBuffer
	original := log.Writer()
	log.SetOutput(&output)
	t.Cleanup(func() { log.SetOutput(original) })

	hostileKey := strings.Repeat("QUJDRA", 40)
	server := &ADMSServer{agent: &Agent{devices: newDeviceTracker()}}
	server.handleCData(
		httptest.NewRecorder(),
		httptest.NewRequest(
			http.MethodPost,
			"/iclock/cdata?SN=TA1&type=BioData",
			strings.NewReader(hostileKey+"=plaintext-template"),
		),
	)

	got := output.String()
	if strings.Contains(got, hostileKey) || strings.Contains(got, "plaintext-template") {
		t.Fatalf("BioData handler logged arbitrary biometric field: %q", got)
	}
}

type trackingZeroReader struct {
	remaining int
	read      int
}

func (reader *trackingZeroReader) Read(buffer []byte) (int, error) {
	if reader.remaining == 0 {
		return 0, io.EOF
	}
	count := len(buffer)
	if count > reader.remaining {
		count = reader.remaining
	}
	for index := range buffer[:count] {
		buffer[index] = 0
	}
	reader.remaining -= count
	reader.read += count
	return count, nil
}
