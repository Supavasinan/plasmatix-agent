package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testDeploymentID = "11111111-1111-4111-8111-111111111111"
	testCommandID    = "22222222-2222-4222-8222-222222222222"
	testStaleID      = "33333333-3333-4333-8333-333333333333"
)

type deliveryResultRecord struct {
	Status     string `json:"status"`
	DeviceSN   string `json:"deviceSn"`
	SHA256     string `json:"sha256"`
	ErrorCode  string `json:"errorCode,omitempty"`
	CommandID  string `json:"commandId"`
	ReturnCode int    `json:"returnCode"`
}

type deliveryFixture struct {
	payload       []byte
	renderer      string
	kind          string
	bioType       int
	slot          int
	family        string
	major         int
	minor         int
	format        string
	personnelID   string
	token         string
	claimCommand  string
	claimCount    int
	payloadCount  int
	resultCount   int
	resultStatus  int
	payloadStatus int
	headerDigest  string
	headerKind    string
	claimBytes    int
	mu            sync.Mutex
	sequence      []string
	results       chan deliveryResultRecord
	payloadServed chan struct{}
	payloadOnce   sync.Once
}

func newDeliveryFixture(payload []byte) *deliveryFixture {
	sum := sha256.Sum256(payload)
	return &deliveryFixture{
		payload:       append([]byte(nil), payload...),
		renderer:      "biodata",
		kind:          "fingerprint_template",
		bioType:       1,
		slot:          3,
		family:        "zkfinger-v12",
		major:         12,
		format:        "templatev12",
		personnelID:   "14",
		token:         strings.Repeat("A", 43),
		claimCommand:  testCommandID,
		resultStatus:  http.StatusOK,
		payloadStatus: http.StatusOK,
		headerDigest:  hex.EncodeToString(sum[:]),
		headerKind:    "fingerprint_template",
		claimBytes:    len(payload),
		results:       make(chan deliveryResultRecord, 16),
	}
}

func (f *deliveryFixture) handler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/agent-bridge/biometric-vault/deployments" &&
			r.Method == http.MethodPost:
			f.mu.Lock()
			f.claimCount++
			f.sequence = append(f.sequence, "claim")
			f.mu.Unlock()
			var body struct {
				DeploymentID string `json:"deploymentId"`
				DeviceSN     string `json:"deviceSn"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode claim: %v", err)
			}
			if body.DeploymentID != testDeploymentID || body.DeviceSN != "AC1" {
				t.Errorf("claim body = %#v", body)
			}
			if r.Header.Get("X-API-Key") != "agent-key" {
				t.Errorf("claim API key missing")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deployments": []any{map[string]any{
					"deploymentId":   testDeploymentID,
					"vaultAssetId":   "asset-1",
					"deviceSn":       "AC1",
					"personnelId":    f.personnelID,
					"commandId":      f.claimCommand,
					"renderer":       f.renderer,
					"deliveryToken":  f.token,
					"tokenExpiresAt": "2026-07-28T03:01:00.000Z",
					"asset": map[string]any{
						"kind":            f.kind,
						"bioType":         f.bioType,
						"slotIndex":       f.slot,
						"algorithmFamily": f.family,
						"algorithmMajor":  f.major,
						"algorithmMinor":  f.minor,
						"format":          f.format,
						"byteCount":       f.claimBytes,
						"sha256":          f.headerDigest,
					},
				}},
			})
		case r.URL.Path == "/api/agent-bridge/biometric-vault/deployments/"+
			testDeploymentID+"/payload" && r.Method == http.MethodGet:
			f.mu.Lock()
			f.payloadCount++
			f.sequence = append(f.sequence, "payload")
			f.mu.Unlock()
			if r.Header.Get("Authorization") != "Bearer "+f.token {
				t.Errorf("payload bearer token missing")
			}
			if r.Header.Get("X-Device-SN") != "AC1" {
				t.Errorf("payload device = %q", r.Header.Get("X-Device-SN"))
			}
			if f.payloadStatus != http.StatusOK {
				w.WriteHeader(f.payloadStatus)
				_, _ = w.Write([]byte(`{"error":"delivery_token_replayed"}`))
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Content-SHA256", f.headerDigest)
			w.Header().Set("X-Asset-Kind", f.headerKind)
			w.Header().Set("X-Biometric-Type", strconv.Itoa(f.bioType))
			w.Header().Set("X-Slot-Index", strconv.Itoa(f.slot))
			w.Header().Set("X-Algorithm-Family", f.family)
			w.Header().Set("X-Algorithm-Major", strconv.Itoa(f.major))
			w.Header().Set("X-Algorithm-Minor", strconv.Itoa(f.minor))
			w.Header().Set("X-Asset-Format", f.format)
			w.Header().Set("Content-Length", strconv.Itoa(len(f.payload)))
			_, _ = w.Write(f.payload)
			if f.payloadServed != nil {
				f.payloadOnce.Do(func() { close(f.payloadServed) })
			}
		case r.URL.Path == "/api/agent-bridge/biometric-vault/deployments/"+
			testDeploymentID+"/result" && r.Method == http.MethodPost:
			var result deliveryResultRecord
			if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
				t.Errorf("decode result: %v", err)
			}
			f.mu.Lock()
			f.resultCount++
			f.sequence = append(f.sequence, "result")
			status := f.resultStatus
			if f.resultCount > 1 {
				status = http.StatusOK
			}
			f.mu.Unlock()
			f.results <- result
			w.WriteHeader(status)
		case r.URL.Path == "/api/agent-bridge/commands":
			_, _ = w.Write([]byte(`{"commands":[]}`))
		default:
			http.NotFound(w, r)
		}
	})
}

func newDeliveryAgent(cloudURL string) (*Agent, *ADMSServer) {
	tracker := newDeviceTracker()
	tracker.observeProtocol("AC1", ProtocolObservation{
		Path: "/iclock/registry",
		Capabilities: map[string]string{
			"fingerfunon":            "1",
			"biodatafun":             "1",
			"fingeralgorithmversion": "12.0",
		},
	})
	agent := &Agent{
		config:  Config{APIKey: "agent-key", PlamatixURL: cloudURL},
		devices: tracker,
	}
	server := &ADMSServer{
		agent:          agent,
		cmdQueue:       make(map[string][]ADMSCommand),
		pendingCmd:     make(map[pendingCommandKey]ADMSCommand),
		cloudCmdID:     make(map[string]struct{}),
		queryBuffers:   make(map[string][]byte),
		secretCmdQueue: make(map[string][]*secretADMSCommand),
		secretPending:  make(map[pendingCommandKey]*secretADMSCommand),
		secretCmdID:    make(map[string]struct{}),
	}
	agent.adms = server
	return agent, server
}

func processTestDeployment(agent *Agent, ctx context.Context, commandID string) error {
	return agent.ProcessBiometricDeployment(
		withBiometricDeploymentCommandID(ctx, commandID),
		testDeploymentID,
		"AC1",
	)
}

func waitDeliveryResult(t *testing.T, results <-chan deliveryResultRecord) deliveryResultRecord {
	t.Helper()
	select {
	case result := <-results:
		return result
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for deployment result")
		return deliveryResultRecord{}
	}
}

func TestBiometricDeliveryEndToEndAckAndLostResultRetry(t *testing.T) {
	raw := []byte("fingerprint-template")
	fixture := newDeliveryFixture(raw)
	fixture.resultStatus = http.StatusInternalServerError
	cloud := httptest.NewServer(fixture.handler(t))
	defer cloud.Close()
	agent, server := newDeliveryAgent(cloud.URL)

	if err := processTestDeployment(agent, context.Background(), testCommandID); err != nil {
		t.Fatalf("process deployment: %v", err)
	}
	if len(server.secretCmdQueue["AC1"]) != 1 {
		t.Fatalf("secret queue length = %d; want 1", len(server.secretCmdQueue["AC1"]))
	}

	response := httptest.NewRecorder()
	server.handleGetRequest(
		response,
		httptest.NewRequest(http.MethodGet, "/iclock/getrequest?SN=AC1", nil),
	)
	encoded := base64.StdEncoding.EncodeToString(raw)
	if !strings.HasSuffix(response.Body.String(), "\tTmp="+encoded) {
		t.Fatalf("scanner command does not contain the expected typed payload")
	}
	localID := strings.SplitN(strings.TrimPrefix(response.Body.String(), "C:"), ":", 2)[0]
	pending := server.secretPending[pendingCommandKey{
		DeviceSN: "AC1",
		LocalID:  mustTestInt(t, localID),
	}]
	if pending == nil {
		t.Fatal("served secret command is not pending")
	}
	commandBuffer := pending.payload

	server.handleDeviceCmd(
		httptest.NewRecorder(),
		httptest.NewRequest(
			http.MethodPost,
			"/iclock/devicecmd?SN=AC1",
			strings.NewReader("ID="+localID+"&Return=0"),
		),
	)
	first := waitDeliveryResult(t, fixture.results)
	second := waitDeliveryResult(t, fixture.results)
	if first != second {
		t.Fatalf("retried result changed: first=%#v second=%#v", first, second)
	}
	if second.Status != "applied" || second.DeviceSN != "AC1" ||
		second.SHA256 != fixture.headerDigest || second.CommandID != testCommandID ||
		second.ReturnCode != 0 {
		t.Fatalf("result = %#v", second)
	}
	if second.ErrorCode != "" {
		t.Fatalf("applied result exposed error code %q", second.ErrorCode)
	}
	for index, value := range commandBuffer {
		if value != 0 {
			t.Fatalf("rendered command byte %d was not zeroed after acknowledgement", index)
		}
	}
	fixture.mu.Lock()
	sequence := append([]string(nil), fixture.sequence...)
	fixture.mu.Unlock()
	if strings.Join(sequence[:3], ",") != "claim,payload,result" {
		t.Fatalf("sequence = %v", sequence)
	}
}

func TestBiometricDeliveryRejectsTokenReplayBeforeQueueing(t *testing.T) {
	fixture := newDeliveryFixture([]byte("fingerprint-template"))
	fixture.payloadStatus = http.StatusConflict
	cloud := httptest.NewServer(fixture.handler(t))
	defer cloud.Close()
	agent, server := newDeliveryAgent(cloud.URL)

	err := processTestDeployment(agent, context.Background(), testCommandID)
	if err == nil || err.Error() != "delivery_token_replayed" {
		t.Fatalf("error = %v; want delivery_token_replayed", err)
	}
	if len(server.secretCmdQueue["AC1"]) != 0 {
		t.Fatal("token replay queued a scanner command")
	}
	result := waitDeliveryResult(t, fixture.results)
	if result.Status != "failed" || result.ErrorCode != "delivery_token_replayed" ||
		result.CommandID != testCommandID {
		t.Fatalf("result = %#v", result)
	}
}

func TestBiometricDeliveryRejectsMalformedClaimTokenBeforeFetch(t *testing.T) {
	fixture := newDeliveryFixture([]byte("fingerprint-template"))
	fixture.token = "not-a-32-byte-token"
	cloud := httptest.NewServer(fixture.handler(t))
	defer cloud.Close()
	agent, server := newDeliveryAgent(cloud.URL)

	err := processTestDeployment(agent, context.Background(), testCommandID)
	if err == nil || err.Error() != "invalid_deployment_claim" {
		t.Fatalf("error = %v; want invalid_deployment_claim", err)
	}
	if len(server.secretCmdQueue["AC1"]) != 0 {
		t.Fatal("malformed claim token queued a scanner command")
	}
	fixture.mu.Lock()
	fetches := fixture.payloadCount
	fixture.mu.Unlock()
	if fetches != 0 {
		t.Fatalf("malformed claim token fetched payload %d time(s)", fetches)
	}
}

func TestBiometricDeliveryRejectsPayloadIntegrityAndSizeFailures(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*deliveryFixture)
		wantCode  string
		wantFetch int
	}{
		{
			name: "payload metadata mismatch",
			mutate: func(f *deliveryFixture) {
				f.headerKind = "face_template"
			},
			wantCode:  "payload_metadata_mismatch",
			wantFetch: 1,
		},
		{
			name: "claim byte count mismatch",
			mutate: func(f *deliveryFixture) {
				f.claimBytes++
			},
			wantCode:  "payload_size_mismatch",
			wantFetch: 1,
		},
		{
			name: "payload digest mismatch",
			mutate: func(f *deliveryFixture) {
				f.headerDigest = strings.Repeat("0", 64)
			},
			wantCode:  "ciphertext_tampered",
			wantFetch: 1,
		},
		{
			name: "oversize fingerprint",
			mutate: func(f *deliveryFixture) {
				f.payload = bytes.Repeat([]byte{7}, maxFingerprintTemplateBytes+1)
				sum := sha256.Sum256(f.payload)
				f.headerDigest = hex.EncodeToString(sum[:])
				f.claimBytes = len(f.payload)
			},
			wantCode:  "payload_too_large",
			wantFetch: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newDeliveryFixture([]byte("fingerprint-template"))
			tt.mutate(fixture)
			cloud := httptest.NewServer(fixture.handler(t))
			defer cloud.Close()
			agent, server := newDeliveryAgent(cloud.URL)

			err := processTestDeployment(agent, context.Background(), testCommandID)
			if err == nil || err.Error() != tt.wantCode {
				t.Fatalf("error = %v; want %s", err, tt.wantCode)
			}
			if len(server.secretCmdQueue["AC1"]) != 0 {
				t.Fatal("invalid payload queued a scanner command")
			}
			result := waitDeliveryResult(t, fixture.results)
			if result.ErrorCode != tt.wantCode {
				t.Fatalf("result = %#v", result)
			}
			fixture.mu.Lock()
			gotFetch := fixture.payloadCount
			fixture.mu.Unlock()
			if gotFetch != tt.wantFetch {
				t.Fatalf("payload fetches = %d; want %d", gotFetch, tt.wantFetch)
			}
		})
	}
}

func TestBiometricDeliveryRejectsLiveProfileAndAlgorithmDrift(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*Agent)
		wantCode string
	}{
		{
			name: "algorithm drift",
			mutate: func(agent *Agent) {
				agent.devices.observeProtocol("AC1", ProtocolObservation{
					Path: "/iclock/registry",
					Capabilities: map[string]string{
						"fingeralgorithmversion": "13.0",
					},
				})
			},
			wantCode: "algorithm_mismatch",
		},
		{
			name: "refused profile",
			mutate: func(agent *Agent) {
				agent.devices.mu.Lock()
				agent.devices.devices["AC1"].Protocol.Profile = ProtocolUnknown
				agent.devices.devices["AC1"].Protocol.Confidence = 0
				agent.devices.mu.Unlock()
			},
			wantCode: "target_profile_untrusted",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newDeliveryFixture([]byte("fingerprint-template"))
			cloud := httptest.NewServer(fixture.handler(t))
			defer cloud.Close()
			agent, server := newDeliveryAgent(cloud.URL)
			tt.mutate(agent)

			err := processTestDeployment(agent, context.Background(), testCommandID)
			if err == nil || err.Error() != tt.wantCode {
				t.Fatalf("error = %v; want %s", err, tt.wantCode)
			}
			if len(server.secretCmdQueue["AC1"]) != 0 {
				t.Fatal("live compatibility failure queued a command")
			}
			if result := waitDeliveryResult(t, fixture.results); result.ErrorCode != tt.wantCode {
				t.Fatalf("result = %#v", result)
			}
		})
	}
}

func TestBiometricDeliveryRequiresCurrentInterceptedCommand(t *testing.T) {
	tests := []struct {
		name      string
		intercept string
		claim     string
	}{
		{name: "missing intercepted command", claim: testCommandID},
		{name: "stale intercepted command", intercept: testStaleID, claim: testCommandID},
		{name: "missing claim command", intercept: testCommandID},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newDeliveryFixture([]byte("fingerprint-template"))
			fixture.claimCommand = tt.claim
			cloud := httptest.NewServer(fixture.handler(t))
			defer cloud.Close()
			agent, server := newDeliveryAgent(cloud.URL)

			err := processTestDeployment(agent, context.Background(), tt.intercept)
			if err == nil || err.Error() != "stale_deployment_command" {
				t.Fatalf("error = %v; want stale_deployment_command", err)
			}
			if len(server.secretCmdQueue["AC1"]) != 0 {
				t.Fatal("stale command queued a scanner command")
			}
			fixture.mu.Lock()
			fetches := fixture.payloadCount
			fixture.mu.Unlock()
			if fetches != 0 {
				t.Fatalf("stale command fetched payload %d time(s)", fetches)
			}
		})
	}
}

func TestBiometricDeliveryInterceptsReferenceAndDeduplicatesClaim(t *testing.T) {
	fixture := newDeliveryFixture([]byte("fingerprint-template"))
	commandsCalls := 0
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/agent-bridge/commands" {
			commandsCalls++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"commands": []any{map[string]any{
					"id":    testCommandID,
					"cmd":   "DEPLOY_BIOMETRIC_ASSET " + testDeploymentID,
					"label": "typed vault deployment",
				}},
			})
			return
		}
		fixture.handler(t).ServeHTTP(w, r)
	}))
	defer cloud.Close()
	_, server := newDeliveryAgent(cloud.URL)

	if _, err := server.drainCloudCommands("AC1"); err != nil {
		t.Fatalf("first drain: %v", err)
	}
	if _, err := server.drainCloudCommands("AC1"); err != nil {
		t.Fatalf("duplicate drain: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		server.mu.Lock()
		queued := len(server.secretCmdQueue["AC1"])
		normal := len(server.cmdQueue["AC1"])
		server.mu.Unlock()
		if queued == 1 {
			if normal != 0 {
				t.Fatal("typed vault reference entered the ordinary scanner queue")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("intercepted deployment was not queued")
		}
		time.Sleep(time.Millisecond)
	}
	fixture.mu.Lock()
	claims := fixture.claimCount
	fixture.mu.Unlock()
	if claims != 1 || commandsCalls != 2 {
		t.Fatalf("claims = %d commands calls = %d", claims, commandsCalls)
	}
}

func TestBiometricDeliveryIgnoresStaleScannerResultAndZerosOnShutdown(t *testing.T) {
	fixture := newDeliveryFixture([]byte("fingerprint-template"))
	cloud := httptest.NewServer(fixture.handler(t))
	defer cloud.Close()
	agent, server := newDeliveryAgent(cloud.URL)
	if err := processTestDeployment(agent, context.Background(), testCommandID); err != nil {
		t.Fatalf("process deployment: %v", err)
	}
	response := httptest.NewRecorder()
	server.handleGetRequest(
		response,
		httptest.NewRequest(http.MethodGet, "/iclock/getrequest?SN=AC1", nil),
	)
	localID := mustTestInt(
		t,
		strings.SplitN(strings.TrimPrefix(response.Body.String(), "C:"), ":", 2)[0],
	)
	pending := server.secretPending[pendingCommandKey{DeviceSN: "AC1", LocalID: localID}]
	commandBuffer := pending.payload

	server.handleDeviceCmd(
		httptest.NewRecorder(),
		httptest.NewRequest(
			http.MethodPost,
			"/iclock/devicecmd?SN=AC1",
			strings.NewReader("ID="+strconv.Itoa(localID+1)+"&Return=0"),
		),
	)
	select {
	case result := <-fixture.results:
		t.Fatalf("stale scanner result reported completion: %#v", result)
	case <-time.After(50 * time.Millisecond):
	}
	server.shutdownBiometricDelivery()
	for index, value := range commandBuffer {
		if value != 0 {
			t.Fatalf("rendered command byte %d was not zeroed on shutdown", index)
		}
	}
}

func TestBiometricDeliveryRechecksLiveStateBeforeServingQueuedCommand(t *testing.T) {
	fixture := newDeliveryFixture([]byte("fingerprint-template"))
	cloud := httptest.NewServer(fixture.handler(t))
	defer cloud.Close()
	agent, server := newDeliveryAgent(cloud.URL)
	if err := processTestDeployment(agent, context.Background(), testCommandID); err != nil {
		t.Fatalf("process deployment: %v", err)
	}
	commandBuffer := server.secretCmdQueue["AC1"][0].payload
	agent.devices.observeProtocol("AC1", ProtocolObservation{
		Path: "/iclock/registry",
		Capabilities: map[string]string{
			"fingeralgorithmversion": "13.0",
		},
	})

	response := httptest.NewRecorder()
	server.handleGetRequest(
		response,
		httptest.NewRequest(http.MethodGet, "/iclock/getrequest?SN=AC1", nil),
	)
	if response.Body.String() != "OK" {
		t.Fatalf("drifted queued command reached scanner: %q", response.Body.String())
	}
	result := waitDeliveryResult(t, fixture.results)
	if result.Status != "failed" || result.ErrorCode != "algorithm_mismatch" {
		t.Fatalf("result = %#v", result)
	}
	for index, value := range commandBuffer {
		if value != 0 {
			t.Fatalf("rendered command byte %d was not zeroed after live drift", index)
		}
	}
}

func TestBiometricDeliveryCancellationDoesNotQueue(t *testing.T) {
	started := make(chan struct{})
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/payload") {
			close(started)
			<-r.Context().Done()
			return
		}
		fixture := newDeliveryFixture([]byte("fingerprint-template"))
		fixture.handler(t).ServeHTTP(w, r)
	}))
	defer cloud.Close()
	agent, server := newDeliveryAgent(cloud.URL)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- processTestDeployment(agent, ctx, testCommandID)
	}()
	<-started
	cancel()
	select {
	case err := <-done:
		if err == nil || err.Error() != "deployment_cancelled" {
			t.Fatalf("error = %v; want deployment_cancelled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled deployment did not return")
	}
	if len(server.secretCmdQueue["AC1"]) != 0 {
		t.Fatal("cancelled deployment queued a scanner command")
	}
}

func TestBiometricDeliveryCancellationAfterFetchDoesNotQueue(t *testing.T) {
	fixture := newDeliveryFixture([]byte("fingerprint-template"))
	fixture.payloadServed = make(chan struct{})
	cloud := httptest.NewServer(fixture.handler(t))
	defer cloud.Close()
	agent, server := newDeliveryAgent(cloud.URL)
	agent.devices.mu.Lock()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- processTestDeployment(agent, ctx, testCommandID)
	}()
	<-fixture.payloadServed
	time.Sleep(25 * time.Millisecond)
	cancel()
	agent.devices.mu.Unlock()

	select {
	case err := <-done:
		if err == nil || err.Error() != "deployment_cancelled" {
			t.Fatalf("error = %v; want deployment_cancelled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled post-fetch deployment did not return")
	}
	if len(server.secretCmdQueue["AC1"]) != 0 {
		t.Fatal("post-fetch cancellation queued a scanner command")
	}
}

type blockingSecretResponseWriter struct {
	header  http.Header
	writes  int
	started chan struct{}
	release chan struct{}
	body    []byte
}

func (w *blockingSecretResponseWriter) Header() http.Header {
	return w.header
}

func (w *blockingSecretResponseWriter) WriteHeader(_ int) {}

func (w *blockingSecretResponseWriter) Write(value []byte) (int, error) {
	w.writes++
	if w.writes == 1 {
		return len(value), nil
	}
	close(w.started)
	<-w.release
	w.body = append(w.body, value...)
	return len(value), nil
}

func TestBiometricDeliveryShutdownWaitsForSecretResponseWriteBeforeZeroing(
	t *testing.T,
) {
	original := []byte("mutable-secret-command")
	command := &secretADMSCommand{
		deviceSN:     "AC1",
		deploymentID: testDeploymentID,
		commandID:    testCommandID,
		payload:      append([]byte(nil), original...),
	}
	server := &ADMSServer{
		secretCmdQueue: map[string][]*secretADMSCommand{"AC1": {command}},
		secretPending:  make(map[pendingCommandKey]*secretADMSCommand),
		secretCmdID:    map[string]struct{}{testCommandID: {}},
	}
	command = server.popSecretCommand("AC1")
	writer := &blockingSecretResponseWriter{
		header:  make(http.Header),
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	writeDone := make(chan error, 1)
	go func() {
		writeDone <- writeSecretADMSCommand(writer, command)
	}()
	<-writer.started

	shutdownDone := make(chan struct{})
	go func() {
		server.shutdownBiometricDelivery()
		close(shutdownDone)
	}()
	select {
	case <-shutdownDone:
		close(writer.release)
		<-writeDone
		t.Fatal("shutdown zeroed a secret command while its response write was active")
	case <-time.After(50 * time.Millisecond):
	}
	close(writer.release)
	if err := <-writeDone; err != nil {
		t.Fatalf("write secret command: %v", err)
	}
	<-shutdownDone
	if !bytes.Equal(writer.body, original) {
		t.Fatalf("response write observed a zeroed or partial secret command")
	}
	for index, value := range command.payload {
		if value != 0 {
			t.Fatalf("command byte %d was not zeroed after response completion", index)
		}
	}
}

func TestBiometricDeliveryAdmissionIsBoundedBeforeClaim(t *testing.T) {
	fixture := newDeliveryFixture([]byte("fingerprint-template"))
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/agent-bridge/commands" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"commands": []any{map[string]any{
					"id":  testCommandID,
					"cmd": "DEPLOY_BIOMETRIC_ASSET " + testDeploymentID,
				}},
			})
			return
		}
		fixture.handler(t).ServeHTTP(w, r)
	}))
	defer cloud.Close()
	_, server := newDeliveryAgent(cloud.URL)
	for index := 0; index < maxSecretADMSCommands; index++ {
		server.secretCmdID["occupied-"+strconv.Itoa(index)] = struct{}{}
	}

	if _, err := server.drainCloudCommands("AC1"); err != nil {
		t.Fatalf("drain commands: %v", err)
	}
	time.Sleep(150 * time.Millisecond)
	fixture.mu.Lock()
	claims := fixture.claimCount
	results := fixture.resultCount
	fixture.mu.Unlock()
	if claims != 0 || results != 0 {
		t.Fatalf("bounded-out reference made claims=%d results=%d; want neither", claims, results)
	}
	if len(server.secretCmdID) != maxSecretADMSCommands {
		t.Fatalf("secret reservations = %d; want %d", len(server.secretCmdID), maxSecretADMSCommands)
	}
}

func TestBiometricDeliveryInvalidDeviceDoesNotLeakPreReservation(t *testing.T) {
	fixture := newDeliveryFixture([]byte("fingerprint-template"))
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/agent-bridge/commands" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"commands": []any{map[string]any{
					"id":  testCommandID,
					"cmd": "DEPLOY_BIOMETRIC_ASSET " + testDeploymentID,
				}},
			})
			return
		}
		fixture.handler(t).ServeHTTP(w, r)
	}))
	defer cloud.Close()
	_, server := newDeliveryAgent(cloud.URL)

	if _, err := server.drainCloudCommands("invalid device serial"); err != nil {
		t.Fatalf("drain commands: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if len(server.secretCmdID) != 0 {
		t.Fatalf("invalid device leaked %d secret reservation(s)", len(server.secretCmdID))
	}
	fixture.mu.Lock()
	claims := fixture.claimCount
	fixture.mu.Unlock()
	if claims != 0 {
		t.Fatalf("invalid device made %d claim(s)", claims)
	}
}

func TestBiometricDeliveryRenderMatrix(t *testing.T) {
	payload := []byte{1, 2, 3, 4}
	tests := []struct {
		name     string
		state    DeviceProtocolState
		metadata biometricDeploymentMetadata
		prefix   string
		wantCode string
	}{
		{
			name: "legacy TA FINGERTMP",
			state: DeviceProtocolState{
				Profile:     ProtocolTAPush,
				Confidence:  90,
				PushVersion: "2.4.1",
				Capabilities: map[string]string{
					"fingerfunon":            "1",
					"fingeralgorithmversion": "10.0",
				},
			},
			metadata: biometricDeploymentMetadata{
				Renderer: "finger_legacy", PersonnelID: "14",
				Kind: "fingerprint_template", BioType: 1, SlotIndex: 3,
				AlgorithmFamily: "zkfinger-v10", AlgorithmMajor: 10,
				Format: "templatev10",
			},
			prefix: "DATA UPDATE FINGERTMP PIN=14\tFID=3\tSize=4\tValid=1\tTMP=",
		},
		{
			name: "old TA DATA FP",
			state: DeviceProtocolState{
				Profile:     ProtocolTAPush,
				Confidence:  90,
				PushVersion: "2.2.13",
				Capabilities: map[string]string{
					"fingerfunon":            "1",
					"fingeralgorithmversion": "10.0",
				},
			},
			metadata: biometricDeploymentMetadata{
				Renderer: "finger_legacy", PersonnelID: "14",
				Kind: "fingerprint_template", BioType: 1, SlotIndex: 3,
				AlgorithmFamily: "zkfinger-v10", AlgorithmMajor: 10,
				Format: "templatev10",
			},
			prefix: "DATA FP PIN=14\tFID=3\tSize=4\tValid=1\tTMP=",
		},
		{
			name: "TA BIODATA",
			state: DeviceProtocolState{
				Profile:     ProtocolTAPush,
				Confidence:  90,
				PushVersion: "2.4.1",
				Capabilities: map[string]string{
					"facefunon":            "1",
					"biodatafun":           "1",
					"facealgorithmversion": "7.1",
				},
			},
			metadata: biometricDeploymentMetadata{
				Renderer: "biodata", PersonnelID: "14",
				Kind: "face_template", BioType: 9, SlotIndex: 0,
				AlgorithmFamily: "zkface-v7", AlgorithmMajor: 7,
				AlgorithmMinor: 1, Format: "facev7",
			},
			prefix: "DATA UPDATE BIODATA Pin=14\tNo=0\tType=9\tMajorVer=7\tMinorVer=1\tTmp=",
		},
		{
			name: "AC BIOPHOTO",
			state: DeviceProtocolState{
				Profile:    ProtocolACPush3,
				Confidence: 95,
				Capabilities: map[string]string{
					"facefunon":   "1",
					"biophotofun": "1",
				},
			},
			metadata: biometricDeploymentMetadata{
				Renderer: "face_photo", PersonnelID: "14",
				Kind: "face_comparison_photo", BioType: 9, SlotIndex: 0,
				AlgorithmFamily: "portable_photo", Format: "jpeg",
			},
			prefix: "DATA UPDATE BIOPHOTO PIN=14\tNo=0\tType=9\tSize=4\tPhoto=",
		},
		{
			name: "AC refuses legacy renderer",
			state: DeviceProtocolState{
				Profile:    ProtocolACPush3,
				Confidence: 95,
				Capabilities: map[string]string{
					"fingerfunon":            "1",
					"fingeralgorithmversion": "10.0",
				},
			},
			metadata: biometricDeploymentMetadata{
				Renderer: "finger_legacy", PersonnelID: "14",
				Kind: "fingerprint_template", BioType: 1, SlotIndex: 3,
				AlgorithmFamily: "zkfinger-v10", AlgorithmMajor: 10,
				Format: "templatev10",
			},
			wantCode: "record_type_unsupported",
		},
		{
			name: "TA refuses BIODATA for legacy fingerprint generation",
			state: DeviceProtocolState{
				Profile:     ProtocolTAPush,
				Confidence:  90,
				PushVersion: "2.4.1",
				Capabilities: map[string]string{
					"fingerfunon":            "1",
					"biodatafun":             "1",
					"fingeralgorithmversion": "10.0",
				},
			},
			metadata: biometricDeploymentMetadata{
				Renderer: "biodata", PersonnelID: "14",
				Kind: "fingerprint_template", BioType: 1, SlotIndex: 3,
				AlgorithmFamily: "zkfinger-v10", AlgorithmMajor: 10,
				Format: "templatev10",
			},
			wantCode: "record_type_unsupported",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			command, code := renderBiometricDeploymentCommand(tt.state, tt.metadata, payload)
			defer zeroBytes(command)
			if code != tt.wantCode {
				t.Fatalf("code = %q; want %q", code, tt.wantCode)
			}
			if tt.wantCode == "" &&
				!bytes.HasPrefix(command, []byte(tt.prefix)) {
				t.Fatalf("command has wrong typed prefix")
			}
		})
	}
}

func mustTestInt(t *testing.T, value string) int {
	t.Helper()
	number, err := strconv.Atoi(value)
	if err != nil {
		t.Fatalf("invalid integer %q: %v", value, err)
	}
	return number
}

func TestBiometricDeliveryResultContainsNoRawPayload(t *testing.T) {
	secret := []byte("raw-template-never-report")
	fixture := newDeliveryFixture(secret)
	cloud := httptest.NewServer(fixture.handler(t))
	defer cloud.Close()
	agent, server := newDeliveryAgent(cloud.URL)
	if err := processTestDeployment(agent, context.Background(), testCommandID); err != nil {
		t.Fatalf("process deployment: %v", err)
	}
	response := httptest.NewRecorder()
	server.handleGetRequest(
		response,
		httptest.NewRequest(http.MethodGet, "/iclock/getrequest?SN=AC1", nil),
	)
	localID := strings.SplitN(strings.TrimPrefix(response.Body.String(), "C:"), ":", 2)[0]
	server.handleDeviceCmd(
		httptest.NewRecorder(),
		httptest.NewRequest(
			http.MethodPost,
			"/iclock/devicecmd?SN=AC1",
			strings.NewReader("ID="+localID+"&Return=-7&Template="+
				base64.StdEncoding.EncodeToString(secret)),
		),
	)
	result := waitDeliveryResult(t, fixture.results)
	encoded, _ := json.Marshal(result)
	if bytes.Contains(encoded, secret) ||
		bytes.Contains(encoded, []byte(base64.StdEncoding.EncodeToString(secret))) {
		t.Fatalf("result body leaked raw biometric payload")
	}
	if result.Status != "failed" || result.ErrorCode != "device_command_failed" ||
		result.ReturnCode != -7 {
		t.Fatalf("result = %#v", result)
	}
}
