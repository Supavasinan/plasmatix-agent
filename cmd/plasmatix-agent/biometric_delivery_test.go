package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	claimExpected string
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
				DeploymentID      string `json:"deploymentId"`
				DeviceSN          string `json:"deviceSn"`
				ExpectedCommandID string `json:"expectedCommandId"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode claim: %v", err)
			}
			if body.DeploymentID != testDeploymentID || body.DeviceSN != "AC1" {
				t.Errorf("claim body = %#v", body)
			}
			f.mu.Lock()
			f.claimExpected = body.ExpectedCommandID
			f.mu.Unlock()
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

func newDeliveryAgent(t *testing.T, cloudURL string) (*Agent, *ADMSServer) {
	t.Helper()
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
		config:   Config{APIKey: "agent-key", PlamatixURL: cloudURL},
		stateDir: t.TempDir(),
		devices:  tracker,
	}
	outbox, err := openBiometricResultOutbox(agent.stateDir)
	if err != nil {
		t.Fatalf("open result outbox: %v", err)
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
		resultOutbox:   outbox,
	}
	agent.adms = server
	server.startBiometricResultOutboxWorker()
	t.Cleanup(server.shutdownBiometricDelivery)
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

type manualSecretDeadline struct {
	at       time.Time
	callback func()
	stopped  bool
}

type manualSecretClock struct {
	now       time.Time
	deadlines []*manualSecretDeadline
}

func newManualSecretClock() *manualSecretClock {
	return &manualSecretClock{
		now: time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC),
	}
}

func (clock *manualSecretClock) Now() time.Time {
	return clock.now
}

func (clock *manualSecretClock) AfterFunc(
	delay time.Duration,
	callback func(),
) func() bool {
	deadline := &manualSecretDeadline{
		at:       clock.now.Add(delay),
		callback: callback,
	}
	clock.deadlines = append(clock.deadlines, deadline)
	return func() bool {
		if deadline.stopped {
			return false
		}
		deadline.stopped = true
		return true
	}
}

func (clock *manualSecretClock) Advance(elapsed time.Duration) {
	clock.now = clock.now.Add(elapsed)
	for _, deadline := range clock.deadlines {
		if deadline.stopped || deadline.at.After(clock.now) {
			continue
		}
		deadline.stopped = true
		deadline.callback()
	}
}

func useManualSecretClock(server *ADMSServer, clock *manualSecretClock) {
	server.secretNow = clock.Now
	server.secretAfterFunc = clock.AfterFunc
}

func TestBiometricDeliveryEndToEndAckAndLostResultRetry(t *testing.T) {
	raw := []byte("fingerprint-template")
	fixture := newDeliveryFixture(raw)
	fixture.resultStatus = http.StatusInternalServerError
	cloud := httptest.NewServer(fixture.handler(t))
	defer cloud.Close()
	agent, server := newDeliveryAgent(t, cloud.URL)

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
	agent, server := newDeliveryAgent(t, cloud.URL)

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

func TestBiometricDeliveryFailureRetainsResultWhenDurableEnqueueFails(
	t *testing.T,
) {
	fixture := newDeliveryFixture([]byte("fingerprint-template"))
	fixture.payloadStatus = http.StatusConflict
	cloud := httptest.NewServer(fixture.handler(t))
	defer cloud.Close()
	agent, server := newDeliveryAgent(t, cloud.URL)
	server.resultOutbox.path = filepath.Join(
		agent.stateDir,
		"missing",
		biometricResultOutboxFilename,
	)

	err := processTestDeployment(agent, context.Background(), testCommandID)
	if err == nil || err.Error() != "delivery_token_replayed" {
		t.Fatalf("error = %v; want delivery_token_replayed", err)
	}
	server.mu.Lock()
	_, active := server.secretCmdID[testCommandID]
	pending := server.resultEnqueuePending[testCommandID]
	outboxErr := server.resultOutboxErr
	server.mu.Unlock()
	if !active || pending.result.CommandID != testCommandID {
		t.Fatalf("failed process active=%v pending=%#v", active, pending)
	}
	if outboxErr != nil {
		t.Fatalf("failed process disabled unrelated outbox work: %v", outboxErr)
	}
}

func TestBiometricDeliveryRejectsMalformedClaimTokenBeforeFetch(t *testing.T) {
	fixture := newDeliveryFixture([]byte("fingerprint-template"))
	fixture.token = "not-a-32-byte-token"
	cloud := httptest.NewServer(fixture.handler(t))
	defer cloud.Close()
	agent, server := newDeliveryAgent(t, cloud.URL)

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
			agent, server := newDeliveryAgent(t, cloud.URL)

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
			agent, server := newDeliveryAgent(t, cloud.URL)
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
			agent, server := newDeliveryAgent(t, cloud.URL)

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
			fixture.mu.Lock()
			expected := fixture.claimExpected
			fixture.mu.Unlock()
			if tt.intercept != "" && expected != tt.intercept {
				t.Fatalf("claim expectedCommandId = %q; want %q", expected, tt.intercept)
			}
		})
	}
}

func TestBiometricDeliveryStaleClaimResponseStopsBeforePayloadOrResult(
	t *testing.T,
) {
	var claimBody struct {
		DeploymentID      string `json:"deploymentId"`
		DeviceSN          string `json:"deviceSn"`
		ExpectedCommandID string `json:"expectedCommandId"`
	}
	var payloadCalls atomic.Int32
	var resultCalls atomic.Int32
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/agent-bridge/biometric-vault/deployments":
			if err := json.NewDecoder(r.Body).Decode(&claimBody); err != nil {
				t.Errorf("decode claim: %v", err)
			}
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"stale_deployment_command"}`))
		case strings.HasSuffix(r.URL.Path, "/payload"):
			payloadCalls.Add(1)
		case strings.HasSuffix(r.URL.Path, "/result"):
			resultCalls.Add(1)
		default:
			http.NotFound(w, r)
		}
	}))
	defer cloud.Close()
	agent, server := newDeliveryAgent(t, cloud.URL)

	err := processTestDeployment(agent, context.Background(), testStaleID)
	if err == nil || err.Error() != "stale_deployment_command" {
		t.Fatalf("error = %v; want stale_deployment_command", err)
	}
	if claimBody.DeploymentID != testDeploymentID ||
		claimBody.DeviceSN != "AC1" ||
		claimBody.ExpectedCommandID != testStaleID {
		t.Fatalf("claim body = %#v", claimBody)
	}
	if payloadCalls.Load() != 0 || resultCalls.Load() != 0 {
		t.Fatalf("stale claim made payload=%d result=%d calls",
			payloadCalls.Load(), resultCalls.Load())
	}
	server.mu.Lock()
	reservations := len(server.secretCmdID)
	server.mu.Unlock()
	if reservations != 0 {
		t.Fatalf("stale claim retained %d reservation(s)", reservations)
	}
}

func TestBiometricDeliveryReleasesFailedLeaseForSameIDRedelivery(t *testing.T) {
	fixture := newDeliveryFixture([]byte("fingerprint-template"))
	var claims atomic.Int32
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
		if r.URL.Path == "/api/agent-bridge/biometric-vault/deployments" {
			currentClaim := claims.Add(1)
			if currentClaim > 1 {
				fixture.handler(t).ServeHTTP(w, r)
				return
			}
			var body struct {
				ExpectedCommandID string `json:"expectedCommandId"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode claim: %v", err)
			}
			if body.ExpectedCommandID != testCommandID {
				t.Errorf("expectedCommandId = %q", body.ExpectedCommandID)
			}
			http.Error(w, `{"error":"deployment_claim_failed"}`, http.StatusInternalServerError)
			return
		}
		fixture.handler(t).ServeHTTP(w, r)
	}))
	defer cloud.Close()
	_, server := newDeliveryAgent(t, cloud.URL)

	if _, err := server.drainCloudCommands("AC1"); err != nil {
		t.Fatalf("first drain: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		server.mu.Lock()
		active := len(server.secretCmdID)
		server.mu.Unlock()
		if claims.Load() == 1 && active == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("failed lease remained active: claims=%d reservations=%d",
				claims.Load(), active)
		}
		time.Sleep(time.Millisecond)
	}

	if _, err := server.drainCloudCommands("AC1"); err != nil {
		t.Fatalf("redelivery drain: %v", err)
	}
	deadline = time.Now().Add(3 * time.Second)
	for {
		server.mu.Lock()
		queued := len(server.secretCmdQueue["AC1"])
		server.mu.Unlock()
		if queued == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("same-ID lease was not retried: claims=%d queued=%d",
				claims.Load(), queued)
		}
		time.Sleep(time.Millisecond)
	}
	if claims.Load() != 2 {
		t.Fatalf("claim attempts = %d; want 2", claims.Load())
	}
}

func TestBiometricDeliveryMapsConsumedPayloadTransportFailureToNetworkUnavailable(
	t *testing.T,
) {
	fixture := newDeliveryFixture([]byte("fingerprint-template"))
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/payload") {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Content-SHA256", fixture.headerDigest)
			w.Header().Set("X-Asset-Kind", fixture.kind)
			w.Header().Set("X-Biometric-Type", strconv.Itoa(fixture.bioType))
			w.Header().Set("X-Slot-Index", strconv.Itoa(fixture.slot))
			w.Header().Set("X-Algorithm-Family", fixture.family)
			w.Header().Set("X-Algorithm-Major", strconv.Itoa(fixture.major))
			w.Header().Set("X-Algorithm-Minor", strconv.Itoa(fixture.minor))
			w.Header().Set("X-Asset-Format", fixture.format)
			w.Header().Set("Content-Length", strconv.Itoa(len(fixture.payload)))
			_, _ = w.Write(fixture.payload[:4])
			return
		}
		fixture.handler(t).ServeHTTP(w, r)
	}))
	defer cloud.Close()
	agent, server := newDeliveryAgent(t, cloud.URL)

	err := processTestDeployment(agent, context.Background(), testCommandID)
	if err == nil || err.Error() != "network_unavailable" {
		t.Fatalf("error = %v; want network_unavailable", err)
	}
	if len(server.secretCmdQueue["AC1"]) != 0 {
		t.Fatal("partial payload queued a scanner command")
	}
	result := waitDeliveryResult(t, fixture.results)
	if result.ErrorCode != "network_unavailable" ||
		result.CommandID != testCommandID {
		t.Fatalf("result = %#v", result)
	}
}

func TestBiometricDeliveryRejectsDuplicateOrContradictorySafePayloadHeaders(
	t *testing.T,
) {
	tests := []struct {
		name   string
		mutate func(http.Header)
	}{
		{
			name: "duplicate digest",
			mutate: func(header http.Header) {
				header.Add("X-Content-SHA256", strings.Repeat("a", 64))
			},
		},
		{
			name: "contradictory content length",
			mutate: func(header http.Header) {
				header.Set("Content-Length", "1")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newDeliveryFixture([]byte("fingerprint-template"))
			cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/payload") {
					header := w.Header()
					header.Set("Content-Type", "application/octet-stream")
					header.Set("Cache-Control", "no-store")
					header.Set("X-Content-SHA256", fixture.headerDigest)
					header.Set("X-Asset-Kind", fixture.kind)
					header.Set("X-Biometric-Type", strconv.Itoa(fixture.bioType))
					header.Set("X-Slot-Index", strconv.Itoa(fixture.slot))
					header.Set("X-Algorithm-Family", fixture.family)
					header.Set("X-Algorithm-Major", strconv.Itoa(fixture.major))
					header.Set("X-Algorithm-Minor", strconv.Itoa(fixture.minor))
					header.Set("X-Asset-Format", fixture.format)
					header.Set("Content-Length", strconv.Itoa(len(fixture.payload)))
					tt.mutate(header)
					_, _ = w.Write(fixture.payload)
					return
				}
				fixture.handler(t).ServeHTTP(w, r)
			}))
			defer cloud.Close()
			agent, server := newDeliveryAgent(t, cloud.URL)

			err := processTestDeployment(agent, context.Background(), testCommandID)
			wantCode := "payload_metadata_mismatch"
			if tt.name == "contradictory content length" {
				wantCode = "payload_size_mismatch"
			}
			if err == nil || err.Error() != wantCode {
				t.Fatalf("error = %v; want %s", err, wantCode)
			}
			if len(server.secretCmdQueue["AC1"]) != 0 {
				t.Fatal("contradictory headers queued a scanner command")
			}
		})
	}
}

func TestBiometricDeliveryRejectsNonCanonicalDeliveryToken(t *testing.T) {
	fixture := newDeliveryFixture([]byte("fingerprint-template"))
	fixture.token = strings.Repeat("A", 42) + "B"
	cloud := httptest.NewServer(fixture.handler(t))
	defer cloud.Close()
	agent, server := newDeliveryAgent(t, cloud.URL)

	err := processTestDeployment(agent, context.Background(), testCommandID)
	if err == nil || err.Error() != "invalid_deployment_claim" {
		t.Fatalf("error = %v; want invalid_deployment_claim", err)
	}
	if len(server.secretCmdQueue["AC1"]) != 0 {
		t.Fatal("non-canonical token queued a scanner command")
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
	_, server := newDeliveryAgent(t, cloud.URL)

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
	agent, server := newDeliveryAgent(t, cloud.URL)
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

func TestBiometricDeliveryReservesSameLocalCommandForLostScannerACK(t *testing.T) {
	fixture := newDeliveryFixture([]byte("fingerprint-template"))
	cloud := httptest.NewServer(fixture.handler(t))
	defer cloud.Close()
	agent, server := newDeliveryAgent(t, cloud.URL)
	if err := processTestDeployment(agent, context.Background(), testCommandID); err != nil {
		t.Fatalf("process deployment: %v", err)
	}

	first := httptest.NewRecorder()
	server.handleGetRequest(
		first,
		httptest.NewRequest(http.MethodGet, "/iclock/getrequest?SN=AC1", nil),
	)
	second := httptest.NewRecorder()
	server.handleGetRequest(
		second,
		httptest.NewRequest(http.MethodGet, "/iclock/getrequest?SN=AC1", nil),
	)

	if first.Body.String() == "OK" || second.Body.String() != first.Body.String() {
		t.Fatalf("lost ACK retransmit changed command:\nfirst=%q\nsecond=%q",
			first.Body.String(), second.Body.String())
	}
	if got := len(server.secretPending); got != 1 {
		t.Fatalf("pending secret commands = %d; want 1", got)
	}
}

type failingSecretResponseWriter struct {
	header http.Header
}

func (w *failingSecretResponseWriter) Header() http.Header {
	return w.header
}

func (w *failingSecretResponseWriter) WriteHeader(_ int) {}

func (w *failingSecretResponseWriter) Write(value []byte) (int, error) {
	if bytes.HasPrefix(value, []byte("C:")) {
		return len(value), nil
	}
	return 0, errors.New("scanner connection lost")
}

func TestBiometricDeliveryRetriesSameBytesAfterLostResponseWrite(t *testing.T) {
	fixture := newDeliveryFixture([]byte("fingerprint-template"))
	cloud := httptest.NewServer(fixture.handler(t))
	defer cloud.Close()
	agent, server := newDeliveryAgent(t, cloud.URL)
	if err := processTestDeployment(agent, context.Background(), testCommandID); err != nil {
		t.Fatalf("process deployment: %v", err)
	}
	original := append([]byte(nil), server.secretCmdQueue["AC1"][0].payload...)

	server.handleGetRequest(
		&failingSecretResponseWriter{header: make(http.Header)},
		httptest.NewRequest(http.MethodGet, "/iclock/getrequest?SN=AC1", nil),
	)
	retry := httptest.NewRecorder()
	server.handleGetRequest(
		retry,
		httptest.NewRequest(http.MethodGet, "/iclock/getrequest?SN=AC1", nil),
	)

	if !bytes.HasSuffix(retry.Body.Bytes(), original) {
		t.Fatalf("retry did not re-serve the original mutable command bytes")
	}
	select {
	case result := <-fixture.results:
		t.Fatalf("lost response write falsely reported a terminal result: %#v", result)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestBiometricDeliveryTimeoutZerosReleasesAndReportsNetworkUnavailable(
	t *testing.T,
) {
	fixture := newDeliveryFixture([]byte("fingerprint-template"))
	cloud := httptest.NewServer(fixture.handler(t))
	defer cloud.Close()
	agent, server := newDeliveryAgent(t, cloud.URL)
	if err := processTestDeployment(agent, context.Background(), testCommandID); err != nil {
		t.Fatalf("process deployment: %v", err)
	}
	commandBuffer := server.secretCmdQueue["AC1"][0].payload

	var firstID string
	for attempt := 0; attempt < maxSecretCommandServeAttempts; attempt++ {
		response := httptest.NewRecorder()
		server.handleGetRequest(
			response,
			httptest.NewRequest(http.MethodGet, "/iclock/getrequest?SN=AC1", nil),
		)
		if response.Body.String() == "OK" {
			t.Fatalf("serve attempt %d returned OK", attempt+1)
		}
		id := strings.SplitN(strings.TrimPrefix(response.Body.String(), "C:"), ":", 2)[0]
		if firstID == "" {
			firstID = id
		} else if id != firstID {
			t.Fatalf("serve attempt %d changed local ID from %s to %s",
				attempt+1, firstID, id)
		}
	}

	timeoutResponse := httptest.NewRecorder()
	server.handleGetRequest(
		timeoutResponse,
		httptest.NewRequest(http.MethodGet, "/iclock/getrequest?SN=AC1", nil),
	)
	if timeoutResponse.Body.String() != "OK" {
		t.Fatalf("exhausted command was served again: %q", timeoutResponse.Body.String())
	}
	result := waitDeliveryResult(t, fixture.results)
	if result.ErrorCode != "network_unavailable" ||
		result.CommandID != testCommandID {
		t.Fatalf("timeout result = %#v", result)
	}
	server.mu.Lock()
	reservations := len(server.secretCmdID)
	pending := len(server.secretPending)
	server.mu.Unlock()
	if reservations != 0 || pending != 0 {
		t.Fatalf("timeout retained reservations=%d pending=%d", reservations, pending)
	}
	for index, value := range commandBuffer {
		if value != 0 {
			t.Fatalf("command byte %d was not zeroed on terminal timeout", index)
		}
	}
}

func TestBiometricDeliveryDeadlineExpiresPendingSecretCommand(t *testing.T) {
	fixture := newDeliveryFixture([]byte("fingerprint-template"))
	cloud := httptest.NewServer(fixture.handler(t))
	defer cloud.Close()
	agent, server := newDeliveryAgent(t, cloud.URL)
	if err := processTestDeployment(agent, context.Background(), testCommandID); err != nil {
		t.Fatalf("process deployment: %v", err)
	}
	first := httptest.NewRecorder()
	server.handleGetRequest(
		first,
		httptest.NewRequest(http.MethodGet, "/iclock/getrequest?SN=AC1", nil),
	)
	server.mu.Lock()
	for _, command := range server.secretPending {
		command.firstServedAt = time.Now().Add(-secretCommandServeDeadline)
	}
	server.mu.Unlock()

	expired := httptest.NewRecorder()
	server.handleGetRequest(
		expired,
		httptest.NewRequest(http.MethodGet, "/iclock/getrequest?SN=AC1", nil),
	)
	if expired.Body.String() != "OK" {
		t.Fatalf("deadline-expired command was served: %q", expired.Body.String())
	}
	if result := waitDeliveryResult(t, fixture.results); result.ErrorCode != "network_unavailable" {
		t.Fatalf("deadline result = %#v", result)
	}
}

func TestBiometricDeliveryDeadlineExpiresWithoutAnotherScannerPoll(t *testing.T) {
	fixture := newDeliveryFixture([]byte("fingerprint-template"))
	cloud := httptest.NewServer(fixture.handler(t))
	defer cloud.Close()
	agent, server := newDeliveryAgent(t, cloud.URL)
	clock := newManualSecretClock()
	useManualSecretClock(server, clock)
	if err := processTestDeployment(agent, context.Background(), testCommandID); err != nil {
		t.Fatalf("process deployment: %v", err)
	}
	commandBuffer := server.secretCmdQueue["AC1"][0].payload
	first := httptest.NewRecorder()
	server.handleGetRequest(
		first,
		httptest.NewRequest(http.MethodGet, "/iclock/getrequest?SN=AC1", nil),
	)
	if first.Body.String() == "OK" {
		t.Fatal("first scanner poll did not serve the command")
	}

	clock.Advance(secretCommandServeDeadline)

	result := waitDeliveryResult(t, fixture.results)
	if result.Status != "failed" ||
		result.ErrorCode != "network_unavailable" ||
		result.CommandID != testCommandID {
		t.Fatalf("deadline result = %#v", result)
	}
	server.mu.Lock()
	pending := len(server.secretPending)
	reserved := len(server.secretCmdID)
	server.mu.Unlock()
	if pending != 0 || reserved != 0 {
		t.Fatalf("no-poll expiry retained pending=%d reserved=%d", pending, reserved)
	}
	for index, value := range commandBuffer {
		if value != 0 {
			t.Fatalf("no-poll expiry retained command byte %d", index)
		}
	}
}

func TestBiometricDeliveryDeadlineAndACKBoundaryHasOneTerminalWinner(t *testing.T) {
	tests := []struct {
		name       string
		timeoutWin bool
		wantStatus string
		wantError  string
	}{
		{
			name:       "ACK wins before deadline callback",
			wantStatus: "applied",
		},
		{
			name:       "deadline callback wins before ACK",
			timeoutWin: true,
			wantStatus: "failed",
			wantError:  "network_unavailable",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newDeliveryFixture([]byte("fingerprint-template"))
			cloud := httptest.NewServer(fixture.handler(t))
			defer cloud.Close()
			agent, server := newDeliveryAgent(t, cloud.URL)
			clock := newManualSecretClock()
			useManualSecretClock(server, clock)
			if err := processTestDeployment(
				agent,
				context.Background(),
				testCommandID,
			); err != nil {
				t.Fatalf("process deployment: %v", err)
			}
			response := httptest.NewRecorder()
			server.handleGetRequest(
				response,
				httptest.NewRequest(
					http.MethodGet,
					"/iclock/getrequest?SN=AC1",
					nil,
				),
			)
			localID := strings.SplitN(
				strings.TrimPrefix(response.Body.String(), "C:"),
				":",
				2,
			)[0]
			ack := func() {
				server.handleDeviceCmd(
					httptest.NewRecorder(),
					httptest.NewRequest(
						http.MethodPost,
						"/iclock/devicecmd?SN=AC1",
						strings.NewReader("ID="+localID+"&Return=0"),
					),
				)
			}
			if tt.timeoutWin {
				clock.Advance(secretCommandServeDeadline)
				ack()
			} else {
				ack()
				clock.Advance(secretCommandServeDeadline)
			}

			result := waitDeliveryResult(t, fixture.results)
			if result.Status != tt.wantStatus || result.ErrorCode != tt.wantError {
				t.Fatalf("terminal result = %#v", result)
			}
			select {
			case duplicate := <-fixture.results:
				t.Fatalf("deadline/ACK race emitted duplicate result %#v", duplicate)
			case <-time.After(50 * time.Millisecond):
			}
		})
	}
}

func TestBiometricDeliveryRetransmitRevalidatesLiveCompatibility(t *testing.T) {
	fixture := newDeliveryFixture([]byte("fingerprint-template"))
	cloud := httptest.NewServer(fixture.handler(t))
	defer cloud.Close()
	agent, server := newDeliveryAgent(t, cloud.URL)
	if err := processTestDeployment(agent, context.Background(), testCommandID); err != nil {
		t.Fatalf("process deployment: %v", err)
	}
	first := httptest.NewRecorder()
	server.handleGetRequest(
		first,
		httptest.NewRequest(http.MethodGet, "/iclock/getrequest?SN=AC1", nil),
	)
	agent.devices.observeProtocol("AC1", ProtocolObservation{
		Path: "/iclock/registry",
		Capabilities: map[string]string{
			"fingeralgorithmversion": "13.0",
		},
	})

	retry := httptest.NewRecorder()
	server.handleGetRequest(
		retry,
		httptest.NewRequest(http.MethodGet, "/iclock/getrequest?SN=AC1", nil),
	)
	if retry.Body.String() != "OK" {
		t.Fatalf("drifted retransmit reached scanner: %q", retry.Body.String())
	}
	result := waitDeliveryResult(t, fixture.results)
	if result.ErrorCode != "algorithm_mismatch" {
		t.Fatalf("drift result = %#v", result)
	}
}

func TestBiometricDeliveryRechecksLiveStateBeforeServingQueuedCommand(t *testing.T) {
	fixture := newDeliveryFixture([]byte("fingerprint-template"))
	cloud := httptest.NewServer(fixture.handler(t))
	defer cloud.Close()
	agent, server := newDeliveryAgent(t, cloud.URL)
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
	agent, server := newDeliveryAgent(t, cloud.URL)
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
	agent, server := newDeliveryAgent(t, cloud.URL)
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

type secretResponseWriteTimeoutError struct{}

func (secretResponseWriteTimeoutError) Error() string   { return "write deadline exceeded" }
func (secretResponseWriteTimeoutError) Timeout() bool   { return true }
func (secretResponseWriteTimeoutError) Temporary() bool { return true }

type deadlineBlockingSecretResponseWriter struct {
	header       http.Header
	writes       int
	started      chan struct{}
	deadlineOnce sync.Once
	deadline     chan struct{}
}

func (w *deadlineBlockingSecretResponseWriter) Header() http.Header {
	return w.header
}

func (w *deadlineBlockingSecretResponseWriter) WriteHeader(_ int) {}

func (w *deadlineBlockingSecretResponseWriter) SetWriteDeadline(
	deadline time.Time,
) error {
	if deadline.IsZero() {
		return nil
	}
	time.AfterFunc(time.Until(deadline), func() {
		w.deadlineOnce.Do(func() {
			close(w.deadline)
		})
	})
	return nil
}

func (w *deadlineBlockingSecretResponseWriter) Write(value []byte) (int, error) {
	w.writes++
	if w.writes == 1 {
		return len(value), nil
	}
	close(w.started)
	<-w.deadline
	return 0, secretResponseWriteTimeoutError{}
}

type deadlineRecordingSecretResponseWriter struct {
	header   http.Header
	deadline chan time.Time
	body     bytes.Buffer
}

func (w *deadlineRecordingSecretResponseWriter) Header() http.Header {
	return w.header
}

func (w *deadlineRecordingSecretResponseWriter) WriteHeader(_ int) {}

func (w *deadlineRecordingSecretResponseWriter) SetWriteDeadline(
	deadline time.Time,
) error {
	w.deadline <- deadline
	return nil
}

func (w *deadlineRecordingSecretResponseWriter) Write(value []byte) (int, error) {
	return w.body.Write(value)
}

func TestBiometricDeliverySecretWriteDeadlineStartsAfterPayloadPin(
	t *testing.T,
) {
	command := &secretADMSCommand{
		deviceSN:     "AC1",
		deploymentID: testDeploymentID,
		commandID:    testCommandID,
		payload:      []byte("mutable-secret-command"),
	}
	server := &ADMSServer{
		secretCmdQueue: map[string][]*secretADMSCommand{"AC1": {command}},
		secretPending:  make(map[pendingCommandKey]*secretADMSCommand),
		secretCmdID:    map[string]struct{}{testCommandID: {}},
	}
	command = server.popSecretCommand("AC1")
	command.payloadMu.Lock()
	writer := &deadlineRecordingSecretResponseWriter{
		header:   make(http.Header),
		deadline: make(chan time.Time, 1),
	}
	type writeResult struct {
		written bool
		err     error
	}
	done := make(chan writeResult, 1)
	go func() {
		written, err := server.writePendingSecretADMSCommand(writer, command)
		done <- writeResult{written: written, err: err}
	}()

	select {
	case deadline := <-writer.deadline:
		command.payloadMu.Unlock()
		<-done
		t.Fatalf(
			"write deadline %s started while the owning writer was waiting for the payload pin",
			deadline,
		)
	case <-time.After(50 * time.Millisecond):
	}
	if command.serveAttempts != 1 {
		command.payloadMu.Unlock()
		<-done
		t.Fatalf("serve attempts while waiting for payload pin = %d; want 1", command.serveAttempts)
	}

	command.payloadMu.Unlock()
	select {
	case <-writer.deadline:
	case <-time.After(time.Second):
		t.Fatal("write deadline was not set immediately before the actual write")
	}
	result := <-done
	if !result.written || result.err != nil {
		t.Fatalf("write after payload pin written=%v err=%v", result.written, result.err)
	}
	server.shutdownBiometricDelivery()
}

func TestBiometricDeliveryConcurrentPollHasOneWriterAndResponsiveTerminalState(
	t *testing.T,
) {
	tests := []struct {
		name       string
		startEvent func(*ADMSServer, *manualSecretClock, int) <-chan struct{}
		stateReady func(*ADMSServer, pendingCommandKey) bool
	}{
		{
			name: "ACK",
			startEvent: func(
				server *ADMSServer,
				_ *manualSecretClock,
				localID int,
			) <-chan struct{} {
				done := make(chan struct{})
				go func() {
					server.completeSecretCommand(
						pendingCommandKey{DeviceSN: "AC1", LocalID: localID},
						0,
					)
					close(done)
				}()
				return done
			},
			stateReady: func(server *ADMSServer, key pendingCommandKey) bool {
				_, pending := server.secretPending[key]
				return !pending
			},
		},
		{
			name: "expiry",
			startEvent: func(
				_ *ADMSServer,
				clock *manualSecretClock,
				_ int,
			) <-chan struct{} {
				done := make(chan struct{})
				go func() {
					clock.Advance(secretCommandServeDeadline)
					close(done)
				}()
				return done
			},
			stateReady: func(server *ADMSServer, key pendingCommandKey) bool {
				_, pending := server.secretPending[key]
				return !pending
			},
		},
		{
			name: "shutdown",
			startEvent: func(
				server *ADMSServer,
				_ *manualSecretClock,
				_ int,
			) <-chan struct{} {
				done := make(chan struct{})
				go func() {
					server.shutdownBiometricDelivery()
					close(done)
				}()
				return done
			},
			stateReady: func(server *ADMSServer, _ pendingCommandKey) bool {
				return server.secretClosed && len(server.secretPending) == 0
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outbox, err := openBiometricResultOutbox(t.TempDir())
			if err != nil {
				t.Fatalf("open outbox: %v", err)
			}
			clock := newManualSecretClock()
			original := []byte("mutable-secret-command")
			command := &secretADMSCommand{
				deviceSN:     "AC1",
				deploymentID: testDeploymentID,
				commandID:    testCommandID,
				sha256:       strings.Repeat("a", 64),
				payload:      append([]byte(nil), original...),
			}
			server := &ADMSServer{
				secretCmdQueue:      map[string][]*secretADMSCommand{"AC1": {command}},
				secretPending:       make(map[pendingCommandKey]*secretADMSCommand),
				secretCmdID:         map[string]struct{}{testCommandID: {}},
				resultOutbox:        outbox,
				resultOutboxStarted: true,
			}
			useManualSecretClock(server, clock)

			first := server.popSecretCommand("AC1")
			firstWriter := &blockingSecretResponseWriter{
				header:  make(http.Header),
				started: make(chan struct{}),
				release: make(chan struct{}),
			}
			firstDone := make(chan error, 1)
			go func() {
				_, writeErr := server.writePendingSecretADMSCommand(firstWriter, first)
				firstDone <- writeErr
			}()
			<-firstWriter.started

			type claimResult struct {
				command *secretADMSCommand
				busy    bool
			}
			secondSelected := make(chan claimResult, 1)
			secondDone := make(chan error, 1)
			go func() {
				second, busy := server.claimSecretCommandWriter("AC1")
				secondSelected <- claimResult{command: second, busy: busy}
				if second == nil {
					secondDone <- nil
					return
				}
				_, writeErr := server.writePendingSecretADMSCommand(
					httptest.NewRecorder(),
					second,
				)
				secondDone <- writeErr
			}()
			second := <-secondSelected
			if second.command != nil {
				t.Errorf(
					"concurrent poll selected pending command %d while its writer was active",
					second.command.id,
				)
			}
			if !second.busy {
				t.Error("concurrent poll did not receive the immediate retry signal")
			}
			if first.serveAttempts != 1 {
				t.Errorf("concurrent poll incremented serve attempts to %d; want 1", first.serveAttempts)
			}

			reservationDone := make(chan bool, 1)
			go func() {
				ok, _ := server.reserveSecretCommand(testStaleID)
				reservationDone <- ok
			}()
			select {
			case reserved := <-reservationDone:
				if !reserved {
					t.Error("unrelated reservation was refused while a writer was active")
				}
			case <-time.After(100 * time.Millisecond):
				close(firstWriter.release)
				<-firstDone
				<-secondDone
				t.Fatal("duplicate writer blocked an unrelated reservation")
			}

			key := pendingCommandKey{DeviceSN: "AC1", LocalID: first.id}
			eventDone := tt.startEvent(server, clock, first.id)
			stateDeadline := time.Now().Add(100 * time.Millisecond)
			stateResponsive := false
			for time.Now().Before(stateDeadline) {
				if server.mu.TryLock() {
					stateResponsive = tt.stateReady(server, key)
					server.mu.Unlock()
					if stateResponsive {
						break
					}
				}
				time.Sleep(time.Millisecond)
			}
			if !stateResponsive {
				close(firstWriter.release)
				<-firstDone
				<-secondDone
				<-eventDone
				t.Fatalf("%s could not detach terminal state while the first writer was stalled", tt.name)
			}
			select {
			case <-eventDone:
				close(firstWriter.release)
				<-firstDone
				<-secondDone
				t.Fatalf("%s zeroed or completed before the active writer released its payload pin", tt.name)
			case <-time.After(25 * time.Millisecond):
			}

			close(firstWriter.release)
			if writeErr := <-firstDone; writeErr != nil {
				t.Fatalf("first writer release: %v", writeErr)
			}
			if writeErr := <-secondDone; writeErr != nil {
				t.Fatalf("second poll: %v", writeErr)
			}
			select {
			case <-eventDone:
			case <-time.After(time.Second):
				t.Fatalf("%s did not complete after the active writer released its payload pin", tt.name)
			}
			if !bytes.Equal(firstWriter.body, original) {
				t.Fatalf("first writer body = %q; want %q", firstWriter.body, original)
			}
			for index, value := range command.payload {
				if value != 0 {
					t.Fatalf("%s retained payload byte %d", tt.name, index)
				}
			}
			if tt.name != "shutdown" {
				server.shutdownBiometricDelivery()
			}
		})
	}
}

func TestBiometricDeliveryConcurrentPollAtAttemptLimitDoesNotWaitForWriter(
	t *testing.T,
) {
	command := &secretADMSCommand{
		deviceSN:     "AC1",
		deploymentID: testDeploymentID,
		commandID:    testCommandID,
		payload:      []byte("mutable-secret-command"),
	}
	server := &ADMSServer{
		secretCmdQueue: map[string][]*secretADMSCommand{"AC1": {command}},
		secretPending:  make(map[pendingCommandKey]*secretADMSCommand),
		secretCmdID:    map[string]struct{}{testCommandID: {}},
	}
	first := server.popSecretCommand("AC1")
	server.mu.Lock()
	first.serveAttempts = maxSecretCommandServeAttempts
	server.mu.Unlock()
	writer := &blockingSecretResponseWriter{
		header:  make(http.Header),
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := server.writePendingSecretADMSCommand(writer, first)
		writeDone <- writeErr
	}()
	<-writer.started

	type claimResult struct {
		command *secretADMSCommand
		busy    bool
	}
	secondDone := make(chan claimResult, 1)
	go func() {
		second, busy := server.claimSecretCommandWriter("AC1")
		secondDone <- claimResult{command: second, busy: busy}
	}()
	select {
	case second := <-secondDone:
		if second.command != nil {
			t.Errorf("attempt-limit poll selected active command %d", second.command.id)
		}
		if !second.busy {
			t.Error("attempt-limit poll did not receive the immediate retry signal")
		}
	case <-time.After(100 * time.Millisecond):
		close(writer.release)
		<-writeDone
		<-secondDone
		t.Fatal("attempt-limit poll waited for the active writer payload pin")
	}
	if first.serveAttempts != maxSecretCommandServeAttempts {
		close(writer.release)
		<-writeDone
		t.Fatalf(
			"attempt-limit poll changed serve attempts to %d; want %d",
			first.serveAttempts,
			maxSecretCommandServeAttempts,
		)
	}

	close(writer.release)
	if writeErr := <-writeDone; writeErr != nil {
		t.Fatalf("release active writer: %v", writeErr)
	}
	server.shutdownBiometricDelivery()
}

func TestBiometricDeliverySecretWriteDeadlineDurablyTerminatesAndReleases(
	t *testing.T,
) {
	outbox, err := openBiometricResultOutbox(t.TempDir())
	if err != nil {
		t.Fatalf("open outbox: %v", err)
	}
	payload := []byte("mutable-secret-command")
	command := &secretADMSCommand{
		deviceSN:     "AC1",
		deploymentID: testDeploymentID,
		commandID:    testCommandID,
		sha256:       strings.Repeat("a", 64),
		payload:      payload,
	}
	server := &ADMSServer{
		secretCmdQueue:      map[string][]*secretADMSCommand{"AC1": {command}},
		secretPending:       make(map[pendingCommandKey]*secretADMSCommand),
		secretCmdID:         map[string]struct{}{testCommandID: {}},
		resultOutbox:        outbox,
		resultOutboxStarted: true,
		secretWriteTimeout:  25 * time.Millisecond,
	}
	command = server.popSecretCommand("AC1")
	writer := &deadlineBlockingSecretResponseWriter{
		header:   make(http.Header),
		started:  make(chan struct{}),
		deadline: make(chan struct{}),
	}

	done := make(chan error, 1)
	go func() {
		_, writeErr := server.writePendingSecretADMSCommand(writer, command)
		done <- writeErr
	}()
	<-writer.started
	select {
	case writeErr := <-done:
		if writeErr == nil {
			t.Fatal("deadline-blocked secret write returned no error")
		}
	case <-time.After(time.Second):
		t.Fatal("deadline-blocked secret write did not terminate")
	}

	records := outbox.snapshot()
	if len(records) != 1 ||
		records[0].CommandID != testCommandID ||
		records[0].ErrorCode != "network_unavailable" {
		t.Fatalf("deadline result = %#v", records)
	}
	for index, value := range payload {
		if value != 0 {
			t.Fatalf("deadline retained secret payload byte %d", index)
		}
	}
	server.mu.Lock()
	_, active := server.secretCmdID[testCommandID]
	pending := len(server.secretPending)
	server.mu.Unlock()
	if active || pending != 0 {
		t.Fatalf("deadline retained active=%v pending=%d", active, pending)
	}

	shutdownDone := make(chan struct{})
	go func() {
		server.shutdownBiometricDelivery()
		close(shutdownDone)
	}()
	select {
	case <-shutdownDone:
	case <-time.After(time.Second):
		t.Fatal("shutdown stalled after the secret write deadline")
	}
}

func TestBiometricDeliveryBlockedWriteDoesNotStallOtherCommandProgress(
	t *testing.T,
) {
	outbox, err := openBiometricResultOutbox(t.TempDir())
	if err != nil {
		t.Fatalf("open outbox: %v", err)
	}
	command := &secretADMSCommand{
		deviceSN:     "AC1",
		deploymentID: testDeploymentID,
		commandID:    testCommandID,
		sha256:       strings.Repeat("a", 64),
		payload:      []byte("mutable-secret-command"),
	}
	server := &ADMSServer{
		secretCmdQueue:      map[string][]*secretADMSCommand{"AC1": {command}},
		secretPending:       make(map[pendingCommandKey]*secretADMSCommand),
		secretCmdID:         map[string]struct{}{testCommandID: {}},
		resultOutbox:        outbox,
		resultOutboxStarted: true,
	}
	command = server.popSecretCommand("AC1")
	writer := &blockingSecretResponseWriter{
		header:  make(http.Header),
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := server.writePendingSecretADMSCommand(writer, command)
		writeDone <- writeErr
	}()
	<-writer.started

	expireDone := make(chan struct{})
	go func() {
		server.expirePendingSecretCommand(command)
		close(expireDone)
	}()
	time.Sleep(25 * time.Millisecond)

	reserved := make(chan bool, 1)
	go func() {
		ok, _ := server.reserveSecretCommand(testStaleID)
		reserved <- ok
	}()
	select {
	case ok := <-reserved:
		if !ok {
			t.Fatal("unrelated command was refused while one write was blocked")
		}
	case <-time.After(100 * time.Millisecond):
		close(writer.release)
		<-writeDone
		<-expireDone
		t.Fatal("blocked secret I/O stalled unrelated command progress")
	}

	close(writer.release)
	if writeErr := <-writeDone; writeErr != nil {
		t.Fatalf("release blocked write: %v", writeErr)
	}
	<-expireDone
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

func TestBiometricDeliveryRejectsNonCanonicalUUIDsAtEveryIngress(t *testing.T) {
	canonicalDeploymentID := "abcdefab-cdef-4abc-8def-abcdefabcdea"
	canonicalCommandID := "abcdefab-cdef-4abc-8def-abcdefabcdef"
	uppercaseDeploymentID := strings.ToUpper(canonicalDeploymentID)
	uppercaseCommandID := strings.ToUpper(canonicalCommandID)
	if validBiometricUUID(uppercaseDeploymentID) ||
		validBiometricUUID(uppercaseCommandID) {
		t.Fatal("uppercase UUID text was accepted as canonical")
	}

	t.Run("reference", func(t *testing.T) {
		server := &ADMSServer{
			agent:          &Agent{},
			secretCmdQueue: make(map[string][]*secretADMSCommand),
			secretPending:  make(map[pendingCommandKey]*secretADMSCommand),
			secretCmdID:    make(map[string]struct{}),
		}
		if !server.interceptBiometricDeploymentReference("AC1", ADMSCommand{
			CloudID: uppercaseCommandID,
			Command: "DEPLOY_BIOMETRIC_ASSET " + uppercaseDeploymentID,
		}) {
			t.Fatal("uppercase typed reference was not intercepted")
		}
		server.mu.Lock()
		reservations := len(server.secretCmdID)
		server.mu.Unlock()
		if reservations != 0 {
			t.Fatalf("uppercase typed reference retained %d reservation(s)", reservations)
		}
	})

	t.Run("claim", func(t *testing.T) {
		fixture := newDeliveryFixture([]byte("fingerprint-template"))
		fixture.claimCommand = uppercaseCommandID
		cloud := httptest.NewServer(fixture.handler(t))
		defer cloud.Close()
		agent, server := newDeliveryAgent(t, cloud.URL)
		err := agent.ProcessBiometricDeployment(
			withBiometricDeploymentCommandID(
				context.Background(),
				uppercaseCommandID,
			),
			testDeploymentID,
			"AC1",
		)
		if err == nil || err.Error() != "stale_deployment_command" {
			t.Fatalf("uppercase claim command error = %v", err)
		}
		fixture.mu.Lock()
		claims := fixture.claimCount
		fixture.mu.Unlock()
		if claims != 0 {
			t.Fatalf("uppercase command reached claim ingress %d time(s)", claims)
		}
		server.mu.Lock()
		queued := len(server.secretCmdQueue["AC1"])
		server.mu.Unlock()
		if queued != 0 {
			t.Fatal("uppercase claim command queued scanner bytes")
		}
	})

	t.Run("result", func(t *testing.T) {
		outbox, err := openBiometricResultOutbox(t.TempDir())
		if err != nil {
			t.Fatalf("open outbox: %v", err)
		}
		server := &ADMSServer{
			secretCmdID:  map[string]struct{}{uppercaseCommandID: {}},
			resultOutbox: outbox,
			secretClosed: true,
		}
		server.startBiometricResultWorker(
			testOutboxResult(uppercaseCommandID),
			testDeploymentID,
		)
		if records := outbox.snapshot(); len(records) != 0 {
			t.Fatalf("uppercase result entered durable outbox: %#v", records)
		}
		server.mu.Lock()
		pending := len(server.resultEnqueuePending)
		_, active := server.secretCmdID[uppercaseCommandID]
		server.mu.Unlock()
		if pending != 0 || active {
			t.Fatalf("uppercase result retained pending=%d active=%v", pending, active)
		}
	})
}

func TestBiometricDeliveryTerminalEventBeforeWritePreventsEmptyCommandWrite(
	t *testing.T,
) {
	tests := []struct {
		name      string
		terminate func(*ADMSServer, *manualSecretClock, int)
	}{
		{
			name: "ACK before write pin",
			terminate: func(
				server *ADMSServer,
				_ *manualSecretClock,
				localID int,
			) {
				server.completeSecretCommand(
					pendingCommandKey{DeviceSN: "AC1", LocalID: localID},
					0,
				)
			},
		},
		{
			name: "timeout before write pin",
			terminate: func(
				_ *ADMSServer,
				clock *manualSecretClock,
				_ int,
			) {
				clock.Advance(secretCommandServeDeadline)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock := newManualSecretClock()
			command := &secretADMSCommand{
				deviceSN:     "AC1",
				deploymentID: testDeploymentID,
				commandID:    testCommandID,
				payload:      []byte("mutable-secret-command"),
			}
			server := &ADMSServer{
				secretCmdQueue: map[string][]*secretADMSCommand{
					"AC1": {command},
				},
				secretPending: make(map[pendingCommandKey]*secretADMSCommand),
				secretCmdID:   map[string]struct{}{testCommandID: {}},
			}
			useManualSecretClock(server, clock)
			command = server.popSecretCommand("AC1")
			tt.terminate(server, clock, command.id)

			writer := httptest.NewRecorder()
			written, err := server.writePendingSecretADMSCommand(writer, command)
			if err != nil {
				t.Fatalf("write pending command: %v", err)
			}
			if written {
				t.Fatal("terminal pre-write command was counted as written")
			}
			if writer.Body.Len() != 0 {
				t.Fatalf("terminal pre-write command wrote %q", writer.Body.String())
			}
		})
	}
}

func TestBiometricDeliveryTerminalEventDuringWriteWaitsForPinnedPayload(
	t *testing.T,
) {
	tests := []struct {
		name      string
		terminate func(*ADMSServer, *manualSecretClock, int)
	}{
		{
			name: "ACK during write",
			terminate: func(
				server *ADMSServer,
				_ *manualSecretClock,
				localID int,
			) {
				server.completeSecretCommand(
					pendingCommandKey{DeviceSN: "AC1", LocalID: localID},
					0,
				)
			},
		},
		{
			name: "timeout during write",
			terminate: func(
				_ *ADMSServer,
				clock *manualSecretClock,
				_ int,
			) {
				clock.Advance(secretCommandServeDeadline)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock := newManualSecretClock()
			original := []byte("mutable-secret-command")
			command := &secretADMSCommand{
				deviceSN:     "AC1",
				deploymentID: testDeploymentID,
				commandID:    testCommandID,
				payload:      append([]byte(nil), original...),
			}
			server := &ADMSServer{
				secretCmdQueue: map[string][]*secretADMSCommand{
					"AC1": {command},
				},
				secretPending: make(map[pendingCommandKey]*secretADMSCommand),
				secretCmdID:   map[string]struct{}{testCommandID: {}},
			}
			useManualSecretClock(server, clock)
			command = server.popSecretCommand("AC1")
			writer := &blockingSecretResponseWriter{
				header:  make(http.Header),
				started: make(chan struct{}),
				release: make(chan struct{}),
			}
			writeDone := make(chan struct {
				written bool
				err     error
			}, 1)
			go func() {
				written, err := server.writePendingSecretADMSCommand(
					writer,
					command,
				)
				writeDone <- struct {
					written bool
					err     error
				}{written: written, err: err}
			}()
			<-writer.started
			terminalDone := make(chan struct{})
			go func() {
				tt.terminate(server, clock, command.id)
				close(terminalDone)
			}()
			select {
			case <-terminalDone:
				close(writer.release)
				<-writeDone
				t.Fatal("terminal event did not wait for pinned payload")
			case <-time.After(50 * time.Millisecond):
			}
			close(writer.release)
			writeResult := <-writeDone
			if !writeResult.written || writeResult.err != nil {
				t.Fatalf(
					"pinned write written=%v err=%v",
					writeResult.written,
					writeResult.err,
				)
			}
			<-terminalDone
			if !bytes.Equal(writer.body, original) {
				t.Fatalf("pinned write body = %q; want %q", writer.body, original)
			}
			for index, value := range command.payload {
				if value != 0 {
					t.Fatalf("terminal event retained payload byte %d", index)
				}
			}
		})
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
	_, server := newDeliveryAgent(t, cloud.URL)
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
	_, server := newDeliveryAgent(t, cloud.URL)

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
	agent, server := newDeliveryAgent(t, cloud.URL)
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
	select {
	case result := <-fixture.results:
		encoded, _ := json.Marshal(result)
		if bytes.Contains(encoded, secret) ||
			bytes.Contains(encoded, []byte(base64.StdEncoding.EncodeToString(secret))) {
			t.Fatalf("result body leaked raw biometric payload")
		}
		t.Fatalf("secret ACK with echoed biometric field was accepted: %#v", result)
	case <-time.After(50 * time.Millisecond):
	}
	if len(server.secretPending) != 1 {
		t.Fatal("malformed secret ACK removed the pending command")
	}
	server.shutdownBiometricDelivery()
}

func TestBiometricDeliverySecretACKStrictParsingAndZeroing(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "echoed template", body: "ID=7&Return=0&Template=secret"},
		{name: "echoed tmp", body: "ID=7&Return=0&TMP=secret"},
		{name: "echoed photo", body: "ID=7&Return=0&Photo=secret"},
		{name: "duplicate id", body: "ID=7&ID=7&Return=0"},
		{name: "duplicate return", body: "ID=7&Return=0&Return=0"},
		{name: "malformed return", body: "ID=7&Return=not-a-number"},
		{name: "unknown field", body: "ID=7&Return=0&Extra=1"},
		{name: "oversize", body: "ID=7&Return=0&" + strings.Repeat("X", maxSecretACKBodyBytes)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := &ADMSServer{
				secretPending: map[pendingCommandKey]*secretADMSCommand{
					{DeviceSN: "AC1", LocalID: 7}: {
						id:        7,
						deviceSN:  "AC1",
						commandID: testCommandID,
						payload:   []byte("mutable-command"),
					},
				},
				secretCmdID: map[string]struct{}{testCommandID: {}},
			}
			body := []byte(tt.body)
			handled, accepted := server.handleSecretDeviceCommandACK("AC1", body)
			if !handled || accepted {
				t.Fatalf("handled=%v accepted=%v; want true,false", handled, accepted)
			}
			if len(server.secretPending) != 1 {
				t.Fatal("invalid secret ACK removed pending command")
			}
			for index, value := range body {
				if value != 0 {
					t.Fatalf("ACK byte %d was not zeroed", index)
				}
			}
		})
	}
}

func TestBiometricDeliverySecretACKCannotFallThroughGenericPercentDecoding(
	t *testing.T,
) {
	command := &secretADMSCommand{
		id:           7,
		deviceSN:     "AC1",
		deploymentID: testDeploymentID,
		commandID:    testCommandID,
		payload:      []byte("mutable-command"),
	}
	server := &ADMSServer{
		pendingCmd: make(map[pendingCommandKey]ADMSCommand),
		secretPending: map[pendingCommandKey]*secretADMSCommand{
			{DeviceSN: "AC1", LocalID: 7}: command,
		},
		secretCmdID: map[string]struct{}{testCommandID: {}},
	}
	server.handleDeviceCmd(
		httptest.NewRecorder(),
		httptest.NewRequest(
			http.MethodPost,
			"/iclock/devicecmd?SN=AC1",
			strings.NewReader("%49D=7&Return=0"),
		),
	)
	if len(server.secretPending) != 1 {
		t.Fatal("percent-encoded secret ACK bypassed strict mutable-byte parsing")
	}
	if !bytes.Equal(command.payload, []byte("mutable-command")) {
		t.Fatal("rejected encoded ACK zeroed pending command bytes")
	}
}

func TestDeviceCommandACKRoutingResolvesEncodedIDBeforeChoosingParser(
	t *testing.T,
) {
	server := &ADMSServer{
		pendingCmd: map[pendingCommandKey]ADMSCommand{
			{DeviceSN: "AC1", LocalID: 9}: {ID: 9},
		},
		secretPending: map[pendingCommandKey]*secretADMSCommand{
			{DeviceSN: "AC1", LocalID: 7}: {
				id:       7,
				deviceSN: "AC1",
				payload:  []byte("mutable-command"),
			},
		},
	}
	tests := []struct {
		name string
		body []byte
		want deviceCommandACKRoute
	}{
		{
			name: "encoded secret ID remains strict",
			body: []byte("%49D=%37&Return=0&Template=hostile"),
			want: deviceCommandACKSecret,
		},
		{
			name: "encoded generic ID remains generic",
			body: []byte("%49D=%39&Return=0&Result=generic"),
			want: deviceCommandACKGeneric,
		},
		{
			name: "duplicate IDs prefer secret routing",
			body: []byte("ID=9&ID=7&Return=0"),
			want: deviceCommandACKSecret,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := server.routeDeviceCommandACK("AC1", tt.body); got != tt.want {
				t.Fatalf("route = %v; want %v", got, tt.want)
			}
		})
	}
}

func TestGenericDeviceCommandACKBehaviorRemainsSeparate(t *testing.T) {
	reported := make(chan map[string]any, 1)
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode generic result: %v", err)
		}
		reported <- body
		w.WriteHeader(http.StatusOK)
	}))
	defer cloud.Close()
	server := &ADMSServer{
		agent: &Agent{config: Config{
			APIKey:      "agent-key",
			PlamatixURL: cloud.URL,
		}},
		pendingCmd: map[pendingCommandKey]ADMSCommand{
			{DeviceSN: "AC1", LocalID: 9}: {
				ID:      9,
				CloudID: testStaleID,
			},
		},
		cloudCmdID:    map[string]struct{}{testStaleID: {}},
		secretPending: make(map[pendingCommandKey]*secretADMSCommand),
	}
	server.handleDeviceCmd(
		httptest.NewRecorder(),
		httptest.NewRequest(
			http.MethodPost,
			"/iclock/devicecmd?SN=AC1",
			strings.NewReader("ID=9&Return=-7&Result=generic"),
		),
	)
	select {
	case body := <-reported:
		if body["id"] != testStaleID ||
			body["returnCode"] != float64(-7) ||
			body["resultBody"] != "ID=9&Return=-7" {
			t.Fatalf("generic result body = %#v", body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("generic ACK was not reported")
	}
}

func TestGenericDeviceCommandACKWithAnotherSecretPendingKeepsGenericBehavior(
	t *testing.T,
) {
	reported := make(chan map[string]any, 1)
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode generic result: %v", err)
		}
		reported <- body
		w.WriteHeader(http.StatusOK)
	}))
	defer cloud.Close()
	secret := &secretADMSCommand{
		id:           7,
		deviceSN:     "AC1",
		deploymentID: testDeploymentID,
		commandID:    testCommandID,
		payload:      []byte("mutable-command"),
	}
	server := &ADMSServer{
		agent: &Agent{config: Config{
			APIKey:      "agent-key",
			PlamatixURL: cloud.URL,
		}},
		pendingCmd: map[pendingCommandKey]ADMSCommand{
			{DeviceSN: "AC1", LocalID: 9}: {
				ID:      9,
				CloudID: testStaleID,
			},
		},
		cloudCmdID: map[string]struct{}{testStaleID: {}},
		secretPending: map[pendingCommandKey]*secretADMSCommand{
			{DeviceSN: "AC1", LocalID: 7}: secret,
		},
		secretCmdID: map[string]struct{}{testCommandID: {}},
	}
	server.handleDeviceCmd(
		httptest.NewRecorder(),
		httptest.NewRequest(
			http.MethodPost,
			"/iclock/devicecmd?SN=AC1",
			strings.NewReader(
				"ID=9&Return=-7&Result="+strings.Repeat("g", 300),
			),
		),
	)
	select {
	case body := <-reported:
		if body["id"] != testStaleID ||
			body["returnCode"] != float64(-7) ||
			body["resultBody"] != "ID=9&Return=-7" {
			t.Fatalf("generic result body = %#v", body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("generic ACK alongside secret pending was not reported")
	}
	server.mu.Lock()
	pendingSecret := server.secretPending[pendingCommandKey{DeviceSN: "AC1", LocalID: 7}]
	server.mu.Unlock()
	if pendingSecret != secret ||
		!bytes.Equal(secret.payload, []byte("mutable-command")) {
		t.Fatal("generic ACK changed the unrelated pending secret command")
	}
}

type ackBodyReadBarrier struct {
	body    []byte
	started chan struct{}
	release chan struct{}
	sent    bool
}

func (reader *ackBodyReadBarrier) Read(destination []byte) (int, error) {
	if !reader.sent {
		reader.sent = true
		written := copy(destination, reader.body)
		close(reader.started)
		return written, nil
	}
	<-reader.release
	return 0, io.EOF
}

func TestDeviceCommandACKRoutesSecretCreatedWhileBodyIsRead(t *testing.T) {
	body := []byte("ID=7&Return=0")
	reader := &ackBodyReadBarrier{
		body:    body,
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	command := &secretADMSCommand{
		id:           7,
		deviceSN:     "AC1",
		deploymentID: testDeploymentID,
		commandID:    testCommandID,
		payload:      []byte("mutable-command"),
	}
	commandBuffer := command.payload
	server := &ADMSServer{
		pendingCmd:    make(map[pendingCommandKey]ADMSCommand),
		secretPending: make(map[pendingCommandKey]*secretADMSCommand),
		secretCmdID:   map[string]struct{}{testCommandID: {}},
	}
	done := make(chan struct{})
	go func() {
		server.handleDeviceCmd(
			httptest.NewRecorder(),
			httptest.NewRequest(
				http.MethodPost,
				"/iclock/devicecmd?SN=AC1",
				reader,
			),
		)
		close(done)
	}()
	<-reader.started
	server.mu.Lock()
	server.secretPending[pendingCommandKey{DeviceSN: "AC1", LocalID: 7}] = command
	server.mu.Unlock()
	close(reader.release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ACK handler did not finish")
	}
	server.mu.Lock()
	_, pending := server.secretPending[pendingCommandKey{DeviceSN: "AC1", LocalID: 7}]
	server.mu.Unlock()
	if pending {
		t.Fatal("ACK used a pre-read device-wide snapshot and missed the exact secret ID")
	}
	for index, value := range commandBuffer {
		if value != 0 {
			t.Fatalf("ACK-created-during-read retained command byte %d", index)
		}
	}
}
