package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const testVaultAssetID = "44444444-4444-4444-8444-444444444444"

type deletionFixture struct {
	t              *testing.T
	mu             sync.Mutex
	claims         int
	rechecks       int
	payloadFetch   int
	results        []map[string]any
	claimStatus    int
	recheckStatus  int
	claimBody      map[string]any
	recheckBody    map[string]any
	resultFailures int
	resultReady    chan struct{}
}

func newDeletionFixture(t *testing.T) *deletionFixture {
	t.Helper()
	return &deletionFixture{
		t:             t,
		claimStatus:   http.StatusOK,
		recheckStatus: http.StatusOK,
		resultReady:   make(chan struct{}, 4),
		claimBody: map[string]any{
			"operation":    "delete",
			"deploymentId": testDeploymentID,
			"commandId":    testCommandID,
			"attempt":      2,
			"deviceSn":     "AC1",
			"personnelId":  "14",
			"vaultAssetId": testVaultAssetID,
			"asset": map[string]any{
				"kind":      "fingerprint_template",
				"bioType":   1,
				"slotIndex": 3,
			},
		},
	}
}

func (fixture *deletionFixture) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch {
		case request.URL.Path == "/api/agent-bridge/biometric-vault/deployments" &&
			request.Method == http.MethodPost:
			body, err := io.ReadAll(request.Body)
			if err != nil {
				fixture.t.Errorf("read claim: %v", err)
				http.Error(w, "read", http.StatusInternalServerError)
				return
			}
			var input map[string]any
			if json.Unmarshal(body, &input) != nil {
				fixture.t.Errorf("invalid claim JSON: %q", body)
			}
			if request.Header.Get("X-API-Key") != "agent-key" {
				fixture.t.Errorf("missing claim API key")
			}
			fixture.mu.Lock()
			if recheck, exists := input["recheck"]; exists {
				fixture.rechecks++
				want := map[string]any{
					"attempt":      float64(2),
					"vaultAssetId": testVaultAssetID,
				}
				if got, ok := recheck.(map[string]any); !ok ||
					got["attempt"] != want["attempt"] ||
					got["vaultAssetId"] != want["vaultAssetId"] ||
					len(got) != len(want) {
					fixture.t.Errorf("recheck = %#v; want %#v", recheck, want)
				}
			} else {
				fixture.claims++
			}
			status := fixture.claimStatus
			if _, rechecking := input["recheck"]; rechecking {
				status = fixture.recheckStatus
			}
			claim := fixture.claimBody
			if _, rechecking := input["recheck"]; rechecking &&
				fixture.recheckBody != nil {
				claim = fixture.recheckBody
			}
			fixture.mu.Unlock()
			if status != http.StatusOK {
				w.WriteHeader(status)
				_, _ = w.Write([]byte(`{"error":"stale_deployment_attempt"}`))
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deployments": []any{claim},
			})
		case strings.HasSuffix(request.URL.Path, "/payload"):
			fixture.mu.Lock()
			fixture.payloadFetch++
			fixture.mu.Unlock()
			http.Error(w, "delete must not fetch payload", http.StatusInternalServerError)
		case request.URL.Path == "/api/agent-bridge/biometric-vault/deployments/"+
			testDeploymentID+"/result" && request.Method == http.MethodPost:
			var result map[string]any
			decoder := json.NewDecoder(request.Body)
			if err := decoder.Decode(&result); err != nil {
				fixture.t.Errorf("decode result: %v", err)
			}
			fixture.mu.Lock()
			fixture.results = append(fixture.results, result)
			resultNumber := len(fixture.results)
			failures := fixture.resultFailures
			fixture.mu.Unlock()
			fixture.resultReady <- struct{}{}
			if resultNumber <= failures {
				http.Error(w, "lost response", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":           true,
				"deploymentId": testDeploymentID,
				"status":       result["status"],
			})
		case request.URL.Path == "/api/agent-bridge/commands":
			_, _ = w.Write([]byte(`{"commands":[]}`))
		default:
			http.NotFound(w, request)
		}
	})
}

func (fixture *deletionFixture) snapshot() (int, int, int, []map[string]any) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return fixture.claims, fixture.rechecks, fixture.payloadFetch,
		append([]map[string]any(nil), fixture.results...)
}

func processTestDeletion(agent *Agent, ctx context.Context, commandID string) error {
	return agent.ProcessBiometricDeletion(
		withBiometricDeploymentCommandID(ctx, commandID),
		testDeploymentID,
		"AC1",
	)
}

func TestBiometricDeletionReferenceParserIsExact(t *testing.T) {
	tests := []struct {
		command      string
		wantID       string
		wantTypedRef bool
	}{
		{"DELETE_BIOMETRIC_ASSET " + testDeploymentID, testDeploymentID, true},
		{" DELETE_BIOMETRIC_ASSET " + testDeploymentID + " ", "", true},
		{"DELETE_BIOMETRIC_ASSET\t" + testDeploymentID, "", true},
		{"DELETE_BIOMETRIC_ASSET AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", "", true},
		{"DELETE_BIOMETRIC_ASSET " + testDeploymentID + " extra", "", true},
		{"DEPLOY_BIOMETRIC_ASSET " + testDeploymentID, "", false},
		{"delete_biometric_asset " + testDeploymentID, "", false},
	}
	for _, test := range tests {
		t.Run(test.command, func(t *testing.T) {
			gotID, gotTypedRef := parseBiometricDeletionReference(test.command)
			if gotID != test.wantID || gotTypedRef != test.wantTypedRef {
				t.Fatalf(
					"parseBiometricDeletionReference(%q) = (%q, %t); want (%q, %t)",
					test.command,
					gotID,
					gotTypedRef,
					test.wantID,
					test.wantTypedRef,
				)
			}
		})
	}
}

func TestBiometricDeletionRenderMatrix(t *testing.T) {
	tests := []struct {
		name     string
		state    DeviceProtocolState
		metadata biometricDeletionMetadata
		want     string
		wantCode string
	}{
		{
			name: "TA before 2.2.14 uses FP",
			state: DeviceProtocolState{
				Profile: ProtocolTAPush, Confidence: 90, PushVersion: "2.2.13",
				Capabilities: map[string]string{
					"fingerfunon": "1", "fingeralgorithmversion": "10.0",
				},
			},
			metadata: biometricDeletionMetadata{
				PersonnelID: "14", Kind: "fingerprint_template", BioType: 1, SlotIndex: 3,
			},
			want: "DATA DELETE FP PIN=14\tFID=3",
		},
		{
			name: "TA 2.2.14 legacy uses FINGERTMP",
			state: DeviceProtocolState{
				Profile: ProtocolTAPush, Confidence: 90, PushVersion: "2.2.14",
				Capabilities: map[string]string{
					"fingerfunon": "1", "fingeralgorithmversion": "10.0",
				},
			},
			metadata: biometricDeletionMetadata{
				PersonnelID: "14", Kind: "fingerprint_template", BioType: 1, SlotIndex: 3,
			},
			want: "DATA DELETE FINGERTMP PIN=14\tFID=3",
		},
		{
			name: "modern TA fingerprint uses BIODATA",
			state: DeviceProtocolState{
				Profile: ProtocolTAPush, Confidence: 90, PushVersion: "2.4.1",
				Capabilities: map[string]string{
					"fingerfunon": "1", "biodatafun": "1",
					"fingeralgorithmversion": "12.0",
				},
			},
			metadata: biometricDeletionMetadata{
				PersonnelID: "14", Kind: "fingerprint_template", BioType: 1, SlotIndex: 3,
			},
			want: "DATA DELETE BIODATA Pin=14\tNo=3\tType=1",
		},
		{
			name: "AC face template uses BIODATA",
			state: DeviceProtocolState{
				Profile: ProtocolACPush3, Confidence: 90,
				Capabilities: map[string]string{
					"facefunon": "1", "biodatafun": "1",
					"facealgorithmversion": "7.1",
				},
			},
			metadata: biometricDeletionMetadata{
				PersonnelID: "14", Kind: "face_template", BioType: 9, SlotIndex: 0,
			},
			want: "DATA DELETE BIODATA Pin=14\tNo=0\tType=9",
		},
		{
			name: "AC comparison photo uses BIOPHOTO",
			state: DeviceProtocolState{
				Profile: ProtocolACPush3, Confidence: 90,
				Capabilities: map[string]string{
					"facefunon": "1", "biophotofun": "1",
				},
			},
			metadata: biometricDeletionMetadata{
				PersonnelID: "14", Kind: "face_comparison_photo", BioType: 9, SlotIndex: 0,
			},
			want: "DATA DELETE BIOPHOTO PIN=14\tNo=0\tType=9",
		},
		{
			name:  "unknown profile fails closed",
			state: DeviceProtocolState{},
			metadata: biometricDeletionMetadata{
				PersonnelID: "14", Kind: "fingerprint_template", BioType: 1, SlotIndex: 3,
			},
			wantCode: "target_profile_untrusted",
		},
		{
			name: "TA face is unsupported",
			state: DeviceProtocolState{
				Profile: ProtocolTAPush, Confidence: 90, PushVersion: "2.4.1",
				Capabilities: map[string]string{"facefunon": "1", "biodatafun": "1"},
			},
			metadata: biometricDeletionMetadata{
				PersonnelID: "14", Kind: "face_template", BioType: 9, SlotIndex: 0,
			},
			wantCode: "record_type_unsupported",
		},
		{
			name: "invalid slot fails closed",
			state: DeviceProtocolState{
				Profile: ProtocolACPush3, Confidence: 90,
				Capabilities: map[string]string{"fingerfunon": "1", "biodatafun": "1"},
			},
			metadata: biometricDeletionMetadata{
				PersonnelID: "14", Kind: "fingerprint_template", BioType: 1, SlotIndex: 10,
			},
			wantCode: "invalid_deployment_claim",
		},
		{
			name: "kind and type mismatch fails closed",
			state: DeviceProtocolState{
				Profile: ProtocolACPush3, Confidence: 90,
				Capabilities: map[string]string{"facefunon": "1", "biodatafun": "1"},
			},
			metadata: biometricDeletionMetadata{
				PersonnelID: "14", Kind: "face_template", BioType: 1, SlotIndex: 0,
			},
			wantCode: "invalid_deployment_claim",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rendered, code := renderBiometricDeletionCommand(test.state, test.metadata)
			defer zeroBytes(rendered)
			if string(rendered) != test.want || code != test.wantCode {
				t.Fatalf(
					"renderBiometricDeletionCommand() = (%q, %q); want (%q, %q)",
					rendered,
					code,
					test.want,
					test.wantCode,
				)
			}
		})
	}
}

func TestBiometricDeletionClaimRecheckQueueAckAndSafeResult(t *testing.T) {
	fixture := newDeletionFixture(t)
	cloud := httptest.NewServer(fixture.handler())
	defer cloud.Close()
	agent, server := newDeliveryAgent(t, cloud.URL)

	if err := processTestDeletion(agent, context.Background(), testCommandID); err != nil {
		t.Fatalf("process deletion: %v", err)
	}
	if len(server.secretCmdQueue["AC1"]) != 1 {
		t.Fatalf("secret queue length = %d; want 1", len(server.secretCmdQueue["AC1"]))
	}

	response := httptest.NewRecorder()
	server.handleGetRequest(
		response,
		httptest.NewRequest(http.MethodGet, "/iclock/getrequest?SN=AC1", nil),
	)
	if got := response.Body.String(); !strings.HasSuffix(
		got,
		":DATA DELETE BIODATA Pin=14\tNo=3\tType=1",
	) {
		t.Fatalf("scanner command = %q", got)
	}
	localID := strings.SplitN(strings.TrimPrefix(response.Body.String(), "C:"), ":", 2)[0]
	server.handleDeviceCmd(
		httptest.NewRecorder(),
		httptest.NewRequest(
			http.MethodPost,
			"/iclock/devicecmd?SN=AC1",
			strings.NewReader("ID="+localID+"&Return=0"),
		),
	)

	select {
	case <-fixture.resultReady:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for delete result")
	}
	claims, rechecks, payloadFetches, results := fixture.snapshot()
	if claims != 1 || rechecks != 1 || payloadFetches != 0 || len(results) != 1 {
		t.Fatalf(
			"calls = claims:%d rechecks:%d payload:%d results:%d",
			claims,
			rechecks,
			payloadFetches,
			len(results),
		)
	}
	want := map[string]any{
		"operation":    "delete",
		"status":       "applied",
		"deviceSn":     "AC1",
		"commandId":    testCommandID,
		"attempt":      float64(2),
		"vaultAssetId": testVaultAssetID,
		"returnCode":   float64(0),
	}
	if len(results[0]) != len(want) {
		t.Fatalf("result = %#v; want exact metadata-only fields %#v", results[0], want)
	}
	for key, value := range want {
		if results[0][key] != value {
			t.Fatalf("result[%q] = %#v; want %#v", key, results[0][key], value)
		}
	}
	serialized, _ := json.Marshal(results[0])
	for _, forbidden := range [][]byte{
		[]byte("sha256"),
		[]byte("personnelId"),
		[]byte("payload"),
		[]byte("deliveryToken"),
		[]byte("DATA DELETE"),
		[]byte("PIN"),
	} {
		if bytes.Contains(serialized, forbidden) {
			t.Fatalf("safe delete result contains forbidden bytes %q: %s", forbidden, serialized)
		}
	}
}

func TestBiometricDeletionStaleRecheckQueuesAndReportsNothing(t *testing.T) {
	fixture := newDeletionFixture(t)
	fixture.recheckStatus = http.StatusConflict
	cloud := httptest.NewServer(fixture.handler())
	defer cloud.Close()
	agent, server := newDeliveryAgent(t, cloud.URL)

	err := processTestDeletion(agent, context.Background(), testCommandID)
	if deliveryErrorCode(err) != "stale_deployment_attempt" {
		t.Fatalf("error = %v; want stale_deployment_attempt", err)
	}
	claims, rechecks, payloadFetches, results := fixture.snapshot()
	if claims != 1 || rechecks != 1 || payloadFetches != 0 || len(results) != 0 {
		t.Fatalf(
			"calls = claims:%d rechecks:%d payload:%d results:%d",
			claims,
			rechecks,
			payloadFetches,
			len(results),
		)
	}
	if len(server.secretCmdQueue["AC1"]) != 0 ||
		len(server.secretPending) != 0 ||
		len(server.resultOutbox.snapshot()) != 0 {
		t.Fatal("stale recheck admitted scanner mutation or a false result")
	}
}

func cloneDeletionClaim(t *testing.T, claim map[string]any) map[string]any {
	t.Helper()
	body, err := json.Marshal(claim)
	if err != nil {
		t.Fatalf("marshal claim: %v", err)
	}
	var cloned map[string]any
	if json.Unmarshal(body, &cloned) != nil {
		t.Fatal("clone claim")
	}
	return cloned
}

func TestBiometricDeletionRecheckRejectsMetadataGenerationDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"command", func(claim map[string]any) { claim["commandId"] = testStaleID }},
		{"attempt", func(claim map[string]any) { claim["attempt"] = 3 }},
		{"generation", func(claim map[string]any) {
			claim["vaultAssetId"] = "55555555-5555-4555-8555-555555555555"
		}},
		{"personnel", func(claim map[string]any) { claim["personnelId"] = "15" }},
		{"kind", func(claim map[string]any) {
			claim["asset"].(map[string]any)["kind"] = "face_template"
			claim["asset"].(map[string]any)["bioType"] = 9
			claim["asset"].(map[string]any)["slotIndex"] = 0
		}},
		{"slot", func(claim map[string]any) {
			claim["asset"].(map[string]any)["slotIndex"] = 4
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newDeletionFixture(t)
			fixture.recheckBody = cloneDeletionClaim(t, fixture.claimBody)
			test.mutate(fixture.recheckBody)
			cloud := httptest.NewServer(fixture.handler())
			defer cloud.Close()
			agent, server := newDeliveryAgent(t, cloud.URL)

			err := processTestDeletion(agent, context.Background(), testCommandID)
			if err == nil {
				t.Fatal("drifted generation recheck was accepted")
			}
			if len(server.secretCmdQueue["AC1"]) != 0 ||
				len(server.resultOutbox.snapshot()) != 0 {
				t.Fatal("drifted generation recheck queued or falsely reported deletion")
			}
		})
	}
}

func TestBiometricDeletionScannerPollRevalidatesCapabilityAndZeros(t *testing.T) {
	fixture := newDeletionFixture(t)
	cloud := httptest.NewServer(fixture.handler())
	defer cloud.Close()
	agent, server := newDeliveryAgent(t, cloud.URL)
	if err := processTestDeletion(agent, context.Background(), testCommandID); err != nil {
		t.Fatalf("process deletion: %v", err)
	}
	commandBuffer := server.secretCmdQueue["AC1"][0].payload
	agent.devices.observeProtocol("AC1", ProtocolObservation{
		Path: "/iclock/registry",
		Capabilities: map[string]string{
			"biodatafun": "0",
		},
	})

	response := httptest.NewRecorder()
	server.handleGetRequest(
		response,
		httptest.NewRequest(http.MethodGet, "/iclock/getrequest?SN=AC1", nil),
	)
	if response.Body.String() != "OK" {
		t.Fatalf("incompatible delete reached scanner: %q", response.Body.String())
	}
	select {
	case <-fixture.resultReady:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for compatibility failure")
	}
	_, _, _, results := fixture.snapshot()
	if len(results) != 1 ||
		results[0]["operation"] != "delete" ||
		results[0]["status"] != "failed" ||
		results[0]["errorCode"] != "record_type_unsupported" ||
		results[0]["attempt"] != float64(2) ||
		results[0]["vaultAssetId"] != testVaultAssetID {
		t.Fatalf("compatibility result = %#v", results)
	}
	for index, value := range commandBuffer {
		if value != 0 {
			t.Fatalf("delete command byte %d was not zeroed", index)
		}
	}
}

func TestBiometricDeletionLostScannerResponseRetransmitsIdenticalMutableBytes(
	t *testing.T,
) {
	fixture := newDeletionFixture(t)
	cloud := httptest.NewServer(fixture.handler())
	defer cloud.Close()
	agent, server := newDeliveryAgent(t, cloud.URL)
	if err := processTestDeletion(agent, context.Background(), testCommandID); err != nil {
		t.Fatalf("process deletion: %v", err)
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
		t.Fatal("lost delete response did not retransmit identical mutable bytes")
	}
	_, _, _, results := fixture.snapshot()
	if len(results) != 0 {
		t.Fatalf("lost delete response falsely reported %#v", results)
	}
}

func TestBiometricDeletionLostResultResponseRetriesIdenticalGeneration(
	t *testing.T,
) {
	fixture := newDeletionFixture(t)
	fixture.resultFailures = 1
	cloud := httptest.NewServer(fixture.handler())
	defer cloud.Close()
	agent, server := newDeliveryAgent(t, cloud.URL)
	if err := processTestDeletion(agent, context.Background(), testCommandID); err != nil {
		t.Fatalf("process deletion: %v", err)
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
			strings.NewReader("ID="+localID+"&Return=0"),
		),
	)
	for index := 0; index < 2; index++ {
		select {
		case <-fixture.resultReady:
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for retried delete result")
		}
	}
	_, _, _, results := fixture.snapshot()
	if len(results) != 2 {
		t.Fatalf("delete result posts = %d; want 2", len(results))
	}
	first, _ := json.Marshal(results[0])
	second, _ := json.Marshal(results[1])
	if !bytes.Equal(first, second) {
		t.Fatalf("lost result retry changed body:\nfirst=%s\nsecond=%s", first, second)
	}
}

func TestBiometricDeletionScannerTimeoutZerosAndReportsGeneration(t *testing.T) {
	fixture := newDeletionFixture(t)
	cloud := httptest.NewServer(fixture.handler())
	defer cloud.Close()
	agent, server := newDeliveryAgent(t, cloud.URL)
	clock := newManualSecretClock()
	useManualSecretClock(server, clock)
	if err := processTestDeletion(agent, context.Background(), testCommandID); err != nil {
		t.Fatalf("process deletion: %v", err)
	}
	response := httptest.NewRecorder()
	server.handleGetRequest(
		response,
		httptest.NewRequest(http.MethodGet, "/iclock/getrequest?SN=AC1", nil),
	)
	commandBuffer := server.secretPending[pendingCommandKey{
		DeviceSN: "AC1",
		LocalID: mustTestInt(
			t,
			strings.SplitN(strings.TrimPrefix(response.Body.String(), "C:"), ":", 2)[0],
		),
	}].payload
	clock.Advance(secretCommandServeDeadline)

	select {
	case <-fixture.resultReady:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for delete timeout result")
	}
	_, _, _, results := fixture.snapshot()
	if len(results) != 1 ||
		results[0]["operation"] != "delete" ||
		results[0]["status"] != "failed" ||
		results[0]["errorCode"] != "network_unavailable" ||
		results[0]["attempt"] != float64(2) ||
		results[0]["vaultAssetId"] != testVaultAssetID {
		t.Fatalf("delete timeout result = %#v", results)
	}
	for index, value := range commandBuffer {
		if value != 0 {
			t.Fatalf("timed-out delete command byte %d was not zeroed", index)
		}
	}
}

func TestBiometricDeletionCancellationQueuesAndReportsNothing(t *testing.T) {
	fixture := newDeletionFixture(t)
	cloud := httptest.NewServer(fixture.handler())
	defer cloud.Close()
	agent, server := newDeliveryAgent(t, cloud.URL)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := processTestDeletion(agent, ctx, testCommandID)
	if deliveryErrorCode(err) != "deployment_cancelled" {
		t.Fatalf("cancelled deletion error = %v", err)
	}
	_, _, payloadFetches, results := fixture.snapshot()
	if payloadFetches != 0 ||
		len(results) != 0 ||
		len(server.secretCmdQueue["AC1"]) != 0 {
		t.Fatal("cancelled deletion fetched, queued, or reported")
	}
}

func TestBiometricDeletionShutdownZerosQueuedCommand(t *testing.T) {
	fixture := newDeletionFixture(t)
	cloud := httptest.NewServer(fixture.handler())
	defer cloud.Close()
	agent, server := newDeliveryAgent(t, cloud.URL)
	if err := processTestDeletion(agent, context.Background(), testCommandID); err != nil {
		t.Fatalf("process deletion: %v", err)
	}
	commandBuffer := server.secretCmdQueue["AC1"][0].payload
	server.shutdownBiometricDelivery()
	for index, value := range commandBuffer {
		if value != 0 {
			t.Fatalf("queued delete command byte %d was not zeroed on shutdown", index)
		}
	}
	_, _, _, results := fixture.snapshot()
	if len(results) != 0 {
		t.Fatalf("shutdown falsely reported delete result %#v", results)
	}
}

func TestBiometricDeletionRejectsHostileClaimExtras(t *testing.T) {
	for _, mutation := range []struct {
		name  string
		key   string
		value any
	}{
		{"delivery token", "deliveryToken", strings.Repeat("A", 43)},
		{"payload", "payload", "secret"},
		{"nested crypto object", "crypto", map[string]any{"nonce": "secret"}},
		{"unknown field", "employeeName", "Sensitive Name"},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			fixture := newDeletionFixture(t)
			fixture.claimBody[mutation.key] = mutation.value
			cloud := httptest.NewServer(fixture.handler())
			defer cloud.Close()
			agent, server := newDeliveryAgent(t, cloud.URL)

			err := processTestDeletion(agent, context.Background(), testCommandID)
			if deliveryErrorCode(err) != "invalid_deployment_claim" {
				t.Fatalf("error = %v; want invalid_deployment_claim", err)
			}
			if len(server.secretCmdQueue["AC1"]) != 0 {
				t.Fatal("hostile claim extra admitted a delete command")
			}
		})
	}
}

func TestBiometricDeletionRejectsInvalidMetadata(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"wrong operation", func(claim map[string]any) { claim["operation"] = "deploy" }},
		{"wrong command", func(claim map[string]any) { claim["commandId"] = testStaleID }},
		{"wrong device", func(claim map[string]any) { claim["deviceSn"] = "OTHER" }},
		{"invalid attempt", func(claim map[string]any) { claim["attempt"] = 0 }},
		{"invalid generation", func(claim map[string]any) { claim["vaultAssetId"] = "asset" }},
		{"invalid PIN", func(claim map[string]any) { claim["personnelId"] = "14\tDROP" }},
		{"invalid slot", func(claim map[string]any) {
			claim["asset"].(map[string]any)["slotIndex"] = 10
		}},
		{"invalid kind", func(claim map[string]any) {
			claim["asset"].(map[string]any)["kind"] = "iris_template"
		}},
		{"kind type mismatch", func(claim map[string]any) {
			claim["asset"].(map[string]any)["bioType"] = 9
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newDeletionFixture(t)
			test.mutate(fixture.claimBody)
			cloud := httptest.NewServer(fixture.handler())
			defer cloud.Close()
			agent, server := newDeliveryAgent(t, cloud.URL)

			err := processTestDeletion(agent, context.Background(), testCommandID)
			code := deliveryErrorCode(err)
			if code != "invalid_deployment_claim" && code != "stale_deployment_command" {
				t.Fatalf("error = %v; want a closed claim", err)
			}
			if len(server.secretCmdQueue["AC1"]) != 0 {
				t.Fatal("invalid metadata admitted a delete command")
			}
		})
	}
}

func TestBiometricDeletionInterceptorNeverForwardsTypedReference(t *testing.T) {
	fixture := newDeletionFixture(t)
	cloud := httptest.NewServer(fixture.handler())
	defer cloud.Close()
	_, server := newDeliveryAgent(t, cloud.URL)

	if !server.interceptBiometricDeploymentReference("AC1", ADMSCommand{
		Command: "DELETE_BIOMETRIC_ASSET " + testDeploymentID,
		CloudID: testCommandID,
	}) {
		t.Fatal("delete reference was not intercepted")
	}
	if !server.interceptBiometricDeploymentReference("AC1", ADMSCommand{
		Command: "DELETE_BIOMETRIC_ASSET " + testDeploymentID,
		CloudID: testCommandID,
	}) {
		t.Fatal("duplicate delete reference was not intercepted")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		claims, _, _, _ := fixture.snapshot()
		if claims == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for typed deletion claim")
		}
		time.Sleep(time.Millisecond)
	}
	for _, command := range server.cmdQueue["AC1"] {
		if strings.Contains(command.Command, "DELETE_BIOMETRIC_ASSET") {
			t.Fatal("typed deletion reference entered the generic scanner queue")
		}
	}
	claims, _, _, _ := fixture.snapshot()
	if claims != 1 {
		t.Fatalf("duplicate delete reference made %d claims; want 1", claims)
	}
}

func TestBiometricDeletionMalformedReferenceNeverUsesGenericResultEndpoint(
	t *testing.T,
) {
	var genericResults int
	var mu sync.Mutex
	cloud := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if request.URL.Path == "/api/agent-bridge/commands/result" {
			mu.Lock()
			genericResults++
			mu.Unlock()
		}
		writer.WriteHeader(http.StatusOK)
	}))
	defer cloud.Close()
	_, server := newDeliveryAgent(t, cloud.URL)

	for _, command := range []ADMSCommand{
		{Command: "DELETE_BIOMETRIC_ASSET not-a-uuid", CloudID: testCommandID},
		{Command: "DELETE_BIOMETRIC_ASSET " + testDeploymentID + " extra", CloudID: testCommandID},
		{Command: "DELETE_BIOMETRIC_ASSET " + testDeploymentID, CloudID: "not-a-command"},
	} {
		if !server.interceptBiometricDeploymentReference("AC1", command) {
			t.Fatalf("malformed typed reference was not intercepted: %q", command.Command)
		}
	}
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if genericResults != 0 {
		t.Fatalf("malformed delete used generic result endpoint %d time(s)", genericResults)
	}
}

func TestBiometricDeletionOutboxRecordRejectsSecretFieldsAndPreservesGeneration(t *testing.T) {
	outbox, err := openBiometricResultOutbox(t.TempDir())
	if err != nil {
		t.Fatalf("open outbox: %v", err)
	}
	result := biometricDeploymentResult{
		Operation:    "delete",
		Status:       "failed",
		DeviceSN:     "AC1",
		ErrorCode:    "network_unavailable",
		CommandID:    testCommandID,
		Attempt:      2,
		VaultAssetID: testVaultAssetID,
		ReturnCode:   -1,
	}
	if err := outbox.enqueue(testDeploymentID, result, time.Now()); err != nil {
		t.Fatalf("enqueue delete result: %v", err)
	}
	records := outbox.snapshot()
	if len(records) != 1 ||
		records[0].Operation != "delete" ||
		records[0].Attempt != 2 ||
		records[0].VaultAssetID != testVaultAssetID ||
		records[0].SHA256 != "" {
		t.Fatalf("record = %#v", records)
	}
	body := mustReadTestFile(t, outbox.path)
	for _, forbidden := range []string{
		"personnelId", "payload", "deliveryToken", "DATA DELETE", `"pin"`,
	} {
		if bytes.Contains(body, []byte(forbidden)) {
			t.Fatalf("persisted outbox contains forbidden field %q: %s", forbidden, body)
		}
	}
	if !bytes.Contains(body, []byte(`"operation":"delete"`)) ||
		!bytes.Contains(body, []byte(`"attempt":2`)) ||
		!bytes.Contains(body, []byte(`"vaultAssetId":"`+testVaultAssetID+`"`)) {
		t.Fatalf("persisted outbox omitted delete generation: %s", body)
	}
}

func TestBiometricDeletionOutboxResumesGenerationBoundResultAfterRestart(
	t *testing.T,
) {
	stateDir := t.TempDir()
	first, err := openBiometricResultOutbox(stateDir)
	if err != nil {
		t.Fatalf("open first outbox: %v", err)
	}
	result := biometricDeploymentResult{
		Operation:    "delete",
		Status:       "failed",
		DeviceSN:     "AC1",
		ErrorCode:    "network_unavailable",
		CommandID:    testCommandID,
		Attempt:      2,
		VaultAssetID: testVaultAssetID,
		ReturnCode:   -1,
	}
	if err := first.enqueue(
		testDeploymentID,
		result,
		time.Now().Add(-time.Second),
	); err != nil {
		t.Fatalf("enqueue before restart: %v", err)
	}

	reported := make(chan map[string]any, 1)
	cloud := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Errorf("decode restarted result: %v", err)
		}
		reported <- body
		writer.WriteHeader(http.StatusOK)
	}))
	defer cloud.Close()
	reopened, err := openBiometricResultOutbox(stateDir)
	if err != nil {
		t.Fatalf("reopen outbox: %v", err)
	}
	agent := &Agent{
		config:   Config{APIKey: "agent-key", PlamatixURL: cloud.URL},
		stateDir: stateDir,
	}
	server := &ADMSServer{agent: agent, resultOutbox: reopened}
	agent.adms = server
	server.startBiometricResultOutboxWorker()
	t.Cleanup(server.shutdownBiometricDelivery)

	select {
	case body := <-reported:
		if body["operation"] != "delete" ||
			body["attempt"] != float64(2) ||
			body["vaultAssetId"] != testVaultAssetID ||
			body["sha256"] != nil {
			t.Fatalf("restarted delete result = %#v", body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("restarted outbox did not report delete generation")
	}
}

func TestBiometricDeletionOutboxRejectsCorruptGenerationMetadata(t *testing.T) {
	tests := []string{
		`{"version":1,"records":[{"deploymentId":"` + testDeploymentID +
			`","operation":"delete","commandId":"` + testCommandID +
			`","attempt":0,"vaultAssetId":"` + testVaultAssetID +
			`","deviceSn":"AC1","status":"failed","errorCode":"network_unavailable","returnCode":-1,"attempts":0,"nextAttemptAt":"2026-07-30T00:00:00Z"}]}`,
		`{"version":1,"records":[{"deploymentId":"` + testDeploymentID +
			`","operation":"delete","commandId":"` + testCommandID +
			`","attempt":2,"vaultAssetId":"not-a-generation","deviceSn":"AC1","status":"failed","errorCode":"network_unavailable","returnCode":-1,"attempts":0,"nextAttemptAt":"2026-07-30T00:00:00Z"}]}`,
		`{"version":1,"records":[{"deploymentId":"` + testDeploymentID +
			`","operation":"delete","commandId":"` + testCommandID +
			`","attempt":2,"vaultAssetId":"` + testVaultAssetID +
			`","deviceSn":"AC1","status":"applied","sha256":"` +
			strings.Repeat("a", 64) +
			`","returnCode":0,"attempts":0,"nextAttemptAt":"2026-07-30T00:00:00Z"}]}`,
		`{"version":1,"records":[{"deploymentId":"` + testDeploymentID +
			`","operation":"delete","commandId":"` + testCommandID +
			`","attempt":2,"vaultAssetId":"` + testVaultAssetID +
			`","deviceSn":"AC1","status":"failed","errorCode":"device_command_failed","returnCode":2147483648,"attempts":0,"nextAttemptAt":"2026-07-30T00:00:00Z"}]}`,
	}
	for index, document := range tests {
		t.Run(strconv.Itoa(index), func(t *testing.T) {
			stateDir := t.TempDir()
			path := stateDir + "/" + biometricResultOutboxFilename
			if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
				t.Fatalf("write corrupt outbox: %v", err)
			}
			if _, err := openBiometricResultOutbox(stateDir); !errors.Is(
				err,
				errBiometricResultOutboxCorrupt,
			) {
				t.Fatalf("open corrupt outbox error = %v", err)
			}
		})
	}
}

func mustReadTestFile(t *testing.T, path string) []byte {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return body
}

func TestBiometricDeletionResultJSONHasNoZeroValuePresentFields(t *testing.T) {
	body, err := json.Marshal(biometricDeploymentResult{
		Operation:    "delete",
		Status:       "applied",
		DeviceSN:     "AC1",
		CommandID:    testCommandID,
		Attempt:      1,
		VaultAssetID: testVaultAssetID,
		ReturnCode:   0,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(body, []byte("sha256")) ||
		bytes.Contains(body, []byte("errorCode")) ||
		!bytes.Contains(body, []byte(`"attempt":1`)) {
		t.Fatalf("delete result JSON = %s", body)
	}
}

func TestBiometricDeletionRendererDoesNotReturnStringBackedState(t *testing.T) {
	rendered, code := renderBiometricDeletionCommand(
		DeviceProtocolState{
			Profile: ProtocolACPush3, Confidence: 90,
			Capabilities: map[string]string{
				"fingerfunon": "1", "biodatafun": "1",
				"fingeralgorithmversion": "12.0",
			},
		},
		biometricDeletionMetadata{
			PersonnelID: "14", Kind: "fingerprint_template", BioType: 1, SlotIndex: 3,
		},
	)
	if code != "" {
		t.Fatalf("render code = %q", code)
	}
	copyOfRendered := append([]byte(nil), rendered...)
	zeroBytes(rendered)
	if bytes.Equal(rendered, copyOfRendered) {
		t.Fatal("mutable delete command did not zero")
	}
	for index, value := range rendered {
		if value != 0 {
			t.Fatalf("rendered[%d] = %d after zero", index, value)
		}
	}
}

func TestBiometricDeletionResultReturnCodeIsBounded(t *testing.T) {
	for _, returnCode := range []int{
		-2_147_483_648,
		2_147_483_647,
	} {
		result := biometricDeploymentResult{
			Operation:    "delete",
			Status:       "failed",
			DeviceSN:     "AC1",
			ErrorCode:    "device_command_failed",
			CommandID:    testCommandID,
			Attempt:      1,
			VaultAssetID: testVaultAssetID,
			ReturnCode:   returnCode,
		}
		if err := (&biometricResultOutbox{
			path: t.TempDir() + "/outbox.json",
		}).enqueue(testDeploymentID, result, time.Now()); err != nil {
			t.Fatalf("returnCode %s rejected: %v", strconv.Itoa(returnCode), err)
		}
	}
}
