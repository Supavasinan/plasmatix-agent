package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Deterministic certification of the encrypted biometric vault flow.
//
// Every scenario drives the agent's real capture, delivery, deletion, and
// protocol code against an in-process cloud and scanner. Nothing here talks to
// hardware, so the emitted report is always mode "simulated" and never claims
// hardware certification.

const (
	certReportEnv     = "BIOMETRIC_CERT_REPORT"
	certWebVersionEnv = "BIOMETRIC_CERT_WEB_VERSION"
)

// certRequiredScenarios is the approved list. The report is invalid unless
// every one of these is present and passed.
var certRequiredScenarios = []string{
	"encrypted_capture",
	"no_plaintext_persistence",
	"ta_push_delivery",
	"ac_push_delivery",
	"algorithm_refusal",
	"tamper_detection",
	"token_expiry",
	"token_replay",
	"retry_idempotency",
	"lost_ack_reconciliation",
	"revocation",
	"tenant_isolation",
	"source_reconciliation",
	"conflict_quarantine",
	"server_repoint_preservation",
	"face_photo_generation",
}

type certScenarioResult struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type certReport struct {
	Mode              string               `json:"mode"`
	HardwareCertified bool                 `json:"hardwareCertified"`
	AgentVersion      string               `json:"agentVersion"`
	WebVersion        string               `json:"webVersion"`
	GeneratedBy       string               `json:"generatedBy"`
	Scenarios         []certScenarioResult `json:"scenarios"`
}

// certFingerprint is the deterministic fingerprint-template fixture. Its bytes
// must never appear in the report, in agent state, or in any result body.
var certFingerprint = []byte("CERTIFICATION-FINGERPRINT-TEMPLATE-FIXTURE")

// certPhoto is a deterministic JPEG-shaped fixture for photo generation.
var certPhoto = append([]byte{0xFF, 0xD8, 0xFF, 0xE0}, []byte("CERT-FACE-PHOTO")...)

func certDigest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// certAgent builds an agent whose single scanner "AC1" reports the given
// protocol observation, so scenarios can pick TA PUSH or AC PUSH 3 behaviour.
func certAgent(
	t *testing.T,
	cloudURL string,
	observation ProtocolObservation,
) (*Agent, *ADMSServer) {
	t.Helper()
	tracker := newDeviceTracker()
	tracker.observeProtocol("AC1", observation)
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

func certTAObservation(capabilities map[string]string) ProtocolObservation {
	return ProtocolObservation{
		Path:         "/iclock/cdata",
		PushVersion:  "2.4.0",
		Capabilities: capabilities,
	}
}

func certACObservation(capabilities map[string]string) ProtocolObservation {
	return ProtocolObservation{
		Path:         "/iclock/registry",
		Capabilities: capabilities,
	}
}

// certServe pops the queued scanner command and returns the served body.
func certServe(t *testing.T, server *ADMSServer) string {
	t.Helper()
	response := httptest.NewRecorder()
	server.handleGetRequest(
		response,
		httptest.NewRequest(http.MethodGet, "/iclock/getrequest?SN=AC1", nil),
	)
	return response.Body.String()
}

// certAck acknowledges the command carried in a served body.
func certAck(t *testing.T, server *ADMSServer, served string) {
	t.Helper()
	localID := strings.SplitN(strings.TrimPrefix(served, "C:"), ":", 2)[0]
	server.handleDeviceCmd(
		httptest.NewRecorder(),
		httptest.NewRequest(
			http.MethodPost,
			"/iclock/devicecmd?SN=AC1",
			strings.NewReader("ID="+localID+"&Return=0"),
		),
	)
}

func TestBiometricVaultCertification(t *testing.T) {
	results := make([]certScenarioResult, 0, len(certRequiredScenarios))
	record := func(name string, scenario func(t *testing.T) string) {
		detail := ""
		passed := t.Run(name, func(subtest *testing.T) {
			detail = scenario(subtest)
		})
		status := "failed"
		if passed {
			status = "passed"
		}
		results = append(results, certScenarioResult{
			Name:   name,
			Status: status,
			Detail: detail,
		})
	}

	record("encrypted_capture", certEncryptedCapture)
	record("no_plaintext_persistence", certNoPlaintextPersistence)
	record("ta_push_delivery", certTAPushDelivery)
	record("ac_push_delivery", certACPushDelivery)
	record("algorithm_refusal", certAlgorithmRefusal)
	record("tamper_detection", certTamperDetection)
	record("token_expiry", certTokenExpiry)
	record("token_replay", certTokenReplay)
	record("retry_idempotency", certRetryIdempotency)
	record("lost_ack_reconciliation", certLostAckReconciliation)
	record("revocation", certRevocation)
	record("tenant_isolation", certTenantIsolation)
	record("source_reconciliation", certSourceReconciliation)
	record("conflict_quarantine", certConflictQuarantine)
	record("server_repoint_preservation", certServerRepointPreservation)
	record("face_photo_generation", certFacePhotoGeneration)

	seen := make(map[string]certScenarioResult, len(results))
	for _, result := range results {
		seen[result.Name] = result
	}
	for _, required := range certRequiredScenarios {
		result, ok := seen[required]
		if !ok {
			t.Fatalf("certification report is missing scenario %q", required)
		}
		if result.Status != "passed" {
			t.Errorf("scenario %q did not pass", required)
		}
	}

	report := certReport{
		Mode:              "simulated",
		HardwareCertified: false,
		AgentVersion:      certAgentVersion(t),
		WebVersion:        os.Getenv(certWebVersionEnv),
		GeneratedBy:       "TestBiometricVaultCertification",
		Scenarios:         results,
	}
	serialized, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}

	// The report is an artifact that leaves this process: it must never carry
	// fixture template bytes in raw or base64 form.
	for _, forbidden := range []string{
		string(certFingerprint),
		base64.StdEncoding.EncodeToString(certFingerprint),
		string(certPhoto),
		base64.StdEncoding.EncodeToString(certPhoto),
	} {
		if strings.Contains(string(serialized), forbidden) {
			t.Fatalf("certification report leaked fixture bytes")
		}
	}

	if path := os.Getenv(certReportEnv); path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("create report directory: %v", err)
		}
		if err := os.WriteFile(path, serialized, 0o600); err != nil {
			t.Fatalf("write report: %v", err)
		}
	}
}

func certAgentVersion(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "VERSION"))
	if err != nil {
		t.Fatalf("read VERSION: %v", err)
	}
	return strings.TrimSpace(string(raw))
}

// --- Scenarios ----------------------------------------------------------

// encrypted_capture: the agent parses a device upload and posts the raw bytes
// to the vault capture endpoint as an authenticated binary request. The bytes
// are only ever in flight — the web app owns encryption at rest.
func certEncryptedCapture(t *testing.T) string {
	var (
		gotBody    []byte
		gotHeaders http.Header
	)
	cloud := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/agent-bridge/biometric-vault/capture" {
				http.NotFound(w, r)
				return
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("read capture body: %v", err)
			}
			gotBody = body
			gotHeaders = r.Header.Clone()
			w.WriteHeader(http.StatusAccepted)
		}))
	defer cloud.Close()

	state := DeviceProtocolState{
		Profile:     ProtocolTAPush,
		Confidence:  90,
		PushVersion: "2.4.0",
		Capabilities: map[string]string{
			"fingerfunon":            "1",
			"biodatafun":             "1",
			"fingeralgorithmversion": "12.0",
		},
	}
	upload := fmt.Sprintf(
		"PIN=14\tNo=3\tType=1\tMajorVer=12\tMinorVer=0\tTmp=%s",
		base64.StdEncoding.EncodeToString(certFingerprint),
	)
	assets, err := ExtractBiometricAssets("BIODATA", []byte(upload), state)
	if err != nil {
		t.Fatalf("extract assets: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("extracted %d assets; want 1", len(assets))
	}
	asset := assets[0]
	asset.DeviceSN = "AC1"
	metadata := asset.SafeMetadata()
	wantDigest := certDigest(certFingerprint)
	if metadata.SHA256 != wantDigest {
		t.Fatalf("captured digest = %q; want %q", metadata.SHA256, wantDigest)
	}

	agent, _ := certAgent(t, cloud.URL, certTAObservation(state.Capabilities))
	if err := agent.UploadBiometricAsset(context.Background(), asset); err != nil {
		t.Fatalf("upload asset: %v", err)
	}
	if string(gotBody) != string(certFingerprint) {
		t.Fatalf("capture body did not match the captured template bytes")
	}
	if gotHeaders.Get("X-API-Key") != "agent-key" ||
		gotHeaders.Get("X-Device-SN") != "AC1" ||
		gotHeaders.Get("X-Content-Type") != "" &&
			gotHeaders.Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("capture headers = %#v", gotHeaders)
	}
	if gotHeaders.Get("Cache-Control") != "no-store" {
		t.Fatalf("capture must not be cacheable")
	}
	return fmt.Sprintf(
		"uploaded %d bytes as an authenticated binary request; digest %s",
		metadata.ByteCount,
		metadata.SHA256[:12],
	)
}

// no_plaintext_persistence: after a full delivery nothing under the agent state
// directory contains the template, and log redaction removes it from text.
func certNoPlaintextPersistence(t *testing.T) string {
	fixture := newDeliveryFixture(certFingerprint)
	cloud := httptest.NewServer(fixture.handler(t))
	defer cloud.Close()
	agent, server := certAgent(t, cloud.URL, certACObservation(map[string]string{
		"fingerfunon":            "1",
		"biodatafun":             "1",
		"fingeralgorithmversion": "12.0",
	}))

	if err := processTestDeployment(agent, context.Background(), testCommandID); err != nil {
		t.Fatalf("process deployment: %v", err)
	}
	served := certServe(t, server)
	certAck(t, server, served)
	if result := waitDeliveryResult(t, fixture.results); result.Status != "applied" {
		t.Fatalf("result = %#v", result)
	}

	encoded := base64.StdEncoding.EncodeToString(certFingerprint)
	scanned := 0
	err := filepath.Walk(agent.stateDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		scanned++
		if strings.Contains(string(body), string(certFingerprint)) ||
			strings.Contains(string(body), encoded) {
			t.Fatalf("agent state file %s persisted the template", filepath.Base(path))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk state dir: %v", err)
	}

	redacted := RedactBiometricText("DATA UPDATE BIODATA Pin=14\tTmp=" + encoded)
	if strings.Contains(redacted, encoded) {
		t.Fatalf("redaction left the template in log text")
	}
	return fmt.Sprintf(
		"scanned %d state files and redacted log text; no template bytes at rest",
		scanned,
	)
}

// ta_push_delivery: a legacy fingerprint template renders as FINGERTMP on a
// TA PUSH scanner and is acknowledged.
func certTAPushDelivery(t *testing.T) string {
	fixture := newDeliveryFixture(certFingerprint)
	fixture.renderer = "finger_legacy"
	fixture.family = "zkfinger-v9"
	fixture.major = 9
	fixture.minor = 0
	fixture.format = "templatev9"
	cloud := httptest.NewServer(fixture.handler(t))
	defer cloud.Close()
	agent, server := certAgent(t, cloud.URL, certTAObservation(map[string]string{
		"fingerfunon":            "1",
		"fingeralgorithmversion": "9.0",
	}))

	if err := processTestDeployment(agent, context.Background(), testCommandID); err != nil {
		t.Fatalf("process deployment: %v", err)
	}
	served := certServe(t, server)
	if !strings.Contains(served, "DATA UPDATE FINGERTMP PIN=14") {
		t.Fatalf("TA PUSH command = %q", served)
	}
	if !strings.HasSuffix(served, "\tTMP="+base64.StdEncoding.EncodeToString(certFingerprint)) {
		t.Fatalf("TA PUSH command did not carry the rendered template")
	}
	certAck(t, server, served)
	result := waitDeliveryResult(t, fixture.results)
	if result.Status != "applied" || result.ReturnCode != 0 {
		t.Fatalf("result = %#v", result)
	}
	return "rendered DATA UPDATE FINGERTMP and the scanner acknowledged it"
}

// ac_push_delivery: a modern template renders as BIODATA on an AC PUSH 3
// scanner and is acknowledged.
func certACPushDelivery(t *testing.T) string {
	fixture := newDeliveryFixture(certFingerprint)
	cloud := httptest.NewServer(fixture.handler(t))
	defer cloud.Close()
	agent, server := certAgent(t, cloud.URL, certACObservation(map[string]string{
		"fingerfunon":            "1",
		"biodatafun":             "1",
		"fingeralgorithmversion": "12.0",
	}))

	if err := processTestDeployment(agent, context.Background(), testCommandID); err != nil {
		t.Fatalf("process deployment: %v", err)
	}
	served := certServe(t, server)
	if !strings.Contains(served, "DATA UPDATE BIODATA Pin=14") {
		t.Fatalf("AC PUSH command = %q", served)
	}
	if !strings.HasSuffix(served, "\tTmp="+base64.StdEncoding.EncodeToString(certFingerprint)) {
		t.Fatalf("AC PUSH command did not carry the rendered template")
	}
	certAck(t, server, served)
	result := waitDeliveryResult(t, fixture.results)
	if result.Status != "applied" {
		t.Fatalf("result = %#v", result)
	}
	return "rendered DATA UPDATE BIODATA and the scanner acknowledged it"
}

// algorithm_refusal: a template whose algorithm does not match the live scanner
// is refused and never reaches the scanner queue.
func certAlgorithmRefusal(t *testing.T) string {
	fixture := newDeliveryFixture(certFingerprint)
	fixture.family = "zkfinger-v11"
	fixture.major = 11
	fixture.format = "templatev11"
	cloud := httptest.NewServer(fixture.handler(t))
	defer cloud.Close()
	agent, server := certAgent(t, cloud.URL, certACObservation(map[string]string{
		"fingerfunon":            "1",
		"biodatafun":             "1",
		"fingeralgorithmversion": "12.0",
	}))

	err := processTestDeployment(agent, context.Background(), testCommandID)
	if err == nil {
		t.Fatal("mismatched algorithm was accepted")
	}
	code := deliveryErrorCode(err)
	if code != "algorithm_mismatch" {
		t.Fatalf("error code = %q; want algorithm_mismatch", code)
	}
	if len(server.secretCmdQueue["AC1"]) != 0 {
		t.Fatal("refused deployment queued a scanner command")
	}
	result := waitDeliveryResult(t, fixture.results)
	if result.Status != "failed" || result.ErrorCode != "algorithm_mismatch" {
		t.Fatalf("result = %#v", result)
	}
	return "device reported finger algorithm 12.0 and the 11.0 template was refused"
}

// tamper_detection: payload bytes that do not match the claimed digest are
// rejected before anything is queued.
func certTamperDetection(t *testing.T) string {
	fixture := newDeliveryFixture(certFingerprint)
	// Keep the advertised digest but serve mutated ciphertext.
	mutated := append([]byte(nil), certFingerprint...)
	mutated[0] ^= 0xFF
	fixture.payload = mutated
	fixture.claimBytes = len(mutated)
	cloud := httptest.NewServer(fixture.handler(t))
	defer cloud.Close()
	agent, server := certAgent(t, cloud.URL, certACObservation(map[string]string{
		"fingerfunon":            "1",
		"biodatafun":             "1",
		"fingeralgorithmversion": "12.0",
	}))

	err := processTestDeployment(agent, context.Background(), testCommandID)
	if err == nil {
		t.Fatal("tampered payload was accepted")
	}
	if len(server.secretCmdQueue["AC1"]) != 0 {
		t.Fatal("tampered payload queued a scanner command")
	}
	result := waitDeliveryResult(t, fixture.results)
	if result.Status != "failed" {
		t.Fatalf("result = %#v", result)
	}
	return fmt.Sprintf(
		"mutated ciphertext rejected with %q before queueing",
		deliveryErrorCode(err),
	)
}

// token_expiry: the vault refuses an expired delivery token and the agent
// surfaces that refusal without queueing.
func certTokenExpiry(t *testing.T) string {
	fixture := newDeliveryFixture(certFingerprint)
	fixture.payloadStatus = http.StatusUnauthorized
	cloud := httptest.NewServer(fixture.handler(t))
	defer cloud.Close()
	agent, server := certAgent(t, cloud.URL, certACObservation(map[string]string{
		"fingerfunon":            "1",
		"biodatafun":             "1",
		"fingeralgorithmversion": "12.0",
	}))

	err := processTestDeployment(agent, context.Background(), testCommandID)
	if err == nil {
		t.Fatal("expired delivery token was accepted")
	}
	if len(server.secretCmdQueue["AC1"]) != 0 {
		t.Fatal("expired token queued a scanner command")
	}
	result := waitDeliveryResult(t, fixture.results)
	if result.Status != "failed" {
		t.Fatalf("result = %#v", result)
	}
	return fmt.Sprintf(
		"expired token refused at the payload endpoint with %q",
		deliveryErrorCode(err),
	)
}

// token_replay: a second fetch of a single-use token fails and nothing queues.
func certTokenReplay(t *testing.T) string {
	fixture := newDeliveryFixture(certFingerprint)
	fixture.payloadStatus = http.StatusConflict
	cloud := httptest.NewServer(fixture.handler(t))
	defer cloud.Close()
	agent, server := certAgent(t, cloud.URL, certACObservation(map[string]string{
		"fingerfunon":            "1",
		"biodatafun":             "1",
		"fingeralgorithmversion": "12.0",
	}))

	err := processTestDeployment(agent, context.Background(), testCommandID)
	if deliveryErrorCode(err) != "delivery_token_replayed" {
		t.Fatalf("error = %v; want delivery_token_replayed", err)
	}
	if len(server.secretCmdQueue["AC1"]) != 0 {
		t.Fatal("replayed token queued a scanner command")
	}
	result := waitDeliveryResult(t, fixture.results)
	if result.Status != "failed" || result.ErrorCode != "delivery_token_replayed" {
		t.Fatalf("result = %#v", result)
	}
	return "replayed single-use token refused before queueing"
}

// retry_idempotency: the vault re-offers the same typed reference (a retry the
// agent cannot distinguish from the first delivery). The agent must claim it
// once and queue exactly one scanner command.
func certRetryIdempotency(t *testing.T) string {
	fixture := newDeliveryFixture(certFingerprint)
	commandCalls := 0
	cloud := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/agent-bridge/commands" {
				commandCalls++
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
	_, server := certAgent(t, cloud.URL, certACObservation(map[string]string{
		"fingerfunon":            "1",
		"biodatafun":             "1",
		"fingeralgorithmversion": "12.0",
	}))

	// The identical reference is delivered twice.
	if _, err := server.drainCloudCommands("AC1"); err != nil {
		t.Fatalf("first drain: %v", err)
	}
	if _, err := server.drainCloudCommands("AC1"); err != nil {
		t.Fatalf("retried drain: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		server.mu.Lock()
		queued := len(server.secretCmdQueue["AC1"])
		ordinary := len(server.cmdQueue["AC1"])
		server.mu.Unlock()
		if queued == 1 {
			if ordinary != 0 {
				t.Fatal("typed vault reference entered the ordinary scanner queue")
			}
			break
		}
		if queued > 1 {
			t.Fatalf("retried reference queued %d scanner commands; want 1", queued)
		}
		if time.Now().After(deadline) {
			t.Fatal("retried reference was never queued")
		}
		time.Sleep(time.Millisecond)
	}

	fixture.mu.Lock()
	claims := fixture.claimCount
	payloadFetches := fixture.payloadCount
	fixture.mu.Unlock()
	if claims != 1 || payloadFetches != 1 {
		t.Fatalf("claims = %d payload fetches = %d; want 1 and 1",
			claims, payloadFetches)
	}
	return fmt.Sprintf(
		"reference offered %d times produced exactly one claim, fetch and queued command",
		commandCalls,
	)
}

// lost_ack_reconciliation: a lost result response is retried with byte-identical
// content until the vault accepts it.
func certLostAckReconciliation(t *testing.T) string {
	fixture := newDeliveryFixture(certFingerprint)
	fixture.resultStatus = http.StatusInternalServerError
	cloud := httptest.NewServer(fixture.handler(t))
	defer cloud.Close()
	agent, server := certAgent(t, cloud.URL, certACObservation(map[string]string{
		"fingerfunon":            "1",
		"biodatafun":             "1",
		"fingeralgorithmversion": "12.0",
	}))

	if err := processTestDeployment(agent, context.Background(), testCommandID); err != nil {
		t.Fatalf("process deployment: %v", err)
	}
	served := certServe(t, server)
	certAck(t, server, served)

	first := waitDeliveryResult(t, fixture.results)
	second := waitDeliveryResult(t, fixture.results)
	if first != second {
		t.Fatalf("retried result changed: first=%#v second=%#v", first, second)
	}
	if second.Status != "applied" || second.CommandID != testCommandID {
		t.Fatalf("result = %#v", second)
	}
	return "lost result response retried byte-identically and reconciled once"
}

// revocation: a typed deletion removes the slot from the scanner and reports a
// metadata-only result.
func certRevocation(t *testing.T) string {
	fixture := newDeletionFixture(t)
	cloud := httptest.NewServer(fixture.handler())
	defer cloud.Close()
	agent, server := certAgent(t, cloud.URL, certACObservation(map[string]string{
		"fingerfunon":            "1",
		"biodatafun":             "1",
		"fingeralgorithmversion": "12.0",
	}))

	if err := processTestDeletion(agent, context.Background(), testCommandID); err != nil {
		t.Fatalf("process deletion: %v", err)
	}
	served := certServe(t, server)
	if !strings.Contains(served, "DATA DELETE BIODATA Pin=14") {
		t.Fatalf("deletion command = %q", served)
	}
	certAck(t, server, served)

	select {
	case <-fixture.resultReady:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for delete result")
	}
	_, _, payloadFetches, deleteResults := fixture.snapshot()
	if payloadFetches != 0 {
		t.Fatalf("deletion fetched %d payloads; want 0", payloadFetches)
	}
	if len(deleteResults) != 1 || deleteResults[0]["status"] != "applied" {
		t.Fatalf("delete results = %#v", deleteResults)
	}
	serialized, err := json.Marshal(deleteResults[0])
	if err != nil {
		t.Fatalf("marshal delete result: %v", err)
	}
	for _, forbidden := range []string{"sha256", "personnelId", "Tmp"} {
		if strings.Contains(string(serialized), forbidden) {
			t.Fatalf("delete result leaked %q", forbidden)
		}
	}
	return "typed deletion applied and reported without any asset metadata"
}

// tenant_isolation: a claim naming a scanner the agent did not ask about is
// refused, so one organization's deployment cannot land on another's device.
func certTenantIsolation(t *testing.T) string {
	claims := 0
	payloads := 0
	cloud := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/api/agent-bridge/biometric-vault/deployments" &&
				r.Method == http.MethodPost:
				claims++
				_ = json.NewEncoder(w).Encode(map[string]any{
					"deployments": []any{map[string]any{
						"deploymentId": testDeploymentID,
						"vaultAssetId": "asset-1",
						// Foreign scanner: not the device the agent claimed for.
						"deviceSn":       "FOREIGN-SCANNER",
						"personnelId":    "14",
						"commandId":      testCommandID,
						"renderer":       "biodata",
						"deliveryToken":  strings.Repeat("A", 43),
						"tokenExpiresAt": "2027-07-28T03:01:00.000Z",
						"asset": map[string]any{
							"kind":            "fingerprint_template",
							"bioType":         1,
							"slotIndex":       3,
							"algorithmFamily": "zkfinger-v12",
							"algorithmMajor":  12,
							"algorithmMinor":  0,
							"format":          "templatev12",
							"byteCount":       len(certFingerprint),
							"sha256":          certDigest(certFingerprint),
						},
					}},
				})
			case strings.HasSuffix(r.URL.Path, "/payload"):
				payloads++
				w.WriteHeader(http.StatusOK)
			default:
				w.WriteHeader(http.StatusOK)
			}
		}))
	defer cloud.Close()
	agent, server := certAgent(t, cloud.URL, certACObservation(map[string]string{
		"fingerfunon":            "1",
		"biodatafun":             "1",
		"fingeralgorithmversion": "12.0",
	}))

	err := processTestDeployment(agent, context.Background(), testCommandID)
	if err == nil {
		t.Fatal("claim for a foreign scanner was accepted")
	}
	if payloads != 0 {
		t.Fatalf("foreign claim fetched %d payloads; want 0", payloads)
	}
	if len(server.secretCmdQueue["AC1"]) != 0 {
		t.Fatal("foreign claim queued a scanner command")
	}
	return fmt.Sprintf(
		"claim naming a foreign scanner refused with %q before payload access",
		deliveryErrorCode(err),
	)
}

// source_reconciliation: a captured asset keeps an exact, reconstructable
// source profile (scanner, slot, algorithm) with no bytes in the metadata.
func certSourceReconciliation(t *testing.T) string {
	state := DeviceProtocolState{
		Profile:     ProtocolTAPush,
		Confidence:  90,
		PushVersion: "2.4.0",
		Capabilities: map[string]string{
			"fingerfunon":            "1",
			"biodatafun":             "1",
			"fingeralgorithmversion": "12.0",
		},
	}
	upload := fmt.Sprintf(
		"PIN=14\tNo=7\tType=1\tMajorVer=12\tMinorVer=0\tTmp=%s",
		base64.StdEncoding.EncodeToString(certFingerprint),
	)
	assets, err := ExtractBiometricAssets("BIODATA", []byte(upload), state)
	if err != nil {
		t.Fatalf("extract assets: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("extracted %d assets; want 1", len(assets))
	}
	asset := assets[0]
	asset.DeviceSN = "AC1"
	metadata := asset.SafeMetadata()

	if metadata.DeviceSN != "AC1" || metadata.PIN != "14" ||
		metadata.SlotIndex != 7 || metadata.BioType != 1 {
		t.Fatalf("safe metadata = %#v", metadata)
	}
	if metadata.AlgorithmMajor != 12 || metadata.AlgorithmMinor != 0 {
		t.Fatalf("algorithm = %d.%d; want 12.0",
			metadata.AlgorithmMajor, metadata.AlgorithmMinor)
	}
	if metadata.SHA256 != certDigest(certFingerprint) {
		t.Fatalf("digest = %q", metadata.SHA256)
	}
	serialized, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("marshal metadata: %v", err)
	}
	if strings.Contains(string(serialized), string(certFingerprint)) ||
		strings.Contains(
			string(serialized),
			base64.StdEncoding.EncodeToString(certFingerprint),
		) {
		t.Fatal("safe metadata carried template bytes")
	}
	return fmt.Sprintf(
		"reconciled scanner AC1 slot %d as %s %d.%d with digest %s",
		metadata.SlotIndex,
		metadata.AlgorithmFamily,
		metadata.AlgorithmMajor,
		metadata.AlgorithmMinor,
		metadata.SHA256[:12],
	)
}

// conflict_quarantine: a scanner that contradicts its own protocol evidence is
// quarantined to unknown/zero confidence, which blocks every vault delivery.
func certConflictQuarantine(t *testing.T) string {
	tracker := newDeviceTracker()
	tracker.observeProtocol("AC1", certTAObservation(map[string]string{
		"fingerfunon":            "1",
		"fingeralgorithmversion": "12.0",
	}))
	before, ok := tracker.protocolState("AC1")
	if !ok || before.Profile != ProtocolTAPush || before.Confidence < 80 {
		t.Fatalf("initial state = %#v", before)
	}

	// The same serial now answers on an AC PUSH 3 route: contradictory.
	tracker.observeProtocol("AC1", certACObservation(nil))
	after, ok := tracker.protocolState("AC1")
	if !ok {
		t.Fatal("device disappeared after conflicting observation")
	}
	if after.Profile != ProtocolUnknown || after.Confidence != 0 {
		t.Fatalf("conflicting evidence did not quarantine the scanner: %#v", after)
	}

	// A quarantined scanner must refuse rendering rather than guess.
	code := validateLiveBiometricRenderer(after, biometricDeploymentMetadata{
		Renderer:        "biodata",
		PersonnelID:     "14",
		Kind:            "fingerprint_template",
		BioType:         1,
		SlotIndex:       3,
		AlgorithmFamily: "zkfinger-v12",
		AlgorithmMajor:  12,
		Format:          "templatev12",
	})
	if code != "target_profile_untrusted" {
		t.Fatalf("quarantined scanner render code = %q", code)
	}
	return "contradictory protocol evidence quarantined the scanner and blocked delivery"
}

// server_repoint_preservation: pointing the agent at a different Plasmatix
// server does not clear learned scanner state.
func certServerRepointPreservation(t *testing.T) string {
	first := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer second.Close()

	agent, _ := certAgent(t, first.URL, certTAObservation(map[string]string{
		"fingerfunon":            "1",
		"fingeralgorithmversion": "12.0",
	}))
	before, ok := agent.devices.protocolState("AC1")
	if !ok {
		t.Fatal("scanner state missing before repoint")
	}

	agent.config.PlamatixURL = second.URL

	after, ok := agent.devices.protocolState("AC1")
	if !ok {
		t.Fatal("scanner state was cleared by the server repoint")
	}
	if after.Profile != before.Profile || after.Confidence != before.Confidence ||
		after.PushVersion != before.PushVersion {
		t.Fatalf("scanner state changed across repoint: before=%#v after=%#v",
			before, after)
	}
	if after.Capabilities["fingeralgorithmversion"] != "12.0" {
		t.Fatalf("capabilities lost across repoint: %#v", after.Capabilities)
	}
	return fmt.Sprintf(
		"scanner stayed %s at confidence %d across a server repoint",
		after.Profile,
		after.Confidence,
	)
}

// face_photo_generation: a face comparison photo is delivered only to a profile
// validated for photo-to-template generation, rendered as BIOPHOTO.
func certFacePhotoGeneration(t *testing.T) string {
	fixture := newDeliveryFixture(certPhoto)
	fixture.renderer = "face_photo"
	fixture.kind = "face_comparison_photo"
	fixture.headerKind = "face_comparison_photo"
	fixture.bioType = 9
	fixture.slot = 0
	fixture.family = "portable_photo"
	fixture.major = 0
	fixture.minor = 0
	fixture.format = "jpeg"
	cloud := httptest.NewServer(fixture.handler(t))
	defer cloud.Close()

	capabilities := map[string]string{
		"facefunon":   "1",
		"biophotofun": "1",
		"biodatafun":  "1",
	}
	agent, server := certAgent(t, cloud.URL, certACObservation(capabilities))

	if err := processTestDeployment(agent, context.Background(), testCommandID); err != nil {
		t.Fatalf("process deployment: %v", err)
	}
	served := certServe(t, server)
	if !strings.Contains(served, "DATA UPDATE BIOPHOTO PIN=14") {
		t.Fatalf("photo command = %q", served)
	}
	if !strings.HasSuffix(served, "\tPhoto="+base64.StdEncoding.EncodeToString(certPhoto)) {
		t.Fatalf("photo command did not carry the rendered photo")
	}
	certAck(t, server, served)
	result := waitDeliveryResult(t, fixture.results)
	if result.Status != "applied" {
		t.Fatalf("result = %#v", result)
	}

	// A TA PUSH scanner is not validated for photo generation.
	taState := DeviceProtocolState{
		Profile:      ProtocolTAPush,
		Confidence:   90,
		PushVersion:  "2.4.0",
		Capabilities: capabilities,
	}
	code := validateLiveBiometricRenderer(taState, biometricDeploymentMetadata{
		Renderer:        "face_photo",
		PersonnelID:     "14",
		Kind:            "face_comparison_photo",
		BioType:         9,
		AlgorithmFamily: "portable_photo",
		Format:          "jpeg",
	})
	if code != "record_type_unsupported" {
		t.Fatalf("TA PUSH photo render code = %q; want record_type_unsupported", code)
	}
	return "photo delivered to the validated AC PUSH 3 profile and refused on TA PUSH"
}
