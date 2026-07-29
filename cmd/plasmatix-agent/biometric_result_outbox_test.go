package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testOutboxResult(commandID string) biometricDeploymentResult {
	return biometricDeploymentResult{
		Status:     "failed",
		DeviceSN:   "AC1",
		SHA256:     strings.Repeat("a", 64),
		ErrorCode:  "network_unavailable",
		CommandID:  commandID,
		ReturnCode: -1,
	}
}

func TestBiometricResultOutboxPersistsMetadataAcrossRestartWithPrivateModes(
	t *testing.T,
) {
	stateDir := t.TempDir()
	outbox, err := openBiometricResultOutbox(stateDir)
	if err != nil {
		t.Fatalf("open outbox: %v", err)
	}
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	if err := outbox.enqueue(testDeploymentID, testOutboxResult(testCommandID), now); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	reopened, err := openBiometricResultOutbox(stateDir)
	if err != nil {
		t.Fatalf("reopen outbox: %v", err)
	}
	records := reopened.snapshot()
	if len(records) != 1 {
		t.Fatalf("reopened records = %d; want 1", len(records))
	}
	if records[0].DeploymentID != testDeploymentID ||
		records[0].CommandID != testCommandID ||
		records[0].ErrorCode != "network_unavailable" ||
		records[0].Attempts != 0 ||
		!records[0].NextAttemptAt.Equal(now) {
		t.Fatalf("reopened record = %#v", records[0])
	}

	dirInfo, err := os.Stat(stateDir)
	if err != nil {
		t.Fatalf("stat state directory: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("state directory mode = %o; want 700", got)
	}
	fileInfo, err := os.Stat(filepath.Join(stateDir, biometricResultOutboxFilename))
	if err != nil {
		t.Fatalf("stat outbox: %v", err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("outbox mode = %o; want 600", got)
	}
	raw, err := os.ReadFile(filepath.Join(stateDir, biometricResultOutboxFilename))
	if err != nil {
		t.Fatalf("read outbox: %v", err)
	}
	for _, forbidden := range [][]byte{
		[]byte("payload"),
		[]byte("rendered"),
		[]byte("deliveryToken"),
		[]byte("personnelId"),
		[]byte("Authorization"),
		[]byte("Template"),
		[]byte("TMP"),
		[]byte("Photo"),
	} {
		if bytes.Contains(raw, forbidden) {
			t.Fatalf("metadata-only outbox contains forbidden field %q", forbidden)
		}
	}
}

func TestBiometricResultOutboxDeduplicatesAndBoundsCapacity(t *testing.T) {
	outbox, err := openBiometricResultOutbox(t.TempDir())
	if err != nil {
		t.Fatalf("open outbox: %v", err)
	}
	now := time.Now().UTC()
	result := testOutboxResult(testCommandID)
	if err := outbox.enqueue(testDeploymentID, result, now); err != nil {
		t.Fatalf("first enqueue: %v", err)
	}
	if err := outbox.enqueue(testDeploymentID, result, now.Add(time.Second)); err != nil {
		t.Fatalf("duplicate enqueue: %v", err)
	}
	if got := len(outbox.snapshot()); got != 1 {
		t.Fatalf("deduplicated records = %d; want 1", got)
	}

	conflicting := result
	conflicting.ErrorCode = "device_command_failed"
	if err := outbox.enqueue(testDeploymentID, conflicting, now); err == nil {
		t.Fatal("conflicting duplicate replaced a durable result")
	}

	for index := 1; index < maxBiometricResultOutboxRecords; index++ {
		commandID := testUUIDForIndex(index)
		deploymentID := testUUIDForIndex(index + maxBiometricResultOutboxRecords)
		if err := outbox.enqueue(deploymentID, testOutboxResult(commandID), now); err != nil {
			t.Fatalf("enqueue record %d: %v", index, err)
		}
	}
	if got := len(outbox.snapshot()); got != maxBiometricResultOutboxRecords {
		t.Fatalf("records = %d; want %d", got, maxBiometricResultOutboxRecords)
	}
	if err := outbox.enqueue(
		testUUIDForIndex(500),
		testOutboxResult(testUUIDForIndex(501)),
		now,
	); err == nil {
		t.Fatal("outbox accepted a record beyond bounded capacity")
	}
}

func TestBiometricResultOutboxDeduplicatesLeaseWhileResultIsPending(t *testing.T) {
	outbox, err := openBiometricResultOutbox(t.TempDir())
	if err != nil {
		t.Fatalf("open outbox: %v", err)
	}
	if err := outbox.enqueue(
		testDeploymentID,
		testOutboxResult(testCommandID),
		time.Now().Add(time.Hour),
	); err != nil {
		t.Fatalf("enqueue pending result: %v", err)
	}
	server := &ADMSServer{
		resultOutbox: outbox,
		secretCmdID:  make(map[string]struct{}),
	}

	reserved, code := server.reserveSecretCommand(testCommandID)
	if reserved || code != "" {
		t.Fatalf("pending-result lease reserved=%v code=%q; want deduplicated", reserved, code)
	}
	if got := len(server.secretCmdID); got != 0 {
		t.Fatalf("pending-result lease created %d local reservation(s)", got)
	}
}

func TestBiometricResultOutboxCorruptionDisablesSecretAdmission(t *testing.T) {
	server := &ADMSServer{
		resultOutbox:    &biometricResultOutbox{},
		resultOutboxErr: errBiometricResultOutboxCorrupt,
		secretCmdID:     make(map[string]struct{}),
	}
	reserved, code := server.reserveSecretCommand(testCommandID)
	if reserved || code != "deployment_delivery_unavailable" {
		t.Fatalf("corrupt outbox reserved=%v code=%q", reserved, code)
	}
}

func TestBiometricResultOutboxCorruptionFailsClosedWithoutEchoingContent(
	t *testing.T,
) {
	stateDir := t.TempDir()
	secret := "raw-template-must-not-appear"
	corrupt := `{"version":1,"records":[{"payload":"` + secret + `"}]}`
	if err := os.WriteFile(
		filepath.Join(stateDir, biometricResultOutboxFilename),
		[]byte(corrupt),
		0o600,
	); err != nil {
		t.Fatalf("write corrupt outbox: %v", err)
	}
	_, err := openBiometricResultOutbox(stateDir)
	if err == nil {
		t.Fatal("corrupt outbox was accepted")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("corruption error echoed secret content: %v", err)
	}
}

func TestBiometricResultOutboxRetriesLostResponseAndDeletesAfterSuccess(
	t *testing.T,
) {
	stateDir := t.TempDir()
	var mu sync.Mutex
	var requests int
	var bodies [][]byte
	var persistedBeforePost bool
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := new(bytes.Buffer)
		_, _ = body.ReadFrom(r.Body)
		mu.Lock()
		requests++
		bodies = append(bodies, append([]byte(nil), body.Bytes()...))
		current := requests
		persisted, readErr := os.ReadFile(
			filepath.Join(stateDir, biometricResultOutboxFilename),
		)
		if readErr == nil && bytes.Contains(persisted, []byte(testCommandID)) {
			persistedBeforePost = true
		}
		mu.Unlock()
		if current == 1 {
			connection, _, hijackErr := w.(http.Hijacker).Hijack()
			if hijackErr != nil {
				t.Errorf("hijack lost response: %v", hijackErr)
				return
			}
			_ = connection.Close()
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true, "deploymentId": testDeploymentID, "status": "failed",
		})
	}))
	defer cloud.Close()

	outbox, err := openBiometricResultOutbox(stateDir)
	if err != nil {
		t.Fatalf("open outbox: %v", err)
	}
	agent := &Agent{
		config:   Config{APIKey: "agent-key", PlamatixURL: cloud.URL},
		stateDir: stateDir,
	}
	server := &ADMSServer{
		agent:         agent,
		resultOutbox:  outbox,
		secretCmdID:   map[string]struct{}{testCommandID: {}},
		secretPending: make(map[pendingCommandKey]*secretADMSCommand),
	}
	agent.adms = server
	server.startBiometricResultWorker(testOutboxResult(testCommandID), testDeploymentID)
	t.Cleanup(server.shutdownBiometricDelivery)

	deadline := time.Now().Add(3 * time.Second)
	for {
		mu.Lock()
		gotRequests := requests
		gotBodies := append([][]byte(nil), bodies...)
		mu.Unlock()
		if gotRequests >= 2 && len(outbox.snapshot()) == 0 {
			if !bytes.Equal(gotBodies[0], gotBodies[1]) {
				t.Fatal("lost-response retry changed the safe result body")
			}
			mu.Lock()
			wasPersisted := persistedBeforePost
			mu.Unlock()
			if !wasPersisted {
				t.Fatal("result network request started before durable enqueue")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("outbox did not retry/delete: requests=%d records=%d",
				gotRequests, len(outbox.snapshot()))
		}
		time.Sleep(time.Millisecond)
	}
}

func TestBiometricResultOutboxResumesPendingReportAfterRestart(t *testing.T) {
	stateDir := t.TempDir()
	first, err := openBiometricResultOutbox(stateDir)
	if err != nil {
		t.Fatalf("open first outbox: %v", err)
	}
	if err := first.enqueue(
		testDeploymentID,
		testOutboxResult(testCommandID),
		time.Now().Add(-time.Second),
	); err != nil {
		t.Fatalf("enqueue before restart: %v", err)
	}

	reported := make(chan deliveryResultRecord, 1)
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var result deliveryResultRecord
		if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
			t.Errorf("decode result: %v", err)
		}
		reported <- result
		w.WriteHeader(http.StatusOK)
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
	case result := <-reported:
		if result.CommandID != testCommandID ||
			result.ErrorCode != "network_unavailable" {
			t.Fatalf("restarted report = %#v", result)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("restarted outbox did not report pending metadata")
	}
	deadline := time.Now().Add(time.Second)
	for len(reopened.snapshot()) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("restarted outbox retained successful report")
		}
		time.Sleep(time.Millisecond)
	}
}

func testUUIDForIndex(index int) string {
	return fmt.Sprintf("aaaaaaaa-aaaa-4aaa-8aaa-%012x", index)
}

func TestBiometricResultOutboxBackoffMetadataSurvivesRestart(t *testing.T) {
	stateDir := t.TempDir()
	outbox, err := openBiometricResultOutbox(stateDir)
	if err != nil {
		t.Fatalf("open outbox: %v", err)
	}
	now := time.Now().UTC()
	if err := outbox.enqueue(testDeploymentID, testOutboxResult(testCommandID), now); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if err := outbox.recordRetry(testDeploymentID, testCommandID, now); err != nil {
		t.Fatalf("record retry: %v", err)
	}
	reopened, err := openBiometricResultOutbox(stateDir)
	if err != nil {
		t.Fatalf("reopen outbox: %v", err)
	}
	record := reopened.snapshot()[0]
	if record.Attempts != 1 || !record.NextAttemptAt.After(now) {
		t.Fatalf("retry metadata = %#v", record)
	}
}

func TestBiometricResultOutboxTerminalSafeResponseIsDeleted(t *testing.T) {
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"stale_deployment_command"}`))
	}))
	defer cloud.Close()
	outbox, err := openBiometricResultOutbox(t.TempDir())
	if err != nil {
		t.Fatalf("open outbox: %v", err)
	}
	server := &ADMSServer{
		agent:        &Agent{config: Config{PlamatixURL: cloud.URL}},
		resultOutbox: outbox,
	}
	server.agent.adms = server
	if err := outbox.enqueue(
		testDeploymentID,
		testOutboxResult(testCommandID),
		time.Now(),
	); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	server.startBiometricResultOutboxWorker()
	t.Cleanup(server.shutdownBiometricDelivery)

	deadline := time.Now().Add(3 * time.Second)
	for len(outbox.snapshot()) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("terminal safe response remained in outbox")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestBiometricResultOutboxWorkerStopsWithContext(t *testing.T) {
	outbox, err := openBiometricResultOutbox(t.TempDir())
	if err != nil {
		t.Fatalf("open outbox: %v", err)
	}
	server := &ADMSServer{
		agent:        &Agent{},
		resultOutbox: outbox,
	}
	server.agent.adms = server
	server.startBiometricResultOutboxWorker()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		server.shutdownBiometricDelivery()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("outbox worker did not stop with Agent shutdown")
	}
}
