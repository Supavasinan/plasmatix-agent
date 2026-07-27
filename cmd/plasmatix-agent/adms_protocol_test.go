package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Catches a regression where a classic TA PUSH 2.x handshake is left
// unknown, causing the agent to serve the AC PUSH fingerprint dialect.
func TestObserveProtocolClassifiesTAPushVersion(t *testing.T) {
	state := ObserveProtocol(DeviceProtocolState{}, ProtocolObservation{
		Path:        "/iclock/cdata",
		PushVersion: "2.4.1",
	})

	if state.Profile != ProtocolTAPush {
		t.Fatalf("profile = %q; want %q", state.Profile, ProtocolTAPush)
	}
	if state.Confidence < 80 {
		t.Fatalf("confidence = %d; want at least 80", state.Confidence)
	}
}

// Catches a regression where contradictory strong evidence leaves a device
// locked to the wrong dialect instead of returning to the safe fallback.
func TestObserveProtocolConflictFallsBackToUnknown(t *testing.T) {
	state := ObserveProtocol(
		DeviceProtocolState{
			Profile:    ProtocolTAPush,
			Confidence: 90,
			Evidence:   []string{"push_version_2_x"},
		},
		ProtocolObservation{Path: "/iclock/registry"},
	)

	if state.Profile != ProtocolUnknown {
		t.Fatalf("profile = %q; want %q", state.Profile, ProtocolUnknown)
	}
	if state.Confidence != 0 {
		t.Fatalf("confidence = %d; want 0 after conflict", state.Confidence)
	}
}

// Catches shared-map mutations that could let one request silently rewrite
// the stored capability evidence for later command decisions.
func TestDeviceTrackerProtocolStateReturnsIndependentSnapshot(t *testing.T) {
	tracker := newDeviceTracker()
	tracker.observeProtocol("TA1", ProtocolObservation{
		Path:        "/iclock/cdata",
		PushVersion: "2.4.1",
		Capabilities: map[string]string{
			"fingerfunon": "1",
		},
	})

	first, ok := tracker.protocolState("TA1")
	if !ok {
		t.Fatal("protocol state not stored")
	}
	first.Capabilities["fingerfunon"] = "0"
	first.Evidence[0] = "changed"

	second, ok := tracker.protocolState("TA1")
	if !ok {
		t.Fatal("protocol state disappeared")
	}
	if second.Capabilities["fingerfunon"] != "1" {
		t.Fatalf("stored capability mutated: %#v", second.Capabilities)
	}
	if second.Evidence[0] != "push_version_2_x" {
		t.Fatalf("stored evidence mutated: %#v", second.Evidence)
	}
}

// Catches a disconnected observer that classifies correctly in isolation but
// never receives real registration requests from the ADMS handler.
func TestHandleRegistryRecordsACPushEvidence(t *testing.T) {
	tracker := newDeviceTracker()
	server := &ADMSServer{agent: &Agent{devices: tracker}}
	request := httptest.NewRequest(
		http.MethodGet,
		"/iclock/registry?SN=AC1",
		nil,
	)

	server.handleRegistry(httptest.NewRecorder(), request)

	state, ok := tracker.protocolState("AC1")
	if !ok {
		t.Fatal("protocol state not recorded")
	}
	if state.Profile != ProtocolACPush3 {
		t.Fatalf("profile = %q; want %q", state.Profile, ProtocolACPush3)
	}
}

// Catches a missing cdata wiring path that would leave TA terminals unknown
// even though they report their PUSH version during the real handshake.
func TestHandleCDataRecordsTAPushVersion(t *testing.T) {
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer cloud.Close()

	tracker := newDeviceTracker()
	server := &ADMSServer{agent: &Agent{
		config:  Config{PlamatixURL: cloud.URL},
		devices: tracker,
	}}
	request := httptest.NewRequest(
		http.MethodGet,
		"/iclock/cdata?SN=TA1&pushver=2.4.1",
		nil,
	)

	server.handleCData(httptest.NewRecorder(), request)

	state, ok := tracker.protocolState("TA1")
	if !ok {
		t.Fatal("protocol state not recorded")
	}
	if state.Profile != ProtocolTAPush {
		t.Fatalf("profile = %q; want %q", state.Profile, ProtocolTAPush)
	}
}

// Catches device-specific key casing leaking into later capability lookups.
func TestObserveProtocolNormalizesCapabilityKeys(t *testing.T) {
	state := ObserveProtocol(DeviceProtocolState{}, ProtocolObservation{
		Path:        "/iclock/cdata",
		PushVersion: "2.4.1",
		Capabilities: map[string]string{
			"FingerFunOn": "1",
			"FACEFUNON":   "1",
		},
	})

	if state.Capabilities["fingerfunon"] != "1" {
		t.Fatalf("finger capability = %#v", state.Capabilities)
	}
	if state.Capabilities["facefunon"] != "1" {
		t.Fatalf("face capability = %#v", state.Capabilities)
	}
}

// Catches a handler that records only the PUSH version and drops the
// capability values required by biometric command selection.
func TestHandleCDataRecordsReportedCapabilities(t *testing.T) {
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer cloud.Close()

	tracker := newDeviceTracker()
	server := &ADMSServer{agent: &Agent{
		config:  Config{PlamatixURL: cloud.URL},
		devices: tracker,
	}}
	request := httptest.NewRequest(
		http.MethodGet,
		"/iclock/cdata?SN=TA1&pushver=2.4.1&FingerFunOn=1&MultiBioVersion=1%3A12.0",
		nil,
	)

	server.handleCData(httptest.NewRecorder(), request)

	state, _ := tracker.protocolState("TA1")
	if state.Capabilities["fingerfunon"] != "1" {
		t.Fatalf("capabilities = %#v", state.Capabilities)
	}
	if state.Capabilities["multibioversion"] != "1:12.0" {
		t.Fatalf("capabilities = %#v", state.Capabilities)
	}
}

// Catches an unbounded evidence slice that would grow on every device poll.
func TestObserveProtocolBoundsEvidenceHistory(t *testing.T) {
	state := DeviceProtocolState{}
	for range 40 {
		state = ObserveProtocol(state, ProtocolObservation{Path: "/iclock/registry"})
	}
	if len(state.Evidence) > 16 {
		t.Fatalf("evidence length = %d; want at most 16", len(state.Evidence))
	}
}

// Catches protocol state that cannot be aged or shown accurately in the UI.
func TestObserveProtocolRecordsObservationTime(t *testing.T) {
	state := ObserveProtocol(DeviceProtocolState{}, ProtocolObservation{
		Path:        "/iclock/cdata",
		PushVersion: "2.4.1",
	})
	if state.ObservedAt.IsZero() {
		t.Fatal("observation time is zero")
	}
}

// Catches a newly contacted device appearing with an empty profile value,
// which is ambiguous to API and UI consumers.
func TestDeviceTrackerNewContactDefaultsToUnknown(t *testing.T) {
	tracker := newDeviceTracker()
	tracker.noteContact("NEW1", "")

	state, ok := tracker.protocolState("NEW1")
	if !ok {
		t.Fatal("newly contacted device was not tracked")
	}
	if state.Profile != ProtocolUnknown {
		t.Fatalf("profile = %q; want %q", state.Profile, ProtocolUnknown)
	}
}

// Catches contradictory TA evidence silently replacing a strongly detected
// AC PUSH profile; conflicts must return to the safe unknown state.
func TestObserveProtocolReverseConflictFallsBackToUnknown(t *testing.T) {
	state := ObserveProtocol(
		DeviceProtocolState{
			Profile:    ProtocolACPush3,
			Confidence: 95,
			Evidence:   []string{"ac_push_route"},
		},
		ProtocolObservation{
			Path:        "/iclock/cdata",
			PushVersion: "2.4.1",
		},
	)

	if state.Profile != ProtocolUnknown {
		t.Fatalf("profile = %q; want %q", state.Profile, ProtocolUnknown)
	}
	if state.Confidence != 0 {
		t.Fatalf("confidence = %d; want 0 after conflict", state.Confidence)
	}
}

// Catches the PUSH 3.x event channel bypassing protocol observation after a
// device connects directly to /iclock/push.
func TestHandlePushRecordsACPushEvidence(t *testing.T) {
	tracker := newDeviceTracker()
	server := &ADMSServer{agent: &Agent{devices: tracker}}
	request := httptest.NewRequest(
		http.MethodGet,
		"/iclock/push?SN=AC2",
		nil,
	)

	server.handlePush(httptest.NewRecorder(), request)

	state, ok := tracker.protocolState("AC2")
	if !ok {
		t.Fatal("protocol state not recorded")
	}
	if state.Profile != ProtocolACPush3 {
		t.Fatalf("profile = %q; want %q", state.Profile, ProtocolACPush3)
	}
}

// Catches heartbeat snapshots sharing nested protocol maps and slices with
// the live tracker state.
func TestDeviceTrackerSnapshotClonesProtocolState(t *testing.T) {
	tracker := newDeviceTracker()
	tracker.observeProtocol("TA2", ProtocolObservation{
		Path:         "/iclock/cdata",
		PushVersion:  "2.4.1",
		Capabilities: map[string]string{"fingerfunon": "1"},
	})

	first := tracker.snapshot()
	first[0].Protocol.Capabilities["fingerfunon"] = "0"
	first[0].Protocol.Evidence[0] = "changed"

	second := tracker.snapshot()
	if second[0].Protocol.Capabilities["fingerfunon"] != "1" {
		t.Fatalf("stored capability mutated: %#v", second[0].Protocol.Capabilities)
	}
	if second[0].Protocol.Evidence[0] != "push_version_2_x" {
		t.Fatalf("stored evidence mutated: %#v", second[0].Protocol.Evidence)
	}
}
