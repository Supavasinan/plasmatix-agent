package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProtocolHeartbeatIncludesDetectedDeviceState(t *testing.T) {
	payloads := make(chan map[string]any, 1)
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode heartbeat: %v", err)
		}
		payloads <- payload
		w.WriteHeader(http.StatusOK)
	}))
	defer cloud.Close()

	tracker := newDeviceTracker()
	tracker.observeProtocol("TA5", ProtocolObservation{
		Path:        "/iclock/cdata",
		PushVersion: "2.4.1",
		Capabilities: map[string]string{
			"fingerfunon": "1",
		},
	})
	agent := &Agent{
		config:  Config{PlamatixURL: cloud.URL},
		devices: tracker,
	}

	if err := agent.postHeartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	payload := <-payloads
	devices := payload["devices"].([]any)
	device := devices[0].(map[string]any)

	if device["protocolProfile"] != "ta_push" {
		t.Fatalf("protocolProfile = %#v", device["protocolProfile"])
	}
	if device["protocolConfidence"] != float64(90) {
		t.Fatalf("protocolConfidence = %#v", device["protocolConfidence"])
	}
	if device["pushVersion"] != "2.4.1" {
		t.Fatalf("pushVersion = %#v", device["pushVersion"])
	}
	if device["protocolCapabilities"].(map[string]any)["fingerfunon"] != "1" {
		t.Fatalf("protocolCapabilities = %#v", device["protocolCapabilities"])
	}
	if len(device["protocolEvidence"].([]any)) == 0 {
		t.Fatal("protocolEvidence is empty")
	}
	if device["protocolObservedAt"] == nil {
		t.Fatal("protocolObservedAt is missing")
	}
}
