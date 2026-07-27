package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestRenderDeviceCommandTAFingerprintEnrollment(t *testing.T) {
	got := RenderDeviceCommand(DeviceProtocolState{
		Profile:     ProtocolTAPush,
		Confidence:  90,
		PushVersion: "2.4.1",
	}, "ENROLL_BIO TYPE=1\tNO=3\tPIN=14\tRETRY=0\tOVERWRITE=1")

	want := "ENROLL_FP PIN=14\tFID=3\tRETRY=0\tOVERWRITE=1"
	if got.Rendered != want || got.Action != CommandTranslated {
		t.Fatalf("decision = %#v; want rendered %q and action %q", got, want, CommandTranslated)
	}
}

func TestRenderDeviceCommandUnknownPassesThrough(t *testing.T) {
	original := "ENROLL_BIO TYPE=1\tNO=3\tPIN=14\tRETRY=0\tOVERWRITE=1"
	got := RenderDeviceCommand(DeviceProtocolState{}, original)

	if got.Rendered != original || got.Action != CommandPassedThrough {
		t.Fatalf("decision = %#v; want unchanged command", got)
	}
}

func TestHandleGetRequestRendersCommandForDeviceProfile(t *testing.T) {
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"commands":[]}`))
	}))
	defer cloud.Close()

	tracker := newDeviceTracker()
	tracker.observeProtocol("TA3", ProtocolObservation{
		Path:        "/iclock/cdata",
		PushVersion: "2.4.1",
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
	id := server.enqueueCommand(
		"TA3",
		"ENROLL_BIO TYPE=1\tNO=3\tPIN=14\tRETRY=0\tOVERWRITE=1",
	)

	request := httptest.NewRequest(http.MethodGet, "/iclock/getrequest?SN=TA3", nil)
	recorder := httptest.NewRecorder()
	server.handleGetRequest(recorder, request)

	want := "C:" + strconv.Itoa(id) + ":ENROLL_FP PIN=14\tFID=3\tRETRY=0\tOVERWRITE=1"
	if recorder.Body.String() != want {
		t.Fatalf("body = %q; want %q", recorder.Body.String(), want)
	}
}

func TestRenderDeviceCommandUsesLegacyFingerprintTable(t *testing.T) {
	got := RenderDeviceCommand(DeviceProtocolState{
		Profile:     ProtocolTAPush,
		Confidence:  90,
		PushVersion: "2.4.1",
		Capabilities: map[string]string{
			"fingeralgorithmversion": "10.0",
		},
	}, "DATA UPDATE BIODATA Pin=14\tNo=3\tType=1\tMajorVer=10\tMinorVer=0\tTmp=QUJDRA==")

	want := "DATA UPDATE FINGERTMP PIN=14\tFID=3\tSize=4\tValid=1\tTMP=QUJDRA=="
	if got.Rendered != want || got.Action != CommandTranslated {
		t.Fatalf("decision = %#v; want rendered %q and action %q", got, want, CommandTranslated)
	}
}

func TestRenderDeviceCommandRefusesMismatchedModernFingerprint(t *testing.T) {
	got := RenderDeviceCommand(DeviceProtocolState{
		Profile:     ProtocolTAPush,
		Confidence:  90,
		PushVersion: "2.4.1",
		Capabilities: map[string]string{
			"fingeralgorithmversion": "12.0",
		},
	}, "DATA UPDATE BIODATA Pin=14\tNo=3\tType=1\tMajorVer=11\tMinorVer=0\tTmp=QUJDRA==")

	if got.Action != CommandRefused {
		t.Fatalf("decision = %#v; want action %q", got, CommandRefused)
	}
	if got.Rendered != "" {
		t.Fatalf("rendered = %q; refused commands must not be sent", got.Rendered)
	}
}

func TestRenderDeviceCommandUsesLegacyFingerprintDelete(t *testing.T) {
	got := RenderDeviceCommand(DeviceProtocolState{
		Profile:     ProtocolTAPush,
		Confidence:  90,
		PushVersion: "2.4.1",
		Capabilities: map[string]string{
			"fingeralgorithmversion": "10.0",
		},
	}, "DATA DELETE BIODATA Pin=14\tNo=3\tType=1")

	want := "DATA DELETE FINGERTMP PIN=14\tFID=3"
	if got.Rendered != want || got.Action != CommandTranslated {
		t.Fatalf("decision = %#v; want rendered %q and action %q", got, want, CommandTranslated)
	}
}

func TestRenderDeviceCommandUsesDataFPForOldPush(t *testing.T) {
	got := RenderDeviceCommand(DeviceProtocolState{
		Profile:     ProtocolTAPush,
		Confidence:  90,
		PushVersion: "2.2.13",
	}, "DATA UPDATE BIODATA Pin=14\tNo=3\tType=1\tMajorVer=10\tMinorVer=0\tTmp=QUJDRA==")

	want := "DATA FP PIN=14\tFID=3\tSize=4\tValid=1\tTMP=QUJDRA=="
	if got.Rendered != want || got.Action != CommandTranslated {
		t.Fatalf("decision = %#v; want rendered %q and action %q", got, want, CommandTranslated)
	}
}

func TestHandleGetRequestReportsRefusedCloudCommand(t *testing.T) {
	result := make(chan map[string]any, 1)
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/agent-bridge/commands/result" {
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("decode result: %v", err)
			}
			result <- payload
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"commands":[]}`))
	}))
	defer cloud.Close()

	tracker := newDeviceTracker()
	tracker.observeProtocol("TA4", ProtocolObservation{
		Path:        "/iclock/cdata",
		PushVersion: "2.4.1",
		Capabilities: map[string]string{
			"fingeralgorithmversion": "12.0",
		},
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
	server.enqueueADMSCommand(
		"TA4",
		"DATA UPDATE BIODATA Pin=14\tNo=3\tType=1\tMajorVer=11\tMinorVer=0\tTmp=QUJDRA==",
		"cloud-1",
		"write fingerprint",
	)

	request := httptest.NewRequest(http.MethodGet, "/iclock/getrequest?SN=TA4", nil)
	recorder := httptest.NewRecorder()
	server.handleGetRequest(recorder, request)

	if recorder.Body.String() != "OK" {
		t.Fatalf("body = %q; refused command must not be sent", recorder.Body.String())
	}
	select {
	case payload := <-result:
		if payload["id"] != "cloud-1" || payload["returnCode"] != float64(-2) {
			t.Fatalf("result payload = %#v", payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for refused command result")
	}
}
