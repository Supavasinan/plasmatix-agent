package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Captured verbatim from the SenseFace 2A at 10.10.40.96 (SN NYU7253100765,
// ZAM70-NF24HA-Ver3.3.12) answering a PushOptions request. Kept byte-for-byte
// so a firmware quirk cannot be "fixed" by quietly rewriting the fixture.
const senseFace2AOptions = "~DeviceName=SenseFace 2A,MAC=00:17:61:11:c4:40," +
	"TransactionCount=1342,~MaxAttLogCount=15,UserCount=17,~MaxUserCount=30," +
	"PhotoFunOn=1,~MaxUserPhotoCount=3000,FingerFunOn=1,FPVersion=13," +
	"~MaxFingerCount=30,FPCount=18,FaceFunOn=1,FaceVersion=40," +
	"~MaxFaceCount=1500,FaceCount=0,FvFunOn=0,FvVersion=3,~MaxFvCount=10," +
	"FvCount=0,PvFunOn=0,PvVersion=12,~MaxPvCount=,PvCount=0,Language=76," +
	"IPAddress=10.10.40.96,~Platform=ZAM70_TFT,~OEMVendor=ZKTECO CO.," +
	"FWVersion=ZAM70-NF24HA-Ver3.3.12,PushVersion=Ver 3.1.2S-20250616," +
	"VisilightFun=1,MultiBioDataSupport=0:1:0:0:0:0:0:0:0:1," +
	"MultiBioPhotoSupport=0:0:0:0:0:0:0:0:0:1,BioPhotoFun=1,BioDataFun=," +
	"~LockFunOn=1,MultiBioVersion=0:13.0:0:0:0:0:0:0:0:40.1," +
	"MaxMultiBioDataCount=0:3000:0:0:0:0:0:0:0:1500,MultiBioDataCount=0:18:0:0:0:0:0:0:0:0"

func TestParseDeviceOptionsReadsRealSenseFacePayload(t *testing.T) {
	options := parseDeviceOptions([]byte(senseFace2AOptions))

	for key, want := range map[string]string{
		"~DeviceName":         "SenseFace 2A",
		"FWVersion":           "ZAM70-NF24HA-Ver3.3.12",
		"FPVersion":           "13",
		"FaceVersion":         "40",
		"BioDataFun":          "",
		"MultiBioVersion":     "0:13.0:0:0:0:0:0:0:0:40.1",
		"MultiBioDataSupport": "0:1:0:0:0:0:0:0:0:1",
		"~MaxUserCount":       "30",
	} {
		if got := options[key]; got != want {
			t.Errorf("options[%q] = %q, want %q", key, got, want)
		}
	}
}

func TestCapabilitiesFromRealSenseFacePayload(t *testing.T) {
	capabilities := capabilitiesFromOptions(parseDeviceOptions([]byte(senseFace2AOptions)))

	want := map[string]string{
		// The scalar flag is blank on this firmware; MultiBioDataSupport
		// advertises the fingerprint and face slots, so BIODATA is accepted.
		"biodatafun": "1",
		// Exact major.minor, taken from MultiBioVersion rather than the
		// minor-less FPVersion/FaceVersion scalars.
		"fingeralgorithmversion": "13.0",
		"facealgorithmversion":   "40.1",
		"fingerfunon":            "1",
		"facefunon":              "1",
		"biophotofun":            "1",
		"photofunon":             "1",
	}
	for key, expected := range want {
		if got := capabilities[key]; got != expected {
			t.Errorf("capabilities[%q] = %q, want %q", key, got, expected)
		}
	}
}

func TestBioDataFunPrefersExplicitFlagOverSlotList(t *testing.T) {
	// A device that explicitly denies BIODATA must not have that overridden by
	// the slot list, or Plasmatix would ship templates the firmware rejects.
	capabilities := capabilitiesFromOptions(parseDeviceOptions(
		[]byte("BioDataFun=0,MultiBioDataSupport=0:1:0:0:0:0:0:0:0:1"),
	))
	if got := capabilities["biodatafun"]; got != "0" {
		t.Errorf("biodatafun = %q, want %q", got, "0")
	}
}

func TestAlgorithmVersionAbsentWhenModalityUnsupported(t *testing.T) {
	// Slot 9 reads 0 — no visible-light face engine. Reporting "0.0" would let
	// the cloud match a stored template against a version the device lacks.
	capabilities := capabilitiesFromOptions(parseDeviceOptions(
		[]byte("MultiBioVersion=0:13.0:0:0:0:0:0:0:0:0,FingerFunOn=1"),
	))
	if _, present := capabilities["facealgorithmversion"]; present {
		t.Errorf("facealgorithmversion should be absent, got %q",
			capabilities["facealgorithmversion"])
	}
	if got := capabilities["fingeralgorithmversion"]; got != "13.0" {
		t.Errorf("fingeralgorithmversion = %q, want %q", got, "13.0")
	}
}

func TestScalarVersionFallbackWhenMultiBioAbsent(t *testing.T) {
	// Older firmware omits MultiBioVersion entirely.
	capabilities := capabilitiesFromOptions(parseDeviceOptions(
		[]byte("FingerFunOn=1,FPVersion=10,BioDataFun=1"),
	))
	if got := capabilities["fingeralgorithmversion"]; got != "10.0" {
		t.Errorf("fingeralgorithmversion = %q, want %q", got, "10.0")
	}
}

func TestHandshakeRequestsCapabilitiesAndUsesTabbedTransFlag(t *testing.T) {
	resp := buildHandshakeOptions("NYU7253100765", "9999", stampStyleLegacy, 7)

	// Without PushOptionsFlag + PushOptions the device never sends its options
	// block, and every biometric delivery stays blocked on unknown algorithms.
	for _, required := range []string{
		"GET OPTION FROM: NYU7253100765",
		"PushOptionsFlag=1",
		"PushOptions=" + pushOptionsRequest,
		"ServerVer=2.4.1",
		"PushProtVer=2.4.1",
		"SupportPing=1",
		"MaxPostSize=1048576",
		"Encrypt=0",
		"EncryptFlag=1000000000",
		"ATTLOGStamp=9999",
	} {
		if !strings.Contains(resp, required) {
			t.Errorf("handshake missing %q\ngot:\n%s", required, resp)
		}
	}

	if strings.Contains(resp, "Encrypt=None") {
		t.Error("Encrypt=None is the legacy spelling; this firmware expects Encrypt=0")
	}

	// The tab separators are the whole point — spaces make the firmware treat
	// the list as one unrecognised token.
	if !strings.Contains(resp, "AttLog\tOpLog\tAttPhoto") {
		t.Errorf("TransFlag tokens must be tab-separated, got:\n%s", resp)
	}
	for _, token := range []string{"FACE", "BioPhoto", "FVEIN", "FPImag"} {
		if !strings.Contains(resp, token) {
			t.Errorf("TransFlag missing %q — device will not push that record type", token)
		}
	}
}

func TestHandshakeFullSyncStampReplaysBacklog(t *testing.T) {
	if !strings.Contains(buildHandshakeOptions("SN1", "0", stampStyleLegacy, 7), "ATTLOGStamp=0") {
		t.Error("full-sync handshake must carry stamp 0 so the device replays")
	}
}

// TestRealDeviceHandshakeUnlocksBiometricGate replays the exact two-request
// sequence the SenseFace 2A at 10.10.40.96 performs against ZKBioTime, taken
// from a packet capture, and asserts the agent ends up knowing everything the
// cloud's compatibility check requires.
//
// Before device options were parsed, this sequence left protocolCapabilities
// empty, so evaluateCompatibility rejected every template with
// algorithm_unknown no matter how long the agent ran.
func TestRealDeviceHandshakeUnlocksBiometricGate(t *testing.T) {
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
	const sn = "NYU7253100765"

	// 1. The device's real handshake, query string copied from the capture.
	handshake := httptest.NewRecorder()
	server.handleCData(handshake, httptest.NewRequest(
		http.MethodGet,
		"/iclock/cdata?SN="+sn+"&options=all&language=76&pushver=2.4.1"+
			"&DeviceType=att&PushOptionsFlag=1",
		nil,
	))
	if !strings.Contains(handshake.Body.String(), "PushOptions=") {
		t.Fatal("handshake did not ask the device for its capabilities")
	}

	// The 2.4.1 push version alone should already classify the device.
	state, _ := tracker.protocolState(sn)
	if state.Profile != ProtocolTAPush {
		t.Fatalf("profile = %q, want %q", state.Profile, ProtocolTAPush)
	}
	if state.Confidence < 80 {
		t.Fatalf("confidence = %d, want >= 80 (cloud gate)", state.Confidence)
	}

	// 2. The device replies with its option block.
	options := httptest.NewRecorder()
	server.handleCData(options, httptest.NewRequest(
		http.MethodPost,
		"/iclock/cdata?SN="+sn+"&table=options",
		strings.NewReader(senseFace2AOptions),
	))
	if body := options.Body.String(); body != "OK" {
		t.Fatalf("options ack = %q, want %q — a count ack makes the "+
			"firmware re-send the block forever", body, "OK")
	}

	// The profile must survive the second request, and capabilities merge in.
	state, _ = tracker.protocolState(sn)
	if state.Profile != ProtocolTAPush || state.Confidence < 80 {
		t.Fatalf("profile/confidence regressed after options: %q/%d",
			state.Profile, state.Confidence)
	}
	for key, want := range map[string]string{
		"biodatafun":             "1",
		"fingeralgorithmversion": "13.0",
		"facealgorithmversion":   "40.1",
		"fingerfunon":            "1",
		"facefunon":              "1",
	} {
		if got := state.Capabilities[key]; got != want {
			t.Errorf("capabilities[%q] = %q, want %q", key, got, want)
		}
	}
}

func TestHandshakeStampStyleSelectsKeySpelling(t *testing.T) {
	legacy := buildHandshakeOptions("SN1", "9999", stampStyleLegacy, 7)
	if !strings.Contains(legacy, "ATTLOGStamp=9999") {
		t.Errorf("legacy style must emit ATTLOGStamp, got:\n%s", legacy)
	}
	if strings.Contains(legacy, "\nStamp=") {
		t.Error("legacy style must not emit the push3 Stamp key")
	}

	push3 := buildHandshakeOptions("SN1", "9999", stampStylePush3, 7)
	for _, want := range []string{"Stamp=9999", "OpStamp=9999", "PhotoStamp=None"} {
		if !strings.Contains(push3, want) {
			t.Errorf("push3 style missing %q, got:\n%s", want, push3)
		}
	}
	if strings.Contains(push3, "ATTLOGStamp") {
		t.Error("push3 style must not emit the legacy ATTLOGStamp key")
	}
}

func TestHandshakeCarriesConfiguredTimeZone(t *testing.T) {
	// A hardcoded offset silently shifts every punch on any site that is not
	// UTC+7 — the exact failure that cost this deployment a day of records.
	for offset, want := range map[int]string{7: "TimeZone=7", 0: "TimeZone=0", -5: "TimeZone=-5"} {
		got := buildHandshakeOptions("SN1", "9999", stampStyleLegacy, offset)
		if !strings.Contains(got, want) {
			t.Errorf("offset %d: handshake missing %q", offset, want)
		}
	}
}

func TestNormalizeConfigValidatesDeviceSettings(t *testing.T) {
	base := Config{APIKey: "k", PlamatixURL: "https://example.test", Mode: "adms"}

	cfg, err := normalizeConfig(base)
	if err != nil {
		t.Fatalf("defaults rejected: %v", err)
	}
	if cfg.StampStyle != stampStyleLegacy {
		t.Errorf("default stamp style = %q, want %q", cfg.StampStyle, stampStyleLegacy)
	}

	withZone := base
	withZone.DeviceTimeZone = 99
	if _, err := normalizeConfig(withZone); err == nil {
		t.Error("device_timezone 99 must be rejected")
	}

	withStyle := base
	withStyle.StampStyle = "guess"
	if _, err := normalizeConfig(withStyle); err == nil {
		t.Error("unknown stamp_style must be rejected")
	}
}
