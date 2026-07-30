package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func TestExtractBiometricAssetsKeepsBytesOutOfMetadata(t *testing.T) {
	body := []byte("PIN=14\tFID=3\tSize=4\tValid=1\tTMP=QUJDRA==")
	assets, err := ExtractBiometricAssets("FINGERTMP", body, DeviceProtocolState{
		Capabilities: map[string]string{"fingeralgorithmversion": "10.0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 1 || !bytes.Equal(assets[0].Bytes, []byte("ABCD")) {
		t.Fatalf("decoded asset count/size = %d/%d; want 1/4", len(assets), len(assets[0].Bytes))
	}
	encoded, err := json.Marshal(assets[0].SafeMetadata())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("QUJDRA")) || bytes.Contains(encoded, []byte("ABCD")) {
		t.Fatal("safe metadata leaked template bytes")
	}
	if assets[0].AssetKind != "fingerprint_template" ||
		assets[0].AlgorithmFamily != "zkfinger-v10" ||
		assets[0].AlgorithmMajor != 10 ||
		assets[0].AlgorithmMinor != 0 ||
		assets[0].AssetFormat != "templatev10" {
		t.Fatalf("fingerprint metadata = %#v", assets[0].SafeMetadata())
	}
}

func TestExtractBiometricAssetsParsesMultipleBioDataRows(t *testing.T) {
	body := []byte(strings.Join([]string{
		"Pin=14\tNo=2\tType=1\tMajorVer=12\tMinorVer=1\tFormat=templatev12\tTmp=QUJDRA==",
		"PIN=15\tNO=0\tTYPE=9\tMajorVer=7\tMinorVer=4\tFormat=facev7\tTemplate=RUZHSA==",
	}, "\n"))

	assets, err := ExtractBiometricAssets("BIODATA", body, DeviceProtocolState{})
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 2 {
		t.Fatalf("asset count = %d; want 2", len(assets))
	}
	if assets[0].PIN != "14" || assets[0].BioType != 1 || assets[0].SlotIndex != 2 ||
		assets[0].AssetKind != "fingerprint_template" || !bytes.Equal(assets[0].Bytes, []byte("ABCD")) {
		t.Fatalf("fingerprint metadata = %#v", assets[0].SafeMetadata())
	}
	if assets[1].PIN != "15" || assets[1].BioType != 9 || assets[1].SlotIndex != 0 ||
		assets[1].AssetKind != "face_template" || !bytes.Equal(assets[1].Bytes, []byte("EFGH")) {
		t.Fatalf("face metadata = %#v", assets[1].SafeMetadata())
	}
}

func TestExtractBiometricAssetsParsesBioPhotoJPEG(t *testing.T) {
	jpeg := []byte{0xff, 0xd8, 0xff, 0xe0, 'J', 'F', 'I', 'F', 0xff, 0xd9}
	body := []byte("PIN=14\tNo=0\tType=9\tphoto_base64=" + base64.StdEncoding.EncodeToString(jpeg))

	assets, err := ExtractBiometricAssets("BIOPHOTO", body, DeviceProtocolState{})
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 1 || !bytes.Equal(assets[0].Bytes, jpeg) {
		t.Fatalf("decoded photo count/size = %d/%d; want 1/%d", len(assets), len(assets[0].Bytes), len(jpeg))
	}
	if assets[0].AssetKind != "face_comparison_photo" ||
		assets[0].AssetFormat != "jpeg" ||
		assets[0].AlgorithmFamily != "portable_photo" ||
		assets[0].AlgorithmMajor != 0 ||
		assets[0].AlgorithmMinor != 0 {
		t.Fatalf("photo metadata = %#v", assets[0].SafeMetadata())
	}
}

func TestExtractBiometricAssetsRejectsInvalidBase64(t *testing.T) {
	_, err := ExtractBiometricAssets(
		"FINGERTMP",
		[]byte("PIN=14\tFID=3\tTMP=not-!base64"),
		DeviceProtocolState{},
	)
	if err == nil || !strings.Contains(err.Error(), "invalid biometric encoding") {
		t.Fatalf("error = %v; want invalid biometric encoding", err)
	}
	if strings.Contains(err.Error(), "not-!base64") {
		t.Fatal("parse error leaked the encoded template")
	}
}

func TestExtractBiometricAssetsRejectsInvalidIdentityMetadata(t *testing.T) {
	tests := []struct {
		name  string
		table string
		body  string
	}{
		{
			name:  "missing fingerprint slot",
			table: "FINGERTMP",
			body:  "PIN=14\tTMP=QUJDRA==",
		},
		{
			name:  "malformed fingerprint slot",
			table: "FINGERTMP",
			body:  "PIN=14\tFID=invalid\tTMP=QUJDRA==",
		},
		{
			name:  "out of range fingerprint slot",
			table: "FINGERTMP",
			body:  "PIN=14\tFID=10\tTMP=QUJDRA==",
		},
		{
			name:  "malformed biodata type",
			table: "BIODATA",
			body:  "PIN=14\tNo=0\tType=invalid\tTmp=QUJDRA==",
		},
		{
			name:  "malformed biodata slot",
			table: "BIODATA",
			body:  "PIN=14\tNo=invalid\tType=1\tTmp=QUJDRA==",
		},
		{
			name:  "non-face biophoto",
			table: "BIOPHOTO",
			body:  "PIN=14\tNo=0\tType=1\tPhoto=QUJDRA==",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ExtractBiometricAssets(tt.table, []byte(tt.body), DeviceProtocolState{})
			if err == nil {
				t.Fatal("expected invalid biometric metadata error")
			}
			if strings.Contains(err.Error(), "QUJDRA") || strings.Contains(err.Error(), "ABCD") {
				t.Fatal("metadata error leaked biometric material")
			}
		})
	}
}

func TestExtractBiometricAssetsRejectsTooManyRows(t *testing.T) {
	rows := make([]string, 65)
	for index := range rows {
		rows[index] = "PIN=14\tFID=0\tTMP=QUJDRA=="
	}

	_, err := ExtractBiometricAssets(
		"FINGERTMP",
		[]byte(strings.Join(rows, "\n")),
		DeviceProtocolState{},
	)
	if err == nil || !strings.Contains(err.Error(), "too many biometric assets") {
		t.Fatalf("error = %v; want aggregate row rejection", err)
	}
}

func TestExtractBiometricAssetsPreservesUnknownAlgorithmAsSafeMetadata(t *testing.T) {
	assets, err := ExtractBiometricAssets(
		"BIODATA",
		[]byte("Pin=14\tNo=3\tType=1\tTmp=QUJDRA=="),
		DeviceProtocolState{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 1 || assets[0].AlgorithmFamily != "unknown" ||
		assets[0].AlgorithmMajor != -1 || assets[0].AlgorithmMinor != -1 {
		t.Fatalf("unknown algorithm metadata = %#v", assets[0].SafeMetadata())
	}
}

func TestExtractBiometricAssetsCanonicalizesUntrustedFormat(t *testing.T) {
	hostile := strings.Repeat("QUJDRA", 200)
	tests := []struct {
		name       string
		table      string
		row        string
		state      DeviceProtocolState
		wantFormat string
	}{
		{
			name:       "fingerprint",
			table:      "FINGERTMP",
			row:        "PIN=14\tFID=3\tFormat=" + hostile + "\tTMP=QUJDRA==",
			state:      DeviceProtocolState{Capabilities: map[string]string{"fingeralgorithmversion": "10.0"}},
			wantFormat: "templatev10",
		},
		{
			name:       "face template",
			table:      "BIODATA",
			row:        "Pin=14\tNo=0\tType=9\tMajorVer=7\tMinorVer=4\tFormat=" + hostile + "\tTmp=RUZHSA==",
			state:      DeviceProtocolState{Capabilities: map[string]string{"facealgorithmversion": "7.4"}},
			wantFormat: "facev7",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assets, err := ExtractBiometricAssets(tt.table, []byte(tt.row), tt.state)
			if err != nil {
				t.Fatal(err)
			}
			defer zeroBytes(assets[0].Bytes)
			if got := assets[0].AssetFormat; got != tt.wantFormat {
				t.Fatalf("asset format = %q; want canonical %q", got, tt.wantFormat)
			}
			metadata, err := json.Marshal(assets[0].SafeMetadata())
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(metadata, []byte(hostile)) {
				t.Fatal("safe metadata retained untrusted format")
			}
		})
	}
}

func TestBiometricMetadataAndUploadCanonicalizeUntrustedFormat(t *testing.T) {
	hostile := strings.Repeat("QUJDRA", 200)
	observedFormat := make(chan string, 1)
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observedFormat <- r.Header.Get("X-Asset-Format")
		w.WriteHeader(http.StatusCreated)
	}))
	defer cloud.Close()

	asset := CapturedBiometricAsset{
		DeviceSN:        "TA1",
		PIN:             "14",
		BioType:         1,
		SlotIndex:       3,
		AssetKind:       "fingerprint_template",
		AlgorithmFamily: "zkfinger-v10",
		AlgorithmMajor:  10,
		AlgorithmMinor:  0,
		AssetFormat:     hostile,
		Bytes:           []byte("ABCD"),
	}
	if metadata := asset.SafeMetadata(); metadata.AssetFormat != "templatev10" {
		t.Fatalf("safe metadata format = %q; want templatev10", metadata.AssetFormat)
	}
	agent := &Agent{config: Config{PlamatixURL: cloud.URL}}
	if err := agent.UploadBiometricAsset(context.Background(), asset); err != nil {
		t.Fatal(err)
	}
	if got := <-observedFormat; got != "templatev10" {
		t.Fatalf("upload format header = %q; want templatev10", got)
	}
}

func TestBiometricMetadataAndUploadRejectUnsafeIdentityAndHeaderMetadata(t *testing.T) {
	secret := strings.Repeat("U0VDUkVU", 40)
	baseAsset := CapturedBiometricAsset{
		DeviceSN:        "TA1",
		PIN:             "14",
		BioType:         1,
		SlotIndex:       3,
		AssetKind:       "fingerprint_template",
		AlgorithmFamily: "zkfinger-v10",
		AlgorithmMajor:  10,
		AlgorithmMinor:  0,
		AssetFormat:     "templatev10",
	}
	tests := []struct {
		name   string
		mutate func(*CapturedBiometricAsset)
	}{
		{name: "oversized device SN", mutate: func(asset *CapturedBiometricAsset) {
			asset.DeviceSN = secret
		}},
		{name: "unsafe personnel ID", mutate: func(asset *CapturedBiometricAsset) {
			asset.PIN = "14\r\n" + secret
		}},
		{name: "invalid biometric type", mutate: func(asset *CapturedBiometricAsset) {
			asset.BioType = 7
		}},
		{name: "hostile asset kind", mutate: func(asset *CapturedBiometricAsset) {
			asset.AssetKind = secret
		}},
		{name: "hostile algorithm family", mutate: func(asset *CapturedBiometricAsset) {
			asset.AlgorithmFamily = secret
		}},
		{name: "out of range algorithm version", mutate: func(asset *CapturedBiometricAsset) {
			asset.AlgorithmMajor = 256
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requests := make(chan struct{}, 1)
			cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests <- struct{}{}
				w.WriteHeader(http.StatusCreated)
			}))
			defer cloud.Close()

			asset := baseAsset
			tt.mutate(&asset)
			asset.Bytes = []byte("ABCD")
			metadata, err := json.Marshal(asset.SafeMetadata())
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(metadata, []byte(secret)) {
				t.Fatalf("safe metadata retained unsafe input: %s", metadata)
			}

			agent := &Agent{config: Config{PlamatixURL: cloud.URL}}
			if err := agent.UploadBiometricAsset(context.Background(), asset); err == nil {
				t.Fatal("unsafe upload metadata was accepted")
			}
			select {
			case <-requests:
				t.Fatal("unsafe metadata reached upload headers")
			default:
			}
		})
	}
}

func TestExtractBiometricAssetsRejectsUnsafeOrOversizedPersonnelID(t *testing.T) {
	for _, pin := range []string{
		"14\rsecret",
		strings.Repeat("U0VDUkVU", 20),
	} {
		_, err := ExtractBiometricAssets(
			"FINGERTMP",
			[]byte("PIN="+pin+"\tFID=3\tTMP=QUJDRA=="),
			DeviceProtocolState{},
		)
		if err == nil {
			t.Fatalf("unsafe personnel ID %q was accepted", pin)
		}
	}
}

func TestExtractBiometricAssetsValidatesExplicitAlgorithmVersions(t *testing.T) {
	tests := []struct {
		name       string
		metadata   string
		capability string
		wantMajor  int
		wantMinor  int
	}{
		{
			name:       "explicit absent uses bounded capability",
			capability: "10.0",
			wantMajor:  10,
			wantMinor:  0,
		},
		{
			name:       "matching explicit and capability",
			metadata:   "\tMajorVer=10\tMinorVer=0",
			capability: "10.0",
			wantMajor:  10,
			wantMinor:  0,
		},
		{
			name:      "valid explicit without capability",
			metadata:  "\tMajorVer=10\tMinorVer=0",
			wantMajor: 10,
			wantMinor: 0,
		},
		{
			name:       "malformed explicit major",
			metadata:   "\tMajorVer=bad\tMinorVer=0",
			capability: "10.0",
			wantMajor:  -1,
			wantMinor:  -1,
		},
		{
			name:       "malformed explicit minor",
			metadata:   "\tMajorVer=10\tMinorVer=bad",
			capability: "10.0",
			wantMajor:  -1,
			wantMinor:  -1,
		},
		{
			name:       "partial explicit version",
			metadata:   "\tMajorVer=10",
			capability: "10.0",
			wantMajor:  -1,
			wantMinor:  -1,
		},
		{
			name:       "out of range explicit version",
			metadata:   "\tMajorVer=256\tMinorVer=0",
			capability: "256.0",
			wantMajor:  -1,
			wantMinor:  -1,
		},
		{
			name:       "explicit conflicts with capability",
			metadata:   "\tMajorVer=11\tMinorVer=0",
			capability: "10.0",
			wantMajor:  -1,
			wantMinor:  -1,
		},
		{
			name:       "malformed capability prevents comparison",
			metadata:   "\tMajorVer=10\tMinorVer=0",
			capability: "not-a-version",
			wantMajor:  -1,
			wantMinor:  -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := DeviceProtocolState{}
			if tt.capability != "" {
				state.Capabilities = map[string]string{"fingeralgorithmversion": tt.capability}
			}
			row := "Pin=14\tNo=3\tType=1" + tt.metadata + "\tTmp=QUJDRA=="
			assets, err := ExtractBiometricAssets("BIODATA", []byte(row), state)
			if err != nil {
				t.Fatal(err)
			}
			defer zeroBytes(assets[0].Bytes)
			if assets[0].AlgorithmMajor != tt.wantMajor ||
				assets[0].AlgorithmMinor != tt.wantMinor {
				t.Fatalf(
					"algorithm = %s/%d/%d; want major/minor %d/%d",
					assets[0].AlgorithmFamily,
					assets[0].AlgorithmMajor,
					assets[0].AlgorithmMinor,
					tt.wantMajor,
					tt.wantMinor,
				)
			}
			if tt.wantMajor < 0 && assets[0].AlgorithmFamily != "unknown" {
				t.Fatalf("algorithm family = %q; want unknown", assets[0].AlgorithmFamily)
			}
		})
	}
}

func TestExtractBiometricAssetsRejectsDuplicateAlgorithmMetadata(t *testing.T) {
	tests := []struct {
		name     string
		metadata string
	}{
		{
			name:     "same key with identical values",
			metadata: "\tMajorVer=10\tMajorVer=10\tMinorVer=0",
		},
		{
			name:     "case variant with conflicting values",
			metadata: "\tMajorVer=10\tmajorver=11\tMinorVer=0",
		},
		{
			name:     "alias with identical values",
			metadata: "\tMajorVer=10\tAlgorithmMajor=10\tMinorVer=0",
		},
		{
			name:     "minor alias with conflicting values",
			metadata: "\tMajorVer=10\tMinorVer=0\tAlgorithmMinor=1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			row := "Pin=14\tNo=3\tType=1" + tt.metadata + "\tTmp=QUJDRA=="
			assets, err := ExtractBiometricAssets(
				"BIODATA",
				[]byte(row),
				DeviceProtocolState{
					Capabilities: map[string]string{"fingeralgorithmversion": "10.0"},
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			defer zeroBytes(assets[0].Bytes)
			if assets[0].AlgorithmFamily != "unknown" ||
				assets[0].AlgorithmMajor != -1 ||
				assets[0].AlgorithmMinor != -1 {
				t.Fatalf(
					"duplicate algorithm metadata was trusted: %#v",
					assets[0].SafeMetadata(),
				)
			}
		})
	}
}

func TestExtractBiometricAssetsRejectsDuplicatedCapabilityQueryValues(t *testing.T) {
	tests := []struct {
		name   string
		values url.Values
	}{
		{
			name: "same query key with identical values",
			values: url.Values{
				"FingerAlgorithmVersion": {"10.0", "10.0"},
			},
		},
		{
			name: "case-variant query keys with conflicting values",
			values: url.Values{
				"FingerAlgorithmVersion": {"10.0"},
				"fingeralgorithmversion": {"11.0"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assets, err := ExtractBiometricAssets(
				"FINGERTMP",
				[]byte("PIN=14\tFID=3\tTMP=QUJDRA=="),
				DeviceProtocolState{Capabilities: capabilitiesFromQuery(tt.values)},
			)
			if err != nil {
				t.Fatal(err)
			}
			defer zeroBytes(assets[0].Bytes)
			if assets[0].AlgorithmFamily != "unknown" ||
				assets[0].AlgorithmMajor != -1 ||
				assets[0].AlgorithmMinor != -1 {
				t.Fatalf(
					"duplicated capability was trusted: %#v",
					assets[0].SafeMetadata(),
				)
			}
		})
	}
}

func TestExtractBiometricAssetsRejectsOversizeDecodedAsset(t *testing.T) {
	tests := []struct {
		name  string
		table string
		row   string
		limit int
	}{
		{
			name:  "fingerprint",
			table: "FINGERTMP",
			row:   "PIN=14\tFID=3\tTMP=",
			limit: 64 * 1024,
		},
		{
			name:  "face template",
			table: "BIODATA",
			row:   "Pin=14\tNo=0\tType=9\tTmp=",
			limit: 1024 * 1024,
		},
		{
			name:  "face comparison photo",
			table: "BIOPHOTO",
			row:   "PIN=14\tNo=0\tType=9\tPhoto=",
			limit: 5 * 1024 * 1024,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, tt.limit+1))
			_, err := ExtractBiometricAssets(tt.table, []byte(tt.row+encoded), DeviceProtocolState{})
			if err == nil || !strings.Contains(err.Error(), "too large") {
				t.Fatalf("error = %v; want decoded-size rejection", err)
			}
		})
	}
}

func TestUploadBiometricAssetSendsAuthenticatedBinaryAndZeroesBytes(t *testing.T) {
	type capture struct {
		body          []byte
		headers       http.Header
		contentLength int64
	}
	captured := make(chan capture, 1)
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read capture body: %v", err)
		}
		captured <- capture{body: body, headers: r.Header.Clone(), contentLength: r.ContentLength}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"ok":true,"vaultAssetId":"asset-1"}`))
	}))
	defer cloud.Close()

	raw := []byte("ABCD")
	agent := &Agent{config: Config{PlamatixURL: cloud.URL, APIKey: "agent-secret"}}
	err := agent.UploadBiometricAsset(context.Background(), CapturedBiometricAsset{
		DeviceSN:         "TA1",
		PIN:              "14",
		BioType:          1,
		SlotIndex:        3,
		AssetKind:        "fingerprint_template",
		AlgorithmFamily:  "zkfinger-v10",
		AlgorithmMajor:   10,
		AlgorithmMinor:   0,
		AssetFormat:      "templatev10",
		CaptureCommandID: "11111111-1111-4111-8111-111111111111",
		Bytes:            raw,
	})
	if err != nil {
		t.Fatal(err)
	}

	got := <-captured
	if !bytes.Equal(got.body, []byte("ABCD")) {
		t.Fatalf("capture body size = %d; want 4", len(got.body))
	}
	for _, value := range raw {
		if value != 0 {
			t.Fatal("decoded bytes were not zeroed after upload")
		}
	}
	wantHeaders := map[string]string{
		"Content-Type":         "application/octet-stream",
		"X-API-Key":            "agent-secret",
		"Cache-Control":        "no-store",
		"X-Device-SN":          "TA1",
		"X-Personnel-ID":       "14",
		"X-Biometric-Type":     "1",
		"X-Slot-Index":         "3",
		"X-Asset-Kind":         "fingerprint_template",
		"X-Algorithm-Family":   "zkfinger-v10",
		"X-Algorithm-Major":    "10",
		"X-Algorithm-Minor":    "0",
		"X-Asset-Format":       "templatev10",
		"X-Capture-Command-ID": "11111111-1111-4111-8111-111111111111",
	}
	for name, want := range wantHeaders {
		if got.headers.Get(name) != want {
			t.Errorf("%s = %q; want %q", name, got.headers.Get(name), want)
		}
	}
	if got.contentLength != 4 || got.headers.Get("Content-Length") != strconv.Itoa(4) {
		t.Errorf("content length = %d / %q; want 4", got.contentLength, got.headers.Get("Content-Length"))
	}
}

func TestUploadBiometricAssetRedactsCloudFailureAndDoesNotClaimPersistence(t *testing.T) {
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"failed","detail":"TMP=QUJDRA=="}`))
	}))
	defer cloud.Close()

	raw := []byte("ABCD")
	agent := &Agent{config: Config{PlamatixURL: cloud.URL}}
	err := agent.UploadBiometricAsset(context.Background(), CapturedBiometricAsset{
		DeviceSN:        "TA1",
		PIN:             "14",
		BioType:         1,
		SlotIndex:       3,
		AssetKind:       "fingerprint_template",
		AlgorithmFamily: "zkfinger-v10",
		AlgorithmMajor:  10,
		AlgorithmMinor:  0,
		AssetFormat:     "templatev10",
		Bytes:           raw,
	})
	if err == nil {
		t.Fatal("expected vault persistence error")
	}
	if strings.Contains(err.Error(), "QUJDRA") || strings.Contains(err.Error(), "ABCD") {
		t.Fatalf("upload error leaked biometric material: %s", err)
	}
	if strings.Contains(strings.ToLower(err.Error()), "persisted") ||
		strings.Contains(strings.ToLower(err.Error()), "stored") {
		t.Fatalf("upload error incorrectly claimed persistence: %s", err)
	}
	for _, value := range raw {
		if value != 0 {
			t.Fatal("decoded bytes were not zeroed after failed upload")
		}
	}
}

func TestUploadBiometricAssetNeverReturnsArbitraryResponseBody(t *testing.T) {
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal detail must not escape"}`))
	}))
	defer cloud.Close()

	raw := []byte("ABCD")
	agent := &Agent{config: Config{PlamatixURL: cloud.URL}}
	err := agent.UploadBiometricAsset(context.Background(), CapturedBiometricAsset{
		DeviceSN:        "TA1",
		PIN:             "14",
		BioType:         1,
		SlotIndex:       3,
		AssetKind:       "fingerprint_template",
		AlgorithmFamily: "zkfinger-v10",
		AlgorithmMajor:  10,
		AlgorithmMinor:  0,
		AssetFormat:     "templatev10",
		Bytes:           raw,
	})
	if err == nil {
		t.Fatal("expected vault persistence error")
	}
	if strings.Contains(err.Error(), "internal detail") {
		t.Fatalf("upload error returned arbitrary response body: %s", err)
	}
}
