package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	maxFingerprintTemplateBytes  = 64 * 1024
	maxFaceTemplateBytes         = 1024 * 1024
	maxFacePhotoBytes            = 5 * 1024 * 1024
	maxBiometricAssetsPerRequest = 64
	maxBiometricAlgorithmVersion = 255
	maxBiometricIdentifierLength = 64
)

var ErrBiometricVaultDisabled = errors.New("biometric vault disabled")

const invalidBiometricMetadata = "[invalid]"

type CapturedBiometricAsset struct {
	DeviceSN         string `json:"deviceSn"`
	PIN              string `json:"pin"`
	BioType          int    `json:"bioType"`
	SlotIndex        int    `json:"slotIndex"`
	AssetKind        string `json:"assetKind"`
	AlgorithmFamily  string `json:"algorithmFamily"`
	AlgorithmMajor   int    `json:"algorithmMajor"`
	AlgorithmMinor   int    `json:"algorithmMinor"`
	AssetFormat      string `json:"assetFormat"`
	CaptureCommandID string `json:"captureCommandId,omitempty"`
	Bytes            []byte `json:"-"`
}

type BiometricSafeMetadata struct {
	DeviceSN        string `json:"deviceSn"`
	PIN             string `json:"pin"`
	BioType         int    `json:"bioType"`
	SlotIndex       int    `json:"slotIndex"`
	AssetKind       string `json:"assetKind"`
	AlgorithmFamily string `json:"algorithmFamily"`
	AlgorithmMajor  int    `json:"algorithmMajor"`
	AlgorithmMinor  int    `json:"algorithmMinor"`
	AssetFormat     string `json:"assetFormat"`
	ByteCount       int    `json:"byteCount"`
	SHA256          string `json:"sha256"`
}

type biometricFields struct {
	values      map[string]string
	occurrences map[string][]string
}

func (asset CapturedBiometricAsset) SafeMetadata() BiometricSafeMetadata {
	sum := sha256.Sum256(asset.Bytes)
	deviceSN, validDeviceSN := canonicalBiometricIdentifier(asset.DeviceSN)
	if !validDeviceSN {
		deviceSN = invalidBiometricMetadata
	}
	pin, validPIN := canonicalBiometricIdentifier(asset.PIN)
	if !validPIN {
		pin = invalidBiometricMetadata
	}
	bioType, slot := asset.BioType, asset.SlotIndex
	if bioType != 1 && bioType != 9 {
		bioType = -1
	}
	if slot < 0 || slot > 9 {
		slot = -1
	}
	kind, family, major, minor, format := safeBiometricProfile(asset)
	return BiometricSafeMetadata{
		DeviceSN:        deviceSN,
		PIN:             pin,
		BioType:         bioType,
		SlotIndex:       slot,
		AssetKind:       kind,
		AlgorithmFamily: family,
		AlgorithmMajor:  major,
		AlgorithmMinor:  minor,
		AssetFormat:     format,
		ByteCount:       len(asset.Bytes),
		SHA256:          hex.EncodeToString(sum[:]),
	}
}

func ExtractBiometricAssets(
	table string,
	body []byte,
	state DeviceProtocolState,
) ([]CapturedBiometricAsset, error) {
	table = strings.ToUpper(strings.TrimSpace(table))
	switch table {
	case "FINGERTMP", "BIODATA", "BIOPHOTO":
	default:
		return nil, fmt.Errorf("unsupported biometric table %q", table)
	}

	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) > maxBiometricAssetsPerRequest {
		return nil, fmt.Errorf(
			"too many biometric assets (maximum %d)",
			maxBiometricAssetsPerRequest,
		)
	}
	assets := make([]CapturedBiometricAsset, 0, len(lines))
	for rowIndex, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := parseBiometricFields(line)
		asset, include, err := extractBiometricAsset(table, fields, state)
		if err != nil {
			for index := range assets {
				zeroBytes(assets[index].Bytes)
			}
			return nil, fmt.Errorf("biometric row %d: %w", rowIndex+1, err)
		}
		if include {
			assets = append(assets, asset)
		}
	}
	return assets, nil
}

func extractBiometricAsset(
	table string,
	fields biometricFields,
	state DeviceProtocolState,
) (CapturedBiometricAsset, bool, error) {
	pin, pinPresent, pinUnique := uniqueBiometricField(fields, "pin", "userid", "uid")
	if !pinPresent || pin == "" {
		return CapturedBiometricAsset{}, false, errors.New("missing biometric PIN")
	}
	if !pinUnique {
		return CapturedBiometricAsset{}, false, errors.New("duplicated biometric PIN")
	}
	var validPIN bool
	pin, validPIN = canonicalBiometricIdentifier(pin)
	if !validPIN {
		return CapturedBiometricAsset{}, false, errors.New("invalid biometric PIN")
	}

	bioType := 9
	slot := 0
	assetKind := "face_comparison_photo"
	encoded := biometricField(
		fields,
		"photo",
		"photobase64",
		"photo_base64",
		"base64photo",
		"base64_photo",
		"biophoto",
		"template",
		"tmp",
	)
	limit := maxFacePhotoBytes
	format := ""
	family := "portable_photo"
	major, minor := 0, 0

	switch table {
	case "FINGERTMP":
		bioType = 1
		var err error
		slot, err = requiredBiometricInt(fields, 0, 9, "fid", "no")
		if err != nil {
			return CapturedBiometricAsset{}, false, err
		}
		assetKind = "fingerprint_template"
		encoded = biometricField(fields, "tmp", "template")
		limit = maxFingerprintTemplateBytes
		family, major, minor = biometricAlgorithm("finger", fields, state)
		format = canonicalBiometricFormat("finger", major)
	case "BIODATA":
		var err error
		bioType, err = requiredBiometricInt(fields, 1, 9, "type")
		if err != nil {
			return CapturedBiometricAsset{}, false, err
		}
		if bioType != 1 && bioType != 9 {
			return CapturedBiometricAsset{}, false, errors.New("unsupported biometric type")
		}
		slot, err = requiredBiometricInt(fields, 0, 9, "no", "index")
		if err != nil {
			return CapturedBiometricAsset{}, false, err
		}
		encoded = biometricField(fields, "tmp", "template")
		if bioType == 1 {
			assetKind = "fingerprint_template"
			limit = maxFingerprintTemplateBytes
			family, major, minor = biometricAlgorithm("finger", fields, state)
			format = canonicalBiometricFormat("finger", major)
		} else {
			assetKind = "face_template"
			limit = maxFaceTemplateBytes
			family, major, minor = biometricAlgorithm("face", fields, state)
			format = canonicalBiometricFormat("face", major)
		}
	case "BIOPHOTO":
		var err error
		slot, err = requiredBiometricInt(fields, 0, 9, "no", "index")
		if err != nil {
			return CapturedBiometricAsset{}, false, err
		}
		if len(fields.occurrences["type"]) > 0 {
			fieldType, typeErr := requiredBiometricInt(fields, 1, 9, "type")
			if typeErr != nil {
				return CapturedBiometricAsset{}, false, typeErr
			}
			if fieldType != 9 {
				return CapturedBiometricAsset{}, false, errors.New("unsupported biometric photo type")
			}
		}
	}

	if encoded == "" {
		return CapturedBiometricAsset{}, false, errors.New("missing biometric payload")
	}
	decoded, err := decodeBoundedBiometric(encoded, limit)
	if err != nil {
		return CapturedBiometricAsset{}, false, err
	}
	if table == "BIOPHOTO" {
		format = detectedPhotoFormat(decoded)
		if format == "" {
			zeroBytes(decoded)
			return CapturedBiometricAsset{}, false, errors.New("unsupported biometric photo format")
		}
	}
	if format == "" {
		format = "unknown"
	}

	return CapturedBiometricAsset{
		PIN:             pin,
		BioType:         bioType,
		SlotIndex:       slot,
		AssetKind:       assetKind,
		AlgorithmFamily: family,
		AlgorithmMajor:  major,
		AlgorithmMinor:  minor,
		AssetFormat:     format,
		Bytes:           decoded,
	}, true, nil
}

func parseBiometricFields(line string) biometricFields {
	fields := biometricFields{
		values:      make(map[string]string),
		occurrences: make(map[string][]string),
	}
	for index, pair := range strings.Split(strings.TrimSpace(line), "\t") {
		key, value, ok := strings.Cut(pair, "=")
		if !ok {
			continue
		}
		if index == 0 {
			if separator := strings.LastIndexAny(key, " "); separator >= 0 {
				key = key[separator+1:]
			}
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		fields.values[key] = value
		fields.occurrences[key] = append(fields.occurrences[key], value)
	}
	return fields
}

func biometricField(fields biometricFields, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(fields.values[strings.ToLower(key)]); value != "" {
			return value
		}
	}
	return ""
}

func requiredBiometricInt(
	fields biometricFields,
	minimum int,
	maximum int,
	keys ...string,
) (int, error) {
	var values []string
	for _, key := range keys {
		values = append(values, fields.occurrences[strings.ToLower(key)]...)
	}
	if len(values) == 0 {
		return 0, errors.New("missing biometric numeric metadata")
	}
	if len(values) != 1 {
		return 0, errors.New("duplicated biometric numeric metadata")
	}
	raw := strings.TrimSpace(values[0])
	if raw == "" {
		return 0, errors.New("missing biometric numeric metadata")
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < minimum || value > maximum {
		return 0, errors.New("invalid biometric numeric metadata")
	}
	return value, nil
}

func biometricAlgorithm(
	modality string,
	fields biometricFields,
	state DeviceProtocolState,
) (string, int, int) {
	major, majorPresent, majorOK := boundedBiometricVersionField(
		fields,
		1,
		"majorver",
		"algorithmmajor",
	)
	minor, minorPresent, minorOK := boundedBiometricVersionField(
		fields,
		0,
		"minorver",
		"algorithmminor",
	)

	capability, capabilityPresent := state.Capabilities[modality+"algorithmversion"]
	capabilityMajor, capabilityMinor, capabilityOK := boundedBiometricAlgorithmVersion(capability)

	if !majorPresent && !minorPresent {
		if !capabilityPresent || !capabilityOK {
			return "unknown", -1, -1
		}
		major, minor = capabilityMajor, capabilityMinor
	} else {
		if !majorPresent || !minorPresent || !majorOK || !minorOK {
			return "unknown", -1, -1
		}
		if capabilityPresent &&
			(!capabilityOK || major != capabilityMajor || minor != capabilityMinor) {
			return "unknown", -1, -1
		}
	}

	return "zk" + modality + "-v" + strconv.Itoa(major), major, minor
}

func uniqueBiometricField(fields biometricFields, keys ...string) (string, bool, bool) {
	var values []string
	for _, key := range keys {
		values = append(values, fields.occurrences[strings.ToLower(key)]...)
	}
	if len(values) == 0 {
		return "", false, false
	}
	return strings.TrimSpace(values[0]), true, len(values) == 1
}

func boundedBiometricVersionField(
	fields biometricFields,
	minimum int,
	keys ...string,
) (int, bool, bool) {
	var values []string
	for _, key := range keys {
		values = append(values, fields.occurrences[strings.ToLower(key)]...)
	}
	if len(values) == 0 {
		return 0, false, false
	}
	// Duplicates fail closed even when byte-for-byte identical. No supported
	// ZKTeco row dialect requires repeated algorithm version fields, so
	// accepting them would only reintroduce map-collapse ambiguity.
	if len(values) != 1 {
		return 0, true, false
	}
	raw := strings.TrimSpace(values[0])
	value, err := strconv.Atoi(raw)
	return value, true, err == nil &&
		value >= minimum &&
		value <= maxBiometricAlgorithmVersion
}

func boundedBiometricAlgorithmVersion(value string) (int, int, bool) {
	major, minor, ok := algorithmVersion(value)
	return major, minor, ok &&
		major <= maxBiometricAlgorithmVersion &&
		minor <= maxBiometricAlgorithmVersion
}

func canonicalBiometricFormat(modality string, major int) string {
	if major < 1 || major > maxBiometricAlgorithmVersion {
		return "unknown"
	}
	switch modality {
	case "finger":
		return "templatev" + strconv.Itoa(major)
	case "face":
		return "facev" + strconv.Itoa(major)
	default:
		return "unknown"
	}
}

func canonicalCapturedAssetFormat(asset CapturedBiometricAsset) string {
	switch asset.AssetKind {
	case "fingerprint_template":
		return canonicalBiometricFormat("finger", asset.AlgorithmMajor)
	case "face_template":
		return canonicalBiometricFormat("face", asset.AlgorithmMajor)
	case "face_comparison_photo":
		switch strings.ToLower(strings.TrimSpace(asset.AssetFormat)) {
		case "jpeg":
			return "jpeg"
		case "png":
			return "png"
		default:
			return "unknown"
		}
	default:
		return "unknown"
	}
}

func canonicalBiometricIdentifier(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxBiometricIdentifierLength {
		return "", false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '.' || character == '_' || character == '-' {
			continue
		}
		return "", false
	}
	return value, true
}

func safeBiometricProfile(asset CapturedBiometricAsset) (string, string, int, int, string) {
	switch asset.AssetKind {
	case "fingerprint_template":
		if asset.BioType != 1 {
			return "unknown", "unknown", -1, -1, "unknown"
		}
		if asset.AlgorithmFamily == "unknown" &&
			asset.AlgorithmMajor == -1 &&
			asset.AlgorithmMinor == -1 {
			return asset.AssetKind, "unknown", -1, -1, "unknown"
		}
		expected := "zkfinger-v" + strconv.Itoa(asset.AlgorithmMajor)
		if asset.AlgorithmMajor >= 1 &&
			asset.AlgorithmMajor <= maxBiometricAlgorithmVersion &&
			asset.AlgorithmMinor >= 0 &&
			asset.AlgorithmMinor <= maxBiometricAlgorithmVersion &&
			asset.AlgorithmFamily == expected {
			return asset.AssetKind, expected, asset.AlgorithmMajor, asset.AlgorithmMinor,
				canonicalBiometricFormat("finger", asset.AlgorithmMajor)
		}
	case "face_template":
		if asset.BioType != 9 {
			return "unknown", "unknown", -1, -1, "unknown"
		}
		if asset.AlgorithmFamily == "unknown" &&
			asset.AlgorithmMajor == -1 &&
			asset.AlgorithmMinor == -1 {
			return asset.AssetKind, "unknown", -1, -1, "unknown"
		}
		expected := "zkface-v" + strconv.Itoa(asset.AlgorithmMajor)
		if asset.AlgorithmMajor >= 1 &&
			asset.AlgorithmMajor <= maxBiometricAlgorithmVersion &&
			asset.AlgorithmMinor >= 0 &&
			asset.AlgorithmMinor <= maxBiometricAlgorithmVersion &&
			asset.AlgorithmFamily == expected {
			return asset.AssetKind, expected, asset.AlgorithmMajor, asset.AlgorithmMinor,
				canonicalBiometricFormat("face", asset.AlgorithmMajor)
		}
	case "face_comparison_photo":
		if asset.BioType == 9 &&
			asset.AlgorithmFamily == "portable_photo" &&
			asset.AlgorithmMajor == 0 &&
			asset.AlgorithmMinor == 0 {
			return asset.AssetKind, "portable_photo", 0, 0,
				canonicalCapturedAssetFormat(asset)
		}
	}
	return "unknown", "unknown", -1, -1, "unknown"
}

func validateBiometricAssetMetadata(asset CapturedBiometricAsset) (CapturedBiometricAsset, error) {
	deviceSN, validDeviceSN := canonicalBiometricIdentifier(asset.DeviceSN)
	pin, validPIN := canonicalBiometricIdentifier(asset.PIN)
	kind, family, major, minor, format := safeBiometricProfile(asset)
	if !validDeviceSN || !validPIN ||
		(asset.BioType != 1 && asset.BioType != 9) ||
		asset.SlotIndex < 0 || asset.SlotIndex > 9 ||
		kind == "unknown" ||
		len(asset.Bytes) == 0 ||
		(asset.CaptureCommandID != "" &&
			!isBiometricCaptureCommandID(asset.CaptureCommandID)) {
		return CapturedBiometricAsset{}, errors.New("invalid biometric upload metadata")
	}
	limit := maxFacePhotoBytes
	switch kind {
	case "fingerprint_template":
		limit = maxFingerprintTemplateBytes
	case "face_template":
		limit = maxFaceTemplateBytes
	}
	if len(asset.Bytes) > limit {
		return CapturedBiometricAsset{}, errors.New("invalid biometric upload metadata")
	}
	asset.DeviceSN = deviceSN
	asset.PIN = pin
	asset.AssetKind = kind
	asset.AlgorithmFamily = family
	asset.AlgorithmMajor = major
	asset.AlgorithmMinor = minor
	asset.AssetFormat = format
	return asset, nil
}

func decodeBoundedBiometric(encoded string, limit int) ([]byte, error) {
	encoded = strings.TrimSpace(encoded)
	maxEncoded := base64.StdEncoding.EncodedLen(limit) + 2
	if len(encoded) > maxEncoded {
		return nil, fmt.Errorf("biometric asset too large (maximum %d bytes)", limit)
	}

	source := []byte(encoded)
	scratch := make([]byte, base64.StdEncoding.DecodedLen(len(source)))
	defer zeroBytes(scratch)
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		decodedCount, err := encoding.Decode(scratch, source)
		if err == nil {
			if decodedCount == 0 {
				return nil, errors.New("empty biometric payload")
			}
			if decodedCount > limit {
				return nil, fmt.Errorf("biometric asset too large (maximum %d bytes)", limit)
			}
			bounded := make([]byte, decodedCount)
			copy(bounded, scratch[:decodedCount])
			return bounded, nil
		}
		zeroBytes(scratch)
	}
	return nil, errors.New("invalid biometric encoding")
}

func detectedPhotoFormat(photo []byte) string {
	switch http.DetectContentType(photo) {
	case "image/jpeg":
		return "jpeg"
	case "image/png":
		return "png"
	default:
		return ""
	}
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func isBiometricCaptureCommandID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if character != '-' {
				return false
			}
			continue
		}
		if !((character >= '0' && character <= '9') ||
			(character >= 'a' && character <= 'f') ||
			(character >= 'A' && character <= 'F')) {
			return false
		}
	}
	return true
}

func (agent *Agent) UploadBiometricAsset(
	ctx context.Context,
	asset CapturedBiometricAsset,
) error {
	defer zeroBytes(asset.Bytes)
	validated, err := validateBiometricAssetMetadata(asset)
	if err != nil {
		return err
	}
	asset = validated

	uploadURL := strings.TrimRight(agent.config.PlamatixURL, "/") +
		"/api/agent-bridge/biometric-vault/capture"
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		uploadURL,
		bytes.NewReader(asset.Bytes),
	)
	if err != nil {
		return fmt.Errorf("create biometric vault request: %w", err)
	}
	request.ContentLength = int64(len(asset.Bytes))
	request.Header.Set("Content-Length", strconv.Itoa(len(asset.Bytes)))
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("Cache-Control", "no-store")
	request.Header.Set("X-API-Key", agent.config.APIKey)
	request.Header.Set("X-Device-SN", asset.DeviceSN)
	request.Header.Set("X-Personnel-ID", asset.PIN)
	request.Header.Set("X-Biometric-Type", strconv.Itoa(asset.BioType))
	request.Header.Set("X-Slot-Index", strconv.Itoa(asset.SlotIndex))
	request.Header.Set("X-Asset-Kind", asset.AssetKind)
	request.Header.Set("X-Algorithm-Family", asset.AlgorithmFamily)
	request.Header.Set("X-Algorithm-Major", strconv.Itoa(asset.AlgorithmMajor))
	request.Header.Set("X-Algorithm-Minor", strconv.Itoa(asset.AlgorithmMinor))
	request.Header.Set("X-Asset-Format", canonicalCapturedAssetFormat(asset))
	request.Header.Set("X-Capture-Command-ID", asset.CaptureCommandID)

	response, err := cloudHTTPClient(30 * time.Second).Do(request)
	if err != nil {
		return fmt.Errorf("biometric vault unavailable: %w", err)
	}
	defer response.Body.Close()

	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, 16*1024))
	if readErr != nil {
		return fmt.Errorf("read biometric vault response: %w", readErr)
	}
	defer zeroBytes(responseBody)
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return nil
	}
	if response.StatusCode == http.StatusNotFound {
		var payload struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(responseBody, &payload) == nil &&
			payload.Error == "biometric_vault_disabled" {
			return ErrBiometricVaultDisabled
		}
	}

	return fmt.Errorf("biometric vault capture failed: HTTP %d", response.StatusCode)
}
