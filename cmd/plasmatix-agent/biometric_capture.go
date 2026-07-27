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
)

var ErrBiometricVaultDisabled = errors.New("biometric vault disabled")

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

func (asset CapturedBiometricAsset) SafeMetadata() BiometricSafeMetadata {
	sum := sha256.Sum256(asset.Bytes)
	return BiometricSafeMetadata{
		DeviceSN:        asset.DeviceSN,
		PIN:             asset.PIN,
		BioType:         asset.BioType,
		SlotIndex:       asset.SlotIndex,
		AssetKind:       asset.AssetKind,
		AlgorithmFamily: asset.AlgorithmFamily,
		AlgorithmMajor:  asset.AlgorithmMajor,
		AlgorithmMinor:  asset.AlgorithmMinor,
		AssetFormat:     asset.AssetFormat,
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
	fields map[string]string,
	state DeviceProtocolState,
) (CapturedBiometricAsset, bool, error) {
	pin := biometricField(fields, "pin", "userid", "uid")
	if pin == "" {
		return CapturedBiometricAsset{}, false, errors.New("missing biometric PIN")
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
		format = biometricField(fields, "format")
		if format == "" && major >= 0 {
			format = "templatev" + strconv.Itoa(major)
		}
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
		format = biometricField(fields, "format")
		if bioType == 1 {
			assetKind = "fingerprint_template"
			limit = maxFingerprintTemplateBytes
			family, major, minor = biometricAlgorithm("finger", fields, state)
		} else {
			assetKind = "face_template"
			limit = maxFaceTemplateBytes
			family, major, minor = biometricAlgorithm("face", fields, state)
		}
		if format == "" && major >= 0 {
			format = "templatev" + strconv.Itoa(major)
		}
	case "BIOPHOTO":
		var err error
		slot, err = requiredBiometricInt(fields, 0, 9, "no", "index")
		if err != nil {
			return CapturedBiometricAsset{}, false, err
		}
		if _, present := fields["type"]; present {
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

func parseBiometricFields(line string) map[string]string {
	fields := make(map[string]string)
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
		fields[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
	}
	return fields
}

func biometricField(fields map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(fields[strings.ToLower(key)]); value != "" {
			return value
		}
	}
	return ""
}

func requiredBiometricInt(
	fields map[string]string,
	minimum int,
	maximum int,
	keys ...string,
) (int, error) {
	var raw string
	var present bool
	for _, key := range keys {
		raw, present = fields[strings.ToLower(key)]
		if present {
			break
		}
	}
	raw = strings.TrimSpace(raw)
	if !present || raw == "" {
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
	fields map[string]string,
	state DeviceProtocolState,
) (string, int, int) {
	major, majorOK := nonNegativeInt(biometricField(fields, "majorver", "algorithmmajor"))
	minor, minorOK := nonNegativeInt(biometricField(fields, "minorver", "algorithmminor"))
	if !majorOK || !minorOK {
		capability := state.Capabilities[modality+"algorithmversion"]
		major, minor, majorOK = algorithmVersion(capability)
		minorOK = majorOK
	}
	if !majorOK || !minorOK {
		return "unknown", -1, -1
	}
	return "zk" + modality + "-v" + strconv.Itoa(major), major, minor
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
	request.Header.Set("X-Device-SN", sanitizeHeaderValue(asset.DeviceSN))
	request.Header.Set("X-Personnel-ID", sanitizeHeaderValue(asset.PIN))
	request.Header.Set("X-Biometric-Type", strconv.Itoa(asset.BioType))
	request.Header.Set("X-Slot-Index", strconv.Itoa(asset.SlotIndex))
	request.Header.Set("X-Asset-Kind", asset.AssetKind)
	request.Header.Set("X-Algorithm-Family", asset.AlgorithmFamily)
	request.Header.Set("X-Algorithm-Major", strconv.Itoa(asset.AlgorithmMajor))
	request.Header.Set("X-Algorithm-Minor", strconv.Itoa(asset.AlgorithmMinor))
	request.Header.Set("X-Asset-Format", asset.AssetFormat)
	request.Header.Set("X-Capture-Command-ID", sanitizeHeaderValue(asset.CaptureCommandID))

	response, err := cloudHTTPClient(30 * time.Second).Do(request)
	if err != nil {
		return fmt.Errorf("biometric vault unavailable: %w", err)
	}
	defer response.Body.Close()

	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, 16*1024))
	if readErr != nil {
		return fmt.Errorf("read biometric vault response: %w", readErr)
	}
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

	detail := strings.TrimSpace(RedactBiometricText(string(responseBody)))
	if detail == "" {
		return fmt.Errorf("biometric vault capture failed: HTTP %d", response.StatusCode)
	}
	return fmt.Errorf("biometric vault capture failed: HTTP %d: %s", response.StatusCode, detail)
}
