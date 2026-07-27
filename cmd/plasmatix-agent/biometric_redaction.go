package main

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

var (
	biometricEqualsField = regexp.MustCompile(
		`(?i)\b(?:tmp|template|photo|photo[_-]?base64|base64[_-]?photo|biophoto)=([^\t\r\n&]+)`,
	)
)

func RedactBiometricText(value string) string {
	lines := strings.Split(value, "\n")
	for index, line := range lines {
		lines[index] = redactBiometricLine(line)
	}
	return strings.Join(lines, "\n")
}

func redactBiometricLine(value string) string {
	trimmed := strings.TrimSpace(value)
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		var decoded any
		if json.Unmarshal([]byte(trimmed), &decoded) != nil {
			return "[REDACTED:MALFORMED_JSON]"
		}
		redactBiometricJSONValue(decoded)
		redacted, err := json.Marshal(decoded)
		if err != nil {
			return "[REDACTED:JSON]"
		}
		return string(redacted)
	}
	return biometricEqualsField.ReplaceAllStringFunc(value, redactEqualsBiometricField)
}

func redactEqualsBiometricField(field string) string {
	key, encoded, ok := strings.Cut(field, "=")
	if !ok {
		return field
	}
	return key + "=" + redactedBiometricValue(encoded)
}

func redactBiometricJSONValue(value any) {
	switch typed := value.(type) {
	case map[string]any:
		for key, fieldValue := range typed {
			if isBiometricFieldName(key) {
				if encoded, ok := fieldValue.(string); ok {
					typed[key] = redactedBiometricValue(encoded)
				} else {
					typed[key] = "[REDACTED]"
				}
				continue
			}
			redactBiometricJSONValue(fieldValue)
		}
	case []any:
		for _, item := range typed {
			redactBiometricJSONValue(item)
		}
	}
}

func isBiometricFieldName(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "tmp", "template", "photo", "photobase64", "photo_base64",
		"photo-base64", "base64photo", "base64_photo", "base64-photo", "biophoto":
		return true
	default:
		return false
	}
}

func redactedBiometricValue(encoded string) string {
	byteCount := len(encoded)
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		decoded, err := encoding.DecodeString(encoded)
		decodedCount := len(decoded)
		zeroBytes(decoded)
		if err == nil {
			byteCount = decodedCount
			break
		}
	}
	return "[REDACTED:" + strconv.Itoa(byteCount) + "]"
}
