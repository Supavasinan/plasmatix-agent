package main

import (
	"encoding/base64"
	"regexp"
	"strconv"
	"strings"
)

var (
	biometricEqualsField = regexp.MustCompile(
		`(?i)\b(?:tmp|template|photo|photo[_-]?base64|base64[_-]?photo|biophoto)=([^\t\r\n&]+)`,
	)
	biometricJSONField = regexp.MustCompile(
		`(?i)"(?:tmp|template|photo|photo[_-]?base64|base64[_-]?photo|biophoto)"\s*:\s*"([^"]*)"`,
	)
)

func RedactBiometricText(value string) string {
	value = biometricEqualsField.ReplaceAllStringFunc(value, redactEqualsBiometricField)
	return biometricJSONField.ReplaceAllStringFunc(value, redactJSONBiometricField)
}

func redactEqualsBiometricField(field string) string {
	key, encoded, ok := strings.Cut(field, "=")
	if !ok {
		return field
	}
	return key + "=" + redactedBiometricValue(encoded)
}

func redactJSONBiometricField(field string) string {
	colon := strings.IndexByte(field, ':')
	if colon < 0 {
		return field
	}
	prefix := field[:colon+1]
	encoded := strings.TrimSpace(field[colon+1:])
	encoded = strings.Trim(encoded, `"`)
	return prefix + `"` + redactedBiometricValue(encoded) + `"`
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
