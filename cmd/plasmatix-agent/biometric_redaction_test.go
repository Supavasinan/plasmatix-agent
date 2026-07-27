package main

import (
	"net/url"
	"strings"
	"testing"
)

func TestBiometricRedactionRemovesTemplateAndPhotoFieldsCaseInsensitively(t *testing.T) {
	input := strings.Join([]string{
		"PIN=14\tTMP=QUJDRA==\tValid=1",
		"Pin=15\tTemplate=RUZHSA==",
		`{"photoBase64":"SUpLTA==","note":"safe"}`,
		"BIOPHOTO=TU5PUA==",
		"photo_base64=UVJTVA==",
	}, "\n")

	got := RedactBiometricText(input)

	for _, secret := range []string{"QUJDRA==", "RUZHSA==", "SUpLTA==", "TU5PUA==", "UVJTVA=="} {
		if strings.Contains(got, secret) {
			t.Fatalf("redacted text retained biometric value %q", secret)
		}
	}
	if strings.Count(got, "[REDACTED:4]") != 5 {
		t.Fatalf("redacted text = %q; want five decoded byte counts", got)
	}
	if !strings.Contains(got, "PIN=14") || !strings.Contains(got, `"note":"safe"`) {
		t.Fatalf("redaction removed safe context: %q", got)
	}
}

func TestBiometricRedactionDoesNotEchoInvalidEncodedValue(t *testing.T) {
	got := RedactBiometricText("Template=not-!base64\tstatus=failed")
	if strings.Contains(got, "not-!base64") {
		t.Fatal("redaction retained invalid template value")
	}
	if !strings.Contains(got, "[REDACTED:11]") {
		t.Fatalf("redaction = %q; want raw byte count for invalid encoding", got)
	}
}

func TestBiometricRedactionConsumesSpaceSplitBase64Suffix(t *testing.T) {
	values, err := url.ParseQuery("CMD=DATA+UPDATE+FINGERTMP%09TMP%3DQUJD+RA%3D%3D%09Valid%3D1")
	if err != nil {
		t.Fatal(err)
	}

	got := RedactBiometricText(values.Get("CMD"))

	if strings.Contains(got, "QUJD") || strings.Contains(got, "RA==") {
		t.Fatal("redaction retained a space-split biometric suffix")
	}
	if !strings.Contains(got, "\tValid=1") {
		t.Fatalf("redaction removed the next delimited field: %q", got)
	}
}

func TestBiometricRedactionFailsClosedForMalformedAndNonStringJSON(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "unterminated string",
			input: `{"template":"QUJDRA==`,
		},
		{
			name:  "escaped quote",
			input: `{"template":"QUJ\"DRA==","note":"safe"}`,
		},
		{
			name:  "non-string biometric field",
			input: `{"template":{"raw":"QUJDRA=="}}`,
		},
		{
			name:  "malformed object",
			input: `{"template":"QUJDRA==","broken":}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RedactBiometricText(tt.input)
			for _, secret := range []string{"QUJDRA==", `QUJ\"DRA==`, "DRA=="} {
				if strings.Contains(got, secret) {
					t.Fatalf("redacted text retained biometric material: %q", got)
				}
			}
		})
	}
}
