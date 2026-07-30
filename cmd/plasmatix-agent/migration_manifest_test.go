package main

import (
	"testing"
)

func TestMigrationManifestCanonicalHashIgnoresMapOrder(t *testing.T) {
	first, err := HashMigrationRecord(map[string]any{
		"pin": "14",
		"name": map[string]any{
			"first": "Ada",
			"last":  "Lovelace",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := HashMigrationRecord(map[string]any{
		"name": map[string]any{
			"last":  "Lovelace",
			"first": "Ada",
		},
		"pin": "14",
	})
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("hashes differ: %s != %s", first, second)
	}
}

func TestMigrationManifestRejectsUnbalancedDispositions(t *testing.T) {
	err := ValidateMigrationDispositionTotals(MigrationDispositionTotals{
		Source:               10,
		Imported:             6,
		AlreadyPresent:       1,
		IntentionallySkipped: 1,
		Quarantined:          1,
		Failed:               0,
	})
	if err == nil {
		t.Fatal("unbalanced dispositions were accepted")
	}
}

func TestMigrationManifestAcceptsBalancedDispositions(t *testing.T) {
	err := ValidateMigrationDispositionTotals(MigrationDispositionTotals{
		Source:               10,
		Imported:             6,
		AlreadyPresent:       1,
		IntentionallySkipped: 1,
		Quarantined:          1,
		Failed:               1,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestMigrationManifestRejectsSecretAndTemplateFields(t *testing.T) {
	for _, record := range []map[string]any{
		{"pin": "14", "password": "secret"},
		{"pin": "14", "TMP": "template-bytes"},
	} {
		if _, err := HashMigrationRecord(record); err == nil {
			t.Fatalf("sensitive record accepted: %#v", record)
		}
	}
}
