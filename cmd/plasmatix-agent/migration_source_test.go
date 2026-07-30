package main

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestMigrationSourcePreflightUsesReadOnlyAllowlistedQuery(t *testing.T) {
	backend := &fakeMigrationBackend{
		rowsByQuery: map[string][]map[string]any{
			migrationQueryPreflight: {{
				"database_name":    "zkbiotime",
				"server_version":   "15.4",
				"employees_table":  true,
				"attendance_table": true,
			}},
		},
	}
	source := NewZKBioTimeMigrationSource(backend, "postgres://user:sentinel@db/zk")

	fingerprint, err := source.Preflight(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !backend.readOnly {
		t.Fatal("query ran without a read-only transaction")
	}
	if len(backend.queryIDs) != 1 || backend.queryIDs[0] != migrationQueryPreflight {
		t.Fatalf("queries = %#v", backend.queryIDs)
	}
	if fingerprint.SHA256 == "" {
		t.Fatal("source fingerprint is empty")
	}
}

func TestMigrationSourceRejectsUnsupportedSchema(t *testing.T) {
	backend := &fakeMigrationBackend{
		rowsByQuery: map[string][]map[string]any{
			migrationQueryPreflight: {{
				"database_name":    "unknown",
				"server_version":   "15.4",
				"employees_table":  false,
				"attendance_table": true,
			}},
		},
	}
	source := NewZKBioTimeMigrationSource(backend, "postgres://db/unknown")

	if _, err := source.Preflight(context.Background()); err == nil {
		t.Fatal("unsupported schema was accepted")
	}
}

func TestMigrationSourceRedactsConnectionSecret(t *testing.T) {
	backend := &fakeMigrationBackend{err: errors.New("dial failed for sentinel-password")}
	source := NewZKBioTimeMigrationSource(
		backend,
		"postgres://user:sentinel-password@db/zkbiotime",
	)

	_, err := source.Inventory(context.Background())
	if err == nil {
		t.Fatal("connection failure was ignored")
	}
	if strings.Contains(err.Error(), "sentinel-password") {
		t.Fatalf("secret leaked in error: %v", err)
	}
}

func TestMigrationSourceFingerprintIsStable(t *testing.T) {
	rows := map[string][]map[string]any{
		migrationQueryPreflight: {{
			"database_name":    "zkbiotime",
			"server_version":   "15.4",
			"employees_table":  true,
			"attendance_table": true,
		}},
	}
	first := NewZKBioTimeMigrationSource(
		&fakeMigrationBackend{rowsByQuery: rows},
		"postgres://db/zkbiotime",
	)
	second := NewZKBioTimeMigrationSource(
		&fakeMigrationBackend{rowsByQuery: rows},
		"postgres://db/zkbiotime",
	)
	firstFingerprint, _ := first.Preflight(context.Background())
	secondFingerprint, _ := second.Preflight(context.Background())
	if firstFingerprint != secondFingerprint {
		t.Fatalf("fingerprints differ: %#v != %#v", firstFingerprint, secondFingerprint)
	}
}

type fakeMigrationBackend struct {
	readOnly    bool
	queryIDs    []string
	rowsByQuery map[string][]map[string]any
	err         error
}

func (f *fakeMigrationBackend) WithReadOnly(
	ctx context.Context,
	run func(MigrationQueryer) error,
) error {
	if f.err != nil {
		return f.err
	}
	f.readOnly = true
	return run(f)
}

func (f *fakeMigrationBackend) QueryRows(
	_ context.Context,
	queryID string,
	_ string,
	_ ...any,
) ([]map[string]any, error) {
	f.queryIDs = append(f.queryIDs, queryID)
	return f.rowsByQuery[queryID], nil
}
