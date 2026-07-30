package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type MigrationDispositionTotals struct {
	Source               int `json:"source"`
	Imported             int `json:"imported"`
	AlreadyPresent       int `json:"alreadyPresent"`
	IntentionallySkipped int `json:"intentionallySkipped"`
	Quarantined          int `json:"quarantined"`
	Failed               int `json:"failed"`
}

func ValidateMigrationDispositionTotals(totals MigrationDispositionTotals) error {
	values := []int{
		totals.Source,
		totals.Imported,
		totals.AlreadyPresent,
		totals.IntentionallySkipped,
		totals.Quarantined,
		totals.Failed,
	}
	for _, value := range values {
		if value < 0 {
			return fmt.Errorf("migration disposition totals cannot be negative")
		}
	}
	disposed := totals.Imported +
		totals.AlreadyPresent +
		totals.IntentionallySkipped +
		totals.Quarantined +
		totals.Failed
	if totals.Source != disposed {
		return fmt.Errorf(
			"unbalanced migration manifest: source=%d dispositions=%d",
			totals.Source,
			disposed,
		)
	}
	return nil
}

func HashMigrationRecord(record map[string]any) (string, error) {
	normalized, err := normalizeMigrationValue(record)
	if err != nil {
		return "", err
	}
	canonical, err := json.Marshal(normalized)
	if err != nil {
		return "", fmt.Errorf("canonicalize migration record: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func normalizeMigrationValue(value any) (any, error) {
	switch typed := value.(type) {
	case map[string]any:
		normalized := make(map[string]any, len(typed))
		for key, child := range typed {
			if isSensitiveMigrationField(key) {
				return nil, fmt.Errorf("migration record contains prohibited field %q", key)
			}
			next, err := normalizeMigrationValue(child)
			if err != nil {
				return nil, err
			}
			normalized[key] = next
		}
		return normalized, nil
	case []any:
		normalized := make([]any, len(typed))
		for index, child := range typed {
			next, err := normalizeMigrationValue(child)
			if err != nil {
				return nil, err
			}
			normalized[index] = next
		}
		return normalized, nil
	case time.Time:
		location, err := time.LoadLocation("Asia/Bangkok")
		if err != nil {
			return nil, fmt.Errorf("load Bangkok timezone: %w", err)
		}
		return typed.In(location).Format(time.RFC3339Nano), nil
	default:
		return value, nil
	}
}

func isSensitiveMigrationField(key string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(key), "_", ""))
	switch normalized {
	case "password", "passwd", "secret", "token", "apikey", "tmp",
		"template", "templateblob", "biometricblob", "photobase64":
		return true
	default:
		return false
	}
}
