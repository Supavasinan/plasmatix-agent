package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// The exact key set of a production agent.json written by Plasmatix's
// installer: JSON, and no device_timezone. Before this test existed, the JSON
// branch of loadConfig never set DeviceTimeZone, so it arrived as Go's zero
// value — UTC — and the first clock sync after switching to ADMS mode would
// have set a Bangkok scanner seven hours slow.
func TestLoadConfigJSONWithoutTimeZoneDefaultsToSiteZone(t *testing.T) {
	cfg, err := loadConfig(writeConfig(t, `{
		"api_key": "k",
		"plasmatix_url": "https://plasmatix.example",
		"mode": "adms",
		"zkbio_url": "https://zkbiotime.example",
		"zkbio_username": "admin",
		"zkbio_password": "p"
	}`))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.DeviceTimeZone != defaultDeviceTimeZone {
		t.Fatalf("DeviceTimeZone = %d, want %d", cfg.DeviceTimeZone, defaultDeviceTimeZone)
	}

	// And what that means on the wire: 01:00 UTC is 08:00 in Bangkok, so the
	// scanner must be told 08:00, not 01:00.
	instant := time.Date(2026, 9, 13, 1, 0, 0, 0, time.UTC)
	want := deviceClockSyncCommand(instant, 7)
	if got := deviceClockSyncCommand(instant, cfg.DeviceTimeZone); got != want {
		t.Fatalf("clock command = %q, want %q", got, want)
	}
	decoded := decodeZKDateTime(encodeZKDateTime(instant.In(deviceLocation(cfg.DeviceTimeZone))), time.UTC)
	if decoded.Hour() != 8 {
		t.Fatalf("scanner would be set to %02d:00, want 08:00", decoded.Hour())
	}
}

// An explicit zero is a real site at UTC+0 and must not be replaced by the
// default — which is why absence and zero have to be told apart.
func TestLoadConfigJSONHonoursExplicitTimeZones(t *testing.T) {
	for _, tc := range []struct {
		body string
		want int
	}{
		{`{"api_key":"k","plasmatix_url":"https://x","mode":"adms","device_timezone":0}`, 0},
		{`{"api_key":"k","plasmatix_url":"https://x","mode":"adms","device_timezone":8}`, 8},
		{`{"api_key":"k","plasmatix_url":"https://x","mode":"adms","device_timezone":-5}`, -5},
	} {
		cfg, err := loadConfig(writeConfig(t, tc.body))
		if err != nil {
			t.Fatalf("loadConfig(%s): %v", tc.body, err)
		}
		if cfg.DeviceTimeZone != tc.want {
			t.Fatalf("DeviceTimeZone = %d, want %d for %s", cfg.DeviceTimeZone, tc.want, tc.body)
		}
	}
}

func TestLoadConfigJSONRejectsOutOfRangeTimeZone(t *testing.T) {
	if _, err := loadConfig(writeConfig(t,
		`{"api_key":"k","plasmatix_url":"https://x","mode":"adms","device_timezone":15}`,
	)); err == nil {
		t.Fatal("expected an error for device_timezone 15")
	}
}

// stamp_style was readable from the key:value format only.
func TestLoadConfigJSONReadsStampStyle(t *testing.T) {
	cfg, err := loadConfig(writeConfig(t,
		`{"api_key":"k","plasmatix_url":"https://x","mode":"adms","stamp_style":"push3"}`,
	))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.StampStyle != stampStylePush3 {
		t.Fatalf("StampStyle = %q, want %q", cfg.StampStyle, stampStylePush3)
	}
}

// The key:value format already defaulted correctly; keep it that way.
func TestLoadConfigKeyValueWithoutTimeZoneDefaultsToSiteZone(t *testing.T) {
	cfg, err := loadConfig(writeConfig(t,
		"api_key: k\nplasmatix_url: https://x\nmode: adms\n",
	))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.DeviceTimeZone != defaultDeviceTimeZone {
		t.Fatalf("DeviceTimeZone = %d, want %d", cfg.DeviceTimeZone, defaultDeviceTimeZone)
	}
}
