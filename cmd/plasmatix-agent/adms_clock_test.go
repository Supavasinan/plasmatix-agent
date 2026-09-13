package main

import (
	"strings"
	"testing"
	"time"
)

func TestEncodeZKDateTimeKnownValue(t *testing.T) {
	// Worked by hand against ZKTeco's fixed 31-day-month encoding:
	//   days  = (2026-2000)*12*31 + (8-1)*31 + (28-1) = 9672 + 217 + 27 = 9916
	//   value = 9916*86400 + 18*3600 + 45*60 = 856742400 + 64800 + 2700
	const want int64 = 856809900
	got := encodeZKDateTime(time.Date(2026, 8, 28, 18, 45, 0, 0, time.UTC))
	if got != want {
		t.Fatalf("encodeZKDateTime = %d, want %d", got, want)
	}
}

func TestZKDateTimeRoundTrips(t *testing.T) {
	for _, moment := range []time.Time{
		time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 8, 28, 18, 45, 13, 0, time.UTC),
		time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
		time.Date(2031, 2, 28, 6, 7, 8, 0, time.UTC),
	} {
		got := decodeZKDateTime(encodeZKDateTime(moment), time.UTC)
		if !got.Equal(moment) {
			t.Errorf("round trip of %s produced %s", moment, got)
		}
	}
}

func TestClockSyncCommandUsesDeviceTimeZone(t *testing.T) {
	// 11:45 UTC is 18:45 at UTC+7. Sending UTC here would set every scanner
	// seven hours slow and silently misdate every punch it records.
	instant := time.Date(2026, 8, 28, 11, 45, 0, 0, time.UTC)

	command := deviceClockSyncCommand(instant, 7)
	if !strings.HasPrefix(command, "SET OPTIONS DateTime=") {
		t.Fatalf("unexpected command %q", command)
	}

	want := encodeZKDateTime(time.Date(2026, 8, 28, 18, 45, 0, 0, time.UTC))
	if got := deviceClockSyncCommand(instant, 7); !strings.HasSuffix(got, itoa(want)) {
		t.Errorf("command %q does not encode 18:45 local (%d)", got, want)
	}

	// A different offset must produce a different instant.
	if deviceClockSyncCommand(instant, 0) == command {
		t.Error("UTC+0 and UTC+7 produced the same clock command")
	}
}

func TestSyncDeviceClocksQueuesPerDevice(t *testing.T) {
	tracker := newDeviceTracker()
	tracker.noteContact("SN-A", "10.0.0.1:5000")
	tracker.noteContact("SN-B", "10.0.0.2:5000")

	agent := &Agent{
		config:  Config{DeviceTimeZone: 7},
		devices: tracker,
	}
	agent.adms = &ADMSServer{
		agent:      agent,
		cmdQueue:   map[string][]ADMSCommand{},
		cloudCmdID: map[string]struct{}{},
		pendingCmd: map[pendingCommandKey]ADMSCommand{},
	}

	agent.syncDeviceClocks(time.Date(2026, 8, 28, 11, 45, 0, 0, time.UTC))

	for _, sn := range []string{"SN-A", "SN-B"} {
		queue := agent.adms.cmdQueue[sn]
		if len(queue) != 1 {
			t.Fatalf("SN=%s queued %d commands, want 1", sn, len(queue))
		}
		if !strings.HasPrefix(queue[0].Command, "SET OPTIONS DateTime=") {
			t.Errorf("SN=%s queued %q", sn, queue[0].Command)
		}
	}
}

func itoa(v int64) string {
	digits := ""
	if v == 0 {
		return "0"
	}
	for v > 0 {
		digits = string(rune('0'+v%10)) + digits
		v /= 10
	}
	return digits
}

func TestClockCommandSurvivesTAPushRendering(t *testing.T) {
	// ta_push rewrites some biometric commands. A clock-set must reach the
	// device verbatim on every profile, or standalone timekeeping silently
	// stops working on exactly the hardware this was built for.
	command := deviceClockSyncCommand(time.Now(), 7)

	for _, state := range []DeviceProtocolState{
		{Profile: ProtocolTAPush, Confidence: 90},
		{Profile: ProtocolACPush3, Confidence: 95},
		{Profile: ProtocolUnknown, Confidence: 0},
	} {
		decision := RenderDeviceCommand(state, command)
		if decision.Action == CommandRefused {
			t.Errorf("profile %s refused the clock command: %s",
				state.Profile, decision.Reason)
		}
		if decision.Rendered != command {
			t.Errorf("profile %s rewrote the clock command to %q",
				state.Profile, decision.Rendered)
		}
	}
}
