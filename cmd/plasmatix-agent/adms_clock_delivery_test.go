package main

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func newClockTestServer(t *testing.T, timeZone int) (*Agent, func()) {
	t.Helper()
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"commands":[]}`))
	}))
	tracker := newDeviceTracker()
	tracker.noteContact("SN-CLOCK", "10.0.0.9:5000")
	agent := &Agent{
		config:  Config{PlamatixURL: cloud.URL, DeviceTimeZone: timeZone},
		devices: tracker,
	}
	agent.adms = &ADMSServer{
		agent:        agent,
		cmdQueue:     map[string][]ADMSCommand{},
		pendingCmd:   map[pendingCommandKey]ADMSCommand{},
		cloudCmdID:   map[string]struct{}{},
		queryBuffers: map[string][]byte{},
	}
	return agent, cloud.Close
}

// ZKBioTime queues "SET OPTIONS DateTime=%s" with the value unfilled
// (core/zkcmdproc.pyc, SyncACTime) and supplies the time when the device
// collects the command. Computing it at queue time instead meant a scanner that
// was offline across a tick — rebooting, or on a network blip — collected a
// time up to an hour stale, and ran that far slow until the next tick.
func TestClockTimeIsFilledInWhenTheDeviceCollectsIt(t *testing.T) {
	agent, closeCloud := newClockTestServer(t, 7)
	defer closeCloud()

	// Queued "a week ago": the device was offline when the tick fired.
	agent.syncDeviceClocks(time.Now().Add(-7 * 24 * time.Hour))

	request := httptest.NewRequest(http.MethodGet, "/iclock/getrequest?SN=SN-CLOCK", nil)
	recorder := httptest.NewRecorder()
	agent.adms.handleGetRequest(recorder, request)
	collectedAt := time.Now()

	body := recorder.Body.String()
	if strings.Contains(body, "%s") {
		t.Fatalf("device received the unfilled template: %q", body)
	}
	_, raw, found := strings.Cut(body, "SET OPTIONS DateTime=")
	if !found {
		t.Fatalf("no clock command delivered: %q", body)
	}
	value, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		t.Fatalf("clock value %q is not an integer: %v", raw, err)
	}

	zone := deviceLocation(7)
	delivered := decodeZKDateTime(value, zone)
	want := collectedAt.In(zone)
	if drift := want.Sub(delivered); drift < -2*time.Second || drift > 2*time.Second {
		t.Fatalf("device set to %s, want ~%s (drift %s)",
			delivered.Format(time.RFC3339), want.Format(time.RFC3339), drift)
	}
}

// ZKBioTime also skips queueing when a clock command is already pending for
// the terminal. Without that, a scanner offline for five hours collected five
// clock-sets on return, each rewinding it, ahead of any real command.
func TestClockSyncIsNotQueuedWhileOneIsPending(t *testing.T) {
	agent, closeCloud := newClockTestServer(t, 7)
	defer closeCloud()

	start := time.Date(2026, 9, 13, 1, 0, 0, 0, time.UTC)
	for hour := 0; hour < 5; hour++ {
		agent.syncDeviceClocks(start.Add(time.Duration(hour) * time.Hour))
	}

	clockCommands := 0
	for _, cmd := range agent.adms.cmdQueue["SN-CLOCK"] {
		if strings.HasPrefix(cmd.Command, "SET OPTIONS DateTime=") {
			clockCommands++
		}
	}
	if clockCommands != 1 {
		t.Fatalf("queued %d clock commands for one offline device, want 1", clockCommands)
	}
}

// Once collected, the next tick must queue again — the dedup is about pending
// commands, not about syncing only once.
func TestClockSyncQueuesAgainAfterDelivery(t *testing.T) {
	agent, closeCloud := newClockTestServer(t, 7)
	defer closeCloud()

	agent.syncDeviceClocks(time.Now())
	recorder := httptest.NewRecorder()
	agent.adms.handleGetRequest(recorder,
		httptest.NewRequest(http.MethodGet, "/iclock/getrequest?SN=SN-CLOCK", nil))
	if !strings.Contains(recorder.Body.String(), "SET OPTIONS DateTime=") {
		t.Fatalf("first clock command not delivered: %q", recorder.Body.String())
	}

	agent.syncDeviceClocks(time.Now())
	if n := len(agent.adms.cmdQueue["SN-CLOCK"]); n != 1 {
		t.Fatalf("after delivery the next tick queued %d commands, want 1", n)
	}
}

// Other commands queued behind a pending clock-set must still go out in order.
func TestClockDedupDoesNotSwallowOtherCommands(t *testing.T) {
	agent, closeCloud := newClockTestServer(t, 7)
	defer closeCloud()

	agent.syncDeviceClocks(time.Now())
	agent.adms.enqueueCommand("SN-CLOCK", "REBOOT")
	agent.syncDeviceClocks(time.Now())

	queue := agent.adms.cmdQueue["SN-CLOCK"]
	if len(queue) != 2 || queue[1].Command != "REBOOT" {
		got := make([]string, 0, len(queue))
		for _, c := range queue {
			got = append(got, c.Command)
		}
		t.Fatalf("queue = %q, want [clock, REBOOT]", got)
	}
}
