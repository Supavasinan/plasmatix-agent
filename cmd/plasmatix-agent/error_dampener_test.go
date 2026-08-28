package main

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// testClock is a hand-advanced clock so dampening windows are exercised
// without sleeping.
type testClock struct{ t time.Time }

func (c *testClock) now() time.Time          { return c.t }
func (c *testClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestDampener(remind time.Duration) (*errorDampener, *testClock) {
	clock := &testClock{t: time.Date(2026, 8, 19, 9, 0, 0, 0, time.UTC)}
	d := newErrorDampener(remind)
	d.now = clock.now
	return d, clock
}

func TestErrorDampenerLogsTheFirstFailureInFull(t *testing.T) {
	d, _ := newTestDampener(30 * time.Minute)

	got := d.fail(errors.New("boom: service is down"))
	if !strings.Contains(got, "boom: service is down") {
		t.Fatalf("first failure = %q, want the full error text", got)
	}
}

func TestErrorDampenerSuppressesAnIdenticalRepeat(t *testing.T) {
	d, clock := newTestDampener(30 * time.Minute)
	d.fail(errors.New("boom"))

	clock.advance(60 * time.Second)
	if got := d.fail(errors.New("boom")); got != "" {
		t.Fatalf("repeat = %q, want it suppressed", got)
	}
}

// A silent loop is as bad as a noisy one, so a long outage still reports in
// periodically — with the toll so far.
func TestErrorDampenerRemindsAfterTheWindowWithTheToll(t *testing.T) {
	d, clock := newTestDampener(30 * time.Minute)
	d.fail(errors.New("boom"))
	for i := 0; i < 29; i++ {
		clock.advance(60 * time.Second)
		d.fail(errors.New("boom"))
	}

	clock.advance(60 * time.Second)
	got := d.fail(errors.New("boom"))
	if got == "" {
		t.Fatal("want a reminder once the window has elapsed")
	}
	if !strings.Contains(got, "31") {
		t.Errorf("reminder = %q, want the attempt count (31)", got)
	}
	if !strings.Contains(got, "30m") {
		t.Errorf("reminder = %q, want how long it has been failing", got)
	}
}

// A change of error is a change of state: it always gets logged.
func TestErrorDampenerLogsADifferentErrorImmediately(t *testing.T) {
	d, clock := newTestDampener(30 * time.Minute)
	d.fail(errors.New("boom"))

	clock.advance(60 * time.Second)
	got := d.fail(errors.New("a different failure"))
	if !strings.Contains(got, "a different failure") {
		t.Fatalf("changed error = %q, want it logged immediately", got)
	}
}

func TestErrorDampenerReportsRecoveryWithTheToll(t *testing.T) {
	d, clock := newTestDampener(30 * time.Minute)
	d.fail(errors.New("boom"))
	clock.advance(5 * time.Minute)
	d.fail(errors.New("boom"))

	got := d.recovered()
	if got == "" {
		t.Fatal("want a recovery line after a run of failures")
	}
	if !strings.Contains(got, "2") || !strings.Contains(got, "5m") {
		t.Errorf("recovery = %q, want the attempt count and duration", got)
	}
}

func TestErrorDampenerStaysQuietWhenNothingWasFailing(t *testing.T) {
	d, _ := newTestDampener(30 * time.Minute)

	if got := d.recovered(); got != "" {
		t.Fatalf("recovered() = %q, want silence when there was no outage", got)
	}
}

// After a recovery the next failure is a fresh outage, not a suppressed repeat.
func TestErrorDampenerLogsInFullAgainAfterRecovery(t *testing.T) {
	d, clock := newTestDampener(30 * time.Minute)
	d.fail(errors.New("boom"))
	d.recovered()

	clock.advance(60 * time.Second)
	if got := d.fail(errors.New("boom")); !strings.Contains(got, "boom") {
		t.Fatalf("post-recovery failure = %q, want it logged in full", got)
	}
}
