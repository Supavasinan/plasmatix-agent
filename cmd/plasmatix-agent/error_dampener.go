package main

import (
	"fmt"
	"time"
)

// errorDampener collapses a run of identical failures into a single log line,
// a periodic reminder, and a recovery line.
//
// The agent's log ring holds 500 entries (see newLogBuffer in main.go), so a
// failure logged once a minute evicts every other event in about eight hours:
// a long outage erases the device, ADMS and heartbeat history you need to
// diagnose it, and leaves the Logs page showing nothing but the same line.
// Dampening keeps that page readable without going silent — an outage still
// reports in on every remind interval, carrying the toll so far.
//
// It is not safe for concurrent use; the poll loop it serves is single-goroutine.
type errorDampener struct {
	remind time.Duration
	now    func() time.Time

	signature string
	count     int
	firstAt   time.Time
	lastLogAt time.Time
}

func newErrorDampener(remind time.Duration) *errorDampener {
	return &errorDampener{remind: remind, now: time.Now}
}

// fail records a failure and returns the line to log, or "" to stay quiet.
// A change of error text is a change of state and is always reported.
func (d *errorDampener) fail(err error) string {
	message := err.Error()
	now := d.now()

	if message != d.signature {
		d.signature = message
		d.count = 1
		d.firstAt = now
		d.lastLogAt = now
		return message
	}

	d.count++
	if now.Sub(d.lastLogAt) < d.remind {
		return ""
	}
	d.lastLogAt = now
	return fmt.Sprintf(
		"still failing — %d attempts over %s: %s",
		d.count, now.Sub(d.firstAt).Round(time.Minute), message,
	)
}

// recovered clears the failure run and returns a line reporting what it cost,
// or "" when nothing was failing.
func (d *errorDampener) recovered() string {
	if d.signature == "" {
		return ""
	}
	count := d.count
	since := d.now().Sub(d.firstAt).Round(time.Second)
	d.signature = ""
	d.count = 0
	return fmt.Sprintf("recovered after %d failed attempts over %s", count, since)
}
