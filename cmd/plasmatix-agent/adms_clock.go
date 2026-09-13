package main

import (
	"context"
	"fmt"
	"log"
	"time"
)

// ZKTeco encodes a wall-clock time as a single integer with a fixed 31-day
// month and 12-month year, so the value is NOT a Unix timestamp and the
// arithmetic deliberately allows impossible dates such as 31 February — the
// firmware does the same, and matching it exactly is the point.
//
//	value = ((year-2000)*12*31 + (month-1)*31 + (day-1)) * 86400
//	        + hour*3600 + minute*60 + second
//
// The device applies this against the TimeZone offset from the handshake, so
// the caller must pass the time already expressed in the device's own zone.
func encodeZKDateTime(t time.Time) int64 {
	year, month, day := t.Date()
	hour, minute, second := t.Clock()
	days := int64(year-2000)*12*31 + int64(month-1)*31 + int64(day-1)
	return days*86400 + int64(hour)*3600 + int64(minute)*60 + int64(second)
}

// decodeZKDateTime inverts encodeZKDateTime. It exists so the encoding can be
// round-tripped in tests: a clock command that is wrong by an hour is invisible
// until punches start landing at the wrong time.
func decodeZKDateTime(value int64, loc *time.Location) time.Time {
	days := value / 86400
	remainder := value % 86400
	year := days / (12 * 31)
	month := (days % (12 * 31)) / 31
	day := days % 31
	return time.Date(
		int(year)+2000, time.Month(month+1), int(day+1),
		int(remainder/3600), int((remainder%3600)/60), int(remainder%60),
		0, loc,
	)
}

// deviceClockSyncCommand renders the ADMS command that sets a scanner's clock.
//
// The verb is SET OPTIONS, plural. ZKBioTime's own bytecode uses
// "SET OPTIONS DateTime=%s" in both core/zkcmdproc (SyncACTime) and
// iclock/comm/utils, while reserving the singular "SET OPTION" for other
// device settings. Sending the singular form here is silently ignored by the
// firmware — the command is acked and the clock never moves.
//
// The value is ZKTeco's packed date integer (see encodeZKDateTime). That
// encoding is the long-standing ZK convention but is the one part of this
// command not confirmed from ZKBioTime's bytecode, since the value is computed
// rather than stored as a literal. Verify against a device before relying on
// it unattended: queue one command and read the clock back.
func deviceClockSyncCommand(now time.Time, timeZone int) string {
	local := now.In(deviceLocation(timeZone))
	return fmt.Sprintf("SET OPTIONS DateTime=%d", encodeZKDateTime(local))
}

// deviceLocation builds the fixed-offset zone the scanner runs in. ZKTeco
// devices hold a whole-hour offset with no DST rules, so a fixed zone is the
// accurate model rather than an IANA name.
func deviceLocation(timeZone int) *time.Location {
	return time.FixedZone(fmt.Sprintf("UTC%+d", timeZone), timeZone*3600)
}

// clockSyncInterval is how often each known device is re-synced. ZKTeco
// terminals drift by seconds per day, and attendance rounding makes anything
// under a minute of drift irrelevant, so hourly is ample and keeps the command
// queue quiet.
const clockSyncInterval = time.Hour

// runClockSyncLoop keeps every scanner the agent has heard from on the agent's
// own clock. ZKBioTime owns this today; without it, an agent running standalone
// leaves the device free-running and every punch slowly drifts out of true.
func (a *Agent) runClockSyncLoop(ctx context.Context) {
	ticker := time.NewTicker(clockSyncInterval)
	defer ticker.Stop()

	a.syncDeviceClocks(time.Now())
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			a.syncDeviceClocks(now)
		}
	}
}

// syncDeviceClocks queues a clock-set for each device currently tracked. The
// command is only picked up on that device's next getrequest poll, so a
// scanner that is offline simply receives it when it comes back.
func (a *Agent) syncDeviceClocks(now time.Time) {
	if a.adms == nil || a.devices == nil {
		return
	}
	command := deviceClockSyncCommand(now, a.config.DeviceTimeZone)
	for _, device := range a.devices.snapshot() {
		if device.SN == "" {
			continue
		}
		a.adms.enqueueCommand(device.SN, command)
		log.Printf("[ADMS] Queued clock sync for SN=%s (%s)",
			safeBiometricLogIdentifier(device.SN),
			now.In(deviceLocation(a.config.DeviceTimeZone)).Format(time.RFC3339),
		)
	}
}
