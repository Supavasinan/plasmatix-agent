package main

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// captureLog redirects the standard logger for the duration of a test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	flags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(io.Discard)
		log.SetFlags(flags)
	})
	return &buf
}

// A sustained outage must not fill the 500-entry log ring with one repeated
// line — that evicts the device and heartbeat history needed to diagnose it.
func TestPollOnceLogsARepeatedOutageOnlyOnce(t *testing.T) {
	srv := faultPageServer(t)
	a := &Agent{zkbiotime: newZKBioTimeClientWith(srv.URL, "x", "x", srv.Client())}
	p := a.newZKBioTimePoller()
	p.cursor, p.cursorLoaded = 1196, true

	buf := captureLog(t)
	for i := 0; i < 5; i++ {
		p.pollOnce(context.Background())
	}

	if n := strings.Count(buf.String(), "catch up transactions"); n != 1 {
		t.Fatalf("logged the same failure %d times, want 1:\n%s", n, buf.String())
	}
	if !strings.Contains(buf.String(), "service is down") {
		t.Error("the one line that is logged must still explain the outage")
	}
}

// Recovery is a state change, so it gets its own line with what the outage cost.
func TestPollOnceReportsRecovery(t *testing.T) {
	var healthy atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if healthy.Load() {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"next":null,"data":[]}`)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, biotimeFaultPage)
	}))
	defer srv.Close()

	a := &Agent{zkbiotime: newZKBioTimeClientWith(srv.URL, "x", "x", srv.Client())}
	p := a.newZKBioTimePoller()
	p.cursor, p.cursorLoaded = 1196, true

	buf := captureLog(t)
	p.pollOnce(context.Background())
	p.pollOnce(context.Background())
	healthy.Store(true)
	p.pollOnce(context.Background())

	out := buf.String()
	if !strings.Contains(out, "recovered after 2 failed attempts") {
		t.Fatalf("want a recovery line naming the toll, got:\n%s", out)
	}
}

// A healthy poll loop stays silent; recovery lines only follow a real outage.
func TestPollOnceStaysSilentWhenHealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"next":null,"data":[]}`)
	}))
	defer srv.Close()

	a := &Agent{zkbiotime: newZKBioTimeClientWith(srv.URL, "x", "x", srv.Client())}
	p := a.newZKBioTimePoller()
	p.cursor, p.cursorLoaded = 1196, true

	buf := captureLog(t)
	p.pollOnce(context.Background())
	p.pollOnce(context.Background())

	if buf.Len() != 0 {
		t.Fatalf("healthy polling should log nothing, got:\n%s", buf.String())
	}
}
