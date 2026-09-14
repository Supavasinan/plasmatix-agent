package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestADMSLimitsKnownAndChunkedBodies(t *testing.T) {
	var called bool
	server := newADMSHTTPServer(":0", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		read, err := io.Copy(io.Discard, r.Body)
		if err == nil || read > maxADMSRequestBodyBytes {
			t.Error("chunked body was not bounded")
		}
	}))
	if server.ReadHeaderTimeout == 0 || server.ReadTimeout == 0 || server.IdleTimeout == 0 {
		t.Fatal("ADMS must bound slow and idle clients")
	}
	request := httptest.NewRequest(http.MethodPost, "/iclock/cdata", nil)
	request.ContentLength = maxADMSRequestBodyBytes + 1
	recorder := httptest.NewRecorder()
	server.Handler.ServeHTTP(recorder, request)
	if called || recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatal("oversized known-length body reached a handler")
	}
	request = httptest.NewRequest(http.MethodPost, "/iclock/cdata", strings.NewReader(strings.Repeat("x", maxADMSRequestBodyBytes+1)))
	request.ContentLength = -1
	server.Handler.ServeHTTP(httptest.NewRecorder(), request)
	if !called {
		t.Fatal("chunked body was not exercised")
	}
}

func TestQueryBufferLimitsAndExpiry(t *testing.T) {
	now := time.Now()
	s := &ADMSServer{}
	first := []byte("first")
	if _, ok := s.collectQueryPack("active", first, false, now); !ok {
		t.Fatal("first pack rejected")
	}
	result, ok := s.collectQueryPack("active", []byte("second"), true, now)
	if !ok || string(result) != "firstsecond" || len(s.queryBuffers) != 0 {
		t.Fatal("valid query did not assemble and release its buffer")
	}
	s.collectQueryPack("oversized", first, false, now)
	if _, ok := s.collectQueryPack("oversized", make([]byte, maxQueryBufferBytes), false, now); ok {
		t.Fatal("oversized query accepted")
	}
	if len(s.queryBuffers) != 0 {
		t.Fatal("rejected query retained a buffer")
	}
	for i := 0; i < maxQueryBuffers; i++ {
		if _, ok := s.collectQueryPack(fmt.Sprint(i), first, false, now); !ok {
			t.Fatal("buffer rejected before capacity")
		}
	}
	if _, ok := s.collectQueryPack("extra", first, false, now); ok {
		t.Fatal("unbounded unfinished queries")
	}
	if _, ok := s.collectQueryPack("after-expiry", first, false, now.Add(queryBufferTTL)); !ok || len(s.queryBuffers) != 1 {
		t.Fatal("abandoned queries were not expired")
	}
}

func TestQueryBufferGlobalByteLimit(t *testing.T) {
	s := &ADMSServer{}
	now := time.Now()
	for i := 0; i < maxTotalQueryBytes/maxQueryBufferBytes; i++ {
		if _, ok := s.collectQueryPack(fmt.Sprint(i), make([]byte, maxQueryBufferBytes), false, now); !ok {
			t.Fatal("valid buffer rejected")
		}
	}
	if _, ok := s.collectQueryPack("extra", []byte("x"), false, now); ok {
		t.Fatal("total retained query bytes exceeded the limit")
	}
}
