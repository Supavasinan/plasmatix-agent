package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

var testJPEG = append(
	[]byte{0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00},
	bytes.Repeat([]byte{0x01}, 64)...,
)

func TestHandleFDataForwardsValidJPEG(t *testing.T) {
	type forwardedPhoto struct {
		body    []byte
		headers http.Header
	}
	forwarded := make(chan forwardedPhoto, 1)
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		forwarded <- forwardedPhoto{body: body, headers: r.Header.Clone()}
		w.WriteHeader(http.StatusCreated)
	}))
	defer cloud.Close()

	server := &ADMSServer{agent: &Agent{config: Config{
		PlamatixURL: cloud.URL,
		APIKey:      "secret",
	}}}
	request := httptest.NewRequest(
		http.MethodPost,
		"/iclock/fdata?SN=TA1&filename=../photo.jpg&stamp=88",
		bytes.NewReader(testJPEG),
	)
	recorder := httptest.NewRecorder()

	server.handleFData(recorder, request)

	if recorder.Code != http.StatusOK || strings.TrimSpace(recorder.Body.String()) != "OK" {
		t.Fatalf("response = %d %q; want 200 OK", recorder.Code, recorder.Body.String())
	}
	got := <-forwarded
	if !bytes.Equal(got.body, testJPEG) {
		t.Fatal("forwarded JPEG differs from input")
	}
	if got.headers.Get("X-Device-SN") != "TA1" ||
		got.headers.Get("X-Photo-Name") != "photo.jpg" ||
		got.headers.Get("X-Photo-Stamp") != "88" ||
		got.headers.Get("X-API-Key") != "secret" ||
		got.headers.Get("X-Content-SHA256") == "" {
		t.Fatalf("forwarded headers = %#v", got.headers)
	}
}

func TestHandleFDataRejectsInvalidRequests(t *testing.T) {
	server := &ADMSServer{agent: &Agent{}}
	tests := []struct {
		name       string
		url        string
		body       io.Reader
		wantStatus int
	}{
		{
			name:       "missing serial",
			url:        "/iclock/fdata?filename=photo.jpg",
			body:       bytes.NewReader(testJPEG),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "unsupported signature",
			url:        "/iclock/fdata?SN=TA1&filename=photo.txt",
			body:       strings.NewReader("not an image"),
			wantStatus: http.StatusUnsupportedMediaType,
		},
		{
			name:       "larger than eight MiB",
			url:        "/iclock/fdata?SN=TA1&filename=photo.jpg",
			body:       io.LimitReader(zeroReader{}, 8*1024*1024+1),
			wantStatus: http.StatusRequestEntityTooLarge,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, tt.url, tt.body)
			recorder := httptest.NewRecorder()
			server.handleFData(recorder, request)
			if recorder.Code != tt.wantStatus {
				t.Fatalf("status = %d; want %d", recorder.Code, tt.wantStatus)
			}
		})
	}
}

func TestHandleFDataReturnsRetryableCloudFailure(t *testing.T) {
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
	}))
	defer cloud.Close()

	server := &ADMSServer{agent: &Agent{config: Config{PlamatixURL: cloud.URL}}}
	request := httptest.NewRequest(
		http.MethodPost,
		"/iclock/fdata?SN=TA1&filename=photo.jpg",
		bytes.NewReader(testJPEG),
	)
	recorder := httptest.NewRecorder()
	server.handleFData(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d; want 503 so the device retries", recorder.Code)
	}
}

type zeroReader struct{}

func (zeroReader) Read(buffer []byte) (int, error) {
	for index := range buffer {
		buffer[index] = 0
	}
	return len(buffer), nil
}
