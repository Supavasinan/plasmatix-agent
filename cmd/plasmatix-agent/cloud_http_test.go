package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestCloudConfigurationRequiresSecureRemoteOrigin(t *testing.T) {
	for _, endpoint := range []string{
		"http://cloud.example", "http://10.0.0.5:5452", "file:///tmp/agent",
		"https://user:password@cloud.example", "https:///missing-host",
		"https://cloud.example?key=secret", "https://cloud.example#fragment",
	} {
		if _, err := normalizeConfig(Config{APIKey: "key", Mode: "adms", PlamatixURL: endpoint}); err == nil {
			t.Errorf("accepted unsafe cloud URL %q", endpoint)
		}
	}
	for _, endpoint := range []string{
		"https://cloud.example", "https://cloud.example/base", "http://localhost:3000",
		"http://127.0.0.1:3000", "http://[::1]:3000",
	} {
		if _, err := normalizeConfig(Config{APIKey: "key", Mode: "adms", PlamatixURL: endpoint}); err != nil {
			t.Errorf("valid cloud URL rejected: %v", err)
		}
	}
}

func TestCloudRedirectDoesNotLeakAPIKey(t *testing.T) {
	var reached atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Store(true)
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	request, _ := http.NewRequest(http.MethodGet, source.URL, nil)
	request.Header.Set("X-API-Key", "test-secret")
	response, err := cloudHTTPClient(time.Second).Do(request)
	if response != nil {
		response.Body.Close()
	}
	if err == nil || reached.Load() {
		t.Fatal("cross-origin redirect must fail before reaching the destination")
	}
}

func TestCloudSameOriginRedirectPreservesAuthentication(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/final", http.StatusTemporaryRedirect)
			return
		}
		if r.Header.Get("X-API-Key") != "test-secret" {
			t.Error("same-origin authentication was lost")
		}
		io.WriteString(w, "ok")
	}))
	defer server.Close()
	request, _ := http.NewRequest(http.MethodGet, server.URL, nil)
	request.Header.Set("X-API-Key", "test-secret")
	response, err := cloudHTTPClient(time.Second).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatal(response.Status)
	}
}

func TestZKBioTimeCloudRelayRejectsUntrustedTLS(t *testing.T) {
	var reached atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Store(true)
	}))
	defer server.Close()
	agent := &Agent{config: Config{PlamatixURL: server.URL, APIKey: "test-secret"}}
	if err := agent.relayZKBioTimeTransactions(context.Background(), nil, 0); err == nil {
		t.Fatal("attendance relay accepted an untrusted TLS certificate")
	}
	if reached.Load() {
		t.Fatal("credentials or attendance data reached an untrusted server")
	}
}
