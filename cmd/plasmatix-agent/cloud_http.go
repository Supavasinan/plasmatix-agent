package main

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func validateCloudURL(raw string) error {
	endpoint, err := url.Parse(raw)
	if err != nil || endpoint.Hostname() == "" || endpoint.User != nil ||
		endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return errors.New("plasmatix_url must be an HTTP(S) base URL without credentials, query or fragment")
	}
	if endpoint.Scheme == "https" {
		return nil
	}
	// Local development can use HTTP; a LAN or internet control channel cannot.
	host := endpoint.Hostname()
	ip := net.ParseIP(host)
	if endpoint.Scheme == "http" && (strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback())) {
		return nil
	}
	return errors.New("plasmatix_url requires HTTPS except on loopback")
}

// The command channel and attendance relay carry an API key. Go's default
// redirect policy forwards custom headers (including X-API-Key) to other hosts.
// Keep every hop on the original origin and retain certificate verification.
func cloudHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("too many cloud redirects")
			}
			original := via[0].URL
			if request.URL.Scheme != original.Scheme ||
				!strings.EqualFold(request.URL.Host, original.Host) || request.URL.User != nil {
				return errors.New("cloud redirect must stay on the configured origin")
			}
			return nil
		},
	}
}
