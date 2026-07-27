package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"time"
)

const maxDevicePhotoBytes = 8 * 1024 * 1024

func (s *ADMSServer) handleFData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sn := sanitizeHeaderValue(r.URL.Query().Get("SN"))
	if sn == "" {
		http.Error(w, "missing device serial", http.StatusBadRequest)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxDevicePhotoBytes)
	photo, err := io.ReadAll(r.Body)
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if strings.Contains(err.Error(), "request body too large") ||
			errors.As(err, &maxBytesError) {
			http.Error(w, "photo exceeds 8 MiB", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "read photo", http.StatusBadRequest)
		return
	}
	contentType := http.DetectContentType(photo)
	if contentType != "image/jpeg" && contentType != "image/png" {
		http.Error(w, "unsupported photo type", http.StatusUnsupportedMediaType)
		return
	}

	name := path.Base(sanitizeHeaderValue(r.URL.Query().Get("filename")))
	if name == "." || name == "/" || name == "" {
		if contentType == "image/png" {
			name = "device-photo.png"
		} else {
			name = "device-photo.jpg"
		}
	}
	stamp := sanitizeHeaderValue(r.URL.Query().Get("stamp"))
	sum := sha256.Sum256(photo)

	uploadURL := strings.TrimRight(s.agent.config.PlamatixURL, "/") +
		"/api/agent-bridge/device-photo"
	request, err := http.NewRequest(http.MethodPost, uploadURL, bytes.NewReader(photo))
	if err != nil {
		http.Error(w, "create photo upload", http.StatusServiceUnavailable)
		return
	}
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("X-API-Key", s.agent.config.APIKey)
	request.Header.Set("X-Device-SN", sn)
	request.Header.Set("X-Photo-Name", name)
	request.Header.Set("X-Photo-Stamp", stamp)
	request.Header.Set("X-Content-SHA256", hex.EncodeToString(sum[:]))

	response, err := cloudHTTPClient(30 * time.Second).Do(request)
	if err != nil {
		http.Error(w, "photo storage unavailable", http.StatusServiceUnavailable)
		return
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, response.Body)
		status := response.StatusCode
		if status < 500 {
			status = http.StatusBadGateway
		}
		http.Error(w, fmt.Sprintf("photo storage failed: HTTP %d", response.StatusCode), status)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, "OK")
}

func sanitizeHeaderValue(value string) string {
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == 0 {
			return -1
		}
		return r
	}, value))
}
