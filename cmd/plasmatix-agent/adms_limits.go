package main

import (
	"net/http"
	"time"
)

const (
	maxADMSRequestBodyBytes = 32 * 1024 * 1024
	maxQueryBufferBytes     = 8 * 1024 * 1024
	maxTotalQueryBytes      = 32 * 1024 * 1024
	maxQueryBuffers         = 64
	queryBufferTTL          = time.Minute
)

func newADMSHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > maxADMSRequestBodyBytes {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxADMSRequestBodyBytes)
			handler.ServeHTTP(w, r)
		}),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      secretCommandWriteTimeout,
		IdleTimeout:       60 * time.Second,
	}
}

// collectQueryPack bounds both each reply and all unfinished multipart replies.
// Abandoned replies expire on the next upload. Callers hold no lock.
func (s *ADMSServer) collectQueryPack(key string, body []byte, final bool, now time.Time) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.queryBuffers == nil {
		s.queryBuffers = make(map[string][]byte)
	}
	if s.queryBufferUpdated == nil {
		s.queryBufferUpdated = make(map[string]time.Time)
	}
	total := 0
	for bufferedKey, buffer := range s.queryBuffers {
		if updated, ok := s.queryBufferUpdated[bufferedKey]; ok && now.Sub(updated) >= queryBufferTTL {
			clear(buffer)
			delete(s.queryBuffers, bufferedKey)
			delete(s.queryBufferUpdated, bufferedKey)
			continue
		}
		total += len(buffer)
	}
	previous, exists := s.queryBuffers[key]
	if len(previous)+len(body) > maxQueryBufferBytes || total+len(body) > maxTotalQueryBytes ||
		(!exists && len(s.queryBuffers) >= maxQueryBuffers) {
		clear(previous)
		delete(s.queryBuffers, key)
		delete(s.queryBufferUpdated, key)
		return nil, false
	}
	buffer := append(previous, body...)
	if final {
		delete(s.queryBuffers, key)
		delete(s.queryBufferUpdated, key)
		return buffer, true
	}
	s.queryBuffers[key] = buffer
	s.queryBufferUpdated[key] = now
	return nil, true
}
