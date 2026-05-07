package main

import (
	"strings"
	"sync"
	"time"
)

// LogBuffer is a fixed-capacity ring buffer of recent log lines. It's wired
// in as an io.Writer alongside stderr so every log.Printf call is also
// captured here, then surfaced to the bridge via the "logs" command.
type LogBuffer struct {
	mu    sync.Mutex
	items []LogEntry
	cap   int
}

type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level,omitempty"`
	Message   string `json:"message"`
}

func newLogBuffer(capacity int) *LogBuffer {
	if capacity <= 0 {
		capacity = 500
	}
	return &LogBuffer{
		items: make([]LogEntry, 0, capacity),
		cap:   capacity,
	}
}

// Write captures one log record. The standard log package calls Write once
// per record, so we treat each Write as one entry (trimming the trailing
// newline). Multi-line writes are kept as a single entry with embedded
// newlines so structured payloads stay together.
func (b *LogBuffer) Write(p []byte) (int, error) {
	line := strings.TrimRight(string(p), "\r\n")
	if line == "" {
		return len(p), nil
	}

	entry := LogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Level:     detectLevel(line),
		Message:   line,
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	b.items = append(b.items, entry)
	if len(b.items) > b.cap {
		b.items = b.items[len(b.items)-b.cap:]
	}
	return len(p), nil
}

// Snapshot returns up to limit most-recent entries (oldest first). limit <= 0
// returns all buffered entries.
func (b *LogBuffer) Snapshot(limit int) []LogEntry {
	b.mu.Lock()
	defer b.mu.Unlock()

	n := len(b.items)
	if limit <= 0 || limit > n {
		limit = n
	}
	out := make([]LogEntry, limit)
	copy(out, b.items[n-limit:])
	return out
}

func detectLevel(line string) string {
	lower := strings.ToLower(line)
	switch {
	case strings.Contains(lower, "fatal"),
		strings.Contains(lower, "error"),
		strings.Contains(lower, "failed"),
		strings.Contains(lower, "panic"):
		return "ERROR"
	case strings.Contains(lower, "warn"):
		return "WARN"
	default:
		return "INFO"
	}
}
