package main

import (
	"regexp"
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

// LogEntry is the structured form of a single log line surfaced to the
// bridge. Free-form Go log output is parsed once on capture so the UI can
// render real columns instead of regex-stripping a flat string.
type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level,omitempty"`
	Category  string `json:"category,omitempty"` // bracketed tag, e.g. "ADMS", "heartbeat"
	SN        string `json:"sn,omitempty"`       // device serial number
	Method    string `json:"method,omitempty"`   // HTTP method
	Path      string `json:"path,omitempty"`     // HTTP path
	Remote    string `json:"remote,omitempty"`   // ip:port
	Query     string `json:"query,omitempty"`    // raw query string
	Message   string `json:"message"`            // cleaned, human-readable action
	Raw       string `json:"raw,omitempty"`      // original line as written
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

	entry := parseLogLine(line)
	entry.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)

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

// stdlib log prefix: "2006/01/02 15:04:05 " (or with microseconds)
var stdlibPrefix = regexp.MustCompile(`^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?\s+`)

// "[Tag] " prefix; allows internal spaces (we have none today, but be lenient).
var bracketPrefix = regexp.MustCompile(`^\[([^\]]+)\]\s*`)

// HTTP request, e.g. "GET /iclock/getrequest"
var httpRequest = regexp.MustCompile(`\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\/\S+)`)

// key=value extractors. Values are non-greedy up to whitespace, comma, or
// semicolon so we don't swallow trailing punctuation.
var (
	snField     = regexp.MustCompile(`\bSN=([^\s,;)]+)`)
	remoteField = regexp.MustCompile(`\bremote=([^\s,;)]+)`)
	queryField  = regexp.MustCompile(`\bquery=([^\s,;)]+)`)
)

// key=value chunks that should be stripped from the cleaned message,
// optionally swallowing a leading connective ("for"/"from"/"to") and any
// trailing punctuation so we don't leave orphan glue words behind.
var noiseChunk = regexp.MustCompile(
	`(?:\b(?:for|from|to)\s+)?\b(?:SN=\S+|remote=\S+|query=\S+)[;,]?`,
)

var (
	multiSpace    = regexp.MustCompile(`\s{2,}`)
	leftoverPunct = regexp.MustCompile(`\s*[,;:\-]\s*$`)
)

func parseLogLine(line string) LogEntry {
	entry := LogEntry{Raw: line}

	body := stdlibPrefix.ReplaceAllString(line, "")

	if m := bracketPrefix.FindStringSubmatch(body); m != nil {
		entry.Category = m[1]
		body = body[len(m[0]):]
	}

	if m := snField.FindStringSubmatch(body); m != nil {
		entry.SN = m[1]
	}
	if m := remoteField.FindStringSubmatch(body); m != nil {
		entry.Remote = m[1]
	}
	if m := queryField.FindStringSubmatch(body); m != nil {
		entry.Query = m[1]
	}
	if m := httpRequest.FindStringSubmatch(body); m != nil {
		entry.Method = m[1]
		entry.Path = m[2]
	}

	cleaned := body
	if entry.Method != "" && entry.Path != "" {
		cleaned = httpRequest.ReplaceAllString(cleaned, "")
	}
	cleaned = noiseChunk.ReplaceAllString(cleaned, "")
	cleaned = multiSpace.ReplaceAllString(cleaned, " ")
	cleaned = strings.TrimSpace(cleaned)
	cleaned = leftoverPunct.ReplaceAllString(cleaned, "")
	cleaned = strings.TrimSpace(cleaned)

	entry.Message = cleaned
	entry.Level = detectLevel(line)
	return entry
}

func detectLevel(line string) string {
	lower := strings.ToLower(line)
	switch {
	case strings.Contains(lower, "fatal"),
		strings.Contains(lower, "panic"):
		return "FATAL"
	case strings.Contains(lower, "error"),
		strings.Contains(lower, "failed"),
		strings.Contains(lower, "invalid"):
		return "ERROR"
	case strings.Contains(lower, "warn"):
		return "WARN"
	default:
		return "INFO"
	}
}
