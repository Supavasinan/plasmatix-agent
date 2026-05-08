package main

import "testing"

func TestParseLogLine(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want LogEntry
	}{
		{
			name: "ADMS getrequest",
			in:   "2026/05/08 13:11:33 [ADMS] GET /iclock/getrequest from SN=NYU7253100765 remote=10.10.40.96:40558 query=SN=NYU7253100765",
			want: LogEntry{
				Level:    "INFO",
				Category: "ADMS",
				SN:       "NYU7253100765",
				Method:   "GET",
				Path:     "/iclock/getrequest",
				Remote:   "10.10.40.96:40558",
				Query:    "SN=NYU7253100765",
				Message:  "",
			},
		},
		{
			name: "ADMS no command",
			in:   "2026/05/08 13:11:34 [ADMS] No command for SN=NYU7253100765; responding OK",
			want: LogEntry{
				Level:    "INFO",
				Category: "ADMS",
				SN:       "NYU7253100765",
				Message:  "No command responding OK",
			},
		},
		{
			name: "ADMS attlog",
			in:   "2026/05/08 13:11:34 [ADMS] Received ATTLOG from SN=NYU7253100765 (5 rows)",
			want: LogEntry{
				Level:    "INFO",
				Category: "ADMS",
				SN:       "NYU7253100765",
				Message:  "Received ATTLOG (5 rows)",
			},
		},
		{
			name: "ADMS error",
			in:   "2026/05/08 13:11:34 [ADMS] Post attlog failed (HTTP 500): boom",
			want: LogEntry{
				Level:    "ERROR",
				Category: "ADMS",
				Message:  "Post attlog failed (HTTP 500): boom",
			},
		},
		{
			name: "heartbeat",
			in:   "2026/05/08 13:11:34 [heartbeat] post failed: timeout",
			want: LogEntry{
				Level:    "ERROR",
				Category: "heartbeat",
				Message:  "post failed: timeout",
			},
		},
		{
			name: "no bracket",
			in:   "2026/05/08 13:11:34 ADMS server listening on :8080",
			want: LogEntry{
				Level:   "INFO",
				Message: "ADMS server listening on :8080",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseLogLine(tc.in)
			// Timestamp is filled in Write, not parseLogLine.
			if got.Level != tc.want.Level {
				t.Errorf("Level = %q, want %q", got.Level, tc.want.Level)
			}
			if got.Category != tc.want.Category {
				t.Errorf("Category = %q, want %q", got.Category, tc.want.Category)
			}
			if got.SN != tc.want.SN {
				t.Errorf("SN = %q, want %q", got.SN, tc.want.SN)
			}
			if got.Method != tc.want.Method {
				t.Errorf("Method = %q, want %q", got.Method, tc.want.Method)
			}
			if got.Path != tc.want.Path {
				t.Errorf("Path = %q, want %q", got.Path, tc.want.Path)
			}
			if got.Remote != tc.want.Remote {
				t.Errorf("Remote = %q, want %q", got.Remote, tc.want.Remote)
			}
			if got.Query != tc.want.Query {
				t.Errorf("Query = %q, want %q", got.Query, tc.want.Query)
			}
			if tc.want.Message != "" && got.Message != tc.want.Message {
				t.Errorf("Message = %q, want %q", got.Message, tc.want.Message)
			}
			if got.Raw != tc.in {
				t.Errorf("Raw = %q, want %q", got.Raw, tc.in)
			}
		})
	}
}
