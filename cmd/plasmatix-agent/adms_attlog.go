package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// attlogBatchRows bounds one request to Plasmatix; a full replay of a
// scanner's memory is sent as several.
const attlogBatchRows = 1000

// attlogSaveTimeout is how long one batch may take. The scanner is waiting on
// the same request, so it stays well inside its own upload timeout.
const attlogSaveTimeout = 20 * time.Second

// parseATTLOGRows reads attendance rows in either shape a scanner sends.
//
// A live TA PUSH upload is positional: PIN, time, status, verify, workcode,
// tab-separated. Query replies from newer firmware are key=value pairs
// (pin=…, time=…). Lines with no PIN or time are logged and dropped; they
// can never be stored, so there is nothing to keep them on the scanner for.
func parseATTLOGRows(sn string, body []byte) []ADMSAttendance {
	var rows []ADMSAttendance
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		row, ok := parseATTLOGLine(line)
		if !ok {
			log.Printf("[ADMS] Invalid ATTLOG line from SN=%s: %s", sn, line)
			continue
		}
		row.DeviceSN = sn
		rows = append(rows, row)
	}
	return rows
}

func parseATTLOGLine(line string) (ADMSAttendance, bool) {
	fields := strings.Split(line, "\t")
	if strings.Contains(fields[0], "=") {
		kv := parseTabKV(line)
		lower := make(map[string]string, len(kv))
		for key, value := range kv {
			lower[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
		}
		row := ADMSAttendance{
			UserID:     firstNonEmpty(lower["pin"], lower["userid"]),
			PunchTime:  firstNonEmpty(lower["time"], lower["checktime"]),
			Status:     atoiOrZero(firstNonEmpty(lower["status"], lower["state"])),
			VerifyMode: atoiOrZero(firstNonEmpty(lower["verify"], lower["verifytype"])),
			WorkCode:   atoiOrZero(lower["workcode"]),
		}
		return row, row.UserID != "" && row.PunchTime != ""
	}

	if len(fields) < 2 {
		return ADMSAttendance{}, false
	}
	at := func(i int) string {
		if i < len(fields) {
			return strings.TrimSpace(fields[i])
		}
		return ""
	}
	status, _ := strconv.Atoi(at(2))
	verifyMode, _ := strconv.Atoi(at(3))
	workCode, _ := strconv.Atoi(at(4))
	row := ADMSAttendance{
		UserID:     at(0),
		PunchTime:  at(1),
		Status:     status,
		VerifyMode: verifyMode,
		WorkCode:   workCode,
	}
	return row, row.UserID != "" && row.PunchTime != ""
}

// saveAttendance stores rows in Plasmatix and returns nil only once every
// batch has been acknowledged as committed.
func (s *ADMSServer) saveAttendance(rows []ADMSAttendance) error {
	for start := 0; start < len(rows); start += attlogBatchRows {
		end := min(start+attlogBatchRows, len(rows))
		if err := s.postAttendanceBatch(rows[start:end]); err != nil {
			return err
		}
	}
	return nil
}

type attlogBatchReply struct {
	OK       bool   `json:"ok"`
	Received *int   `json:"received"`
	Ignored  string `json:"ignored"`
}

// errBatchUnsupported means Plasmatix predates attlog_batch: it answers an
// unknown type with 200 {"ignored": …} and stores nothing.
var errBatchUnsupported = errors.New("attlog_batch not supported by Plasmatix")

func (s *ADMSServer) postAttendanceBatch(rows []ADMSAttendance) error {
	reply, err := s.postAttlog(map[string]any{"type": "attlog_batch", "data": rows})
	if errors.Is(err, errBatchUnsupported) {
		return s.postAttendanceRows(rows)
	}
	if err != nil {
		return err
	}
	if reply.Received == nil || *reply.Received != len(rows) {
		return fmt.Errorf("plasmatix acknowledged %v of %d rows", reply.Received, len(rows))
	}
	return nil
}

// postAttendanceRows is the one-row-per-request path for a Plasmatix without
// the batch endpoint. Its 200 already means the row was inserted.
func (s *ADMSServer) postAttendanceRows(rows []ADMSAttendance) error {
	for _, row := range rows {
		if _, err := s.postAttlog(map[string]any{"type": "attlog", "data": row}); err != nil {
			return err
		}
	}
	return nil
}

func (s *ADMSServer) postAttlog(payload map[string]any) (attlogBatchReply, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return attlogBatchReply{}, err
	}
	attURL := fmt.Sprintf("%s/api/agent-bridge/attlog", s.agent.config.PlamatixURL)
	req, err := http.NewRequest(http.MethodPost, attURL, bytes.NewReader(body))
	if err != nil {
		return attlogBatchReply{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", s.agent.config.APIKey)

	res, err := cloudHTTPClient(attlogSaveTimeout).Do(req)
	if err != nil {
		return attlogBatchReply{}, err
	}
	defer res.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	if res.StatusCode != http.StatusOK {
		return attlogBatchReply{}, fmt.Errorf("HTTP %d: %s", res.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var reply attlogBatchReply
	if err := json.Unmarshal(respBody, &reply); err != nil {
		return attlogBatchReply{}, fmt.Errorf("decode attlog reply: %w", err)
	}
	if reply.Ignored != "" {
		return reply, errBatchUnsupported
	}
	if !reply.OK {
		return reply, fmt.Errorf("plasmatix did not confirm: %s", strings.TrimSpace(string(respBody)))
	}
	return reply, nil
}
