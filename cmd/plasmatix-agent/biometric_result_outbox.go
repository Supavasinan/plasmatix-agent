package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	biometricResultOutboxFilename   = "biometric-result-outbox.json"
	maxBiometricResultOutboxRecords = 64
	maxBiometricResultOutboxBytes   = 256 * 1024
	biometricResultOutboxVersion    = 1
)

var (
	errBiometricResultOutboxFull     = errors.New("biometric result outbox is full")
	errBiometricResultOutboxConflict = errors.New("biometric result outbox record conflicts")
	errBiometricResultOutboxCorrupt  = errors.New("biometric result outbox is corrupt")
	errBiometricResultOutboxPersist  = errors.New("biometric result outbox persistence failed")
)

type biometricResultOutboxRecord struct {
	DeploymentID  string    `json:"deploymentId"`
	CommandID     string    `json:"commandId"`
	DeviceSN      string    `json:"deviceSn"`
	Status        string    `json:"status"`
	SHA256        string    `json:"sha256,omitempty"`
	ErrorCode     string    `json:"errorCode,omitempty"`
	ReturnCode    int       `json:"returnCode"`
	Attempts      int       `json:"attempts"`
	NextAttemptAt time.Time `json:"nextAttemptAt"`
}

type biometricResultOutboxDocument struct {
	Version int                           `json:"version"`
	Records []biometricResultOutboxRecord `json:"records"`
}

type biometricResultOutbox struct {
	mu      sync.Mutex
	path    string
	records []biometricResultOutboxRecord
}

func openBiometricResultOutbox(stateDir string) (*biometricResultOutbox, error) {
	if stateDir == "" {
		return nil, errBiometricResultOutboxPersist
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, errBiometricResultOutboxPersist
	}
	if err := os.Chmod(stateDir, 0o700); err != nil {
		return nil, errBiometricResultOutboxPersist
	}
	outbox := &biometricResultOutbox{
		path: filepath.Join(stateDir, biometricResultOutboxFilename),
	}
	pathInfo, err := os.Lstat(outbox.path)
	if errors.Is(err, os.ErrNotExist) {
		return outbox, nil
	}
	if err != nil {
		return nil, errBiometricResultOutboxPersist
	}
	if !pathInfo.Mode().IsRegular() {
		return nil, errBiometricResultOutboxCorrupt
	}
	if err := os.Chmod(outbox.path, 0o600); err != nil {
		return nil, errBiometricResultOutboxPersist
	}
	file, err := os.Open(outbox.path)
	if err != nil {
		return nil, errBiometricResultOutboxPersist
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() > maxBiometricResultOutboxBytes {
		return nil, errBiometricResultOutboxCorrupt
	}
	body, err := io.ReadAll(io.LimitReader(
		file,
		maxBiometricResultOutboxBytes+1,
	))
	if err != nil || len(body) > maxBiometricResultOutboxBytes ||
		!jsonHasUniqueObjectMembers(body) {
		zeroBytes(body)
		return nil, errBiometricResultOutboxCorrupt
	}
	defer zeroBytes(body)
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var document biometricResultOutboxDocument
	if decoder.Decode(&document) != nil {
		return nil, errBiometricResultOutboxCorrupt
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF ||
		document.Version != biometricResultOutboxVersion ||
		len(document.Records) > maxBiometricResultOutboxRecords {
		return nil, errBiometricResultOutboxCorrupt
	}
	seen := make(map[string]struct{}, len(document.Records))
	for _, record := range document.Records {
		if !validBiometricResultOutboxRecord(record) {
			return nil, errBiometricResultOutboxCorrupt
		}
		if _, duplicated := seen[record.CommandID]; duplicated {
			return nil, errBiometricResultOutboxCorrupt
		}
		seen[record.CommandID] = struct{}{}
	}
	outbox.records = append([]biometricResultOutboxRecord(nil), document.Records...)
	return outbox, nil
}

func jsonHasUniqueObjectMembers(body []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	if !scanUniqueJSONValue(decoder) {
		return false
	}
	_, err := decoder.Token()
	return err == io.EOF
}

func scanUniqueJSONValue(decoder *json.Decoder) bool {
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return true
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return false
			}
			key, valid := keyToken.(string)
			if !valid {
				return false
			}
			if _, duplicate := seen[key]; duplicate {
				return false
			}
			seen[key] = struct{}{}
			if !scanUniqueJSONValue(decoder) {
				return false
			}
		}
		closing, err := decoder.Token()
		return err == nil && closing == json.Delim('}')
	case '[':
		for decoder.More() {
			if !scanUniqueJSONValue(decoder) {
				return false
			}
		}
		closing, err := decoder.Token()
		return err == nil && closing == json.Delim(']')
	default:
		return false
	}
}

func (outbox *biometricResultOutbox) enqueue(
	deploymentID string,
	result biometricDeploymentResult,
	now time.Time,
) error {
	return outbox.enqueueWithCommit(deploymentID, result, now, nil)
}

func (outbox *biometricResultOutbox) enqueueWithCommit(
	deploymentID string,
	result biometricDeploymentResult,
	now time.Time,
	commit func(),
) error {
	record := biometricResultOutboxRecord{
		DeploymentID:  deploymentID,
		CommandID:     result.CommandID,
		DeviceSN:      result.DeviceSN,
		Status:        result.Status,
		SHA256:        result.SHA256,
		ErrorCode:     result.ErrorCode,
		ReturnCode:    result.ReturnCode,
		NextAttemptAt: now.UTC(),
	}
	if !validBiometricResultOutboxRecord(record) {
		return errBiometricResultOutboxCorrupt
	}
	outbox.mu.Lock()
	defer outbox.mu.Unlock()
	for _, current := range outbox.records {
		if current.CommandID != result.CommandID {
			continue
		}
		if sameBiometricResultOutboxValue(current, record) {
			if commit != nil {
				commit()
			}
			return nil
		}
		return errBiometricResultOutboxConflict
	}
	if len(outbox.records) >= maxBiometricResultOutboxRecords {
		return errBiometricResultOutboxFull
	}
	outbox.records = append(outbox.records, record)
	if err := outbox.persistLocked(); err != nil {
		outbox.records = outbox.records[:len(outbox.records)-1]
		return err
	}
	if commit != nil {
		commit()
	}
	return nil
}

func (outbox *biometricResultOutbox) recordRetry(
	deploymentID,
	commandID string,
	now time.Time,
) error {
	outbox.mu.Lock()
	defer outbox.mu.Unlock()
	key := biometricResultOutboxKey(deploymentID, commandID)
	for index := range outbox.records {
		record := &outbox.records[index]
		if biometricResultOutboxKey(record.DeploymentID, record.CommandID) != key {
			continue
		}
		previous := *record
		record.Attempts++
		record.NextAttemptAt = now.UTC().Add(biometricResultBackoff(record.Attempts))
		if err := outbox.persistLocked(); err != nil {
			*record = previous
			return err
		}
		return nil
	}
	return nil
}

func (outbox *biometricResultOutbox) delete(
	deploymentID,
	commandID string,
) error {
	outbox.mu.Lock()
	defer outbox.mu.Unlock()
	key := biometricResultOutboxKey(deploymentID, commandID)
	for index, record := range outbox.records {
		if biometricResultOutboxKey(record.DeploymentID, record.CommandID) != key {
			continue
		}
		previous := append([]biometricResultOutboxRecord(nil), outbox.records...)
		outbox.records = append(outbox.records[:index], outbox.records[index+1:]...)
		if err := outbox.persistLocked(); err != nil {
			outbox.records = previous
			return err
		}
		return nil
	}
	return nil
}

func (outbox *biometricResultOutbox) snapshot() []biometricResultOutboxRecord {
	outbox.mu.Lock()
	defer outbox.mu.Unlock()
	return append([]biometricResultOutboxRecord(nil), outbox.records...)
}

func (outbox *biometricResultOutbox) admission(
	commandID string,
	activeReservations int,
) (bool, bool) {
	outbox.mu.Lock()
	defer outbox.mu.Unlock()
	for _, record := range outbox.records {
		if record.CommandID == commandID {
			return true, true
		}
	}
	return false,
		len(outbox.records)+activeReservations <
			maxBiometricResultOutboxRecords
}

func (outbox *biometricResultOutbox) next(
	now time.Time,
) (biometricResultOutboxRecord, time.Duration, bool) {
	records := outbox.snapshot()
	if len(records) == 0 {
		return biometricResultOutboxRecord{}, 0, false
	}
	sort.Slice(records, func(left, right int) bool {
		return records[left].NextAttemptAt.Before(records[right].NextAttemptAt)
	})
	wait := records[0].NextAttemptAt.Sub(now)
	if wait < 0 {
		wait = 0
	}
	return records[0], wait, true
}

func (outbox *biometricResultOutbox) persistLocked() error {
	document := biometricResultOutboxDocument{
		Version: biometricResultOutboxVersion,
		Records: outbox.records,
	}
	body, err := json.Marshal(document)
	if err != nil || len(body) > maxBiometricResultOutboxBytes {
		zeroBytes(body)
		return errBiometricResultOutboxPersist
	}
	defer zeroBytes(body)

	directory := filepath.Dir(outbox.path)
	temp, err := os.CreateTemp(directory, ".biometric-result-outbox-*")
	if err != nil {
		return errBiometricResultOutboxPersist
	}
	tempPath := temp.Name()
	cleanup := true
	defer func() {
		_ = temp.Close()
		if cleanup {
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		return errBiometricResultOutboxPersist
	}
	if _, err := temp.Write(body); err != nil {
		return errBiometricResultOutboxPersist
	}
	if err := temp.Sync(); err != nil {
		return errBiometricResultOutboxPersist
	}
	if err := temp.Close(); err != nil {
		return errBiometricResultOutboxPersist
	}
	if err := os.Rename(tempPath, outbox.path); err != nil {
		return errBiometricResultOutboxPersist
	}
	cleanup = false
	if err := os.Chmod(outbox.path, 0o600); err != nil {
		return errBiometricResultOutboxPersist
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return errBiometricResultOutboxPersist
	}
	defer directoryHandle.Close()
	if err := directoryHandle.Sync(); err != nil {
		return errBiometricResultOutboxPersist
	}
	return nil
}

func validBiometricResultOutboxRecord(record biometricResultOutboxRecord) bool {
	if !validBiometricUUID(record.DeploymentID) ||
		!validBiometricUUID(record.CommandID) ||
		!validDeliveryIdentifier(record.DeviceSN) ||
		record.Attempts < 0 ||
		record.Attempts > 1_000_000 ||
		record.NextAttemptAt.IsZero() {
		return false
	}
	switch record.Status {
	case "applied":
		return record.ErrorCode == "" && validBiometricDigest(record.SHA256)
	case "failed":
		return (record.SHA256 == "" || validBiometricDigest(record.SHA256)) &&
			validBiometricErrorCode(record.ErrorCode)
	default:
		return false
	}
}

func sameBiometricResultOutboxValue(
	left,
	right biometricResultOutboxRecord,
) bool {
	return left.DeploymentID == right.DeploymentID &&
		left.CommandID == right.CommandID &&
		left.DeviceSN == right.DeviceSN &&
		left.Status == right.Status &&
		left.SHA256 == right.SHA256 &&
		left.ErrorCode == right.ErrorCode &&
		left.ReturnCode == right.ReturnCode
}

func biometricResultOutboxKey(deploymentID, commandID string) string {
	return deploymentID + "\x00" + commandID
}

func biometricResultBackoff(attempt int) time.Duration {
	if attempt < 1 {
		return 0
	}
	delay := time.Second
	for current := 1; current < attempt && delay < 5*time.Minute; current++ {
		delay *= 2
	}
	if delay > 5*time.Minute {
		return 5 * time.Minute
	}
	return delay
}

func (s *ADMSServer) startBiometricResultOutboxWorker() {
	s.mu.Lock()
	if s.secretClosed ||
		s.resultOutbox == nil ||
		s.resultOutboxStarted {
		s.mu.Unlock()
		return
	}
	if s.biometricDeliveryCtx == nil {
		s.biometricDeliveryCtx, s.biometricDeliveryStop =
			context.WithCancel(context.Background())
	}
	if s.resultOutboxWake == nil {
		s.resultOutboxWake = make(chan struct{}, 1)
	}
	ctx := s.biometricDeliveryCtx
	wake := s.resultOutboxWake
	s.resultOutboxStarted = true
	s.biometricDeliveryWorkers.Add(1)
	s.mu.Unlock()

	go func() {
		defer s.biometricDeliveryWorkers.Done()
		s.runBiometricResultOutbox(ctx, wake)
	}()
}

func (s *ADMSServer) wakeBiometricResultOutbox() {
	s.startBiometricResultOutboxWorker()
	s.mu.Lock()
	wake := s.resultOutboxWake
	s.mu.Unlock()
	if wake == nil {
		return
	}
	select {
	case wake <- struct{}{}:
	default:
	}
}

func (s *ADMSServer) runBiometricResultOutbox(
	ctx context.Context,
	wake <-chan struct{},
) {
	for {
		if !s.flushPendingBiometricResults() {
			timer := time.NewTimer(time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-wake:
				timer.Stop()
				continue
			case <-timer.C:
				continue
			}
		}
		record, wait, found := s.resultOutbox.next(time.Now())
		if !found {
			select {
			case <-ctx.Done():
				return
			case <-wake:
				continue
			}
		}
		if wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-wake:
				timer.Stop()
				continue
			case <-timer.C:
			}
		}

		terminal, err := s.postBiometricDeploymentResult(ctx, record)
		if err == nil || terminal {
			if deleteErr := s.resultOutbox.delete(
				record.DeploymentID,
				record.CommandID,
			); deleteErr != nil {
				s.disableBiometricResultOutbox(deleteErr)
				return
			}
			continue
		}
		if retryErr := s.resultOutbox.recordRetry(
			record.DeploymentID,
			record.CommandID,
			time.Now(),
		); retryErr != nil {
			s.disableBiometricResultOutbox(retryErr)
			return
		}
	}
}

func (s *ADMSServer) disableBiometricResultOutbox(err error) {
	s.mu.Lock()
	if s.resultOutboxErr == nil {
		s.resultOutboxErr = err
	}
	s.mu.Unlock()
}

func (s *ADMSServer) postBiometricDeploymentResult(
	ctx context.Context,
	record biometricResultOutboxRecord,
) (terminal bool, err error) {
	result := biometricDeploymentResult{
		Status:     record.Status,
		DeviceSN:   record.DeviceSN,
		SHA256:     record.SHA256,
		ErrorCode:  record.ErrorCode,
		CommandID:  record.CommandID,
		ReturnCode: record.ReturnCode,
	}
	body, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		return false, deliveryError("deployment_result_failed")
	}
	defer zeroBytes(body)
	endpoint := strings.TrimRight(s.agent.config.PlamatixURL, "/") +
		"/api/agent-bridge/biometric-vault/deployments/" +
		record.DeploymentID + "/result"
	request, requestErr := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint,
		bytes.NewReader(body),
	)
	if requestErr != nil {
		return false, classifyBiometricRequestError(ctx, "deployment_result_failed")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-API-Key", s.agent.config.APIKey)
	response, requestErr := cloudHTTPClient(biometricResultHTTPTimeout).Do(request)
	if requestErr != nil {
		return false, classifyBiometricRequestError(ctx, "network_unavailable")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxBiometricErrorBodyBytes))
	if response.StatusCode == http.StatusOK {
		return false, nil
	}
	if response.StatusCode >= 400 && response.StatusCode < 500 {
		return true, deliveryError("deployment_result_rejected")
	}
	return false, deliveryError("deployment_result_failed")
}
