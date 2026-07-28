package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxSecretADMSCommands        = 16
	maxBiometricClaimBodyBytes   = 64 * 1024
	maxBiometricErrorBodyBytes   = 4 * 1024
	biometricResultMaxAttempts   = 3
	biometricResultHTTPTimeout   = 10 * time.Second
	biometricDeliveryHTTPTimeout = 15 * time.Second
)

type biometricDeploymentCommandContextKey struct{}

type biometricDeploymentCommandContext struct {
	commandID string
	reserved  bool
}

type biometricDeploymentAsset struct {
	Kind            string `json:"kind"`
	BioType         int    `json:"bioType"`
	SlotIndex       int    `json:"slotIndex"`
	AlgorithmFamily string `json:"algorithmFamily"`
	AlgorithmMajor  int    `json:"algorithmMajor"`
	AlgorithmMinor  int    `json:"algorithmMinor"`
	Format          string `json:"format"`
	ByteCount       int    `json:"byteCount"`
	SHA256          string `json:"sha256"`
}

type claimedBiometricDeployment struct {
	DeploymentID  string                   `json:"deploymentId"`
	DeviceSN      string                   `json:"deviceSn"`
	PersonnelID   string                   `json:"personnelId"`
	CommandID     string                   `json:"commandId"`
	Renderer      string                   `json:"renderer"`
	DeliveryToken string                   `json:"deliveryToken"`
	Asset         biometricDeploymentAsset `json:"asset"`
}

type biometricDeploymentClaimResponse struct {
	Deployments []claimedBiometricDeployment `json:"deployments"`
}

type biometricDeploymentMetadata struct {
	Renderer        string
	PersonnelID     string
	Kind            string
	BioType         int
	SlotIndex       int
	AlgorithmFamily string
	AlgorithmMajor  int
	AlgorithmMinor  int
	Format          string
	ByteCount       int
	SHA256          string
}

type secretADMSCommand struct {
	id           int
	deviceSN     string
	deploymentID string
	commandID    string
	sha256       string
	metadata     biometricDeploymentMetadata
	payloadMu    sync.Mutex
	payload      []byte
}

func (command *secretADMSCommand) zeroPayload() {
	command.payloadMu.Lock()
	zeroBytes(command.payload)
	command.payload = nil
	command.payloadMu.Unlock()
}

type biometricDeploymentResult struct {
	Status     string `json:"status"`
	DeviceSN   string `json:"deviceSn"`
	SHA256     string `json:"sha256"`
	ErrorCode  string `json:"errorCode,omitempty"`
	CommandID  string `json:"commandId"`
	ReturnCode int    `json:"returnCode"`
}

type biometricDeliveryError struct {
	code string
}

func (e *biometricDeliveryError) Error() string {
	return e.code
}

func deliveryError(code string) error {
	return &biometricDeliveryError{code: code}
}

func deliveryErrorCode(err error) string {
	var typed *biometricDeliveryError
	if errors.As(err, &typed) {
		return typed.code
	}
	return "deployment_delivery_failed"
}

func withBiometricDeploymentCommandID(ctx context.Context, commandID string) context.Context {
	return context.WithValue(
		ctx,
		biometricDeploymentCommandContextKey{},
		biometricDeploymentCommandContext{commandID: commandID},
	)
}

func withReservedBiometricDeploymentCommandID(
	ctx context.Context,
	commandID string,
) context.Context {
	return context.WithValue(
		ctx,
		biometricDeploymentCommandContextKey{},
		biometricDeploymentCommandContext{
			commandID: commandID,
			reserved:  true,
		},
	)
}

func biometricDeploymentCommand(ctx context.Context) (string, bool) {
	command, _ := ctx.Value(
		biometricDeploymentCommandContextKey{},
	).(biometricDeploymentCommandContext)
	return strings.TrimSpace(command.commandID), command.reserved
}

func parseBiometricDeploymentReference(command string) (string, bool) {
	fields := strings.Fields(command)
	if len(fields) == 0 || fields[0] != "DEPLOY_BIOMETRIC_ASSET" {
		return "", false
	}
	if len(fields) != 2 {
		return "", true
	}
	return fields[1], true
}

func (s *ADMSServer) interceptBiometricDeploymentReference(
	deviceSN string,
	command ADMSCommand,
) bool {
	deploymentID, reference := parseBiometricDeploymentReference(command.Command)
	if !reference {
		return false
	}
	if !validBiometricUUID(command.CloudID) ||
		!validBiometricUUID(deploymentID) ||
		!validDeliveryIdentifier(deviceSN) {
		if command.CloudID != "" {
			go s.reportCloudCommandResult(
				command.CloudID,
				-2,
				"invalid biometric deployment reference",
			)
		}
		return true
	}
	reserved, _ := s.reserveSecretCommand(command.CloudID)
	if !reserved {
		return true
	}
	ctx, admitted := s.startBiometricDeliveryWorker()
	if !admitted {
		s.releaseSecretCommand(command.CloudID)
		return true
	}
	go func() {
		defer s.biometricDeliveryWorkers.Done()
		_ = s.agent.ProcessBiometricDeployment(
			withReservedBiometricDeploymentCommandID(ctx, command.CloudID),
			deploymentID,
			deviceSN,
		)
	}()
	return true
}

func (a *Agent) ProcessBiometricDeployment(
	ctx context.Context,
	deploymentID,
	deviceSN string,
) error {
	if ctx == nil {
		ctx = context.Background()
	}
	commandID, preReserved := biometricDeploymentCommand(ctx)
	if !validBiometricUUID(deploymentID) ||
		!validBiometricUUID(commandID) ||
		!validDeliveryIdentifier(deviceSN) {
		return deliveryError("stale_deployment_command")
	}
	if a.adms == nil || a.devices == nil {
		return deliveryError("deployment_delivery_unavailable")
	}
	processContext, finishProcess, admitted := a.adms.startBiometricDeliveryProcess(ctx)
	if !admitted {
		if preReserved {
			a.adms.releaseSecretCommand(commandID)
		}
		return deliveryError("deployment_cancelled")
	}
	defer finishProcess()
	ctx = processContext

	reserved, reservationCode := true, ""
	if !preReserved {
		reserved, reservationCode = a.adms.reserveSecretCommand(commandID)
	}
	if !reserved && reservationCode == "" {
		return nil
	}
	if !reserved {
		return deliveryError(reservationCode)
	}
	retainReservation := false
	defer func() {
		if !retainReservation {
			a.adms.releaseSecretCommand(commandID)
		}
	}()

	claimed, err := a.claimBiometricDeployment(ctx, deploymentID, deviceSN)
	if err != nil {
		return err
	}
	if claimed == nil {
		return nil
	}
	if claimed.CommandID != commandID {
		return deliveryError("stale_deployment_command")
	}
	a.adms.supersedeSecretDeployment(deploymentID, commandID)

	metadata := biometricDeploymentMetadata{
		Renderer:        claimed.Renderer,
		PersonnelID:     claimed.PersonnelID,
		Kind:            claimed.Asset.Kind,
		BioType:         claimed.Asset.BioType,
		SlotIndex:       claimed.Asset.SlotIndex,
		AlgorithmFamily: claimed.Asset.AlgorithmFamily,
		AlgorithmMajor:  claimed.Asset.AlgorithmMajor,
		AlgorithmMinor:  claimed.Asset.AlgorithmMinor,
		Format:          claimed.Asset.Format,
		ByteCount:       claimed.Asset.ByteCount,
		SHA256:          claimed.Asset.SHA256,
	}

	payload, err := a.fetchBiometricDeploymentPayload(
		ctx,
		deploymentID,
		deviceSN,
		claimed.DeliveryToken,
		metadata,
	)
	if err != nil {
		if deliveryErrorCode(err) != "deployment_cancelled" {
			a.reportBiometricDeploymentFailure(
				ctx,
				deploymentID,
				deviceSN,
				commandID,
				metadata.SHA256,
				deliveryErrorCode(err),
			)
		}
		return err
	}
	defer zeroBytes(payload)
	if ctx.Err() != nil {
		zeroBytes(payload)
		return deliveryError("deployment_cancelled")
	}

	state, found := a.devices.protocolState(deviceSN)
	if !found {
		err = deliveryError("target_profile_untrusted")
		zeroBytes(payload)
		a.reportBiometricDeploymentFailure(
			ctx,
			deploymentID,
			deviceSN,
			commandID,
			metadata.SHA256,
			deliveryErrorCode(err),
		)
		return err
	}
	rendered, renderCode := renderBiometricDeploymentCommand(state, metadata, payload)
	if renderCode != "" {
		zeroBytes(rendered)
		zeroBytes(payload)
		err = deliveryError(renderCode)
		a.reportBiometricDeploymentFailure(
			ctx,
			deploymentID,
			deviceSN,
			commandID,
			metadata.SHA256,
			renderCode,
		)
		return err
	}
	if ctx.Err() != nil {
		zeroBytes(rendered)
		zeroBytes(payload)
		return deliveryError("deployment_cancelled")
	}

	queued := a.adms.enqueueSecretCommand(&secretADMSCommand{
		deviceSN:     deviceSN,
		deploymentID: deploymentID,
		commandID:    commandID,
		sha256:       metadata.SHA256,
		metadata:     metadata,
		payload:      rendered,
	})
	if !queued {
		zeroBytes(rendered)
		zeroBytes(payload)
		err = deliveryError("secret_command_queue_full")
		a.reportBiometricDeploymentFailure(
			ctx,
			deploymentID,
			deviceSN,
			commandID,
			metadata.SHA256,
			deliveryErrorCode(err),
		)
		return err
	}

	retainReservation = true
	return nil
}

func (a *Agent) claimBiometricDeployment(
	ctx context.Context,
	deploymentID,
	deviceSN string,
) (*claimedBiometricDeployment, error) {
	requestBody, err := json.Marshal(struct {
		DeploymentID string `json:"deploymentId"`
		DeviceSN     string `json:"deviceSn"`
	}{
		DeploymentID: deploymentID,
		DeviceSN:     deviceSN,
	})
	if err != nil {
		return nil, deliveryError("deployment_claim_failed")
	}
	defer zeroBytes(requestBody)

	endpoint := strings.TrimRight(a.config.PlamatixURL, "/") +
		"/api/agent-bridge/biometric-vault/deployments"
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint,
		bytes.NewReader(requestBody),
	)
	if err != nil {
		return nil, classifyBiometricRequestError(ctx, "deployment_claim_failed")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-API-Key", a.config.APIKey)

	response, err := cloudHTTPClient(biometricDeliveryHTTPTimeout).Do(request)
	if err != nil {
		return nil, classifyBiometricRequestError(ctx, "network_unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, biometricHTTPError(response, "deployment_claim_failed")
	}

	var body biometricDeploymentClaimResponse
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxBiometricClaimBodyBytes+1))
	if err := decoder.Decode(&body); err != nil {
		return nil, deliveryError("invalid_deployment_claim")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return nil, deliveryError("invalid_deployment_claim")
	}
	if len(body.Deployments) == 0 {
		return nil, nil
	}
	if len(body.Deployments) != 1 {
		return nil, deliveryError("invalid_deployment_claim")
	}
	claimed := body.Deployments[0]
	if !validBiometricUUID(claimed.CommandID) {
		return nil, deliveryError("stale_deployment_command")
	}
	if !validClaimedBiometricDeployment(claimed, deploymentID, deviceSN) {
		return nil, deliveryError("invalid_deployment_claim")
	}
	return &claimed, nil
}

func validClaimedBiometricDeployment(
	claimed claimedBiometricDeployment,
	deploymentID,
	deviceSN string,
) bool {
	if claimed.DeploymentID != deploymentID ||
		claimed.DeviceSN != deviceSN ||
		!validDeliveryIdentifier(claimed.PersonnelID) ||
		!validBiometricUUID(claimed.CommandID) ||
		!validDeliveryToken(claimed.DeliveryToken) ||
		(claimed.Renderer != "finger_legacy" &&
			claimed.Renderer != "biodata" &&
			claimed.Renderer != "face_photo") {
		return false
	}
	asset := claimed.Asset
	if asset.Kind != "fingerprint_template" &&
		asset.Kind != "face_template" &&
		asset.Kind != "face_comparison_photo" {
		return false
	}
	if asset.BioType != 1 && asset.BioType != 9 {
		return false
	}
	if asset.SlotIndex < 0 || asset.SlotIndex > 9 ||
		asset.AlgorithmMajor < 0 ||
		asset.AlgorithmMajor > maxBiometricAlgorithmVersion ||
		asset.AlgorithmMinor < 0 ||
		asset.AlgorithmMinor > maxBiometricAlgorithmVersion ||
		asset.ByteCount <= 0 ||
		!validDeliveryIdentifier(asset.AlgorithmFamily) ||
		!validDeliveryIdentifier(asset.Format) ||
		!validBiometricDigest(asset.SHA256) {
		return false
	}
	return true
}

func (a *Agent) fetchBiometricDeploymentPayload(
	ctx context.Context,
	deploymentID,
	deviceSN,
	token string,
	metadata biometricDeploymentMetadata,
) ([]byte, error) {
	limit := biometricDeploymentSizeLimit(metadata.Kind)
	if limit == 0 {
		return nil, deliveryError("record_type_unsupported")
	}

	endpoint := strings.TrimRight(a.config.PlamatixURL, "/") +
		"/api/agent-bridge/biometric-vault/deployments/" +
		deploymentID + "/payload"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, classifyBiometricRequestError(ctx, "payload_delivery_failed")
	}
	request.Header.Set("X-API-Key", a.config.APIKey)
	request.Header.Set("X-Device-SN", deviceSN)
	request.Header.Set("Authorization", "Bearer "+token)

	response, err := cloudHTTPClient(biometricDeliveryHTTPTimeout).Do(request)
	if err != nil {
		return nil, classifyBiometricRequestError(ctx, "network_unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, biometricHTTPError(response, "payload_delivery_failed")
	}

	payload, err := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
	if err != nil {
		zeroBytes(payload)
		return nil, classifyBiometricRequestError(ctx, "payload_delivery_failed")
	}
	if len(payload) > limit {
		zeroBytes(payload)
		return nil, deliveryError("payload_too_large")
	}
	if !matchesBiometricPayloadHeaders(response, metadata) {
		zeroBytes(payload)
		return nil, deliveryError("payload_metadata_mismatch")
	}
	if len(payload) != metadata.ByteCount {
		zeroBytes(payload)
		return nil, deliveryError("payload_size_mismatch")
	}

	headerDigest := strings.ToLower(strings.TrimSpace(
		response.Header.Get("X-Content-SHA256"),
	))
	if !validBiometricDigest(headerDigest) || headerDigest != metadata.SHA256 {
		zeroBytes(payload)
		return nil, deliveryError("ciphertext_tampered")
	}
	sum := sha256.Sum256(payload)
	computed := hex.EncodeToString(sum[:])
	if computed != metadata.SHA256 {
		zeroBytes(payload)
		return nil, deliveryError("ciphertext_tampered")
	}
	return payload, nil
}

func matchesBiometricPayloadHeaders(
	response *http.Response,
	metadata biometricDeploymentMetadata,
) bool {
	headers := response.Header
	return headers.Get("Content-Type") == "application/octet-stream" &&
		headers.Get("Cache-Control") == "no-store" &&
		headers.Get("X-Asset-Kind") == metadata.Kind &&
		headers.Get("X-Biometric-Type") == strconv.Itoa(metadata.BioType) &&
		headers.Get("X-Slot-Index") == strconv.Itoa(metadata.SlotIndex) &&
		headers.Get("X-Algorithm-Family") == metadata.AlgorithmFamily &&
		headers.Get("X-Algorithm-Major") == strconv.Itoa(metadata.AlgorithmMajor) &&
		headers.Get("X-Algorithm-Minor") == strconv.Itoa(metadata.AlgorithmMinor) &&
		headers.Get("X-Asset-Format") == metadata.Format
}

func biometricDeploymentSizeLimit(kind string) int {
	switch kind {
	case "fingerprint_template":
		return maxFingerprintTemplateBytes
	case "face_template":
		return maxFaceTemplateBytes
	case "face_comparison_photo":
		return maxFacePhotoBytes
	default:
		return 0
	}
}

func renderBiometricDeploymentCommand(
	state DeviceProtocolState,
	metadata biometricDeploymentMetadata,
	payload []byte,
) ([]byte, string) {
	code := validateLiveBiometricRenderer(state, metadata)
	if code != "" {
		return nil, code
	}

	command := make([]byte, 0, len(payload)*4/3+256)
	switch metadata.Renderer {
	case "finger_legacy":
		record := "DATA UPDATE FINGERTMP PIN="
		if pushVersionBefore(state.PushVersion, 2, 2, 14) {
			record = "DATA FP PIN="
		}
		command = append(command, record...)
		command = append(command, metadata.PersonnelID...)
		command = append(command, "\tFID="...)
		command = strconv.AppendInt(command, int64(metadata.SlotIndex), 10)
		command = append(command, "\tSize="...)
		command = strconv.AppendInt(command, int64(len(payload)), 10)
		command = append(command, "\tValid=1\tTMP="...)
	case "biodata":
		command = append(command, "DATA UPDATE BIODATA Pin="...)
		command = append(command, metadata.PersonnelID...)
		command = append(command, "\tNo="...)
		command = strconv.AppendInt(command, int64(metadata.SlotIndex), 10)
		command = append(command, "\tType="...)
		command = strconv.AppendInt(command, int64(metadata.BioType), 10)
		command = append(command, "\tMajorVer="...)
		command = strconv.AppendInt(command, int64(metadata.AlgorithmMajor), 10)
		command = append(command, "\tMinorVer="...)
		command = strconv.AppendInt(command, int64(metadata.AlgorithmMinor), 10)
		command = append(command, "\tTmp="...)
	case "face_photo":
		command = append(command, "DATA UPDATE BIOPHOTO PIN="...)
		command = append(command, metadata.PersonnelID...)
		command = append(command, "\tNo="...)
		command = strconv.AppendInt(command, int64(metadata.SlotIndex), 10)
		command = append(command, "\tType=9\tSize="...)
		command = strconv.AppendInt(command, int64(len(payload)), 10)
		command = append(command, "\tPhoto="...)
	default:
		return nil, "record_type_unsupported"
	}
	command = base64.StdEncoding.AppendEncode(command, payload)
	return command, ""
}

func validateLiveBiometricRenderer(
	state DeviceProtocolState,
	metadata biometricDeploymentMetadata,
) string {
	if state.Confidence < 80 || state.Confidence > 100 {
		return "target_profile_untrusted"
	}
	if !validDeliveryIdentifier(metadata.PersonnelID) {
		return "invalid_deployment_claim"
	}
	capabilities := normalizeCapabilities(state.Capabilities)
	taVersion, validTA := approvedTAPushVersion(state.PushVersion)
	switch state.Profile {
	case ProtocolTAPush:
		if !validTA {
			return "target_profile_untrusted"
		}
	case ProtocolACPush3:
	default:
		return "target_profile_untrusted"
	}

	switch metadata.Renderer {
	case "finger_legacy":
		if state.Profile != ProtocolTAPush ||
			metadata.Kind != "fingerprint_template" ||
			metadata.BioType != 1 ||
			metadata.AlgorithmMajor > 10 ||
			capabilities["fingerfunon"] != "1" {
			return "record_type_unsupported"
		}
		if code := exactLiveTemplateAlgorithm(metadata, capabilities, "finger"); code != "" {
			return code
		}
		if metadata.Format != "templatev"+strconv.Itoa(metadata.AlgorithmMajor) {
			return "algorithm_mismatch"
		}
		return ""
	case "biodata":
		if state.Profile == ProtocolTAPush &&
			comparePushVersion(taVersion, [3]int{2, 2, 14}) < 0 {
			return "record_type_unsupported"
		}
		if capabilities["biodatafun"] != "1" {
			return "record_type_unsupported"
		}
		switch metadata.Kind {
		case "fingerprint_template":
			if metadata.BioType != 1 || capabilities["fingerfunon"] != "1" {
				return "record_type_unsupported"
			}
			if state.Profile == ProtocolTAPush && metadata.AlgorithmMajor <= 10 {
				return "record_type_unsupported"
			}
			if code := exactLiveTemplateAlgorithm(metadata, capabilities, "finger"); code != "" {
				return code
			}
			if metadata.Format != "templatev"+strconv.Itoa(metadata.AlgorithmMajor) {
				return "algorithm_mismatch"
			}
		case "face_template":
			if metadata.BioType != 9 || capabilities["facefunon"] != "1" {
				return "record_type_unsupported"
			}
			if code := exactLiveTemplateAlgorithm(metadata, capabilities, "face"); code != "" {
				return code
			}
			if metadata.Format != "facev"+strconv.Itoa(metadata.AlgorithmMajor) {
				return "algorithm_mismatch"
			}
		default:
			return "record_type_unsupported"
		}
		return ""
	case "face_photo":
		if state.Profile != ProtocolACPush3 ||
			metadata.Kind != "face_comparison_photo" ||
			metadata.BioType != 9 ||
			metadata.AlgorithmFamily != "portable_photo" ||
			metadata.AlgorithmMajor != 0 ||
			metadata.AlgorithmMinor != 0 ||
			(metadata.Format != "jpeg" && metadata.Format != "png") ||
			capabilities["facefunon"] != "1" ||
			capabilities["biophotofun"] != "1" {
			return "record_type_unsupported"
		}
		return ""
	default:
		return "record_type_unsupported"
	}
}

func exactLiveTemplateAlgorithm(
	metadata biometricDeploymentMetadata,
	capabilities map[string]string,
	modality string,
) string {
	major, minor, valid := algorithmVersion(
		capabilities[modality+"algorithmversion"],
	)
	if !valid {
		return "algorithm_unknown"
	}
	if metadata.AlgorithmFamily != "zk"+modality+"-v"+strconv.Itoa(major) ||
		metadata.AlgorithmMajor != major ||
		metadata.AlgorithmMinor != minor {
		return "algorithm_mismatch"
	}
	return ""
}

func approvedTAPushVersion(value string) ([3]int, bool) {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return [3]int{}, false
	}
	version := [3]int{}
	for index, part := range parts {
		number, err := strconv.Atoi(part)
		if err != nil || number < 0 {
			return [3]int{}, false
		}
		version[index] = number
	}
	return version,
		comparePushVersion(version, [3]int{2, 2, 0}) >= 0 &&
			comparePushVersion(version, [3]int{2, 4, 1}) <= 0
}

func comparePushVersion(left, right [3]int) int {
	for index := range left {
		if left[index] < right[index] {
			return -1
		}
		if left[index] > right[index] {
			return 1
		}
	}
	return 0
}

func validBiometricUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if character != '-' {
				return false
			}
			continue
		}
		if !((character >= '0' && character <= '9') ||
			(character >= 'a' && character <= 'f') ||
			(character >= 'A' && character <= 'F')) {
			return false
		}
	}
	if value[14] < '1' || value[14] > '5' {
		return false
	}
	switch value[19] {
	case '8', '9', 'a', 'b', 'A', 'B':
	default:
		return false
	}
	return true
}

func validDeliveryIdentifier(value string) bool {
	canonical, valid := canonicalBiometricIdentifier(value)
	return valid && canonical == value
}

func validDeliveryToken(value string) bool {
	if len(value) != base64.RawURLEncoding.EncodedLen(32) {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	valid := err == nil && len(decoded) == 32
	zeroBytes(decoded)
	return valid
}

func validBiometricDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}

func classifyBiometricRequestError(ctx context.Context, fallback string) error {
	if ctx.Err() != nil {
		return deliveryError("deployment_cancelled")
	}
	return deliveryError(fallback)
}

func biometricHTTPError(response *http.Response, fallback string) error {
	var body struct {
		Error string `json:"error"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxBiometricErrorBodyBytes))
	if decoder.Decode(&body) == nil && validBiometricErrorCode(body.Error) {
		return deliveryError(body.Error)
	}
	return deliveryError(fallback)
}

func validBiometricErrorCode(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') &&
			character != '_' {
			return false
		}
	}
	return true
}

func (s *ADMSServer) reserveSecretCommand(commandID string) (bool, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.secretClosed {
		return false, "deployment_cancelled"
	}
	if s.secretCmdID == nil {
		s.secretCmdID = make(map[string]struct{})
	}
	if _, exists := s.secretCmdID[commandID]; exists {
		return false, ""
	}
	if len(s.secretCmdID) >= maxSecretADMSCommands {
		return false, "secret_command_queue_full"
	}
	s.secretCmdID[commandID] = struct{}{}
	return true, ""
}

func (s *ADMSServer) releaseSecretCommand(commandID string) {
	s.mu.Lock()
	delete(s.secretCmdID, commandID)
	s.mu.Unlock()
}

func (s *ADMSServer) enqueueSecretCommand(command *secretADMSCommand) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.secretClosed {
		return false
	}
	if _, reserved := s.secretCmdID[command.commandID]; !reserved {
		return false
	}
	if s.secretCmdQueue == nil {
		s.secretCmdQueue = make(map[string][]*secretADMSCommand)
	}
	s.cmdID++
	command.id = s.cmdID
	s.secretCmdQueue[command.deviceSN] = append(
		s.secretCmdQueue[command.deviceSN],
		command,
	)
	return true
}

func (s *ADMSServer) supersedeSecretDeployment(
	deploymentID,
	currentCommandID string,
) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for deviceSN, queue := range s.secretCmdQueue {
		retained := queue[:0]
		for _, command := range queue {
			if command.deploymentID == deploymentID &&
				command.commandID != currentCommandID {
				command.zeroPayload()
				delete(s.secretCmdID, command.commandID)
				continue
			}
			retained = append(retained, command)
		}
		s.secretCmdQueue[deviceSN] = retained
	}
	for key, command := range s.secretPending {
		if command.deploymentID == deploymentID &&
			command.commandID != currentCommandID {
			command.zeroPayload()
			delete(s.secretPending, key)
			delete(s.secretCmdID, command.commandID)
		}
	}
}

func (s *ADMSServer) popSecretCommand(deviceSN string) *secretADMSCommand {
	s.mu.Lock()
	defer s.mu.Unlock()
	queue := s.secretCmdQueue[deviceSN]
	if len(queue) == 0 {
		return nil
	}
	command := queue[0]
	s.secretCmdQueue[deviceSN] = queue[1:]
	if s.secretPending == nil {
		s.secretPending = make(map[pendingCommandKey]*secretADMSCommand)
	}
	s.secretPending[pendingCommandKey{
		DeviceSN: deviceSN,
		LocalID:  command.id,
	}] = command
	return command
}

func (s *ADMSServer) queuedSecretCommandCompatibility(
	command *secretADMSCommand,
) string {
	if s.agent == nil || s.agent.devices == nil {
		return "target_profile_untrusted"
	}
	state, found := s.agent.devices.protocolState(command.deviceSN)
	if !found {
		return "target_profile_untrusted"
	}
	return validateLiveBiometricRenderer(state, command.metadata)
}

func writeSecretADMSCommand(w http.ResponseWriter, command *secretADMSCommand) error {
	command.payloadMu.Lock()
	defer command.payloadMu.Unlock()
	prefix := make([]byte, 0, 32)
	prefix = append(prefix, "C:"...)
	prefix = strconv.AppendInt(prefix, int64(command.id), 10)
	prefix = append(prefix, ':')
	written, err := w.Write(prefix)
	zeroBytes(prefix)
	if err != nil || written != len(prefix) {
		return errors.New("secret command prefix write failed")
	}
	written, err = w.Write(command.payload)
	if err != nil || written != len(command.payload) {
		return errors.New("secret command payload write failed")
	}
	return nil
}

func (s *ADMSServer) failServedSecretCommand(
	command *secretADMSCommand,
	code string,
	returnCode int,
) {
	key := pendingCommandKey{DeviceSN: command.deviceSN, LocalID: command.id}
	s.mu.Lock()
	current, exists := s.secretPending[key]
	if exists && current == command {
		delete(s.secretPending, key)
	}
	command.zeroPayload()
	s.mu.Unlock()
	if exists {
		s.startBiometricResultWorker(biometricDeploymentResult{
			Status:     "failed",
			DeviceSN:   command.deviceSN,
			SHA256:     command.sha256,
			ErrorCode:  code,
			CommandID:  command.commandID,
			ReturnCode: returnCode,
		}, command.deploymentID)
	}
}

func (s *ADMSServer) completeSecretCommand(
	key pendingCommandKey,
	returnCode int,
) bool {
	s.mu.Lock()
	command, exists := s.secretPending[key]
	if exists {
		delete(s.secretPending, key)
		command.zeroPayload()
	}
	s.mu.Unlock()
	if !exists {
		return false
	}

	result := biometricDeploymentResult{
		Status:     "applied",
		DeviceSN:   command.deviceSN,
		SHA256:     command.sha256,
		CommandID:  command.commandID,
		ReturnCode: returnCode,
	}
	if returnCode != 0 {
		result.Status = "failed"
		result.ErrorCode = "device_command_failed"
	}
	s.startBiometricResultWorker(result, command.deploymentID)
	return true
}

func (s *ADMSServer) reportBiometricDeploymentFailure(
	ctx context.Context,
	deploymentID,
	deviceSN,
	commandID,
	digest,
	code string,
) {
	result := biometricDeploymentResult{
		Status:     "failed",
		DeviceSN:   deviceSN,
		SHA256:     digest,
		ErrorCode:  code,
		CommandID:  commandID,
		ReturnCode: -1,
	}
	_ = s.reportBiometricDeploymentResult(ctx, deploymentID, result)
}

func (a *Agent) reportBiometricDeploymentFailure(
	ctx context.Context,
	deploymentID,
	deviceSN,
	commandID,
	digest,
	code string,
) {
	if a.adms == nil {
		return
	}
	a.adms.reportBiometricDeploymentFailure(
		ctx,
		deploymentID,
		deviceSN,
		commandID,
		digest,
		code,
	)
}

func (s *ADMSServer) startBiometricResultWorker(
	result biometricDeploymentResult,
	deploymentID string,
) {
	ctx, admitted := s.startBiometricDeliveryWorker()
	if !admitted {
		s.releaseSecretCommand(result.CommandID)
		return
	}
	go func() {
		defer s.biometricDeliveryWorkers.Done()
		defer s.releaseSecretCommand(result.CommandID)
		_ = s.reportBiometricDeploymentResult(ctx, deploymentID, result)
	}()
}

func (s *ADMSServer) reportBiometricDeploymentResult(
	ctx context.Context,
	deploymentID string,
	result biometricDeploymentResult,
) error {
	body, err := json.Marshal(result)
	if err != nil {
		return deliveryError("deployment_result_failed")
	}
	defer zeroBytes(body)
	endpoint := strings.TrimRight(s.agent.config.PlamatixURL, "/") +
		"/api/agent-bridge/biometric-vault/deployments/" +
		deploymentID + "/result"

	var lastErr error
	for attempt := 0; attempt < biometricResultMaxAttempts; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(biometricResultRetryDelay(attempt))
			select {
			case <-ctx.Done():
				timer.Stop()
				return deliveryError("deployment_cancelled")
			case <-timer.C:
			}
		}
		request, requestErr := http.NewRequestWithContext(
			ctx,
			http.MethodPost,
			endpoint,
			bytes.NewReader(body),
		)
		if requestErr != nil {
			return classifyBiometricRequestError(ctx, "deployment_result_failed")
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-API-Key", s.agent.config.APIKey)
		response, requestErr := cloudHTTPClient(biometricResultHTTPTimeout).Do(request)
		if requestErr != nil {
			lastErr = classifyBiometricRequestError(ctx, "network_unavailable")
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxBiometricErrorBodyBytes))
		_ = response.Body.Close()
		if response.StatusCode == http.StatusOK {
			return nil
		}
		if response.StatusCode >= 400 && response.StatusCode < 500 {
			return deliveryError("deployment_result_rejected")
		}
		lastErr = deliveryError("deployment_result_failed")
	}
	if lastErr != nil {
		return lastErr
	}
	return deliveryError("deployment_result_failed")
}

func biometricResultRetryDelay(attempt int) time.Duration {
	switch attempt {
	case 1:
		return 100 * time.Millisecond
	default:
		return 300 * time.Millisecond
	}
}

func (s *ADMSServer) startBiometricDeliveryProcess(
	parent context.Context,
) (context.Context, func(), bool) {
	s.mu.Lock()
	if s.secretClosed {
		s.mu.Unlock()
		return nil, nil, false
	}
	if s.biometricDeliveryCtx == nil {
		s.biometricDeliveryCtx, s.biometricDeliveryStop =
			context.WithCancel(context.Background())
	}
	serverContext := s.biometricDeliveryCtx
	s.biometricDeliveryWorkers.Add(1)
	s.mu.Unlock()

	processContext, cancel := context.WithCancel(parent)
	stopServerCancellation := context.AfterFunc(serverContext, cancel)
	return processContext, func() {
		stopServerCancellation()
		cancel()
		s.biometricDeliveryWorkers.Done()
	}, true
}

func (s *ADMSServer) startBiometricDeliveryWorker() (context.Context, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.secretClosed {
		return nil, false
	}
	if s.biometricDeliveryCtx == nil {
		s.biometricDeliveryCtx, s.biometricDeliveryStop =
			context.WithCancel(context.Background())
	}
	s.biometricDeliveryWorkers.Add(1)
	return s.biometricDeliveryCtx, true
}

func (s *ADMSServer) shutdownBiometricDelivery() {
	s.mu.Lock()
	if s.secretClosed {
		s.mu.Unlock()
		s.biometricDeliveryWorkers.Wait()
		return
	}
	s.secretClosed = true
	if s.biometricDeliveryStop != nil {
		s.biometricDeliveryStop()
	}
	for deviceSN, queue := range s.secretCmdQueue {
		for _, command := range queue {
			command.zeroPayload()
		}
		delete(s.secretCmdQueue, deviceSN)
	}
	for key, command := range s.secretPending {
		command.zeroPayload()
		delete(s.secretPending, key)
	}
	clear(s.secretCmdID)
	s.mu.Unlock()
	s.biometricDeliveryWorkers.Wait()
}
