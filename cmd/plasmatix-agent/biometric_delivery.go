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
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxSecretADMSCommands         = 16
	maxSecretACKBodyBytes         = 256
	maxDeviceCommandACKBodyBytes  = 4 * 1024
	maxSecretCommandServeAttempts = 3
	secretCommandServeDeadline    = 30 * time.Second
	secretCommandWriteTimeout     = 20 * time.Second
	maxBiometricClaimBodyBytes    = 64 * 1024
	maxBiometricErrorBodyBytes    = 4 * 1024
	biometricResultHTTPTimeout    = 10 * time.Second
	biometricDeliveryHTTPTimeout  = 15 * time.Second
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

type biometricDeletionMetadata struct {
	PersonnelID string
	Kind        string
	BioType     int
	SlotIndex   int
}

type secretADMSCommand struct {
	id             int
	deviceSN       string
	deploymentID   string
	commandID      string
	operation      string
	attempt        int
	vaultAssetID   string
	sha256         string
	metadata       biometricDeploymentMetadata
	deleteMetadata biometricDeletionMetadata
	payloadMu      sync.Mutex
	payload        []byte
	firstServedAt  time.Time
	serveAttempts  int
	deadlineStop   func() bool
	writerActive   bool
}

func (command *secretADMSCommand) zeroPayload() {
	command.payloadMu.Lock()
	zeroBytes(command.payload)
	command.payload = nil
	command.payloadMu.Unlock()
}

func (command *secretADMSCommand) result(
	status,
	errorCode string,
	returnCode int,
) biometricDeploymentResult {
	return biometricDeploymentResult{
		Operation:    command.operation,
		Status:       status,
		DeviceSN:     command.deviceSN,
		SHA256:       command.sha256,
		ErrorCode:    errorCode,
		CommandID:    command.commandID,
		Attempt:      command.attempt,
		VaultAssetID: command.vaultAssetID,
		ReturnCode:   returnCode,
	}
}

type biometricDeploymentResult struct {
	Operation    string `json:"operation,omitempty"`
	Status       string `json:"status"`
	DeviceSN     string `json:"deviceSn"`
	SHA256       string `json:"sha256,omitempty"`
	ErrorCode    string `json:"errorCode,omitempty"`
	CommandID    string `json:"commandId"`
	Attempt      int    `json:"attempt,omitempty"`
	VaultAssetID string `json:"vaultAssetId,omitempty"`
	ReturnCode   int    `json:"returnCode"`
}

type pendingBiometricResult struct {
	deploymentID string
	result       biometricDeploymentResult
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

func parseBiometricDeletionReference(command string) (string, bool) {
	fields := strings.Fields(command)
	if len(fields) == 0 || fields[0] != "DELETE_BIOMETRIC_ASSET" {
		return "", false
	}
	const prefix = "DELETE_BIOMETRIC_ASSET "
	if len(fields) != 2 ||
		command != prefix+fields[1] ||
		!validBiometricUUID(fields[1]) {
		return "", true
	}
	return fields[1], true
}

func (s *ADMSServer) interceptBiometricDeploymentReference(
	deviceSN string,
	command ADMSCommand,
) bool {
	deploymentID, deleteReference := parseBiometricDeletionReference(command.Command)
	if !deleteReference {
		var reference bool
		deploymentID, reference = parseBiometricDeploymentReference(command.Command)
		if !reference {
			return false
		}
	}
	if !validBiometricUUID(command.CloudID) ||
		!validBiometricUUID(deploymentID) ||
		!validDeliveryIdentifier(deviceSN) {
		if !deleteReference && command.CloudID != "" {
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
		processContext := withReservedBiometricDeploymentCommandID(
			ctx,
			command.CloudID,
		)
		if deleteReference {
			_ = s.agent.ProcessBiometricDeletion(
				processContext,
				deploymentID,
				deviceSN,
			)
			return
		}
		_ = s.agent.ProcessBiometricDeployment(
			processContext,
			deploymentID,
			deviceSN,
		)
	}()
	return true
}

func (a *Agent) ProcessBiometricDeletion(
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

	claimed, err := a.claimBiometricDeletion(
		ctx,
		deploymentID,
		deviceSN,
		commandID,
		nil,
	)
	if err != nil {
		return err
	}
	if claimed == nil {
		return nil
	}
	a.adms.supersedeSecretDeployment(deploymentID, commandID)

	metadata := biometricDeletionMetadata{
		PersonnelID: claimed.PersonnelID,
		Kind:        claimed.Asset.Kind,
		BioType:     claimed.Asset.BioType,
		SlotIndex:   claimed.Asset.SlotIndex,
	}
	state, found := a.devices.protocolState(deviceSN)
	if !found {
		err = deliveryError("target_profile_untrusted")
		retainReservation = true
		a.reportBiometricDeletionFailure(ctx, claimed, deliveryErrorCode(err))
		return err
	}
	rendered, renderCode := renderBiometricDeletionCommand(state, metadata)
	if renderCode != "" {
		zeroBytes(rendered)
		err = deliveryError(renderCode)
		retainReservation = true
		a.reportBiometricDeletionFailure(ctx, claimed, renderCode)
		return err
	}
	renderedOwnedByQueue := false
	defer func() {
		if !renderedOwnedByQueue {
			zeroBytes(rendered)
		}
	}()
	if ctx.Err() != nil {
		return deliveryError("deployment_cancelled")
	}

	rechecked, err := a.claimBiometricDeletion(
		ctx,
		deploymentID,
		deviceSN,
		commandID,
		&biometricDeletionRecheck{
			Attempt:      claimed.Attempt,
			VaultAssetID: claimed.VaultAssetID,
		},
	)
	if err != nil {
		return err
	}
	if !sameClaimedBiometricDeletion(claimed, rechecked) {
		return deliveryError("stale_deployment_attempt")
	}
	if ctx.Err() != nil {
		return deliveryError("deployment_cancelled")
	}

	queued := a.adms.enqueueSecretCommand(&secretADMSCommand{
		deviceSN:       deviceSN,
		deploymentID:   deploymentID,
		commandID:      commandID,
		operation:      "delete",
		attempt:        claimed.Attempt,
		vaultAssetID:   claimed.VaultAssetID,
		deleteMetadata: metadata,
		payload:        rendered,
	})
	if !queued {
		err = deliveryError("secret_command_queue_full")
		retainReservation = true
		a.reportBiometricDeletionFailure(ctx, claimed, deliveryErrorCode(err))
		return err
	}
	renderedOwnedByQueue = true
	retainReservation = true
	return nil
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

	claimed, err := a.claimBiometricDeployment(
		ctx,
		deploymentID,
		deviceSN,
		commandID,
	)
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
			retainReservation = true
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
		retainReservation = true
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
		retainReservation = true
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
		retainReservation = true
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
	deviceSN,
	expectedCommandID string,
) (*claimedBiometricDeployment, error) {
	requestBody, err := json.Marshal(struct {
		DeploymentID      string `json:"deploymentId"`
		DeviceSN          string `json:"deviceSn"`
		ExpectedCommandID string `json:"expectedCommandId"`
	}{
		DeploymentID:      deploymentID,
		DeviceSN:          deviceSN,
		ExpectedCommandID: expectedCommandID,
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
	if !validBiometricUUID(claimed.CommandID) ||
		claimed.CommandID != expectedCommandID {
		return nil, deliveryError("stale_deployment_command")
	}
	if !validClaimedBiometricDeployment(claimed, deploymentID, deviceSN) {
		return nil, deliveryError("invalid_deployment_claim")
	}
	return &claimed, nil
}

type biometricDeletionRecheck struct {
	Attempt      int    `json:"attempt"`
	VaultAssetID string `json:"vaultAssetId"`
}

type claimedBiometricDeletion struct {
	Operation    string `json:"operation"`
	DeploymentID string `json:"deploymentId"`
	CommandID    string `json:"commandId"`
	Attempt      int    `json:"attempt"`
	DeviceSN     string `json:"deviceSn"`
	PersonnelID  string `json:"personnelId"`
	VaultAssetID string `json:"vaultAssetId"`
	Asset        struct {
		Kind      string `json:"kind"`
		BioType   int    `json:"bioType"`
		SlotIndex int    `json:"slotIndex"`
	} `json:"asset"`
}

func (a *Agent) claimBiometricDeletion(
	ctx context.Context,
	deploymentID,
	deviceSN,
	expectedCommandID string,
	recheck *biometricDeletionRecheck,
) (*claimedBiometricDeletion, error) {
	requestInput := struct {
		DeploymentID      string                    `json:"deploymentId"`
		DeviceSN          string                    `json:"deviceSn"`
		ExpectedCommandID string                    `json:"expectedCommandId"`
		Recheck           *biometricDeletionRecheck `json:"recheck,omitempty"`
	}{
		DeploymentID:      deploymentID,
		DeviceSN:          deviceSN,
		ExpectedCommandID: expectedCommandID,
		Recheck:           recheck,
	}
	requestBody, err := json.Marshal(requestInput)
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
	if !exactBiometricHeader(response.Header, "Cache-Control", "no-store") {
		return nil, deliveryError("invalid_deployment_claim")
	}
	body, err := io.ReadAll(io.LimitReader(
		response.Body,
		maxBiometricClaimBodyBytes+1,
	))
	if err != nil || len(body) > maxBiometricClaimBodyBytes {
		zeroBytes(body)
		return nil, deliveryError("invalid_deployment_claim")
	}
	defer zeroBytes(body)
	if !jsonHasUniqueObjectMembers(body) {
		return nil, deliveryError("invalid_deployment_claim")
	}

	var envelope struct {
		Deployments []json.RawMessage `json:"deployments"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil {
		return nil, deliveryError("invalid_deployment_claim")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return nil, deliveryError("invalid_deployment_claim")
	}
	if len(envelope.Deployments) == 0 {
		return nil, nil
	}
	if len(envelope.Deployments) != 1 {
		return nil, deliveryError("invalid_deployment_claim")
	}
	var claimed claimedBiometricDeletion
	decoder = json.NewDecoder(bytes.NewReader(envelope.Deployments[0]))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&claimed) != nil || decoder.Decode(&trailing) != io.EOF {
		return nil, deliveryError("invalid_deployment_claim")
	}
	if claimed.CommandID != expectedCommandID {
		return nil, deliveryError("stale_deployment_command")
	}
	if !validClaimedBiometricDeletion(claimed, deploymentID, deviceSN) {
		return nil, deliveryError("invalid_deployment_claim")
	}
	if recheck != nil &&
		(claimed.Attempt != recheck.Attempt ||
			claimed.VaultAssetID != recheck.VaultAssetID) {
		return nil, deliveryError("stale_deployment_attempt")
	}
	return &claimed, nil
}

func validClaimedBiometricDeletion(
	claimed claimedBiometricDeletion,
	deploymentID,
	deviceSN string,
) bool {
	if claimed.Operation != "delete" ||
		claimed.DeploymentID != deploymentID ||
		claimed.DeviceSN != deviceSN ||
		!validBiometricUUID(claimed.CommandID) ||
		!validBiometricUUID(claimed.VaultAssetID) ||
		claimed.Attempt < 1 ||
		claimed.Attempt > 5 ||
		!validDeliveryIdentifier(claimed.PersonnelID) ||
		claimed.Asset.SlotIndex < 0 ||
		claimed.Asset.SlotIndex > 9 {
		return false
	}
	switch claimed.Asset.Kind {
	case "fingerprint_template":
		return claimed.Asset.BioType == 1
	case "face_template", "face_comparison_photo":
		return claimed.Asset.BioType == 9
	default:
		return false
	}
}

func sameClaimedBiometricDeletion(
	left,
	right *claimedBiometricDeletion,
) bool {
	return left != nil &&
		right != nil &&
		left.Operation == right.Operation &&
		left.DeploymentID == right.DeploymentID &&
		left.CommandID == right.CommandID &&
		left.Attempt == right.Attempt &&
		left.DeviceSN == right.DeviceSN &&
		left.PersonnelID == right.PersonnelID &&
		left.VaultAssetID == right.VaultAssetID &&
		left.Asset.Kind == right.Asset.Kind &&
		left.Asset.BioType == right.Asset.BioType &&
		left.Asset.SlotIndex == right.Asset.SlotIndex
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
	if response.ContentLength < 0 ||
		response.ContentLength != int64(metadata.ByteCount) {
		return nil, deliveryError("payload_size_mismatch")
	}

	payload, err := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
	if err != nil {
		zeroBytes(payload)
		return nil, classifyBiometricRequestError(ctx, "network_unavailable")
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
	return exactBiometricHeader(headers, "Content-Type", "application/octet-stream") &&
		exactBiometricHeader(headers, "Cache-Control", "no-store") &&
		exactBiometricHeader(headers, "X-Content-SHA256", metadata.SHA256) &&
		exactBiometricHeader(headers, "X-Asset-Kind", metadata.Kind) &&
		exactBiometricHeader(headers, "X-Biometric-Type", strconv.Itoa(metadata.BioType)) &&
		exactBiometricHeader(headers, "X-Slot-Index", strconv.Itoa(metadata.SlotIndex)) &&
		exactBiometricHeader(headers, "X-Algorithm-Family", metadata.AlgorithmFamily) &&
		exactBiometricHeader(headers, "X-Algorithm-Major", strconv.Itoa(metadata.AlgorithmMajor)) &&
		exactBiometricHeader(headers, "X-Algorithm-Minor", strconv.Itoa(metadata.AlgorithmMinor)) &&
		exactBiometricHeader(headers, "X-Asset-Format", metadata.Format)
}

func exactBiometricHeader(headers http.Header, name, expected string) bool {
	values := headers.Values(name)
	return len(values) == 1 && values[0] == expected
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

func renderBiometricDeletionCommand(
	state DeviceProtocolState,
	metadata biometricDeletionMetadata,
) ([]byte, string) {
	renderer, code := validateLiveBiometricDeletion(state, metadata)
	if code != "" {
		return nil, code
	}
	command := make([]byte, 0, 128)
	switch renderer {
	case "finger_fp":
		command = append(command, "DATA DELETE FP PIN="...)
		command = append(command, metadata.PersonnelID...)
		command = append(command, "\tFID="...)
		command = strconv.AppendInt(command, int64(metadata.SlotIndex), 10)
	case "finger_legacy":
		command = append(command, "DATA DELETE FINGERTMP PIN="...)
		command = append(command, metadata.PersonnelID...)
		command = append(command, "\tFID="...)
		command = strconv.AppendInt(command, int64(metadata.SlotIndex), 10)
	case "biodata":
		command = append(command, "DATA DELETE BIODATA Pin="...)
		command = append(command, metadata.PersonnelID...)
		command = append(command, "\tNo="...)
		command = strconv.AppendInt(command, int64(metadata.SlotIndex), 10)
		command = append(command, "\tType="...)
		command = strconv.AppendInt(command, int64(metadata.BioType), 10)
	case "biophoto":
		command = append(command, "DATA DELETE BIOPHOTO PIN="...)
		command = append(command, metadata.PersonnelID...)
		command = append(command, "\tNo="...)
		command = strconv.AppendInt(command, int64(metadata.SlotIndex), 10)
		command = append(command, "\tType=9"...)
	default:
		return nil, "record_type_unsupported"
	}
	return command, ""
}

func validateLiveBiometricDeletion(
	state DeviceProtocolState,
	metadata biometricDeletionMetadata,
) (string, string) {
	if state.Confidence < 80 || state.Confidence > 100 {
		return "", "target_profile_untrusted"
	}
	if !validDeliveryIdentifier(metadata.PersonnelID) ||
		metadata.SlotIndex < 0 ||
		metadata.SlotIndex > 9 {
		return "", "invalid_deployment_claim"
	}
	switch metadata.Kind {
	case "fingerprint_template":
		if metadata.BioType != 1 {
			return "", "invalid_deployment_claim"
		}
	case "face_template", "face_comparison_photo":
		if metadata.BioType != 9 {
			return "", "invalid_deployment_claim"
		}
	default:
		return "", "invalid_deployment_claim"
	}

	capabilities := normalizeCapabilities(state.Capabilities)
	switch state.Profile {
	case ProtocolTAPush:
		taVersion, valid := approvedTAPushVersion(state.PushVersion)
		if !valid {
			return "", "target_profile_untrusted"
		}
		if metadata.Kind != "fingerprint_template" ||
			capabilities["fingerfunon"] != "1" {
			return "", "record_type_unsupported"
		}
		major, _, valid := algorithmVersion(
			capabilities["fingeralgorithmversion"],
		)
		if !valid {
			return "", "algorithm_unknown"
		}
		if major <= 10 {
			if comparePushVersion(taVersion, [3]int{2, 2, 14}) < 0 {
				return "finger_fp", ""
			}
			return "finger_legacy", ""
		}
		if capabilities["biodatafun"] != "1" {
			return "", "record_type_unsupported"
		}
		return "biodata", ""
	case ProtocolACPush3:
		switch metadata.Kind {
		case "fingerprint_template":
			if capabilities["fingerfunon"] != "1" ||
				capabilities["biodatafun"] != "1" {
				return "", "record_type_unsupported"
			}
			if _, _, valid := algorithmVersion(
				capabilities["fingeralgorithmversion"],
			); !valid {
				return "", "algorithm_unknown"
			}
			return "biodata", ""
		case "face_template":
			if capabilities["facefunon"] != "1" ||
				capabilities["biodatafun"] != "1" {
				return "", "record_type_unsupported"
			}
			if _, _, valid := algorithmVersion(
				capabilities["facealgorithmversion"],
			); !valid {
				return "", "algorithm_unknown"
			}
			return "biodata", ""
		case "face_comparison_photo":
			if capabilities["facefunon"] != "1" ||
				capabilities["biophotofun"] != "1" {
				return "", "record_type_unsupported"
			}
			return "biophoto", ""
		}
	}
	return "", "target_profile_untrusted"
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
			(character >= 'a' && character <= 'f')) {
			return false
		}
	}
	if value[14] < '1' || value[14] > '5' {
		return false
	}
	switch value[19] {
	case '8', '9', 'a', 'b':
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
	encoding := base64.RawURLEncoding.Strict()
	if len(value) != encoding.EncodedLen(32) {
		return false
	}
	decoded, err := encoding.DecodeString(value)
	valid := err == nil &&
		len(decoded) == 32 &&
		encoding.EncodeToString(decoded) == value
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
	if !validBiometricUUID(commandID) {
		return false, "stale_deployment_command"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.secretClosed {
		return false, "deployment_cancelled"
	}
	if s.resultOutbox == nil || s.resultOutboxErr != nil {
		return false, "deployment_delivery_unavailable"
	}
	if s.secretCmdID == nil {
		s.secretCmdID = make(map[string]struct{})
	}
	if _, exists := s.secretCmdID[commandID]; exists {
		return false, ""
	}
	if pendingResult, capacity := s.resultOutbox.admission(
		commandID,
		len(s.secretCmdID),
	); pendingResult {
		return false, ""
	} else if !capacity {
		return false, "secret_command_queue_full"
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
	if command == nil ||
		!validBiometricUUID(command.deploymentID) ||
		!validBiometricUUID(command.commandID) ||
		!validDeliveryIdentifier(command.deviceSN) {
		return false
	}
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
	var removed []*secretADMSCommand
	for deviceSN, queue := range s.secretCmdQueue {
		retained := queue[:0]
		for _, command := range queue {
			if command.deploymentID == deploymentID &&
				command.commandID != currentCommandID {
				removed = append(removed, command)
				continue
			}
			retained = append(retained, command)
		}
		s.secretCmdQueue[deviceSN] = retained
	}
	for _, command := range s.secretPending {
		if command.deploymentID == deploymentID &&
			command.commandID != currentCommandID {
			if s.detachExactPendingSecretCommandLocked(command) {
				removed = append(removed, command)
			}
		}
	}
	s.mu.Unlock()
	for _, command := range removed {
		command.zeroPayload()
	}
	s.mu.Lock()
	for _, command := range removed {
		delete(s.secretCmdID, command.commandID)
	}
	s.mu.Unlock()
}

func (s *ADMSServer) popSecretCommand(deviceSN string) *secretADMSCommand {
	command, _ := s.claimSecretCommandWriter(deviceSN)
	return command
}

func (s *ADMSServer) claimSecretCommandWriter(
	deviceSN string,
) (*secretADMSCommand, bool) {
	s.mu.Lock()
	for key, command := range s.secretPending {
		if key.DeviceSN != deviceSN {
			continue
		}
		if command.writerActive {
			s.mu.Unlock()
			return nil, true
		}
		if command.serveAttempts >= maxSecretCommandServeAttempts ||
			(!command.firstServedAt.IsZero() &&
				!s.secretCommandNow().Before(
					command.firstServedAt.Add(secretCommandServeDeadline),
				)) {
			s.detachExactPendingSecretCommandLocked(command)
			s.mu.Unlock()
			command.zeroPayload()
			s.mu.Lock()
			wake := s.enqueueBiometricResultLocked(command.result(
				"failed",
				"network_unavailable",
				-1,
			), command.deploymentID)
			s.mu.Unlock()
			if wake {
				s.wakeBiometricResultOutbox()
			}
			return nil, false
		}
		command.writerActive = true
		command.serveAttempts++
		s.mu.Unlock()
		return command, false
	}
	queue := s.secretCmdQueue[deviceSN]
	if len(queue) == 0 {
		s.mu.Unlock()
		return nil, false
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
	command.firstServedAt = s.secretCommandNow()
	command.serveAttempts = 1
	command.writerActive = true
	s.scheduleSecretCommandDeadlineLocked(command)
	s.mu.Unlock()
	return command, false
}

func (s *ADMSServer) secretCommandNow() time.Time {
	if s.secretNow != nil {
		return s.secretNow()
	}
	return time.Now()
}

func (s *ADMSServer) scheduleSecretCommandDeadlineLocked(
	command *secretADMSCommand,
) {
	callback := func() {
		s.expirePendingSecretCommand(command)
	}
	if s.secretAfterFunc != nil {
		command.deadlineStop = s.secretAfterFunc(
			secretCommandServeDeadline,
			callback,
		)
		return
	}
	timer := time.AfterFunc(secretCommandServeDeadline, callback)
	command.deadlineStop = timer.Stop
}

func (command *secretADMSCommand) stopDeadlineLocked() {
	if command.deadlineStop != nil {
		command.deadlineStop()
		command.deadlineStop = nil
	}
}

func (s *ADMSServer) expirePendingSecretCommand(command *secretADMSCommand) {
	key := pendingCommandKey{DeviceSN: command.deviceSN, LocalID: command.id}
	s.mu.Lock()
	current, exists := s.secretPending[key]
	if !exists || current != command {
		s.mu.Unlock()
		return
	}
	command.deadlineStop = nil
	s.detachExactPendingSecretCommandLocked(command)
	s.mu.Unlock()
	command.zeroPayload()
	s.mu.Lock()
	wake := s.enqueueBiometricResultLocked(command.result(
		"failed",
		"network_unavailable",
		-1,
	), command.deploymentID)
	s.mu.Unlock()
	if wake {
		s.wakeBiometricResultOutbox()
	}
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
	if command.operation == "delete" {
		_, code := validateLiveBiometricDeletion(state, command.deleteMetadata)
		return code
	}
	return validateLiveBiometricRenderer(state, command.metadata)
}

func writeSecretADMSCommand(w http.ResponseWriter, command *secretADMSCommand) error {
	command.payloadMu.Lock()
	defer command.payloadMu.Unlock()
	return writeSecretADMSCommandLocked(w, command)
}

func (s *ADMSServer) writePendingSecretADMSCommand(
	w http.ResponseWriter,
	command *secretADMSCommand,
) (bool, error) {
	key := pendingCommandKey{DeviceSN: command.deviceSN, LocalID: command.id}
	command.payloadMu.Lock()
	s.mu.Lock()
	current, exists := s.secretPending[key]
	if !exists || current != command || !command.writerActive {
		s.mu.Unlock()
		command.payloadMu.Unlock()
		return false, nil
	}
	if len(command.payload) == 0 {
		command.writerActive = false
		s.mu.Unlock()
		command.payloadMu.Unlock()
		return false, nil
	}
	s.mu.Unlock()

	writeTimeout := s.secretWriteTimeout
	if writeTimeout <= 0 {
		writeTimeout = secretCommandWriteTimeout
	}
	controller := http.NewResponseController(w)
	_ = controller.SetWriteDeadline(time.Now().Add(writeTimeout))
	err := writeSecretADMSCommandLocked(w, command)
	command.payloadMu.Unlock()
	if err != nil {
		if secretCommandWriteTimedOut(err) {
			s.failServedSecretCommand(
				command,
				"network_unavailable",
				-1,
			)
		} else {
			s.releaseSecretCommandWriter(command)
		}
		return false, err
	}
	s.releaseSecretCommandWriter(command)
	return true, nil
}

func (s *ADMSServer) releaseSecretCommandWriter(command *secretADMSCommand) {
	key := pendingCommandKey{DeviceSN: command.deviceSN, LocalID: command.id}
	s.mu.Lock()
	if current, exists := s.secretPending[key]; exists && current == command {
		command.writerActive = false
	}
	s.mu.Unlock()
}

func (s *ADMSServer) detachExactPendingSecretCommandLocked(
	command *secretADMSCommand,
) bool {
	key := pendingCommandKey{DeviceSN: command.deviceSN, LocalID: command.id}
	current, exists := s.secretPending[key]
	if !exists || current != command {
		return false
	}
	command.writerActive = false
	command.stopDeadlineLocked()
	delete(s.secretPending, key)
	return true
}

func secretCommandWriteTimedOut(err error) bool {
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}

func writeSecretADMSCommandLocked(
	w http.ResponseWriter,
	command *secretADMSCommand,
) error {
	prefix := make([]byte, 0, 32)
	prefix = append(prefix, "C:"...)
	prefix = strconv.AppendInt(prefix, int64(command.id), 10)
	prefix = append(prefix, ':')
	written, err := w.Write(prefix)
	zeroBytes(prefix)
	if err != nil {
		return errors.Join(errors.New("secret command prefix write failed"), err)
	}
	if written != len(prefix) {
		return errors.New("secret command prefix write failed")
	}
	written, err = w.Write(command.payload)
	if err != nil {
		return errors.Join(errors.New("secret command payload write failed"), err)
	}
	if written != len(command.payload) {
		return errors.New("secret command payload write failed")
	}
	return nil
}

func (s *ADMSServer) failServedSecretCommand(
	command *secretADMSCommand,
	code string,
	returnCode int,
) {
	s.mu.Lock()
	removed := s.detachExactPendingSecretCommandLocked(command)
	s.mu.Unlock()
	if !removed {
		return
	}
	command.zeroPayload()
	s.mu.Lock()
	wake := s.enqueueBiometricResultLocked(command.result(
		"failed",
		code,
		returnCode,
	), command.deploymentID)
	s.mu.Unlock()
	if wake {
		s.wakeBiometricResultOutbox()
	}
}

func (s *ADMSServer) completeSecretCommand(
	key pendingCommandKey,
	returnCode int,
) bool {
	s.mu.Lock()
	command, exists := s.secretPending[key]
	if exists {
		exists = s.detachExactPendingSecretCommandLocked(command)
	}
	if !exists {
		s.mu.Unlock()
		return false
	}
	s.mu.Unlock()
	command.zeroPayload()

	result := command.result("applied", "", returnCode)
	if returnCode != 0 {
		result.Status = "failed"
		result.ErrorCode = "device_command_failed"
	}
	s.mu.Lock()
	wake := s.enqueueBiometricResultLocked(result, command.deploymentID)
	s.mu.Unlock()
	if wake {
		s.wakeBiometricResultOutbox()
	}
	return true
}

func (s *ADMSServer) reportBiometricDeploymentFailure(
	_ context.Context,
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
	s.startBiometricResultWorker(result, deploymentID)
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

func (a *Agent) reportBiometricDeletionFailure(
	_ context.Context,
	claimed *claimedBiometricDeletion,
	code string,
) {
	if a.adms == nil || claimed == nil {
		return
	}
	a.adms.startBiometricResultWorker(biometricDeploymentResult{
		Operation:    "delete",
		Status:       "failed",
		DeviceSN:     claimed.DeviceSN,
		ErrorCode:    code,
		CommandID:    claimed.CommandID,
		Attempt:      claimed.Attempt,
		VaultAssetID: claimed.VaultAssetID,
		ReturnCode:   -1,
	}, claimed.DeploymentID)
}

func (s *ADMSServer) startBiometricResultWorker(
	result biometricDeploymentResult,
	deploymentID string,
) {
	s.mu.Lock()
	wake := s.enqueueBiometricResultLocked(result, deploymentID)
	s.mu.Unlock()
	if wake {
		s.wakeBiometricResultOutbox()
	}
}

func (s *ADMSServer) enqueueBiometricResultLocked(
	result biometricDeploymentResult,
	deploymentID string,
) bool {
	if !validBiometricUUID(deploymentID) ||
		!validBiometricUUID(result.CommandID) ||
		!validDeliveryIdentifier(result.DeviceSN) {
		delete(s.resultEnqueuePending, result.CommandID)
		delete(s.secretCmdID, result.CommandID)
		return false
	}
	if s.resultOutbox == nil {
		delete(s.secretCmdID, result.CommandID)
		return false
	}
	if err := s.resultOutbox.enqueueWithCommit(
		deploymentID,
		result,
		time.Now(),
		func() {
			delete(s.resultEnqueuePending, result.CommandID)
			delete(s.secretCmdID, result.CommandID)
		},
	); err != nil {
		if s.resultEnqueuePending == nil {
			s.resultEnqueuePending = make(map[string]pendingBiometricResult)
		}
		if _, exists := s.resultEnqueuePending[result.CommandID]; !exists {
			s.resultEnqueuePending[result.CommandID] = pendingBiometricResult{
				deploymentID: deploymentID,
				result:       result,
			}
		}
		return s.agent != nil
	}
	return true
}

func (s *ADMSServer) flushPendingBiometricResults() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.resultEnqueuePending) == 0 {
		return true
	}
	if s.resultOutbox == nil {
		return false
	}
	flushed := true
	for commandID, pending := range s.resultEnqueuePending {
		if err := s.resultOutbox.enqueueWithCommit(
			pending.deploymentID,
			pending.result,
			time.Now(),
			func() {
				delete(s.resultEnqueuePending, commandID)
				delete(s.secretCmdID, commandID)
			},
		); err != nil {
			flushed = false
			continue
		}
	}
	return flushed
}

func (s *ADMSServer) pendingSecretCommandID(deviceSN string, localID int) bool {
	s.mu.Lock()
	_, exists := s.secretPending[pendingCommandKey{
		DeviceSN: deviceSN,
		LocalID:  localID,
	}]
	s.mu.Unlock()
	return exists
}

type deviceCommandACKRoute uint8

const (
	deviceCommandACKUnknown deviceCommandACKRoute = iota
	deviceCommandACKGeneric
	deviceCommandACKSecret
)

func (s *ADMSServer) routeDeviceCommandACK(
	deviceSN string,
	body []byte,
) deviceCommandACKRoute {
	localIDs := inspectDeviceCommandRoutingIDs(body)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, localID := range localIDs {
		if _, exists := s.secretPending[pendingCommandKey{
			DeviceSN: deviceSN,
			LocalID:  localID,
		}]; exists {
			return deviceCommandACKSecret
		}
	}
	for _, localID := range localIDs {
		if _, exists := s.pendingCmd[pendingCommandKey{
			DeviceSN: deviceSN,
			LocalID:  localID,
		}]; exists {
			return deviceCommandACKGeneric
		}
	}
	return deviceCommandACKUnknown
}

func inspectDeviceCommandRoutingIDs(body []byte) []int {
	localIDs := make([]int, 0, 1)
	for _, field := range bytes.Split(body, []byte{'&'}) {
		key, value, found := bytes.Cut(field, []byte{'='})
		if !found {
			continue
		}
		routingKey, valid := decodeACKRoutingComponent(key)
		if !valid || !bytes.Equal(routingKey, []byte("ID")) {
			zeroBytes(routingKey)
			continue
		}
		zeroBytes(routingKey)
		routingValue, valid := decodeACKRoutingComponent(value)
		if !valid {
			zeroBytes(routingValue)
			continue
		}
		localID, valid := strictACKInteger(
			routingValue,
			1,
			int(^uint32(0)>>1),
		)
		zeroBytes(routingValue)
		if valid {
			localIDs = append(localIDs, localID)
		}
	}
	return localIDs
}

func decodeACKRoutingComponent(value []byte) ([]byte, bool) {
	decoded := make([]byte, 0, len(value))
	for index := 0; index < len(value); index++ {
		switch value[index] {
		case '+':
			decoded = append(decoded, ' ')
		case '%':
			if index+2 >= len(value) {
				return decoded, false
			}
			high, highValid := ackHexNibble(value[index+1])
			low, lowValid := ackHexNibble(value[index+2])
			if !highValid || !lowValid {
				return decoded, false
			}
			decoded = append(decoded, high<<4|low)
			index += 2
		default:
			decoded = append(decoded, value[index])
		}
	}
	return decoded, true
}

func ackHexNibble(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	case value >= 'A' && value <= 'F':
		return value - 'A' + 10, true
	default:
		return 0, false
	}
}

func (s *ADMSServer) handleSecretDeviceCommandACK(
	deviceSN string,
	body []byte,
) (handled, accepted bool) {
	defer zeroBytes(body)
	localID, returnCode, valid := parseSecretDeviceCommandACK(body)
	if localID <= 0 || !s.pendingSecretCommandID(deviceSN, localID) {
		return false, false
	}
	if !valid {
		return true, false
	}
	return true, s.completeSecretCommand(
		pendingCommandKey{DeviceSN: deviceSN, LocalID: localID},
		returnCode,
	)
}

func parseSecretDeviceCommandACK(body []byte) (localID, returnCode int, valid bool) {
	if len(body) == 0 || len(body) > maxSecretACKBodyBytes {
		return inspectSecretDeviceCommandID(body), 0, false
	}
	fields := bytes.Split(body, []byte{'&'})
	if len(fields) != 2 {
		return inspectSecretDeviceCommandID(body), 0, false
	}
	seenID, seenReturn := false, false
	for _, field := range fields {
		key, value, found := bytes.Cut(field, []byte{'='})
		if !found || len(key) == 0 || len(value) == 0 {
			return inspectSecretDeviceCommandID(body), 0, false
		}
		switch {
		case bytes.Equal(key, []byte("ID")) && !seenID:
			parsed, ok := strictACKInteger(value, 1, int(^uint32(0)>>1))
			if !ok {
				return 0, 0, false
			}
			localID, seenID = parsed, true
		case bytes.Equal(key, []byte("Return")) && !seenReturn:
			parsed, ok := strictACKInteger(value, -1_000_000, 1_000_000)
			if !ok {
				return localID, 0, false
			}
			returnCode, seenReturn = parsed, true
		default:
			return inspectSecretDeviceCommandID(body), 0, false
		}
	}
	return localID, returnCode, seenID && seenReturn
}

func inspectSecretDeviceCommandID(body []byte) int {
	for _, field := range bytes.Split(body, []byte{'&'}) {
		key, value, found := bytes.Cut(field, []byte{'='})
		if !found || !bytes.Equal(key, []byte("ID")) {
			continue
		}
		parsed, ok := strictACKInteger(value, 1, int(^uint32(0)>>1))
		if ok {
			return parsed
		}
	}
	return 0
}

func strictACKInteger(value []byte, minimum, maximum int) (int, bool) {
	if len(value) == 0 {
		return 0, false
	}
	negative := false
	index := 0
	if value[0] == '-' {
		negative = true
		index = 1
		if index == len(value) {
			return 0, false
		}
	}
	number := 0
	for ; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return 0, false
		}
		digit := int(value[index] - '0')
		if number > (maximum+1-digit)/10 {
			return 0, false
		}
		number = number*10 + digit
	}
	if negative {
		number = -number
	}
	return number, number >= minimum && number <= maximum
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
	var removed []*secretADMSCommand
	for deviceSN, queue := range s.secretCmdQueue {
		removed = append(removed, queue...)
		delete(s.secretCmdQueue, deviceSN)
	}
	for _, command := range s.secretPending {
		if s.detachExactPendingSecretCommandLocked(command) {
			removed = append(removed, command)
		}
	}
	clear(s.secretCmdID)
	s.mu.Unlock()
	for _, command := range removed {
		command.zeroPayload()
	}
	s.biometricDeliveryWorkers.Wait()
}
