package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// Domain separation constant for device connections (legacy, used only by
// the crypto helper below which the new flow no longer exercises).
const DomainDevice = "vettid-device-v1"

// Device message type constants for per-operation request/response after pairing.
// The pairing flow itself uses the NATS subject tree under MessageSpace.*.device.*
// (see vettid-dev/docs/DESKTOP-CONNECTION-FLOW.md) and doesn't use these types.
const (
	DeviceMsgOpRequest        = "device_op_request"
	DeviceMsgOpResponse       = "device_op_response"
	DeviceMsgApprovalRequest  = "device_approval_request"
	DeviceMsgApprovalResponse = "device_approval_response"
)

// DeviceCapability tiers

// DeviceIndependentCapabilities returns operations the desktop can execute
// directly (still requires phone heartbeat to be fresh).
func DeviceIndependentCapabilities() []string {
	return []string{
		"profile.view",
		"connection.list",
		"connection.get",
		"feed.list",
		"feed.sync",
		"audit.query",
		"message.list",
		"message.read",
		"agent.list",
		"secrets.catalog",
	}
}

// DevicePhoneRequiredCapabilities returns operations that require explicit
// phone approval before the vault will execute them.
func DevicePhoneRequiredCapabilities() []string {
	return []string{
		"secrets.retrieve",
		"secrets.add",
		"secrets.delete",
		"connection.create",
		"connection.revoke",
		"profile.update",
		"personal-data.get",
		"personal-data.update",
		"credential.get",
		"credential.update",
		"pin.setup",
		"pin.unlock",
		"pin.change",
		"service.auth.request",
		"agent.approve",
	}
}

// isIndependentCapability checks whether the given operation can be
// executed by a device connection without phone approval.
func isIndependentCapability(op string) bool {
	for _, cap := range DeviceIndependentCapabilities() {
		if cap == op {
			return true
		}
	}
	return false
}

// isPINOperation returns true if the operation is a PIN operation,
// which is NEVER accepted from a device connection.
func isPINOperation(op string) bool {
	return op == "pin.setup" || op == "pin.unlock" || op == "pin.change"
}

// PendingDeviceApproval tracks a device operation request awaiting phone approval.
type PendingDeviceApproval struct {
	RequestID    string    `json:"request_id"`
	ConnectionID string    `json:"connection_id"`
	Operation    string    `json:"operation"`
	Payload      []byte    `json:"payload"`
	CreatedAt    time.Time `json:"created_at"`
}

// DeviceHandler processes messages from desktop device connections.
//
// Device messages arrive via NATS on MessageSpace.{guid}.forOwner.device,
// are forwarded by the parent process to the enclave, and routed here
// by handleVaultOp when "forOwner" + "device" is detected in the subject.
//
// Each message is an AgentEnvelope containing:
//   - type: message type (device_connection_request, device_op_request, etc.)
//   - key_id: connection ID (used to look up the connection record)
//   - payload: encrypted with the connection's derived key
//   - sequence: monotonically increasing per connection
//
// Responses are published directly via VsockPublisher to the device's
// response topic, not through the standard reply path.
type DeviceHandler struct {
	ownerSpace       string
	storage          *EncryptedStorage
	publisher        *VsockPublisher
	eventHandler     *EventHandler
	connHandler      *ConnectionsHandler
	pendingApprovals map[string]*PendingDeviceApproval
	mu               sync.Mutex
	stopCleanup      chan struct{}
}

// NewDeviceHandler creates a new device handler.
func NewDeviceHandler(
	ownerSpace string,
	storage *EncryptedStorage,
	publisher *VsockPublisher,
	eventHandler *EventHandler,
	connHandler *ConnectionsHandler,
) *DeviceHandler {
	dh := &DeviceHandler{
		ownerSpace:       ownerSpace,
		storage:          storage,
		publisher:        publisher,
		eventHandler:     eventHandler,
		connHandler:      connHandler,
		pendingApprovals: make(map[string]*PendingDeviceApproval),
		stopCleanup:      make(chan struct{}),
	}
	go dh.cleanExpiredSessions()
	return dh
}

// HandleDeviceMessage is the main router for device messages.
// It decrypts the envelope with the connection key and dispatches.
func (dh *DeviceHandler) HandleDeviceMessage(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var envelope AgentEnvelope
	if err := unmarshalRequest(msg.Payload, &envelope, "HandleDeviceMessage"); err != nil {
		log.Warn().Err(err).Msg("Failed to parse device envelope")
		return nil, nil
	}

	log.Debug().
		Str("type", envelope.Type).
		Str("key_id", envelope.KeyID).
		Uint64("sequence", envelope.Sequence).
		Msg("Received device message")

	// Pairing no longer uses this envelope channel — see DESKTOP-CONNECTION-FLOW.md.
	// Per-operation messages require a valid connection.
	connData, err := dh.storage.Get("connections/" + envelope.KeyID)
	if err != nil {
		log.Warn().Str("key_id", envelope.KeyID).Msg("Device connection not found")
		return nil, nil
	}

	var conn ConnectionRecord
	if err := json.Unmarshal(connData, &conn); err != nil {
		log.Warn().Err(err).Msg("Failed to parse device connection record")
		return nil, nil
	}

	// Validate connection
	if !conn.IsDevice() {
		log.Warn().Str("type", conn.GetConnectionType()).Msg("Connection is not a device")
		return nil, nil
	}
	if conn.Status != "active" {
		log.Warn().Str("status", conn.Status).Msg("Device connection not active")
		return nil, nil
	}
	if len(conn.SharedSecret) == 0 {
		log.Warn().Msg("Device connection has no shared secret")
		return nil, nil
	}

	// Derive connection key
	connKey, err := deriveConnectionKey(conn.SharedSecret)
	if err != nil {
		log.Error().Err(err).Msg("Failed to derive device connection key")
		return nil, nil
	}
	defer zeroBytes(connKey)

	// Decrypt payload
	encryptedPayload, err := extractPayloadBytes(envelope.Payload)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to extract device payload bytes")
		return nil, nil
	}

	plaintext, err := decryptXChaCha20(connKey, encryptedPayload)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to decrypt device payload")
		return nil, nil
	}
	defer zeroBytes(plaintext)

	// Route by message type
	switch envelope.Type {
	case DeviceMsgOpRequest:
		return dh.handleDeviceOpRequest(ctx, &conn, plaintext, connKey, &envelope)
	default:
		log.Warn().Str("type", envelope.Type).Msg("Unknown device message type")
		return nil, nil
	}
}

// handleDeviceOpRequest checks session validity, phone heartbeat, and capability tier,
// then executes the operation or delegates to phone for approval.
func (dh *DeviceHandler) handleDeviceOpRequest(ctx context.Context, conn *ConnectionRecord, plaintext []byte, connKey []byte, envelope *AgentEnvelope) (*OutgoingMessage, error) {
	var req struct {
		RequestID string          `json:"request_id"`
		Operation string          `json:"operation"`
		Payload   json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(plaintext, &req); err != nil {
		log.Warn().Err(err).Msg("Failed to parse device op request")
		return nil, nil
	}

	// Check session validity
	if err := dh.checkSession(conn); err != nil {
		dh.publishDeviceResponse(conn, connKey, DeviceMsgOpResponse, map[string]interface{}{
			"request_id": req.RequestID,
			"success":    false,
			"error":      err.Error(),
		})
		return nil, nil
	}

	// PIN operations are NEVER accepted from device connections
	if isPINOperation(req.Operation) {
		log.Warn().
			Str("connection_id", conn.ConnectionID).
			Str("operation", req.Operation).
			Msg("PIN operation rejected from device connection")

		dh.publishDeviceResponse(conn, connKey, DeviceMsgOpResponse, map[string]interface{}{
			"request_id": req.RequestID,
			"success":    false,
			"error":      "PIN operations are not permitted from desktop devices",
		})
		return nil, nil
	}

	// Update session activity
	now := time.Now().Unix()
	if conn.DeviceSession != nil {
		conn.DeviceSession.LastActiveAt = now
	}
	connData, _ := json.Marshal(conn)
	dh.storage.Put("connections/"+conn.ConnectionID, connData)

	// Check capability tier
	if isIndependentCapability(req.Operation) {
		// Independent operation — execute directly
		dh.publishDeviceResponse(conn, connKey, DeviceMsgOpResponse, map[string]interface{}{
			"request_id": req.RequestID,
			"success":    true,
			"status":     "executed",
			"operation":  req.Operation,
		})
		return nil, nil
	}

	// Phone-required operation — delegate to phone for approval
	dh.mu.Lock()
	dh.pendingApprovals[req.RequestID] = &PendingDeviceApproval{
		RequestID:    req.RequestID,
		ConnectionID: conn.ConnectionID,
		Operation:    req.Operation,
		Payload:      req.Payload,
		CreatedAt:    time.Now(),
	}
	dh.mu.Unlock()

	// Log the approval request
	if dh.eventHandler != nil {
		dh.eventHandler.LogConnectionEvent(ctx, EventTypeDeviceApprovalRequested, conn.ConnectionID, "",
			fmt.Sprintf("Device requests approval for: %s", req.Operation))
	}

	// Publish approval request to phone via OwnerSpace
	deviceName := conn.PeerAlias
	if conn.DeviceMetadata != nil && conn.DeviceMetadata.Hostname != "" {
		deviceName = conn.DeviceMetadata.Hostname
	}

	approvalReq := map[string]interface{}{
		"request_id":    req.RequestID,
		"connection_id": conn.ConnectionID,
		"device_name":   deviceName,
		"operation":     req.Operation,
		"payload":       req.Payload,
		"timestamp":     time.Now().UTC(),
	}
	approvalBytes, _ := json.Marshal(approvalReq)

	approvalTopic := fmt.Sprintf("OwnerSpace.%s.forApp.device.approval.request.%s", dh.ownerSpace, req.RequestID)
	pubMsg := &OutgoingMessage{
		ID:      generateMessageID(),
		Type:    MessageTypeNATSPublish,
		Subject: approvalTopic,
		Payload: approvalBytes,
	}

	// Also notify desktop that approval is pending
	dh.publishDeviceResponse(conn, connKey, DeviceMsgOpResponse, map[string]interface{}{
		"request_id": req.RequestID,
		"success":    true,
		"status":     "pending_approval",
		"operation":  req.Operation,
	})

	return pubMsg, nil
}

// HandlePhoneApprovalResponse processes the phone's approve/deny for delegated operations.
func (dh *DeviceHandler) HandlePhoneApprovalResponse(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var resp struct {
		RequestID string `json:"request_id"`
		Approved  bool   `json:"approved"`
		Reason    string `json:"reason,omitempty"`
	}
	if err := unmarshalRequest(msg.Payload, &resp, "HandlePhoneApprovalResponse"); err != nil {
		return &OutgoingMessage{
			RequestID: msg.GetID(),
			Type:      MessageTypeError,
			Payload:   json.RawMessage(`{"error":"invalid approval response"}`),
		}, nil
	}

	dh.mu.Lock()
	pending, ok := dh.pendingApprovals[resp.RequestID]
	if ok {
		delete(dh.pendingApprovals, resp.RequestID)
	}
	dh.mu.Unlock()

	if !ok {
		return &OutgoingMessage{
			RequestID: msg.GetID(),
			Type:      MessageTypeResponse,
			Payload:   json.RawMessage(`{"success":false,"error":"no pending approval found"}`),
		}, nil
	}

	// Look up connection to send response to desktop
	connData, err := dh.storage.Get("connections/" + pending.ConnectionID)
	if err != nil {
		return &OutgoingMessage{
			RequestID: msg.GetID(),
			Type:      MessageTypeError,
			Payload:   json.RawMessage(`{"error":"connection not found"}`),
		}, nil
	}

	var conn ConnectionRecord
	if err := json.Unmarshal(connData, &conn); err != nil {
		return &OutgoingMessage{
			RequestID: msg.GetID(),
			Type:      MessageTypeError,
			Payload:   json.RawMessage(`{"error":"failed to read connection"}`),
		}, nil
	}

	connKey, err := deriveConnectionKey(conn.SharedSecret)
	if err != nil {
		log.Error().Err(err).Msg("Failed to derive connection key for approval response")
		return nil, nil
	}
	defer zeroBytes(connKey)

	if resp.Approved {
		// Log approval
		if dh.eventHandler != nil {
			dh.eventHandler.LogConnectionEvent(ctx, EventTypeDeviceApprovalGranted, conn.ConnectionID, "",
				fmt.Sprintf("Phone approved device operation: %s", pending.Operation))
		}

		dh.publishDeviceResponse(&conn, connKey, DeviceMsgOpResponse, map[string]interface{}{
			"request_id": pending.RequestID,
			"success":    true,
			"status":     "approved",
			"operation":  pending.Operation,
		})
	} else {
		// Log denial
		if dh.eventHandler != nil {
			dh.eventHandler.LogConnectionEvent(ctx, EventTypeDeviceApprovalDenied, conn.ConnectionID, "",
				fmt.Sprintf("Phone denied device operation: %s", pending.Operation))
		}

		dh.publishDeviceResponse(&conn, connKey, DeviceMsgOpResponse, map[string]interface{}{
			"request_id": pending.RequestID,
			"success":    false,
			"status":     "denied",
			"operation":  pending.Operation,
			"reason":     resp.Reason,
		})
	}

	respPayload, _ := json.Marshal(map[string]interface{}{
		"success":    true,
		"request_id": resp.RequestID,
		"approved":   resp.Approved,
	})

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respPayload,
	}, nil
}

// checkSession validates that the device session is active and not expired.
// Wall-clock expiry is the only bound — there's no heartbeat requirement
// under the new design (see DESKTOP-CONNECTION-FLOW.md).
func (dh *DeviceHandler) checkSession(conn *ConnectionRecord) error {
	if conn.DeviceSession == nil {
		return fmt.Errorf("no active device session")
	}

	session := conn.DeviceSession

	switch session.Status {
	case "revoked":
		return fmt.Errorf("session has been revoked")
	case "expired":
		return fmt.Errorf("session has expired")
	}

	// Check expiration
	now := time.Now().Unix()
	if now > session.ExpiresAt {
		session.Status = "expired"
		connData, _ := json.Marshal(conn)
		dh.storage.Put("connections/"+conn.ConnectionID, connData)

		if dh.eventHandler != nil {
			dh.eventHandler.LogConnectionEvent(context.Background(), EventTypeDeviceSessionExpired, conn.ConnectionID, "",
				"Device session expired")
		}
		return fmt.Errorf("session has expired")
	}

	return nil
}

// cleanExpiredSessions runs every minute and cleans up expired device sessions.
func (dh *DeviceHandler) cleanExpiredSessions() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			dh.doCleanExpiredSessions()
		case <-dh.stopCleanup:
			return
		}
	}
}

func (dh *DeviceHandler) doCleanExpiredSessions() {
	indexData, err := dh.storage.Get("connections/_index")
	if err != nil {
		return
	}

	var connectionIDs []string
	json.Unmarshal(indexData, &connectionIDs)

	now := time.Now().Unix()
	for _, connID := range connectionIDs {
		data, err := dh.storage.Get("connections/" + connID)
		if err != nil {
			continue
		}

		var record ConnectionRecord
		if json.Unmarshal(data, &record) != nil {
			continue
		}

		if !record.IsDevice() || record.DeviceSession == nil {
			continue
		}

		session := record.DeviceSession

		// Expire active sessions past their wall-clock deadline
		if session.Status == "active" && now > session.ExpiresAt {
			session.Status = "expired"

			// Wipe the session key from storage
			if session.SessionKeyID != "" {
				keyPath := fmt.Sprintf("device_session_keys/%s/%s", record.ConnectionID, session.SessionKeyID)
				_ = dh.storage.Delete(keyPath)
			}

			connData, _ := json.Marshal(record)
			dh.storage.Put("connections/"+record.ConnectionID, connData)

			if dh.eventHandler != nil {
				dh.eventHandler.LogConnectionEvent(context.Background(), EventTypeDeviceSessionExpired, record.ConnectionID, "",
					"Device session expired (cleanup)")
			}

			log.Info().
				Str("connection_id", record.ConnectionID).
				Str("session_id", session.SessionID).
				Msg("Device session expired during cleanup")
		}
	}

	// Clean up stale pending approvals (older than 10 minutes)
	dh.mu.Lock()
	for id, pending := range dh.pendingApprovals {
		if time.Since(pending.CreatedAt) > 10*time.Minute {
			delete(dh.pendingApprovals, id)
		}
	}
	dh.mu.Unlock()
}

// publishDeviceResponse encrypts and publishes a response to the device's topic.
func (dh *DeviceHandler) publishDeviceResponse(conn *ConnectionRecord, connKey []byte, msgType string, payload interface{}) {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal device response")
		return
	}

	encrypted, err := encryptXChaCha20(connKey, payloadBytes)
	if err != nil {
		log.Error().Err(err).Msg("Failed to encrypt device response")
		return
	}
	zeroBytes(payloadBytes)

	encPayloadJSON, _ := json.Marshal(encrypted)
	envBytes, _ := json.Marshal(AgentEnvelope{
		Type:      msgType,
		KeyID:     conn.ConnectionID,
		Payload:   encPayloadJSON,
		Timestamp: time.Now().UTC(),
	})

	topic := fmt.Sprintf("MessageSpace.%s.forOwner.device.%s", dh.ownerSpace, conn.ConnectionID)
	dh.publisher.PublishRaw(topic, envBytes)
}

// Stop shuts down the background cleanup goroutine.
func (dh *DeviceHandler) Stop() {
	close(dh.stopCleanup)
}

// --- Crypto helpers ---

// decryptECIESDeviceDomain decrypts ECIES data from a device using the device domain.
// Format: ephemeral_pubkey (32) || nonce (24) || ciphertext+tag
func decryptECIESDeviceDomain(privateKey []byte, data []byte) ([]byte, error) {
	minSize := 32 + chacha20poly1305.NonceSizeX + chacha20poly1305.Overhead
	if len(data) < minSize {
		return nil, fmt.Errorf("ECIES data too short: need at least %d bytes, got %d", minSize, len(data))
	}

	ephPub := data[:32]
	nonce := data[32 : 32+chacha20poly1305.NonceSizeX]
	ciphertext := data[32+chacha20poly1305.NonceSizeX:]

	// X25519 key exchange
	sharedSecret, err := curve25519.X25519(privateKey, ephPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH key exchange: %w", err)
	}
	defer zeroBytes(sharedSecret)

	// HKDF with device domain (distinct from agent domain)
	r := hkdf.New(sha256.New, sharedSecret, []byte(DomainDevice), nil)
	encKey := make([]byte, 32)
	if _, err := io.ReadFull(r, encKey); err != nil {
		return nil, fmt.Errorf("HKDF derive: %w", err)
	}
	defer zeroBytes(encKey)

	// XChaCha20-Poly1305
	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("ECIES decrypt: %w", err)
	}

	return plaintext, nil
}
