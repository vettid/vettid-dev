package main

// Stage-2 pairing handlers for desktop device connections.
// See vettid-dev/docs/DESKTOP-CONNECTION-FLOW.md for the full protocol.
//
// Flow summary:
//
//   Stage 1 (HandleCreateDeviceInvite in connections.go):
//     - App generates 8-char invite, vault publishes scoped creds to JetStream
//     - Desktop resolves code via embedded guest account
//     - Desktop reconnects with scoped creds
//
//   Stage 2 (this file):
//     - Desktop posts device.request-session with ephemeral pubkey + approval_token
//       → HandleDeviceRequestSession stores pending auth, notifies app
//     - User scans QR on phone, app posts device.authorize-session with duration
//       → HandleDeviceAuthorizeSession does X25519 key exchange, activates session
//     - On expiry, user can scan extension QR
//       → HandleDeviceExtendSession rotates keys, new session_key
//     - Logout or admin action
//       → HandleDeviceRevoke marks revoked, wipes session key, notifies desktop

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// DomainDeviceSession separates device session keys from any other HKDF-derived
// key in the system. Must match the desktop client.
const DomainDeviceSession = "vettid-device-session-v1"

// MaxSessionDurationSeconds caps a user-approved session at 24 hours.
const MaxSessionDurationSeconds int64 = 24 * 60 * 60

// DefaultSessionDurationSeconds is used when the app doesn't supply one.
const DefaultSessionDurationSeconds int64 = 60 * 60

// DevicePendingAuthTTL is how long a stage-2 request waits for app approval
// before being garbage-collected.
const DevicePendingAuthTTL = 10 * time.Minute

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

type DeviceRequestSessionRequest struct {
	ConnectionID   string          `json:"connection_id"`
	ApprovalToken  string          `json:"approval_token"`   // hex, 32 bytes
	DevicePubKey   string          `json:"device_pubkey"`    // hex, 32 bytes (X25519)
	DeviceMetadata *DeviceMetadata `json:"device_metadata"`  // fingerprint shown to user
}

type DeviceAuthorizeSessionRequest struct {
	ConnectionID    string `json:"connection_id"`
	ApprovalToken   string `json:"approval_token"`   // must match DevicePendingAuth.ApprovalToken
	DeviceName      string `json:"device_name"`      // user-assigned
	DurationSeconds int64  `json:"duration_seconds"` // capped server-side at 24h
}

type DeviceExtendSessionRequest struct {
	ConnectionID    string `json:"connection_id"`
	ApprovalToken   string `json:"approval_token"`
	DurationSeconds int64  `json:"duration_seconds"`
}

type DeviceRevokeRequest struct {
	ConnectionID string `json:"connection_id"`
	Reason       string `json:"reason,omitempty"` // "logout" when device-initiated
}

// DeviceEndSessionRequest ends just the current session — wipes the
// session_key + flips DeviceSession.Status to "expired" — without
// revoking the connection. Lets the user manually lock their desktop
// without re-pairing on the next use; the desktop can immediately
// publish device.request-session to start a fresh session under the
// same connection_id. Use device.revoke when the goal is to retire
// the desktop entirely.
type DeviceEndSessionRequest struct {
	ConnectionID string `json:"connection_id"`
	Reason       string `json:"reason,omitempty"` // "user_locked" when desktop-initiated
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

// HandleDeviceRequestSession processes a stage-2 request from the desktop.
// Desktop has completed stage 1 (NATS access) and now wants session authorization.
// Stores approval_token + desktop pubkey + fingerprint; notifies the user's app.
func (h *ConnectionsHandler) HandleDeviceRequestSession(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req DeviceRequestSessionRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleDeviceRequestSession"); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" || req.ApprovalToken == "" || req.DevicePubKey == "" {
		return h.errorResponse(msg.GetID(), "connection_id, approval_token, and device_pubkey are required")
	}

	tokenBytes, err := hex.DecodeString(req.ApprovalToken)
	if err != nil || len(tokenBytes) != 32 {
		return h.errorResponse(msg.GetID(), "approval_token must be 32 hex-encoded bytes")
	}
	pubBytes, err := hex.DecodeString(req.DevicePubKey)
	if err != nil || len(pubBytes) != 32 {
		return h.errorResponse(msg.GetID(), "device_pubkey must be 32 hex-encoded bytes")
	}

	data, err := h.storage.Get("connections/" + req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found — invite expired or already consumed")
	}
	var record ConnectionRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to read connection")
	}
	if !record.IsDevice() {
		return h.errorResponse(msg.GetID(), "Connection is not a device")
	}
	if record.Status != "pending_pairing" && record.Status != "active" {
		return h.errorResponse(msg.GetID(), fmt.Sprintf("Connection in state %q cannot accept new session request", record.Status))
	}

	now := time.Now()
	record.DevicePendingAuth = &DevicePendingAuth{
		ApprovalToken: req.ApprovalToken,
		DevicePubKey:  pubBytes,
		RequestedAt:   now.Unix(),
		ExpiresAt:     now.Add(DevicePendingAuthTTL).Unix(),
	}
	if req.DeviceMetadata != nil {
		meta := *req.DeviceMetadata
		if meta.FirstSeenAt == 0 {
			meta.FirstSeenAt = now.Unix()
		}
		record.DeviceMetadata = &meta
	}

	// Store and notify
	connBytes, _ := json.Marshal(&record)
	if err := h.storage.Put("connections/"+record.ConnectionID, connBytes); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to persist pending auth")
	}

	if h.publisher != nil {
		// Fingerprint shown to user for verification
		var fpPrefix string
		if record.DeviceMetadata != nil && record.DeviceMetadata.BinaryFingerprint != "" {
			if len(record.DeviceMetadata.BinaryFingerprint) >= 8 {
				fpPrefix = record.DeviceMetadata.BinaryFingerprint[:8]
			} else {
				fpPrefix = record.DeviceMetadata.BinaryFingerprint
			}
		}
		notif := map[string]interface{}{
			"connection_id":         record.ConnectionID,
			"device_metadata":       record.DeviceMetadata,
			"binary_fp_prefix":      fpPrefix,
			"expires_at":            record.DevicePendingAuth.ExpiresAt,
			"default_duration_s":    DefaultSessionDurationSeconds,
			"max_duration_s":        MaxSessionDurationSeconds,
		}
		notifBytes, _ := json.Marshal(notif)
		if err := h.publisher.PublishToApp(ctx, "device.pending-authorization", notifBytes); err != nil {
			log.Warn().Err(err).Msg("Failed to notify app of device pending auth")
		}
	}

	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(ctx, EventTypeDeviceConnectionRequest, record.ConnectionID, "", "Device requested session authorization")
	}

	log.Info().
		Str("connection_id", record.ConnectionID).
		Msg("Device stage-2 request stored; awaiting app authorization")

	resp := map[string]interface{}{
		"success":       true,
		"connection_id": record.ConnectionID,
		"expires_at":    record.DevicePendingAuth.ExpiresAt,
	}
	respBytes, _ := json.Marshal(resp)
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleDeviceAuthorizeSession processes the user's approval from the app.
// Verifies approval_token, does X25519 key exchange, derives session_key,
// activates the DeviceSession, publishes activation to the desktop.
func (h *ConnectionsHandler) HandleDeviceAuthorizeSession(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req DeviceAuthorizeSessionRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleDeviceAuthorizeSession"); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}
	if req.ConnectionID == "" || req.ApprovalToken == "" {
		return h.errorResponse(msg.GetID(), "connection_id and approval_token are required")
	}

	duration := req.DurationSeconds
	if duration <= 0 {
		duration = DefaultSessionDurationSeconds
	}
	if duration > MaxSessionDurationSeconds {
		duration = MaxSessionDurationSeconds
	}

	data, err := h.storage.Get("connections/" + req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}
	var record ConnectionRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to read connection")
	}
	if !record.IsDevice() {
		return h.errorResponse(msg.GetID(), "Connection is not a device")
	}
	if record.DevicePendingAuth == nil {
		return h.errorResponse(msg.GetID(), "No pending authorization for this device")
	}
	if time.Now().Unix() > record.DevicePendingAuth.ExpiresAt {
		record.DevicePendingAuth = nil
		connBytes, _ := json.Marshal(&record)
		h.storage.Put("connections/"+record.ConnectionID, connBytes)
		return h.errorResponse(msg.GetID(), "Authorization request expired — ask the device to try again")
	}
	if !constantTimeEqualString(record.DevicePendingAuth.ApprovalToken, req.ApprovalToken) {
		return h.errorResponse(msg.GetID(), "approval_token mismatch — scan the QR shown on the desktop")
	}

	// X25519 key exchange (vault ephemeral × device ephemeral)
	vaultPriv := make([]byte, 32)
	if _, err := rand.Read(vaultPriv); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to generate vault keypair")
	}
	vaultPub, err := curve25519.X25519(vaultPriv, curve25519.Basepoint)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to derive vault public key")
	}
	// SECURITY (#83): DevicePubKey is wire-supplied by the pairing
	// device; reject small-order points before the ECDH.
	sharedSecret, err := safeX25519(vaultPriv, record.DevicePendingAuth.DevicePubKey)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to compute shared secret")
	}
	defer zeroBytes(vaultPriv)
	defer zeroBytes(sharedSecret)

	// Build session and derive session_key
	sessionID := newUUID()
	sessionKey, err := deriveDeviceSessionKey(sharedSecret, record.ConnectionID, sessionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to derive session key")
	}
	defer zeroBytes(sessionKey)

	// Store session
	now := time.Now()
	expiresAt := now.Add(time.Duration(duration) * time.Second)
	record.DeviceSession = &DeviceSession{
		SessionID:        sessionID,
		Status:           "active",
		CreatedAt:        now.Unix(),
		ExpiresAt:        expiresAt.Unix(),
		LastActiveAt:     now.Unix(),
		DurationSeconds:  duration,
		KeyRotationCount: 0,
		SessionKeyID:     sessionID, // key id == session id for v1; simpler
	}
	record.Status = "active"
	record.PeerAlias = req.DeviceName
	if record.DeviceMetadata != nil {
		record.DeviceMetadata.DeviceName = req.DeviceName
	}
	record.DevicePendingAuth = nil // one-shot

	// Persist the session_key separately in encrypted vault storage so device
	// ops can look it up. Key material never leaves the enclave.
	keyPath := fmt.Sprintf("device_session_keys/%s/%s", record.ConnectionID, sessionID)
	if err := h.storage.Put(keyPath, sessionKey); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to persist session key")
	}

	connBytes, _ := json.Marshal(&record)
	if err := h.storage.Put("connections/"+record.ConnectionID, connBytes); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to store activated connection")
	}

	// Notify the desktop with the vault's ephemeral pubkey + session metadata
	if h.publisher != nil {
		activation := map[string]interface{}{
			"type":           "device.session.activated",
			"connection_id":  record.ConnectionID,
			"session_id":     sessionID,
			"session_key_id": sessionID,
			"vault_pubkey":   hex.EncodeToString(vaultPub),
			"expires_at":     expiresAt.Unix(),
			"duration_s":     duration,
		}
		activationBytes, _ := json.Marshal(activation)
		subject := fmt.Sprintf("MessageSpace.%s.forApp.device.%s.activated", h.ownerSpace, record.ConnectionID)
		if err := h.publisher.PublishRaw(subject, activationBytes); err != nil {
			log.Error().Err(err).Str("subject", subject).Msg("Failed to publish device activation")
			return h.errorResponse(msg.GetID(), "Failed to notify desktop")
		}
	}

	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(ctx, EventTypeDeviceSessionCreated, record.ConnectionID, "",
			fmt.Sprintf("Device session created (%s, %ds)", record.PeerAlias, duration))
	}

	log.Info().
		Str("connection_id", record.ConnectionID).
		Str("session_id", sessionID).
		Int64("duration_s", duration).
		Msg("Device session authorized")

	resp := map[string]interface{}{
		"success":       true,
		"connection_id": record.ConnectionID,
		"session_id":    sessionID,
		"expires_at":    expiresAt.Unix(),
	}
	respBytes, _ := json.Marshal(resp)
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleDeviceExtendSession rotates the session key and extends the expiry.
// Triggered when the user scans the extension QR from an expired desktop.
// Semantically identical to HandleDeviceAuthorizeSession but reuses the
// existing ConnectionRecord and increments KeyRotationCount.
func (h *ConnectionsHandler) HandleDeviceExtendSession(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req DeviceExtendSessionRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleDeviceExtendSession"); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}
	if req.ConnectionID == "" || req.ApprovalToken == "" {
		return h.errorResponse(msg.GetID(), "connection_id and approval_token are required")
	}

	duration := req.DurationSeconds
	if duration <= 0 {
		duration = DefaultSessionDurationSeconds
	}
	if duration > MaxSessionDurationSeconds {
		duration = MaxSessionDurationSeconds
	}

	data, err := h.storage.Get("connections/" + req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}
	var record ConnectionRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to read connection")
	}
	if !record.IsDevice() {
		return h.errorResponse(msg.GetID(), "Connection is not a device")
	}
	if record.Status == "revoked" {
		return h.errorResponse(msg.GetID(), "Connection revoked")
	}
	if record.DevicePendingAuth == nil {
		return h.errorResponse(msg.GetID(), "No pending authorization — ask the desktop to request a new session")
	}
	if time.Now().Unix() > record.DevicePendingAuth.ExpiresAt {
		record.DevicePendingAuth = nil
		connBytes, _ := json.Marshal(&record)
		h.storage.Put("connections/"+record.ConnectionID, connBytes)
		return h.errorResponse(msg.GetID(), "Authorization request expired")
	}
	if !constantTimeEqualString(record.DevicePendingAuth.ApprovalToken, req.ApprovalToken) {
		return h.errorResponse(msg.GetID(), "approval_token mismatch")
	}

	// Fresh keypair, fresh shared secret, fresh session key
	vaultPriv := make([]byte, 32)
	if _, err := rand.Read(vaultPriv); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to generate vault keypair")
	}
	vaultPub, err := curve25519.X25519(vaultPriv, curve25519.Basepoint)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to derive vault public key")
	}
	// SECURITY (#83): DevicePubKey is wire-supplied by the pairing
	// device; reject small-order points before the ECDH.
	sharedSecret, err := safeX25519(vaultPriv, record.DevicePendingAuth.DevicePubKey)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to compute shared secret")
	}
	defer zeroBytes(vaultPriv)
	defer zeroBytes(sharedSecret)

	newSessionID := newUUID()
	sessionKey, err := deriveDeviceSessionKey(sharedSecret, record.ConnectionID, newSessionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to derive session key")
	}
	defer zeroBytes(sessionKey)

	// Wipe the previous session key from storage (best-effort)
	if record.DeviceSession != nil && record.DeviceSession.SessionKeyID != "" {
		oldKeyPath := fmt.Sprintf("device_session_keys/%s/%s", record.ConnectionID, record.DeviceSession.SessionKeyID)
		if err := h.storage.Delete(oldKeyPath); err != nil {
			log.Warn().Err(err).Str("path", oldKeyPath).Msg("Failed to delete previous session key (non-fatal)")
		}
	}

	now := time.Now()
	expiresAt := now.Add(time.Duration(duration) * time.Second)
	rotationCount := 1
	if record.DeviceSession != nil {
		rotationCount = record.DeviceSession.KeyRotationCount + 1
	}
	record.DeviceSession = &DeviceSession{
		SessionID:        newSessionID,
		Status:           "active",
		CreatedAt:        now.Unix(),
		ExpiresAt:        expiresAt.Unix(),
		LastActiveAt:     now.Unix(),
		DurationSeconds:  duration,
		KeyRotationCount: rotationCount,
		SessionKeyID:     newSessionID,
	}
	record.Status = "active"
	record.DevicePendingAuth = nil

	keyPath := fmt.Sprintf("device_session_keys/%s/%s", record.ConnectionID, newSessionID)
	if err := h.storage.Put(keyPath, sessionKey); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to persist session key")
	}

	connBytes, _ := json.Marshal(&record)
	if err := h.storage.Put("connections/"+record.ConnectionID, connBytes); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to persist extended session")
	}

	if h.publisher != nil {
		activation := map[string]interface{}{
			"type":           "device.session.activated",
			"connection_id":  record.ConnectionID,
			"session_id":     newSessionID,
			"session_key_id": newSessionID,
			"vault_pubkey":   hex.EncodeToString(vaultPub),
			"expires_at":     expiresAt.Unix(),
			"duration_s":     duration,
			"rotation":       rotationCount,
		}
		activationBytes, _ := json.Marshal(activation)
		subject := fmt.Sprintf("MessageSpace.%s.forApp.device.%s.activated", h.ownerSpace, record.ConnectionID)
		if err := h.publisher.PublishRaw(subject, activationBytes); err != nil {
			log.Error().Err(err).Str("subject", subject).Msg("Failed to publish extension activation")
		}
	}

	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(ctx, EventTypeDeviceSessionExtended, record.ConnectionID, "",
			fmt.Sprintf("Device session extended (rotation %d)", rotationCount))
	}

	resp := map[string]interface{}{
		"success":       true,
		"connection_id": record.ConnectionID,
		"session_id":    newSessionID,
		"expires_at":    expiresAt.Unix(),
		"rotation":      rotationCount,
	}
	respBytes, _ := json.Marshal(resp)
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// deriveDeviceSessionKey derives a 32-byte symmetric key from a shared secret.
// Must match the desktop client's derivation exactly.
func deriveDeviceSessionKey(sharedSecret []byte, connectionID, sessionID string) ([]byte, error) {
	if len(sharedSecret) != 32 {
		return nil, fmt.Errorf("shared secret must be 32 bytes, got %d", len(sharedSecret))
	}
	info := []byte(DomainDeviceSession + "|" + sessionID)
	r := hkdf.New(sha256.New, sharedSecret, []byte(connectionID), info)
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("HKDF expand: %w", err)
	}
	return key, nil
}

// HandleDeviceEndSession is the soft counterpart to HandleRevokeDevice:
// it wipes the active session key and marks DeviceSession.Status as
// "expired" without revoking the connection record. Lets the user
// immediately end a session from the desktop's UI and start a new one
// (via the standard request-session → authorize-session re-flow)
// without re-pairing.
//
// Called either from the desktop (user clicked "End Session") or from
// the phone (user tapped "Lock now" on the connection detail screen).
func (h *ConnectionsHandler) HandleDeviceEndSession(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req DeviceEndSessionRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleDeviceEndSession"); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}
	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	data, err := h.storage.Get("connections/" + req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}
	var record ConnectionRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to read connection")
	}
	if !record.IsDevice() {
		return h.errorResponse(msg.GetID(), "Connection is not a device")
	}
	if record.Status == "revoked" {
		return h.errorResponse(msg.GetID(), "Connection revoked")
	}
	if record.DeviceSession == nil || record.DeviceSession.Status != "active" {
		return h.errorResponse(msg.GetID(), "No active session to end")
	}

	// Wipe the session_key blob — same primitive HandleRevokeDevice
	// uses. After this the desktop's cached session key is useless
	// against the vault, even if the desktop hasn't yet noticed the
	// session ended.
	keyPath := fmt.Sprintf("device_session_keys/%s/%s", record.ConnectionID, record.DeviceSession.SessionKeyID)
	if err := h.storage.Delete(keyPath); err != nil {
		log.Warn().Err(err).Str("path", keyPath).Msg("Failed to delete session key during end-session (non-fatal)")
	}

	now := time.Now().Unix()
	record.DeviceSession.Status = "expired"
	record.DeviceSession.LastActiveAt = now
	// Clear DevicePendingAuth: any in-flight request-session token is
	// stale once the active session is ended. The desktop must re-
	// initiate request-session to get a fresh approval_token.
	record.DevicePendingAuth = nil

	connBytes, _ := json.Marshal(&record)
	if err := h.storage.Put("connections/"+record.ConnectionID, connBytes); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to persist session end")
	}

	// Notify the desktop so it can transition straight to its
	// SessionExpired view (instead of waiting for the next get_session_
	// info poll to discover the change). Same subject HandleRevoke
	// uses but with a different `type` so the desktop's listener can
	// distinguish "ended, can restart" from "revoked, must re-pair".
	if h.publisher != nil {
		endNotif := map[string]interface{}{
			"type":          "device.session.ended",
			"connection_id": record.ConnectionID,
			"reason":        req.Reason,
		}
		notifBytes, _ := json.Marshal(endNotif)
		subject := fmt.Sprintf("MessageSpace.%s.forApp.device.%s.ended", h.ownerSpace, record.ConnectionID)
		if err := h.publisher.PublishRaw(subject, notifBytes); err != nil {
			log.Warn().Err(err).Str("subject", subject).Msg("Failed to publish device.session.ended (non-fatal)")
		}
	}

	log.Info().
		Str("connection_id", record.ConnectionID).
		Str("reason", req.Reason).
		Msg("Device session ended (connection kept)")

	resp := struct {
		Success      bool   `json:"success"`
		ConnectionID string `json:"connection_id"`
	}{Success: true, ConnectionID: record.ConnectionID}
	respBytes, _ := json.Marshal(resp)
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// constantTimeEqualString compares two hex strings in constant time.
func constantTimeEqualString(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// newUUID returns a random UUID v4 string.
func newUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
