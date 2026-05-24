package main

// Stage-2 pairing handlers for AI agent connections.
// See vettid-agent/docs/AGENT-PAIRING-FLOW.md for the full protocol.
//
// Flow summary (parallel to device_pairing.go):
//
//   Stage 1 (HandleCreateAgentInvite in connections.go):
//     - App generates 12-char invite, vault publishes scoped creds to JetStream
//     - Agent resolves code via guest creds minted by the bootstrap Lambda
//     - Agent reconnects with scoped creds
//
//   Stage 2 (this file):
//     - Agent posts agent.request-session with ephemeral pubkey + approval_token
//       + agent_metadata + requested_scope + requested_approval_mode + requested_duration_s
//       → HandleAgentRequestSession stores pending auth, notifies app
//     - User taps Approve on phone, app posts agent.authorize-session with the
//       *final* scope/approval_mode/duration/rate_limit
//       → HandleAgentAuthorizeSession does X25519 key exchange, writes the
//         ConnectionContract chosen by the owner, activates the AgentSession
//     - On expiry, user can approve an extension (a separate request-session
//       round-trip — agent picks new ephemeral keypair, owner re-approves)
//       → HandleAgentExtendSession rotates keys, new session_key
//     - Logout or admin action
//       → HandleAgentEndSession soft-ends without revoking the connection;
//         HandleRevokeAgent (in connections.go) tears down completely.
//
// Differences from device flow:
//   - Multi-active per owner is allowed: an operator can run claude-code +
//     cursor + a self-hosted-llm simultaneously, so authorize-session does
//     NOT enforce one-active-per-vault. Each connection_id is independent.
//   - The phone is the *sole* authority that writes record.Contract.
//     `requested_scope` etc. on the agent's request are hints only — the
//     owner's authorize payload picks the final values.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/curve25519"
)

// DomainAgentSession separates agent session keys from any other HKDF-derived
// key in the system. Must match the agent client.
const DomainAgentSession = "vettid-agent-session-v1"

// AgentPendingAuthTTL is how long a stage-2 agent request waits for owner
// approval before being garbage-collected. Same as device.
const AgentPendingAuthTTL = 10 * time.Minute

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

type AgentRequestSessionRequest struct {
	ConnectionID            string         `json:"connection_id"`
	ApprovalToken           string         `json:"approval_token"`            // hex, 32 bytes
	AgentPubKey             string         `json:"agent_pubkey"`              // hex, 32 bytes (X25519)
	AgentMetadata           *AgentMetadata `json:"agent_metadata"`            // identity card shown to owner
	RequestedScope          []string       `json:"requested_scope,omitempty"` // hint
	RequestedApprovalMode   string         `json:"requested_approval_mode,omitempty"`
	RequestedDurationSecs   int64          `json:"requested_duration_s,omitempty"`
}

type AgentAuthorizeSessionRequest struct {
	ConnectionID    string    `json:"connection_id"`
	ApprovalToken   string    `json:"approval_token"`
	AgentName       string    `json:"agent_name"`              // owner-assigned
	GrantedScope    []string  `json:"granted_scope"`           // final scope chosen by owner
	ApprovalMode    string    `json:"approval_mode"`           // "always_ask" | "auto_within_contract"
	RateLimit       RateLimit `json:"rate_limit"`
	DurationSeconds int64     `json:"duration_seconds"`        // capped server-side at 24h
}

type AgentExtendSessionRequest struct {
	ConnectionID    string    `json:"connection_id"`
	ApprovalToken   string    `json:"approval_token"`
	GrantedScope    []string  `json:"granted_scope,omitempty"` // optional — defaults to existing
	ApprovalMode    string    `json:"approval_mode,omitempty"`
	RateLimit       *RateLimit `json:"rate_limit,omitempty"`
	DurationSeconds int64     `json:"duration_seconds"`
}

type AgentEndSessionRequest struct {
	ConnectionID string `json:"connection_id"`
	Reason       string `json:"reason,omitempty"`
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

// HandleAgentRequestSession processes a stage-2 request from a paired agent.
// Agent has completed stage 1 (NATS access) and now wants session authorization.
// Stores approval_token + agent pubkey + metadata + requested_* hints; notifies
// the user's app so the owner can review and approve.
func (h *ConnectionsHandler) HandleAgentRequestSession(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req AgentRequestSessionRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleAgentRequestSession"); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" || req.ApprovalToken == "" || req.AgentPubKey == "" {
		return h.errorResponse(msg.GetID(), "connection_id, approval_token, and agent_pubkey are required")
	}

	tokenBytes, err := hex.DecodeString(req.ApprovalToken)
	if err != nil || len(tokenBytes) != 32 {
		return h.errorResponse(msg.GetID(), "approval_token must be 32 hex-encoded bytes")
	}
	pubBytes, err := hex.DecodeString(req.AgentPubKey)
	if err != nil || len(pubBytes) != 32 {
		return h.errorResponse(msg.GetID(), "agent_pubkey must be 32 hex-encoded bytes")
	}

	data, err := h.storage.Get("connections/" + req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found — invite expired or already consumed")
	}
	var record ConnectionRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to read connection")
	}
	if !record.IsAgent() {
		return h.errorResponse(msg.GetID(), "Connection is not an agent")
	}
	if record.Status != "pending_pairing" && record.Status != "active" {
		return h.errorResponse(msg.GetID(), fmt.Sprintf("Connection in state %q cannot accept new session request", record.Status))
	}

	now := time.Now()
	record.AgentPendingAuth = &AgentPendingAuth{
		ApprovalToken:         req.ApprovalToken,
		AgentPubKey:           pubBytes,
		RequestedAt:           now.Unix(),
		ExpiresAt:             now.Add(AgentPendingAuthTTL).Unix(),
		RequestedScope:        req.RequestedScope,
		RequestedApprovalMode: req.RequestedApprovalMode,
		RequestedDurationSecs: req.RequestedDurationSecs,
	}
	if req.AgentMetadata != nil {
		meta := *req.AgentMetadata
		if meta.FirstSeenAt == 0 {
			meta.FirstSeenAt = now.Unix()
		}
		record.AgentMetadata = &meta
	}

	connBytes, _ := json.Marshal(&record)
	if err := h.storage.Put("connections/"+record.ConnectionID, connBytes); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to persist pending auth")
	}

	if h.publisher != nil {
		var fpPrefix string
		if record.AgentMetadata != nil && record.AgentMetadata.BinaryFingerprint != "" {
			if len(record.AgentMetadata.BinaryFingerprint) >= 8 {
				fpPrefix = record.AgentMetadata.BinaryFingerprint[:8]
			} else {
				fpPrefix = record.AgentMetadata.BinaryFingerprint
			}
		}
		notif := map[string]interface{}{
			"connection_id":             record.ConnectionID,
			"approval_token":            req.ApprovalToken,
			"agent_pubkey":              req.AgentPubKey,
			"agent_metadata":            record.AgentMetadata,
			"binary_fp_prefix":          fpPrefix,
			"expires_at":                record.AgentPendingAuth.ExpiresAt,
			"requested_scope":           req.RequestedScope,
			"requested_approval_mode":   req.RequestedApprovalMode,
			"requested_duration_s":      req.RequestedDurationSecs,
			"default_duration_s":        DefaultSessionDurationSeconds,
			"max_duration_s":            MaxSessionDurationSeconds,
		}
		notifBytes, _ := json.Marshal(notif)
		if err := h.publisher.PublishToApp(ctx, "agent.pending-authorization", notifBytes); err != nil {
			log.Warn().Err(err).Msg("Failed to notify app of agent pending auth")
		}
	}

	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(ctx, EventTypeAgentConnectionRequest, record.ConnectionID, "",
			"Agent requested session authorization")
	}

	log.Info().
		Str("connection_id", record.ConnectionID).
		Msg("Agent stage-2 request stored; awaiting owner authorization")

	resp := map[string]interface{}{
		"success":       true,
		"connection_id": record.ConnectionID,
		"expires_at":    record.AgentPendingAuth.ExpiresAt,
	}
	respBytes, _ := json.Marshal(resp)
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleAgentAuthorizeSession processes the owner's approval from the app.
// Verifies approval_token, does X25519 key exchange, derives session_key,
// writes the ConnectionContract chosen by the owner, activates the AgentSession,
// publishes activation to the agent.
//
// Unlike the device equivalent, this does NOT enforce one-active-per-vault —
// multiple agent sessions can coexist (locked decision 2026-05-23).
func (h *ConnectionsHandler) HandleAgentAuthorizeSession(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req AgentAuthorizeSessionRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleAgentAuthorizeSession"); err != nil {
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

	approvalMode := req.ApprovalMode
	if approvalMode == "" {
		approvalMode = "always_ask"
	}

	data, err := h.storage.Get("connections/" + req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}
	var record ConnectionRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to read connection")
	}
	if !record.IsAgent() {
		return h.errorResponse(msg.GetID(), "Connection is not an agent")
	}
	if record.AgentPendingAuth == nil {
		return h.errorResponse(msg.GetID(), "No pending authorization for this agent")
	}
	if time.Now().Unix() > record.AgentPendingAuth.ExpiresAt {
		record.AgentPendingAuth = nil
		connBytes, _ := json.Marshal(&record)
		h.storage.Put("connections/"+record.ConnectionID, connBytes)
		return h.errorResponse(msg.GetID(), "Authorization request expired — ask the agent to try again")
	}
	if !constantTimeEqualString(record.AgentPendingAuth.ApprovalToken, req.ApprovalToken) {
		return h.errorResponse(msg.GetID(), "approval_token mismatch — verify the token shown by the agent")
	}

	// X25519 key exchange (vault ephemeral × agent ephemeral)
	vaultPriv := make([]byte, 32)
	if _, err := rand.Read(vaultPriv); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to generate vault keypair")
	}
	vaultPub, err := curve25519.X25519(vaultPriv, curve25519.Basepoint)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to derive vault public key")
	}
	// SECURITY (#83): AgentPubKey is wire-supplied by the pairing agent;
	// reject small-order points before the ECDH.
	sharedSecret, err := safeX25519(vaultPriv, record.AgentPendingAuth.AgentPubKey)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to compute shared secret")
	}
	defer zeroBytes(vaultPriv)
	defer zeroBytes(sharedSecret)

	sessionID := newUUID()
	sessionKey, err := deriveSessionKey(DomainAgentSession, sharedSecret, record.ConnectionID, sessionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to derive session key")
	}
	defer zeroBytes(sessionKey)

	now := time.Now()
	expiresAt := now.Add(time.Duration(duration) * time.Second)
	record.AgentSession = &AgentSession{
		SessionID:        sessionID,
		Status:           "active",
		CreatedAt:        now.Unix(),
		ExpiresAt:        expiresAt.Unix(),
		LastActiveAt:     now.Unix(),
		DurationSeconds:  duration,
		KeyRotationCount: 0,
		SessionKeyID:     sessionID,
	}
	record.Status = "active"
	if req.AgentName != "" {
		record.PeerAlias = req.AgentName
	}
	// Phone is the sole authority that writes Contract.
	record.Contract = &ConnectionContract{
		AgentName:    record.PeerAlias,
		Scope:        req.GrantedScope,
		ApprovalMode: approvalMode,
		RateLimit:    req.RateLimit,
	}
	record.AgentPendingAuth = nil // one-shot

	keyPath := fmt.Sprintf("agent_session_keys/%s/%s", record.ConnectionID, sessionID)
	if err := h.storage.Put(keyPath, sessionKey); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to persist session key")
	}

	connBytes, _ := json.Marshal(&record)
	if err := h.storage.Put("connections/"+record.ConnectionID, connBytes); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to store activated connection")
	}

	if h.publisher != nil {
		activation := map[string]interface{}{
			"type":           "agent.session.activated",
			"connection_id":  record.ConnectionID,
			"session_id":     sessionID,
			"session_key_id": sessionID,
			"vault_pubkey":   hex.EncodeToString(vaultPub),
			"expires_at":     expiresAt.Unix(),
			"duration_s":     duration,
			"granted_scope":  req.GrantedScope,
			"approval_mode":  approvalMode,
			"rate_limit":     req.RateLimit,
		}
		activationBytes, _ := json.Marshal(activation)
		subject := fmt.Sprintf("MessageSpace.%s.forApp.agent.%s.activated", h.ownerSpace, record.ConnectionID)
		if err := h.publisher.PublishRaw(subject, activationBytes); err != nil {
			log.Error().Err(err).Str("subject", subject).Msg("Failed to publish agent activation")
			return h.errorResponse(msg.GetID(), "Failed to notify agent")
		}

		// Also publish to the broad forApp.connection bus so the owner
		// app's connection list refreshes immediately. The peer-pair
		// path emits this from HandleRespond when status flips to
		// active; the agent path was only emitting the agent-specific
		// subject above (which the agent receives, not the owner app).
		// Without this, the connection list showed the Stage-1
		// placeholder label until some other event happened to trigger
		// a refresh — observed ~30s lag in testing on 2026-05-24.
		// PeerGUID is empty for agent connections; the activated
		// payload's peer_alias is now the owner-edited name from
		// authorize-session.
		appNotif := map[string]interface{}{
			"type":          "connection.activated",
			"connection_id": record.ConnectionID,
			"peer_alias":    record.PeerAlias,
		}
		appNotifBytes, _ := json.Marshal(appNotif)
		if err := h.publisher.PublishToApp(ctx, "connection.activated", appNotifBytes); err != nil {
			log.Warn().Err(err).Msg("Failed to publish connection.activated for agent (non-fatal)")
		}
	}

	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(ctx, EventTypeAgentSessionCreated, record.ConnectionID, "",
			fmt.Sprintf("Agent session created (%s, %ds, %d scope tokens)", record.PeerAlias, duration, len(req.GrantedScope)))
	}

	log.Info().
		Str("connection_id", record.ConnectionID).
		Str("session_id", sessionID).
		Int64("duration_s", duration).
		Int("scope_count", len(req.GrantedScope)).
		Msg("Agent session authorized")

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

// HandleAgentExtendSession rotates the session key and extends the expiry.
// Triggered when the agent (typically the embedded AI agent calling
// POST /v1/pair/extend on the local API) detects an impending expiry and
// the owner re-approves on the phone. Reuses the existing ConnectionRecord
// and increments KeyRotationCount.
//
// Scope/approval_mode/rate_limit are only re-written if the owner explicitly
// supplied them in the extend payload; otherwise the existing Contract is
// preserved. This mirrors how desktop's extend flow operates.
func (h *ConnectionsHandler) HandleAgentExtendSession(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req AgentExtendSessionRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleAgentExtendSession"); err != nil {
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
	if !record.IsAgent() {
		return h.errorResponse(msg.GetID(), "Connection is not an agent")
	}
	if record.Status == "revoked" {
		return h.errorResponse(msg.GetID(), "Connection revoked")
	}
	if record.AgentPendingAuth == nil {
		return h.errorResponse(msg.GetID(), "No pending authorization — ask the agent to request a new session")
	}
	if time.Now().Unix() > record.AgentPendingAuth.ExpiresAt {
		record.AgentPendingAuth = nil
		connBytes, _ := json.Marshal(&record)
		h.storage.Put("connections/"+record.ConnectionID, connBytes)
		return h.errorResponse(msg.GetID(), "Authorization request expired")
	}
	if !constantTimeEqualString(record.AgentPendingAuth.ApprovalToken, req.ApprovalToken) {
		return h.errorResponse(msg.GetID(), "approval_token mismatch")
	}

	vaultPriv := make([]byte, 32)
	if _, err := rand.Read(vaultPriv); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to generate vault keypair")
	}
	vaultPub, err := curve25519.X25519(vaultPriv, curve25519.Basepoint)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to derive vault public key")
	}
	// SECURITY (#83): AgentPubKey is wire-supplied by the pairing agent;
	// reject small-order points before the ECDH.
	sharedSecret, err := safeX25519(vaultPriv, record.AgentPendingAuth.AgentPubKey)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to compute shared secret")
	}
	defer zeroBytes(vaultPriv)
	defer zeroBytes(sharedSecret)

	newSessionID := newUUID()
	sessionKey, err := deriveSessionKey(DomainAgentSession, sharedSecret, record.ConnectionID, newSessionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to derive session key")
	}
	defer zeroBytes(sessionKey)

	if record.AgentSession != nil && record.AgentSession.SessionKeyID != "" {
		oldKeyPath := fmt.Sprintf("agent_session_keys/%s/%s", record.ConnectionID, record.AgentSession.SessionKeyID)
		if err := h.storage.Delete(oldKeyPath); err != nil {
			log.Warn().Err(err).Str("path", oldKeyPath).Msg("Failed to delete previous session key (non-fatal)")
		}
	}

	now := time.Now()
	expiresAt := now.Add(time.Duration(duration) * time.Second)
	rotationCount := 1
	if record.AgentSession != nil {
		rotationCount = record.AgentSession.KeyRotationCount + 1
	}
	record.AgentSession = &AgentSession{
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
	// Owner can re-scope at extend time. Empty fields preserve the existing Contract.
	if record.Contract == nil {
		record.Contract = &ConnectionContract{AgentName: record.PeerAlias}
	}
	if len(req.GrantedScope) > 0 {
		record.Contract.Scope = req.GrantedScope
	}
	if req.ApprovalMode != "" {
		record.Contract.ApprovalMode = req.ApprovalMode
	}
	if req.RateLimit != nil {
		record.Contract.RateLimit = *req.RateLimit
	}
	record.AgentPendingAuth = nil

	keyPath := fmt.Sprintf("agent_session_keys/%s/%s", record.ConnectionID, newSessionID)
	if err := h.storage.Put(keyPath, sessionKey); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to persist session key")
	}

	connBytes, _ := json.Marshal(&record)
	if err := h.storage.Put("connections/"+record.ConnectionID, connBytes); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to persist extended session")
	}

	if h.publisher != nil {
		activation := map[string]interface{}{
			"type":           "agent.session.activated",
			"connection_id":  record.ConnectionID,
			"session_id":     newSessionID,
			"session_key_id": newSessionID,
			"vault_pubkey":   hex.EncodeToString(vaultPub),
			"expires_at":     expiresAt.Unix(),
			"duration_s":     duration,
			"granted_scope":  record.Contract.Scope,
			"approval_mode":  record.Contract.ApprovalMode,
			"rate_limit":     record.Contract.RateLimit,
			"rotation":       rotationCount,
		}
		activationBytes, _ := json.Marshal(activation)
		subject := fmt.Sprintf("MessageSpace.%s.forApp.agent.%s.activated", h.ownerSpace, record.ConnectionID)
		if err := h.publisher.PublishRaw(subject, activationBytes); err != nil {
			log.Error().Err(err).Str("subject", subject).Msg("Failed to publish agent extension activation")
		}
	}

	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(ctx, EventTypeAgentSessionExtended, record.ConnectionID, "",
			fmt.Sprintf("Agent session extended (rotation %d)", rotationCount))
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

// HandleAgentEndSession is the soft counterpart to HandleRevokeAgent:
// it wipes the active session key and marks AgentSession.Status as
// "expired" without revoking the connection record. The agent can
// then re-initiate request-session under the same connection_id without
// re-pairing.
//
// Called either from the agent (operator stopped the daemon) or from
// the phone (owner tapped "Lock now" on the agent's connection detail).
func (h *ConnectionsHandler) HandleAgentEndSession(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	// AGENT-PAIRED-CONTRACT-MODEL: end-session is a no-op now. Agents
	// are paired-or-revoked; there is no session to "end" short of
	// revocation. We keep the wire op so older agent clients that
	// still call it on shutdown don't see an error, log the request
	// to the audit trail for visibility, and return success.
	// Callers that actually want to terminate a pairing should use
	// agent.revoke.
	var req AgentEndSessionRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleAgentEndSession"); err != nil {
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
	if !record.IsAgent() {
		return h.errorResponse(msg.GetID(), "Connection is not an agent")
	}

	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(ctx, EventTypeAgentSessionExpired, record.ConnectionID, "",
			fmt.Sprintf("Agent end-session call received (no-op in paired/contract model; reason=%s)", req.Reason))
	}

	log.Info().
		Str("connection_id", record.ConnectionID).
		Str("reason", req.Reason).
		Msg("Agent end-session received — no-op (paired/contract model)")

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
