package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Domain separation constants for agent connections.
// Must match the vettid-agent crypto package.
const (
	DomainConnection = "vettid-connection-v1"
	DomainAgent      = "vettid-agent-v1"
)

// PendingApproval tracks an agent request awaiting owner approval.
type PendingApproval struct {
	RequestID    string          `json:"request_id"`
	ConnectionID string          `json:"connection_id"`
	SecretID     string          `json:"secret_id"`
	Action       string          `json:"action"` // "retrieve", "http_request", "sign"
	Purpose      string          `json:"purpose"`
	Params       json.RawMessage `json:"params,omitempty"` // for action requests
	CreatedAt    time.Time       `json:"created_at"`
}

// AgentHandler processes messages from AI agent connectors.
//
// Agent messages arrive via NATS on MessageSpace.{guid}.forOwner.agent,
// are forwarded by the parent process to the enclave, and routed here
// by handleVaultOp when a "forOwner" segment is detected in the subject.
//
// Each message is an Envelope containing:
//   - type: message type (agent_secret_request, agent_action_request, etc.)
//   - key_id: connection ID (used to look up the connection record)
//   - payload: encrypted with the connection's shared secret
//   - sequence: monotonically increasing per connection
//
// Responses are published directly via VsockPublisher to the agent's
// response topic, not through the standard reply path.
type AgentHandler struct {
	ownerSpace       string
	storage          *EncryptedStorage
	publisher        *VsockPublisher
	eventHandler     *EventHandler
	connHandler      *ConnectionsHandler
	secretsHandler   *AgentSecretsHandler
	pendingApprovals map[string]*PendingApproval // keyed by request_id
	rateLimiter      *agentRateLimiter           // per-connection DoS guard (#32)
}

// NewAgentHandler creates a new agent handler.
func NewAgentHandler(
	ownerSpace string,
	storage *EncryptedStorage,
	publisher *VsockPublisher,
	eventHandler *EventHandler,
	connHandler *ConnectionsHandler,
	secretsHandler *AgentSecretsHandler,
) *AgentHandler {
	return &AgentHandler{
		ownerSpace:       ownerSpace,
		storage:          storage,
		publisher:        publisher,
		eventHandler:     eventHandler,
		connHandler:      connHandler,
		secretsHandler:   secretsHandler,
		pendingApprovals: make(map[string]*PendingApproval),
		rateLimiter:      newAgentRateLimiter(),
	}
}

// --- Envelope types (matching vettid-agent/internal/nats/messages.go) ---

// AgentEnvelope is the outer message format from the agent connector.
type AgentEnvelope struct {
	Type      string          `json:"type"`
	KeyID     string          `json:"key_id"`
	Payload   json.RawMessage `json:"payload"` // Encrypted bytes (base64 in JSON)
	Timestamp time.Time       `json:"timestamp"`
	Sequence  uint64          `json:"sequence"`
}

// Agent message type constants (matching vettid-agent).
const (
	AgentMsgConnectionRequest = "agent_connection_request"
	AgentMsgSecretRequest     = "agent_secret_request"
	AgentMsgActionRequest     = "agent_action_request"
	AgentMsgCatalogRequest    = "agent_catalog_request"
	AgentMsgMessage           = "agent_message"

	AgentMsgSecretResponse     = "agent_secret_response"
	AgentMsgActionResponse     = "agent_action_response"
	AgentMsgCatalogResponse    = "agent_secret_catalog"
	AgentMsgConnectionApproved = "agent_connection_approved"
	AgentMsgConnectionDenied   = "agent_connection_denied"
	AgentMsgMessageResponse    = "agent_message_response" // owner reply to agent (has reply_content)
	// AgentMsgMessageAck is the vault's delivery confirmation for a
	// message the agent itself sent. Distinct from AgentMsgMessageResponse
	// so the agent can tell "owner replied" from "vault saw my send" —
	// they land on the same forOwner.agent.<conn> subject. Older agents
	// that don't recognize the type log it under "Ignoring unknown
	// NATS message type" and drop it, which is the desired behavior.
	AgentMsgMessageAck = "agent_message_ack"

	// AgentMsgLeashGranted carries a successfully-approved LEASH JWT back
	// to the agent. Payload: AgentLeashGrantedPayload (compact JWT + jti +
	// kid + expires_at). Lands on forOwner.agent.<conn> alongside chat
	// messages; the agent demuxes by Type and resolves the in-flight
	// mint tracker entry.
	AgentMsgLeashGranted = "agent_leash_granted"

	// AgentMsgLeashDenied tells the agent its mint request was rejected
	// by the owner (or auto-denied by the vault for protocol reasons).
	// Payload: AgentLeashDeniedPayload (request_id + reason).
	AgentMsgLeashDenied = "agent_leash_denied"
)

// AgentLeashGrantedPayload carries a minted LEASH back to the agent that
// requested it via the leash_mint_request flow.
type AgentLeashGrantedPayload struct {
	RequestID string `json:"request_id"`
	Leash     string `json:"leash"`
	JTI       string `json:"jti"`
	Kid       string `json:"kid"`
	IssuedAt  int64  `json:"issued_at"`
	ExpiresAt int64  `json:"expires_at"`
}

// AgentLeashDeniedPayload tells the agent its mint request was denied.
type AgentLeashDeniedPayload struct {
	RequestID string `json:"request_id"`
	Reason    string `json:"reason"`
}

// AgentLeashMintRequest is the payload of an agent.message with
// content_type=leash_mint_request — the agent asking the owner to mint a
// LEASH bound to its Ed25519 pubkey.
type AgentLeashMintRequest struct {
	RequestID      string   `json:"request_id"`     // dedup + correlation
	AgentPubkey    string   `json:"agent_pubkey"`   // base64url Ed25519 pubkey to bind
	RequestedScope []string `json:"requested_scope"` // hint; phone is the authority
	DurationSecs   int64    `json:"duration_secs"`  // hint; phone may shorten
	Reason         string   `json:"reason,omitempty"`
}

// PendingLeashRequest stored at agent_leash_pending/{request_id} while the
// owner decides. Separate from PendingApproval (per-op secret approvals)
// because the payload + downstream action (HandleGrantAttest) differ.
type PendingLeashRequest struct {
	RequestID      string   `json:"request_id"`
	ConnectionID   string   `json:"connection_id"`
	AgentPubkey    string   `json:"agent_pubkey"`
	RequestedScope []string `json:"requested_scope"`
	DurationSecs   int64    `json:"duration_secs"`
	Reason         string   `json:"reason,omitempty"`
	CreatedAt      int64    `json:"created_at"`
	ExpiresAt      int64    `json:"expires_at"` // request-side TTL; owner has this long to decide
}

// --- Request/Response types (matching vettid-agent) ---

// AgentSecretRequest is the decrypted payload of a secret request.
type AgentSecretRequest struct {
	RequestID  string `json:"request_id"`
	SecretID   string `json:"secret_id,omitempty"`
	SecretType string `json:"secret_type,omitempty"`
	SecretName string `json:"secret_name,omitempty"`
	Purpose    string `json:"purpose"`
	TTL        int    `json:"ttl"`
	Action     string `json:"action"` // "retrieve"
}

// AgentSecretResponse is the response sent back for a secret request.
type AgentSecretResponse struct {
	RequestID   string `json:"request_id"`
	Status      string `json:"status"` // "approved", "denied", "pending_approval"
	SecretValue string `json:"secret_value,omitempty"`
	ExpiresAt   string `json:"expires_at,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

// AgentActionRequest is the decrypted payload of a use-in-enclave request.
type AgentActionRequest struct {
	RequestID string          `json:"request_id"`
	SecretID  string          `json:"secret_id"`
	Action    string          `json:"action"` // "http_request", "sign"
	Purpose   string          `json:"purpose"`
	Params    json.RawMessage `json:"params"`
}

// AgentActionResponse is the response sent back for an action request.
type AgentActionResponse struct {
	RequestID string          `json:"request_id"`
	Status    string          `json:"status"` // "completed", "denied", "error"
	Result    json.RawMessage `json:"result,omitempty"`
	Reason    string          `json:"reason,omitempty"`
}

// AgentHTTPRequestParams specifies an HTTP request to be made in the enclave.
type AgentHTTPRequestParams struct {
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	Headers         map[string]string `json:"headers,omitempty"`
	Body            string            `json:"body,omitempty"`
	SecretPlacement string            `json:"secret_placement"` // "bearer", "header", "query", "basic_auth"
	SecretField     string            `json:"secret_field,omitempty"`
}

// AgentHTTPResponseResult is the result of an HTTP request.
type AgentHTTPResponseResult struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       string            `json:"body"`
}

// AgentSignRequestParams specifies data to be signed in the enclave.
type AgentSignRequestParams struct {
	Data      string `json:"data"`      // base64-encoded
	Algorithm string `json:"algorithm"` // "ed25519", "hmac-sha256"
}

// AgentSignResult is the result of a signing operation.
type AgentSignResult struct {
	Signature string `json:"signature"` // base64-encoded
	Algorithm string `json:"algorithm"`
}

// AgentCatalogRefreshRequest asks the vault to re-push the catalog.
type AgentCatalogRefreshRequest struct {
	CurrentVersion uint64 `json:"current_version"`
}

// addToMessageIndex appends a message ID to the per-connection index
// at messages/<conn>/_index. Without this, message.list returns empty
// for agent conversations even after messages have been stored — the
// list handler iterates the index, not the messages/<conn>/* keyspace
// directly. Mirrors MessagingHandler.addToMessageIndex but lives here
// because the agent handler doesn't hold a MessagingHandler reference
// (only a *EncryptedStorage), and inlining at every store-site would
// be three copies of the same five lines.
func (h *AgentHandler) addToMessageIndex(connectionID, messageID string) {
	indexKey := fmt.Sprintf("messages/%s/_index", connectionID)
	var index []string
	if data, err := h.storage.Get(indexKey); err == nil {
		_ = json.Unmarshal(data, &index)
	}
	index = append(index, messageID)
	if data, err := json.Marshal(index); err == nil {
		_ = h.storage.Put(indexKey, data)
	}
}

// --- Main message handler ---

// HandleAgentMessage processes an incoming message from an agent connector.
// It parses the envelope, looks up the connection, decrypts the payload,
// routes to the appropriate handler, encrypts the response, and publishes it.
func (h *AgentHandler) HandleAgentMessage(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	// Parse envelope
	var envelope AgentEnvelope
	if err := unmarshalRequest(msg.Payload, &envelope, "HandleAgentMessage"); err != nil {
		log.Warn().Err(err).Msg("Failed to parse agent envelope")
		return nil, nil // Don't send error back — can't identify connection
	}

	if envelope.KeyID == "" {
		log.Warn().Msg("Agent envelope missing key_id")
		return nil, nil
	}

	log.Debug().
		Str("type", envelope.Type).
		Str("key_id", envelope.KeyID).
		Uint64("seq", envelope.Sequence).
		Msg("Processing agent message")

	// SECURITY (#32): rate-limit by connection_id (== envelope.KeyID).
	// Applied here, before the storage lookup and AEAD decrypt, so a
	// hostile peer holding valid creds can't burn CPU + the inbound
	// channel by spinning. Bucket: 60-message burst, 1 msg/sec refill,
	// 512 active connections. Connection requests share the same bucket
	// scheme keyed by the proposed connection_id.
	if h.rateLimiter != nil && !h.rateLimiter.Allow(envelope.KeyID) {
		log.Warn().
			Str("type", envelope.Type).
			Str("key_id", envelope.KeyID).
			Msg("Agent message rate-limited — dropping")
		return nil, nil
	}

	// Handle connection request separately — it's ECIES-encrypted, not connection-key encrypted
	if envelope.Type == AgentMsgConnectionRequest {
		return h.handleConnectionRequest(ctx, msg, &envelope)
	}

	// Look up connection by key_id (key_id == connection_id)
	conn, err := h.getConnection(envelope.KeyID)
	if err != nil {
		log.Warn().Str("key_id", envelope.KeyID).Msg("Agent connection not found")
		return nil, nil
	}

	// Validate connection
	if conn.Status != "active" {
		log.Warn().
			Str("connection_id", conn.ConnectionID).
			Str("status", conn.Status).
			Msg("Agent connection not active")
		return nil, nil
	}

	if !conn.IsAgent() {
		log.Warn().
			Str("connection_id", conn.ConnectionID).
			Str("type", conn.GetConnectionType()).
			Msg("Connection is not an agent connection")
		return nil, nil
	}

	// Load the encryption key for this connection. Agent connections
	// don't have a peer SharedSecret — every agent op (secret request,
	// catalog refresh, action request, owner→agent reply path) crypto
	// is keyed on AgentSession.SessionKey, sealed at Stage-2 pairing
	// under agent_session_keys/<conn>/<sessionKeyID>. The prior code
	// required SharedSecret unconditionally, which silently dropped
	// EVERY agent message (returned nil, nil from this handler with a
	// warn log) — observed during the 2026-05-24 chat-test hunt:
	// catalog refreshes accepted by the local /v1/secrets/refresh
	// endpoint never round-tripped to the vault, /v1/secrets stayed
	// empty forever, /v1/messages/send silently lost messages. Fix
	// mirrors HandleAgentMessageReply: prefer AgentSession key when
	// present; fall back to deriveConnectionKey for any non-agent
	// caller this entrypoint ever picks up.
	var connKey []byte
	if conn.AgentSession != nil && conn.AgentSession.SessionKeyID != "" {
		keyPath := fmt.Sprintf("agent_session_keys/%s/%s", conn.ConnectionID, conn.AgentSession.SessionKeyID)
		sessionKey, err := h.storage.Get(keyPath)
		if err != nil || len(sessionKey) == 0 {
			log.Warn().
				Str("connection_id", conn.ConnectionID).
				Str("session_key_id", conn.AgentSession.SessionKeyID).
				Msg("Agent session key not found in storage (extend or re-pair required)")
			return nil, nil
		}
		connKey = sessionKey
	} else {
		if len(conn.SharedSecret) == 0 {
			log.Warn().
				Str("connection_id", conn.ConnectionID).
				Msg("Agent connection has neither AgentSession nor SharedSecret")
			return nil, nil
		}
		ck, err := deriveConnectionKey(conn.SharedSecret)
		if err != nil {
			log.Error().Err(err).Str("connection_id", conn.ConnectionID).Msg("Failed to derive connection key")
			return nil, nil
		}
		connKey = ck
	}
	defer zeroBytes(connKey)

	// Decrypt payload
	encryptedPayload, err := extractPayloadBytes(envelope.Payload)
	if err != nil {
		log.Warn().Err(err).Str("connection_id", conn.ConnectionID).Msg("Failed to extract payload bytes")
		return nil, nil
	}

	plaintext, err := decryptXChaCha20(connKey, encryptedPayload)
	if err != nil {
		log.Warn().Err(err).Str("connection_id", conn.ConnectionID).Msg("Failed to decrypt agent payload")
		return nil, nil
	}
	defer zeroBytes(plaintext)

	// Route by message type
	var responseBytes []byte
	var responseType string

	switch envelope.Type {
	case AgentMsgSecretRequest:
		responseBytes, responseType, err = h.handleSecretRequest(ctx, conn, plaintext)
	case AgentMsgActionRequest:
		responseBytes, responseType, err = h.handleActionRequest(ctx, conn, plaintext)
	case AgentMsgCatalogRequest:
		responseBytes, responseType, err = h.handleCatalogRequest(ctx, conn, plaintext)
	case AgentMsgMessage:
		responseBytes, responseType, err = h.handleAgentMessage(ctx, conn, plaintext)
	default:
		log.Warn().Str("type", envelope.Type).Msg("Unknown agent message type")
		return nil, nil
	}

	if err != nil {
		log.Error().Err(err).
			Str("type", envelope.Type).
			Str("connection_id", conn.ConnectionID).
			Msg("Agent handler error")
		return nil, nil
	}

	// Encrypt response
	encryptedResponse, err := encryptXChaCha20(connKey, responseBytes)
	if err != nil {
		log.Error().Err(err).Msg("Failed to encrypt agent response")
		return nil, nil
	}
	zeroBytes(responseBytes)

	// Build response envelope. Sequence is time.Now().UnixNano() rather
	// than echoing envelope.Sequence — the agent's EnvelopeValidator
	// (messages.go) keeps a SINGLE global lastSeqSeen across every
	// inbound envelope on the connection, so the vault has to emit a
	// monotonically-increasing sequence across ALL response paths
	// (this one + publishAgentResponse). Echoing the request sequence
	// here would conflict with the unsolicited publishes (chat replies
	// etc.) that have no request to echo — those use UnixNano too.
	// UnixNano is non-zero, monotonic across vault restarts, and
	// distinct from anything the agent has seen before.
	respEnvelope := AgentEnvelope{
		Type:      responseType,
		KeyID:     conn.ConnectionID,
		Timestamp: time.Now().UTC(),
		Sequence:  uint64(time.Now().UnixNano()),
	}

	// Marshal the encrypted payload as JSON bytes for the envelope
	encPayloadJSON, _ := json.Marshal(encryptedResponse)
	respEnvelope.Payload = encPayloadJSON

	envBytes, err := json.Marshal(respEnvelope)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal agent response envelope")
		return nil, nil
	}

	// Publish response to the agent's response topic
	responseTopic := fmt.Sprintf("MessageSpace.%s.forOwner.agent.%s", h.ownerSpace, conn.ConnectionID)
	if err := h.publisher.PublishRaw(responseTopic, envBytes); err != nil {
		log.Error().Err(err).
			Str("topic", responseTopic).
			Msg("Failed to publish agent response")
		return nil, nil
	}

	log.Debug().
		Str("type", responseType).
		Str("connection_id", conn.ConnectionID).
		Str("topic", responseTopic).
		Msg("Agent response published")

	// Return nil — response was sent directly via publisher, not through standard reply path
	return nil, nil
}

// --- Type-specific handlers ---

// handleSecretRequest processes a secret retrieve request from an agent.
func (h *AgentHandler) handleSecretRequest(ctx context.Context, conn *ConnectionRecord, plaintext []byte) ([]byte, string, error) {
	var req AgentSecretRequest
	if err := json.Unmarshal(plaintext, &req); err != nil {
		return nil, "", fmt.Errorf("invalid secret request: %w", err)
	}

	log.Info().
		Str("connection_id", conn.ConnectionID).
		Str("request_id", req.RequestID).
		Str("secret_id", req.SecretID).
		Str("purpose", req.Purpose).
		Msg("Agent secret request")

	// Resolve secret
	secret, err := h.resolveSecret(req)
	if err != nil {
		resp := AgentSecretResponse{
			RequestID: req.RequestID,
			Status:    "denied",
			Reason:    "Secret not found",
		}
		data, _ := json.Marshal(resp)
		return data, AgentMsgSecretResponse, nil
	}

	// Check capability — secrets.get gates the whole retrieve path.
	if conn.Contract == nil || !HasCapability(conn.Contract.Scope, CapSecretsGet) {
		h.eventHandler.LogConnectionEvent(ctx, EventTypeAgentSecretDenied, conn.ConnectionID, "",
			fmt.Sprintf("secrets.get capability not granted (secret %s)", secret.SecretID))
		resp := AgentSecretResponse{
			RequestID: req.RequestID,
			Status:    "denied",
			Reason:    "Capability secrets.get not granted",
		}
		data, _ := json.Marshal(resp)
		return data, AgentMsgSecretResponse, nil
	}

	// Check per-secret allowed actions. Minor secrets currently expose
	// "retrieve" only; future per-secret action allowlists (sign, derive)
	// would gate here.
	if !HasAction("retrieve", secret.AllowedActions) {
		resp := AgentSecretResponse{
			RequestID: req.RequestID,
			Status:    "denied",
			Reason:    "Retrieve action not allowed for this secret",
		}
		data, _ := json.Marshal(resp)
		return data, AgentMsgSecretResponse, nil
	}

	// Check approval mode
	approvalMode := "always_ask"
	if conn.Contract != nil {
		approvalMode = conn.Contract.ApprovalMode
	}

	switch approvalMode {
	case "auto_all", "auto_within_contract":
		// Auto-approve
		h.eventHandler.LogConnectionEvent(ctx, EventTypeAgentSecretAutoApproved, conn.ConnectionID, "",
			fmt.Sprintf("Auto-approved secret %s for agent %s", secret.Name, conn.PeerAlias))

		expiresAt := ""
		if req.TTL > 0 {
			expiresAt = time.Now().Add(time.Duration(req.TTL) * time.Second).UTC().Format(time.RFC3339)
		}

		resp := AgentSecretResponse{
			RequestID:   req.RequestID,
			Status:      "approved",
			SecretValue: secret.Value,
			ExpiresAt:   expiresAt,
		}
		data, _ := json.Marshal(resp)
		return data, AgentMsgSecretResponse, nil

	default: // "always_ask"
		// Store pending approval so we can fulfill it when the app responds
		h.pendingApprovals[req.RequestID] = &PendingApproval{
			RequestID:    req.RequestID,
			ConnectionID: conn.ConnectionID,
			SecretID:     secret.SecretID,
			Action:       "retrieve",
			Purpose:      req.Purpose,
			CreatedAt:    time.Now(),
		}

		// Send approval request to mobile app
		approvalPayload, _ := json.Marshal(map[string]interface{}{
			"request_id":    req.RequestID,
			"connection_id": conn.ConnectionID,
			"agent_name":    conn.PeerAlias,
			"secret_id":     secret.SecretID,
			"secret_name":   secret.Name,
			"category":      secret.Category,
			"purpose":       req.Purpose,
			"action":        req.Action,
		})
		h.publisher.PublishToApp(ctx, "agent.secret.request", approvalPayload)

		h.eventHandler.LogConnectionEvent(ctx, EventTypeAgentSecretRequested, conn.ConnectionID, "",
			fmt.Sprintf("Secret request pending approval: %s for %s", secret.Name, conn.PeerAlias))

		resp := AgentSecretResponse{
			RequestID: req.RequestID,
			Status:    "pending_approval",
			Reason:    "Awaiting owner approval",
		}
		data, _ := json.Marshal(resp)
		return data, AgentMsgSecretResponse, nil
	}
}

// handleActionRequest processes a use-in-enclave action request from an agent.
func (h *AgentHandler) handleActionRequest(ctx context.Context, conn *ConnectionRecord, plaintext []byte) ([]byte, string, error) {
	var req AgentActionRequest
	if err := json.Unmarshal(plaintext, &req); err != nil {
		return nil, "", fmt.Errorf("invalid action request: %w", err)
	}

	log.Info().
		Str("connection_id", conn.ConnectionID).
		Str("request_id", req.RequestID).
		Str("secret_id", req.SecretID).
		Str("action", req.Action).
		Str("purpose", req.Purpose).
		Msg("Agent action request")

	// Look up secret
	secret, err := h.secretsHandler.GetSecret(req.SecretID)
	if err != nil {
		resp := AgentActionResponse{
			RequestID: req.RequestID,
			Status:    "denied",
			Reason:    "Secret not found",
		}
		data, _ := json.Marshal(resp)
		return data, AgentMsgActionResponse, nil
	}

	// Check capability — secrets.action gates use-with operations.
	if conn.Contract == nil || !HasCapability(conn.Contract.Scope, CapSecretsAction) {
		h.eventHandler.LogConnectionEvent(ctx, EventTypeAgentActionDenied, conn.ConnectionID, "",
			fmt.Sprintf("secrets.action capability not granted (secret %s)", secret.SecretID))
		resp := AgentActionResponse{
			RequestID: req.RequestID,
			Status:    "denied",
			Reason:    "Capability secrets.action not granted",
		}
		data, _ := json.Marshal(resp)
		return data, AgentMsgActionResponse, nil
	}

	// Per-secret action allowlist
	if !HasAction("use", secret.AllowedActions) {
		resp := AgentActionResponse{
			RequestID: req.RequestID,
			Status:    "denied",
			Reason:    "Use action not allowed for this secret",
		}
		data, _ := json.Marshal(resp)
		return data, AgentMsgActionResponse, nil
	}

	// Check approval mode
	approvalMode := "always_ask"
	if conn.Contract != nil {
		approvalMode = conn.Contract.ApprovalMode
	}

	if approvalMode == "always_ask" {
		// Store pending approval so we can fulfill it when the app responds
		h.pendingApprovals[req.RequestID] = &PendingApproval{
			RequestID:    req.RequestID,
			ConnectionID: conn.ConnectionID,
			SecretID:     req.SecretID,
			Action:       req.Action,
			Purpose:      req.Purpose,
			Params:       req.Params,
			CreatedAt:    time.Now(),
		}

		// Send approval request to mobile app
		approvalPayload, _ := json.Marshal(map[string]interface{}{
			"request_id":    req.RequestID,
			"connection_id": conn.ConnectionID,
			"agent_name":    conn.PeerAlias,
			"secret_id":     secret.SecretID,
			"secret_name":   secret.Name,
			"category":      secret.Category,
			"action":        req.Action,
			"purpose":       req.Purpose,
		})
		h.publisher.PublishToApp(ctx, "agent.action.request", approvalPayload)

		h.eventHandler.LogConnectionEvent(ctx, EventTypeAgentActionRequested, conn.ConnectionID, "",
			fmt.Sprintf("Action request pending approval: %s on %s for %s", req.Action, secret.Name, conn.PeerAlias))

		resp := AgentActionResponse{
			RequestID: req.RequestID,
			Status:    "pending_approval",
			Reason:    "Awaiting owner approval",
		}
		data, _ := json.Marshal(resp)
		return data, AgentMsgActionResponse, nil
	}

	// Auto-approve: execute the action
	h.eventHandler.LogConnectionEvent(ctx, EventTypeAgentActionCompleted, conn.ConnectionID, "",
		fmt.Sprintf("Action auto-approved: %s on %s for %s", req.Action, secret.Name, conn.PeerAlias))

	result, err := h.executeAction(req, secret)
	if err != nil {
		log.Error().Err(err).
			Str("action", req.Action).
			Str("secret_id", req.SecretID).
			Msg("Action execution failed")

		resp := AgentActionResponse{
			RequestID: req.RequestID,
			Status:    "error",
			Reason:    "Action execution failed",
		}
		data, _ := json.Marshal(resp)
		return data, AgentMsgActionResponse, nil
	}

	resp := AgentActionResponse{
		RequestID: req.RequestID,
		Status:    "completed",
		Result:    result,
	}
	data, _ := json.Marshal(resp)
	return data, AgentMsgActionResponse, nil
}

// handleCatalogRequest processes a catalog refresh request from an agent.
// The catalog returned is the same one peers see via the profile (minor
// secrets with Discoverability != private) — see agent_secrets.go
// BuildCatalog. Capability secrets.catalog.read gates the call.
func (h *AgentHandler) handleCatalogRequest(ctx context.Context, conn *ConnectionRecord, plaintext []byte) ([]byte, string, error) {
	var req AgentCatalogRefreshRequest
	if err := json.Unmarshal(plaintext, &req); err != nil {
		return nil, "", fmt.Errorf("invalid catalog request: %w", err)
	}

	if conn.Contract == nil || !HasCapability(conn.Contract.Scope, CapSecretsCatalogRead) {
		log.Info().
			Str("connection_id", conn.ConnectionID).
			Msg("Catalog refresh denied — secrets.catalog.read not granted")
		// Return an empty catalog rather than an error envelope so the
		// agent still has a defined response shape. A capability-denied
		// agent that polls the catalog gets a steady-state empty answer.
		empty := &AgentSecretCatalog{Entries: []AgentSecretCatalogEntry{}}
		data, _ := json.Marshal(empty)
		return data, AgentMsgCatalogResponse, nil
	}

	log.Info().
		Str("connection_id", conn.ConnectionID).
		Uint64("current_version", req.CurrentVersion).
		Msg("Agent catalog refresh request")

	catalog := h.secretsHandler.BuildCatalog()

	data, err := json.Marshal(catalog)
	if err != nil {
		return nil, "", fmt.Errorf("marshal catalog: %w", err)
	}

	return data, AgentMsgCatalogResponse, nil
}

// handleAgentMessage processes a text message or approval request from an agent.
// Stores the message, creates a feed event, and notifies the app. Gated on
// the agent having the message.send capability.
func (h *AgentHandler) handleAgentMessage(ctx context.Context, conn *ConnectionRecord, plaintext []byte) ([]byte, string, error) {
	if conn.Contract == nil || !HasCapability(conn.Contract.Scope, CapMessageSend) {
		log.Info().
			Str("connection_id", conn.ConnectionID).
			Msg("agent message dropped — message.send capability not granted")
		ack, _ := json.Marshal(map[string]interface{}{"status": "denied", "reason": "capability message.send not granted"})
		return ack, AgentMsgMessageAck, nil
	}

	var msg struct {
		MessageID         string          `json:"message_id"`
		ContentType       string          `json:"content_type"` // "text", "approval_request", or "leash_mint_request"
		Content           string          `json:"content"`
		Approval          json.RawMessage `json:"approval,omitempty"`
		LeashMintRequest  json.RawMessage `json:"leash_mint_request,omitempty"`
	}
	if err := json.Unmarshal(plaintext, &msg); err != nil {
		return nil, "", fmt.Errorf("invalid agent message: %w", err)
	}

	if msg.MessageID == "" {
		msg.MessageID = fmt.Sprintf("amsg-%d", time.Now().UnixNano())
	}

	// LEASH mint requests are a transactional side-channel ask, not chat
	// content. Branch out before the chat-message storage path so the
	// request doesn't pollute the conversation thread and the response
	// flow can deliver the JWT directly to the agent via a distinct
	// envelope type (AgentMsgLeashGranted).
	if msg.ContentType == "leash_mint_request" {
		return h.handleLeashMintRequest(ctx, conn, msg.MessageID, msg.LeashMintRequest)
	}

	agentName := conn.PeerAlias
	if agentName == "" {
		agentName = "Agent"
	}
	agentType := ""
	if conn.AgentMetadata != nil {
		agentType = conn.AgentMetadata.AgentType
	}

	// Store message in the connection's message namespace. Use the
	// proper MessageRecord struct so time.Time fields serialize as
	// RFC3339 strings — the prior map literal stamped created_at as
	// time.Now().Unix() (int), which then failed to unmarshal back
	// into MessageRecord.CreatedAt (time.Time) when HandleList read
	// it, silently dropping the record. Result: message.list returned
	// empty for every agent conversation regardless of how many
	// messages had been exchanged — observed during 2026-05-25 v8
	// validation.
	contentType := msg.ContentType
	if contentType == "" {
		contentType = "text"
	}
	rec := MessageRecord{
		MessageID:    msg.MessageID,
		ConnectionID: conn.ConnectionID,
		Direction:    MessageDirectionIncoming,
		ContentType:  contentType,
		Status:       MessageStatusDelivered,
		Content:      msg.Content,
		CreatedAt:    time.Now().UTC(),
	}
	recordBytes, _ := json.Marshal(rec)
	storageKey := fmt.Sprintf("messages/%s/%s", conn.ConnectionID, msg.MessageID)
	if err := h.storage.Put(storageKey, recordBytes); err != nil {
		log.Warn().Err(err).Msg("Failed to store agent message")
	}
	h.addToMessageIndex(conn.ConnectionID, msg.MessageID)

	// Create feed event based on content type
	if msg.ContentType == "approval_request" {
		// Parse approval details for the feed event
		var approval struct {
			Title       string `json:"title"`
			Description string `json:"description"`
		}
		if msg.Approval != nil {
			json.Unmarshal(msg.Approval, &approval)
		}
		title := approval.Title
		if title == "" {
			title = fmt.Sprintf("%s requests approval", agentName)
		}

		// Store as pending approval for the app to act on
		h.pendingApprovals[msg.MessageID] = &PendingApproval{
			RequestID:    msg.MessageID,
			ConnectionID: conn.ConnectionID,
			Action:       "approval_request",
			Purpose:      approval.Description,
			CreatedAt:    time.Now(),
		}

		if h.eventHandler != nil {
			h.eventHandler.LogEvent(ctx, &Event{
				EventType:  EventTypeAgentApprovalRequested,
				SourceType: "agent",
				SourceID:   conn.ConnectionID,
				Title:      title,
				Message:    approval.Description,
				Metadata: map[string]string{
					"message_id":    msg.MessageID,
					"connection_id": conn.ConnectionID,
					"agent_name":    agentName,
					"agent_type":    agentType,
					"content_type":  msg.ContentType,
				},
			})
		}
	} else {
		// Text message — show in feed and notify app
		preview := msg.Content
		if len(preview) > 100 {
			preview = preview[:100] + "..."
		}

		if h.eventHandler != nil {
			h.eventHandler.LogEvent(ctx, &Event{
				EventType:  EventTypeAgentMessageReceived,
				SourceType: "agent",
				SourceID:   conn.ConnectionID,
				Title:      fmt.Sprintf("From %s", agentName),
				Message:    preview,
				Metadata: map[string]string{
					"message_id":    msg.MessageID,
					"connection_id": conn.ConnectionID,
					"agent_name":    agentName,
					"agent_type":    agentType,
					"content_type":  "text",
				},
			})
		}
	}

	// Notify the app in real-time
	if h.publisher != nil {
		notification := map[string]interface{}{
			"message_id":    msg.MessageID,
			"connection_id": conn.ConnectionID,
			"agent_name":    agentName,
			"agent_type":    agentType,
			"content":       msg.Content,
			"content_type":  msg.ContentType,
			"sent_at":       time.Now().Unix(),
		}
		if msg.Approval != nil {
			notification["approval"] = json.RawMessage(msg.Approval)
		}
		notifBytes, _ := json.Marshal(notification)
		eventType := "agent.message.received"
		if msg.ContentType == "approval_request" {
			eventType = "agent.approval.request"
		}
		h.publisher.PublishToApp(ctx, eventType, notifBytes)
	}

	// Ack to agent. Distinct envelope type from AgentMsgMessageResponse
	// so the agent doesn't echo this ack into the owner-reply log.
	ack, _ := json.Marshal(map[string]interface{}{
		"message_id": msg.MessageID,
		"status":     "delivered",
	})
	return ack, AgentMsgMessageAck, nil
}

// handleLeashMintRequest accepts an agent-initiated request to mint a
// LEASH bound to its own Ed25519 pubkey. The flow:
//
//  1. Decode + validate the request payload.
//  2. Persist a PendingLeashRequest under agent_leash_pending/{request_id}.
//  3. Push a forApp.agent.leash-mint-pending notification so the owner's
//     phone auto-navigates to LeashApprovalScreen.
//  4. Return an ack to the agent (no JWT yet — that arrives later via
//     AgentMsgLeashGranted/Denied once the owner approves or denies).
//
// Approval lands later via HandleAgentLeashApprove (the phone publishes
// agent.leash-approve); that's where we mint via HandleGrantAttest and
// publish the JWT back to the agent.
const leashRequestTTL = 5 * time.Minute

// leashPendingIndexKey is the index of all live PendingLeashRequest
// row IDs for this owner. Used by HandleAgentLeashPendingList so the
// phone can poll on resume and recover any requests it missed while
// backgrounded (forApp.agent.leash-mint-pending is NATS core, not
// JetStream — dropped if no subscriber was live at publish time).
const leashPendingIndexKey = "agent_leash_pending/_index"

func (h *AgentHandler) handleLeashMintRequest(ctx context.Context, conn *ConnectionRecord, fallbackRequestID string, raw json.RawMessage) ([]byte, string, error) {
	if len(raw) == 0 {
		return nil, "", fmt.Errorf("leash_mint_request payload is required")
	}
	var req AgentLeashMintRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, "", fmt.Errorf("invalid leash_mint_request payload: %w", err)
	}

	if req.RequestID == "" {
		req.RequestID = fallbackRequestID
	}
	if req.AgentPubkey == "" {
		return nil, "", fmt.Errorf("agent_pubkey is required (base64url Ed25519 pubkey)")
	}
	if len(req.RequestedScope) == 0 {
		return nil, "", fmt.Errorf("at least one requested_scope token is required")
	}
	if req.DurationSecs <= 0 {
		req.DurationSecs = 1800 // 30m default — matches the demo session length used by vettid.dev/leash
	}

	now := time.Now()
	pending := PendingLeashRequest{
		RequestID:      req.RequestID,
		ConnectionID:   conn.ConnectionID,
		AgentPubkey:    req.AgentPubkey,
		RequestedScope: req.RequestedScope,
		DurationSecs:   req.DurationSecs,
		Reason:         req.Reason,
		CreatedAt:      now.Unix(),
		ExpiresAt:      now.Add(leashRequestTTL).Unix(),
	}
	body, err := json.Marshal(&pending)
	if err != nil {
		return nil, "", fmt.Errorf("marshal pending leash request: %w", err)
	}
	storageKey := "agent_leash_pending/" + req.RequestID
	if err := h.storage.Put(storageKey, body); err != nil {
		return nil, "", fmt.Errorf("persist pending leash request: %w", err)
	}
	if err := h.storage.AddToIndex(leashPendingIndexKey, req.RequestID); err != nil {
		// Non-fatal — the row exists, the index is just for the
		// resume-recovery list op. Log and continue.
		log.Warn().Err(err).Str("request_id", req.RequestID).
			Msg("Failed to add pending leash request to index (resume recovery may miss this)")
	}

	if h.publisher != nil {
		agentName := conn.PeerAlias
		if agentName == "" {
			agentName = "Agent"
		}
		agentType := ""
		if conn.AgentMetadata != nil {
			agentType = conn.AgentMetadata.AgentType
		}
		notif := map[string]interface{}{
			"type":            "agent.leash-mint-pending",
			"request_id":      req.RequestID,
			"connection_id":   conn.ConnectionID,
			"agent_name":      agentName,
			"agent_type":      agentType,
			"agent_pubkey":    req.AgentPubkey,
			"requested_scope": req.RequestedScope,
			"duration_secs":   req.DurationSecs,
			"reason":          req.Reason,
			"expires_at":      pending.ExpiresAt,
		}
		notifBytes, _ := json.Marshal(notif)
		if err := h.publisher.PublishToApp(ctx, "agent.leash-mint-pending", notifBytes); err != nil {
			log.Warn().Err(err).Msg("Failed to publish agent.leash-mint-pending (non-fatal)")
		}
	}

	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(ctx, EventTypeAgentSessionCreated, conn.ConnectionID, "",
			fmt.Sprintf("Agent requested LEASH mint (%d scope tokens, %ds)", len(req.RequestedScope), req.DurationSecs))
	}

	log.Info().
		Str("connection_id", conn.ConnectionID).
		Str("request_id", req.RequestID).
		Int("scope_count", len(req.RequestedScope)).
		Int64("duration_secs", req.DurationSecs).
		Msg("LEASH mint request stored; awaiting owner approval")

	ack, _ := json.Marshal(map[string]interface{}{
		"status":     "pending",
		"request_id": req.RequestID,
		"expires_at": pending.ExpiresAt,
	})
	return ack, AgentMsgMessageAck, nil
}

// HandleAgentMessageReply processes a user's reply to an agent message.
// Called from the app via forVault.agent.message-reply.
// Encrypts the reply and publishes to the agent's NATS response topic.
func (h *AgentHandler) HandleAgentMessageReply(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		ConnectionID string `json:"connection_id"`
		Content      string `json:"content"`
		MessageID    string `json:"message_id,omitempty"` // Optional: reply to specific message
		Action       string `json:"action,omitempty"`     // For approval responses: "approve"/"deny"
	}
	if err := unmarshalRequest(msg.Payload, &req, "HandleAgentMessageReply"); err != nil {
		return errorResponse(msg.GetID(), "invalid request"), nil
	}

	if req.ConnectionID == "" {
		return errorResponse(msg.GetID(), "connection_id required"), nil
	}

	conn, err := h.getConnection(req.ConnectionID)
	if err != nil {
		return errorResponse(msg.GetID(), "connection not found"), nil
	}

	// Agent connections require the message.recv capability for the
	// vault to deliver owner replies. Peer connections (non-agent) use
	// their own visibility model and don't have an agent Contract; let
	// them through unchanged.
	if conn.IsAgent() && (conn.Contract == nil || !HasCapability(conn.Contract.Scope, CapMessageRecv)) {
		return errorResponse(msg.GetID(), "agent lacks message.recv capability"), nil
	}

	// Generate message ID
	replyID := fmt.Sprintf("reply-%d", time.Now().UnixNano())

	// Store outgoing message. Use the proper MessageRecord struct so
	// time.Time serializes as RFC3339 — the prior map literal stored
	// created_at as time.Now().Unix() (int) which broke unmarshal back
	// into MessageRecord.CreatedAt (time.Time) on the read path. The
	// `action` and `reply_to` fields aren't on the struct; if we ever
	// surface those on the conversation pane we'll add them. For now
	// they're audit-log-only via the LogEvent call below.
	rec := MessageRecord{
		MessageID:    replyID,
		ConnectionID: conn.ConnectionID,
		Direction:    MessageDirectionOutgoing,
		ContentType:  "text",
		Status:       MessageStatusSent,
		Content:      req.Content,
		CreatedAt:    time.Now().UTC(),
	}
	recordBytes, _ := json.Marshal(rec)
	storageKey := fmt.Sprintf("messages/%s/%s", conn.ConnectionID, replyID)
	h.storage.Put(storageKey, recordBytes)
	h.addToMessageIndex(conn.ConnectionID, replyID)

	// Build response for agent
	agentResponse := map[string]interface{}{
		"message_id": replyID,
	}
	if req.Action != "" {
		agentResponse["action"] = req.Action
	}
	if req.Content != "" {
		agentResponse["reply_content"] = req.Content
	}
	if req.MessageID != "" {
		agentResponse["reply_to"] = req.MessageID
	}

	responseBytes, _ := json.Marshal(agentResponse)

	// Encrypt with the right key for the connection type:
	//   - Agent connections: AgentSession.SessionKey (loaded from
	//     agent_session_keys storage by SessionKeyID). Agents don't
	//     have a peer SharedSecret — the prior unconditional
	//     deriveConnectionKey(SharedSecret) returned "shared secret
	//     must not be empty" for every agent reply, surfacing on the
	//     phone as "Message failed" (vettid-dev 2026-05-24 hunt).
	//   - Future peer-equivalent uses (none today): SharedSecret via
	//     deriveConnectionKey. Kept as the fallback so this stays
	//     safe if the caller surface ever broadens.
	var connKey []byte
	if conn.AgentSession != nil && conn.AgentSession.SessionKeyID != "" {
		keyPath := fmt.Sprintf("agent_session_keys/%s/%s", conn.ConnectionID, conn.AgentSession.SessionKeyID)
		sessionKey, err := h.storage.Get(keyPath)
		if err != nil || len(sessionKey) == 0 {
			return errorResponse(msg.GetID(), "agent session key not found (extend or re-pair required)"), nil
		}
		connKey = sessionKey
	} else {
		ck, err := deriveConnectionKey(conn.SharedSecret)
		if err != nil {
			return errorResponse(msg.GetID(), "failed to derive key"), nil
		}
		connKey = ck
	}
	defer zeroBytes(connKey)
	topic := fmt.Sprintf("MessageSpace.%s.forOwner.agent.%s", h.ownerSpace, conn.ConnectionID)
	h.publishAgentResponse(connKey, conn.ConnectionID, AgentMsgMessageResponse, responseBytes, topic)

	// Publish a forApp event so the OWNER's other surfaces (e.g.
	// desktop viewing the same conversation, or another paired phone)
	// refresh the conversation thread. Mirrors the agent.message.received
	// notification handleAgentMessage emits for the opposite direction.
	// Without this push, the surface that DIDN'T send the message
	// (the desktop here) has stale state until the user forces a
	// refresh — observed in the 2026-05-25 v6 validation pass.
	if h.publisher != nil {
		appNotif := map[string]interface{}{
			"message_id":    replyID,
			"connection_id": conn.ConnectionID,
			"direction":     "outgoing",
			"content":       req.Content,
			"content_type":  "text",
			"sent_at":       time.Now().Unix(),
		}
		appNotifBytes, _ := json.Marshal(appNotif)
		_ = h.publisher.PublishToApp(ctx, "agent.message.sent", appNotifBytes)
	}

	// Log event
	if h.eventHandler != nil {
		h.eventHandler.LogEvent(ctx, &Event{
			EventType:  EventTypeAgentMessageSent,
			SourceType: "agent",
			SourceID:   conn.ConnectionID,
			Title:      "Reply sent",
			Message:    req.Content,
			Metadata: map[string]string{
				"message_id":    replyID,
				"connection_id": conn.ConnectionID,
			},
		})
	}

	resp, _ := json.Marshal(map[string]interface{}{
		"success":    true,
		"message_id": replyID,
	})
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   resp,
	}, nil
}

// HandleAppApprovalResponse processes an approval/denial from the mobile app
// for a pending agent request. It looks up the pending request, fulfills it
// by sending the response to the agent, and cleans up.
func (h *AgentHandler) HandleAppApprovalResponse(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var payload struct {
		RequestID string `json:"request_id"`
		Response  string `json:"response"` // "approve" or "deny"
		Reason    string `json:"reason,omitempty"`
	}
	if err := unmarshalRequest(msg.Payload, &payload, "HandleAppApprovalResponse"); err != nil {
		log.Warn().Err(err).Msg("Failed to parse approval response payload")
		return createSuccessResponse(msg.GetID(), false, "invalid payload")
	}

	if payload.RequestID == "" {
		return createSuccessResponse(msg.GetID(), false, "missing request_id")
	}

	// Look up pending approval
	pending, ok := h.pendingApprovals[payload.RequestID]
	if !ok {
		log.Warn().Str("request_id", payload.RequestID).Msg("No pending approval found")
		return createSuccessResponse(msg.GetID(), false, "no pending request found")
	}

	// Clean up regardless of outcome
	delete(h.pendingApprovals, payload.RequestID)

	// Look up connection
	conn, err := h.getConnection(pending.ConnectionID)
	if err != nil {
		log.Warn().Str("connection_id", pending.ConnectionID).Msg("Connection not found for pending approval")
		return createSuccessResponse(msg.GetID(), false, "connection not found")
	}

	// Derive connection key
	connKey, err := deriveConnectionKey(conn.SharedSecret)
	if err != nil {
		log.Error().Err(err).Msg("Failed to derive connection key for approval response")
		return createSuccessResponse(msg.GetID(), false, "internal error")
	}
	defer zeroBytes(connKey)

	responseTopic := fmt.Sprintf("MessageSpace.%s.forOwner.agent.%s", h.ownerSpace, conn.ConnectionID)

	if payload.Response == "deny" {
		// Denied
		h.eventHandler.LogConnectionEvent(ctx, EventTypeAgentSecretDenied, conn.ConnectionID, "",
			fmt.Sprintf("Owner denied request %s: %s", pending.RequestID, payload.Reason))

		var respBytes []byte
		var respType string

		if pending.Action == "retrieve" {
			resp := AgentSecretResponse{
				RequestID: pending.RequestID,
				Status:    "denied",
				Reason:    "Owner denied the request",
			}
			if payload.Reason != "" {
				resp.Reason = payload.Reason
			}
			respBytes, _ = json.Marshal(resp)
			respType = AgentMsgSecretResponse
		} else {
			resp := AgentActionResponse{
				RequestID: pending.RequestID,
				Status:    "denied",
				Reason:    "Owner denied the request",
			}
			if payload.Reason != "" {
				resp.Reason = payload.Reason
			}
			respBytes, _ = json.Marshal(resp)
			respType = AgentMsgActionResponse
		}

		h.publishAgentResponse(connKey, conn.ConnectionID, respType, respBytes, responseTopic)
		return createSuccessResponse(msg.GetID(), true, "denied")
	}

	// Approved — fulfill the request
	if pending.Action == "retrieve" {
		// Retrieve secret
		secret, err := h.secretsHandler.GetSecret(pending.SecretID)
		if err != nil {
			log.Error().Err(err).Str("secret_id", pending.SecretID).Msg("Secret not found for approved request")
			return createSuccessResponse(msg.GetID(), false, "secret no longer available")
		}

		h.eventHandler.LogConnectionEvent(ctx, EventTypeAgentSecretAutoApproved, conn.ConnectionID, "",
			fmt.Sprintf("Owner approved secret %s for agent %s", secret.Name, conn.PeerAlias))

		resp := AgentSecretResponse{
			RequestID:   pending.RequestID,
			Status:      "approved",
			SecretValue: secret.Value,
		}
		respBytes, _ := json.Marshal(resp)
		h.publishAgentResponse(connKey, conn.ConnectionID, AgentMsgSecretResponse, respBytes, responseTopic)
		zeroBytes(respBytes)
	} else {
		// Execute action
		secret, err := h.secretsHandler.GetSecret(pending.SecretID)
		if err != nil {
			log.Error().Err(err).Str("secret_id", pending.SecretID).Msg("Secret not found for approved action")
			return createSuccessResponse(msg.GetID(), false, "secret no longer available")
		}

		h.eventHandler.LogConnectionEvent(ctx, EventTypeAgentActionCompleted, conn.ConnectionID, "",
			fmt.Sprintf("Owner approved action %s on %s for %s", pending.Action, secret.Name, conn.PeerAlias))

		actionReq := AgentActionRequest{
			RequestID: pending.RequestID,
			SecretID:  pending.SecretID,
			Action:    pending.Action,
			Purpose:   pending.Purpose,
			Params:    pending.Params,
		}

		result, err := h.executeAction(actionReq, secret)
		if err != nil {
			resp := AgentActionResponse{
				RequestID: pending.RequestID,
				Status:    "error",
				Reason:    "Action execution failed",
			}
			respBytes, _ := json.Marshal(resp)
			h.publishAgentResponse(connKey, conn.ConnectionID, AgentMsgActionResponse, respBytes, responseTopic)
			return createSuccessResponse(msg.GetID(), true, "approved but action failed")
		}

		resp := AgentActionResponse{
			RequestID: pending.RequestID,
			Status:    "completed",
			Result:    result,
		}
		respBytes, _ := json.Marshal(resp)
		h.publishAgentResponse(connKey, conn.ConnectionID, AgentMsgActionResponse, respBytes, responseTopic)
	}

	return createSuccessResponse(msg.GetID(), true, "approved")
}

// publishAgentResponse encrypts and publishes a response to an agent.
func (h *AgentHandler) publishAgentResponse(connKey []byte, connectionID, responseType string, responseBytes []byte, topic string) {
	encrypted, err := encryptXChaCha20(connKey, responseBytes)
	if err != nil {
		log.Error().Err(err).Msg("Failed to encrypt agent approval response")
		return
	}

	encPayloadJSON, _ := json.Marshal(encrypted)
	envBytes, err := json.Marshal(AgentEnvelope{
		Type:      responseType,
		KeyID:     connectionID,
		Payload:   encPayloadJSON,
		Timestamp: time.Now().UTC(),
		// Non-zero monotonic sequence — agent's EnvelopeValidator
		// rejects zero ("envelope sequence missing") and any value
		// not strictly greater than lastSeqSeen. UnixNano gives both
		// guarantees in one shot, with no need for a per-handler
		// counter or persisted state. Must align with HandleAgentMessage's
		// inline response envelope which uses the same source.
		Sequence: uint64(time.Now().UnixNano()),
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal agent approval response envelope")
		return
	}

	if err := h.publisher.PublishRaw(topic, envBytes); err != nil {
		log.Error().Err(err).Str("topic", topic).Msg("Failed to publish agent approval response")
	}
}

// createSuccessResponse builds a standard success/error response for app-to-vault operations.
func createSuccessResponse(requestID string, success bool, message string) (*OutgoingMessage, error) {
	resp := map[string]interface{}{
		"success": success,
		"message": message,
	}
	respBytes, _ := json.Marshal(resp)
	return &OutgoingMessage{
		RequestID: requestID,
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// CleanExpiredApprovals removes pending approvals older than the given duration.
func (h *AgentHandler) CleanExpiredApprovals(maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge)
	for id, pending := range h.pendingApprovals {
		if pending.CreatedAt.Before(cutoff) {
			delete(h.pendingApprovals, id)
			log.Debug().Str("request_id", id).Msg("Cleaned expired pending approval")
		}
	}
}

// handleConnectionRequest processes an agent connection request (registration completion).
// The payload is ECIES-encrypted with the vault's public key, not connection-key encrypted.
func (h *AgentHandler) handleConnectionRequest(ctx context.Context, msg *IncomingMessage, envelope *AgentEnvelope) (*OutgoingMessage, error) {
	log.Info().Msg("Processing agent connection request")

	// The payload is ECIES-encrypted — delegate to connections handler
	resp, err := h.connHandler.HandleAcceptAgentConnection(ctx, msg, envelope)

	// HandleAcceptAgentConnection returns a nats_publish OutgoingMessage on success.
	// Publish it directly via the publisher so it becomes an intermediate message,
	// not the final response (which would cause the supervisor to hang).
	if resp != nil && resp.Type == MessageTypeNATSPublish {
		if pubErr := h.publisher.PublishRaw(resp.Subject, resp.Payload); pubErr != nil {
			log.Error().Err(pubErr).
				Str("subject", resp.Subject).
				Msg("Failed to publish agent connection response")
		}
		return nil, nil
	}

	return resp, err
}

// --- Action execution ---

// executeAction runs the requested action using the secret value.
// The secret value is used inside the enclave and never leaves it.
func (h *AgentHandler) executeAction(req AgentActionRequest, secret *AgentSharedSecret) (json.RawMessage, error) {
	switch req.Action {
	case "http_request":
		return h.executeHTTPRequest(req.Params, secret.Value)
	case "sign":
		return h.executeSign(req.Params, secret.Value)
	default:
		return nil, fmt.Errorf("unsupported action: %s", req.Action)
	}
}

// executeHTTPRequest makes an HTTP request with the secret injected.
// SECURITY: The secret value is injected per the secret_placement field
// and never returned in the response. Only the HTTP response is returned.
func (h *AgentHandler) executeHTTPRequest(params json.RawMessage, secretValue string) (json.RawMessage, error) {
	var p AgentHTTPRequestParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid HTTP request params: %w", err)
	}

	// Validate URL — only HTTPS allowed for security
	if len(p.URL) < 8 || p.URL[:8] != "https://" {
		return nil, fmt.Errorf("only HTTPS URLs are allowed")
	}

	// Validate method
	switch p.Method {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD":
		// OK
	default:
		return nil, fmt.Errorf("unsupported HTTP method: %s", p.Method)
	}

	// Build the request (actual HTTP execution is deferred to a future step
	// when the enclave has outbound HTTP capability via vsock proxy).
	// For now, return an error indicating the feature isn't available yet.
	result := AgentHTTPResponseResult{
		StatusCode: 501,
		Body:       "HTTP request execution not yet available in enclave",
	}

	data, _ := json.Marshal(result)
	return data, nil
}

// executeSign signs data using the secret value as the key.
func (h *AgentHandler) executeSign(params json.RawMessage, secretValue string) (json.RawMessage, error) {
	var p AgentSignRequestParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid sign params: %w", err)
	}

	switch p.Algorithm {
	case "hmac-sha256":
		// HMAC-SHA256 using secret as key
		mac := computeHMACSHA256([]byte(secretValue), []byte(p.Data))
		result := AgentSignResult{
			Signature: fmt.Sprintf("%x", mac),
			Algorithm: "hmac-sha256",
		}
		data, _ := json.Marshal(result)
		return data, nil

	default:
		return nil, fmt.Errorf("unsupported signing algorithm: %s", p.Algorithm)
	}
}

// --- Secret resolution ---

// resolveSecret finds a secret by ID, type+name fallback, or name. The
// type+name fallback walks the catalog (same visibility surface peers
// see) and resolves the first match to its full record.
func (h *AgentHandler) resolveSecret(req AgentSecretRequest) (*AgentSharedSecret, error) {
	if req.SecretID != "" {
		return h.secretsHandler.GetSecret(req.SecretID)
	}

	catalog := h.secretsHandler.BuildCatalog()
	for _, entry := range catalog.Entries {
		if req.SecretType != "" && entry.Category == req.SecretType {
			if req.SecretName == "" || entry.Name == req.SecretName {
				return h.secretsHandler.GetSecret(entry.SecretID)
			}
			continue
		}
		if req.SecretName != "" && entry.Name == req.SecretName {
			return h.secretsHandler.GetSecret(entry.SecretID)
		}
	}

	return nil, fmt.Errorf("secret not found")
}

// --- Connection lookup ---

// getConnection retrieves a connection record by ID.
func (h *AgentHandler) getConnection(connectionID string) (*ConnectionRecord, error) {
	data, err := h.storage.Get("connections/" + connectionID)
	if err != nil {
		return nil, fmt.Errorf("connection not found: %s", connectionID)
	}

	var record ConnectionRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("failed to unmarshal connection: %w", err)
	}

	return &record, nil
}

// --- Crypto helpers ---

// deriveConnectionKey derives the symmetric encryption key for a connection
// from the X25519 shared secret using HKDF-SHA256 with connection domain.
// Matches vettid-agent's DeriveConnectionKey.
func deriveConnectionKey(sharedSecret []byte) ([]byte, error) {
	if len(sharedSecret) == 0 {
		return nil, fmt.Errorf("shared secret must not be empty")
	}

	// HKDF-SHA256: salt=domain, info=nil
	// Matches agent: hkdf.New(sha256.New, sharedSecret, []byte(DomainConnection), nil)
	r := hkdf.New(sha256.New, sharedSecret, []byte(DomainConnection), nil)
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("HKDF expand: %w", err)
	}

	return key, nil
}

// encryptXChaCha20 encrypts data using XChaCha20-Poly1305.
// Format: nonce (24 bytes) || ciphertext+tag
// Matches vettid-agent's crypto.Encrypt.
func encryptXChaCha20(key, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// nonce is prepended to ciphertext
	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// decryptXChaCha20 decrypts data using XChaCha20-Poly1305.
// Expects format: nonce (24 bytes) || ciphertext+tag
// Matches vettid-agent's crypto.Decrypt.
func decryptXChaCha20(key, data []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	nonceSize := aead.NonceSize()
	minSize := nonceSize + aead.Overhead()
	if len(data) < minSize {
		return nil, fmt.Errorf("ciphertext too short: need at least %d bytes, got %d", minSize, len(data))
	}

	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: authentication failed")
	}

	return plaintext, nil
}

// extractPayloadBytes extracts the raw bytes from the JSON-encoded payload field.
// The agent sends encrypted bytes which get JSON-serialized as a base64 string.
func extractPayloadBytes(raw json.RawMessage) ([]byte, error) {
	var payload []byte
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("extract payload bytes: %w", err)
	}
	return payload, nil
}

// computeHMACSHA256 computes HMAC-SHA256.
func computeHMACSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// decryptECIESAgentDomain decrypts ECIES data from an agent using the agent domain.
// Format: ephemeral_pubkey (32) || nonce (24) || ciphertext+tag
func decryptECIESAgentDomain(privateKey []byte, data []byte) ([]byte, error) {
	minSize := 32 + chacha20poly1305.NonceSizeX + chacha20poly1305.Overhead
	if len(data) < minSize {
		return nil, fmt.Errorf("ECIES data too short: need at least %d bytes, got %d", minSize, len(data))
	}

	ephPub := data[:32]
	nonce := data[32 : 32+chacha20poly1305.NonceSizeX]
	ciphertext := data[32+chacha20poly1305.NonceSizeX:]

	// SECURITY (#83): wire-side ephemeral pub key — refuse small-order
	// points before the ECDH so a malicious agent can't probe the
	// vault's long-lived agent key via contributory behavior.
	sharedSecret, err := safeX25519(privateKey, ephPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH key exchange: %w", err)
	}
	defer zeroBytes(sharedSecret)

	// HKDF with agent domain
	r := hkdf.New(sha256.New, sharedSecret, []byte(DomainAgent), nil)
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

	// SECURITY (#72): try domainCryptoAADv1 first, fall back to nil
	// AAD for pre-#72 ciphertexts. The agent-side encrypt path will
	// adopt the same AAD in a paired vettid-agent update.
	plaintext, err := aeadOpenWithLegacyFallback(aead, nonce, ciphertext, domainCryptoAADv1)
	if err != nil {
		return nil, fmt.Errorf("ECIES decrypt: %w", err)
	}

	return plaintext, nil
}
