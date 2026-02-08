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
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// Domain separation constants for agent connections.
// Must match the vettid-agent crypto package.
const (
	DomainConnection = "vettid-connection-v1"
	DomainAgent      = "vettid-agent-v1"
)

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
	ownerSpace     string
	storage        *EncryptedStorage
	publisher      *VsockPublisher
	eventHandler   *EventHandler
	connHandler    *ConnectionsHandler
	secretsHandler *AgentSecretsHandler
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
		ownerSpace:     ownerSpace,
		storage:        storage,
		publisher:      publisher,
		eventHandler:   eventHandler,
		connHandler:    connHandler,
		secretsHandler: secretsHandler,
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

	AgentMsgSecretResponse     = "agent_secret_response"
	AgentMsgActionResponse     = "agent_action_response"
	AgentMsgCatalogResponse    = "agent_secret_catalog"
	AgentMsgConnectionApproved = "agent_connection_approved"
	AgentMsgConnectionDenied   = "agent_connection_denied"
)

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

// --- Main message handler ---

// HandleAgentMessage processes an incoming message from an agent connector.
// It parses the envelope, looks up the connection, decrypts the payload,
// routes to the appropriate handler, encrypts the response, and publishes it.
func (h *AgentHandler) HandleAgentMessage(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	// Parse envelope
	var envelope AgentEnvelope
	if err := json.Unmarshal(msg.Payload, &envelope); err != nil {
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

	// Ensure we have a shared secret
	if len(conn.SharedSecret) == 0 {
		log.Warn().
			Str("connection_id", conn.ConnectionID).
			Msg("Agent connection has no shared secret")
		return nil, nil
	}

	// Derive connection key from shared secret
	connKey, err := deriveConnectionKey(conn.SharedSecret)
	if err != nil {
		log.Error().Err(err).Str("connection_id", conn.ConnectionID).Msg("Failed to derive connection key")
		return nil, nil
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

	// Build response envelope
	respEnvelope := AgentEnvelope{
		Type:      responseType,
		KeyID:     conn.ConnectionID,
		Timestamp: time.Now().UTC(),
		Sequence:  envelope.Sequence,
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

	// Check scope
	if conn.Contract != nil && !InScope(secret.Category, conn.Contract.Scope) {
		h.eventHandler.LogConnectionEvent(ctx, EventTypeAgentSecretDenied, conn.ConnectionID, "", fmt.Sprintf("Secret %s out of scope", secret.SecretID))

		resp := AgentSecretResponse{
			RequestID: req.RequestID,
			Status:    "denied",
			Reason:    "Secret category not in scope",
		}
		data, _ := json.Marshal(resp)
		return data, AgentMsgSecretResponse, nil
	}

	// Check allowed actions
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

	// Check scope
	if conn.Contract != nil && !InScope(secret.Category, conn.Contract.Scope) {
		h.eventHandler.LogConnectionEvent(ctx, EventTypeAgentActionDenied, conn.ConnectionID, "",
			fmt.Sprintf("Action denied: secret %s out of scope", secret.SecretID))

		resp := AgentActionResponse{
			RequestID: req.RequestID,
			Status:    "denied",
			Reason:    "Secret category not in scope",
		}
		data, _ := json.Marshal(resp)
		return data, AgentMsgActionResponse, nil
	}

	// Check allowed actions
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
func (h *AgentHandler) handleCatalogRequest(ctx context.Context, conn *ConnectionRecord, plaintext []byte) ([]byte, string, error) {
	var req AgentCatalogRefreshRequest
	if err := json.Unmarshal(plaintext, &req); err != nil {
		return nil, "", fmt.Errorf("invalid catalog request: %w", err)
	}

	log.Info().
		Str("connection_id", conn.ConnectionID).
		Uint64("current_version", req.CurrentVersion).
		Msg("Agent catalog refresh request")

	scope := []string{}
	if conn.Contract != nil {
		scope = conn.Contract.Scope
	}

	catalog := h.secretsHandler.BuildCatalog(scope)

	data, err := json.Marshal(catalog)
	if err != nil {
		return nil, "", fmt.Errorf("marshal catalog: %w", err)
	}

	return data, AgentMsgCatalogResponse, nil
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

// resolveSecret finds a secret by ID, type+name fallback, or name.
func (h *AgentHandler) resolveSecret(req AgentSecretRequest) (*AgentSharedSecret, error) {
	// Prefer direct ID lookup
	if req.SecretID != "" {
		return h.secretsHandler.GetSecret(req.SecretID)
	}

	// Fallback: search by category + name
	index := h.secretsHandler.getIndex()
	for _, id := range index {
		secret, err := h.secretsHandler.GetSecret(id)
		if err != nil {
			continue
		}
		if req.SecretType != "" && secret.Category == req.SecretType {
			if req.SecretName == "" || secret.Name == req.SecretName {
				return secret, nil
			}
		}
		if req.SecretName != "" && secret.Name == req.SecretName {
			return secret, nil
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

// --- Catalog push ---

// PushCatalogToAgent builds and pushes the secret catalog to an active agent connection.
func (h *AgentHandler) PushCatalogToAgent(conn *ConnectionRecord) error {
	if len(conn.SharedSecret) == 0 {
		return fmt.Errorf("connection has no shared secret")
	}

	scope := []string{}
	if conn.Contract != nil {
		scope = conn.Contract.Scope
	}

	catalog := h.secretsHandler.BuildCatalog(scope)

	catalogBytes, err := json.Marshal(catalog)
	if err != nil {
		return fmt.Errorf("marshal catalog: %w", err)
	}

	// Derive connection key and encrypt
	connKey, err := deriveConnectionKey(conn.SharedSecret)
	if err != nil {
		return fmt.Errorf("derive connection key: %w", err)
	}
	defer zeroBytes(connKey)

	encrypted, err := encryptXChaCha20(connKey, catalogBytes)
	if err != nil {
		return fmt.Errorf("encrypt catalog: %w", err)
	}
	zeroBytes(catalogBytes)

	// Build envelope
	encPayloadJSON, _ := json.Marshal(encrypted)
	envBytes, err := json.Marshal(AgentEnvelope{
		Type:      AgentMsgCatalogResponse,
		KeyID:     conn.ConnectionID,
		Payload:   encPayloadJSON,
		Timestamp: time.Now().UTC(),
	})
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}

	topic := fmt.Sprintf("MessageSpace.%s.forOwner.agent.%s", h.ownerSpace, conn.ConnectionID)
	return h.publisher.PublishRaw(topic, envBytes)
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

	// X25519 key exchange
	sharedSecret, err := curve25519.X25519(privateKey, ephPub)
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

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("ECIES decrypt: %w", err)
	}

	return plaintext, nil
}
