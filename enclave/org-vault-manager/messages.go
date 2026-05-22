package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
)

// MessageType represents the type of message from the supervisor.
type MessageType string

const (
	// Operations
	MessageTypeVaultOp     MessageType = "vault_op"
	MessageTypeStorageGet  MessageType = "storage_get"
	MessageTypeStoragePut  MessageType = "storage_put"
	MessageTypeNATSPublish MessageType = "nats_publish"

	// HTTP proxy (async — response routed to httpProxy.responseCh in main loop)
	MessageTypeHTTPRequest  MessageType = "http_request"
	MessageTypeHTTPResponse MessageType = "http_response"

	// Audit events (forwarded to parent for DynamoDB persistence + NATS streaming)
	MessageTypeAuditEvent MessageType = "audit_event"

	// Responses
	MessageTypeResponse MessageType = "response"
	MessageTypeError    MessageType = "error"
)

// IncomingMessage is a message from the supervisor/parent.
type IncomingMessage struct {
	Type       MessageType     `json:"type"`
	OwnerSpace string          `json:"owner_space,omitempty"`
	RequestID  string          `json:"request_id,omitempty"`
	// PipeID is the supervisor's pipe-transport correlation token. The
	// main loop must echo it onto the op's response (see OutgoingMessage)
	// so the supervisor's per-VaultProcess pipe reader can route the
	// response back to the waiting ProcessMessage. Without it the
	// supervisor drops the response and ProcessMessage stalls 30s.
	PipeID     string          `json:"pipe_id,omitempty"`
	Subject    string          `json:"subject,omitempty"`
	ReplyTo    string          `json:"reply_to,omitempty"`
	Payload    json.RawMessage `json:"payload,omitempty"`
	ID         string          `json:"id,omitempty"`
}

// GetID returns the message ID.
func (m *IncomingMessage) GetID() string {
	if m.RequestID != "" {
		return m.RequestID
	}
	return m.ID
}

// OutgoingMessage is a message to the supervisor/parent.
type OutgoingMessage struct {
	Type       MessageType     `json:"type"`
	OwnerSpace string          `json:"owner_space,omitempty"`
	RequestID  string          `json:"request_id,omitempty"`
	// PipeID echoes the incoming op's supervisor pipe-transport token
	// (set by the main loop on op responses; see IncomingMessage.PipeID).
	PipeID     string          `json:"pipe_id,omitempty"`
	Subject    string          `json:"subject,omitempty"`
	ReplyTo    string          `json:"reply_to,omitempty"`
	Payload    json.RawMessage `json:"payload,omitempty"`
	Error      string          `json:"error,omitempty"`
	ID         string          `json:"id,omitempty"`
}

// EncryptedEnvelope wraps an encrypted payload sent over an operator connection.
// The connection_id identifies which operator's connection_key to use for decryption.
//
// Format on the wire:
//
//	{
//	  "connection_id": "...",
//	  "ciphertext": [nonce(24) || XChaCha20-Poly1305 ciphertext+tag]
//	}
//
// SECURITY: Payloads from operators are encrypted end-to-end with the connection
// key (HKDF-derived from X25519 ECDH). NATS server never sees plaintext.
type EncryptedEnvelope struct {
	ConnectionID string `json:"connection_id"`
	Ciphertext   []byte `json:"ciphertext"`
}

// MessageHandler processes incoming messages for an org vault.
type MessageHandler struct {
	ownerSpace string
	storage    *EncryptedStorage
	sendFn     func(msg *OutgoingMessage) error

	// Handlers
	credentialStore *CredentialStore
	credentialProxy *CredentialProxy
	connectionMgr   *ConnectionManager
	auditHandler    *AuditHandler
	auditTransfer   *AuditTransferHandler
	httpProxy       *HTTPProxy
	contract        *ContractManager
}

// NewMessageHandler creates a new message handler for the org vault.
func NewMessageHandler(
	ownerSpace string,
	storage *EncryptedStorage,
	sendFn func(msg *OutgoingMessage) error,
) *MessageHandler {
	httpProxy := NewHTTPProxy(ownerSpace, sendFn)
	auditHandler := NewAuditHandler(ownerSpace, storage, sendFn)
	auditTransfer := NewAuditTransferHandler(ownerSpace, storage)
	credentialStore := NewCredentialStore(ownerSpace, storage)
	connectionMgr := NewConnectionManager(ownerSpace, storage, sendFn)
	contract := NewContractManager(ownerSpace, storage)
	credentialProxy := NewCredentialProxy(ownerSpace, credentialStore, httpProxy, auditHandler, connectionMgr, contract)

	return &MessageHandler{
		ownerSpace:      ownerSpace,
		storage:         storage,
		sendFn:          sendFn,
		credentialStore: credentialStore,
		credentialProxy: credentialProxy,
		connectionMgr:   connectionMgr,
		auditHandler:    auditHandler,
		auditTransfer:   auditTransfer,
		httpProxy:       httpProxy,
		contract:        contract,
	}
}

// Initialize loads persistent state.
func (mh *MessageHandler) Initialize(ctx context.Context) error {
	return nil
}

// SecureErase zeros sensitive data.
func (mh *MessageHandler) SecureErase() {
	if mh.connectionMgr != nil {
		mh.connectionMgr.SecureErase()
	}
	log.Debug().Msg("Message handler secure erase complete")
}

// HandleMessage processes an incoming message.
func (mh *MessageHandler) HandleMessage(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	log.Debug().
		Str("id", msg.GetID()).
		Str("type", string(msg.Type)).
		Str("subject", msg.Subject).
		Msg("Handling message")

	switch msg.Type {
	case MessageTypeVaultOp:
		return mh.handleVaultOp(ctx, msg)
	default:
		return nil, fmt.Errorf("unknown message type: %s", msg.Type)
	}
}

// handleVaultOp routes vault operations based on NATS subject.
// Subject format: OrgSpace.{ownerSpace}.{operation}.{subOperation}...
func (mh *MessageHandler) handleVaultOp(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	subject := msg.Subject
	if subject == "" {
		return mh.errorResponse(msg.GetID(), "missing subject")
	}

	parts := strings.Split(subject, ".")
	if len(parts) < 3 {
		return mh.errorResponse(msg.GetID(), "invalid subject format")
	}

	// Skip OrgSpace and ownerSpace to get the operation
	opIndex := 2
	if parts[0] == "OrgSpace" && len(parts) > 2 {
		opIndex = 2
	}

	if opIndex >= len(parts) {
		return mh.errorResponse(msg.GetID(), "missing operation in subject")
	}

	operation := parts[opIndex]

	switch operation {
	case "credential":
		return mh.handleCredentialOperation(ctx, msg, parts[opIndex:])
	case "connection":
		return mh.handleConnectionOperation(ctx, msg, parts[opIndex:])
	case "audit":
		return mh.handleAuditOperation(ctx, msg, parts[opIndex:])
	case "contract":
		return mh.handleContractOperation(ctx, msg, parts[opIndex:])
	case "fromOperator":
		// Incoming message from an operator's connection
		// Format: OrgSpace.{guid}.fromOperator.{connectionID}.{operation}
		if len(parts) < opIndex+3 {
			return mh.errorResponse(msg.GetID(), "missing connection ID in fromOperator subject")
		}
		connectionID := parts[opIndex+1]
		return mh.handleFromOperatorOperation(ctx, msg, connectionID, parts[opIndex+2:])
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown operation: %s", operation))
	}
}

// handleCredentialOperation routes credential.* operations.
func (mh *MessageHandler) handleCredentialOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing credential operation type")
	}

	opType := opParts[1]

	switch opType {
	case "store":
		return mh.credentialStore.HandleStore(msg)
	case "list":
		return mh.credentialStore.HandleList(msg)
	case "rotate":
		return mh.credentialStore.HandleRotate(msg)
	case "delete":
		return mh.credentialStore.HandleDelete(msg)
	case "proxy":
		// Credential proxy requires operator context — but this path is for
		// admin operations. Operator proxy requests come via fromOperator.
		return mh.errorResponse(msg.GetID(), "credential.proxy must be sent via operator connection (fromOperator)")
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown credential operation: %s", opType))
	}
}

// handleConnectionOperation routes connection.* operations.
func (mh *MessageHandler) handleConnectionOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing connection operation type")
	}

	opType := opParts[1]

	switch opType {
	case "invite":
		return mh.connectionMgr.HandleInvite(msg)
	case "list":
		return mh.connectionMgr.HandleList(msg)
	case "revoke":
		return mh.connectionMgr.HandleRevoke(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown connection operation: %s", opType))
	}
}

// handleAuditOperation routes audit.* operations.
func (mh *MessageHandler) handleAuditOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing audit operation type")
	}

	opType := opParts[1]

	switch opType {
	case "query":
		return mh.auditHandler.HandleQuery(msg)
	case "export":
		return mh.auditHandler.HandleExport(msg)
	case "transfer":
		// Audit transfer for data subjects (e.g., patients) — filtered by resource_id.
		// Operator audit remains unconditional; this just exposes a read path.
		return mh.auditTransfer.HandleTransfer(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown audit operation: %s", opType))
	}
}

// handleContractOperation routes contract.* operations.
func (mh *MessageHandler) handleContractOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing contract operation type")
	}

	opType := opParts[1]

	switch opType {
	case "get":
		return mh.contract.HandleGetContract(msg)
	case "update":
		return mh.contract.HandleUpdateContract(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown contract operation: %s", opType))
	}
}

// handleFromOperatorOperation handles messages arriving via an operator's connection.
// The operator is identified by their connection ID — the connection IS the identity.
func (mh *MessageHandler) handleFromOperatorOperation(ctx context.Context, msg *IncomingMessage, connectionID string, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 1 {
		return mh.errorResponse(msg.GetID(), "missing operator operation type")
	}

	// Verify operator connection is active
	operator, err := mh.connectionMgr.GetConnection(connectionID)
	if err != nil {
		return mh.errorResponse(msg.GetID(), "unknown connection: "+connectionID)
	}
	if operator.Status != "active" {
		return mh.errorResponse(msg.GetID(), "connection not active: "+operator.Status)
	}

	// Update last activity
	mh.connectionMgr.TouchConnection(connectionID)

	opType := opParts[0]

	log.Debug().
		Str("connection_id", connectionID).
		Str("operator_email", operator.OperatorEmail).
		Str("operation", opType).
		Msg("Handling operator message")

	switch opType {
	case "credential":
		if len(opParts) < 2 {
			return mh.errorResponse(msg.GetID(), "missing credential sub-operation")
		}
		if opParts[1] == "proxy" {
			// SECURITY: Decrypt the encrypted envelope before dispatching.
			// All operator → org vault credential.proxy messages MUST be encrypted
			// with the operator's connection key.
			plaintext, connKey, err := mh.decryptOperatorEnvelope(msg.Payload, operator)
			if err != nil {
				log.Warn().
					Err(err).
					Str("connection_id", connectionID).
					Msg("Failed to decrypt operator envelope")
				return mh.errorResponse(msg.GetID(), "failed to decrypt request: "+err.Error())
			}
			defer zeroBytes(connKey)

			// Replace payload with decrypted bytes for the proxy handler
			msg.Payload = plaintext

			// Run the proxy
			resp, err := mh.credentialProxy.HandleProxy(ctx, msg, operator)
			if err != nil || resp == nil {
				return resp, err
			}

			// Encrypt the response payload with the same connection key
			encryptedResp, encErr := mh.encryptOperatorPayload(resp.Payload, connKey, connectionID)
			if encErr != nil {
				log.Warn().Err(encErr).Msg("Failed to encrypt response")
				return mh.errorResponse(msg.GetID(), "failed to encrypt response")
			}
			resp.Payload = encryptedResp
			return resp, nil
		}
		return mh.errorResponse(msg.GetID(), "operators can only use credential.proxy")
	case "connect":
		// Operator accepting an invitation (key exchange).
		// This message is plaintext — the connection key doesn't exist yet.
		return mh.connectionMgr.HandleConnect(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown operator operation: %s", opType))
	}
}

// decryptOperatorEnvelope unwraps an EncryptedEnvelope from an operator and
// returns the plaintext payload + the connection key (caller must zero it).
func (mh *MessageHandler) decryptOperatorEnvelope(payload json.RawMessage, operator *OperatorConnection) ([]byte, []byte, error) {
	var env EncryptedEnvelope
	if err := json.Unmarshal(payload, &env); err != nil {
		return nil, nil, fmt.Errorf("invalid envelope: %w", err)
	}
	if len(env.Ciphertext) == 0 {
		return nil, nil, fmt.Errorf("empty ciphertext")
	}

	connKey, err := mh.connectionMgr.DeriveConnectionKey(operator)
	if err != nil {
		return nil, nil, fmt.Errorf("derive key: %w", err)
	}

	plaintext, err := decryptXChaCha20(connKey, env.Ciphertext)
	if err != nil {
		zeroBytes(connKey)
		return nil, nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, connKey, nil
}

// encryptOperatorPayload wraps a plaintext payload in an EncryptedEnvelope
// keyed by the operator's connection key.
func (mh *MessageHandler) encryptOperatorPayload(plaintext []byte, connKey []byte, connectionID string) (json.RawMessage, error) {
	ciphertext, err := encryptXChaCha20(connKey, plaintext)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}
	env := EncryptedEnvelope{
		ConnectionID: connectionID,
		Ciphertext:   ciphertext,
	}
	return json.Marshal(env)
}

// Helper methods

func (mh *MessageHandler) errorResponse(requestID, message string) (*OutgoingMessage, error) {
	return &OutgoingMessage{
		RequestID: requestID,
		Type:      MessageTypeResponse,
		Payload:   mustMarshal(map[string]interface{}{"success": false, "error": message}),
	}, nil
}

func (mh *MessageHandler) successResponse(requestID string, payload interface{}) (*OutgoingMessage, error) {
	return &OutgoingMessage{
		RequestID: requestID,
		Type:      MessageTypeResponse,
		Payload:   mustMarshal(payload),
	}, nil
}

func mustMarshal(v interface{}) json.RawMessage {
	data, err := json.Marshal(v)
	if err != nil {
		return []byte(`{"error":"marshal failed"}`)
	}
	return data
}

func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
