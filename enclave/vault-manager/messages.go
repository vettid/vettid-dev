package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
)

// MessageType represents the type of message from the supervisor
type MessageType string

const (
	// Vault operations
	MessageTypeVaultOp     MessageType = "vault_op"
	MessageTypeStorageGet  MessageType = "storage_get"
	MessageTypeStoragePut  MessageType = "storage_put"
	MessageTypeNATSPublish MessageType = "nats_publish"

	// Responses
	MessageTypeResponse MessageType = "response"
	MessageTypeError    MessageType = "error"
)

// IncomingMessage is a message from the supervisor/parent
type IncomingMessage struct {
	ID         string          `json:"id"`
	Type       MessageType     `json:"type"`
	Subject    string          `json:"subject"`     // NATS subject (e.g., "OwnerSpace.user-123.forVault.call.initiate")
	Payload    json.RawMessage `json:"payload"`
	ReplyTo    string          `json:"reply_to,omitempty"`
}

// OutgoingMessage is a message to the supervisor/parent
type OutgoingMessage struct {
	ID         string          `json:"id"`
	Type       MessageType     `json:"type"`
	Subject    string          `json:"subject,omitempty"`
	Payload    json.RawMessage `json:"payload,omitempty"`
	Error      string          `json:"error,omitempty"`
}

// MessageHandler processes incoming messages
type MessageHandler struct {
	ownerSpace  string
	callHandler *CallHandler
	publisher   *VsockPublisher
}

// VsockPublisher implements CallPublisher using vsock to parent
type VsockPublisher struct {
	ownerSpace string
	sendFn     func(msg *OutgoingMessage) error
}

// NewVsockPublisher creates a new publisher that sends via vsock
func NewVsockPublisher(ownerSpace string, sendFn func(msg *OutgoingMessage) error) *VsockPublisher {
	return &VsockPublisher{
		ownerSpace: ownerSpace,
		sendFn:     sendFn,
	}
}

// PublishToApp sends event to owner's app via forApp channel
func (p *VsockPublisher) PublishToApp(ctx context.Context, eventType string, payload []byte) error {
	subject := fmt.Sprintf("OwnerSpace.%s.forApp.%s", p.ownerSpace, eventType)

	msg := &OutgoingMessage{
		ID:      generateMessageID(),
		Type:    MessageTypeNATSPublish,
		Subject: subject,
		Payload: payload,
	}

	log.Debug().
		Str("subject", subject).
		Msg("Publishing to app")

	return p.sendFn(msg)
}

// PublishToVault sends event to another vault via forVault channel
func (p *VsockPublisher) PublishToVault(ctx context.Context, targetOwnerSpace string, eventType string, payload []byte) error {
	subject := fmt.Sprintf("OwnerSpace.%s.forVault.%s", targetOwnerSpace, eventType)

	msg := &OutgoingMessage{
		ID:      generateMessageID(),
		Type:    MessageTypeNATSPublish,
		Subject: subject,
		Payload: payload,
	}

	log.Debug().
		Str("subject", subject).
		Str("target", targetOwnerSpace).
		Msg("Publishing to vault")

	return p.sendFn(msg)
}

// NewMessageHandler creates a new message handler
func NewMessageHandler(ownerSpace string, storage *EncryptedStorage, publisher *VsockPublisher) *MessageHandler {
	callHandler := NewCallHandler(ownerSpace, storage, publisher)

	return &MessageHandler{
		ownerSpace:  ownerSpace,
		callHandler: callHandler,
		publisher:   publisher,
	}
}

// Initialize loads persistent state
func (mh *MessageHandler) Initialize(ctx context.Context) error {
	// Load block list
	if err := mh.callHandler.LoadBlockList(ctx); err != nil {
		return fmt.Errorf("failed to load block list: %w", err)
	}
	return nil
}

// HandleMessage processes an incoming message
func (mh *MessageHandler) HandleMessage(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	log.Debug().
		Str("id", msg.ID).
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

// handleVaultOp routes vault operations based on subject
func (mh *MessageHandler) handleVaultOp(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	// Parse subject to determine operation type
	// Format: OwnerSpace.{guid}.forVault.{operation...}
	parts := strings.Split(msg.Subject, ".")
	if len(parts) < 4 {
		return mh.errorResponse(msg.ID, "invalid subject format")
	}

	// Extract operation path (everything after forVault)
	opIndex := -1
	for i, part := range parts {
		if part == "forVault" {
			opIndex = i
			break
		}
	}
	if opIndex == -1 || opIndex+1 >= len(parts) {
		return mh.errorResponse(msg.ID, "missing operation in subject")
	}

	operation := parts[opIndex+1]

	switch operation {
	case "call":
		return mh.handleCallOperation(ctx, msg, parts[opIndex+1:])
	case "app":
		return mh.handleAppOperation(ctx, msg, parts[opIndex+1:])
	case "bootstrap":
		return mh.handleBootstrap(ctx, msg)
	case "unseal":
		return mh.handleUnseal(ctx, msg)
	case "sign":
		return mh.handleSign(ctx, msg)
	case "block":
		return mh.handleBlockOperation(ctx, msg, parts[opIndex+1:])
	default:
		return mh.errorResponse(msg.ID, fmt.Sprintf("unknown operation: %s", operation))
	}
}

// handleAppOperation routes app-related operations (like authenticate)
func (mh *MessageHandler) handleAppOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.ID, "missing app operation type")
	}

	opType := opParts[1] // e.g., "authenticate"

	switch opType {
	case "authenticate":
		return mh.handleAuthenticate(msg)
	default:
		return mh.errorResponse(msg.ID, fmt.Sprintf("unknown app operation: %s", opType))
	}
}

// handleCallOperation routes call-related operations
func (mh *MessageHandler) handleCallOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.ID, "missing call event type")
	}

	eventTypeStr := opParts[1] // e.g., "initiate", "offer", "answer"

	// Parse the call event
	var event CallEvent
	if err := json.Unmarshal(msg.Payload, &event); err != nil {
		return mh.errorResponse(msg.ID, fmt.Sprintf("invalid call event payload: %v", err))
	}

	// Map string to CallEventType
	eventType := CallEventType(eventTypeStr)
	event.EventType = eventType

	// Handle the call event
	if err := mh.callHandler.HandleCallEvent(ctx, &event); err != nil {
		return mh.errorResponse(msg.ID, fmt.Sprintf("call handling error: %v", err))
	}

	return mh.successResponse(msg.ID, nil)
}

// handleBlockOperation handles block/unblock requests from the app
func (mh *MessageHandler) handleBlockOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.ID, "missing block operation type")
	}

	opType := opParts[1] // "add" or "remove"

	var req struct {
		TargetID     string `json:"target_id"`
		Reason       string `json:"reason,omitempty"`
		DurationSecs int64  `json:"duration_secs,omitempty"`
	}
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return mh.errorResponse(msg.ID, fmt.Sprintf("invalid block request: %v", err))
	}

	switch opType {
	case "add":
		if err := mh.callHandler.BlockCaller(ctx, req.TargetID, req.Reason, req.DurationSecs); err != nil {
			return mh.errorResponse(msg.ID, err.Error())
		}
	case "remove":
		if err := mh.callHandler.UnblockCaller(ctx, req.TargetID); err != nil {
			return mh.errorResponse(msg.ID, err.Error())
		}
	default:
		return mh.errorResponse(msg.ID, fmt.Sprintf("unknown block operation: %s", opType))
	}

	return mh.successResponse(msg.ID, nil)
}

// handleBootstrap handles vault bootstrap request
func (mh *MessageHandler) handleBootstrap(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	// TODO: Implement bootstrap logic
	log.Info().Msg("Bootstrap requested")
	return mh.successResponse(msg.ID, []byte(`{"status":"bootstrap_pending"}`))
}

// handleUnseal handles credential unseal request
func (mh *MessageHandler) handleUnseal(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	// TODO: Implement unseal logic
	log.Info().Msg("Unseal requested")
	return mh.successResponse(msg.ID, nil)
}

// handleSign handles signing request
func (mh *MessageHandler) handleSign(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	// TODO: Implement signing logic
	log.Info().Msg("Sign requested")
	return mh.successResponse(msg.ID, nil)
}

// Response helpers

func (mh *MessageHandler) successResponse(id string, payload []byte) (*OutgoingMessage, error) {
	return &OutgoingMessage{
		ID:      id,
		Type:    MessageTypeResponse,
		Payload: payload,
	}, nil
}

func (mh *MessageHandler) errorResponse(id string, errMsg string) (*OutgoingMessage, error) {
	return &OutgoingMessage{
		ID:    id,
		Type:  MessageTypeError,
		Error: sanitizeErrorForClient(errMsg),
	}, nil
}

// sanitizeErrorForClient removes potentially sensitive information from error messages
// before returning them to clients. Internal errors are logged but replaced with generic messages.
func sanitizeErrorForClient(errMsg string) string {
	// List of patterns that might expose internal details
	sensitivePatterns := []string{
		"file", "path", "/", "\\",
		"connection", "socket", "vsock",
		"internal", "memory", "malloc",
		"json", "unmarshal", "marshal",
		"EOF", "broken pipe",
		"timeout", "context",
		"storage", "database", "db",
		"key", "secret", "credential",
		"crypto", "cipher", "decrypt", "encrypt",
		"stack", "panic", "runtime",
	}

	lowerErr := strings.ToLower(errMsg)
	for _, pattern := range sensitivePatterns {
		if strings.Contains(lowerErr, pattern) {
			// Log the full error internally
			log.Error().Str("internal_error", errMsg).Msg("Sanitized error returned to client")
			return "operation failed"
		}
	}

	// For known safe error types, return as-is (truncated)
	if len(errMsg) > 100 {
		return errMsg[:100]
	}
	return errMsg
}

func generateMessageID() string {
	return fmt.Sprintf("msg-%d", currentTimestamp())
}
