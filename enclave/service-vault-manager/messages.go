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
	Type       MessageType     `json:"type"`
	OwnerSpace string          `json:"owner_space,omitempty"`
	RequestID  string          `json:"request_id,omitempty"`
	Subject    string          `json:"subject,omitempty"`
	ReplyTo    string          `json:"reply_to,omitempty"`
	Payload    json.RawMessage `json:"payload,omitempty"`
	ID         string          `json:"id,omitempty"` // Legacy fallback
}

// GetID returns the message ID
func (m *IncomingMessage) GetID() string {
	if m.RequestID != "" {
		return m.RequestID
	}
	return m.ID
}

// OutgoingMessage is a message to the supervisor/parent
type OutgoingMessage struct {
	Type       MessageType     `json:"type"`
	OwnerSpace string          `json:"owner_space,omitempty"`
	RequestID  string          `json:"request_id,omitempty"`
	Subject    string          `json:"subject,omitempty"`
	ReplyTo    string          `json:"reply_to,omitempty"`
	Payload    json.RawMessage `json:"payload,omitempty"`
	Error      string          `json:"error,omitempty"`
	ID         string          `json:"id,omitempty"`
}

// MessageHandler processes incoming messages for a service vault
type MessageHandler struct {
	ownerSpace         string
	storage            *EncryptedStorage
	sendFn             func(msg *OutgoingMessage) error

	// Handlers
	userConnectionsHandler *UserConnectionsHandler
	userRequestsHandler    *UserRequestsHandler
	userDataHandler        *UserDataHandler
	contractManager        *ContractManager
	profileManager         *ProfileManager
}

// NewMessageHandler creates a new message handler for the service vault
func NewMessageHandler(
	ownerSpace string,
	storage *EncryptedStorage,
	sendFn func(msg *OutgoingMessage) error,
) *MessageHandler {
	// Create handlers
	contractManager := NewContractManager(ownerSpace, storage, sendFn)
	profileManager := NewProfileManager(ownerSpace, storage, sendFn)
	userConnectionsHandler := NewUserConnectionsHandler(ownerSpace, storage, sendFn, contractManager)
	userRequestsHandler := NewUserRequestsHandler(ownerSpace, storage, sendFn, userConnectionsHandler, contractManager)
	userDataHandler := NewUserDataHandler(ownerSpace, storage, sendFn, userConnectionsHandler, contractManager)

	return &MessageHandler{
		ownerSpace:             ownerSpace,
		storage:                storage,
		sendFn:                 sendFn,
		userConnectionsHandler: userConnectionsHandler,
		userRequestsHandler:    userRequestsHandler,
		userDataHandler:        userDataHandler,
		contractManager:        contractManager,
		profileManager:         profileManager,
	}
}

// Initialize loads persistent state
func (mh *MessageHandler) Initialize(ctx context.Context) error {
	// Load signing keys or generate if needed
	if err := mh.profileManager.InitializeSigningKeys(); err != nil {
		return fmt.Errorf("failed to initialize signing keys: %w", err)
	}
	return nil
}

// SecureErase zeros sensitive data
func (mh *MessageHandler) SecureErase() {
	// Zero any in-memory sensitive data
	log.Debug().Msg("Message handler secure erase complete")
}

// HandleMessage processes an incoming message
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

// handleVaultOp routes vault operations based on subject
func (mh *MessageHandler) handleVaultOp(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	subject := msg.Subject
	if subject == "" {
		return mh.errorResponse(msg.GetID(), "missing subject")
	}

	// Parse subject: ServiceSpace.{ownerSpace}.{operation}.{subOperation}...
	parts := strings.Split(subject, ".")
	if len(parts) < 3 {
		return mh.errorResponse(msg.GetID(), "invalid subject format")
	}

	// Find the operation part (skip ServiceSpace and ownerSpace)
	opIndex := 2
	if parts[0] == "ServiceSpace" && len(parts) > 2 {
		opIndex = 2
	}

	if opIndex >= len(parts) {
		return mh.errorResponse(msg.GetID(), "missing operation in subject")
	}

	operation := parts[opIndex]

	switch operation {
	case "user":
		return mh.handleUserOperation(ctx, msg, parts[opIndex:])
	case "contract":
		return mh.handleContractOperation(ctx, msg, parts[opIndex:])
	case "profile":
		return mh.handleProfileOperation(ctx, msg, parts[opIndex:])
	case "fromUser":
		// Incoming message from a user vault
		if len(parts) < opIndex+2 {
			return mh.errorResponse(msg.GetID(), "missing user ID in fromUser subject")
		}
		userGUID := parts[opIndex+1]
		return mh.handleFromUserOperation(ctx, msg, userGUID, parts[opIndex+2:])
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown operation: %s", operation))
	}
}

// handleUserOperation routes user.* operations
func (mh *MessageHandler) handleUserOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing user operation type")
	}

	subOp := opParts[1] // e.g., "connection", "request", "data"

	switch subOp {
	case "connection":
		return mh.handleUserConnectionOperation(ctx, msg, opParts[1:])
	case "request":
		return mh.handleUserRequestOperation(ctx, msg, opParts[1:])
	case "data":
		return mh.handleUserDataOperation(ctx, msg, opParts[1:])
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown user operation: %s", subOp))
	}
}

// handleUserConnectionOperation routes user.connection.* operations
func (mh *MessageHandler) handleUserConnectionOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing connection operation type")
	}

	opType := opParts[1]

	switch opType {
	case "list":
		return mh.userConnectionsHandler.HandleList(msg)
	case "get":
		return mh.userConnectionsHandler.HandleGet(msg)
	case "disconnect":
		return mh.userConnectionsHandler.HandleDisconnect(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown connection operation: %s", opType))
	}
}

// handleUserRequestOperation routes user.request.* operations
func (mh *MessageHandler) handleUserRequestOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing request operation type")
	}

	opType := opParts[1]

	switch opType {
	case "data":
		return mh.userRequestsHandler.HandleRequestData(msg)
	case "auth":
		return mh.userRequestsHandler.HandleRequestAuth(msg)
	case "consent":
		return mh.userRequestsHandler.HandleRequestConsent(msg)
	case "payment":
		return mh.userRequestsHandler.HandleRequestPayment(msg)
	case "list":
		return mh.userRequestsHandler.HandleListRequests(msg)
	case "get":
		return mh.userRequestsHandler.HandleGetRequest(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown request operation: %s", opType))
	}
}

// handleUserDataOperation routes user.data.* operations
func (mh *MessageHandler) handleUserDataOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing data operation type")
	}

	opType := opParts[1]

	switch opType {
	case "store":
		return mh.userDataHandler.HandleStoreData(msg)
	case "delete":
		return mh.userDataHandler.HandleDeleteData(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown data operation: %s", opType))
	}
}

// handleContractOperation routes contract.* operations
func (mh *MessageHandler) handleContractOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing contract operation type")
	}

	opType := opParts[1]

	switch opType {
	case "get":
		return mh.contractManager.HandleGetContract(msg)
	case "update":
		return mh.contractManager.HandleUpdateContract(msg)
	case "history":
		return mh.contractManager.HandleGetHistory(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown contract operation: %s", opType))
	}
}

// handleProfileOperation routes profile.* operations
func (mh *MessageHandler) handleProfileOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing profile operation type")
	}

	opType := opParts[1]

	switch opType {
	case "get":
		return mh.profileManager.HandleGetProfile(msg)
	case "update":
		return mh.profileManager.HandleUpdateProfile(msg)
	case "resource":
		if len(opParts) < 3 {
			return mh.errorResponse(msg.GetID(), "missing resource operation type")
		}
		resourceOp := opParts[2]
		switch resourceOp {
		case "add":
			return mh.profileManager.HandleAddResource(msg)
		case "remove":
			return mh.profileManager.HandleRemoveResource(msg)
		case "list":
			return mh.profileManager.HandleListResources(msg)
		case "sign":
			return mh.profileManager.HandleSignDownload(msg)
		default:
			return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown resource operation: %s", resourceOp))
		}
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown profile operation: %s", opType))
	}
}

// handleFromUserOperation handles incoming messages from user vaults
// This is called when a user accepts a connection or responds to a request
func (mh *MessageHandler) handleFromUserOperation(ctx context.Context, msg *IncomingMessage, userGUID string, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 1 {
		return mh.errorResponse(msg.GetID(), "missing fromUser operation type")
	}

	opType := opParts[0]

	log.Debug().
		Str("user_guid", userGUID).
		Str("operation", opType).
		Msg("Handling incoming user message")

	switch opType {
	case "connect":
		// User is connecting to this service
		return mh.userConnectionsHandler.HandleConnect(msg, userGUID)
	case "response":
		// User is responding to a request
		return mh.userRequestsHandler.HandleUserResponse(msg, userGUID)
	case "disconnect":
		// User is disconnecting (revoking access)
		return mh.userConnectionsHandler.HandleUserDisconnect(msg, userGUID)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown fromUser operation: %s", opType))
	}
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
