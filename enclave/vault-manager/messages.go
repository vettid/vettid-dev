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
// Field names match the supervisor's Message struct for JSON compatibility
type IncomingMessage struct {
	// Core fields - aligned with supervisor's Message struct
	Type       MessageType     `json:"type"`
	OwnerSpace string          `json:"owner_space,omitempty"`
	RequestID  string          `json:"request_id,omitempty"` // Matches supervisor's RequestID
	Subject    string          `json:"subject,omitempty"`    // NATS subject
	ReplyTo    string          `json:"reply_to,omitempty"`
	Payload    json.RawMessage `json:"payload,omitempty"`

	// Attestation private key for PIN decryption
	// SECURITY: Only included for PIN operations, supervisor provides this
	AttestationPrivateKey []byte `json:"attestation_private_key,omitempty"`

	// Legacy field for backward compatibility
	ID string `json:"id,omitempty"` // Fallback if RequestID not set
}

// GetID returns the message ID, preferring RequestID over ID
func (m *IncomingMessage) GetID() string {
	if m.RequestID != "" {
		return m.RequestID
	}
	return m.ID
}

// OutgoingMessage is a message to the supervisor/parent
// Field names match the supervisor's Message struct for JSON compatibility
type OutgoingMessage struct {
	Type       MessageType     `json:"type"`
	OwnerSpace string          `json:"owner_space,omitempty"`
	RequestID  string          `json:"request_id,omitempty"` // Matches supervisor's RequestID
	Subject    string          `json:"subject,omitempty"`
	ReplyTo    string          `json:"reply_to,omitempty"`
	Payload    json.RawMessage `json:"payload,omitempty"`
	Error      string          `json:"error,omitempty"`

	// Legacy field for backward compatibility
	ID string `json:"id,omitempty"`
}

// MessageHandler processes incoming messages
type MessageHandler struct {
	ownerSpace           string
	storage              *EncryptedStorage
	callHandler          *CallHandler
	secretsHandler       *SecretsHandler
	profileHandler       *ProfileHandler
	credentialHandler    *CredentialHandler
	messagingHandler     *MessagingHandler
	connectionsHandler       *ConnectionsHandler
	notificationsHandler     *NotificationsHandler
	credentialSecretHandler  *CredentialSecretHandler
	eventHandler             *EventHandler
	publisher                *VsockPublisher

	// Cryptographic state and handlers for Phase 4
	vaultState               *VaultState
	bootstrapHandler         *BootstrapHandler
	pinHandler               *PINHandler
	proteanCredentialHandler *ProteanCredentialHandler
	sealerProxy              *SealerProxy

	// Voting handler for vault-signed votes
	voteHandler *VoteHandler

	// Migration handler for migration status, acknowledgment, and recovery
	migrationHandler *MigrationHandler
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
func NewMessageHandler(ownerSpace string, storage *EncryptedStorage, publisher *VsockPublisher, sendFn func(msg *OutgoingMessage) error) *MessageHandler {
	// Create vault state - this holds all cryptographic material in memory
	vaultState := NewVaultState()

	// Create sealer proxy for KMS-dependent operations
	// The sendFn allows the proxy to request KMS operations from the supervisor
	sealerProxy := NewSealerProxy(ownerSpace, sendFn)

	// Create bootstrap handler - generates CEK/UTK pairs
	bootstrapHandler := NewBootstrapHandler(ownerSpace, vaultState)

	// Create PIN handler - handles PIN setup/unlock/change using the sealer proxy
	pinHandler := NewPINHandler(ownerSpace, vaultState, bootstrapHandler, sealerProxy)

	// Create Protean Credential handler - handles credential creation (Phase 3)
	proteanCredentialHandler := NewProteanCredentialHandler(ownerSpace, vaultState, bootstrapHandler)

	// Create vote handler for vault-signed voting
	voteHandler := NewVoteHandler(ownerSpace, vaultState)

	// Create event handler for unified audit logging and feed
	// NOTE: Must be created before handlers that depend on it for logging
	eventHandler := NewEventHandler(ownerSpace, storage, publisher)

	// Create credential secret handler for critical secrets
	credentialSecretHandler := NewCredentialSecretHandler(ownerSpace, storage, vaultState, bootstrapHandler, eventHandler)

	// Create migration handler for migration status and recovery
	migrationHandler := NewMigrationHandler(ownerSpace, storage, vaultState, sealerProxy)

	return &MessageHandler{
		ownerSpace:           ownerSpace,
		storage:              storage,
		callHandler:          NewCallHandler(ownerSpace, storage, publisher, eventHandler),
		secretsHandler:       NewSecretsHandler(ownerSpace, storage),
		profileHandler:       NewProfileHandler(ownerSpace, storage),
		credentialHandler:    NewCredentialHandler(ownerSpace, storage),
		messagingHandler:     NewMessagingHandler(ownerSpace, storage, publisher, eventHandler),
		connectionsHandler:      NewConnectionsHandler(ownerSpace, storage, eventHandler),
		notificationsHandler:    NewNotificationsHandler(ownerSpace, storage, publisher),
		credentialSecretHandler: credentialSecretHandler,
		eventHandler:            eventHandler,
		publisher:               publisher,

		// Cryptographic components
		vaultState:               vaultState,
		bootstrapHandler:         bootstrapHandler,
		pinHandler:               pinHandler,
		proteanCredentialHandler: proteanCredentialHandler,
		sealerProxy:              sealerProxy,

		// Voting
		voteHandler: voteHandler,

		// Migration
		migrationHandler: migrationHandler,
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

// SetSealerResponseChannel sets the channel for receiving sealer responses from supervisor
// This must be called before any PIN operations that require KMS access
func (mh *MessageHandler) SetSealerResponseChannel(ch chan *IncomingMessage) {
	mh.sealerProxy.SetResponseChannel(ch)
}

// GetSealerProxy returns the sealer proxy for routing sealer responses
func (mh *MessageHandler) GetSealerProxy() *SealerProxy {
	return mh.sealerProxy
}

// IsSealerResponse checks if a message is a sealer response from supervisor
func (mh *MessageHandler) IsSealerResponse(msg *IncomingMessage) bool {
	return msg.Type == MessageTypeSealerResponse
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
	// Parse subject to determine operation type
	// Format: OwnerSpace.{guid}.forVault.{operation...}
	parts := strings.Split(msg.Subject, ".")
	if len(parts) < 4 {
		return mh.errorResponse(msg.GetID(), "invalid subject format")
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
		return mh.errorResponse(msg.GetID(), "missing operation in subject")
	}

	operation := parts[opIndex+1]

	switch operation {
	case "call":
		return mh.handleCallOperation(ctx, msg, parts[opIndex+1:])
	case "app":
		return mh.handleAppOperation(ctx, msg, parts[opIndex+1:])
	case "bootstrap":
		return mh.handleBootstrap(ctx, msg)
	case "pin":
		// Route based on payload type for mobile apps using forVault.pin subject
		return mh.handlePinOperation(ctx, msg)
	case "pin-setup":
		return mh.pinHandler.HandlePINSetup(ctx, msg)
	case "pin-unlock":
		return mh.pinHandler.HandlePINUnlock(ctx, msg)
	case "pin-change":
		return mh.pinHandler.HandlePINChange(ctx, msg)
	case "unseal":
		return mh.handleUnseal(ctx, msg)
	case "sign":
		return mh.handleSign(ctx, msg)
	case "block":
		return mh.handleBlockOperation(ctx, msg, parts[opIndex+1:])
	case "secrets":
		return mh.handleSecretsOperation(ctx, msg, parts[opIndex+1:])
	case "profile":
		return mh.handleProfileOperation(ctx, msg, parts[opIndex+1:])
	case "credential":
		return mh.handleCredentialOperation(ctx, msg, parts[opIndex+1:])
	case "message":
		return mh.handleMessageOperation(ctx, msg, parts[opIndex+1:])
	case "connection":
		return mh.handleConnectionOperation(ctx, msg, parts[opIndex+1:])
	case "notification":
		return mh.handleNotificationOperation(ctx, msg, parts[opIndex+1:])
	case "profile-update":
		// Incoming notification from peer vault
		return mh.handleIncomingProfileUpdate(ctx, msg)
	case "revoked":
		// Incoming revocation notice from peer vault
		return mh.handleIncomingRevocation(ctx, msg)
	case "new-message":
		// Incoming message from peer vault
		return mh.handleIncomingPeerMessage(ctx, msg)
	case "read-receipt":
		// Incoming read receipt from peer vault
		return mh.handleIncomingReadReceipt(ctx, msg)
	case "vote":
		// Vault-signed voting operation
		return mh.handleVoteOperation(ctx, msg, parts[opIndex+1:])
	case "feed":
		// Feed operations (unified event feed)
		return mh.handleFeedOperation(ctx, msg, parts[opIndex+1:])
	case "audit":
		// Audit log operations
		return mh.handleAuditOperation(ctx, msg, parts[opIndex+1:])
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown operation: %s", operation))
	}
}

// handlePinOperation routes PIN operations based on payload type
// Supports mobile apps that use forVault.pin subject with type in payload
func (mh *MessageHandler) handlePinOperation(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	// Parse payload to extract the operation type
	var envelope struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(msg.Payload, &envelope); err != nil {
		return mh.errorResponse(msg.GetID(), "invalid payload format")
	}

	log.Debug().
		Str("owner_space", mh.ownerSpace).
		Str("pin_operation", envelope.Type).
		Msg("Routing PIN operation")

	switch envelope.Type {
	case "pin.setup":
		return mh.pinHandler.HandlePINSetup(ctx, msg)
	case "pin.unlock":
		return mh.pinHandler.HandlePINUnlock(ctx, msg)
	case "pin.change":
		return mh.pinHandler.HandlePINChange(ctx, msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown PIN operation type: %s", envelope.Type))
	}
}

// handleAppOperation routes app-related operations (like authenticate)
func (mh *MessageHandler) handleAppOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing app operation type")
	}

	opType := opParts[1] // e.g., "authenticate"

	switch opType {
	case "authenticate":
		return mh.handleAuthenticate(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown app operation: %s", opType))
	}
}

// handleCallOperation routes call-related operations
// Distinguishes between:
// - App requests: call.start, call.accept, call.reject, call.end, call.signal, call.history
// - Incoming vault events: call.initiate, call.offer, call.answer, call.candidate, etc.
func (mh *MessageHandler) handleCallOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing call operation type")
	}

	opType := opParts[1]

	// App-initiated operations (requests from the mobile app)
	switch opType {
	case "start":
		// App wants to initiate an outgoing call
		return mh.callHandler.HandleInitiateCall(ctx, msg)
	case "accept":
		// App wants to accept an incoming call
		return mh.callHandler.HandleAcceptCall(ctx, msg)
	case "reject":
		// App wants to reject an incoming call
		return mh.callHandler.HandleRejectCall(ctx, msg)
	case "end":
		// App wants to end a call
		return mh.callHandler.HandleEndCall(ctx, msg)
	case "signal":
		// App wants to send WebRTC signaling (offer/answer/candidate)
		return mh.callHandler.HandleSendSignaling(ctx, msg)
	case "history":
		// App wants call history
		return mh.callHandler.HandleGetCallHistory(ctx, msg)
	}

	// Incoming events from other vaults (call.initiate, call.offer, etc.)
	var event CallEvent
	if err := json.Unmarshal(msg.Payload, &event); err != nil {
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("invalid call event payload: %v", err))
	}

	// Map string to CallEventType
	eventType := CallEventType(opType)
	event.EventType = eventType

	// Handle the incoming call event
	if err := mh.callHandler.HandleCallEvent(ctx, &event); err != nil {
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("call handling error: %v", err))
	}

	return mh.successResponse(msg.GetID(), nil)
}

// handleBlockOperation handles block/unblock requests from the app
func (mh *MessageHandler) handleBlockOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing block operation type")
	}

	opType := opParts[1] // "add" or "remove"

	var req struct {
		TargetID     string `json:"target_id"`
		Reason       string `json:"reason,omitempty"`
		DurationSecs int64  `json:"duration_secs,omitempty"`
	}
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("invalid block request: %v", err))
	}

	switch opType {
	case "add":
		if err := mh.callHandler.BlockCaller(ctx, req.TargetID, req.Reason, req.DurationSecs); err != nil {
			return mh.errorResponse(msg.GetID(), err.Error())
		}
	case "remove":
		if err := mh.callHandler.UnblockCaller(ctx, req.TargetID); err != nil {
			return mh.errorResponse(msg.GetID(), err.Error())
		}
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown block operation: %s", opType))
	}

	return mh.successResponse(msg.GetID(), nil)
}

// handleBootstrap handles vault bootstrap request
func (mh *MessageHandler) handleBootstrap(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	return mh.bootstrapHandler.HandleBootstrap(ctx, msg)
}

// handleUnseal handles credential unseal request
func (mh *MessageHandler) handleUnseal(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	// TODO: Implement unseal logic
	log.Info().Msg("Unseal requested")
	return mh.successResponse(msg.GetID(), nil)
}

// handleSign handles signing request
func (mh *MessageHandler) handleSign(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	// TODO: Implement signing logic
	log.Info().Msg("Sign requested")
	return mh.successResponse(msg.GetID(), nil)
}

// handleSecretsOperation routes secrets-related operations
func (mh *MessageHandler) handleSecretsOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing secrets operation type")
	}

	opType := opParts[1]

	switch opType {
	case "add":
		return mh.secretsHandler.HandleAdd(msg)
	case "update":
		return mh.secretsHandler.HandleUpdate(msg)
	case "retrieve":
		return mh.secretsHandler.HandleRetrieve(msg)
	case "delete":
		return mh.secretsHandler.HandleDelete(msg)
	case "list":
		return mh.secretsHandler.HandleList(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown secrets operation: %s", opType))
	}
}

// handleProfileOperation routes profile-related operations
func (mh *MessageHandler) handleProfileOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing profile operation type")
	}

	opType := opParts[1]

	switch opType {
	case "get":
		return mh.profileHandler.HandleGet(msg)
	case "update":
		return mh.profileHandler.HandleUpdate(msg)
	case "delete":
		return mh.profileHandler.HandleDelete(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown profile operation: %s", opType))
	}
}

// handleCredentialOperation routes credential-related operations
func (mh *MessageHandler) handleCredentialOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing credential operation type")
	}

	opType := opParts[1]

	switch opType {
	case "create":
		// Protean Credential creation (Phase 3 of enrollment)
		return mh.proteanCredentialHandler.HandleCredentialCreate(ctx, msg)
	case "store":
		return mh.credentialHandler.HandleStore(msg)
	case "sync":
		return mh.credentialHandler.HandleSync(msg)
	case "get":
		return mh.credentialHandler.HandleGet(msg)
	case "version":
		return mh.credentialHandler.HandleVersion(msg)
	case "delete":
		// Delete credential (for vault decommission)
		// First clear in-memory state, then delete from storage
		mh.proteanCredentialHandler.ClearCredential()
		return mh.credentialHandler.HandleDelete(msg)
	case "secret":
		// Critical secrets stored within Protean Credential
		return mh.handleCredentialSecretOperation(ctx, msg, opParts[1:])
	case "migration":
		// Migration status and acknowledgment
		return mh.handleCredentialMigrationOperation(ctx, msg, opParts[1:])
	case "emergency_recovery":
		// Emergency recovery when both enclaves unavailable
		return mh.migrationHandler.HandleEmergencyRecovery(ctx, msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown credential operation: %s", opType))
	}
}

// handleCredentialSecretOperation routes credential.secret.* operations
// These are critical secrets (seed phrases, private keys, etc.) that require password verification
func (mh *MessageHandler) handleCredentialSecretOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing credential.secret operation type")
	}

	opType := opParts[1]

	switch opType {
	case "add":
		return mh.credentialSecretHandler.HandleAdd(msg)
	case "get":
		return mh.credentialSecretHandler.HandleGet(msg)
	case "list":
		return mh.credentialSecretHandler.HandleList(msg)
	case "delete":
		return mh.credentialSecretHandler.HandleDelete(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown credential.secret operation: %s", opType))
	}
}

// handleCredentialMigrationOperation routes credential.migration.* operations
func (mh *MessageHandler) handleCredentialMigrationOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing credential.migration operation type")
	}

	opType := opParts[1]

	switch opType {
	case "status":
		return mh.migrationHandler.HandleStatus(ctx, msg)
	case "acknowledge":
		return mh.migrationHandler.HandleAcknowledge(ctx, msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown credential.migration operation: %s", opType))
	}
}

// handleMessageOperation routes messaging-related operations
func (mh *MessageHandler) handleMessageOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing message operation type")
	}

	opType := opParts[1]

	switch opType {
	case "send":
		return mh.messagingHandler.HandleSend(msg)
	case "read-receipt":
		return mh.messagingHandler.HandleReadReceipt(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown message operation: %s", opType))
	}
}

// handleConnectionOperation routes connection-related operations
func (mh *MessageHandler) handleConnectionOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing connection operation type")
	}

	opType := opParts[1]

	switch opType {
	case "create-invite":
		return mh.connectionsHandler.HandleCreateInvite(msg)
	case "store-credentials":
		return mh.connectionsHandler.HandleStoreCredentials(msg)
	case "revoke":
		return mh.connectionsHandler.HandleRevoke(msg)
	case "list":
		return mh.connectionsHandler.HandleList(msg)
	case "get":
		return mh.connectionsHandler.HandleGet(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown connection operation: %s", opType))
	}
}

// handleNotificationOperation routes notification-related operations
func (mh *MessageHandler) handleNotificationOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing notification operation type")
	}

	opType := opParts[1]

	switch opType {
	case "profile-broadcast":
		return mh.notificationsHandler.HandleProfileBroadcast(msg)
	case "revoke-notify":
		return mh.notificationsHandler.HandleRevokeNotify(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown notification operation: %s", opType))
	}
}

// handleVoteOperation routes voting-related operations
func (mh *MessageHandler) handleVoteOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing vote operation type")
	}

	opType := opParts[1]

	switch opType {
	case "cast":
		return mh.voteHandler.HandleCastVote(ctx, msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown vote operation: %s", opType))
	}
}

// handleFeedOperation routes feed-related operations
func (mh *MessageHandler) handleFeedOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing feed operation type")
	}

	opType := opParts[1]

	switch opType {
	case "list":
		return mh.handleFeedList(ctx, msg)
	case "get":
		return mh.handleFeedGet(ctx, msg)
	case "read":
		return mh.handleFeedRead(ctx, msg)
	case "archive":
		return mh.handleFeedArchive(ctx, msg)
	case "delete":
		return mh.handleFeedDelete(ctx, msg)
	case "action":
		return mh.handleFeedAction(ctx, msg)
	case "sync":
		return mh.handleFeedSync(ctx, msg)
	case "settings":
		if len(opParts) < 3 {
			return mh.errorResponse(msg.GetID(), "missing settings operation")
		}
		switch opParts[2] {
		case "get":
			return mh.handleFeedSettingsGet(ctx, msg)
		case "update":
			return mh.handleFeedSettingsUpdate(ctx, msg)
		default:
			return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown settings operation: %s", opParts[2]))
		}
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown feed operation: %s", opType))
	}
}

// handleAuditOperation routes audit-related operations
func (mh *MessageHandler) handleAuditOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing audit operation type")
	}

	opType := opParts[1]

	switch opType {
	case "query":
		return mh.handleAuditQuery(ctx, msg)
	case "export":
		return mh.handleAuditExport(ctx, msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown audit operation: %s", opType))
	}
}

// --- Feed Operation Handlers ---

func (mh *MessageHandler) handleFeedList(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req FeedListRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		req = FeedListRequest{} // Use defaults
	}

	resp, err := mh.eventHandler.ListFeed(ctx, &req)
	if err != nil {
		return mh.errorResponse(msg.GetID(), err.Error())
	}

	respBytes, _ := json.Marshal(resp)
	return mh.successResponse(msg.GetID(), respBytes)
}

func (mh *MessageHandler) handleFeedGet(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		EventID string `json:"event_id"`
	}
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return mh.errorResponse(msg.GetID(), "invalid request format")
	}

	if req.EventID == "" {
		return mh.errorResponse(msg.GetID(), "event_id is required")
	}

	event, err := mh.eventHandler.GetEvent(ctx, req.EventID)
	if err != nil {
		return mh.errorResponse(msg.GetID(), err.Error())
	}
	if event == nil {
		return mh.errorResponse(msg.GetID(), "event not found")
	}

	respBytes, _ := json.Marshal(event)
	return mh.successResponse(msg.GetID(), respBytes)
}

func (mh *MessageHandler) handleFeedRead(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req FeedUpdateStatusRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return mh.errorResponse(msg.GetID(), "invalid request format")
	}

	if req.EventID == "" {
		return mh.errorResponse(msg.GetID(), "event_id is required")
	}

	if err := mh.eventHandler.MarkRead(ctx, req.EventID); err != nil {
		return mh.errorResponse(msg.GetID(), err.Error())
	}

	resp := map[string]interface{}{"success": true, "event_id": req.EventID}
	respBytes, _ := json.Marshal(resp)
	return mh.successResponse(msg.GetID(), respBytes)
}

func (mh *MessageHandler) handleFeedArchive(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req FeedUpdateStatusRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return mh.errorResponse(msg.GetID(), "invalid request format")
	}

	if req.EventID == "" {
		return mh.errorResponse(msg.GetID(), "event_id is required")
	}

	if err := mh.eventHandler.Archive(ctx, req.EventID); err != nil {
		return mh.errorResponse(msg.GetID(), err.Error())
	}

	resp := map[string]interface{}{"success": true, "event_id": req.EventID}
	respBytes, _ := json.Marshal(resp)
	return mh.successResponse(msg.GetID(), respBytes)
}

func (mh *MessageHandler) handleFeedDelete(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req FeedUpdateStatusRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return mh.errorResponse(msg.GetID(), "invalid request format")
	}

	if req.EventID == "" {
		return mh.errorResponse(msg.GetID(), "event_id is required")
	}

	if err := mh.eventHandler.Delete(ctx, req.EventID); err != nil {
		return mh.errorResponse(msg.GetID(), err.Error())
	}

	resp := map[string]interface{}{"success": true, "event_id": req.EventID}
	respBytes, _ := json.Marshal(resp)
	return mh.successResponse(msg.GetID(), respBytes)
}

func (mh *MessageHandler) handleFeedAction(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req FeedActionRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return mh.errorResponse(msg.GetID(), "invalid request format")
	}

	if req.EventID == "" {
		return mh.errorResponse(msg.GetID(), "event_id is required")
	}

	if err := mh.eventHandler.ExecuteAction(ctx, req.EventID, req.Action); err != nil {
		return mh.errorResponse(msg.GetID(), err.Error())
	}

	resp := map[string]interface{}{"success": true, "event_id": req.EventID, "action": req.Action}
	respBytes, _ := json.Marshal(resp)
	return mh.successResponse(msg.GetID(), respBytes)
}

func (mh *MessageHandler) handleFeedSync(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req FeedSyncRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		req = FeedSyncRequest{} // Use defaults
	}

	resp, err := mh.eventHandler.Sync(ctx, &req)
	if err != nil {
		return mh.errorResponse(msg.GetID(), err.Error())
	}

	respBytes, _ := json.Marshal(resp)
	return mh.successResponse(msg.GetID(), respBytes)
}

func (mh *MessageHandler) handleFeedSettingsGet(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	settings := mh.eventHandler.GetSettings()
	respBytes, _ := json.Marshal(settings)
	return mh.successResponse(msg.GetID(), respBytes)
}

func (mh *MessageHandler) handleFeedSettingsUpdate(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var settings FeedSettings
	if err := json.Unmarshal(msg.Payload, &settings); err != nil {
		return mh.errorResponse(msg.GetID(), "invalid settings format")
	}

	if err := mh.eventHandler.UpdateSettings(&settings); err != nil {
		return mh.errorResponse(msg.GetID(), err.Error())
	}

	resp := map[string]interface{}{"success": true}
	respBytes, _ := json.Marshal(resp)
	return mh.successResponse(msg.GetID(), respBytes)
}

// --- Audit Operation Handlers ---

func (mh *MessageHandler) handleAuditQuery(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req AuditQueryRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		req = AuditQueryRequest{} // Use defaults
	}

	resp, err := mh.eventHandler.QueryAudit(ctx, &req)
	if err != nil {
		return mh.errorResponse(msg.GetID(), err.Error())
	}

	respBytes, _ := json.Marshal(resp)
	return mh.successResponse(msg.GetID(), respBytes)
}

func (mh *MessageHandler) handleAuditExport(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req AuditExportRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return mh.errorResponse(msg.GetID(), "invalid request format")
	}

	if req.Format == "" {
		req.Format = "json"
	}

	resp, err := mh.eventHandler.ExportAudit(ctx, &req)
	if err != nil {
		return mh.errorResponse(msg.GetID(), err.Error())
	}

	respBytes, _ := json.Marshal(resp)
	return mh.successResponse(msg.GetID(), respBytes)
}

// GetEventHandler returns the event handler for external access (e.g., cleanup)
func (mh *MessageHandler) GetEventHandler() *EventHandler {
	return mh.eventHandler
}

// Incoming peer message handlers

// handleIncomingProfileUpdate handles profile update notifications from peer vaults
func (mh *MessageHandler) handleIncomingProfileUpdate(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	if err := mh.notificationsHandler.HandleIncomingProfileUpdate(ctx, msg.Payload); err != nil {
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("failed to handle profile update: %v", err))
	}
	return mh.successResponse(msg.GetID(), nil)
}

// handleIncomingRevocation handles revocation notices from peer vaults
func (mh *MessageHandler) handleIncomingRevocation(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	if err := mh.notificationsHandler.HandleIncomingRevocation(ctx, msg.Payload); err != nil {
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("failed to handle revocation: %v", err))
	}
	return mh.successResponse(msg.GetID(), nil)
}

// handleIncomingPeerMessage handles messages from peer vaults
func (mh *MessageHandler) handleIncomingPeerMessage(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	if err := mh.messagingHandler.HandleIncomingMessage(ctx, msg.Payload); err != nil {
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("failed to handle peer message: %v", err))
	}
	return mh.successResponse(msg.GetID(), nil)
}

// handleIncomingReadReceipt handles read receipts from peer vaults
func (mh *MessageHandler) handleIncomingReadReceipt(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	if err := mh.messagingHandler.HandleIncomingReadReceipt(ctx, msg.Payload); err != nil {
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("failed to handle read receipt: %v", err))
	}
	return mh.successResponse(msg.GetID(), nil)
}

// Response helpers

func (mh *MessageHandler) successResponse(id string, payload []byte) (*OutgoingMessage, error) {
	return &OutgoingMessage{
		RequestID: id,
		Type:      MessageTypeResponse,
		Payload:   payload,
	}, nil
}

func (mh *MessageHandler) errorResponse(id string, errMsg string) (*OutgoingMessage, error) {
	return &OutgoingMessage{
		RequestID: id,
		Type:      MessageTypeError,
		Error:     sanitizeErrorForClient(errMsg),
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

// SecureErase zeros all sensitive data in the message handler and its components
// SECURITY: This must be called before process exit to prevent credential leakage
func (mh *MessageHandler) SecureErase() {
	// Zero vault state (holds all cryptographic material)
	if mh.vaultState != nil {
		mh.vaultState.SecureErase()
		mh.vaultState = nil
	}

	// Clear handler references (they don't hold sensitive data directly)
	mh.bootstrapHandler = nil
	mh.pinHandler = nil
	mh.proteanCredentialHandler = nil
	mh.sealerProxy = nil
	mh.callHandler = nil
	mh.secretsHandler = nil
	mh.profileHandler = nil
	mh.credentialHandler = nil
	mh.messagingHandler = nil
	mh.connectionsHandler = nil
	mh.notificationsHandler = nil
	mh.credentialSecretHandler = nil
	mh.migrationHandler = nil
}
