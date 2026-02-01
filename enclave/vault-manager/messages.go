package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

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
	personalDataHandler  *PersonalDataHandler
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

	// Usability feature handlers
	invitationsHandler *InvitationsHandler
	capabilityHandler  *CapabilityHandler
	settingsHandler    *SettingsHandler

	// Service connection handlers (B2C)
	serviceConnectionHandler  *ServiceConnectionHandler
	serviceContractsHandler   *ServiceContractsHandler
	serviceDataHandler        *ServiceDataHandler
	serviceRequestsHandler    *ServiceRequestsHandler
	serviceResourcesHandler   *ServiceResourcesHandler
	serviceActivityHandler      *ServiceActivityHandler      // Phase 7: Activity & Transparency
	serviceNotificationsHandler *ServiceNotificationsHandler // Phase 8: Notifications & Trust
	serviceOfflineHandler       *ServiceOfflineHandler       // Phase 9: Offline Support

	// Combined datastore handler (Phase 4: Advanced Features)
	combinedDatastoreHandler  *CombinedDatastoreHandler
	datastoreAccessController *DatastoreAccessController
	datastoreAuditHandler     *DatastoreAuditHandler
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

// PublishRaw sends a raw message to an arbitrary subject
func (p *VsockPublisher) PublishRaw(subject string, payload []byte) error {
	msg := &OutgoingMessage{
		ID:      generateMessageID(),
		Type:    MessageTypeNATSPublish,
		Subject: subject,
		Payload: payload,
	}

	log.Debug().
		Str("subject", subject).
		Msg("Publishing raw message")

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
	// Storage is passed so DEK can initialize the encrypted SQLite database
	pinHandler := NewPINHandler(ownerSpace, vaultState, bootstrapHandler, sealerProxy, storage)

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

	// Create profile handler (needed by service contracts)
	profileHandler := NewProfileHandler(ownerSpace, storage)
	profileHandler.SetPublisher(publisher)
	profileHandler.SetVaultState(vaultState)

	// Create personal data handler (separate from profile for clarity)
	personalDataHandler := NewPersonalDataHandler(ownerSpace, storage)

	// Create service connection handlers (B2C)
	serviceConnectionHandler := NewServiceConnectionHandler(ownerSpace, storage, eventHandler, profileHandler)
	serviceContractsHandler := NewServiceContractsHandler(ownerSpace, storage, eventHandler, serviceConnectionHandler, profileHandler)
	serviceDataHandler := NewServiceDataHandler(ownerSpace, storage, eventHandler, serviceConnectionHandler, serviceContractsHandler, profileHandler)
	serviceRequestsHandler := NewServiceRequestsHandler(ownerSpace, storage, eventHandler, serviceConnectionHandler, serviceContractsHandler)
	serviceResourcesHandler := NewServiceResourcesHandler(ownerSpace, storage, eventHandler, serviceConnectionHandler)
	serviceActivityHandler := NewServiceActivityHandler(ownerSpace, storage, eventHandler, serviceConnectionHandler)
	serviceNotificationsHandler := NewServiceNotificationsHandler(ownerSpace, storage, eventHandler, serviceConnectionHandler)
	serviceOfflineHandler := NewServiceOfflineHandler(ownerSpace, storage, eventHandler, serviceConnectionHandler)

	// Create combined datastore handler (Phase 4)
	combinedDatastoreHandler := NewCombinedDatastoreHandler(ownerSpace, storage, eventHandler, serviceConnectionHandler, publisher)
	datastoreAccessController := NewDatastoreAccessController(ownerSpace, storage, eventHandler, combinedDatastoreHandler, publisher)
	datastoreAuditHandler := NewDatastoreAuditHandler(ownerSpace, storage, combinedDatastoreHandler)

	return &MessageHandler{
		ownerSpace:           ownerSpace,
		storage:              storage,
		callHandler:          NewCallHandler(ownerSpace, storage, publisher, eventHandler),
		secretsHandler:       NewSecretsHandler(ownerSpace, storage),
		profileHandler:       profileHandler,
		personalDataHandler:  personalDataHandler,
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

		// Usability feature handlers
		invitationsHandler: NewInvitationsHandler(ownerSpace, storage),
		capabilityHandler:  NewCapabilityHandler(ownerSpace, storage, publisher, eventHandler),
		settingsHandler:    NewSettingsHandler(ownerSpace, storage),

		// Service connection handlers (B2C)
		serviceConnectionHandler:  serviceConnectionHandler,
		serviceContractsHandler:   serviceContractsHandler,
		serviceDataHandler:        serviceDataHandler,
		serviceRequestsHandler:    serviceRequestsHandler,
		serviceResourcesHandler:   serviceResourcesHandler,
		serviceActivityHandler:      serviceActivityHandler,
		serviceNotificationsHandler: serviceNotificationsHandler,
		serviceOfflineHandler:       serviceOfflineHandler,

		// Combined datastore (Phase 4)
		combinedDatastoreHandler:  combinedDatastoreHandler,
		datastoreAccessController: datastoreAccessController,
		datastoreAuditHandler:     datastoreAuditHandler,
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
	// Formats supported:
	// - OwnerSpace.{guid}.forVault.{operation...}  (from mobile app)
	// - MessageSpace.{guid}.fromService.{serviceId}.{operation...}  (from services)
	parts := strings.Split(msg.Subject, ".")
	if len(parts) < 4 {
		return mh.errorResponse(msg.GetID(), "invalid subject format")
	}

	// Check for service messages first (fromService routing)
	// Format: MessageSpace.{ownerSpace}.fromService.{serviceId}.{operation}.*
	serviceIndex := -1
	for i, part := range parts {
		if part == "fromService" {
			serviceIndex = i
			break
		}
	}
	if serviceIndex != -1 && serviceIndex+2 < len(parts) {
		// This is a message from a service
		serviceID := parts[serviceIndex+1]
		return mh.handleFromServiceOperation(ctx, msg, serviceID, parts[serviceIndex+2:])
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
	case "personal-data":
		return mh.handlePersonalDataOperation(ctx, msg, parts[opIndex+1:])
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
	case "invitation":
		// Invitation lifecycle operations
		return mh.handleInvitationOperation(ctx, msg, parts[opIndex+1:])
	case "capability":
		// Capability request operations
		return mh.handleCapabilityOperation(ctx, msg, parts[opIndex+1:])
	case "settings":
		// Settings operations
		return mh.handleSettingsOperation(ctx, msg, parts[opIndex+1:])
	case "notifications":
		// Notifications operations (digest)
		return mh.handleNotificationsDigestOperation(ctx, msg, parts[opIndex+1:])
	case "service":
		// Service connection operations (B2C)
		return mh.handleServiceOperation(ctx, msg, parts[opIndex+1:])
	case "datastore":
		// Combined datastore operations (Phase 4)
		return mh.handleDatastoreOperation(ctx, msg, parts[opIndex+1:])
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
	response, err := mh.bootstrapHandler.HandleBootstrap(ctx, msg)
	if err != nil {
		return response, err
	}

	// Persist ECIES keys to S3 for cold vault recovery
	// This allows the vault to receive encrypted PINs even after restart
	mh.vaultState.mu.RLock()
	eciesPrivate := mh.vaultState.eciesPrivateKey
	eciesPublic := mh.vaultState.eciesPublicKey
	mh.vaultState.mu.RUnlock()

	log.Debug().
		Str("owner_space", mh.ownerSpace).
		Bool("has_ecies_private", eciesPrivate != nil).
		Bool("has_ecies_public", eciesPublic != nil).
		Bool("has_sealer_proxy", mh.sealerProxy != nil).
		Msg("Checking ECIES storage conditions after bootstrap")

	if eciesPrivate != nil && eciesPublic != nil && mh.sealerProxy != nil {
		// Marshal ECIES keys
		eciesKeys := struct {
			PrivateKey []byte `json:"private_key"`
			PublicKey  []byte `json:"public_key"`
		}{
			PrivateKey: eciesPrivate,
			PublicKey:  eciesPublic,
		}
		eciesData, err := json.Marshal(eciesKeys)
		if err != nil {
			log.Warn().Err(err).Str("owner_space", mh.ownerSpace).Msg("Failed to marshal ECIES keys")
		} else {
			defer zeroBytes(eciesData)

			// Seal with KMS
			sealedData, err := mh.sealerProxy.SealCredential(eciesData)
			if err != nil {
				log.Warn().Err(err).Str("owner_space", mh.ownerSpace).Msg("Failed to seal ECIES keys")
			} else {
				// Store sealed ECIES keys to S3
				if err := mh.sealerProxy.StoreSealedECIES(sealedData); err != nil {
					log.Warn().Err(err).Str("owner_space", mh.ownerSpace).Msg("Failed to store ECIES keys to S3 - cold vault unlock may not work")
				} else {
					log.Info().Str("owner_space", mh.ownerSpace).Msg("ECIES keys sealed and stored to S3 for cold vault recovery")
				}
			}
		}
	}

	return response, nil
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
	case "get-shared":
		return mh.profileHandler.HandleGetShared(msg)
	case "sharing-settings":
		// Handle sub-operations for sharing settings
		if len(opParts) < 3 {
			return mh.errorResponse(msg.GetID(), "missing sharing-settings operation")
		}
		switch opParts[2] {
		case "get":
			return mh.profileHandler.HandleGetSharingSettings(msg)
		case "update":
			return mh.profileHandler.HandleUpdateSharingSettings(msg)
		default:
			return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown sharing-settings operation: %s", opParts[2]))
		}
	case "categories":
		// Handle category operations (predefined + custom)
		if len(opParts) < 3 {
			return mh.errorResponse(msg.GetID(), "missing categories operation")
		}
		switch opParts[2] {
		case "get":
			return mh.profileHandler.HandleCategoriesGet(msg)
		case "update":
			return mh.profileHandler.HandleCategoriesUpdate(msg)
		default:
			return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown categories operation: %s", opParts[2]))
		}
	case "public":
		// Handle public profile operations
		if len(opParts) < 3 {
			return mh.errorResponse(msg.GetID(), "missing public operation")
		}
		switch opParts[2] {
		case "get":
			return mh.profileHandler.HandlePublicSettingsGet(msg)
		case "update":
			return mh.profileHandler.HandlePublicSettingsUpdate(msg)
		default:
			return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown public operation: %s", opParts[2]))
		}
	case "publish":
		// Publish public profile to NATS
		return mh.profileHandler.HandlePublish(ctx, msg)
	case "get-published":
		// Get the last published profile (what connections see)
		return mh.profileHandler.HandleGetPublished(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown profile operation: %s", opType))
	}
}

// handlePersonalDataOperation routes personal data operations
func (mh *MessageHandler) handlePersonalDataOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing personal-data operation type")
	}

	opType := opParts[1]

	switch opType {
	case "get":
		return mh.personalDataHandler.HandleGet(msg)
	case "update":
		return mh.personalDataHandler.HandleUpdate(msg)
	case "delete":
		return mh.personalDataHandler.HandleDelete(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown personal-data operation: %s", opType))
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
		response, err := mh.proteanCredentialHandler.HandleCredentialCreate(ctx, msg)
		if err != nil {
			return response, err
		}

		// Persist vault state to S3 for cold vault recovery
		mh.vaultState.mu.RLock()
		dek := mh.vaultState.dek
		mh.vaultState.mu.RUnlock()

		if dek != nil && mh.sealerProxy != nil {
			// Create encrypted vault state for S3 storage
			encryptedState, err := mh.createEncryptedVaultState(dek)
			if err != nil {
				log.Warn().Err(err).Str("owner_space", mh.ownerSpace).Msg("Failed to create encrypted vault state")
			} else {
				// Store to S3
				if err := mh.sealerProxy.StoreVaultState(encryptedState); err != nil {
					log.Warn().Err(err).Str("owner_space", mh.ownerSpace).Msg("Failed to store vault state to S3 - cold vault unlock may not work")
				} else {
					log.Info().Str("owner_space", mh.ownerSpace).Msg("Vault state encrypted and stored to S3 for cold vault recovery")
				}
			}
		}

		// SECURITY: Clear DEK after persistence is complete
		mh.vaultState.mu.Lock()
		if mh.vaultState.dek != nil {
			zeroBytes(mh.vaultState.dek)
			mh.vaultState.dek = nil
		}
		mh.vaultState.mu.Unlock()

		return response, nil
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
	case "initiate":
		return mh.connectionsHandler.HandleInitiate(msg)
	case "respond":
		return mh.connectionsHandler.HandleRespond(msg)
	case "revoke":
		return mh.connectionsHandler.HandleRevoke(msg)
	case "list":
		return mh.connectionsHandler.HandleList(msg)
	case "get":
		return mh.connectionsHandler.HandleGet(msg)
	case "update":
		return mh.connectionsHandler.HandleUpdate(msg)
	case "get-capabilities":
		return mh.connectionsHandler.HandleGetCapabilities(msg)
	case "activity-summary":
		return mh.connectionsHandler.HandleActivitySummary(msg)
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

// --- Usability Feature Operation Handlers ---

// handleInvitationOperation routes invitation-related operations
func (mh *MessageHandler) handleInvitationOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing invitation operation type")
	}

	opType := opParts[1]

	switch opType {
	case "list":
		return mh.invitationsHandler.HandleList(msg)
	case "cancel":
		return mh.invitationsHandler.HandleCancel(msg)
	case "resend":
		return mh.invitationsHandler.HandleResend(msg)
	case "viewed":
		return mh.invitationsHandler.HandleViewed(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown invitation operation: %s", opType))
	}
}

// handleCapabilityOperation routes capability-related operations
func (mh *MessageHandler) handleCapabilityOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing capability operation type")
	}

	opType := opParts[1]

	switch opType {
	case "request":
		// Check for sub-operations
		if len(opParts) >= 3 && opParts[2] == "list" {
			return mh.capabilityHandler.HandleRequestList(msg)
		}
		return mh.capabilityHandler.HandleRequest(msg)
	case "respond":
		return mh.capabilityHandler.HandleRespond(msg)
	case "get":
		return mh.capabilityHandler.HandleGet(msg)
	case "list":
		return mh.capabilityHandler.HandleRequestList(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown capability operation: %s", opType))
	}
}

// handleSettingsOperation routes settings-related operations
func (mh *MessageHandler) handleSettingsOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing settings operation type")
	}

	opType := opParts[1]

	switch opType {
	case "notifications":
		// Handle sub-operations for notifications settings
		if len(opParts) < 3 {
			return mh.errorResponse(msg.GetID(), "missing notifications operation")
		}
		switch opParts[2] {
		case "get":
			return mh.settingsHandler.HandleNotificationsGet(msg)
		case "update":
			return mh.settingsHandler.HandleNotificationsUpdate(msg)
		default:
			return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown notifications operation: %s", opParts[2]))
		}
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown settings operation: %s", opType))
	}
}

// handleNotificationsDigestOperation routes notifications digest operations
func (mh *MessageHandler) handleNotificationsDigestOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing notifications operation type")
	}

	opType := opParts[1]

	switch opType {
	case "digest":
		return mh.settingsHandler.HandleNotificationsDigest(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown notifications operation: %s", opType))
	}
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

// createEncryptedVaultState creates DEK-encrypted vault state for S3 storage.
// Returns the encrypted bytes ready for S3 storage.
func (mh *MessageHandler) createEncryptedVaultState(dek []byte) ([]byte, error) {
	// Create DEK-encrypted vault state
	mh.vaultState.mu.RLock()
	persistedState := struct {
		CEKPrivateKey []byte `json:"cek_private_key"`
		CEKPublicKey  []byte `json:"cek_public_key"`
		UTKPairs      []struct {
			ID        string `json:"id"`
			UTK       []byte `json:"utk"`
			LTK       []byte `json:"ltk"`
			UsedAt    int64  `json:"used_at"`
			CreatedAt int64  `json:"created_at"`
		} `json:"utk_pairs"`
		Credential     *UnsealedCredential `json:"credential,omitempty"`
		SealedMaterial []byte              `json:"sealed_material"`
	}{
		SealedMaterial: mh.vaultState.sealedMaterial,
	}

	if mh.vaultState.cekPair != nil {
		persistedState.CEKPrivateKey = mh.vaultState.cekPair.PrivateKey
		persistedState.CEKPublicKey = mh.vaultState.cekPair.PublicKey
	}

	for _, utk := range mh.vaultState.utkPairs {
		persistedState.UTKPairs = append(persistedState.UTKPairs, struct {
			ID        string `json:"id"`
			UTK       []byte `json:"utk"`
			LTK       []byte `json:"ltk"`
			UsedAt    int64  `json:"used_at"`
			CreatedAt int64  `json:"created_at"`
		}{
			ID:        utk.ID,
			UTK:       utk.UTK,
			LTK:       utk.LTK,
			UsedAt:    utk.UsedAt,
			CreatedAt: utk.CreatedAt,
		})
	}

	if mh.vaultState.credential != nil {
		persistedState.Credential = mh.vaultState.credential
	}
	mh.vaultState.mu.RUnlock()

	// Marshal and encrypt with DEK
	stateData, err := json.Marshal(persistedState)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal vault state: %w", err)
	}
	defer zeroBytes(stateData)

	encryptedState, err := encryptWithDEK(dek, stateData)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt vault state: %w", err)
	}

	return encryptedState, nil
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
	mh.personalDataHandler = nil
	mh.credentialHandler = nil
	mh.messagingHandler = nil
	mh.connectionsHandler = nil
	mh.notificationsHandler = nil
	mh.credentialSecretHandler = nil
	mh.migrationHandler = nil
	mh.invitationsHandler = nil
	mh.capabilityHandler = nil
	mh.settingsHandler = nil
	mh.serviceConnectionHandler = nil
	mh.serviceContractsHandler = nil
	mh.serviceDataHandler = nil
	mh.serviceRequestsHandler = nil
	mh.serviceResourcesHandler = nil
}

// handleServiceOperation routes service-related operations
// Handles B2C service connections including connection management,
// contract handling, and data access
func (mh *MessageHandler) handleServiceOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing service operation type")
	}

	subOp := opParts[1] // e.g., "connection", "contract", "data"

	switch subOp {
	case "connection":
		return mh.handleServiceConnectionOperation(ctx, msg, opParts[1:])
	case "contract":
		return mh.handleServiceContractOperation(ctx, msg, opParts[1:])
	case "data":
		return mh.handleServiceDataOperation(ctx, msg, opParts[1:])
	case "request":
		return mh.handleServiceRequestOperation(ctx, msg, opParts[1:])
	case "profile":
		return mh.handleServiceProfileOperation(ctx, msg, opParts[1:])
	case "activity":
		return mh.handleServiceActivityOperation(ctx, msg, opParts[1:])
	case "notifications":
		return mh.handleServiceNotificationsOperation(ctx, msg, opParts[1:])
	case "trust":
		return mh.handleServiceTrustOperation(ctx, msg, opParts[1:])
	case "violations":
		return mh.handleServiceViolationsOperation(ctx, msg, opParts[1:])
	case "offline":
		return mh.handleServiceOfflineOperation(ctx, msg, opParts[1:])
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown service operation: %s", subOp))
	}
}

// handleServiceConnectionOperation routes service.connection.* operations
func (mh *MessageHandler) handleServiceConnectionOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing connection operation type")
	}

	opType := opParts[1] // e.g., "discover", "initiate", "list"

	switch opType {
	case "discover":
		return mh.serviceConnectionHandler.HandleDiscover(msg)
	case "initiate":
		return mh.serviceConnectionHandler.HandleInitiate(msg)
	case "list":
		return mh.serviceConnectionHandler.HandleList(msg)
	case "get":
		return mh.serviceConnectionHandler.HandleGet(msg)
	case "update":
		return mh.serviceConnectionHandler.HandleUpdate(msg)
	case "revoke":
		return mh.serviceConnectionHandler.HandleRevoke(msg)
	case "health":
		return mh.serviceConnectionHandler.HandleHealth(msg)
	// Tag operations (Phase 6)
	case "tags":
		if len(opParts) < 3 {
			return mh.serviceConnectionHandler.HandleListTags(msg) // Default to list
		}
		tagOp := opParts[2]
		switch tagOp {
		case "list":
			return mh.serviceConnectionHandler.HandleListTags(msg)
		case "add":
			return mh.serviceConnectionHandler.HandleAddTag(msg)
		case "remove":
			return mh.serviceConnectionHandler.HandleRemoveTag(msg)
		default:
			return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown tag operation: %s", tagOp))
		}
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown connection operation: %s", opType))
	}
}

// handleServiceContractOperation routes service.contract.* operations
func (mh *MessageHandler) handleServiceContractOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing contract operation type")
	}

	opType := opParts[1] // e.g., "get", "accept", "reject", "history"

	switch opType {
	case "get":
		return mh.serviceContractsHandler.HandleGetContract(msg)
	case "accept":
		return mh.serviceContractsHandler.HandleAcceptUpdate(msg)
	case "reject":
		return mh.serviceContractsHandler.HandleRejectUpdate(msg)
	case "history":
		return mh.serviceContractsHandler.HandleContractHistory(msg)
	case "update-notification":
		// Incoming notification from service about contract update
		return mh.serviceContractsHandler.HandleContractUpdateNotification(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown contract operation: %s", opType))
	}
}

// handleServiceDataOperation routes service.data.* operations
func (mh *MessageHandler) handleServiceDataOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing data operation type")
	}

	opType := opParts[1] // e.g., "get", "store", "list", "delete", "summary", "export"

	switch opType {
	case "get":
		// Incoming request from service for profile data
		return mh.serviceDataHandler.HandleGet(msg)
	case "store":
		// Incoming request from service to store data
		return mh.serviceDataHandler.HandleStore(msg)
	case "list":
		// User listing service-stored data
		return mh.serviceDataHandler.HandleList(msg)
	case "delete":
		// User deleting service data
		return mh.serviceDataHandler.HandleDelete(msg)
	case "summary":
		// User getting storage summary
		return mh.serviceDataHandler.HandleSummary(msg)
	case "export":
		// User exporting service data
		return mh.serviceDataHandler.HandleExport(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown data operation: %s", opType))
	}
}

// handleServiceRequestOperation routes service.request.* operations
func (mh *MessageHandler) handleServiceRequestOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing request operation type")
	}

	opType := opParts[1] // e.g., "auth", "consent", "payment", "respond", "list"

	switch opType {
	case "auth":
		// Incoming auth request from service
		return mh.serviceRequestsHandler.HandleAuthRequest(msg)
	case "consent":
		// Incoming consent request from service
		return mh.serviceRequestsHandler.HandleConsentRequest(msg)
	case "payment":
		// Incoming payment request from service
		return mh.serviceRequestsHandler.HandlePaymentRequest(msg)
	case "respond":
		// User responding to a request
		return mh.serviceRequestsHandler.HandleRespond(msg)
	case "list":
		// User listing requests
		return mh.serviceRequestsHandler.HandleList(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown request operation: %s", opType))
	}
}

// handleServiceProfileOperation routes service.profile.* operations
func (mh *MessageHandler) handleServiceProfileOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing profile operation type")
	}

	opType := opParts[1] // e.g., "get", "resources", "verify-download"

	switch opType {
	case "get":
		// Get cached service profile
		return mh.serviceResourcesHandler.HandleGetProfile(msg)
	case "resources":
		// Get trusted resources
		return mh.serviceResourcesHandler.HandleGetResources(msg)
	case "verify-download":
		// Verify a download
		return mh.serviceResourcesHandler.HandleVerifyDownload(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown profile operation: %s", opType))
	}
}

// handleServiceActivityOperation routes service.activity.* operations (Phase 7)
func (mh *MessageHandler) handleServiceActivityOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing activity operation type")
	}

	opType := opParts[1] // e.g., "list", "summary"

	switch opType {
	case "list":
		return mh.serviceActivityHandler.HandleActivityList(msg)
	case "summary":
		return mh.serviceActivityHandler.HandleActivitySummary(msg)
	case "data-summary":
		return mh.serviceActivityHandler.HandleDataSummary(msg)
	case "data-export":
		return mh.serviceActivityHandler.HandleDataExport(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown activity operation: %s", opType))
	}
}

// handleServiceNotificationsOperation routes service.notifications.* operations (Phase 8)
func (mh *MessageHandler) handleServiceNotificationsOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing notifications operation type")
	}

	opType := opParts[1] // e.g., "get", "update"

	switch opType {
	case "get":
		return mh.serviceNotificationsHandler.HandleGetNotificationSettings(msg)
	case "update":
		return mh.serviceNotificationsHandler.HandleUpdateNotificationSettings(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown notifications operation: %s", opType))
	}
}

// handleServiceTrustOperation routes service.trust.* operations (Phase 8)
func (mh *MessageHandler) handleServiceTrustOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing trust operation type")
	}

	opType := opParts[1] // e.g., "get"

	switch opType {
	case "get":
		return mh.serviceNotificationsHandler.HandleGetTrustIndicators(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown trust operation: %s", opType))
	}
}

// handleServiceViolationsOperation routes service.violations.* operations (Phase 8)
func (mh *MessageHandler) handleServiceViolationsOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing violations operation type")
	}

	opType := opParts[1] // e.g., "list", "acknowledge"

	switch opType {
	case "list":
		return mh.serviceNotificationsHandler.HandleListViolations(msg)
	case "acknowledge":
		return mh.serviceNotificationsHandler.HandleAcknowledgeViolation(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown violations operation: %s", opType))
	}
}

// handleServiceOfflineOperation routes service.offline.* operations (Phase 9)
func (mh *MessageHandler) handleServiceOfflineOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 2 {
		return mh.errorResponse(msg.GetID(), "missing offline operation type")
	}

	opType := opParts[1] // e.g., "list", "sync", "clear", "retry", "cancel", "status"

	switch opType {
	case "list":
		return mh.serviceOfflineHandler.HandleListOfflineActions(msg)
	case "sync":
		return mh.serviceOfflineHandler.HandleTriggerSync(msg)
	case "clear":
		return mh.serviceOfflineHandler.HandleClearOfflineActions(msg)
	case "retry":
		return mh.serviceOfflineHandler.HandleRetryAction(msg)
	case "cancel":
		return mh.serviceOfflineHandler.HandleCancelAction(msg)
	case "status":
		return mh.serviceOfflineHandler.HandleGetSyncStatus(msg)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown offline operation: %s", opType))
	}
}

// handleDatastoreOperation routes datastore.* operations (Phase 4: Combined Datastore)
func (mh *MessageHandler) handleDatastoreOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 1 {
		return mh.errorResponse(msg.GetID(), "missing datastore operation type")
	}

	opType := opParts[0]

	switch opType {
	case "create":
		return mh.combinedDatastoreHandler.HandleCreate(msg)
	case "approve":
		return mh.combinedDatastoreHandler.HandleApprove(msg)
	case "reject":
		return mh.combinedDatastoreHandler.HandleReject(msg)
	case "invite":
		return mh.combinedDatastoreHandler.HandleInviteParticipant(msg)
	case "join":
		return mh.combinedDatastoreHandler.HandleAcceptInvitation(msg)
	case "approve-participant":
		return mh.combinedDatastoreHandler.HandleApproveParticipant(msg)
	case "list":
		return mh.combinedDatastoreHandler.HandleList(msg)
	case "get":
		return mh.combinedDatastoreHandler.HandleGet(msg)
	// Access control operations (DEV-051)
	case "read":
		return mh.datastoreAccessController.HandleRead(ctx, msg)
	case "write":
		return mh.datastoreAccessController.HandleWrite(ctx, msg)
	case "delete":
		return mh.datastoreAccessController.HandleDelete(ctx, msg)
	case "subscribe":
		return mh.datastoreAccessController.HandleSubscribe(ctx, msg)
	case "unsubscribe":
		return mh.datastoreAccessController.HandleUnsubscribe(ctx, msg)
	// Audit operations (DEV-052)
	case "audit":
		if len(opParts) < 2 {
			return mh.errorResponse(msg.GetID(), "missing audit operation type")
		}
		auditOp := opParts[1]
		switch auditOp {
		case "query":
			return mh.datastoreAuditHandler.HandleQuery(ctx, msg)
		case "export":
			return mh.datastoreAuditHandler.HandleExport(ctx, msg)
		case "verify":
			return mh.datastoreAuditHandler.HandleVerifyChain(ctx, msg)
		default:
			return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown audit operation: %s", auditOp))
		}
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown datastore operation: %s", opType))
	}
}

// handleFromServiceOperation handles incoming messages from services via NATS
// Subject format: MessageSpace.{ownerSpace}.fromService.{serviceId}.{operation}.*
//
// SECURITY: This is the entry point for all service-initiated communication.
// Key security principles:
// - Services can ONLY publish to vaults, never subscribe to user data
// - Connection must be active and verified before processing
// - Capabilities are enforced per-operation
// - All operations are logged for audit
func (mh *MessageHandler) handleFromServiceOperation(ctx context.Context, msg *IncomingMessage, serviceID string, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 1 {
		return mh.errorResponse(msg.GetID(), "missing service operation type")
	}

	log.Debug().
		Str("service_id", serviceID).
		Strs("operation", opParts).
		Msg("Handling incoming service message")

	// Find connection by service ID
	conn, err := mh.findConnectionByServiceID(serviceID)
	if err != nil {
		log.Warn().
			Str("service_id", serviceID).
			Err(err).
			Msg("Service connection lookup failed")
		return mh.errorResponse(msg.GetID(), "service connection not found")
	}

	// Verify connection is active
	if conn.Status != "active" {
		log.Warn().
			Str("service_id", serviceID).
			Str("status", conn.Status).
			Msg("Service connection not active")
		return mh.errorResponse(msg.GetID(), "service connection not active")
	}

	// Update last active timestamp
	go mh.serviceConnectionHandler.UpdateLastActive(conn.ConnectionID)

	operation := opParts[0]

	// Route based on operation type
	switch operation {
	case "auth":
		// Service requesting user authentication
		return mh.serviceRequestsHandler.HandleAuthRequest(msg)

	case "consent":
		// Service requesting data consent
		return mh.serviceRequestsHandler.HandleConsentRequest(msg)

	case "payment":
		// Service requesting payment
		if !conn.ServiceProfile.CurrentContract.CanRequestPayment {
			return mh.errorResponse(msg.GetID(), "service does not have payment capability")
		}
		return mh.serviceRequestsHandler.HandlePaymentRequest(msg)

	case "data":
		// Service requesting or sending data
		if len(opParts) < 2 {
			return mh.errorResponse(msg.GetID(), "missing data operation type")
		}
		return mh.handleFromServiceDataOperation(ctx, msg, conn, opParts[1:])

	case "contract-update":
		// Service publishing contract update
		return mh.serviceContractsHandler.HandleContractUpdateNotification(msg)

	case "notify":
		// Service sending notification
		if !conn.ServiceProfile.CurrentContract.CanSendMessages {
			return mh.errorResponse(msg.GetID(), "service does not have messaging capability")
		}
		return mh.handleFromServiceNotification(ctx, msg, conn)

	case "call":
		// Service initiating a call (DEV-034)
		// Check if service has voice or video call capability
		if !conn.ServiceProfile.CurrentContract.CanRequestVoiceCall && !conn.ServiceProfile.CurrentContract.CanRequestVideoCall {
			return mh.errorResponse(msg.GetID(), "service does not have call capability")
		}
		return mh.handleFromServiceCall(ctx, msg, conn, opParts[1:])

	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown service operation: %s", operation))
	}
}

// handleFromServiceDataOperation handles data requests from services
// Enforces contract capabilities before allowing access
func (mh *MessageHandler) handleFromServiceDataOperation(ctx context.Context, msg *IncomingMessage, conn *ServiceConnectionRecord, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 1 {
		return mh.errorResponse(msg.GetID(), "missing data operation type")
	}

	opType := opParts[0]

	switch opType {
	case "get":
		// Service requesting profile data
		// Parse requested fields from payload
		var req struct {
			Fields []string `json:"fields"`
		}
		if err := json.Unmarshal(msg.Payload, &req); err != nil {
			return mh.errorResponse(msg.GetID(), "invalid request format")
		}

		// Enforce contract - check which fields are allowed
		allowed, denied, err := mh.serviceContractsHandler.EnforceContract(conn.ConnectionID, req.Fields, "read")
		if err != nil {
			return mh.errorResponse(msg.GetID(), "contract enforcement failed")
		}
		if !allowed {
			// Return partial error - some fields denied
			return mh.errorResponse(msg.GetID(), fmt.Sprintf("access denied for fields: %v", denied))
		}

		return mh.serviceDataHandler.HandleGet(msg)

	case "store":
		// Service storing data in user's vault
		if !conn.ServiceProfile.CurrentContract.CanStoreData {
			return mh.errorResponse(msg.GetID(), "service does not have storage capability")
		}
		return mh.serviceDataHandler.HandleStore(msg)

	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown data operation: %s", opType))
	}
}

// ServiceNotification represents a notification from a service (DEV-033)
type ServiceNotification struct {
	Title    string                 `json:"title"`
	Body     string                 `json:"body"`
	Priority string                 `json:"priority,omitempty"` // "low", "normal", "high", "urgent"
	ImageURL string                 `json:"image_url,omitempty"`
	ActionURL string                `json:"action_url,omitempty"`
	Data     map[string]interface{} `json:"data,omitempty"`
}

// handleFromServiceNotification handles notification messages from services (DEV-033)
// Supports priority levels, rate limiting, and forwarding to the app
func (mh *MessageHandler) handleFromServiceNotification(ctx context.Context, msg *IncomingMessage, conn *ServiceConnectionRecord) (*OutgoingMessage, error) {
	var notification ServiceNotification
	if err := json.Unmarshal(msg.Payload, &notification); err != nil {
		return mh.errorResponse(msg.GetID(), "invalid notification format")
	}

	// Validate required fields
	if notification.Title == "" && notification.Body == "" {
		return mh.errorResponse(msg.GetID(), "title or body is required")
	}

	// Default priority
	if notification.Priority == "" {
		notification.Priority = "normal"
	}

	// Validate priority
	var priority Priority
	switch notification.Priority {
	case "low":
		priority = PriorityLow
	case "normal":
		priority = PriorityNormal
	case "high":
		priority = PriorityHigh
	case "urgent":
		priority = PriorityUrgent
	default:
		priority = PriorityNormal
	}

	// Check rate limit for notifications (max 10 per hour per service by default)
	maxNotificationsPerHour := conn.ServiceProfile.CurrentContract.MaxNotificationsPerHour
	if maxNotificationsPerHour == 0 {
		maxNotificationsPerHour = 10 // Default limit
	}
	if err := mh.checkServiceNotificationRateLimit(conn.ConnectionID, maxNotificationsPerHour); err != nil {
		log.Warn().
			Str("connection_id", conn.ConnectionID).
			Str("service_id", conn.ServiceGUID).
			Msg("Service notification rate limit exceeded")
		return mh.errorResponse(msg.GetID(), "notification rate limit exceeded")
	}

	// Create feed event for the notification
	if mh.eventHandler != nil {
		event := &Event{
			EventType:  EventTypeServiceNotification,
			SourceType: "service",
			SourceID:   conn.ConnectionID,
			Title:      notification.Title,
			Message:    notification.Body,
			Priority:   priority,
			FeedStatus: FeedStatusActive,
			ActionType: ActionTypeView,
			Metadata: map[string]string{
				"service_id":   conn.ServiceGUID,
				"service_name": conn.ServiceProfile.ServiceName,
				"action_url":   notification.ActionURL,
				"image_url":    notification.ImageURL,
			},
		}
		if err := mh.eventHandler.LogEvent(ctx, event); err != nil {
			log.Error().Err(err).Msg("Failed to log service notification")
		}
	}

	// Forward to app via NATS (if connected)
	if mh.publisher != nil {
		appNotification := map[string]interface{}{
			"type":         "service.notification",
			"service_id":   conn.ServiceGUID,
			"service_name": conn.ServiceProfile.ServiceName,
			"title":        notification.Title,
			"body":         notification.Body,
			"priority":     notification.Priority,
			"image_url":    notification.ImageURL,
			"action_url":   notification.ActionURL,
			"data":         notification.Data,
			"received_at":  time.Now().Unix(),
		}
		notifBytes, _ := json.Marshal(appNotification)
		if err := mh.publisher.PublishToApp(ctx, "service.notification", notifBytes); err != nil {
			log.Warn().Err(err).Msg("Failed to forward notification to app")
			// Continue - notification is still stored in feed
		}
	}

	log.Info().
		Str("connection_id", conn.ConnectionID).
		Str("service_id", conn.ServiceGUID).
		Str("priority", notification.Priority).
		Msg("Service notification processed")

	resp := map[string]interface{}{
		"success":    true,
		"message":    "notification received",
		"event_type": "service.notification",
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// checkServiceNotificationRateLimit checks rate limit for service notifications
func (mh *MessageHandler) checkServiceNotificationRateLimit(connectionID string, maxPerHour int) error {
	// Use simple in-memory tracking via storage
	key := fmt.Sprintf("rate-limit/notification/%s", connectionID)
	data, _ := mh.storage.Get(key)

	var state struct {
		Count       int   `json:"count"`
		WindowStart int64 `json:"window_start"`
	}

	now := time.Now().Unix()
	hourAgo := now - 3600

	if data != nil {
		json.Unmarshal(data, &state)
	}

	// Reset window if expired
	if state.WindowStart < hourAgo {
		state.Count = 0
		state.WindowStart = now
	}

	// Check limit
	if state.Count >= maxPerHour {
		return fmt.Errorf("rate limit exceeded: %d/%d per hour", state.Count, maxPerHour)
	}

	// Increment counter
	state.Count++
	newData, _ := json.Marshal(state)
	mh.storage.Put(key, newData)

	return nil
}

// findConnectionByServiceID finds a service connection by the service's GUID
func (mh *MessageHandler) findConnectionByServiceID(serviceID string) (*ServiceConnectionRecord, error) {
	// Load connection index and find matching service
	indexData, err := mh.storage.Get("service-connections/_index")
	if err != nil {
		return nil, fmt.Errorf("connection index not found")
	}

	var connectionIDs []string
	if err := json.Unmarshal(indexData, &connectionIDs); err != nil {
		return nil, fmt.Errorf("invalid connection index")
	}

	// Search for connection with matching service ID
	for _, connID := range connectionIDs {
		conn, err := mh.serviceConnectionHandler.GetConnection(connID)
		if err != nil {
			continue
		}
		if conn.ServiceGUID == serviceID && conn.Status == "active" {
			return conn, nil
		}
	}

	return nil, fmt.Errorf("no active connection found for service %s", serviceID)
}

// handleFromServiceCall handles call operations from services (DEV-034)
// Supports: call.initiate, call.signal (offer/answer/candidate), call.end
func (mh *MessageHandler) handleFromServiceCall(ctx context.Context, msg *IncomingMessage, conn *ServiceConnectionRecord, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 1 {
		return mh.errorResponse(msg.GetID(), "missing call operation type")
	}

	opType := opParts[0]

	// Check call type capability
	var callType string
	if len(opParts) > 1 {
		callType = opParts[1] // e.g., "video" or "voice"
	}

	// For initiate, verify the specific call type is allowed
	if opType == "initiate" {
		if callType == "video" && !conn.ServiceProfile.CurrentContract.CanRequestVideoCall {
			return mh.errorResponse(msg.GetID(), "service does not have video call capability")
		}
		if callType == "voice" && !conn.ServiceProfile.CurrentContract.CanRequestVoiceCall {
			return mh.errorResponse(msg.GetID(), "service does not have voice call capability")
		}
	}

	switch opType {
	case "initiate":
		// Service initiating a call
		return mh.callHandler.HandleServiceCallInitiate(ctx, msg, conn)
	case "signal":
		// Service sending WebRTC signaling (offer/answer/candidate)
		return mh.callHandler.HandleServiceCallSignaling(ctx, msg, conn)
	case "end":
		// Service ending the call
		return mh.callHandler.HandleServiceCallEnd(ctx, msg, conn)
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown service call operation: %s", opType))
	}
}
