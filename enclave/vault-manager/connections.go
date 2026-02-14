package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/curve25519"
)

// ConnectionsHandler handles connection credential management.
// This enables vault-to-vault communication.
type ConnectionsHandler struct {
	ownerSpace   string
	storage      *EncryptedStorage
	eventHandler *EventHandler
}

// NewConnectionsHandler creates a new connections handler
func NewConnectionsHandler(ownerSpace string, storage *EncryptedStorage, eventHandler *EventHandler) *ConnectionsHandler {
	return &ConnectionsHandler{
		ownerSpace:   ownerSpace,
		storage:      storage,
		eventHandler: eventHandler,
	}
}

// --- Storage types ---

// Connection type constants
const (
	ConnectionTypePeer   = "peer"   // Human-to-human connection (default)
	ConnectionTypeAgent  = "agent"  // AI agent connection via Agent Connector
	ConnectionTypeDevice = "device" // Desktop device connection via session
)

// ConnectionRecord represents a stored connection
type ConnectionRecord struct {
	ConnectionID      string    `json:"connection_id"`
	ConnectionType    string    `json:"connection_type,omitempty"` // "peer" (default) or "agent"
	PeerAlias         string    `json:"peer_alias"`
	PeerGUID          string    `json:"peer_guid,omitempty"`
	CredentialsType   string    `json:"credentials_type"` // "outbound" or "inbound"
	Credentials       string    `json:"credentials,omitempty"`
	MessageSpaceTopic string    `json:"message_space_topic"`
	Status            string    `json:"status"` // "active", "revoked", "pending", "expired"
	CreatedAt         time.Time `json:"created_at"`
	ExpiresAt         time.Time `json:"expires_at,omitempty"`
	LastRotatedAt     time.Time `json:"last_rotated_at,omitempty"`
	KeyExchangeAt     time.Time `json:"key_exchange_at,omitempty"`
	KeyRotationCount  int       `json:"key_rotation_count"`
	// E2E encryption fields
	LocalPublicKey  []byte `json:"local_public_key,omitempty"`
	LocalPrivateKey []byte `json:"local_private_key,omitempty"`
	PeerPublicKey   []byte `json:"peer_public_key,omitempty"`
	SharedSecret    []byte `json:"shared_secret,omitempty"`

	// Activity tracking
	LastActiveAt  *time.Time `json:"last_active_at,omitempty"`
	ActivityCount int        `json:"activity_count"`

	// Organization features
	Tags       []string `json:"tags,omitempty"`
	IsFavorite bool     `json:"is_favorite"`
	IsArchived bool     `json:"is_archived"`

	// Credential tracking
	CredentialsExpireAt *time.Time `json:"credentials_expire_at,omitempty"`

	// Peer profile sync
	PeerProfileVersion int `json:"peer_profile_version"`

	// Peer verifications and capabilities
	PeerVerifications []string          `json:"peer_verifications,omitempty"`
	PeerCapabilities  map[string]string `json:"peer_capabilities,omitempty"`

	// Agent-specific fields (only set when ConnectionType == "agent")
	AgentMetadata *AgentMetadata      `json:"agent_metadata,omitempty"`
	Contract      *ConnectionContract `json:"contract,omitempty"`

	// Device-specific fields (only set when ConnectionType == "device")
	DeviceMetadata *DeviceMetadata `json:"device_metadata,omitempty"`
	DeviceSession  *DeviceSession  `json:"device_session,omitempty"`
}

// DeviceMetadata holds registration details for a desktop device connection.
// Collected by the desktop app during registration and sent to the vault.
type DeviceMetadata struct {
	DeviceType         string `json:"device_type"`          // "desktop", "laptop", etc.
	BinaryFingerprint  string `json:"binary_fingerprint"`   // SHA-256 of desktop binary
	MachineFingerprint string `json:"machine_fingerprint"`  // HMAC-SHA256 of machine attributes
	IPAddress          string `json:"ip_address"`
	Hostname           string `json:"hostname"`
	Platform           string `json:"platform"`             // linux/amd64, darwin/arm64, etc.
	AppVersion         string `json:"app_version,omitempty"`
	OSVersion          string `json:"os_version,omitempty"`
}

// DeviceSession tracks the time-limited session for a device connection.
// Sessions require periodic phone heartbeats to remain active.
type DeviceSession struct {
	SessionID          string   `json:"session_id"`
	Status             string   `json:"status"`              // "active", "expired", "revoked", "suspended"
	CreatedAt          int64    `json:"created_at"`
	ExpiresAt          int64    `json:"expires_at"`
	LastActiveAt       int64    `json:"last_active_at"`
	LastPhoneHeartbeat int64    `json:"last_phone_heartbeat"`
	ExtendedCount      int      `json:"extended_count"`
	MaxExtensions      int      `json:"max_extensions"`      // default 3
	TTLHours           int      `json:"ttl_hours"`           // default 8
	Capabilities       []string `json:"capabilities,omitempty"`
	RequiresPhone      []string `json:"requires_phone,omitempty"`
}

// AgentMetadata holds registration details for an AI agent connection.
// Collected by the Agent Connector during registration and sent to the vault.
type AgentMetadata struct {
	AgentType          string `json:"agent_type"`           // coding_assistant, data_pipeline, etc.
	BinaryFingerprint  string `json:"binary_fingerprint"`   // SHA-256 of connector binary
	MachineFingerprint string `json:"machine_fingerprint"`  // HMAC-SHA256 of machine attributes
	IPAddress          string `json:"ip_address"`
	Hostname           string `json:"hostname"`
	Platform           string `json:"platform"`             // linux/amd64, darwin/arm64, etc.
}

// ConnectionContract defines the permissions and limits for an agent connection.
// Set by the vault owner when approving an agent connection request.
type ConnectionContract struct {
	AgentName    string    `json:"agent_name"`              // Owner-defined name for this agent
	Scope        []string  `json:"scope"`                   // api_keys, ssh_keys, etc.
	ApprovalMode string    `json:"approval_mode"`           // always_ask, auto_within_contract, auto_all
	RateLimit    RateLimit `json:"rate_limit"`
}

// RateLimit defines request frequency limits for an agent connection.
type RateLimit struct {
	Max int    `json:"max"` // e.g. 60
	Per string `json:"per"` // "hour", "minute"
}

// GetConnectionType returns the effective connection type, defaulting to "peer"
// for connections created before the type field was added.
func (r *ConnectionRecord) GetConnectionType() string {
	if r.ConnectionType == "" {
		return ConnectionTypePeer
	}
	return r.ConnectionType
}

// IsAgent returns true if this is an agent connection.
func (r *ConnectionRecord) IsAgent() bool {
	return r.GetConnectionType() == ConnectionTypeAgent
}

// IsDevice returns true if this is a desktop device connection.
func (r *ConnectionRecord) IsDevice() bool {
	return r.GetConnectionType() == ConnectionTypeDevice
}

// --- Request/Response types ---

// CreateInviteRequest is the payload for connection.create-invite
type CreateInviteRequest struct {
	ConnectionID   string `json:"connection_id,omitempty"`
	PeerGUID       string `json:"peer_guid,omitempty"`
	Label          string `json:"label"`
	ExpiresInHours int    `json:"expires_in_hours"`
}

// CreateInviteResponse is the response for connection.create-invite
type CreateInviteResponse struct {
	ConnectionID      string `json:"connection_id"`
	OwnerSpace        string `json:"owner_space"`
	Credentials       string `json:"credentials"`
	MessageSpaceTopic string `json:"message_space_topic"`
	ExpiresAt         string `json:"expires_at"`
	E2EPublicKey      string `json:"e2e_public_key"`
}

// StoreCredentialsRequest is the payload for connection.store-credentials
type StoreCredentialsRequest struct {
	ConnectionID       string `json:"connection_id"`
	PeerAlias          string `json:"peer_alias"`
	Label              string `json:"label"`
	PeerGUID           string `json:"peer_guid"`
	Credentials        string `json:"credentials"`
	NATSCredentials    string `json:"nats_credentials"`
	MessageSpaceTopic  string `json:"message_space_topic"`
	PeerMessageSpaceID string `json:"peer_message_space_id"`
	PeerOwnerSpaceID   string `json:"peer_owner_space_id"`
	PeerE2EPublicKey   string `json:"peer_e2e_public_key"`
}

// StoreCredentialsResponse is the response for connection.store-credentials
type StoreCredentialsResponse struct {
	Success      bool   `json:"success"`
	ConnectionID string `json:"connection_id"`
	E2EPublicKey string `json:"e2e_public_key"`
}

// InitiateConnectionRequest is the payload for connection.initiate
// Used when User B (invitee) initiates connection with User A (inviter)
type InitiateConnectionRequest struct {
	InvitationID         string            `json:"invitation_id"`
	RequesterProfile     map[string]string `json:"requester_profile"`               // B's profile to share with A
	RequesterCapabilities map[string]string `json:"requester_capabilities,omitempty"` // B's capabilities
	RequesterNATSCreds   string            `json:"requester_nats_credentials"`       // Reciprocal creds for A
	RequesterE2EPublicKey string           `json:"requester_e2e_public_key"`
}

// InitiateConnectionResponse is the response for connection.initiate
type InitiateConnectionResponse struct {
	ConnectionID        string            `json:"connection_id"`
	InviterProfile      map[string]string `json:"inviter_profile"`       // A's profile
	InviterCapabilities map[string]string `json:"inviter_capabilities,omitempty"`
	InviterE2EPublicKey string            `json:"inviter_e2e_public_key"`
	PeerVerifications   []string          `json:"peer_verifications"`    // A's verification status
	Status              string            `json:"status"`                // "pending_their_review"
}

// RevokeConnectionRequest is the payload for connection.revoke
type RevokeConnectionRequest struct {
	ConnectionID string `json:"connection_id"`
}

// RespondConnectionRequest is the payload for connection.respond
// Used for bidirectional consent - both parties must accept
type RespondConnectionRequest struct {
	ConnectionID    string `json:"connection_id"`
	Response        string `json:"response"` // "accept" or "reject"
	RejectionReason string `json:"rejection_reason,omitempty"`
}

// RespondConnectionResponse is the response for connection.respond
type RespondConnectionResponse struct {
	Success      bool   `json:"success"`
	ConnectionID string `json:"connection_id"`
	Status       string `json:"status"` // New connection status after response
	Message      string `json:"message,omitempty"`
}

// ListConnectionsRequest is the payload for connection.list
type ListConnectionsRequest struct {
	ConnectionType string   `json:"connection_type,omitempty"` // "peer", "agent", or "" for all
	Status         string   `json:"status,omitempty"`
	Tags           []string `json:"tags,omitempty"`
	IsFavorite     *bool    `json:"is_favorite,omitempty"`
	IsArchived     *bool    `json:"is_archived,omitempty"`
	Search         string   `json:"search,omitempty"`
	SortBy         string   `json:"sort_by,omitempty"` // "recent_activity", "alphabetical", "created_at"
	SortOrder      string   `json:"sort_order,omitempty"` // "asc", "desc"
	Limit          int      `json:"limit,omitempty"`
	Offset         int      `json:"offset,omitempty"`
}

// ConnectionInfo represents connection info in list response
type ConnectionInfo struct {
	ConnectionID     string `json:"connection_id"`
	ConnectionType   string `json:"connection_type"` // "peer" or "agent"
	PeerAlias        string `json:"peer_alias"`
	PeerGUID         string `json:"peer_guid,omitempty"`
	Status           string `json:"status"`
	CreatedAt        string `json:"created_at"`
	LastRotatedAt    string `json:"last_rotated_at,omitempty"`
	CredentialsType  string `json:"credentials_type"`
	E2EReady         bool   `json:"e2e_ready"`
	KeyExchangeAt    string `json:"key_exchange_at,omitempty"`
	KeyRotationCount int    `json:"key_rotation_count,omitempty"`

	// Enhanced fields
	LastActiveAt        string   `json:"last_active_at,omitempty"`
	ActivityCount       int      `json:"activity_count,omitempty"`
	Tags                []string `json:"tags,omitempty"`
	IsFavorite          bool     `json:"is_favorite,omitempty"`
	IsArchived          bool     `json:"is_archived,omitempty"`
	NeedsAttention      bool     `json:"needs_attention,omitempty"`
	CredentialsExpireAt string   `json:"credentials_expire_at,omitempty"`
	PeerProfileVersion  int      `json:"peer_profile_version,omitempty"`
	PeerVerifications   []string `json:"peer_verifications,omitempty"`

	// Agent-specific fields (only present for agent connections)
	AgentMetadata *AgentMetadata      `json:"agent_metadata,omitempty"`
	Contract      *ConnectionContract `json:"contract,omitempty"`
}

// ListConnectionsResponse is the response for connection.list
type ListConnectionsResponse struct {
	Connections []ConnectionInfo `json:"connections"`
}

// GetConnectionRequest is the payload for connection.get
type GetConnectionRequest struct {
	ConnectionID string `json:"connection_id"`
}

// ConnectionUpdateRequest is the payload for connection.update
type ConnectionUpdateRequest struct {
	ConnectionID string   `json:"connection_id"`
	Tags         []string `json:"tags,omitempty"`
	IsFavorite   *bool    `json:"is_favorite,omitempty"`
	IsArchived   *bool    `json:"is_archived,omitempty"`
	PeerAlias    string   `json:"peer_alias,omitempty"`
}

// ConnectionUpdateResponse is the response for connection.update
type ConnectionUpdateResponse struct {
	Success      bool   `json:"success"`
	ConnectionID string `json:"connection_id"`
}

// GetCapabilitiesRequest is the payload for connection.get-capabilities
type GetCapabilitiesRequest struct {
	ConnectionID string `json:"connection_id"`
}

// GetCapabilitiesResponse is the response for connection.get-capabilities
type GetCapabilitiesResponse struct {
	ConnectionID string            `json:"connection_id"`
	Capabilities map[string]string `json:"capabilities"`
}

// ActivitySummaryRequest is the payload for connection.activity-summary
type ActivitySummaryRequest struct {
	ConnectionID string `json:"connection_id"`
}

// ActivitySummaryResponse is the response for connection.activity-summary
type ActivitySummaryResponse struct {
	ConnectionID     string `json:"connection_id"`
	TotalMessages    int    `json:"total_messages"`
	MessagesSent     int    `json:"messages_sent"`
	MessagesReceived int    `json:"messages_received"`
	TotalCalls       int    `json:"total_calls"`
	LastActivityAt   string `json:"last_activity_at,omitempty"`
	LastActivityType string `json:"last_activity_type,omitempty"`
}

// CreateAgentInviteRequest is the payload for connection.agent.create-invite
type CreateAgentInviteRequest struct {
	Label string `json:"label"` // Optional name for this agent slot
}

// CreateAgentInviteResponse returns data the app needs to call POST /vault/agent/shortlink
type CreateAgentInviteResponse struct {
	ConnectionID   string `json:"connection_id"`
	InvitationID   string `json:"invitation_id"`
	InviteToken    string `json:"invite_token"`     // 32 bytes, base64url
	OwnerGUID      string `json:"owner_guid"`
	VaultPublicKey string `json:"vault_public_key"` // Hex X25519 public key
	ExpiresAt      string `json:"expires_at"`
}

// CreateDeviceInviteRequest is the payload for connection.device.create-invite
type CreateDeviceInviteRequest struct {
	Label string `json:"label"` // Optional name for this device slot
}

// CreateDeviceInviteResponse returns data the app needs to call POST /vault/agent/shortlink
type CreateDeviceInviteResponse struct {
	ConnectionID   string `json:"connection_id"`
	InvitationID   string `json:"invitation_id"`
	InviteToken    string `json:"invite_token"`     // 32 bytes, base64url
	OwnerGUID      string `json:"owner_guid"`
	VaultPublicKey string `json:"vault_public_key"` // Hex X25519 public key
	ExpiresAt      string `json:"expires_at"`
}

// --- Handler methods ---

// HandleCreateInvite handles connection.create-invite messages
func (h *ConnectionsHandler) HandleCreateInvite(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req CreateInviteRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	// Generate connection_id if not provided
	connectionID := req.ConnectionID
	if connectionID == "" {
		idBytes := make([]byte, 16)
		rand.Read(idBytes)
		connectionID = fmt.Sprintf("conn-%x", idBytes)
	}

	expiresInHours := req.ExpiresInHours
	if expiresInHours <= 0 {
		expiresInHours = 24 * 30 // Default 30 days
	}

	expiresAt := time.Now().Add(time.Duration(expiresInHours) * time.Hour)

	// Generate X25519 key pair for E2E encryption
	localPrivate := make([]byte, 32)
	rand.Read(localPrivate)

	// Derive public key from private key using X25519 scalar multiplication
	localPublic, err := curve25519.X25519(localPrivate, curve25519.Basepoint)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to derive public key")
	}

	// Store the outbound connection record
	record := ConnectionRecord{
		ConnectionID:      connectionID,
		PeerAlias:         req.Label,
		PeerGUID:          req.PeerGUID,
		CredentialsType:   "outbound",
		MessageSpaceTopic: fmt.Sprintf("MessageSpace.%s.forOwner.>", h.ownerSpace),
		Status:            "active",
		CreatedAt:         time.Now(),
		ExpiresAt:         expiresAt,
		LocalPublicKey:    localPublic,
		LocalPrivateKey:   localPrivate,
	}

	data, err := json.Marshal(record)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to marshal connection")
	}

	storageKey := "connections/" + connectionID
	if err := h.storage.Put(storageKey, data); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to store connection")
	}

	// Add to index
	h.addToConnectionIndex(connectionID)

	// Log connection created event for audit
	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(context.Background(), EventTypeConnectionCreated, connectionID, req.PeerGUID, "Connection invite created")
	}

	log.Info().Str("connection_id", connectionID).Msg("Connection invite created")

	resp := CreateInviteResponse{
		ConnectionID:      connectionID,
		OwnerSpace:        h.ownerSpace,
		Credentials:       "", // Phase 2: Lambda-generated scoped NATS JWTs
		MessageSpaceTopic: record.MessageSpaceTopic,
		ExpiresAt:         expiresAt.Format(time.RFC3339),
		E2EPublicKey:      fmt.Sprintf("%x", localPublic),
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleCreateAgentInvite handles connection.agent.create-invite messages.
// Creates a connection + invitation for an AI agent connector and returns
// the details the app needs to call POST /vault/agent/shortlink.
func (h *ConnectionsHandler) HandleCreateAgentInvite(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req CreateAgentInviteRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	label := req.Label
	if label == "" {
		label = "Agent"
	}

	// Generate connection ID
	idBytes := make([]byte, 16)
	rand.Read(idBytes)
	connectionID := fmt.Sprintf("conn-%x", idBytes)

	// Agent invitations expire in 24 hours (shorter than peer's 30 days)
	expiresAt := time.Now().Add(24 * time.Hour)

	// Generate X25519 key pair for E2E encryption
	localPrivate := make([]byte, 32)
	rand.Read(localPrivate)

	localPublic, err := curve25519.X25519(localPrivate, curve25519.Basepoint)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to derive public key")
	}

	// Generate invite token (32 bytes, base64url-encoded)
	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	inviteToken := base64.RawURLEncoding.EncodeToString(tokenBytes)

	// Store the outbound agent connection record
	record := ConnectionRecord{
		ConnectionID:      connectionID,
		ConnectionType:    ConnectionTypeAgent,
		PeerAlias:         label,
		CredentialsType:   "outbound",
		MessageSpaceTopic: fmt.Sprintf("MessageSpace.%s.forOwner.>", h.ownerSpace),
		Status:            "invited",
		CreatedAt:         time.Now(),
		ExpiresAt:         expiresAt,
		LocalPublicKey:    localPublic,
		LocalPrivateKey:   localPrivate,
	}

	data, err := json.Marshal(record)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to marshal connection")
	}

	storageKey := "connections/" + connectionID
	if err := h.storage.Put(storageKey, data); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to store connection")
	}

	h.addToConnectionIndex(connectionID)

	// Create invitation record
	invitationID, err := h.createAgentInvitation(connectionID, label, inviteToken, expiresAt)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to create invitation")
	}

	// Log connection created event for audit
	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(context.Background(), EventTypeConnectionCreated, connectionID, "", "Agent invitation created")
	}

	log.Info().
		Str("connection_id", connectionID).
		Str("invitation_id", invitationID).
		Msg("Agent invitation created")

	resp := CreateAgentInviteResponse{
		ConnectionID:   connectionID,
		InvitationID:   invitationID,
		InviteToken:    inviteToken,
		OwnerGUID:      h.ownerSpace,
		VaultPublicKey: fmt.Sprintf("%x", localPublic),
		ExpiresAt:      expiresAt.Format(time.RFC3339),
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// createAgentInvitation creates an invitation record for an agent connection.
func (h *ConnectionsHandler) createAgentInvitation(connectionID, label, inviteToken string, expiresAt time.Time) (string, error) {
	idBytes := make([]byte, 16)
	rand.Read(idBytes)
	invitationID := fmt.Sprintf("inv-%x", idBytes)

	record := InvitationRecord{
		InvitationID:   invitationID,
		ConnectionID:   connectionID,
		Status:         "pending",
		DeliveryMethod: "shortlink",
		Label:          label,
		InviteToken:    inviteToken,
		CreatedAt:      time.Now(),
		ExpiresAt:      expiresAt,
	}

	data, err := json.Marshal(record)
	if err != nil {
		return "", fmt.Errorf("failed to marshal invitation: %w", err)
	}

	if err := h.storage.Put("invitations/"+invitationID, data); err != nil {
		return "", fmt.Errorf("failed to store invitation: %w", err)
	}

	// Add to invitation index
	var index []string
	indexData, err := h.storage.Get("invitations/_index")
	if err == nil {
		json.Unmarshal(indexData, &index)
	}

	for _, id := range index {
		if id == invitationID {
			return invitationID, nil
		}
	}

	index = append(index, invitationID)
	newIndexData, _ := json.Marshal(index)
	h.storage.Put("invitations/_index", newIndexData)

	log.Info().
		Str("invitation_id", invitationID).
		Str("connection_id", connectionID).
		Msg("Agent invitation record created")

	return invitationID, nil
}

// HandleStoreCredentials handles connection.store-credentials messages
func (h *ConnectionsHandler) HandleStoreCredentials(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req StoreCredentialsRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	// Normalize alternate field names from Android client
	if req.PeerAlias == "" && req.Label != "" {
		req.PeerAlias = req.Label
	}
	if req.Credentials == "" && req.NATSCredentials != "" {
		req.Credentials = req.NATSCredentials
	}
	if req.MessageSpaceTopic == "" && req.PeerMessageSpaceID != "" {
		req.MessageSpaceTopic = req.PeerMessageSpaceID
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}
	// Credentials are optional in Phase 1 (no scoped NATS JWTs yet)
	if req.MessageSpaceTopic == "" {
		return h.errorResponse(msg.GetID(), "message_space_topic is required")
	}

	// Generate our X25519 key pair
	localPrivate := make([]byte, 32)
	rand.Read(localPrivate)

	// Derive public key from private key using X25519 scalar multiplication
	localPublic, err := curve25519.X25519(localPrivate, curve25519.Basepoint)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to derive public key")
	}

	// Store the inbound connection record
	record := ConnectionRecord{
		ConnectionID:      req.ConnectionID,
		PeerAlias:         req.PeerAlias,
		PeerGUID:          req.PeerGUID,
		CredentialsType:   "inbound",
		Credentials:       req.Credentials,
		MessageSpaceTopic: req.MessageSpaceTopic,
		Status:            "active",
		CreatedAt:         time.Now(),
		LocalPublicKey:    localPublic,
		LocalPrivateKey:   localPrivate,
		KeyExchangeAt:     time.Now(),
	}

	data, err := json.Marshal(record)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to marshal connection")
	}

	storageKey := "connections/" + req.ConnectionID
	if err := h.storage.Put(storageKey, data); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to store connection")
	}

	h.addToConnectionIndex(req.ConnectionID)

	// Log connection accepted event for audit (storing credentials means accepting the connection)
	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(context.Background(), EventTypeConnectionAccepted, req.ConnectionID, req.PeerGUID, "Connection established")
	}

	log.Info().Str("connection_id", req.ConnectionID).Msg("Connection credentials stored")

	resp := map[string]interface{}{
		"success":       true,
		"connection_id": req.ConnectionID,
		"e2e_public_key": fmt.Sprintf("%x", localPublic),
		"label":         record.PeerAlias,
		"peer_guid":     record.PeerGUID,
		"status":        record.Status,
		"direction":     record.CredentialsType,
		"created_at":    record.CreatedAt.Format(time.RFC3339),
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleInitiate handles connection.initiate messages
// This is used when User B (invitee) initiates a connection with User A (inviter)
// Part of the bidirectional consent flow
func (h *ConnectionsHandler) HandleInitiate(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req InitiateConnectionRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.InvitationID == "" {
		return h.errorResponse(msg.GetID(), "invitation_id is required")
	}
	if req.RequesterE2EPublicKey == "" {
		return h.errorResponse(msg.GetID(), "requester_e2e_public_key is required")
	}

	// Find the connection associated with this invitation
	// Invitations are linked to connections via the connection_id stored in the invitation
	invitationData, err := h.storage.Get("invitations/" + req.InvitationID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Invitation not found")
	}

	var invitation struct {
		ConnectionID string `json:"connection_id"`
		Status       string `json:"status"`
		ExpiresAt    string `json:"expires_at"`
	}
	if err := json.Unmarshal(invitationData, &invitation); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to read invitation")
	}

	if invitation.Status != "pending" {
		return h.errorResponse(msg.GetID(), "Invitation is no longer valid")
	}

	// Load the connection record
	connectionID := invitation.ConnectionID
	storageKey := "connections/" + connectionID
	connData, err := h.storage.Get(storageKey)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}

	var record ConnectionRecord
	if err := json.Unmarshal(connData, &record); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to read connection")
	}

	// Store requester's info in the connection record
	record.PeerCapabilities = req.RequesterCapabilities
	record.Status = "pending_our_review" // Inviter (A) needs to review invitee (B)

	// Decode peer's E2E public key and compute shared secret
	peerPublicKey, err := decodeHexKey(req.RequesterE2EPublicKey)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Invalid requester public key format")
	}
	record.PeerPublicKey = peerPublicKey

	// Compute shared secret using X25519
	if len(record.LocalPrivateKey) > 0 && len(peerPublicKey) > 0 {
		sharedSecret, err := curve25519.X25519(record.LocalPrivateKey, peerPublicKey)
		if err == nil {
			record.SharedSecret = sharedSecret
			record.KeyExchangeAt = time.Now()
		}
	}

	// Save updated connection record
	newData, err := json.Marshal(record)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to update connection")
	}
	if err := h.storage.Put(storageKey, newData); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to store connection update")
	}

	// Log the initiation event
	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(context.Background(), EventTypeConnectionInitiated, connectionID, "", "Connection initiated by peer")
	}

	// Load the inviter's profile to return to the requester
	inviterProfile := make(map[string]string)
	profileIndexData, err := h.storage.Get("profile/_index")
	if err == nil {
		var fieldNames []string
		if json.Unmarshal(profileIndexData, &fieldNames) == nil {
			for _, field := range fieldNames {
				fieldData, err := h.storage.Get("profile/" + field)
				if err == nil {
					var entry struct {
						Value string `json:"value"`
					}
					if json.Unmarshal(fieldData, &entry) == nil {
						inviterProfile[field] = entry.Value
					}
				}
			}
		}
	}

	// Build peer verifications array from profile
	peerVerifications := []string{}
	if _, ok := inviterProfile["email_verified"]; ok {
		if inviterProfile["email_verified"] == "true" {
			peerVerifications = append(peerVerifications, "email")
		}
	}
	if _, ok := inviterProfile["identity_verified"]; ok {
		if inviterProfile["identity_verified"] == "true" {
			peerVerifications = append(peerVerifications, "identity")
		}
	}

	log.Info().
		Str("connection_id", connectionID).
		Str("invitation_id", req.InvitationID).
		Msg("Connection initiated")

	resp := InitiateConnectionResponse{
		ConnectionID:        connectionID,
		InviterProfile:      inviterProfile,
		InviterCapabilities: record.PeerCapabilities,
		InviterE2EPublicKey: fmt.Sprintf("%x", record.LocalPublicKey),
		PeerVerifications:   peerVerifications,
		Status:              "pending_their_review", // B needs to review A
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// decodeHexKey decodes a hex-encoded key string
func decodeHexKey(hexKey string) ([]byte, error) {
	// Remove any leading 0x prefix if present
	if len(hexKey) >= 2 && hexKey[:2] == "0x" {
		hexKey = hexKey[2:]
	}

	decoded := make([]byte, len(hexKey)/2)
	for i := 0; i < len(decoded); i++ {
		var b byte
		_, err := fmt.Sscanf(hexKey[i*2:i*2+2], "%02x", &b)
		if err != nil {
			return nil, fmt.Errorf("invalid hex at position %d: %w", i*2, err)
		}
		decoded[i] = b
	}
	return decoded, nil
}

// HandleRespond handles connection.respond messages
// Part of bidirectional consent - both parties must accept for connection to become active
func (h *ConnectionsHandler) HandleRespond(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req RespondConnectionRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}
	if req.Response != "accept" && req.Response != "reject" {
		return h.errorResponse(msg.GetID(), "response must be 'accept' or 'reject'")
	}

	// Load the connection record
	storageKey := "connections/" + req.ConnectionID
	connData, err := h.storage.Get(storageKey)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}

	var record ConnectionRecord
	if err := json.Unmarshal(connData, &record); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to read connection")
	}

	// Validate current status allows a response
	validStatuses := map[string]bool{
		"pending_our_review":   true, // We need to review and respond
		"pending_their_accept": true, // They reviewed, now we confirm
	}
	if !validStatuses[record.Status] {
		return h.errorResponse(msg.GetID(), fmt.Sprintf("Connection is not awaiting response (status: %s)", record.Status))
	}

	var newStatus string
	var message string

	if req.Response == "reject" {
		// Rejection ends the connection flow
		newStatus = "rejected"
		message = "Connection rejected"

		// Log rejection event
		if h.eventHandler != nil {
			h.eventHandler.LogConnectionEvent(context.Background(), EventTypeConnectionRejected, req.ConnectionID, record.PeerGUID, req.RejectionReason)
		}
	} else {
		// Acceptance - determine next status based on current state
		switch record.Status {
		case "pending_our_review":
			// We reviewed and accepted, now waiting for peer to accept
			newStatus = "pending_their_accept"
			message = "Accepted, waiting for peer confirmation"
		case "pending_their_accept":
			// Both parties have now accepted - connection is active!
			newStatus = "active"
			message = "Connection established"

			// Log acceptance event
			if h.eventHandler != nil {
				h.eventHandler.LogConnectionEvent(context.Background(), EventTypeConnectionAccepted, req.ConnectionID, record.PeerGUID, "Bidirectional consent complete")
			}
		}
	}

	// Update connection record
	record.Status = newStatus
	newData, err := json.Marshal(record)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to update connection")
	}
	if err := h.storage.Put(storageKey, newData); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to store connection update")
	}

	log.Info().
		Str("connection_id", req.ConnectionID).
		Str("response", req.Response).
		Str("new_status", newStatus).
		Msg("Connection response processed")

	resp := RespondConnectionResponse{
		Success:      true,
		ConnectionID: req.ConnectionID,
		Status:       newStatus,
		Message:      message,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleRevoke handles connection.revoke messages
func (h *ConnectionsHandler) HandleRevoke(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req RevokeConnectionRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	storageKey := "connections/" + req.ConnectionID
	data, err := h.storage.Get(storageKey)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}

	var record ConnectionRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to read connection")
	}

	// SECURITY: Zero key material before storing revoked connection
	zeroBytes(record.SharedSecret)
	record.SharedSecret = nil
	zeroBytes(record.LocalPrivateKey)
	record.LocalPrivateKey = nil
	record.Status = "revoked"

	newData, _ := json.Marshal(record)
	if err := h.storage.Put(storageKey, newData); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to revoke connection")
	}

	// Log connection revoked event for audit and feed
	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(context.Background(), EventTypeConnectionRevoked, req.ConnectionID, record.PeerGUID, "Connection revoked")
	}

	log.Info().Str("connection_id", req.ConnectionID).Msg("Connection revoked")

	resp := map[string]interface{}{
		"success":       true,
		"connection_id": req.ConnectionID,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleList handles connection.list messages
func (h *ConnectionsHandler) HandleList(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req ListConnectionsRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		// Allow empty payload for list all
		req = ListConnectionsRequest{}
	}

	// Get connection index
	indexData, err := h.storage.Get("connections/_index")
	var connectionIDs []string
	if err == nil {
		json.Unmarshal(indexData, &connectionIDs)
	}

	connections := make([]ConnectionInfo, 0)
	for _, connID := range connectionIDs {
		data, err := h.storage.Get("connections/" + connID)
		if err != nil {
			continue
		}

		var record ConnectionRecord
		if json.Unmarshal(data, &record) != nil {
			continue
		}

		// Filter by connection type if specified
		if req.ConnectionType != "" && record.GetConnectionType() != req.ConnectionType {
			continue
		}

		// Filter by status if specified
		if req.Status != "" && record.Status != req.Status {
			continue
		}

		// Filter by tags if specified
		if len(req.Tags) > 0 {
			hasTag := false
			for _, reqTag := range req.Tags {
				for _, recTag := range record.Tags {
					if reqTag == recTag {
						hasTag = true
						break
					}
				}
				if hasTag {
					break
				}
			}
			if !hasTag {
				continue
			}
		}

		// Filter by favorite if specified
		if req.IsFavorite != nil && record.IsFavorite != *req.IsFavorite {
			continue
		}

		// Filter by archived if specified
		if req.IsArchived != nil && record.IsArchived != *req.IsArchived {
			continue
		}

		// Filter by search term (case-insensitive substring match on alias or agent name)
		if req.Search != "" {
			searchLower := strings.ToLower(req.Search)
			matchAlias := strings.Contains(strings.ToLower(record.PeerAlias), searchLower)
			matchAgent := record.Contract != nil && strings.Contains(strings.ToLower(record.Contract.AgentName), searchLower)
			if !matchAlias && !matchAgent {
				continue
			}
		}

		// Compute needs_attention flag
		needsAttention := h.computeNeedsAttention(&record)

		info := ConnectionInfo{
			ConnectionID:       record.ConnectionID,
			ConnectionType:     record.GetConnectionType(),
			PeerAlias:          record.PeerAlias,
			PeerGUID:           record.PeerGUID,
			Status:             record.Status,
			CreatedAt:          record.CreatedAt.Format(time.RFC3339),
			CredentialsType:    record.CredentialsType,
			E2EReady:           len(record.SharedSecret) > 0,
			KeyRotationCount:   record.KeyRotationCount,
			ActivityCount:      record.ActivityCount,
			Tags:               record.Tags,
			IsFavorite:         record.IsFavorite,
			IsArchived:         record.IsArchived,
			NeedsAttention:     needsAttention,
			PeerProfileVersion: record.PeerProfileVersion,
			PeerVerifications:  record.PeerVerifications,
			AgentMetadata:      record.AgentMetadata,
			Contract:           record.Contract,
		}

		if !record.LastRotatedAt.IsZero() {
			info.LastRotatedAt = record.LastRotatedAt.Format(time.RFC3339)
		}
		if !record.KeyExchangeAt.IsZero() {
			info.KeyExchangeAt = record.KeyExchangeAt.Format(time.RFC3339)
		}
		if record.LastActiveAt != nil {
			info.LastActiveAt = record.LastActiveAt.Format(time.RFC3339)
		}
		if record.CredentialsExpireAt != nil {
			info.CredentialsExpireAt = record.CredentialsExpireAt.Format(time.RFC3339)
		}

		connections = append(connections, info)
	}

	// Sort connections
	h.sortConnections(connections, req.SortBy, req.SortOrder)

	// Apply pagination
	total := len(connections)
	if req.Offset > 0 && req.Offset < len(connections) {
		connections = connections[req.Offset:]
	} else if req.Offset >= len(connections) {
		connections = []ConnectionInfo{}
	}
	if req.Limit > 0 && req.Limit < len(connections) {
		connections = connections[:req.Limit]
	}

	resp := struct {
		Connections []ConnectionInfo `json:"connections"`
		Total       int              `json:"total"`
		Offset      int              `json:"offset"`
		Limit       int              `json:"limit"`
	}{
		Connections: connections,
		Total:       total,
		Offset:      req.Offset,
		Limit:       req.Limit,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// computeNeedsAttention determines if a connection requires user attention
func (h *ConnectionsHandler) computeNeedsAttention(record *ConnectionRecord) bool {
	// Pending invitations need attention
	if record.Status == "pending" {
		return true
	}

	// Expiring credentials within 7 days need attention
	if record.CredentialsExpireAt != nil {
		sevenDays := time.Now().Add(7 * 24 * time.Hour)
		if record.CredentialsExpireAt.Before(sevenDays) {
			return true
		}
	}

	// Expired connections need attention
	if !record.ExpiresAt.IsZero() && record.ExpiresAt.Before(time.Now()) {
		return true
	}

	return false
}

// sortConnections sorts the connection list based on sort parameters
func (h *ConnectionsHandler) sortConnections(connections []ConnectionInfo, sortBy, sortOrder string) {
	if sortBy == "" {
		sortBy = "created_at"
	}
	if sortOrder == "" {
		sortOrder = "desc"
	}

	// Sort using sort.Slice
	switch sortBy {
	case "alphabetical":
		if sortOrder == "asc" {
			for i := 0; i < len(connections)-1; i++ {
				for j := i + 1; j < len(connections); j++ {
					if strings.ToLower(connections[i].PeerAlias) > strings.ToLower(connections[j].PeerAlias) {
						connections[i], connections[j] = connections[j], connections[i]
					}
				}
			}
		} else {
			for i := 0; i < len(connections)-1; i++ {
				for j := i + 1; j < len(connections); j++ {
					if strings.ToLower(connections[i].PeerAlias) < strings.ToLower(connections[j].PeerAlias) {
						connections[i], connections[j] = connections[j], connections[i]
					}
				}
			}
		}
	case "recent_activity":
		if sortOrder == "asc" {
			for i := 0; i < len(connections)-1; i++ {
				for j := i + 1; j < len(connections); j++ {
					if connections[i].LastActiveAt > connections[j].LastActiveAt {
						connections[i], connections[j] = connections[j], connections[i]
					}
				}
			}
		} else {
			for i := 0; i < len(connections)-1; i++ {
				for j := i + 1; j < len(connections); j++ {
					if connections[i].LastActiveAt < connections[j].LastActiveAt {
						connections[i], connections[j] = connections[j], connections[i]
					}
				}
			}
		}
	default: // created_at
		if sortOrder == "asc" {
			for i := 0; i < len(connections)-1; i++ {
				for j := i + 1; j < len(connections); j++ {
					if connections[i].CreatedAt > connections[j].CreatedAt {
						connections[i], connections[j] = connections[j], connections[i]
					}
				}
			}
		} else {
			for i := 0; i < len(connections)-1; i++ {
				for j := i + 1; j < len(connections); j++ {
					if connections[i].CreatedAt < connections[j].CreatedAt {
						connections[i], connections[j] = connections[j], connections[i]
					}
				}
			}
		}
	}
}

// HandleGet handles connection.get messages
func (h *ConnectionsHandler) HandleGet(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req GetConnectionRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
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

	// Compute needs_attention flag
	needsAttention := h.computeNeedsAttention(&record)

	info := ConnectionInfo{
		ConnectionID:       record.ConnectionID,
		ConnectionType:     record.GetConnectionType(),
		PeerAlias:          record.PeerAlias,
		PeerGUID:           record.PeerGUID,
		Status:             record.Status,
		CreatedAt:          record.CreatedAt.Format(time.RFC3339),
		CredentialsType:    record.CredentialsType,
		E2EReady:           len(record.SharedSecret) > 0,
		KeyRotationCount:   record.KeyRotationCount,
		ActivityCount:      record.ActivityCount,
		Tags:               record.Tags,
		IsFavorite:         record.IsFavorite,
		IsArchived:         record.IsArchived,
		NeedsAttention:     needsAttention,
		PeerProfileVersion: record.PeerProfileVersion,
		PeerVerifications:  record.PeerVerifications,
		AgentMetadata:      record.AgentMetadata,
		Contract:           record.Contract,
	}

	if !record.LastRotatedAt.IsZero() {
		info.LastRotatedAt = record.LastRotatedAt.Format(time.RFC3339)
	}
	if !record.KeyExchangeAt.IsZero() {
		info.KeyExchangeAt = record.KeyExchangeAt.Format(time.RFC3339)
	}
	if record.LastActiveAt != nil {
		info.LastActiveAt = record.LastActiveAt.Format(time.RFC3339)
	}
	if record.CredentialsExpireAt != nil {
		info.CredentialsExpireAt = record.CredentialsExpireAt.Format(time.RFC3339)
	}

	respBytes, _ := json.Marshal(info)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleUpdate handles connection.update messages
func (h *ConnectionsHandler) HandleUpdate(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req ConnectionUpdateRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	storageKey := "connections/" + req.ConnectionID
	data, err := h.storage.Get(storageKey)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}

	var record ConnectionRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to read connection")
	}

	// Update fields if provided
	if req.Tags != nil {
		record.Tags = req.Tags
	}
	if req.IsFavorite != nil {
		record.IsFavorite = *req.IsFavorite
	}
	if req.IsArchived != nil {
		record.IsArchived = *req.IsArchived
	}
	if req.PeerAlias != "" {
		record.PeerAlias = req.PeerAlias
	}

	// Save updated record
	newData, err := json.Marshal(record)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to marshal connection")
	}

	if err := h.storage.Put(storageKey, newData); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to update connection")
	}

	log.Info().Str("connection_id", req.ConnectionID).Msg("Connection updated")

	resp := ConnectionUpdateResponse{
		Success:      true,
		ConnectionID: req.ConnectionID,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleRotate handles connection.rotate messages
// Generates a new X25519 keypair for an active connection
func (h *ConnectionsHandler) HandleRotate(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		ConnectionID string `json:"connection_id"`
	}
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	storageKey := "connections/" + req.ConnectionID
	data, err := h.storage.Get(storageKey)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}

	var record ConnectionRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to read connection")
	}

	if record.Status != "active" {
		return h.errorResponse(msg.GetID(), fmt.Sprintf("Cannot rotate keys for connection with status: %s", record.Status))
	}

	// Generate new X25519 keypair
	localPrivate := make([]byte, 32)
	rand.Read(localPrivate)

	localPublic, err := curve25519.X25519(localPrivate, curve25519.Basepoint)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to derive public key")
	}

	// Update connection record
	record.LocalPrivateKey = localPrivate
	record.LocalPublicKey = localPublic
	record.SharedSecret = nil // Clear shared secret until peer exchanges new key
	record.LastRotatedAt = time.Now()
	record.KeyRotationCount++

	newData, err := json.Marshal(record)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to marshal connection")
	}

	if err := h.storage.Put(storageKey, newData); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to update connection")
	}

	// Log rotation event
	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(context.Background(), EventTypeConnectionRotated, req.ConnectionID, record.PeerGUID, "Keys rotated")
	}

	log.Info().Str("connection_id", req.ConnectionID).Int("rotation_count", record.KeyRotationCount).Msg("Connection keys rotated")

	resp := map[string]interface{}{
		"connection_id":      record.ConnectionID,
		"peer_guid":          record.PeerGUID,
		"label":              record.PeerAlias,
		"status":             record.Status,
		"direction":          record.CredentialsType,
		"created_at":         record.CreatedAt.Format(time.RFC3339),
		"last_rotated_at":    record.LastRotatedAt.Format(time.RFC3339),
		"key_rotation_count": record.KeyRotationCount,
		"e2e_public_key":     fmt.Sprintf("%x", localPublic),
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleGetCredentials handles connection.get-credentials messages
// Returns NATS credentials for communicating with a peer
func (h *ConnectionsHandler) HandleGetCredentials(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		ConnectionID string `json:"connection_id"`
	}
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
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

	resp := map[string]interface{}{
		"connection_id":        record.ConnectionID,
		"nats_credentials":     record.Credentials,
		"peer_message_space_id": record.MessageSpaceTopic,
	}
	if record.CredentialsExpireAt != nil {
		resp["expires_at"] = record.CredentialsExpireAt.Format(time.RFC3339)
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleGetCapabilities handles connection.get-capabilities messages
func (h *ConnectionsHandler) HandleGetCapabilities(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req GetCapabilitiesRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
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

	capabilities := record.PeerCapabilities
	if capabilities == nil {
		capabilities = make(map[string]string)
	}

	resp := GetCapabilitiesResponse{
		ConnectionID: req.ConnectionID,
		Capabilities: capabilities,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleActivitySummary handles connection.activity-summary messages
func (h *ConnectionsHandler) HandleActivitySummary(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req ActivitySummaryRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
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

	// Load activity summary from separate storage
	// Activity is stored at connections/{connection_id}/activity
	activityKey := "connections/" + req.ConnectionID + "/activity"
	var summary ActivitySummaryResponse
	summary.ConnectionID = req.ConnectionID

	activityData, err := h.storage.Get(activityKey)
	if err == nil {
		json.Unmarshal(activityData, &summary)
	}

	// Always use the total activity count from the connection record
	summary.TotalMessages = summary.MessagesSent + summary.MessagesReceived

	if record.LastActiveAt != nil {
		summary.LastActivityAt = record.LastActiveAt.Format(time.RFC3339)
	}

	respBytes, _ := json.Marshal(summary)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// UpdateConnectionActivity updates activity tracking for a connection
func (h *ConnectionsHandler) UpdateConnectionActivity(connectionID string, activityType string) error {
	storageKey := "connections/" + connectionID
	data, err := h.storage.Get(storageKey)
	if err != nil {
		return fmt.Errorf("connection not found: %s", connectionID)
	}

	var record ConnectionRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return fmt.Errorf("failed to read connection: %w", err)
	}

	// Update activity tracking
	now := time.Now()
	record.LastActiveAt = &now
	record.ActivityCount++

	// Save updated record
	newData, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal connection: %w", err)
	}

	if err := h.storage.Put(storageKey, newData); err != nil {
		return fmt.Errorf("failed to update connection: %w", err)
	}

	// Update activity summary
	activityKey := "connections/" + connectionID + "/activity"
	var summary ActivitySummaryResponse
	activityData, err := h.storage.Get(activityKey)
	if err == nil {
		json.Unmarshal(activityData, &summary)
	}

	summary.ConnectionID = connectionID
	summary.LastActivityAt = now.Format(time.RFC3339)
	summary.LastActivityType = activityType

	switch activityType {
	case "message_sent":
		summary.MessagesSent++
	case "message_received":
		summary.MessagesReceived++
	case "call":
		summary.TotalCalls++
	}
	summary.TotalMessages = summary.MessagesSent + summary.MessagesReceived

	summaryData, _ := json.Marshal(summary)
	h.storage.Put(activityKey, summaryData)

	return nil
}

// Helper methods

func (h *ConnectionsHandler) addToConnectionIndex(connectionID string) {
	var index []string
	indexData, err := h.storage.Get("connections/_index")
	if err == nil {
		json.Unmarshal(indexData, &index)
	}

	// Check if already in index
	for _, id := range index {
		if id == connectionID {
			return
		}
	}

	index = append(index, connectionID)
	newIndexData, _ := json.Marshal(index)
	h.storage.Put("connections/_index", newIndexData)
}

// HandleAcceptAgentConnection processes an agent connection request (registration completion).
//
// The agent sends a ConnectionRequest ECIES-encrypted with the vault's X25519 public key.
// This handler:
//  1. Finds the invitation by ID from the decrypted request
//  2. Validates the invitation (exists, not expired, status "pending")
//  3. Computes X25519 shared secret from vault private key + agent public key
//  4. Updates the connection record with agent metadata, shared secret, and "active" status
//  5. Publishes an approval response to the invitation-specific topic
//
// The envelope.Payload is ECIES-encrypted with the vault's connection public key
// using DomainAgent domain separation.
func (h *ConnectionsHandler) HandleAcceptAgentConnection(ctx context.Context, msg *IncomingMessage, envelope *AgentEnvelope) (*OutgoingMessage, error) {
	// Extract encrypted bytes from envelope payload
	encryptedPayload, err := extractPayloadBytes(envelope.Payload)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to extract agent connection request payload")
		return nil, nil
	}

	// We need to find the invitation first to get the connection record's private key.
	// The key_id in the envelope isn't set for connection requests (agent doesn't know
	// connection ID yet). Instead we try all pending agent invitations.
	invRecord, connRecord, err := h.findPendingAgentInvitationForECIES(encryptedPayload)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to find matching agent invitation")
		return nil, nil
	}

	// ECIES-decrypt with the connection's local private key using agent domain
	plaintext, err := decryptECIESAgentDomain(connRecord.LocalPrivateKey, encryptedPayload)
	if err != nil {
		log.Warn().Err(err).
			Str("connection_id", connRecord.ConnectionID).
			Msg("Failed to decrypt agent connection request")
		return nil, nil
	}
	defer zeroBytes(plaintext)

	// Parse the connection request
	var connReq struct {
		InvitationID   string    `json:"invitation_id"`
		AgentPublicKey []byte    `json:"agent_public_key"`
		Registration   AgentMetadata `json:"registration"`
		Timestamp      time.Time `json:"timestamp"`
	}
	if err := json.Unmarshal(plaintext, &connReq); err != nil {
		log.Warn().Err(err).Msg("Failed to parse agent connection request")
		return nil, nil
	}

	// Verify invitation ID matches
	if connReq.InvitationID != invRecord.InvitationID {
		log.Warn().
			Str("expected", invRecord.InvitationID).
			Str("got", connReq.InvitationID).
			Msg("Agent connection request invitation ID mismatch")
		return nil, nil
	}

	// Validate invitation
	if invRecord.Status != "pending" {
		log.Warn().Str("status", invRecord.Status).Msg("Agent invitation not pending")
		return nil, nil
	}
	if time.Now().After(invRecord.ExpiresAt) {
		log.Warn().Msg("Agent invitation expired")
		return nil, nil
	}

	// Validate agent public key
	if len(connReq.AgentPublicKey) != 32 {
		log.Warn().Int("len", len(connReq.AgentPublicKey)).Msg("Invalid agent public key length")
		return nil, nil
	}

	// Compute X25519 shared secret
	sharedSecret, err := curve25519.X25519(connRecord.LocalPrivateKey, connReq.AgentPublicKey)
	if err != nil {
		log.Error().Err(err).Msg("Failed to compute shared secret")
		return nil, nil
	}

	// Update connection record
	connRecord.PeerPublicKey = connReq.AgentPublicKey
	connRecord.SharedSecret = sharedSecret
	connRecord.Status = "active"
	connRecord.KeyExchangeAt = time.Now()
	connRecord.AgentMetadata = &connReq.Registration

	// Set default contract (owner can update later)
	if connRecord.Contract == nil {
		connRecord.Contract = &ConnectionContract{
			AgentName:    connRecord.PeerAlias,
			Scope:        []string{}, // Empty = all categories allowed
			ApprovalMode: "always_ask",
			RateLimit:    RateLimit{Max: 60, Per: "hour"},
		}
	}

	// Save updated connection
	connData, err := json.Marshal(connRecord)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal updated connection")
		return nil, nil
	}
	if err := h.storage.Put("connections/"+connRecord.ConnectionID, connData); err != nil {
		log.Error().Err(err).Msg("Failed to store updated connection")
		return nil, nil
	}

	// Update invitation status
	now := time.Now()
	invRecord.Status = "accepted"
	invRecord.RespondedAt = &now
	invData, _ := json.Marshal(invRecord)
	h.storage.Put("invitations/"+invRecord.InvitationID, invData)

	// Log event
	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(ctx, EventTypeAgentConnectionApproved, connRecord.ConnectionID, "",
			fmt.Sprintf("Agent connection accepted: %s", connRecord.PeerAlias))
	}

	log.Info().
		Str("connection_id", connRecord.ConnectionID).
		Str("invitation_id", invRecord.InvitationID).
		Str("agent_type", connReq.Registration.AgentType).
		Msg("Agent connection accepted")

	// Derive connection key to encrypt the approval response
	connKey, err := deriveConnectionKey(sharedSecret)
	if err != nil {
		log.Error().Err(err).Msg("Failed to derive connection key for approval response")
		return nil, nil
	}
	defer zeroBytes(connKey)

	// Build approval payload
	approval := struct {
		ConnectionID string             `json:"connection_id"`
		KeyID        string             `json:"key_id"`
		Contract     *ConnectionContract `json:"contract"`
	}{
		ConnectionID: connRecord.ConnectionID,
		KeyID:        connRecord.ConnectionID,
		Contract:     connRecord.Contract,
	}
	approvalBytes, _ := json.Marshal(approval)

	// Encrypt with connection key
	encryptedApproval, err := encryptXChaCha20(connKey, approvalBytes)
	if err != nil {
		log.Error().Err(err).Msg("Failed to encrypt approval response")
		return nil, nil
	}
	zeroBytes(approvalBytes)

	// Build response envelope
	encPayloadJSON, _ := json.Marshal(encryptedApproval)
	envBytes, err := json.Marshal(AgentEnvelope{
		Type:      AgentMsgConnectionApproved,
		KeyID:     connRecord.ConnectionID,
		Payload:   encPayloadJSON,
		Timestamp: time.Now().UTC(),
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal approval envelope")
		return nil, nil
	}

	// Publish to invitation-specific topic so the agent can receive it
	responseTopic := fmt.Sprintf("MessageSpace.%s.forOwner.agent.invitation.%s", h.ownerSpace, invRecord.InvitationID)
	log.Debug().Str("topic", responseTopic).Msg("Publishing agent connection approval")

	return &OutgoingMessage{
		ID:      generateMessageID(),
		Type:    MessageTypeNATSPublish,
		Subject: responseTopic,
		Payload: envBytes,
	}, nil
}

// findPendingAgentInvitationForECIES finds the pending agent invitation
// that can successfully decrypt the ECIES payload.
// This is needed because the agent doesn't know the connection ID before registration.
func (h *ConnectionsHandler) findPendingAgentInvitationForECIES(encryptedPayload []byte) (*InvitationRecord, *ConnectionRecord, error) {
	// Get invitation index
	var invIndex []string
	indexData, err := h.storage.Get("invitations/_index")
	if err != nil {
		return nil, nil, fmt.Errorf("no invitations found")
	}
	json.Unmarshal(indexData, &invIndex)

	for _, invID := range invIndex {
		invData, err := h.storage.Get("invitations/" + invID)
		if err != nil {
			continue
		}

		var inv InvitationRecord
		if err := json.Unmarshal(invData, &inv); err != nil {
			continue
		}

		// Only check pending, non-expired invitations
		if inv.Status != "pending" || time.Now().After(inv.ExpiresAt) {
			continue
		}

		// Look up the connection for this invitation
		connData, err := h.storage.Get("connections/" + inv.ConnectionID)
		if err != nil {
			continue
		}

		var conn ConnectionRecord
		if err := json.Unmarshal(connData, &conn); err != nil {
			continue
		}

		// Must be an agent connection with a private key
		if !conn.IsAgent() || len(conn.LocalPrivateKey) == 0 {
			continue
		}

		// Try to decrypt — if it works, this is the right invitation
		_, err = decryptECIESAgentDomain(conn.LocalPrivateKey, encryptedPayload)
		if err == nil {
			return &inv, &conn, nil
		}
	}

	return nil, nil, fmt.Errorf("no matching pending agent invitation found")
}

// HandleCreateDeviceInvite handles connection.device.create-invite messages.
// Creates a connection + invitation for a desktop device and returns
// the details the app needs to call POST /vault/agent/shortlink.
// Mirrors HandleCreateAgentInvite but uses ConnectionTypeDevice.
func (h *ConnectionsHandler) HandleCreateDeviceInvite(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req CreateDeviceInviteRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	label := req.Label
	if label == "" {
		label = "Desktop"
	}

	// Generate connection ID
	idBytes := make([]byte, 16)
	rand.Read(idBytes)
	connectionID := fmt.Sprintf("conn-%x", idBytes)

	// Device invitations expire in 24 hours
	expiresAt := time.Now().Add(24 * time.Hour)

	// Generate X25519 key pair for E2E encryption
	localPrivate := make([]byte, 32)
	rand.Read(localPrivate)

	localPublic, err := curve25519.X25519(localPrivate, curve25519.Basepoint)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to derive public key")
	}

	// Generate invite token (32 bytes, base64url-encoded)
	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	inviteToken := base64.RawURLEncoding.EncodeToString(tokenBytes)

	// Store the outbound device connection record
	record := ConnectionRecord{
		ConnectionID:      connectionID,
		ConnectionType:    ConnectionTypeDevice,
		PeerAlias:         label,
		CredentialsType:   "outbound",
		MessageSpaceTopic: fmt.Sprintf("MessageSpace.%s.forOwner.>", h.ownerSpace),
		Status:            "invited",
		CreatedAt:         time.Now(),
		ExpiresAt:         expiresAt,
		LocalPublicKey:    localPublic,
		LocalPrivateKey:   localPrivate,
	}

	data, err := json.Marshal(record)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to marshal connection")
	}

	storageKey := "connections/" + connectionID
	if err := h.storage.Put(storageKey, data); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to store connection")
	}

	h.addToConnectionIndex(connectionID)

	// Create invitation record (reuses agent invitation infrastructure)
	invitationID, err := h.createDeviceInvitation(connectionID, label, inviteToken, expiresAt)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to create invitation")
	}

	// Log event
	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(context.Background(), EventTypeDeviceConnectionRequest, connectionID, "", "Device invitation created")
	}

	log.Info().
		Str("connection_id", connectionID).
		Str("invitation_id", invitationID).
		Msg("Device invitation created")

	resp := CreateDeviceInviteResponse{
		ConnectionID:   connectionID,
		InvitationID:   invitationID,
		InviteToken:    inviteToken,
		OwnerGUID:      h.ownerSpace,
		VaultPublicKey: fmt.Sprintf("%x", localPublic),
		ExpiresAt:      expiresAt.Format(time.RFC3339),
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// createDeviceInvitation creates an invitation record for a device connection.
func (h *ConnectionsHandler) createDeviceInvitation(connectionID, label, inviteToken string, expiresAt time.Time) (string, error) {
	idBytes := make([]byte, 16)
	rand.Read(idBytes)
	invitationID := fmt.Sprintf("inv-%x", idBytes)

	record := InvitationRecord{
		InvitationID:   invitationID,
		ConnectionID:   connectionID,
		Status:         "pending",
		DeliveryMethod: "shortlink",
		Label:          label,
		InviteToken:    inviteToken,
		CreatedAt:      time.Now(),
		ExpiresAt:      expiresAt,
	}

	data, err := json.Marshal(record)
	if err != nil {
		return "", fmt.Errorf("failed to marshal invitation: %w", err)
	}

	if err := h.storage.Put("invitations/"+invitationID, data); err != nil {
		return "", fmt.Errorf("failed to store invitation: %w", err)
	}

	// Add to invitation index
	var index []string
	indexData, err := h.storage.Get("invitations/_index")
	if err == nil {
		json.Unmarshal(indexData, &index)
	}

	for _, id := range index {
		if id == invitationID {
			return invitationID, nil
		}
	}

	index = append(index, invitationID)
	newIndexData, _ := json.Marshal(index)
	h.storage.Put("invitations/_index", newIndexData)

	log.Info().
		Str("invitation_id", invitationID).
		Str("connection_id", connectionID).
		Msg("Device invitation record created")

	return invitationID, nil
}

// HandleAcceptDeviceConnection processes a device connection request (registration completion).
//
// The desktop sends a ConnectionRequest ECIES-encrypted with the vault's X25519 public key.
// Uses DomainDevice domain separation ("vettid-device-v1") distinct from agent's DomainAgent.
// On acceptance, creates an initial DeviceSession with configured TTL.
func (h *ConnectionsHandler) HandleAcceptDeviceConnection(ctx context.Context, msg *IncomingMessage, envelope *AgentEnvelope) (*OutgoingMessage, error) {
	// Extract encrypted bytes from envelope payload
	encryptedPayload, err := extractPayloadBytes(envelope.Payload)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to extract device connection request payload")
		return nil, nil
	}

	// Find matching pending device invitation via ECIES decryption trial
	invRecord, connRecord, err := h.findPendingDeviceInvitationForECIES(encryptedPayload)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to find matching device invitation")
		return nil, nil
	}

	// ECIES-decrypt with the connection's local private key using device domain
	plaintext, err := decryptECIESDeviceDomain(connRecord.LocalPrivateKey, encryptedPayload)
	if err != nil {
		log.Warn().Err(err).
			Str("connection_id", connRecord.ConnectionID).
			Msg("Failed to decrypt device connection request")
		return nil, nil
	}
	defer zeroBytes(plaintext)

	// Parse the connection request
	var connReq struct {
		InvitationID    string         `json:"invitation_id"`
		DevicePublicKey []byte         `json:"device_public_key"`
		Registration    DeviceMetadata `json:"registration"`
		Timestamp       time.Time      `json:"timestamp"`
	}
	if err := json.Unmarshal(plaintext, &connReq); err != nil {
		log.Warn().Err(err).Msg("Failed to parse device connection request")
		return nil, nil
	}

	// Verify invitation ID matches
	if connReq.InvitationID != invRecord.InvitationID {
		log.Warn().
			Str("expected", invRecord.InvitationID).
			Str("got", connReq.InvitationID).
			Msg("Device connection request invitation ID mismatch")
		return nil, nil
	}

	// Validate invitation
	if invRecord.Status != "pending" {
		log.Warn().Str("status", invRecord.Status).Msg("Device invitation not pending")
		return nil, nil
	}
	if time.Now().After(invRecord.ExpiresAt) {
		log.Warn().Msg("Device invitation expired")
		return nil, nil
	}

	// Validate device public key
	if len(connReq.DevicePublicKey) != 32 {
		log.Warn().Int("len", len(connReq.DevicePublicKey)).Msg("Invalid device public key length")
		return nil, nil
	}

	// Compute X25519 shared secret
	sharedSecret, err := curve25519.X25519(connRecord.LocalPrivateKey, connReq.DevicePublicKey)
	if err != nil {
		log.Error().Err(err).Msg("Failed to compute shared secret")
		return nil, nil
	}

	// Create initial device session
	sessionIDBytes := make([]byte, 16)
	rand.Read(sessionIDBytes)
	now := time.Now()
	ttlHours := 8
	session := &DeviceSession{
		SessionID:          fmt.Sprintf("sess-%x", sessionIDBytes),
		Status:             "active",
		CreatedAt:          now.Unix(),
		ExpiresAt:          now.Add(time.Duration(ttlHours) * time.Hour).Unix(),
		LastActiveAt:       now.Unix(),
		LastPhoneHeartbeat: now.Unix(),
		ExtendedCount:      0,
		MaxExtensions:      3,
		TTLHours:           ttlHours,
		Capabilities:       DeviceIndependentCapabilities(),
		RequiresPhone:      DevicePhoneRequiredCapabilities(),
	}

	// Update connection record
	connRecord.PeerPublicKey = connReq.DevicePublicKey
	connRecord.SharedSecret = sharedSecret
	connRecord.Status = "active"
	connRecord.KeyExchangeAt = time.Now()
	connRecord.DeviceMetadata = &connReq.Registration
	connRecord.DeviceSession = session

	// Save updated connection
	connData, err := json.Marshal(connRecord)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal updated device connection")
		return nil, nil
	}
	if err := h.storage.Put("connections/"+connRecord.ConnectionID, connData); err != nil {
		log.Error().Err(err).Msg("Failed to store updated device connection")
		return nil, nil
	}

	// Update invitation status
	invNow := time.Now()
	invRecord.Status = "accepted"
	invRecord.RespondedAt = &invNow
	invData, _ := json.Marshal(invRecord)
	h.storage.Put("invitations/"+invRecord.InvitationID, invData)

	// Log event
	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(ctx, EventTypeDeviceConnectionApproved, connRecord.ConnectionID, "",
			fmt.Sprintf("Device connection accepted: %s (%s)", connRecord.PeerAlias, connReq.Registration.Hostname))
	}

	log.Info().
		Str("connection_id", connRecord.ConnectionID).
		Str("invitation_id", invRecord.InvitationID).
		Str("hostname", connReq.Registration.Hostname).
		Str("session_id", session.SessionID).
		Msg("Device connection accepted")

	// Derive connection key to encrypt the approval response
	connKey, err := deriveConnectionKey(sharedSecret)
	if err != nil {
		log.Error().Err(err).Msg("Failed to derive connection key for device approval response")
		return nil, nil
	}
	defer zeroBytes(connKey)

	// Build approval payload
	approval := struct {
		ConnectionID string         `json:"connection_id"`
		KeyID        string         `json:"key_id"`
		Session      *DeviceSession `json:"session"`
	}{
		ConnectionID: connRecord.ConnectionID,
		KeyID:        connRecord.ConnectionID,
		Session:      session,
	}
	approvalBytes, _ := json.Marshal(approval)

	// Encrypt with connection key
	encryptedApproval, err := encryptXChaCha20(connKey, approvalBytes)
	if err != nil {
		log.Error().Err(err).Msg("Failed to encrypt device approval response")
		return nil, nil
	}
	zeroBytes(approvalBytes)

	// Build response envelope
	encPayloadJSON, _ := json.Marshal(encryptedApproval)
	envBytes, err := json.Marshal(AgentEnvelope{
		Type:      DeviceMsgConnectionApproved,
		KeyID:     connRecord.ConnectionID,
		Payload:   encPayloadJSON,
		Timestamp: time.Now().UTC(),
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal device approval envelope")
		return nil, nil
	}

	// Publish to invitation-specific topic so the desktop can receive it
	responseTopic := fmt.Sprintf("MessageSpace.%s.forOwner.device.invitation.%s", h.ownerSpace, invRecord.InvitationID)
	log.Debug().Str("topic", responseTopic).Msg("Publishing device connection approval")

	return &OutgoingMessage{
		ID:      generateMessageID(),
		Type:    MessageTypeNATSPublish,
		Subject: responseTopic,
		Payload: envBytes,
	}, nil
}

// findPendingDeviceInvitationForECIES finds the pending device invitation
// that can successfully decrypt the ECIES payload using device domain separation.
func (h *ConnectionsHandler) findPendingDeviceInvitationForECIES(encryptedPayload []byte) (*InvitationRecord, *ConnectionRecord, error) {
	var invIndex []string
	indexData, err := h.storage.Get("invitations/_index")
	if err != nil {
		return nil, nil, fmt.Errorf("no invitations found")
	}
	json.Unmarshal(indexData, &invIndex)

	for _, invID := range invIndex {
		invData, err := h.storage.Get("invitations/" + invID)
		if err != nil {
			continue
		}

		var inv InvitationRecord
		if err := json.Unmarshal(invData, &inv); err != nil {
			continue
		}

		if inv.Status != "pending" || time.Now().After(inv.ExpiresAt) {
			continue
		}

		connData, err := h.storage.Get("connections/" + inv.ConnectionID)
		if err != nil {
			continue
		}

		var conn ConnectionRecord
		if err := json.Unmarshal(connData, &conn); err != nil {
			continue
		}

		// Must be a device connection with a private key
		if !conn.IsDevice() || len(conn.LocalPrivateKey) == 0 {
			continue
		}

		// Try to decrypt — if it works, this is the right invitation
		_, err = decryptECIESDeviceDomain(conn.LocalPrivateKey, encryptedPayload)
		if err == nil {
			return &inv, &conn, nil
		}
	}

	return nil, nil, fmt.Errorf("no matching pending device invitation found")
}

// HandleListDeviceConnections returns all device connections with session status.
func (h *ConnectionsHandler) HandleListDeviceConnections(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	indexData, err := h.storage.Get("connections/_index")
	var connectionIDs []string
	if err == nil {
		json.Unmarshal(indexData, &connectionIDs)
	}

	type DeviceInfo struct {
		ConnectionID string `json:"connection_id"`
		DeviceName   string `json:"device_name"`
		Hostname     string `json:"hostname,omitempty"`
		Platform     string `json:"platform,omitempty"`
		Status       string `json:"status"`
		SessionID    string `json:"session_id,omitempty"`
		SessionStatus string `json:"session_status,omitempty"`
		SessionExpires int64 `json:"session_expires,omitempty"`
		ConnectedAt  string `json:"connected_at"`
		LastActiveAt string `json:"last_active_at,omitempty"`
	}

	devices := make([]DeviceInfo, 0)
	for _, connID := range connectionIDs {
		data, err := h.storage.Get("connections/" + connID)
		if err != nil {
			continue
		}

		var record ConnectionRecord
		if json.Unmarshal(data, &record) != nil {
			continue
		}

		if !record.IsDevice() {
			continue
		}

		info := DeviceInfo{
			ConnectionID: record.ConnectionID,
			DeviceName:   record.PeerAlias,
			Status:       record.Status,
			ConnectedAt:  record.CreatedAt.Format(time.RFC3339),
		}

		if record.DeviceMetadata != nil {
			info.Hostname = record.DeviceMetadata.Hostname
			info.Platform = record.DeviceMetadata.Platform
		}

		if record.DeviceSession != nil {
			info.SessionID = record.DeviceSession.SessionID
			info.SessionStatus = record.DeviceSession.Status
			info.SessionExpires = record.DeviceSession.ExpiresAt
		}

		if record.LastActiveAt != nil {
			info.LastActiveAt = record.LastActiveAt.Format(time.RFC3339)
		}

		devices = append(devices, info)
	}

	resp := struct {
		Devices []DeviceInfo `json:"devices"`
		Count   int          `json:"count"`
	}{
		Devices: devices,
		Count:   len(devices),
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleRevokeDevice revokes a device connection and its session.
func (h *ConnectionsHandler) HandleRevokeDevice(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		ConnectionID string `json:"connection_id"`
	}
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
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

	// Revoke connection
	record.Status = "revoked"

	// Revoke session and zero sensitive material
	if record.DeviceSession != nil {
		record.DeviceSession.Status = "revoked"
	}
	zeroBytes(record.SharedSecret)
	record.SharedSecret = nil

	connData, _ := json.Marshal(record)
	h.storage.Put("connections/"+record.ConnectionID, connData)

	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(ctx, EventTypeDeviceConnectionRevoked, record.ConnectionID, "",
			fmt.Sprintf("Device connection revoked: %s", record.PeerAlias))
	}

	log.Info().
		Str("connection_id", record.ConnectionID).
		Msg("Device connection revoked")

	resp := struct {
		Success      bool   `json:"success"`
		ConnectionID string `json:"connection_id"`
	}{
		Success:      true,
		ConnectionID: record.ConnectionID,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleExtendDeviceSession extends an active device session (phone-initiated only).
func (h *ConnectionsHandler) HandleExtendDeviceSession(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		ConnectionID string `json:"connection_id"`
	}
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	data, err := h.storage.Get("connections/" + req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}

	var record ConnectionRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to read connection")
	}

	if !record.IsDevice() || record.DeviceSession == nil {
		return h.errorResponse(msg.GetID(), "No active device session")
	}

	session := record.DeviceSession
	if session.Status != "active" {
		return h.errorResponse(msg.GetID(), fmt.Sprintf("Session is %s, cannot extend", session.Status))
	}
	if session.ExtendedCount >= session.MaxExtensions {
		return h.errorResponse(msg.GetID(), "Maximum session extensions reached")
	}

	// Extend the session
	now := time.Now()
	session.ExpiresAt = now.Add(time.Duration(session.TTLHours) * time.Hour).Unix()
	session.ExtendedCount++
	session.LastActiveAt = now.Unix()

	connData, _ := json.Marshal(record)
	h.storage.Put("connections/"+record.ConnectionID, connData)

	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(ctx, EventTypeDeviceSessionExtended, record.ConnectionID, "",
			fmt.Sprintf("Device session extended (%d/%d)", session.ExtendedCount, session.MaxExtensions))
	}

	log.Info().
		Str("connection_id", record.ConnectionID).
		Str("session_id", session.SessionID).
		Int("extended_count", session.ExtendedCount).
		Msg("Device session extended")

	resp := struct {
		Success   bool           `json:"success"`
		Session   *DeviceSession `json:"session"`
	}{
		Success: true,
		Session: session,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleDeviceHeartbeat updates the phone heartbeat timestamp on active device sessions.
func (h *ConnectionsHandler) HandleDeviceHeartbeat(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	// Update heartbeat on all active device sessions
	indexData, err := h.storage.Get("connections/_index")
	var connectionIDs []string
	if err == nil {
		json.Unmarshal(indexData, &connectionIDs)
	}

	now := time.Now().Unix()
	updated := 0
	for _, connID := range connectionIDs {
		data, err := h.storage.Get("connections/" + connID)
		if err != nil {
			continue
		}

		var record ConnectionRecord
		if json.Unmarshal(data, &record) != nil {
			continue
		}

		if !record.IsDevice() || record.DeviceSession == nil || record.DeviceSession.Status != "active" {
			continue
		}

		// Check if session was suspended and resume it
		record.DeviceSession.LastPhoneHeartbeat = now
		if record.DeviceSession.Status == "suspended" {
			record.DeviceSession.Status = "active"
			if h.eventHandler != nil {
				h.eventHandler.LogConnectionEvent(ctx, EventTypeDeviceSessionCreated, record.ConnectionID, "",
					"Device session resumed after heartbeat")
			}
		}

		connData, _ := json.Marshal(record)
		h.storage.Put("connections/"+record.ConnectionID, connData)
		updated++
	}

	resp := struct {
		Success bool `json:"success"`
		Updated int  `json:"updated"`
	}{
		Success: true,
		Updated: updated,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleListAgentConnections returns all agent connections with metadata.
func (h *ConnectionsHandler) HandleListAgentConnections(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	indexData, err := h.storage.Get("connections/_index")
	var connectionIDs []string
	if err == nil {
		json.Unmarshal(indexData, &connectionIDs)
	}

	type AgentInfo struct {
		ConnectionID string             `json:"connection_id"`
		AgentName    string             `json:"agent_name"`
		AgentType    string             `json:"agent_type"`
		Status       string             `json:"status"`
		ApprovalMode string             `json:"approval_mode"`
		Scope        []string           `json:"scope"`
		ConnectedAt  string             `json:"connected_at"`
		LastActiveAt string             `json:"last_active_at,omitempty"`
		Hostname     string             `json:"hostname,omitempty"`
		Platform     string             `json:"platform,omitempty"`
	}

	agents := make([]AgentInfo, 0)
	for _, connID := range connectionIDs {
		data, err := h.storage.Get("connections/" + connID)
		if err != nil {
			continue
		}

		var record ConnectionRecord
		if json.Unmarshal(data, &record) != nil {
			continue
		}

		if !record.IsAgent() {
			continue
		}

		info := AgentInfo{
			ConnectionID: record.ConnectionID,
			AgentName:    record.PeerAlias,
			Status:       record.Status,
			ConnectedAt:  record.CreatedAt.UTC().Format(time.RFC3339),
		}

		if record.Contract != nil {
			info.ApprovalMode = record.Contract.ApprovalMode
			info.Scope = record.Contract.Scope
		}

		if record.AgentMetadata != nil {
			info.AgentType = record.AgentMetadata.AgentType
			info.Hostname = record.AgentMetadata.Hostname
			info.Platform = record.AgentMetadata.Platform
		}

		if record.LastActiveAt != nil {
			info.LastActiveAt = record.LastActiveAt.UTC().Format(time.RFC3339)
		}

		agents = append(agents, info)
	}

	resp := map[string]interface{}{
		"success": true,
		"agents":  agents,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleRevokeAgent revokes an agent connection and clears its shared secret.
func (h *ConnectionsHandler) HandleRevokeAgent(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		ConnectionID string `json:"connection_id"`
	}
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	storageKey := "connections/" + req.ConnectionID
	data, err := h.storage.Get(storageKey)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}

	var record ConnectionRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to read connection")
	}

	if !record.IsAgent() {
		return h.errorResponse(msg.GetID(), "Not an agent connection")
	}

	// SECURITY: Zero shared secret before saving
	zeroBytes(record.SharedSecret)
	record.SharedSecret = nil
	record.Status = "revoked"

	newData, _ := json.Marshal(record)
	if err := h.storage.Put(storageKey, newData); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to revoke agent")
	}

	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(ctx, EventTypeConnectionRevoked, req.ConnectionID, "",
			fmt.Sprintf("Agent connection revoked: %s", record.PeerAlias))
	}

	log.Info().Str("connection_id", req.ConnectionID).Str("agent", record.PeerAlias).Msg("Agent connection revoked")

	resp := map[string]interface{}{
		"success":       true,
		"connection_id": req.ConnectionID,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleUpdateAgentContract updates an agent connection's contract (scope, approval mode, rate limit).
func (h *ConnectionsHandler) HandleUpdateAgentContract(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		ConnectionID string    `json:"connection_id"`
		Scope        []string  `json:"scope,omitempty"`
		ApprovalMode string    `json:"approval_mode,omitempty"`
		RateLimit    *RateLimit `json:"rate_limit,omitempty"`
	}
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	storageKey := "connections/" + req.ConnectionID
	data, err := h.storage.Get(storageKey)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}

	var record ConnectionRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to read connection")
	}

	if !record.IsAgent() {
		return h.errorResponse(msg.GetID(), "Not an agent connection")
	}

	if record.Contract == nil {
		record.Contract = &ConnectionContract{
			AgentName:    record.PeerAlias,
			ApprovalMode: "always_ask",
			RateLimit:    RateLimit{Max: 60, Per: "hour"},
		}
	}

	// Apply updates
	if req.Scope != nil {
		record.Contract.Scope = req.Scope
	}
	if req.ApprovalMode != "" {
		// Validate approval mode
		switch req.ApprovalMode {
		case "always_ask", "auto_within_contract", "auto_all":
			record.Contract.ApprovalMode = req.ApprovalMode
		default:
			return h.errorResponse(msg.GetID(), "Invalid approval_mode")
		}
	}
	if req.RateLimit != nil {
		record.Contract.RateLimit = *req.RateLimit
	}

	newData, _ := json.Marshal(record)
	if err := h.storage.Put(storageKey, newData); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to update contract")
	}

	log.Info().
		Str("connection_id", req.ConnectionID).
		Str("approval_mode", record.Contract.ApprovalMode).
		Msg("Agent contract updated")

	resp := map[string]interface{}{
		"success":       true,
		"connection_id": req.ConnectionID,
		"contract":      record.Contract,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

func (h *ConnectionsHandler) errorResponse(id string, message string) (*OutgoingMessage, error) {
	resp := map[string]interface{}{
		"success": false,
		"error":   message,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: id,
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}
