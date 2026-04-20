package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
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
	natsProxy    *NATSProxy
	sealerProxy  *SealerProxy
	publisher    *VsockPublisher
	vaultState   *VaultState
}

// NewConnectionsHandler creates a new connections handler
func NewConnectionsHandler(ownerSpace string, storage *EncryptedStorage, eventHandler *EventHandler, natsProxy *NATSProxy, publisher *VsockPublisher, vaultState *VaultState) *ConnectionsHandler {
	return &ConnectionsHandler{
		ownerSpace:   ownerSpace,
		storage:      storage,
		eventHandler: eventHandler,
		natsProxy:    natsProxy,
		publisher:    publisher,
		vaultState:   vaultState,
	}
}

// SetSealerProxy sets the sealer proxy for account seed loading
func (h *ConnectionsHandler) SetSealerProxy(sp *SealerProxy) {
	h.sealerProxy = sp
}

// CapabilitiesOrDefault returns the connection's capabilities, falling
// back to peer defaults for pre-feature records that have no stored
// capability block. The system connection always returns its read-only
// set regardless of what's persisted.
func (c *ConnectionRecord) CapabilitiesOrDefault() ConnectionCapabilities {
	if c.ConnectionType == ConnectionTypeSystem {
		return SystemCapabilities()
	}
	if c.Capabilities != nil {
		return *c.Capabilities
	}
	return DefaultPeerCapabilities()
}

// EnsureSystemConnection creates the per-vault VettID system connection
// on first call and is a noop afterwards. Idempotent — safe to run on
// every vault init. The system connection is read-only: it has no
// peer_guid, no keys, no message-space topic, and
// CapabilitiesOrDefault() reports read-only messaging only.
func (h *ConnectionsHandler) EnsureSystemConnection(ctx context.Context) error {
	key := "connections/" + SystemConnectionID
	if data, err := h.storage.Get(key); err == nil && len(data) > 0 {
		return nil // already provisioned
	}

	caps := SystemCapabilities()
	record := ConnectionRecord{
		ConnectionID:   SystemConnectionID,
		ConnectionType: ConnectionTypeSystem,
		PeerAlias:      "VettID",
		Status:         "active",
		CreatedAt:      time.Now(),
		Capabilities:   &caps,
	}
	data, err := json.Marshal(&record)
	if err != nil {
		return fmt.Errorf("marshal system connection: %w", err)
	}
	if err := h.storage.Put(key, data); err != nil {
		return fmt.Errorf("store system connection: %w", err)
	}
	h.addToConnectionIndex(SystemConnectionID)
	log.Info().Str("owner_space", h.ownerSpace).Msg("VettID system connection provisioned")
	return nil
}

// --- Storage types ---

// Connection type constants
const (
	ConnectionTypePeer   = "peer"   // Human-to-human connection (default)
	ConnectionTypeAgent  = "agent"  // AI agent connection via Agent Connector
	ConnectionTypeDevice = "device" // Desktop device connection via session
	ConnectionTypeSystem = "system" // VettID service itself (single per vault, capped capabilities)
)

// SystemConnectionID is the reserved connection_id for the per-vault
// VettID system connection. All service-originated events (guides,
// migration prompts, vote notifications, security alerts) append to
// its audit trail.
const SystemConnectionID = "system/vettid"

// ConnectionCapabilities declares which user-visible features a
// connection supports. Peer connections default to all true; agents
// get a configured subset; the VettID system connection is read-only.
type ConnectionCapabilities struct {
	MessagingRead  bool `json:"messaging_read"`
	MessagingWrite bool `json:"messaging_write"`
	VoiceCall      bool `json:"voice_call"`
	VideoCall      bool `json:"video_call"`
	BTCTransfer    bool `json:"btc_transfer"`
}

// DefaultPeerCapabilities returns the capability set a freshly-created
// peer connection starts with — everything on.
func DefaultPeerCapabilities() ConnectionCapabilities {
	return ConnectionCapabilities{
		MessagingRead:  true,
		MessagingWrite: true,
		VoiceCall:      true,
		VideoCall:      true,
		BTCTransfer:    true,
	}
}

// SystemCapabilities returns the read-only capability set for the
// VettID system connection.
func SystemCapabilities() ConnectionCapabilities {
	return ConnectionCapabilities{MessagingRead: true}
}

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
	// Peer routing (for sending notifications back)
	PeerOwnerSpace   string `json:"peer_owner_space,omitempty"`
	PeerMessageSpace string `json:"peer_message_space,omitempty"`

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

	// Capabilities declares which user-visible features this connection
	// supports from the owner's side. Zero value (all false) means the
	// record predates this field and should be treated as a standard
	// peer with every capability available — see
	// ConnectionRecord.CapabilitiesOrDefault().
	Capabilities *ConnectionCapabilities `json:"capabilities,omitempty"`

	// Agent-specific fields (only set when ConnectionType == "agent")
	AgentMetadata *AgentMetadata      `json:"agent_metadata,omitempty"`
	Contract      *ConnectionContract `json:"contract,omitempty"`

	// Device-specific fields (only set when ConnectionType == "device")
	DeviceMetadata    *DeviceMetadata    `json:"device_metadata,omitempty"`
	DeviceSession     *DeviceSession     `json:"device_session,omitempty"`
	DevicePendingAuth *DevicePendingAuth `json:"device_pending_auth,omitempty"`
}

// DeviceMetadata holds registration details for a desktop device connection.
// Collected by the desktop client during stage-2 pairing and shown to the
// user before they approve. See vettid-dev/docs/DESKTOP-CONNECTION-FLOW.md.
type DeviceMetadata struct {
	DeviceName         string `json:"device_name,omitempty"`         // User-assigned label, set at authorize time
	Hostname           string `json:"hostname,omitempty"`
	Platform           string `json:"platform,omitempty"`            // linux-x86_64, darwin-arm64, windows-x86_64, ...
	OSName             string `json:"os_name,omitempty"`             // Fedora, macOS, Windows, ...
	OSVersion          string `json:"os_version,omitempty"`          // 43, 14.4, 11, ...
	AppVersion         string `json:"app_version,omitempty"`
	BinaryFingerprint  string `json:"binary_fingerprint,omitempty"`  // SHA-256 of desktop binary (full)
	MachineFingerprint string `json:"machine_fingerprint,omitempty"` // HMAC-SHA256 over stable machine attrs
	ClientIP           string `json:"client_ip,omitempty"`           // IP observed by vault at pairing time
	FirstSeenAt        int64  `json:"first_seen_at,omitempty"`       // unix seconds
}

// DevicePendingAuth tracks a stage-2 pairing request awaiting user approval.
// Created when the desktop publishes device.request-session and cleared when
// the app publishes device.authorize-session. See DESKTOP-CONNECTION-FLOW.md.
type DevicePendingAuth struct {
	ApprovalToken  string `json:"approval_token"`   // hex, 32 bytes — set by desktop, verified by app via QR
	DevicePubKey   []byte `json:"device_pubkey"`    // desktop's stage-2 ephemeral X25519 pubkey (32 bytes)
	RequestedAt    int64  `json:"requested_at"`     // unix seconds
	ExpiresAt      int64  `json:"expires_at"`       // unix seconds — stage-2 window (e.g. 10 min)
}

// DeviceSession tracks the time-limited session for an authorized device.
// The session_key is never stored — it's derived fresh from the (vault ephemeral,
// device ephemeral) X25519 shared secret, with both sides doing HKDF over
// "vettid-device-session-v1" + session_id. On expiry, both sides wipe the key.
type DeviceSession struct {
	SessionID        string `json:"session_id"`          // uuid
	Status           string `json:"status"`              // "active" | "expired" | "revoked"
	CreatedAt        int64  `json:"created_at"`          // unix seconds
	ExpiresAt        int64  `json:"expires_at"`          // unix seconds — authored duration from CreatedAt
	LastActiveAt     int64  `json:"last_active_at"`      // unix seconds
	DurationSeconds  int64  `json:"duration_seconds"`    // user-approved duration (≤ 24h)
	KeyRotationCount int    `json:"key_rotation_count"`  // incremented on each extend
	SessionKeyID     string `json:"session_key_id"`      // opaque handle so the vault can match the device's current key
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

// CreateInviteRequest is the payload for connection.create-invite.
// Supports all connection types: peer, agent, and device.
type CreateInviteRequest struct {
	ConnectionID     string `json:"connection_id,omitempty"`
	PeerGUID         string `json:"peer_guid,omitempty"`
	Label            string `json:"label"`
	ConnectionType   string `json:"connection_type,omitempty"` // "peer" (default), "agent", or "device"
	ExpiresInHours   int    `json:"expires_in_hours"`
	ExpiresInMinutes int    `json:"expires_in_minutes"`
}

// CreateInviteResponse is the response for connection.create-invite
type CreateInviteResponse struct {
	ConnectionID      string            `json:"connection_id"`
	OwnerSpace        string            `json:"owner_space"`
	Credentials       string            `json:"credentials,omitempty"`
	InviteCode        string            `json:"invite_code,omitempty"`
	MessageSpaceTopic string            `json:"message_space_topic"`
	ExpiresAt         string            `json:"expires_at"`
	E2EPublicKey      string            `json:"e2e_public_key"`
	Label             string            `json:"label"`
	InviterProfile    map[string]string `json:"inviter_profile,omitempty"`
}

// StoreCredentialsRequest is the payload for connection.store-credentials.
// Used by all connection types: peer, agent, and device.
type StoreCredentialsRequest struct {
	ConnectionID       string                 `json:"connection_id"`
	PeerAlias          string                 `json:"peer_alias"`
	Label              string                 `json:"label"`
	PeerGUID           string                 `json:"peer_guid"`
	Credentials        string                 `json:"credentials"`
	NATSCredentials    string                 `json:"nats_credentials"`
	MessageSpaceTopic  string                 `json:"message_space_topic"`
	PeerMessageSpaceID string                 `json:"peer_message_space_id"`
	PeerOwnerSpaceID   string                 `json:"peer_owner_space_id"`
	PeerE2EPublicKey   string                 `json:"peer_e2e_public_key"`
	E2EPublicKey       string                 `json:"e2e_public_key"`          // Hex-encoded X25519 public key (used by agent/device)
	ConnectionType     string                 `json:"connection_type,omitempty"` // "peer" (default), "agent", or "device"
	PeerProfile        map[string]interface{} `json:"peer_profile,omitempty"`
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

	// Cached peer profile (loaded from vault storage)
	PeerProfile json.RawMessage `json:"peer_profile,omitempty"`

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

	// Message preview (for connection card display)
	LastMessagePreview string `json:"last_message_preview,omitempty"`
	LastMessageAt      string `json:"last_message_at,omitempty"`
	UnreadCount        int    `json:"unread_count"`

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

// CreateDeviceInviteRequest is the payload for device.create-invite.
// The user invokes this from the app when they want to pair a new desktop.
type CreateDeviceInviteRequest struct {
	Label string `json:"label,omitempty"` // Optional placeholder; final name is set at authorize time
}

// CreateDeviceInviteResponse returns the short code the user types into the
// desktop client. See vettid-dev/docs/DESKTOP-CONNECTION-FLOW.md §Stage 1.
type CreateDeviceInviteResponse struct {
	ConnectionID string `json:"connection_id"`
	InviteCode   string `json:"invite_code"`   // 8-char ambiguity-safe code
	NATSEndpoint string `json:"nats_endpoint"` // so the app can show it to the user if needed
	ExpiresAt    string `json:"expires_at"`    // ISO 8601 — 2 min from now
}

// --- Handler methods ---

// HandleCreateInvite handles connection.create-invite messages
func (h *ConnectionsHandler) HandleCreateInvite(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req CreateInviteRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleCreateInvite"); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	// Generate connection_id if not provided
	connectionID := req.ConnectionID
	if connectionID == "" {
		idBytes := make([]byte, 16)
		rand.Read(idBytes)
		connectionID = fmt.Sprintf("conn-%x", idBytes)
	}

	// Support expires_in_minutes (preferred) or expires_in_hours (legacy)
	var expiresAt time.Time
	if req.ExpiresInMinutes > 0 {
		expiresAt = time.Now().Add(time.Duration(req.ExpiresInMinutes) * time.Minute)
	} else if req.ExpiresInHours > 0 {
		expiresAt = time.Now().Add(time.Duration(req.ExpiresInHours) * time.Hour)
	} else {
		expiresAt = time.Now().Add(24 * 30 * time.Hour) // Default 30 days
	}

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
		ConnectionType:    req.ConnectionType, // "peer", "agent", or "device" (empty defaults to peer)
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

	// Generate scoped NATS credentials for the invitation
	// These allow the peer to connect and read this vault's published profile
	invitationCreds := ""
	if h.natsProxy != nil {
		creds, err := h.generateInvitationCredentials(expiresAt)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to generate invitation NATS credentials (non-fatal)")
		} else {
			invitationCreds = creds
		}
	}

	// Load inviter's profile for the response
	inviterProfile := h.loadInviterProfile()

	// Always use profile name when available, overriding generic/GUID-based labels
	if firstName, ok := inviterProfile["_system_first_name"]; ok && firstName != "" {
		profileLabel := firstName
		if lastName, ok := inviterProfile["_system_last_name"]; ok && lastName != "" {
			profileLabel += " " + lastName
		}
		profileLabel = strings.TrimSpace(profileLabel)
		if profileLabel != "" {
			req.Label = profileLabel
		}
	}

	// Publish invitation to NATS broker stream so QR code only needs a short code.
	// The scanner fetches the full invitation data from the stream using guest credentials.
	inviteCode := ""
	if h.publisher != nil && invitationCreds != "" {
		inviteCode = generateInviteCode()

		// Extract JWT and seed from .creds format for compact storage
		jwt, seed := extractCredsComponents(invitationCreds)

		// Include inviter's published profile so scanner sees it immediately
		inviterProfile := h.loadPublishedProfileForPeer()

		brokerPayload := map[string]interface{}{
			"type":            "vettid_connection",
			"connection_id":   connectionID,
			"jwt":             jwt,
			"seed":            seed,
			"owner_space":     h.ownerSpace,
			"message_space":   record.MessageSpaceTopic,
			"expires_at":      expiresAt.Format(time.RFC3339),
			"label":           req.Label,
			"inviter_profile": inviterProfile,
		}
		payloadBytes, _ := json.Marshal(brokerPayload)

		subject := fmt.Sprintf("invite.%s", inviteCode)
		if err := h.publisher.PublishRaw(subject, payloadBytes); err != nil {
			log.Warn().Err(err).Str("subject", subject).Msg("Failed to publish invitation to broker (falling back to inline creds)")
			inviteCode = "" // Fall back to inline credentials
		} else {
			log.Info().Str("invite_code", inviteCode).Str("connection_id", connectionID).Msg("Invitation published to broker stream")
		}
	}

	resp := CreateInviteResponse{
		ConnectionID:      connectionID,
		OwnerSpace:        h.ownerSpace,
		Credentials:       invitationCreds,
		InviteCode:        inviteCode,
		MessageSpaceTopic: record.MessageSpaceTopic,
		ExpiresAt:         expiresAt.Format(time.RFC3339),
		E2EPublicKey:      fmt.Sprintf("%x", localPublic),
		Label:             req.Label,
		InviterProfile:    inviterProfile,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleResolveInvite handles connection.resolve-invite messages.
// Fetches invitation data from the NATS INVITATIONS stream via the parent process.
// The app sends the invite code from a scanned QR; the vault resolves it.
func (h *ConnectionsHandler) HandleResolveInvite(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		InviteCode string `json:"invite_code"`
	}
	if err := unmarshalRequest(msg.Payload, &req, "HandleResolveInvite"); err != nil || req.InviteCode == "" {
		return h.errorResponse(msg.GetID(), "invite_code is required")
	}

	if h.sealerProxy == nil {
		return h.errorResponse(msg.GetID(), "sealer proxy not available")
	}

	log.Info().Str("invite_code", req.InviteCode).Msg("Resolving invitation from broker")

	inviteData, err := h.sealerProxy.ResolveInvite(req.InviteCode)
	if err != nil {
		log.Warn().Err(err).Str("invite_code", req.InviteCode).Msg("Failed to resolve invitation")
		return h.errorResponse(msg.GetID(), fmt.Sprintf("invitation not found or expired: %v", err))
	}

	// Return the raw invitation data — it contains connection_id, jwt, seed, owner_space, etc.
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   inviteData,
	}, nil
}

// HandlePeerKeyExchange handles incoming key exchange replies from peers.
// When A's vault processes B's acceptance, it sends A's public key back to B.
// This handler on B's vault stores A's public key and computes the shared secret.
func (h *ConnectionsHandler) HandlePeerKeyExchange(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var keyExchange struct {
		ConnectionID string `json:"connection_id"`
		PeerGUID     string `json:"peer_guid"`
		E2EPublicKey string `json:"e2e_public_key"`
	}

	if err := unmarshalRequest(msg.Payload, &keyExchange, "HandlePeerKeyExchange"); err != nil {
		log.Warn().Err(err).Msg("Failed to parse key exchange message")
		return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}, nil
	}

	if keyExchange.ConnectionID == "" || keyExchange.E2EPublicKey == "" {
		log.Warn().Msg("Key exchange missing connection_id or e2e_public_key")
		return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}, nil
	}

	log.Info().Str("connection_id", keyExchange.ConnectionID).Msg("Received key exchange from peer")

	// Load our connection record
	storageKey := "connections/" + keyExchange.ConnectionID
	connData, err := h.storage.Get(storageKey)
	if err != nil {
		log.Warn().Str("connection_id", keyExchange.ConnectionID).Msg("Connection not found for key exchange")
		return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}, nil
	}

	var record ConnectionRecord
	if err := json.Unmarshal(connData, &record); err != nil {
		log.Warn().Err(err).Msg("Failed to read connection for key exchange")
		return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}, nil
	}

	// Store peer's public key and compute shared secret
	peerPublicKey, err := decodeHexKey(keyExchange.E2EPublicKey)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to decode peer public key in key exchange")
		return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}, nil
	}

	record.PeerPublicKey = peerPublicKey
	if len(record.LocalPrivateKey) > 0 {
		sharedSecret, err := curve25519.X25519(record.LocalPrivateKey, peerPublicKey)
		if err == nil {
			record.SharedSecret = sharedSecret
			record.KeyExchangeAt = time.Now()
			log.Info().Str("connection_id", keyExchange.ConnectionID).Msg("Computed shared secret (B side)")
		} else {
			log.Error().Err(err).Msg("Failed to compute shared secret")
		}
	}

	// Save updated record
	newData, _ := json.Marshal(record)
	if err := h.storage.Put(storageKey, newData); err != nil {
		log.Error().Err(err).Msg("Failed to store connection after key exchange")
	}

	// Notify app that key exchange is complete
	if h.publisher != nil {
		notif := map[string]interface{}{
			"type":          "connection.key-exchanged",
			"connection_id": keyExchange.ConnectionID,
			"peer_guid":     keyExchange.PeerGUID,
		}
		notifBytes, _ := json.Marshal(notif)
		h.publisher.PublishToApp(ctx, "connection.key-exchanged", notifBytes)
	}

	return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}, nil
}

// HandlePeerConnectionActivated handles activation notifications from peers.
// When A reviews and accepts, A's vault publishes this to B's MessageSpace.
func (h *ConnectionsHandler) HandlePeerConnectionActivated(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var activation struct {
		ConnectionID string `json:"connection_id"`
		PeerGUID     string `json:"peer_guid"`
	}

	if err := unmarshalRequest(msg.Payload, &activation, "HandlePeerConnectionActivated"); err != nil || activation.ConnectionID == "" {
		return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}, nil
	}

	log.Info().Str("connection_id", activation.ConnectionID).Msg("Peer activated connection")

	storageKey := "connections/" + activation.ConnectionID
	connData, err := h.storage.Get(storageKey)
	if err != nil {
		return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}, nil
	}

	var record ConnectionRecord
	if err := json.Unmarshal(connData, &record); err != nil {
		return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}, nil
	}

	record.Status = "active"
	newData, _ := json.Marshal(record)
	h.storage.Put(storageKey, newData)

	if h.publisher != nil {
		notif := map[string]interface{}{
			"type":          "connection.activated",
			"connection_id": activation.ConnectionID,
			"peer_guid":     activation.PeerGUID,
			"peer_alias":    record.PeerAlias,
		}
		notifBytes, _ := json.Marshal(notif)
		h.publisher.PublishToApp(ctx, "connection.activated", notifBytes)
	}

	return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}, nil
}

// HandlePeerConnectionRejected handles rejection notifications from peers.
func (h *ConnectionsHandler) HandlePeerConnectionRejected(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var rejection struct {
		ConnectionID string `json:"connection_id"`
		PeerGUID     string `json:"peer_guid"`
	}

	if err := unmarshalRequest(msg.Payload, &rejection, "HandlePeerConnectionRejected"); err != nil || rejection.ConnectionID == "" {
		return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}, nil
	}

	log.Info().Str("connection_id", rejection.ConnectionID).Msg("Peer rejected connection")

	storageKey := "connections/" + rejection.ConnectionID
	connData, err := h.storage.Get(storageKey)
	if err != nil {
		return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}, nil
	}

	var record ConnectionRecord
	if err := json.Unmarshal(connData, &record); err != nil {
		return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}, nil
	}

	record.Status = "rejected"
	zeroBytes(record.SharedSecret)
	record.SharedSecret = nil
	zeroBytes(record.LocalPrivateKey)
	record.LocalPrivateKey = nil
	newData, _ := json.Marshal(record)
	h.storage.Put(storageKey, newData)

	if h.publisher != nil {
		notif := map[string]interface{}{
			"type":          "connection.rejected",
			"connection_id": rejection.ConnectionID,
			"peer_guid":     rejection.PeerGUID,
		}
		notifBytes, _ := json.Marshal(notif)
		h.publisher.PublishToApp(ctx, "connection.rejected", notifBytes)
	}

	return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}, nil
}

// HandleCreateAgentInvite handles connection.agent.create-invite messages.
// Creates a connection + invitation for an AI agent connector and returns
// the details the app needs to call POST /vault/agent/shortlink.
func (h *ConnectionsHandler) HandleCreateAgentInvite(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req CreateAgentInviteRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleCreateAgentInvite"); err != nil {
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
	if err := unmarshalRequest(msg.Payload, &req, "HandleStoreCredentials"); err != nil {
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

	// Determine connection type (default: peer)
	connType := ConnectionTypePeer
	if req.ConnectionType == ConnectionTypeAgent {
		connType = ConnectionTypeAgent
	} else if req.ConnectionType == ConnectionTypeDevice {
		connType = ConnectionTypeDevice
	}

	// Store the inbound connection record
	record := ConnectionRecord{
		ConnectionID:      req.ConnectionID,
		ConnectionType:    connType,
		PeerAlias:         req.PeerAlias,
		PeerGUID:          req.PeerGUID,
		CredentialsType:   "inbound",
		Credentials:       req.Credentials,
		MessageSpaceTopic: req.MessageSpaceTopic,
		PeerOwnerSpace:    req.PeerOwnerSpaceID,
		Status:            "active", // Scanner already consented by accepting the invitation
		CreatedAt:         time.Now(),
		LocalPublicKey:    localPublic,
		LocalPrivateKey:   localPrivate,
	}

	// Agent connections get a default contract
	if connType == ConnectionTypeAgent {
		record.Contract = &ConnectionContract{
			AgentName:    req.PeerAlias,
			Scope:        []string{},
			ApprovalMode: "always_ask",
			RateLimit:    RateLimit{Max: 60, Per: "hour"},
		}
		// Extract agent metadata from peer_profile
		if req.PeerProfile != nil {
			record.AgentMetadata = &AgentMetadata{
				AgentType:          getStringField(req.PeerProfile, "agent_type"),
				Hostname:           getStringField(req.PeerProfile, "hostname"),
				Platform:           getStringField(req.PeerProfile, "platform"),
				BinaryFingerprint:  getStringField(req.PeerProfile, "binary_fingerprint"),
				MachineFingerprint: getStringField(req.PeerProfile, "machine_fingerprint"),
				IPAddress:          getStringField(req.PeerProfile, "ip_address"),
			}
		}
	}

	// Device connections get a default session config
	if connType == ConnectionTypeDevice {
		if req.PeerProfile != nil {
			record.AgentMetadata = &AgentMetadata{
				Hostname:           getStringField(req.PeerProfile, "hostname"),
				Platform:           getStringField(req.PeerProfile, "platform"),
				BinaryFingerprint:  getStringField(req.PeerProfile, "binary_fingerprint"),
				MachineFingerprint: getStringField(req.PeerProfile, "machine_fingerprint"),
			}
		}
	}

	// If e2e_public_key was provided (agent/device pattern), store it directly
	e2eKeyHex := req.E2EPublicKey
	if e2eKeyHex == "" {
		e2eKeyHex = req.PeerE2EPublicKey
	}
	if e2eKeyHex != "" {
		if peerPubBytes, err := hex.DecodeString(e2eKeyHex); err == nil && len(peerPubBytes) == 32 {
			record.PeerPublicKey = peerPubBytes
			// Compute shared secret immediately if peer provided their public key
			if sharedSecret, err := curve25519.X25519(localPrivate, peerPubBytes); err == nil {
				record.SharedSecret = sharedSecret
				record.KeyExchangeAt = time.Now()
			}
		}
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

	// Cache the peer's profile (from the scanner's profile fetch) for the app
	if len(req.PeerProfile) > 0 {
		profileBytes, _ := json.Marshal(req.PeerProfile)
		if err := h.storage.Put("connections/"+req.ConnectionID+"/_peer_profile", profileBytes); err != nil {
			log.Warn().Err(err).Msg("Failed to cache peer profile on inbound connection")
		}
	}

	// Log connection event for audit (storing credentials means we accepted — audit only, no feed prompt needed)
	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(context.Background(), EventTypeConnectionCreated, req.ConnectionID, req.PeerGUID, "Connection initiated")
	}

	log.Info().Str("connection_id", req.ConnectionID).Msg("Connection credentials stored")

	// Notify the inviter's vault that we accepted the connection.
	// Include our full published profile (with photo) so the inviter can review it.
	// Published via parent (backend account) so the parent's MessageSpace subscription receives it.
	if h.publisher != nil && req.PeerOwnerSpaceID != "" {
		fullProfile := h.loadPublishedProfileForPeer()
		notification := map[string]interface{}{
			"connection_id":  req.ConnectionID,
			"peer_guid":      h.ownerSpace,
			"e2e_public_key": fmt.Sprintf("%x", localPublic),
			"owner_space":    h.ownerSpace,
			"message_space":  fmt.Sprintf("MessageSpace.%s.forOwner.>", h.ownerSpace),
			"peer_profile":   fullProfile,
		}

		notifBytes, _ := json.Marshal(notification)
		subject := fmt.Sprintf("MessageSpace.%s.forOwner.connection.accepted", req.PeerOwnerSpaceID)
		if err := h.publisher.PublishRaw(subject, notifBytes); err != nil {
			log.Warn().Err(err).Str("subject", subject).Msg("Failed to notify peer of acceptance (non-fatal)")
		} else {
			log.Info().
				Str("connection_id", req.ConnectionID).
				Str("peer_owner_space", req.PeerOwnerSpaceID).
				Msg("Published acceptance notification to peer's vault")
		}
	}

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
	if err := unmarshalRequest(msg.Payload, &req, "HandleInitiate"); err != nil {
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
	if err := unmarshalRequest(msg.Payload, &req, "HandleRespond"); err != nil {
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
		"pending":              true, // Inviter reviewing peer's profile
		"pending_our_review":   true, // Legacy status
		"pending_their_accept": true, // Legacy status
	}
	if !validStatuses[record.Status] {
		return h.errorResponse(msg.GetID(), fmt.Sprintf("Connection is not awaiting response (status: %s)", record.Status))
	}

	var newStatus string
	var message string

	if req.Response == "reject" {
		newStatus = "rejected"
		message = "Connection rejected"

		// Zero key material
		zeroBytes(record.SharedSecret)
		record.SharedSecret = nil
		zeroBytes(record.LocalPrivateKey)
		record.LocalPrivateKey = nil

		// Log rejection event
		if h.eventHandler != nil {
			h.eventHandler.LogConnectionEvent(context.Background(), EventTypeConnectionRejected, req.ConnectionID, record.PeerGUID, req.RejectionReason)
		}

		// Notify peer of rejection
		if h.publisher != nil && record.PeerOwnerSpace != "" {
			notif := map[string]interface{}{
				"connection_id": req.ConnectionID,
				"peer_guid":     h.ownerSpace,
			}
			notifBytes, _ := json.Marshal(notif)
			subject := fmt.Sprintf("MessageSpace.%s.forOwner.connection.rejected", record.PeerOwnerSpace)
			h.publisher.PublishRaw(subject, notifBytes)
		}
	} else {
		// Accept — connection is now active (key exchange already happened)
		newStatus = "active"
		message = "Connection established"

		// Log completion event (hidden — audit only, user already saw the accept prompt)
		if h.eventHandler != nil {
			h.eventHandler.LogConnectionEvent(context.Background(), EventTypeConnectionCreated, req.ConnectionID, record.PeerGUID, "Connection established")
		}

		// Notify peer that connection is now active
		if h.publisher != nil && record.PeerOwnerSpace != "" {
			notif := map[string]interface{}{
				"connection_id": req.ConnectionID,
				"peer_guid":     h.ownerSpace,
			}
			notifBytes, _ := json.Marshal(notif)
			subject := fmt.Sprintf("MessageSpace.%s.forOwner.connection.activated", record.PeerOwnerSpace)
			h.publisher.PublishRaw(subject, notifBytes)
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

// HandlePeerConnectionNotification handles incoming connection acceptance notifications
// from peers. When User B accepts an invitation, they publish a notification to User A's
// MessageSpace.{ownerSpace}.forOwner.connection.accepted topic. This handler updates
// User A's outbound connection record with User B's details.
func (h *ConnectionsHandler) HandlePeerConnectionNotification(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var notification struct {
		ConnectionID string                 `json:"connection_id"`
		PeerGUID     string                 `json:"peer_guid"`
		PeerProfile  map[string]interface{} `json:"peer_profile"`
		E2EPublicKey string                 `json:"e2e_public_key"`
		OwnerSpace   string                 `json:"owner_space"`
		MessageSpace string                 `json:"message_space"`
	}

	if err := unmarshalRequest(msg.Payload, &notification, "HandlePeerConnectionNotification"); err != nil {
		log.Warn().Err(err).Msg("Failed to parse peer connection notification")
		return &OutgoingMessage{
			Type:    MessageTypeResponse,
			Payload: json.RawMessage(`{"ack":true}`),
		}, nil
	}

	if notification.ConnectionID == "" {
		log.Warn().Msg("Peer connection notification missing connection_id")
		return &OutgoingMessage{
			Type:    MessageTypeResponse,
			Payload: json.RawMessage(`{"ack":true}`),
		}, nil
	}

	log.Info().
		Str("connection_id", notification.ConnectionID).
		Str("peer_guid", notification.PeerGUID).
		Msg("Received peer connection acceptance notification")

	// Load the outbound connection record
	storageKey := "connections/" + notification.ConnectionID
	connData, err := h.storage.Get(storageKey)
	if err != nil {
		log.Warn().Str("connection_id", notification.ConnectionID).Msg("Connection not found for peer notification")
		return &OutgoingMessage{
			Type:    MessageTypeResponse,
			Payload: json.RawMessage(`{"ack":true}`),
		}, nil
	}

	var record ConnectionRecord
	if err := json.Unmarshal(connData, &record); err != nil {
		log.Warn().Err(err).Msg("Failed to read connection for peer notification")
		return &OutgoingMessage{
			Type:    MessageTypeResponse,
			Payload: json.RawMessage(`{"ack":true}`),
		}, nil
	}

	// Update the connection with peer's details
	if notification.PeerGUID != "" {
		record.PeerGUID = notification.PeerGUID
	}
	if notification.OwnerSpace != "" {
		record.PeerOwnerSpace = notification.OwnerSpace
	}
	if notification.MessageSpace != "" {
		record.PeerMessageSpace = notification.MessageSpace
	}

	// Build display name from peer profile
	if notification.PeerProfile != nil {
		firstName, _ := notification.PeerProfile["_system_first_name"].(string)
		lastName, _ := notification.PeerProfile["_system_last_name"].(string)
		displayName := strings.TrimSpace(firstName + " " + lastName)
		if displayName != "" {
			record.PeerAlias = displayName
		}

		// Cache the peer's full profile in vault storage for the app
		profileBytes, _ := json.Marshal(notification.PeerProfile)
		if err := h.storage.Put("connections/"+notification.ConnectionID+"/_peer_profile", profileBytes); err != nil {
			log.Warn().Err(err).Msg("Failed to cache peer profile")
		}
	}

	// Store peer's E2E public key and compute shared secret
	if notification.E2EPublicKey != "" {
		peerPublicKey, err := decodeHexKey(notification.E2EPublicKey)
		if err == nil {
			record.PeerPublicKey = peerPublicKey
			// Compute shared secret using X25519
			if len(record.LocalPrivateKey) > 0 {
				sharedSecret, err := curve25519.X25519(record.LocalPrivateKey, peerPublicKey)
				if err == nil {
					record.SharedSecret = sharedSecret
					record.KeyExchangeAt = time.Now()
					log.Info().Str("connection_id", notification.ConnectionID).Msg("Computed shared secret (A side)")
				}
			}
		}
	}

	// Set status to pending — inviter needs to review peer's profile
	record.Status = "pending"

	// Save updated connection record
	newData, err := json.Marshal(record)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal updated connection")
		return &OutgoingMessage{
			Type:    MessageTypeResponse,
			Payload: json.RawMessage(`{"ack":true}`),
		}, nil
	}
	if err := h.storage.Put(storageKey, newData); err != nil {
		log.Error().Err(err).Msg("Failed to store updated connection")
		return &OutgoingMessage{
			Type:    MessageTypeResponse,
			Payload: json.RawMessage(`{"ack":true}`),
		}, nil
	}

	// Log the acceptance event — include peer name so feed shows who wants to connect
	if h.eventHandler != nil {
		title := fmt.Sprintf("%s wants to connect", record.PeerAlias)
		if record.PeerAlias == "" {
			title = "New connection request"
		}
		h.eventHandler.LogConnectionEvent(ctx, EventTypeConnectionAccepted, notification.ConnectionID, notification.PeerGUID, title)
	}

	log.Info().
		Str("connection_id", notification.ConnectionID).
		Str("peer_guid", notification.PeerGUID).
		Str("peer_alias", record.PeerAlias).
		Msg("Connection updated with peer details, status set to pending")

	// Send key exchange reply to peer's vault with our public key
	// This allows B to compute the same shared secret
	if h.publisher != nil && notification.OwnerSpace != "" && len(record.LocalPublicKey) > 0 {
		keyExchangeReply := map[string]interface{}{
			"connection_id":  notification.ConnectionID,
			"peer_guid":      h.ownerSpace,
			"e2e_public_key": fmt.Sprintf("%x", record.LocalPublicKey),
		}
		replyBytes, _ := json.Marshal(keyExchangeReply)
		subject := fmt.Sprintf("MessageSpace.%s.forOwner.connection.key-exchange", notification.OwnerSpace)
		if err := h.publisher.PublishRaw(subject, replyBytes); err != nil {
			log.Warn().Err(err).Str("subject", subject).Msg("Failed to send key exchange reply")
		} else {
			log.Info().Str("connection_id", notification.ConnectionID).Msg("Published key exchange reply to peer")
		}
	}

	// Notify the owner's app that a peer accepted — show review UI
	if h.publisher != nil {
		appNotification := map[string]interface{}{
			"type":          "connection.peer-accepted",
			"connection_id": notification.ConnectionID,
			"peer_guid":     notification.PeerGUID,
			"peer_alias":    record.PeerAlias,
			"peer_profile":  notification.PeerProfile,
			"status":        "pending",
		}
		notifBytes, _ := json.Marshal(appNotification)
		if err := h.publisher.PublishToApp(ctx, "connection.peer-accepted", notifBytes); err != nil {
			log.Warn().Err(err).Msg("Failed to notify app of peer acceptance")
		}
	}

	return &OutgoingMessage{
		Type:    MessageTypeResponse,
		Payload: json.RawMessage(`{"ack":true}`),
	}, nil
}

// HandleRevoke handles connection.revoke messages
func (h *ConnectionsHandler) HandleRevoke(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req RevokeConnectionRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleRevoke"); err != nil {
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
	if err := unmarshalRequest(msg.Payload, &req, "HandleList"); err != nil {
		// Allow empty payload for list all
		req = ListConnectionsRequest{}
	}

	// Lazy-provision the VettID system connection. The Initialize hook
	// in messages.go runs before PIN unlock, when storage isn't ready
	// yet — so the initial EnsureSystemConnection call is a silent
	// no-op. Running it here, right before the app reads the list,
	// guarantees storage is ready (list is only reachable post-unlock)
	// and keeps the call idempotent.
	if err := h.EnsureSystemConnection(context.Background()); err != nil {
		log.Warn().Err(err).Msg("lazy provision of system connection failed — list may be missing VettID card")
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

		// Load cached peer profile if available
		profileData, err := h.storage.Get("connections/" + connID + "/_peer_profile")
		if err == nil && len(profileData) > 0 {
			info.PeerProfile = json.RawMessage(profileData)
		}

		// Load message preview and unread count for this connection
		info.LastMessagePreview, info.LastMessageAt, info.UnreadCount = h.getMessagePreview(connID)

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
	if err := unmarshalRequest(msg.Payload, &req, "HandleGet"); err != nil {
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
	if err := unmarshalRequest(msg.Payload, &req, "HandleUpdate"); err != nil {
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
	if err := unmarshalRequest(msg.Payload, &req, "HandleRotate"); err != nil {
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
	if err := unmarshalRequest(msg.Payload, &req, "HandleGetCredentials"); err != nil {
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
	if err := unmarshalRequest(msg.Payload, &req, "HandleGetCapabilities"); err != nil {
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
	if err := unmarshalRequest(msg.Payload, &req, "HandleActivitySummary"); err != nil {
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

// HandleCreateDeviceInvite handles device.create-invite messages.
//
// Stage 1 of the device pairing flow (see DESKTOP-CONNECTION-FLOW.md):
//  1. Generate 8-char ambiguity-safe invite code, 2-minute expiry
//  2. Generate scoped NATS credentials bound to a new connection_id
//  3. Publish the full invite payload to the INVITATIONS JetStream subject
//     invite.<code> — the desktop, using its embedded guest account, reads
//     this to obtain the scoped creds
//  4. Create a connection record in "pending_pairing" status
//  5. Return the code + endpoint to the app for display
//
// No ConnectionRecord-held ephemeral keys at this stage. Key exchange happens
// later during stage 2 (device.authorize-session) using fresh ephemeral keys
// so the stage-1 NATS creds, even if leaked, cannot decrypt session data.
func (h *ConnectionsHandler) HandleCreateDeviceInvite(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req CreateDeviceInviteRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleCreateDeviceInvite"); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if h.natsProxy == nil || h.publisher == nil {
		return h.errorResponse(msg.GetID(), "NATS unavailable — cannot create device invite")
	}

	// Generate connection ID
	idBytes := make([]byte, 16)
	rand.Read(idBytes)
	connectionID := fmt.Sprintf("conn-%x", idBytes)

	// 2-minute pairing window
	expiresAt := time.Now().Add(2 * time.Minute)

	// Generate scoped NATS credentials — bound to this connection_id
	accountSeed, err := h.loadAccountSeed()
	if err != nil {
		log.Warn().Err(err).Msg("Failed to load NATS account seed for device invite")
		return h.errorResponse(msg.GetID(), "Failed to generate invitation credentials")
	}
	creds, err := GenerateDeviceCredentials(accountSeed, h.ownerSpace, connectionID, expiresAt)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to generate device credentials")
	}
	jwtStr, seedStr := extractCredsComponents(creds)

	// Generate the 8-char code and publish the invite payload to JetStream
	inviteCode := generateDeviceInviteCode()
	brokerPayload := map[string]interface{}{
		"type":          "vettid_device",
		"connection_id": connectionID,
		"jwt":           jwtStr,
		"seed":          seedStr,
		"owner_space":   h.ownerSpace,
		"message_space": fmt.Sprintf("MessageSpace.%s.forApp.device.%s.>", h.ownerSpace, connectionID),
		"expires_at":    expiresAt.Format(time.RFC3339),
		"label":         req.Label,
	}
	payloadBytes, _ := json.Marshal(brokerPayload)
	subject := fmt.Sprintf("invite.%s", inviteCode)
	if err := h.publisher.PublishRaw(subject, payloadBytes); err != nil {
		log.Error().Err(err).Str("subject", subject).Msg("Failed to publish device invite to broker")
		return h.errorResponse(msg.GetID(), "Failed to publish invitation")
	}

	// Store the outbound device connection record
	record := ConnectionRecord{
		ConnectionID:      connectionID,
		ConnectionType:    ConnectionTypeDevice,
		PeerAlias:         req.Label, // user may have hinted a name; final set at authorize
		CredentialsType:   "outbound",
		MessageSpaceTopic: fmt.Sprintf("MessageSpace.%s.forOwner.device.%s.>", h.ownerSpace, connectionID),
		Status:            "pending_pairing",
		CreatedAt:         time.Now(),
		ExpiresAt:         expiresAt,
	}
	data, err := json.Marshal(record)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to marshal connection")
	}
	if err := h.storage.Put("connections/"+connectionID, data); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to store connection")
	}
	h.addToConnectionIndex(connectionID)

	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(context.Background(), EventTypeDeviceConnectionRequest, connectionID, "", "Device pairing invite created")
	}

	natsEndpoint := ""
	if h.natsProxy != nil {
		natsEndpoint = h.natsProxy.GetNATSEndpoint()
	}

	log.Info().
		Str("connection_id", connectionID).
		Str("invite_code", inviteCode).
		Msg("Device invite created and published to broker")

	resp := CreateDeviceInviteResponse{
		ConnectionID: connectionID,
		InviteCode:   inviteCode,
		NATSEndpoint: natsEndpoint,
		ExpiresAt:    expiresAt.Format(time.RFC3339),
	}
	respBytes, _ := json.Marshal(resp)
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// loadAccountSeed returns the NATS account seed, loading from storage /
// sealer proxy if it isn't cached yet. Mirrors generateInvitationCredentials.
func (h *ConnectionsHandler) loadAccountSeed() (string, error) {
	if h.natsProxy == nil {
		return "", fmt.Errorf("NATS proxy not available")
	}
	if !h.natsProxy.HasAccountSeed() {
		if h.storage != nil {
			if seedData, err := h.storage.Get("nats_account_seed"); err == nil && len(seedData) > 0 {
				h.natsProxy.SetAccountSeed(string(seedData))
			}
		}
	}
	if !h.natsProxy.HasAccountSeed() {
		if h.sealerProxy == nil {
			return "", fmt.Errorf("sealer proxy not available")
		}
		seed, err := h.sealerProxy.LoadAccountSeed()
		if err != nil {
			return "", fmt.Errorf("load account seed: %w", err)
		}
		h.natsProxy.SetAccountSeed(seed)
		if h.storage != nil {
			_ = h.storage.Put("nats_account_seed", []byte(seed))
		}
	}
	seed := h.natsProxy.GetAccountSeed()
	if seed == "" {
		return "", fmt.Errorf("account seed empty after load")
	}
	return seed, nil
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
// Can be called from either the app (admin revoke) or the device itself (logout).
// Wipes the session key, marks the connection revoked, and publishes a
// revocation event so the desktop can clear its local state.
func (h *ConnectionsHandler) HandleRevokeDevice(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req DeviceRevokeRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleRevokeDevice"); err != nil {
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

	// Wipe the session key from storage
	if record.DeviceSession != nil && record.DeviceSession.SessionKeyID != "" {
		keyPath := fmt.Sprintf("device_session_keys/%s/%s", record.ConnectionID, record.DeviceSession.SessionKeyID)
		if err := h.storage.Delete(keyPath); err != nil {
			log.Warn().Err(err).Str("path", keyPath).Msg("Failed to delete session key during revoke (non-fatal)")
		}
	}

	// Mark revoked
	record.Status = "revoked"
	if record.DeviceSession != nil {
		record.DeviceSession.Status = "revoked"
	}
	record.DevicePendingAuth = nil

	connData, _ := json.Marshal(record)
	h.storage.Put("connections/"+record.ConnectionID, connData)

	// Notify the desktop so it can clear local state
	if h.publisher != nil {
		revokeNotif := map[string]interface{}{
			"type":          "device.session.revoked",
			"connection_id": record.ConnectionID,
			"reason":        req.Reason,
		}
		notifBytes, _ := json.Marshal(revokeNotif)
		subject := fmt.Sprintf("MessageSpace.%s.forApp.device.%s.revoked", h.ownerSpace, record.ConnectionID)
		if err := h.publisher.PublishRaw(subject, notifBytes); err != nil {
			log.Warn().Err(err).Str("subject", subject).Msg("Failed to publish device revocation (non-fatal)")
		}
	}

	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(ctx, EventTypeDeviceConnectionRevoked, record.ConnectionID, "",
			fmt.Sprintf("Device connection revoked: %s", record.PeerAlias))
	}

	log.Info().
		Str("connection_id", record.ConnectionID).
		Str("reason", req.Reason).
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

// NOTE: HandleExtendDeviceSession is now defined in device_pairing.go with the
// key-rotation semantics described in DESKTOP-CONNECTION-FLOW.md §Stage 4.
// The old phone-heartbeat-based HandleDeviceHeartbeat is removed — sessions are
// bounded by wall-clock expiry only, extended via user QR scan.

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
	if err := unmarshalRequest(msg.Payload, &req, "HandleRevokeAgent"); err != nil {
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
	if err := unmarshalRequest(msg.Payload, &req, "HandleUpdateAgentContract"); err != nil {
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

// loadInviterProfile reads the vault owner's profile for inclusion in invite responses.
func (h *ConnectionsHandler) loadInviterProfile() map[string]string {
	profile := make(map[string]string)

	systemFields := []string{"_system_first_name", "_system_last_name", "_system_email"}
	for _, field := range systemFields {
		data, err := h.storage.Get("profile/" + field)
		if err != nil {
			continue
		}
		var entry struct {
			Value string `json:"value"`
		}
		if json.Unmarshal(data, &entry) == nil && entry.Value != "" {
			profile[field] = entry.Value
		}
	}

	return profile
}

// loadPublishedProfileForPeer loads the full published profile for sending to
// a connection peer. Uses the shared BuildPublishedProfile function to ensure
// consistency with profile.get-published and profile.publish.
func (h *ConnectionsHandler) loadPublishedProfileForPeer() map[string]interface{} {
	profile := BuildPublishedProfile(h.ownerSpace, h.storage, h.vaultState)
	return PublishedProfileToMap(profile)
}

// getMessagePreview loads the latest message preview, timestamp, and unread count
// for a connection. Used by HandleList to populate connection cards.
func (h *ConnectionsHandler) getMessagePreview(connectionID string) (preview string, lastAt string, unreadCount int) {
	indexKey := fmt.Sprintf("messages/%s/_index", connectionID)
	var messageIDs []string
	indexData, err := h.storage.Get(indexKey)
	if err != nil {
		return "", "", 0
	}
	if json.Unmarshal(indexData, &messageIDs) != nil {
		return "", "", 0
	}

	var latestTime time.Time
	var latestContent string

	for _, msgID := range messageIDs {
		key := fmt.Sprintf("messages/%s/%s", connectionID, msgID)
		data, err := h.storage.Get(key)
		if err != nil {
			continue
		}
		var record MessageRecord
		if json.Unmarshal(data, &record) != nil {
			continue
		}

		// Track latest message
		if record.CreatedAt.After(latestTime) {
			latestTime = record.CreatedAt
			if record.Direction == MessageDirectionIncoming {
				latestContent = "Received a message"
			} else {
				latestContent = "You sent a message"
			}
		}

		// Count unread incoming messages
		if record.Direction == MessageDirectionIncoming && record.Status != MessageStatusRead {
			unreadCount++
		}
	}

	if latestContent != "" {
		// Truncate preview
		if len(latestContent) > 100 {
			preview = latestContent[:100] + "..."
		} else {
			preview = latestContent
		}
		lastAt = latestTime.Format(time.RFC3339)
	}

	return preview, lastAt, unreadCount
}

// generateInvitationCredentials creates scoped NATS credentials for an invitation.
// Loads the account seed from vault storage first (fast path), falling back to
// sealer proxy (DynamoDB via parent) for initial fetch, then caches in vault storage.
func (h *ConnectionsHandler) generateInvitationCredentials(expiresAt time.Time) (string, error) {
	if h.natsProxy == nil {
		return "", fmt.Errorf("NATS proxy not available")
	}

	// Fast path: already cached in memory
	if !h.natsProxy.HasAccountSeed() {
		// Try loading from vault's own encrypted storage first
		if h.storage != nil {
			seedData, err := h.storage.Get("nats_account_seed")
			if err == nil && len(seedData) > 0 {
				log.Info().Str("owner_space", h.ownerSpace).Msg("Loaded NATS account seed from vault storage")
				h.natsProxy.SetAccountSeed(string(seedData))
			}
		}
	}

	// Fallback: fetch via sealer proxy (parent → DynamoDB → KMS) and cache in vault storage
	if !h.natsProxy.HasAccountSeed() {
		if h.sealerProxy == nil {
			return "", fmt.Errorf("sealer proxy not available for account seed loading")
		}

		log.Info().Str("owner_space", h.ownerSpace).Msg("Loading NATS account seed via sealer proxy")
		seed, err := h.sealerProxy.LoadAccountSeed()
		if err != nil {
			return "", fmt.Errorf("failed to load account seed: %w", err)
		}
		h.natsProxy.SetAccountSeed(seed)

		// Cache in vault storage so future loads don't need DynamoDB
		if h.storage != nil {
			if storeErr := h.storage.Put("nats_account_seed", []byte(seed)); storeErr != nil {
				log.Warn().Err(storeErr).Msg("Failed to cache account seed in vault storage (non-fatal)")
			} else {
				log.Info().Str("owner_space", h.ownerSpace).Msg("Cached NATS account seed in vault storage")
			}
		}
	}

	accountSeed := h.natsProxy.GetAccountSeed()
	if accountSeed == "" {
		return "", fmt.Errorf("account seed not available after loading")
	}

	return GenerateInvitationCredentials(accountSeed, h.ownerSpace, expiresAt)
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

// getStringField safely extracts a string value from a map.
func getStringField(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
