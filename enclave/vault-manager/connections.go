package main

import (
	"context"
	"crypto/rand"
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

// ConnectionRecord represents a stored connection
type ConnectionRecord struct {
	ConnectionID      string    `json:"connection_id"`
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
	MessageSpaceTopic string `json:"message_space_topic"`
	ExpiresAt         string `json:"expires_at"`
	E2EPublicKey      string `json:"e2e_public_key"`
}

// StoreCredentialsRequest is the payload for connection.store-credentials
type StoreCredentialsRequest struct {
	ConnectionID      string `json:"connection_id"`
	PeerAlias         string `json:"peer_alias"`
	PeerGUID          string `json:"peer_guid"`
	Credentials       string `json:"credentials"`
	MessageSpaceTopic string `json:"message_space_topic"`
	PeerE2EPublicKey  string `json:"peer_e2e_public_key"`
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

// ListConnectionsRequest is the payload for connection.list
type ListConnectionsRequest struct {
	Status     string   `json:"status,omitempty"`
	Tags       []string `json:"tags,omitempty"`
	IsFavorite *bool    `json:"is_favorite,omitempty"`
	IsArchived *bool    `json:"is_archived,omitempty"`
	Search     string   `json:"search,omitempty"`
	SortBy     string   `json:"sort_by,omitempty"` // "recent_activity", "alphabetical", "created_at"
	SortOrder  string   `json:"sort_order,omitempty"` // "asc", "desc"
	Limit      int      `json:"limit,omitempty"`
	Offset     int      `json:"offset,omitempty"`
}

// ConnectionInfo represents connection info in list response
type ConnectionInfo struct {
	ConnectionID     string `json:"connection_id"`
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

// HandleStoreCredentials handles connection.store-credentials messages
func (h *ConnectionsHandler) HandleStoreCredentials(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req StoreCredentialsRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}
	if req.Credentials == "" {
		return h.errorResponse(msg.GetID(), "credentials are required")
	}
	if req.MessageSpaceTopic == "" {
		return h.errorResponse(msg.GetID(), "message_space_topic is required")
	}

	// Generate our X25519 key pair
	localPrivate := make([]byte, 32)
	rand.Read(localPrivate)
	localPrivate[0] &= 248
	localPrivate[31] &= 127
	localPrivate[31] |= 64
	localPublic := make([]byte, 32)
	copy(localPublic, localPrivate) // Placeholder

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

	resp := StoreCredentialsResponse{
		Success:      true,
		ConnectionID: req.ConnectionID,
		E2EPublicKey: fmt.Sprintf("%x", localPublic),
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

		// Filter by search term (case-insensitive substring match on alias)
		if req.Search != "" {
			searchLower := strings.ToLower(req.Search)
			if !strings.Contains(strings.ToLower(record.PeerAlias), searchLower) {
				continue
			}
		}

		// Compute needs_attention flag
		needsAttention := h.computeNeedsAttention(&record)

		info := ConnectionInfo{
			ConnectionID:       record.ConnectionID,
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
