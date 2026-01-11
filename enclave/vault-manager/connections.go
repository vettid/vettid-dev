package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
)

// ConnectionsHandler handles connection credential management.
// This enables vault-to-vault communication.
type ConnectionsHandler struct {
	ownerSpace string
	storage    *EncryptedStorage
}

// NewConnectionsHandler creates a new connections handler
func NewConnectionsHandler(ownerSpace string, storage *EncryptedStorage) *ConnectionsHandler {
	return &ConnectionsHandler{
		ownerSpace: ownerSpace,
		storage:    storage,
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
	Status            string    `json:"status"` // "active", "revoked"
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

// RevokeConnectionRequest is the payload for connection.revoke
type RevokeConnectionRequest struct {
	ConnectionID string `json:"connection_id"`
}

// ListConnectionsRequest is the payload for connection.list
type ListConnectionsRequest struct {
	Status string `json:"status,omitempty"`
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
}

// ListConnectionsResponse is the response for connection.list
type ListConnectionsResponse struct {
	Connections []ConnectionInfo `json:"connections"`
}

// GetConnectionRequest is the payload for connection.get
type GetConnectionRequest struct {
	ConnectionID string `json:"connection_id"`
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
	// Clamp for X25519
	localPrivate[0] &= 248
	localPrivate[31] &= 127
	localPrivate[31] |= 64

	// For now, store a placeholder - real implementation would derive public key
	localPublic := make([]byte, 32)
	copy(localPublic, localPrivate) // Placeholder

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

		info := ConnectionInfo{
			ConnectionID:     record.ConnectionID,
			PeerAlias:        record.PeerAlias,
			PeerGUID:         record.PeerGUID,
			Status:           record.Status,
			CreatedAt:        record.CreatedAt.Format(time.RFC3339),
			CredentialsType:  record.CredentialsType,
			E2EReady:         len(record.SharedSecret) > 0,
			KeyRotationCount: record.KeyRotationCount,
		}

		if !record.LastRotatedAt.IsZero() {
			info.LastRotatedAt = record.LastRotatedAt.Format(time.RFC3339)
		}
		if !record.KeyExchangeAt.IsZero() {
			info.KeyExchangeAt = record.KeyExchangeAt.Format(time.RFC3339)
		}

		connections = append(connections, info)
	}

	resp := ListConnectionsResponse{
		Connections: connections,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
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

	info := ConnectionInfo{
		ConnectionID:     record.ConnectionID,
		PeerAlias:        record.PeerAlias,
		PeerGUID:         record.PeerGUID,
		Status:           record.Status,
		CreatedAt:        record.CreatedAt.Format(time.RFC3339),
		CredentialsType:  record.CredentialsType,
		E2EReady:         len(record.SharedSecret) > 0,
		KeyRotationCount: record.KeyRotationCount,
	}

	respBytes, _ := json.Marshal(info)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
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
