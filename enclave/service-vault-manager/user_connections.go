package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/curve25519"
)

// UserConnectionsHandler manages connections from users to this service.
// Key principle: Services cannot cache user profiles - they must request data on-demand.
type UserConnectionsHandler struct {
	ownerSpace      string
	storage         *EncryptedStorage
	sendFn          func(msg *OutgoingMessage) error
	contractManager *ContractManager
}

// NewUserConnectionsHandler creates a new user connections handler
func NewUserConnectionsHandler(
	ownerSpace string,
	storage *EncryptedStorage,
	sendFn func(msg *OutgoingMessage) error,
	contractManager *ContractManager,
) *UserConnectionsHandler {
	return &UserConnectionsHandler{
		ownerSpace:      ownerSpace,
		storage:         storage,
		sendFn:          sendFn,
		contractManager: contractManager,
	}
}

// --- Request/Response Types ---

// ConnectRequest is received when a user initiates connection
type ConnectRequest struct {
	ConnectionID    string `json:"connection_id"`
	UserGUID        string `json:"user_guid"`
	UserPublicKey   []byte `json:"user_public_key"` // X25519 for E2E
	ContractVersion int    `json:"contract_version"`
}

// ConnectResponse is sent back to the user
type ConnectResponse struct {
	Success          bool   `json:"success"`
	ConnectionID     string `json:"connection_id"`
	ServicePublicKey []byte `json:"service_public_key"` // Our X25519 public key
	Message          string `json:"message,omitempty"`
}

// ListConnectionsRequest is the payload for user.connection.list
type ListConnectionsRequest struct {
	Status string `json:"status,omitempty"` // Filter by status
	Limit  int    `json:"limit,omitempty"`
	Offset int    `json:"offset,omitempty"`
}

// ListConnectionsResponse is the response for user.connection.list
type ListConnectionsResponse struct {
	Connections []UserConnectionInfo `json:"connections"`
	Total       int                  `json:"total"`
}

// GetConnectionRequest is the payload for user.connection.get
type GetConnectionRequest struct {
	ConnectionID string `json:"connection_id"`
}

// GetConnectionResponse is the response for user.connection.get
type GetConnectionResponse struct {
	Connection UserConnectionInfo `json:"connection"`
}

// DisconnectRequest is the payload for user.connection.disconnect (service-initiated)
type DisconnectRequest struct {
	ConnectionID string `json:"connection_id"`
	Reason       string `json:"reason,omitempty"`
}

// DisconnectResponse is the response for user.connection.disconnect
type DisconnectResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// --- Handlers ---

// HandleConnect accepts a new user connection
// Called when a user scans our QR code and accepts the contract
func (h *UserConnectionsHandler) HandleConnect(msg *IncomingMessage, userGUID string) (*OutgoingMessage, error) {
	var req ConnectRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "invalid request payload")
	}

	// Override userGUID from the subject (trusted source)
	req.UserGUID = userGUID

	log.Info().
		Str("connection_id", req.ConnectionID).
		Str("user_guid", req.UserGUID).
		Int("contract_version", req.ContractVersion).
		Msg("User connecting to service")

	// Verify the contract version is current
	currentContract, err := h.contractManager.GetCurrentContract()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get current contract")
		return h.errorResponse(msg.GetID(), "service configuration error")
	}
	if currentContract == nil {
		return h.errorResponse(msg.GetID(), "service has no published contract")
	}
	if req.ContractVersion != currentContract.Version {
		return h.errorResponse(msg.GetID(), fmt.Sprintf("contract version mismatch: expected %d, got %d", currentContract.Version, req.ContractVersion))
	}

	// Generate our X25519 keypair for this connection
	var privateKey [32]byte
	if _, err := rand.Read(privateKey[:]); err != nil {
		return h.errorResponse(msg.GetID(), "failed to generate keys")
	}
	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	// Compute shared secret with user's public key
	var peerKey [32]byte
	if len(req.UserPublicKey) != 32 {
		return h.errorResponse(msg.GetID(), "invalid user public key")
	}
	copy(peerKey[:], req.UserPublicKey)

	var sharedSecret [32]byte
	curve25519.ScalarMult(&sharedSecret, &privateKey, &peerKey)

	// Create connection record (NO profile data!)
	conn := &UserConnectionRecord{
		ConnectionID:    req.ConnectionID,
		UserGUID:        req.UserGUID,
		LocalPrivateKey: privateKey[:],
		LocalPublicKey:  publicKey[:],
		PeerPublicKey:   req.UserPublicKey,
		SharedSecret:    sharedSecret[:],
		ContractVersion: req.ContractVersion,
		Status:          "active",
		ConnectedAt:     time.Now(),
		LastActivityAt:  time.Now(),
	}

	// Store connection
	connKey := KeyConnectionPrefix + conn.ConnectionID
	if err := h.storage.PutJSON(connKey, conn); err != nil {
		return h.errorResponse(msg.GetID(), "failed to store connection")
	}

	// Add to index
	if err := h.storage.AddToIndex(KeyConnectionIndex, conn.ConnectionID); err != nil {
		log.Warn().Err(err).Msg("Failed to add connection to index")
	}

	log.Info().
		Str("connection_id", conn.ConnectionID).
		Str("user_guid", conn.UserGUID).
		Msg("User connected successfully")

	return h.successResponse(msg.GetID(), ConnectResponse{
		Success:          true,
		ConnectionID:     conn.ConnectionID,
		ServicePublicKey: publicKey[:],
		Message:          "Connected successfully",
	})
}

// HandleList lists all user connections
func (h *UserConnectionsHandler) HandleList(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req ListConnectionsRequest
	if msg.Payload != nil {
		if err := json.Unmarshal(msg.Payload, &req); err != nil {
			return h.errorResponse(msg.GetID(), "invalid request payload")
		}
	}

	// Set defaults
	if req.Limit <= 0 || req.Limit > 100 {
		req.Limit = 50
	}

	// Get all connection IDs
	connIDs, err := h.storage.GetIndex(KeyConnectionIndex)
	if err != nil {
		return h.errorResponse(msg.GetID(), "failed to list connections")
	}

	var connections []UserConnectionInfo
	for _, connID := range connIDs {
		var conn UserConnectionRecord
		connKey := KeyConnectionPrefix + connID
		if err := h.storage.GetJSON(connKey, &conn); err != nil {
			continue
		}

		// Filter by status if specified
		if req.Status != "" && conn.Status != req.Status {
			continue
		}

		connections = append(connections, UserConnectionInfo{
			ConnectionID:    conn.ConnectionID,
			UserGUID:        conn.UserGUID,
			ContractVersion: conn.ContractVersion,
			Status:          conn.Status,
			ConnectedAt:     conn.ConnectedAt,
			LastActivityAt:  conn.LastActivityAt,
		})
	}

	// Apply pagination
	total := len(connections)
	start := req.Offset
	end := start + req.Limit
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}
	connections = connections[start:end]

	return h.successResponse(msg.GetID(), ListConnectionsResponse{
		Connections: connections,
		Total:       total,
	})
}

// HandleGet retrieves a specific connection
func (h *UserConnectionsHandler) HandleGet(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req GetConnectionRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "invalid request payload")
	}

	var conn UserConnectionRecord
	connKey := KeyConnectionPrefix + req.ConnectionID
	if err := h.storage.GetJSON(connKey, &conn); err != nil {
		return h.errorResponse(msg.GetID(), "connection not found")
	}

	return h.successResponse(msg.GetID(), GetConnectionResponse{
		Connection: UserConnectionInfo{
			ConnectionID:    conn.ConnectionID,
			UserGUID:        conn.UserGUID,
			ContractVersion: conn.ContractVersion,
			Status:          conn.Status,
			ConnectedAt:     conn.ConnectedAt,
			LastActivityAt:  conn.LastActivityAt,
		},
	})
}

// HandleDisconnect allows the service to disconnect a user
func (h *UserConnectionsHandler) HandleDisconnect(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req DisconnectRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "invalid request payload")
	}

	var conn UserConnectionRecord
	connKey := KeyConnectionPrefix + req.ConnectionID
	if err := h.storage.GetJSON(connKey, &conn); err != nil {
		return h.errorResponse(msg.GetID(), "connection not found")
	}

	// Update status
	conn.Status = "revoked"
	if err := h.storage.PutJSON(connKey, conn); err != nil {
		return h.errorResponse(msg.GetID(), "failed to update connection")
	}

	log.Info().
		Str("connection_id", conn.ConnectionID).
		Str("user_guid", conn.UserGUID).
		Str("reason", req.Reason).
		Msg("Service disconnected user")

	// Notify the user's vault about the disconnection
	h.notifyUserDisconnect(conn.UserGUID, conn.ConnectionID, req.Reason)

	return h.successResponse(msg.GetID(), DisconnectResponse{
		Success: true,
		Message: "User disconnected",
	})
}

// HandleUserDisconnect handles when a user initiates disconnection
// This is called when a user revokes the connection from their side
func (h *UserConnectionsHandler) HandleUserDisconnect(msg *IncomingMessage, userGUID string) (*OutgoingMessage, error) {
	// Find connection by userGUID
	connIDs, err := h.storage.GetIndex(KeyConnectionIndex)
	if err != nil {
		return h.errorResponse(msg.GetID(), "failed to find connections")
	}

	var foundConn *UserConnectionRecord
	var connKey string
	for _, connID := range connIDs {
		var conn UserConnectionRecord
		key := KeyConnectionPrefix + connID
		if err := h.storage.GetJSON(key, &conn); err != nil {
			continue
		}
		if conn.UserGUID == userGUID && conn.Status == "active" {
			foundConn = &conn
			connKey = key
			break
		}
	}

	if foundConn == nil {
		return h.errorResponse(msg.GetID(), "no active connection found for user")
	}

	// Update status
	foundConn.Status = "revoked"
	if err := h.storage.PutJSON(connKey, foundConn); err != nil {
		return h.errorResponse(msg.GetID(), "failed to update connection")
	}

	log.Info().
		Str("connection_id", foundConn.ConnectionID).
		Str("user_guid", userGUID).
		Msg("User disconnected from service")

	return h.successResponse(msg.GetID(), DisconnectResponse{
		Success: true,
		Message: "Disconnected successfully",
	})
}

// --- Helper Methods ---

// GetConnection retrieves a connection record by ID
func (h *UserConnectionsHandler) GetConnection(connectionID string) (*UserConnectionRecord, error) {
	var conn UserConnectionRecord
	connKey := KeyConnectionPrefix + connectionID
	if err := h.storage.GetJSON(connKey, &conn); err != nil {
		return nil, err
	}
	return &conn, nil
}

// GetConnectionByUserGUID finds an active connection for a user
func (h *UserConnectionsHandler) GetConnectionByUserGUID(userGUID string) (*UserConnectionRecord, error) {
	connIDs, err := h.storage.GetIndex(KeyConnectionIndex)
	if err != nil {
		return nil, err
	}

	for _, connID := range connIDs {
		var conn UserConnectionRecord
		connKey := KeyConnectionPrefix + connID
		if err := h.storage.GetJSON(connKey, &conn); err != nil {
			continue
		}
		if conn.UserGUID == userGUID && conn.Status == "active" {
			return &conn, nil
		}
	}

	return nil, fmt.Errorf("no active connection found for user %s", userGUID)
}

// UpdateLastActivity updates the last activity timestamp
func (h *UserConnectionsHandler) UpdateLastActivity(connectionID string) error {
	var conn UserConnectionRecord
	connKey := KeyConnectionPrefix + connectionID
	if err := h.storage.GetJSON(connKey, &conn); err != nil {
		return err
	}
	conn.LastActivityAt = time.Now()
	return h.storage.PutJSON(connKey, conn)
}

// notifyUserDisconnect sends a disconnection notice to the user's vault
func (h *UserConnectionsHandler) notifyUserDisconnect(userGUID, connectionID, reason string) {
	payload := map[string]interface{}{
		"connection_id": connectionID,
		"reason":        reason,
		"timestamp":     time.Now(),
	}
	data, _ := json.Marshal(payload)

	msg := &OutgoingMessage{
		Type:    MessageTypeNATSPublish,
		Subject: fmt.Sprintf("OwnerSpace.%s.fromService.%s.disconnect", userGUID, h.ownerSpace),
		Payload: data,
	}

	if err := h.sendFn(msg); err != nil {
		log.Warn().Err(err).Str("user_guid", userGUID).Msg("Failed to notify user of disconnection")
	}
}

func (h *UserConnectionsHandler) errorResponse(requestID, message string) (*OutgoingMessage, error) {
	return &OutgoingMessage{
		RequestID: requestID,
		Type:      MessageTypeResponse,
		Payload:   mustMarshal(map[string]interface{}{"success": false, "error": message}),
	}, nil
}

func (h *UserConnectionsHandler) successResponse(requestID string, payload interface{}) (*OutgoingMessage, error) {
	return &OutgoingMessage{
		RequestID: requestID,
		Type:      MessageTypeResponse,
		Payload:   mustMarshal(payload),
	}, nil
}
