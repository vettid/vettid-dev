package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
)

// ConnectionManager manages per-operator connections to the org vault.
// Each operator has their own X25519 keypair — the connection IS the identity.
// No JWTs, no tokens — cryptographic identity via the connection itself.
type ConnectionManager struct {
	ownerSpace string
	storage    *EncryptedStorage
	sendFn     func(msg *OutgoingMessage) error
}

// NewConnectionManager creates a new connection manager.
func NewConnectionManager(ownerSpace string, storage *EncryptedStorage, sendFn func(msg *OutgoingMessage) error) *ConnectionManager {
	return &ConnectionManager{
		ownerSpace: ownerSpace,
		storage:    storage,
		sendFn:     sendFn,
	}
}

// GetConnection retrieves an operator connection by ID.
func (cm *ConnectionManager) GetConnection(connectionID string) (*OperatorConnection, error) {
	var conn OperatorConnection
	if err := cm.storage.GetJSON(KeyOperatorPrefix+connectionID, &conn); err != nil {
		return nil, fmt.Errorf("connection not found: %s", connectionID)
	}
	return &conn, nil
}

// DeriveConnectionKey recomputes the shared secret + HKDF connection_key for
// an operator connection from the persisted private key and peer public key.
//
// SECURITY: SharedSecret is never persisted (json:"-") to avoid storing the
// derived material twice. The ingredients (LocalPrivateKey + PeerPublicKey)
// are encrypted in vault storage, so recomputing on demand is just as secure.
func (cm *ConnectionManager) DeriveConnectionKey(conn *OperatorConnection) ([]byte, error) {
	if len(conn.LocalPrivateKey) == 0 {
		return nil, fmt.Errorf("connection has no private key")
	}
	if len(conn.PeerPublicKey) == 0 {
		return nil, fmt.Errorf("connection not yet connected (no peer public key)")
	}

	curve := ecdh.X25519()
	priv, err := curve.NewPrivateKey(conn.LocalPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("load private key: %w", err)
	}
	peer, err := curve.NewPublicKey(conn.PeerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("load peer public key: %w", err)
	}
	sharedSecret, err := priv.ECDH(peer)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}
	defer zeroBytes(sharedSecret)

	return deriveConnectionKey(sharedSecret)
}

// zeroBytes overwrites a byte slice with zeros.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// TouchConnection updates the last activity timestamp.
func (cm *ConnectionManager) TouchConnection(connectionID string) {
	conn, err := cm.GetConnection(connectionID)
	if err != nil {
		return
	}
	conn.LastActiveAt = time.Now()
	conn.QueryCount++
	cm.storage.PutJSON(KeyOperatorPrefix+connectionID, conn)
}

// ListConnections returns all operator connections (public info only).
func (cm *ConnectionManager) ListConnections() ([]OperatorInfo, error) {
	ids, err := cm.storage.GetIndex(KeyOperatorIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to read operator index: %w", err)
	}

	var operators []OperatorInfo
	for _, id := range ids {
		var conn OperatorConnection
		if err := cm.storage.GetJSON(KeyOperatorPrefix+id, &conn); err != nil {
			continue
		}
		operators = append(operators, conn.ToInfo())
	}
	return operators, nil
}

// SecureErase zeros all connection secrets from memory.
func (cm *ConnectionManager) SecureErase() {
	ids, _ := cm.storage.GetIndex(KeyOperatorIndex)
	for _, id := range ids {
		var conn OperatorConnection
		if err := cm.storage.GetJSON(KeyOperatorPrefix+id, &conn); err != nil {
			continue
		}
		// Zero sensitive key material
		for i := range conn.LocalPrivateKey {
			conn.LocalPrivateKey[i] = 0
		}
		for i := range conn.SharedSecret {
			conn.SharedSecret[i] = 0
		}
	}
}

// --- Message Handlers ---

// HandleInvite generates an invitation for a new operator.
// The invitation includes a connection ID and the vault's X25519 public key.
// The operator will complete the key exchange when they accept.
func (cm *ConnectionManager) HandleInvite(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		OperatorEmail string `json:"operator_email"`
		OperatorRole  string `json:"operator_role"`
	}

	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return errorResponse(msg.GetID(), "invalid request: "+err.Error())
	}

	if req.OperatorEmail == "" || req.OperatorRole == "" {
		return errorResponse(msg.GetID(), "operator_email and operator_role are required")
	}

	// Generate X25519 keypair for this connection
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return errorResponse(msg.GetID(), "failed to generate keypair: "+err.Error())
	}

	connectionID := generateID()
	now := time.Now()

	conn := &OperatorConnection{
		ConnectionID:   connectionID,
		OperatorEmail:  req.OperatorEmail,
		OperatorRole:   req.OperatorRole,
		Status:         "pending",
		LocalPrivateKey: privateKey.Bytes(),
		LocalPublicKey:  privateKey.PublicKey().Bytes(),
		ConnectedAt:    now,
		LastActiveAt:   now,
	}

	if err := cm.storage.PutJSON(KeyOperatorPrefix+connectionID, conn); err != nil {
		return errorResponse(msg.GetID(), "failed to store connection: "+err.Error())
	}

	if err := cm.storage.AddToIndex(KeyOperatorIndex, connectionID); err != nil {
		return errorResponse(msg.GetID(), "failed to update index: "+err.Error())
	}

	log.Info().
		Str("connection_id", connectionID).
		Str("operator_email", req.OperatorEmail).
		Str("operator_role", req.OperatorRole).
		Msg("Operator invitation created")

	return successResponse(msg.GetID(), map[string]interface{}{
		"success":       true,
		"connection_id": connectionID,
		"public_key":    privateKey.PublicKey().Bytes(),
		"org_vault_id":  cm.ownerSpace,
	})
}

// HandleConnect completes the key exchange when an operator accepts an invitation.
func (cm *ConnectionManager) HandleConnect(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		ConnectionID string `json:"connection_id"`
		PeerPublicKey []byte `json:"peer_public_key"` // Operator's X25519 public key
	}

	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return errorResponse(msg.GetID(), "invalid request: "+err.Error())
	}

	if req.ConnectionID == "" || len(req.PeerPublicKey) == 0 {
		return errorResponse(msg.GetID(), "connection_id and peer_public_key are required")
	}

	conn, err := cm.GetConnection(req.ConnectionID)
	if err != nil {
		return errorResponse(msg.GetID(), "connection not found")
	}

	if conn.Status != "pending" {
		return errorResponse(msg.GetID(), "connection is not pending: "+conn.Status)
	}

	// Perform X25519 ECDH key exchange.
	// SECURITY (#83): refuse small-order points before importing the
	// wire-supplied peer pub key, mirroring the safeX25519 guard in
	// vault-manager. ecdh.X25519().ECDH already rejects shared==0;
	// this closes the remaining contributory-behavior gap.
	if err := rejectSmallOrderPoint(req.PeerPublicKey); err != nil {
		return errorResponse(msg.GetID(), "invalid peer public key: "+err.Error())
	}

	privateKey, err := ecdh.X25519().NewPrivateKey(conn.LocalPrivateKey)
	if err != nil {
		return errorResponse(msg.GetID(), "failed to load private key: "+err.Error())
	}

	peerKey, err := ecdh.X25519().NewPublicKey(req.PeerPublicKey)
	if err != nil {
		return errorResponse(msg.GetID(), "invalid peer public key: "+err.Error())
	}

	sharedSecret, err := privateKey.ECDH(peerKey)
	if err != nil {
		return errorResponse(msg.GetID(), "ECDH key exchange failed: "+err.Error())
	}

	// Update connection
	conn.PeerPublicKey = req.PeerPublicKey
	conn.SharedSecret = sharedSecret
	conn.Status = "active"
	conn.ConnectedAt = time.Now()
	conn.LastActiveAt = time.Now()

	if err := cm.storage.PutJSON(KeyOperatorPrefix+conn.ConnectionID, conn); err != nil {
		return errorResponse(msg.GetID(), "failed to update connection: "+err.Error())
	}

	log.Info().
		Str("connection_id", conn.ConnectionID).
		Str("operator_email", conn.OperatorEmail).
		Msg("Operator connected (key exchange complete)")

	return successResponse(msg.GetID(), map[string]interface{}{
		"success":       true,
		"connection_id": conn.ConnectionID,
		"status":        "active",
	})
}

// HandleList returns all operator connections.
func (cm *ConnectionManager) HandleList(msg *IncomingMessage) (*OutgoingMessage, error) {
	operators, err := cm.ListConnections()
	if err != nil {
		return errorResponse(msg.GetID(), "failed to list operators: "+err.Error())
	}

	return successResponse(msg.GetID(), map[string]interface{}{
		"success":   true,
		"operators": operators,
		"count":     len(operators),
	})
}

// HandleRevoke disconnects an operator immediately.
func (cm *ConnectionManager) HandleRevoke(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		ConnectionID string `json:"connection_id"`
		Reason       string `json:"reason,omitempty"`
	}

	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return errorResponse(msg.GetID(), "invalid request: "+err.Error())
	}

	if req.ConnectionID == "" {
		return errorResponse(msg.GetID(), "connection_id is required")
	}

	conn, err := cm.GetConnection(req.ConnectionID)
	if err != nil {
		return errorResponse(msg.GetID(), "connection not found")
	}

	// SECURITY: Zero the shared secret and private key
	for i := range conn.SharedSecret {
		conn.SharedSecret[i] = 0
	}
	for i := range conn.LocalPrivateKey {
		conn.LocalPrivateKey[i] = 0
	}

	conn.Status = "revoked"
	conn.LastActiveAt = time.Now()

	if err := cm.storage.PutJSON(KeyOperatorPrefix+conn.ConnectionID, conn); err != nil {
		return errorResponse(msg.GetID(), "failed to update connection: "+err.Error())
	}

	log.Info().
		Str("connection_id", conn.ConnectionID).
		Str("operator_email", conn.OperatorEmail).
		Str("reason", req.Reason).
		Msg("Operator connection revoked")

	return successResponse(msg.GetID(), map[string]interface{}{
		"success":       true,
		"connection_id": conn.ConnectionID,
		"status":        "revoked",
	})
}
