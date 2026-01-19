package main

import (
	"encoding/json"
	"time"

	"github.com/rs/zerolog/log"
)

// CredentialHandler handles credential sync operations in the enclave.
// The credential blob is CEK-encrypted and synced from the mobile app.
type CredentialHandler struct {
	ownerSpace string
	storage    *EncryptedStorage
}

// NewCredentialHandler creates a new credential handler
func NewCredentialHandler(ownerSpace string, storage *EncryptedStorage) *CredentialHandler {
	return &CredentialHandler{
		ownerSpace: ownerSpace,
		storage:    storage,
	}
}

// --- Request/Response types ---

// CredentialEntry represents a stored credential
type CredentialEntry struct {
	EncryptedBlob      string    `json:"encrypted_blob"`
	EphemeralPublicKey string    `json:"ephemeral_public_key"`
	Nonce              string    `json:"nonce"`
	Version            int       `json:"version"`
	SyncedAt           time.Time `json:"synced_at"`
}

// CredentialStoreRequest is the payload for credential.store (initial enrollment)
type CredentialStoreRequest struct {
	EncryptedBlob      string `json:"encrypted_blob"`
	EphemeralPublicKey string `json:"ephemeral_public_key"`
	Nonce              string `json:"nonce"`
	Version            int    `json:"version"`
}

// CredentialSyncRequest is the payload for credential.sync (after auth rotation)
type CredentialSyncRequest struct {
	EncryptedBlob      string `json:"encrypted_blob"`
	EphemeralPublicKey string `json:"ephemeral_public_key"`
	Nonce              string `json:"nonce"`
	Version            int    `json:"version"`
}

// CredentialGetResponse is the response for credential.get
type CredentialGetResponse struct {
	EncryptedBlob      string `json:"encrypted_blob"`
	EphemeralPublicKey string `json:"ephemeral_public_key"`
	Nonce              string `json:"nonce"`
	Version            int    `json:"version"`
	SyncedAt           string `json:"synced_at"`
}

// CredentialVersionResponse is the response for credential.version
type CredentialVersionResponse struct {
	Version int  `json:"version"`
	Exists  bool `json:"exists"`
}

const credentialStorageKey = "credential/blob"

// --- Handler methods ---

// HandleStore handles credential.store messages (initial enrollment)
func (h *CredentialHandler) HandleStore(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req CredentialStoreRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.EncryptedBlob == "" {
		return h.errorResponse(msg.GetID(), "encrypted_blob is required")
	}
	if req.EphemeralPublicKey == "" {
		return h.errorResponse(msg.GetID(), "ephemeral_public_key is required")
	}
	if req.Nonce == "" {
		return h.errorResponse(msg.GetID(), "nonce is required")
	}
	if req.Version <= 0 {
		return h.errorResponse(msg.GetID(), "version must be positive")
	}

	// Check if credential already exists
	if _, err := h.storage.Get(credentialStorageKey); err == nil {
		return h.errorResponse(msg.GetID(), "credential already exists - use credential.sync to update")
	}

	entry := CredentialEntry{
		EncryptedBlob:      req.EncryptedBlob,
		EphemeralPublicKey: req.EphemeralPublicKey,
		Nonce:              req.Nonce,
		Version:            req.Version,
		SyncedAt:           time.Now().UTC(),
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to marshal credential")
	}

	if err := h.storage.Put(credentialStorageKey, data); err != nil {
		log.Error().Err(err).Msg("Failed to store credential")
		return h.errorResponse(msg.GetID(), "Failed to store credential")
	}

	log.Info().Int("version", req.Version).Msg("Credential stored")

	resp := map[string]interface{}{
		"success": true,
		"version": req.Version,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleSync handles credential.sync messages (after auth rotation)
func (h *CredentialHandler) HandleSync(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req CredentialSyncRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.EncryptedBlob == "" {
		return h.errorResponse(msg.GetID(), "encrypted_blob is required")
	}
	if req.EphemeralPublicKey == "" {
		return h.errorResponse(msg.GetID(), "ephemeral_public_key is required")
	}
	if req.Nonce == "" {
		return h.errorResponse(msg.GetID(), "nonce is required")
	}
	if req.Version <= 0 {
		return h.errorResponse(msg.GetID(), "version must be positive")
	}

	// Check existing version
	existingData, err := h.storage.Get(credentialStorageKey)
	if err == nil {
		var existing CredentialEntry
		if json.Unmarshal(existingData, &existing) == nil {
			if req.Version <= existing.Version {
				return h.errorResponse(msg.GetID(), "version must be greater than current version")
			}
		}
	}

	entry := CredentialEntry{
		EncryptedBlob:      req.EncryptedBlob,
		EphemeralPublicKey: req.EphemeralPublicKey,
		Nonce:              req.Nonce,
		Version:            req.Version,
		SyncedAt:           time.Now().UTC(),
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to marshal credential")
	}

	if err := h.storage.Put(credentialStorageKey, data); err != nil {
		log.Error().Err(err).Msg("Failed to sync credential")
		return h.errorResponse(msg.GetID(), "Failed to sync credential")
	}

	log.Info().Int("version", req.Version).Msg("Credential synced")

	resp := map[string]interface{}{
		"success": true,
		"version": req.Version,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleGet handles credential.get messages
func (h *CredentialHandler) HandleGet(msg *IncomingMessage) (*OutgoingMessage, error) {
	data, err := h.storage.Get(credentialStorageKey)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Credential not found")
	}

	var entry CredentialEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to read credential")
	}

	resp := CredentialGetResponse{
		EncryptedBlob:      entry.EncryptedBlob,
		EphemeralPublicKey: entry.EphemeralPublicKey,
		Nonce:              entry.Nonce,
		Version:            entry.Version,
		SyncedAt:           entry.SyncedAt.Format(time.RFC3339),
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleVersion handles credential.version messages
func (h *CredentialHandler) HandleVersion(msg *IncomingMessage) (*OutgoingMessage, error) {
	resp := CredentialVersionResponse{
		Exists: false,
	}

	data, err := h.storage.Get(credentialStorageKey)
	if err == nil {
		var entry CredentialEntry
		if json.Unmarshal(data, &entry) == nil {
			resp.Exists = true
			resp.Version = entry.Version
		}
	}

	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleDelete handles credential.delete messages (for vault decommission)
// SECURITY: This permanently deletes the credential blob from storage.
// Used during vault decommission to ensure clean re-enrollment.
func (h *CredentialHandler) HandleDelete(msg *IncomingMessage) (*OutgoingMessage, error) {
	// Check if credential exists
	_, err := h.storage.Get(credentialStorageKey)
	if err != nil {
		// Credential doesn't exist - that's fine for decommission, return success
		log.Info().Msg("Credential delete requested but no credential exists")
		resp := map[string]interface{}{
			"success": true,
			"deleted": false,
			"message": "no credential found",
		}
		respBytes, _ := json.Marshal(resp)
		return &OutgoingMessage{
			RequestID: msg.GetID(),
			Type:      MessageTypeResponse,
			Payload:   respBytes,
		}, nil
	}

	// Delete the credential
	if err := h.storage.Delete(credentialStorageKey); err != nil {
		log.Error().Err(err).Msg("Failed to delete credential")
		return h.errorResponse(msg.GetID(), "Failed to delete credential")
	}

	log.Info().Msg("Credential deleted successfully")

	resp := map[string]interface{}{
		"success": true,
		"deleted": true,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

func (h *CredentialHandler) errorResponse(id string, message string) (*OutgoingMessage, error) {
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
