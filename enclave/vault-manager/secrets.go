package main

import (
	"encoding/json"
	"time"

	"github.com/rs/zerolog/log"
)

// SecretsHandler handles secrets-related operations in the enclave.
// Secrets are stored encrypted in the vault's storage.
type SecretsHandler struct {
	ownerSpace string
	storage    *EncryptedStorage
}

// NewSecretsHandler creates a new secrets handler
func NewSecretsHandler(ownerSpace string, storage *EncryptedStorage) *SecretsHandler {
	return &SecretsHandler{
		ownerSpace: ownerSpace,
		storage:    storage,
	}
}

// --- Request/Response types ---

// SecretMetadata contains metadata about a secret
type SecretMetadata struct {
	Category  string   `json:"category,omitempty"`
	Tags      []string `json:"tags,omitempty"`
	CreatedAt string   `json:"created_at,omitempty"`
	UpdatedAt string   `json:"updated_at,omitempty"`
}

// SecretEntry represents a stored secret
type SecretEntry struct {
	Key       string         `json:"key"`
	Value     string         `json:"value"` // Pre-encrypted by client
	Metadata  SecretMetadata `json:"metadata"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

// SecretsAddRequest is the payload for secrets.datastore.add
type SecretsAddRequest struct {
	Key      string         `json:"key"`
	Value    string         `json:"value"` // Pre-encrypted by client
	Metadata SecretMetadata `json:"metadata"`
}

// SecretsUpdateRequest is the payload for secrets.datastore.update
type SecretsUpdateRequest struct {
	Key      string          `json:"key"`
	Value    string          `json:"value"`
	Metadata *SecretMetadata `json:"metadata,omitempty"`
}

// SecretsRetrieveRequest is the payload for secrets.datastore.retrieve
type SecretsRetrieveRequest struct {
	Key string `json:"key"`
}

// SecretsRetrieveResponse is the response for secrets.datastore.retrieve
type SecretsRetrieveResponse struct {
	Key      string         `json:"key"`
	Value    string         `json:"value"`
	Metadata SecretMetadata `json:"metadata"`
}

// SecretsDeleteRequest is the payload for secrets.datastore.delete
type SecretsDeleteRequest struct {
	Key string `json:"key"`
}

// SecretsListRequest is the payload for secrets.datastore.list
type SecretsListRequest struct {
	Category string `json:"category,omitempty"`
	Tag      string `json:"tag,omitempty"`
	Limit    int    `json:"limit,omitempty"`
}

// SecretListItem represents a secret in list response
type SecretListItem struct {
	Key       string         `json:"key"`
	Metadata  SecretMetadata `json:"metadata"`
	UpdatedAt string         `json:"updated_at"`
}

// SecretsListResponse is the response for secrets.datastore.list
type SecretsListResponse struct {
	Items []SecretListItem `json:"items"`
}

// --- Handler methods ---

// HandleAdd handles secrets.datastore.add messages
func (h *SecretsHandler) HandleAdd(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req SecretsAddRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.Key == "" {
		return h.errorResponse(msg.GetID(), "key is required")
	}
	if req.Value == "" {
		return h.errorResponse(msg.GetID(), "value is required")
	}

	// Check if secret already exists
	storageKey := "secrets/" + req.Key
	if _, err := h.storage.Get(storageKey); err == nil {
		return h.errorResponse(msg.GetID(), "Secret already exists - use update to modify")
	}

	now := time.Now().UTC()
	entry := SecretEntry{
		Key:       req.Key,
		Value:     req.Value,
		Metadata:  req.Metadata,
		CreatedAt: now,
		UpdatedAt: now,
	}
	entry.Metadata.CreatedAt = now.Format(time.RFC3339)
	entry.Metadata.UpdatedAt = now.Format(time.RFC3339)

	data, err := json.Marshal(entry)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to marshal secret")
	}

	if err := h.storage.Put(storageKey, data); err != nil {
		log.Error().Err(err).Str("key", req.Key).Msg("Failed to store secret")
		return h.errorResponse(msg.GetID(), "Failed to store secret")
	}

	log.Info().Str("key", req.Key).Msg("Secret added")

	resp := map[string]interface{}{
		"success": true,
		"key":     req.Key,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleUpdate handles secrets.datastore.update messages
func (h *SecretsHandler) HandleUpdate(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req SecretsUpdateRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.Key == "" {
		return h.errorResponse(msg.GetID(), "key is required")
	}
	if req.Value == "" {
		return h.errorResponse(msg.GetID(), "value is required")
	}

	storageKey := "secrets/" + req.Key

	// Get existing secret
	existingData, err := h.storage.Get(storageKey)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Secret not found")
	}

	var entry SecretEntry
	if err := json.Unmarshal(existingData, &entry); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to read existing secret")
	}

	// Update fields
	entry.Value = req.Value
	entry.UpdatedAt = time.Now().UTC()
	entry.Metadata.UpdatedAt = entry.UpdatedAt.Format(time.RFC3339)
	if req.Metadata != nil {
		if req.Metadata.Category != "" {
			entry.Metadata.Category = req.Metadata.Category
		}
		if len(req.Metadata.Tags) > 0 {
			entry.Metadata.Tags = req.Metadata.Tags
		}
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to marshal secret")
	}

	if err := h.storage.Put(storageKey, data); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to update secret")
	}

	log.Info().Str("key", req.Key).Msg("Secret updated")

	resp := map[string]interface{}{
		"success": true,
		"key":     req.Key,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleRetrieve handles secrets.datastore.retrieve messages
func (h *SecretsHandler) HandleRetrieve(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req SecretsRetrieveRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.Key == "" {
		return h.errorResponse(msg.GetID(), "key is required")
	}

	storageKey := "secrets/" + req.Key
	data, err := h.storage.Get(storageKey)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Secret not found")
	}

	var entry SecretEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to read secret")
	}

	resp := SecretsRetrieveResponse{
		Key:      entry.Key,
		Value:    entry.Value,
		Metadata: entry.Metadata,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleDelete handles secrets.datastore.delete messages
func (h *SecretsHandler) HandleDelete(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req SecretsDeleteRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.Key == "" {
		return h.errorResponse(msg.GetID(), "key is required")
	}

	storageKey := "secrets/" + req.Key
	if err := h.storage.Delete(storageKey); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to delete secret")
	}

	log.Info().Str("key", req.Key).Msg("Secret deleted")

	resp := map[string]interface{}{
		"success": true,
		"key":     req.Key,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleList handles secrets.datastore.list messages
func (h *SecretsHandler) HandleList(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req SecretsListRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	// For enclave, we return an empty list since we don't have KV enumeration
	// The app should track its own keys
	resp := SecretsListResponse{
		Items: []SecretListItem{},
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

func (h *SecretsHandler) errorResponse(id string, message string) (*OutgoingMessage, error) {
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
