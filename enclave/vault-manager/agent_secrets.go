package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
)

// AgentSecretsHandler manages secrets that have been explicitly shared
// with agent connections by the vault owner via the mobile app.
//
// Storage namespace: agent-secrets/{secret_id}
// Index: agent-secrets/_index ([]string of secret IDs)
//
// These are separate from the existing secrets/{key} namespace which
// holds client-pre-encrypted secrets. Agent-shared secrets contain
// plaintext values at the Go level because the vault owner sends them
// inside E2E-encrypted envelopes from the mobile app. The underlying
// SQLite storage layer encrypts all data at rest.
type AgentSecretsHandler struct {
	ownerSpace   string
	storage      *EncryptedStorage
	eventHandler *EventHandler
}

// NewAgentSecretsHandler creates a new agent secrets handler.
func NewAgentSecretsHandler(ownerSpace string, storage *EncryptedStorage, eventHandler *EventHandler) *AgentSecretsHandler {
	return &AgentSecretsHandler{
		ownerSpace:   ownerSpace,
		storage:      storage,
		eventHandler: eventHandler,
	}
}

// --- Storage types ---

// AgentSharedSecret represents a secret shared for agent access.
type AgentSharedSecret struct {
	SecretID       string   `json:"secret_id"`
	Name           string   `json:"name"`
	Category       string   `json:"category"`                  // "api_keys", "ssh_keys", etc.
	Description    string   `json:"description,omitempty"`
	Tags           []string `json:"tags,omitempty"`
	Value          string   `json:"value"`                     // Plaintext (storage is encrypted at rest)
	AllowedActions []string `json:"allowed_actions"`           // ["retrieve"], ["use"], or ["retrieve","use"]
	CreatedAt      string   `json:"created_at"`
	UpdatedAt      string   `json:"updated_at"`
}

// --- Request/Response types for app operations ---

// ShareSecretRequest is the payload for agent-secrets.share
type ShareSecretRequest struct {
	SecretID       string   `json:"secret_id,omitempty"`        // Auto-generated if empty
	Name           string   `json:"name"`
	Category       string   `json:"category"`
	Description    string   `json:"description,omitempty"`
	Tags           []string `json:"tags,omitempty"`
	Value          string   `json:"value"`
	AllowedActions []string `json:"allowed_actions"`
}

// ShareSecretResponse is the response for agent-secrets.share
type ShareSecretResponse struct {
	Success  bool   `json:"success"`
	SecretID string `json:"secret_id"`
}

// UpdateSharedSecretRequest is the payload for agent-secrets.update
type UpdateSharedSecretRequest struct {
	SecretID       string   `json:"secret_id"`
	Name           string   `json:"name,omitempty"`
	Category       string   `json:"category,omitempty"`
	Description    string   `json:"description,omitempty"`
	Tags           []string `json:"tags,omitempty"`
	Value          string   `json:"value,omitempty"`
	AllowedActions []string `json:"allowed_actions,omitempty"`
}

// RevokeSharedSecretRequest is the payload for agent-secrets.revoke
type RevokeSharedSecretRequest struct {
	SecretID string `json:"secret_id"`
}

// ListSharedSecretsRequest is the payload for agent-secrets.list
type ListSharedSecretsRequest struct {
	Category string `json:"category,omitempty"` // Filter by category
}

// SharedSecretInfo is a secret entry in list responses (no value exposed).
type SharedSecretInfo struct {
	SecretID       string   `json:"secret_id"`
	Name           string   `json:"name"`
	Category       string   `json:"category"`
	Description    string   `json:"description,omitempty"`
	Tags           []string `json:"tags,omitempty"`
	AllowedActions []string `json:"allowed_actions"`
	CreatedAt      string   `json:"created_at"`
	UpdatedAt      string   `json:"updated_at"`
}

// ListSharedSecretsResponse is the response for agent-secrets.list
type ListSharedSecretsResponse struct {
	Secrets []SharedSecretInfo `json:"secrets"`
}

// ApproveSecretRequestPayload is the payload for agent-secrets.approve
type ApproveSecretRequestPayload struct {
	RequestID string `json:"request_id"`
	Approved  bool   `json:"approved"`
}

// --- Catalog types (sent to agents) ---

// AgentSecretCatalogEntry describes a single secret available to the agent.
// Does NOT include the secret value.
type AgentSecretCatalogEntry struct {
	SecretID       string   `json:"secret_id"`
	Name           string   `json:"name"`
	Category       string   `json:"category"`
	Description    string   `json:"description,omitempty"`
	Tags           []string `json:"tags,omitempty"`
	AllowedActions []string `json:"allowed_actions"`
	UpdatedAt      string   `json:"updated_at,omitempty"`
}

// AgentSecretCatalog is a versioned list of secrets pushed to an agent.
type AgentSecretCatalog struct {
	Entries   []AgentSecretCatalogEntry `json:"entries"`
	Version   uint64                    `json:"version"`
	UpdatedAt string                    `json:"updated_at"`
}

// --- App-facing handler methods ---

// HandleShareSecret stores a secret for agent access.
func (h *AgentSecretsHandler) HandleShareSecret(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req ShareSecretRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.Name == "" {
		return h.errorResponse(msg.GetID(), "name is required")
	}
	if req.Category == "" {
		return h.errorResponse(msg.GetID(), "category is required")
	}
	if req.Value == "" {
		return h.errorResponse(msg.GetID(), "value is required")
	}
	if len(req.AllowedActions) == 0 {
		return h.errorResponse(msg.GetID(), "allowed_actions is required")
	}

	// Validate allowed_actions
	for _, action := range req.AllowedActions {
		if action != "retrieve" && action != "use" {
			return h.errorResponse(msg.GetID(), fmt.Sprintf("invalid action: %s (must be 'retrieve' or 'use')", action))
		}
	}

	secretID := req.SecretID
	if secretID == "" {
		secretID = generateMessageID()
	}

	now := time.Now().UTC().Format(time.RFC3339)
	secret := AgentSharedSecret{
		SecretID:       secretID,
		Name:           req.Name,
		Category:       req.Category,
		Description:    req.Description,
		Tags:           req.Tags,
		Value:          req.Value,
		AllowedActions: req.AllowedActions,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	data, err := json.Marshal(secret)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to store secret")
	}

	if err := h.storage.Put("agent-secrets/"+secretID, data); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to store secret")
	}

	h.addToIndex(secretID)

	// Log event
	if h.eventHandler != nil {
		h.eventHandler.LogSecretEvent(context.Background(), EventTypeSecretAdded, secretID, req.Name, req.Category)
	}

	log.Info().
		Str("secret_id", secretID).
		Str("name", req.Name).
		Str("category", req.Category).
		Msg("Agent secret shared")

	respBytes, _ := json.Marshal(ShareSecretResponse{
		Success:  true,
		SecretID: secretID,
	})

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleUpdateSharedSecret updates an existing agent-shared secret.
func (h *AgentSecretsHandler) HandleUpdateSharedSecret(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req UpdateSharedSecretRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.SecretID == "" {
		return h.errorResponse(msg.GetID(), "secret_id is required")
	}

	secret, err := h.GetSecret(req.SecretID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Secret not found")
	}

	// Apply updates
	if req.Name != "" {
		secret.Name = req.Name
	}
	if req.Category != "" {
		secret.Category = req.Category
	}
	if req.Description != "" {
		secret.Description = req.Description
	}
	if req.Tags != nil {
		secret.Tags = req.Tags
	}
	if req.Value != "" {
		secret.Value = req.Value
	}
	if len(req.AllowedActions) > 0 {
		for _, action := range req.AllowedActions {
			if action != "retrieve" && action != "use" {
				return h.errorResponse(msg.GetID(), fmt.Sprintf("invalid action: %s", action))
			}
		}
		secret.AllowedActions = req.AllowedActions
	}

	secret.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

	data, err := json.Marshal(secret)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to update secret")
	}

	if err := h.storage.Put("agent-secrets/"+req.SecretID, data); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to update secret")
	}

	log.Info().
		Str("secret_id", req.SecretID).
		Msg("Agent secret updated")

	respBytes, _ := json.Marshal(map[string]interface{}{
		"success":   true,
		"secret_id": req.SecretID,
	})

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleRevokeSharedSecret removes a secret from agent access.
func (h *AgentSecretsHandler) HandleRevokeSharedSecret(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req RevokeSharedSecretRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.SecretID == "" {
		return h.errorResponse(msg.GetID(), "secret_id is required")
	}

	// Verify it exists before deleting
	secret, err := h.GetSecret(req.SecretID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Secret not found")
	}

	if err := h.storage.Delete("agent-secrets/" + req.SecretID); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to revoke secret")
	}

	h.removeFromIndex(req.SecretID)

	// Log event
	if h.eventHandler != nil {
		h.eventHandler.LogSecretEvent(context.Background(), EventTypeSecretDeleted, req.SecretID, secret.Name, secret.Category)
	}

	log.Info().
		Str("secret_id", req.SecretID).
		Msg("Agent secret revoked")

	respBytes, _ := json.Marshal(map[string]interface{}{
		"success":   true,
		"secret_id": req.SecretID,
	})

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleListSharedSecrets returns all agent-shared secrets (without values).
func (h *AgentSecretsHandler) HandleListSharedSecrets(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req ListSharedSecretsRequest
	if len(msg.Payload) > 0 {
		json.Unmarshal(msg.Payload, &req)
	}

	index := h.getIndex()
	var secrets []SharedSecretInfo

	for _, id := range index {
		secret, err := h.GetSecret(id)
		if err != nil {
			continue
		}

		// Filter by category if specified
		if req.Category != "" && secret.Category != req.Category {
			continue
		}

		secrets = append(secrets, SharedSecretInfo{
			SecretID:       secret.SecretID,
			Name:           secret.Name,
			Category:       secret.Category,
			Description:    secret.Description,
			Tags:           secret.Tags,
			AllowedActions: secret.AllowedActions,
			CreatedAt:      secret.CreatedAt,
			UpdatedAt:      secret.UpdatedAt,
		})
	}

	if secrets == nil {
		secrets = []SharedSecretInfo{}
	}

	respBytes, _ := json.Marshal(ListSharedSecretsResponse{
		Secrets: secrets,
	})

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// --- Internal methods ---

// GetSecret retrieves a single agent-shared secret by ID.
func (h *AgentSecretsHandler) GetSecret(secretID string) (*AgentSharedSecret, error) {
	data, err := h.storage.Get("agent-secrets/" + secretID)
	if err != nil {
		return nil, fmt.Errorf("secret not found: %s", secretID)
	}

	var secret AgentSharedSecret
	if err := json.Unmarshal(data, &secret); err != nil {
		return nil, fmt.Errorf("failed to unmarshal secret: %w", err)
	}

	return &secret, nil
}

// BuildCatalog builds a catalog of secrets filtered by the connection's scope.
// Scope is a list of categories (e.g., ["api_keys", "ssh_keys"]).
// An empty scope matches all categories.
func (h *AgentSecretsHandler) BuildCatalog(scope []string) *AgentSecretCatalog {
	index := h.getIndex()
	scopeSet := make(map[string]bool, len(scope))
	for _, s := range scope {
		scopeSet[s] = true
	}

	var entries []AgentSecretCatalogEntry

	for _, id := range index {
		secret, err := h.GetSecret(id)
		if err != nil {
			continue
		}

		// Filter by scope if specified
		if len(scopeSet) > 0 && !scopeSet[secret.Category] {
			continue
		}

		entries = append(entries, AgentSecretCatalogEntry{
			SecretID:       secret.SecretID,
			Name:           secret.Name,
			Category:       secret.Category,
			Description:    secret.Description,
			Tags:           secret.Tags,
			AllowedActions: secret.AllowedActions,
			UpdatedAt:      secret.UpdatedAt,
		})
	}

	if entries == nil {
		entries = []AgentSecretCatalogEntry{}
	}

	return &AgentSecretCatalog{
		Entries:   entries,
		Version:   h.getCatalogVersion(),
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

// InScope checks whether a secret's category is allowed by the given scope.
// An empty scope allows all categories.
func InScope(category string, scope []string) bool {
	if len(scope) == 0 {
		return true
	}
	for _, s := range scope {
		if s == category {
			return true
		}
	}
	return false
}

// HasAction checks if a specific action is in the allowed actions list.
func HasAction(action string, allowedActions []string) bool {
	for _, a := range allowedActions {
		if a == action {
			return true
		}
	}
	return false
}

// --- Index management ---

func (h *AgentSecretsHandler) getIndex() []string {
	var index []string
	data, err := h.storage.Get("agent-secrets/_index")
	if err == nil {
		json.Unmarshal(data, &index)
	}
	return index
}

func (h *AgentSecretsHandler) addToIndex(secretID string) {
	index := h.getIndex()
	for _, id := range index {
		if id == secretID {
			return
		}
	}
	index = append(index, secretID)
	data, _ := json.Marshal(index)
	h.storage.Put("agent-secrets/_index", data)

	// Increment catalog version
	h.incrementCatalogVersion()
}

func (h *AgentSecretsHandler) removeFromIndex(secretID string) {
	index := h.getIndex()
	newIndex := make([]string, 0, len(index))
	for _, id := range index {
		if id != secretID {
			newIndex = append(newIndex, id)
		}
	}
	data, _ := json.Marshal(newIndex)
	h.storage.Put("agent-secrets/_index", data)

	// Increment catalog version
	h.incrementCatalogVersion()
}

func (h *AgentSecretsHandler) getCatalogVersion() uint64 {
	data, err := h.storage.Get("agent-secrets/_catalog_version")
	if err != nil {
		return 0
	}
	var version uint64
	json.Unmarshal(data, &version)
	return version
}

func (h *AgentSecretsHandler) incrementCatalogVersion() {
	version := h.getCatalogVersion() + 1
	data, _ := json.Marshal(version)
	h.storage.Put("agent-secrets/_catalog_version", data)
}

// --- Error response helper ---

func (h *AgentSecretsHandler) errorResponse(id string, message string) (*OutgoingMessage, error) {
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
