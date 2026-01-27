package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
)

// ProfileHandler handles profile-related operations in the enclave.
// Profile fields are encrypted values stored in the vault.
type ProfileHandler struct {
	ownerSpace string
	storage    *EncryptedStorage
	publisher  *VsockPublisher
	vaultState *VaultState
}

// NewProfileHandler creates a new profile handler
func NewProfileHandler(ownerSpace string, storage *EncryptedStorage) *ProfileHandler {
	return &ProfileHandler{
		ownerSpace: ownerSpace,
		storage:    storage,
	}
}

// SetPublisher sets the publisher for NATS publishing (called after MessageHandler creation)
func (h *ProfileHandler) SetPublisher(publisher *VsockPublisher) {
	h.publisher = publisher
}

// SetVaultState sets the vault state reference for accessing crypto keys
func (h *ProfileHandler) SetVaultState(state *VaultState) {
	h.vaultState = state
}

// --- Request/Response types ---

// ProfileEntry represents a stored profile field
type ProfileEntry struct {
	Field     string    `json:"field"`
	Value     string    `json:"value"` // Encrypted value
	UpdatedAt time.Time `json:"updated_at"`
}

// ProfileGetRequest is the payload for profile.get
type ProfileGetRequest struct {
	Fields []string `json:"fields,omitempty"` // Specific fields (empty = all known)
}

// ProfileGetResponse is the response for profile.get
type ProfileGetResponse struct {
	Fields map[string]ProfileFieldResponse `json:"fields"`
}

// ProfileFieldResponse represents a single profile field
type ProfileFieldResponse struct {
	Value     string `json:"value"`
	UpdatedAt string `json:"updated_at"`
}

// ProfileUpdateRequest is the payload for profile.update
type ProfileUpdateRequest struct {
	Fields map[string]string `json:"fields"` // Field name -> encrypted value
}

// ProfileDeleteRequest is the payload for profile.delete
type ProfileDeleteRequest struct {
	Fields []string `json:"fields"` // Fields to delete
}

// ProfileGetSharedRequest is the payload for profile.get-shared
type ProfileGetSharedRequest struct {
	ConnectionID string `json:"connection_id,omitempty"` // Optional: apply connection-specific overrides
}

// ProfileGetSharedResponse is the response for profile.get-shared
type ProfileGetSharedResponse struct {
	Fields map[string]ProfileFieldResponse `json:"fields"`
}

// SharingSettings controls which profile fields are shared
type SharingSettings struct {
	DefaultShared        []string            `json:"default_shared"`         // Fields shared by default
	ConnectionOverrides  map[string][]string `json:"connection_overrides"`   // connection_id -> fields
	UpdatedAt            int64               `json:"updated_at"`
}

// --- Handler methods ---

// HandleGet handles profile.get messages
func (h *ProfileHandler) HandleGet(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req ProfileGetRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	result := ProfileGetResponse{
		Fields: make(map[string]ProfileFieldResponse),
	}

	if len(req.Fields) == 0 {
		// Get profile index to find all fields
		indexData, err := h.storage.Get("profile/_index")
		if err == nil {
			var fieldNames []string
			if json.Unmarshal(indexData, &fieldNames) == nil {
				req.Fields = fieldNames
			}
		}
	}

	// Get specific fields
	for _, field := range req.Fields {
		storageKey := "profile/" + field
		data, err := h.storage.Get(storageKey)
		if err != nil {
			continue // Skip missing fields
		}

		var entry ProfileEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			continue
		}

		result.Fields[field] = ProfileFieldResponse{
			Value:     entry.Value,
			UpdatedAt: entry.UpdatedAt.Format(time.RFC3339),
		}
	}

	respBytes, _ := json.Marshal(result)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleUpdate handles profile.update messages
func (h *ProfileHandler) HandleUpdate(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req ProfileUpdateRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if len(req.Fields) == 0 {
		return h.errorResponse(msg.GetID(), "fields are required")
	}

	now := time.Now().UTC()
	updatedFields := 0

	// Get existing index
	var fieldIndex []string
	indexData, err := h.storage.Get("profile/_index")
	if err == nil {
		json.Unmarshal(indexData, &fieldIndex)
	}

	for field, value := range req.Fields {
		entry := ProfileEntry{
			Field:     field,
			Value:     value,
			UpdatedAt: now,
		}

		data, err := json.Marshal(entry)
		if err != nil {
			continue
		}

		storageKey := "profile/" + field
		if err := h.storage.Put(storageKey, data); err != nil {
			log.Warn().Err(err).Str("field", field).Msg("Failed to update profile field")
			continue
		}

		// Add to index if not present
		if !containsString(fieldIndex, field) {
			fieldIndex = append(fieldIndex, field)
		}

		updatedFields++
	}

	// Update index
	if len(fieldIndex) > 0 {
		indexBytes, _ := json.Marshal(fieldIndex)
		h.storage.Put("profile/_index", indexBytes)
	}

	log.Info().Int("fields", updatedFields).Msg("Profile updated")

	resp := map[string]interface{}{
		"success":        true,
		"fields_updated": updatedFields,
		"updated_at":     now.Format(time.RFC3339),
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleDelete handles profile.delete messages
func (h *ProfileHandler) HandleDelete(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req ProfileDeleteRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if len(req.Fields) == 0 {
		return h.errorResponse(msg.GetID(), "fields are required")
	}

	deletedCount := 0
	for _, field := range req.Fields {
		storageKey := "profile/" + field
		if err := h.storage.Delete(storageKey); err == nil {
			deletedCount++
		}
	}

	// Update index
	indexData, err := h.storage.Get("profile/_index")
	if err == nil {
		var fieldIndex []string
		if json.Unmarshal(indexData, &fieldIndex) == nil {
			newIndex := make([]string, 0)
			for _, f := range fieldIndex {
				if !containsString(req.Fields, f) {
					newIndex = append(newIndex, f)
				}
			}
			indexBytes, _ := json.Marshal(newIndex)
			h.storage.Put("profile/_index", indexBytes)
		}
	}

	log.Info().Int("fields", deletedCount).Msg("Profile fields deleted")

	resp := map[string]interface{}{
		"success":        true,
		"fields_deleted": deletedCount,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleGetShared handles profile.get-shared messages
// Returns profile fields filtered by sharing settings
func (h *ProfileHandler) HandleGetShared(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req ProfileGetSharedRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		// Allow empty payload
		req = ProfileGetSharedRequest{}
	}

	// Load sharing settings
	settings, err := h.loadSharingSettings()
	if err != nil {
		// If no sharing settings exist, return empty profile
		result := ProfileGetSharedResponse{
			Fields: make(map[string]ProfileFieldResponse),
		}
		respBytes, _ := json.Marshal(result)
		return &OutgoingMessage{
			RequestID: msg.GetID(),
			Type:      MessageTypeResponse,
			Payload:   respBytes,
		}, nil
	}

	// Determine which fields to share
	fieldsToShare := settings.DefaultShared

	// Apply connection-specific overrides if connection_id is provided
	if req.ConnectionID != "" && settings.ConnectionOverrides != nil {
		if override, exists := settings.ConnectionOverrides[req.ConnectionID]; exists {
			fieldsToShare = override
		}
	}

	// Get the shared fields
	result := ProfileGetSharedResponse{
		Fields: make(map[string]ProfileFieldResponse),
	}

	for _, field := range fieldsToShare {
		storageKey := "profile/" + field
		data, err := h.storage.Get(storageKey)
		if err != nil {
			continue // Skip missing fields
		}

		var entry ProfileEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			continue
		}

		result.Fields[field] = ProfileFieldResponse{
			Value:     entry.Value,
			UpdatedAt: entry.UpdatedAt.Format(time.RFC3339),
		}
	}

	respBytes, _ := json.Marshal(result)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleUpdateSharingSettings handles profile.sharing-settings.update messages
func (h *ProfileHandler) HandleUpdateSharingSettings(msg *IncomingMessage) (*OutgoingMessage, error) {
	var settings SharingSettings
	if err := json.Unmarshal(msg.Payload, &settings); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	settings.UpdatedAt = time.Now().Unix()

	data, err := json.Marshal(settings)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to marshal settings")
	}

	if err := h.storage.Put("profile/_sharing_settings", data); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to save sharing settings")
	}

	log.Info().Msg("Profile sharing settings updated")

	resp := map[string]interface{}{
		"success": true,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleGetSharingSettings handles profile.sharing-settings.get messages
func (h *ProfileHandler) HandleGetSharingSettings(msg *IncomingMessage) (*OutgoingMessage, error) {
	settings, err := h.loadSharingSettings()
	if err != nil {
		// Return empty settings if none exist
		settings = &SharingSettings{
			DefaultShared:       []string{},
			ConnectionOverrides: make(map[string][]string),
		}
	}

	respBytes, _ := json.Marshal(settings)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// loadSharingSettings loads the sharing settings from storage
func (h *ProfileHandler) loadSharingSettings() (*SharingSettings, error) {
	data, err := h.storage.Get("profile/_sharing_settings")
	if err != nil {
		return nil, err
	}

	var settings SharingSettings
	if err := json.Unmarshal(data, &settings); err != nil {
		return nil, err
	}

	return &settings, nil
}

func (h *ProfileHandler) errorResponse(id string, message string) (*OutgoingMessage, error) {
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

// containsString checks if a string is in a slice
func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

// HandleCategoriesGet handles profile.categories.get messages
// Returns both predefined and custom categories
func (h *ProfileHandler) HandleCategoriesGet(msg *IncomingMessage) (*OutgoingMessage, error) {
	// Load custom categories from storage
	var customCategories []CustomCategory
	data, err := h.storage.Get("profile/_categories")
	if err == nil {
		json.Unmarshal(data, &customCategories)
	}
	if customCategories == nil {
		customCategories = []CustomCategory{}
	}

	response := ProfileCategoriesGetResponse{
		Predefined: PredefinedCategories,
		Custom:     customCategories,
	}

	respBytes, _ := json.Marshal(response)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleCategoriesUpdate handles profile.categories.update messages
// Updates the list of custom categories
func (h *ProfileHandler) HandleCategoriesUpdate(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req ProfileCategoriesUpdateRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	// Store custom categories
	data, err := json.Marshal(req.Categories)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to serialize categories")
	}

	if err := h.storage.Put("profile/_categories", data); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to save categories")
	}

	log.Info().Int("count", len(req.Categories)).Msg("Custom categories updated")

	resp := map[string]interface{}{
		"success": true,
		"count":   len(req.Categories),
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandlePublish handles profile.publish messages
// Creates and publishes the public profile to NATS
func (h *ProfileHandler) HandlePublish(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req ProfilePublishRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		// Allow empty payload - use existing settings
		req = ProfilePublishRequest{}
	}

	now := time.Now()
	nowUnix := now.Unix()

	// Load current public profile settings
	var settings PublicProfileSettings
	settingsData, err := h.storage.Get("profile/_public")
	if err == nil {
		json.Unmarshal(settingsData, &settings)
	}

	// Update fields if provided
	if len(req.Fields) > 0 {
		settings.Fields = req.Fields
	}
	settings.UpdatedAt = nowUnix
	settings.PublishedAt = nowUnix
	settings.Version++

	// Save updated settings
	settingsBytes, _ := json.Marshal(settings)
	if err := h.storage.Put("profile/_public", settingsBytes); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to save public profile settings")
	}

	// Build published profile
	profile := PublishedProfile{
		UserGUID:      h.ownerSpace,
		EmailVerified: true, // Assume verified during registration
		Fields:        make(map[string]PublishedField),
		Version:       settings.Version,
		UpdatedAt:     now.Format(time.RFC3339),
	}

	// Get public key from vault state
	if h.vaultState != nil {
		h.vaultState.mu.RLock()
		if h.vaultState.credential != nil && h.vaultState.credential.IdentityPublicKey != nil {
			profile.PublicKey = base64.StdEncoding.EncodeToString(h.vaultState.credential.IdentityPublicKey)
		}
		h.vaultState.mu.RUnlock()
	}

	// Load system fields (registration info) - always included
	systemFields := []string{"_system_first_name", "_system_last_name", "_system_email"}
	for _, field := range systemFields {
		data, err := h.storage.Get("profile/" + field)
		if err != nil {
			continue
		}
		var entry ProfileEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			continue
		}
		switch field {
		case "_system_first_name":
			profile.FirstName = entry.Value
		case "_system_last_name":
			profile.LastName = entry.Value
		case "_system_email":
			profile.Email = entry.Value
		}
	}

	// Load selected personal data fields
	for _, fieldName := range settings.Fields {
		data, err := h.storage.Get("profile/" + fieldName)
		if err != nil {
			continue
		}

		// Try to parse as PersonalDataField first
		var field PersonalDataField
		if err := json.Unmarshal(data, &field); err != nil {
			// Fall back to ProfileEntry format
			var entry ProfileEntry
			if err := json.Unmarshal(data, &entry); err != nil {
				continue
			}
			profile.Fields[fieldName] = PublishedField{
				DisplayName: fieldName,
				Value:       entry.Value,
				FieldType:   string(FieldTypeText),
			}
			continue
		}

		// Skip sensitive fields
		if field.IsSensitive {
			log.Warn().Str("field", fieldName).Msg("Skipping sensitive field from public profile")
			continue
		}

		profile.Fields[fieldName] = PublishedField{
			DisplayName: field.DisplayName,
			Value:       field.Value,
			FieldType:   string(field.FieldType),
		}
	}

	// Publish to NATS
	if h.publisher != nil {
		profileBytes, err := json.Marshal(profile)
		if err != nil {
			log.Error().Err(err).Msg("Failed to serialize public profile")
		} else {
			subject := fmt.Sprintf("%s.profile.public", h.ownerSpace)
			if err := h.publisher.PublishRaw(subject, profileBytes); err != nil {
				log.Error().Err(err).Str("subject", subject).Msg("Failed to publish public profile")
				// Don't fail the request if NATS publish fails
			} else {
				log.Info().
					Str("owner_space", h.ownerSpace).
					Int("version", settings.Version).
					Int("field_count", len(profile.Fields)).
					Msg("Public profile published to NATS")
			}
		}
	}

	response := ProfilePublishResponse{
		Success:     true,
		Version:     settings.Version,
		PublishedAt: now.Format(time.RFC3339),
	}

	respBytes, _ := json.Marshal(response)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandlePublicSettingsGet handles profile.public.get messages
// Returns the current public profile settings (which fields are shared)
func (h *ProfileHandler) HandlePublicSettingsGet(msg *IncomingMessage) (*OutgoingMessage, error) {
	var settings PublicProfileSettings
	data, err := h.storage.Get("profile/_public")
	if err == nil {
		json.Unmarshal(data, &settings)
	} else {
		// Return empty settings if none exist
		settings = PublicProfileSettings{
			Version: 0,
			Fields:  []string{},
		}
	}

	respBytes, _ := json.Marshal(settings)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandlePublicSettingsUpdate handles profile.public.update messages
// Updates which fields are included in the public profile (without publishing)
func (h *ProfileHandler) HandlePublicSettingsUpdate(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		Fields []string `json:"fields"`
	}
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	// Load existing settings
	var settings PublicProfileSettings
	data, err := h.storage.Get("profile/_public")
	if err == nil {
		json.Unmarshal(data, &settings)
	}

	// Update fields
	settings.Fields = req.Fields
	settings.UpdatedAt = time.Now().Unix()
	settings.Version++

	// Save settings
	settingsBytes, _ := json.Marshal(settings)
	if err := h.storage.Put("profile/_public", settingsBytes); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to save settings")
	}

	log.Info().
		Int("version", settings.Version).
		Int("field_count", len(req.Fields)).
		Msg("Public profile settings updated")

	resp := map[string]interface{}{
		"success": true,
		"version": settings.Version,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}
