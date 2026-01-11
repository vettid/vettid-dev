package main

import (
	"encoding/json"
	"time"

	"github.com/rs/zerolog/log"
)

// ProfileHandler handles profile-related operations in the enclave.
// Profile fields are encrypted values stored in the vault.
type ProfileHandler struct {
	ownerSpace string
	storage    *EncryptedStorage
}

// NewProfileHandler creates a new profile handler
func NewProfileHandler(ownerSpace string, storage *EncryptedStorage) *ProfileHandler {
	return &ProfileHandler{
		ownerSpace: ownerSpace,
		storage:    storage,
	}
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
