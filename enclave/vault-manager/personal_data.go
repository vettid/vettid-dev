package main

import (
	"encoding/json"
	"time"

	"github.com/rs/zerolog/log"
)

// PersonalDataHandler handles personal data operations in the enclave.
// Personal data is private data stored in the vault - separate from public profile.
type PersonalDataHandler struct {
	ownerSpace string
	storage    *EncryptedStorage
}

// NewPersonalDataHandler creates a new personal data handler
func NewPersonalDataHandler(ownerSpace string, storage *EncryptedStorage) *PersonalDataHandler {
	return &PersonalDataHandler{
		ownerSpace: ownerSpace,
		storage:    storage,
	}
}

// --- Request/Response types ---

// PersonalDataEntry represents a stored personal data field
type PersonalDataEntry struct {
	Namespace string    `json:"namespace"`
	Value     string    `json:"value"`
	UpdatedAt time.Time `json:"updated_at"`
}

// PersonalDataGetRequest is the payload for personal-data.get
type PersonalDataGetRequest struct {
	Namespaces []string `json:"namespaces,omitempty"` // Specific namespaces (empty = all)
}

// PersonalDataGetResponse is the response for personal-data.get
type PersonalDataGetResponse struct {
	Success bool                                  `json:"success"`
	Fields  map[string]PersonalDataFieldResponse `json:"fields"`
	Error   string                                `json:"error,omitempty"`
}

// PersonalDataFieldResponse represents a single personal data field in responses
type PersonalDataFieldResponse struct {
	Value     string `json:"value"`
	UpdatedAt string `json:"updated_at"`
}

// PersonalDataUpdateRequest is the payload for personal-data.update
type PersonalDataUpdateRequest struct {
	Fields map[string]string `json:"fields"` // Namespace -> value
}

// PersonalDataDeleteRequest is the payload for personal-data.delete
type PersonalDataDeleteRequest struct {
	Namespaces []string `json:"namespaces"` // Namespaces to delete
}

// --- Handler methods ---

// HandleGet handles personal-data.get messages
// Returns all personal data fields stored in the vault
func (h *PersonalDataHandler) HandleGet(msg *IncomingMessage) (*OutgoingMessage, error) {
	log.Info().Str("owner_space", h.ownerSpace).Msg("PersonalDataHandler.HandleGet called")

	// Extract inner payload from envelope format
	payload := h.extractInnerPayload(msg.Payload)

	var req PersonalDataGetRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		// Allow empty payload - return all fields
		req = PersonalDataGetRequest{}
	}

	result := PersonalDataGetResponse{
		Success: true,
		Fields:  make(map[string]PersonalDataFieldResponse),
	}

	// Get the list of namespaces to return
	namespaces := req.Namespaces
	if len(namespaces) == 0 {
		// Load full index of all personal data fields
		indexData, err := h.storage.Get("personal-data/_index")
		if err == nil {
			if err := json.Unmarshal(indexData, &namespaces); err != nil {
				log.Warn().Err(err).Msg("Failed to unmarshal personal data index")
			}
		}
		log.Debug().Int("count", len(namespaces)).Msg("Loaded personal data index")
	}

	// Load each field
	for _, namespace := range namespaces {
		storageKey := "personal-data/" + namespace
		data, err := h.storage.Get(storageKey)
		if err != nil {
			log.Debug().Str("namespace", namespace).Msg("Personal data field not found")
			continue
		}

		var entry PersonalDataEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			log.Warn().Str("namespace", namespace).Err(err).Msg("Failed to unmarshal personal data entry")
			continue
		}

		result.Fields[namespace] = PersonalDataFieldResponse{
			Value:     entry.Value,
			UpdatedAt: entry.UpdatedAt.Format(time.RFC3339),
		}
	}

	log.Info().Int("fields", len(result.Fields)).Msg("Personal data get completed")

	respBytes, _ := json.Marshal(result)
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleUpdate handles personal-data.update messages
// Stores or updates personal data fields in the vault
func (h *PersonalDataHandler) HandleUpdate(msg *IncomingMessage) (*OutgoingMessage, error) {
	log.Info().Str("owner_space", h.ownerSpace).Msg("PersonalDataHandler.HandleUpdate called")

	// Extract inner payload from envelope format
	// Android sends: {"type": "personal-data.update", "payload": {"fields": {...}}}
	payload := h.extractInnerPayload(msg.Payload)

	var req PersonalDataUpdateRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		log.Warn().Err(err).Str("payload", string(payload)).Msg("Failed to unmarshal personal data update request")
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if len(req.Fields) == 0 {
		return h.errorResponse(msg.GetID(), "fields are required")
	}

	now := time.Now().UTC()
	updatedCount := 0

	// Load existing index
	var fieldIndex []string
	indexData, err := h.storage.Get("personal-data/_index")
	if err == nil {
		json.Unmarshal(indexData, &fieldIndex)
	}
	if fieldIndex == nil {
		fieldIndex = []string{}
	}

	log.Debug().Int("existing_index_size", len(fieldIndex)).Int("fields_to_update", len(req.Fields)).Msg("Updating personal data")

	for namespace, value := range req.Fields {
		entry := PersonalDataEntry{
			Namespace: namespace,
			Value:     value,
			UpdatedAt: now,
		}

		data, err := json.Marshal(entry)
		if err != nil {
			log.Warn().Str("namespace", namespace).Err(err).Msg("Failed to marshal personal data entry")
			continue
		}

		storageKey := "personal-data/" + namespace
		if err := h.storage.Put(storageKey, data); err != nil {
			log.Warn().Str("namespace", namespace).Err(err).Msg("Failed to store personal data field")
			continue
		}

		// Add to index if not present
		if !containsString(fieldIndex, namespace) {
			fieldIndex = append(fieldIndex, namespace)
		}

		updatedCount++
		log.Debug().Str("namespace", namespace).Msg("Personal data field updated")
	}

	// Always save the index (even if it was empty before)
	indexBytes, _ := json.Marshal(fieldIndex)
	if err := h.storage.Put("personal-data/_index", indexBytes); err != nil {
		log.Warn().Err(err).Msg("Failed to update personal data index")
	} else {
		log.Debug().Int("index_size", len(fieldIndex)).Msg("Personal data index updated")
	}

	log.Info().Int("updated", updatedCount).Msg("Personal data update completed")

	resp := map[string]interface{}{
		"success":        true,
		"fields_updated": updatedCount,
		"updated_at":     now.Format(time.RFC3339),
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleDelete handles personal-data.delete messages
// Removes personal data fields from the vault
func (h *PersonalDataHandler) HandleDelete(msg *IncomingMessage) (*OutgoingMessage, error) {
	// Extract inner payload from envelope format
	payload := h.extractInnerPayload(msg.Payload)

	var req PersonalDataDeleteRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if len(req.Namespaces) == 0 {
		return h.errorResponse(msg.GetID(), "namespaces are required")
	}

	deletedCount := 0
	for _, namespace := range req.Namespaces {
		storageKey := "personal-data/" + namespace
		if err := h.storage.Delete(storageKey); err == nil {
			deletedCount++
		}
	}

	// Update index
	indexData, err := h.storage.Get("personal-data/_index")
	if err == nil {
		var fieldIndex []string
		if json.Unmarshal(indexData, &fieldIndex) == nil {
			newIndex := make([]string, 0)
			for _, ns := range fieldIndex {
				if !containsString(req.Namespaces, ns) {
					newIndex = append(newIndex, ns)
				}
			}
			indexBytes, _ := json.Marshal(newIndex)
			h.storage.Put("personal-data/_index", indexBytes)
		}
	}

	log.Info().Int("deleted", deletedCount).Msg("Personal data fields deleted")

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

func (h *PersonalDataHandler) errorResponse(id string, message string) (*OutgoingMessage, error) {
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

// extractInnerPayload extracts the inner payload from the message envelope format.
// Android sends: {"type": "...", "payload": {...}}
// This function returns just the inner payload, or the original data if not in envelope format.
func (h *PersonalDataHandler) extractInnerPayload(data json.RawMessage) json.RawMessage {
	if len(data) == 0 {
		return data
	}

	// Try to parse as envelope format
	var envelope struct {
		Type    string          `json:"type"`
		Payload json.RawMessage `json:"payload"`
	}

	if err := json.Unmarshal(data, &envelope); err != nil {
		// Not valid JSON or not envelope format - return original
		return data
	}

	// If there's a nested payload, return it
	if len(envelope.Payload) > 0 {
		log.Debug().
			Str("type", envelope.Type).
			Int("payload_len", len(envelope.Payload)).
			Msg("Extracted inner payload from envelope")
		return envelope.Payload
	}

	// No nested payload - return original (flat format)
	return data
}
