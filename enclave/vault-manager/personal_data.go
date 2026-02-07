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
// Includes system fields (first_name, last_name, email) at top level for Android compatibility
type PersonalDataGetResponse struct {
	Success   bool                                  `json:"success"`
	FirstName string                                `json:"first_name,omitempty"`
	LastName  string                                `json:"last_name,omitempty"`
	Email     string                                `json:"email,omitempty"`
	Fields    map[string]PersonalDataFieldResponse `json:"fields"`
	Error     string                                `json:"error,omitempty"`
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

// PersonalDataUpdateSortOrderRequest is the payload for personal-data.update-sort-order
type PersonalDataUpdateSortOrderRequest struct {
	SortOrder map[string]int `json:"sort_order"` // Namespace -> sort order index
}

// --- Handler methods ---

// HandleGet handles personal-data.get messages
// Returns all personal data fields stored in the vault
func (h *PersonalDataHandler) HandleGet(msg *IncomingMessage) (*OutgoingMessage, error) {
	log.Info().Str("owner_space", h.ownerSpace).Msg("PersonalDataHandler.HandleGet called")

	var req PersonalDataGetRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		// Allow empty payload - return all fields
		req = PersonalDataGetRequest{}
	}

	result := PersonalDataGetResponse{
		Success: true,
		Fields:  make(map[string]PersonalDataFieldResponse),
	}

	// Load system fields (registration info) from profile storage
	// These are stored by PIN handler during enrollment
	systemFields := []string{"_system_first_name", "_system_last_name", "_system_email"}
	for _, field := range systemFields {
		storageKey := "profile/" + field
		data, err := h.storage.Get(storageKey)
		if err != nil {
			log.Debug().Str("field", field).Msg("System field not found in profile storage")
			continue
		}
		// Parse as ProfileEntry (same format used by profile handler)
		var entry struct {
			Value     string `json:"value"`
			UpdatedAt string `json:"updated_at"`
		}
		if err := json.Unmarshal(data, &entry); err != nil {
			log.Warn().Str("field", field).Err(err).Msg("Failed to unmarshal system field")
			continue
		}
		switch field {
		case "_system_first_name":
			result.FirstName = entry.Value
		case "_system_last_name":
			result.LastName = entry.Value
		case "_system_email":
			result.Email = entry.Value
		}
	}
	log.Debug().
		Str("first_name", result.FirstName).
		Str("last_name", result.LastName).
		Str("email", result.Email).
		Msg("Loaded system fields for personal-data.get")

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
		log.Info().Int("count", len(namespaces)).Strs("namespaces", namespaces).Msg("Loaded personal data index")
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

	// Log field names for debugging
	fieldNames := make([]string, 0, len(result.Fields))
	for name := range result.Fields {
		fieldNames = append(fieldNames, name)
	}
	log.Info().Int("fields", len(result.Fields)).Strs("field_names", fieldNames).Msg("Personal data get completed")

	respBytes, _ := json.Marshal(result)
	log.Debug().Str("response_json", string(respBytes)).Msg("Personal data response payload")
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

	var req PersonalDataUpdateRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		log.Warn().Err(err).Str("payload", string(msg.Payload)).Msg("Failed to unmarshal personal data update request")
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
	var req PersonalDataDeleteRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
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

// HandleUpdateSortOrder handles personal-data.update-sort-order messages
// Stores the display order of personal data fields in the vault
func (h *PersonalDataHandler) HandleUpdateSortOrder(msg *IncomingMessage) (*OutgoingMessage, error) {
	log.Info().Str("owner_space", h.ownerSpace).Msg("PersonalDataHandler.HandleUpdateSortOrder called")

	var req PersonalDataUpdateSortOrderRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		log.Warn().Err(err).Str("payload", string(msg.Payload)).Msg("Failed to unmarshal sort order update request")
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if len(req.SortOrder) == 0 {
		return h.errorResponse(msg.GetID(), "sort_order is required")
	}

	// Store the sort order map
	sortOrderBytes, err := json.Marshal(req.SortOrder)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal sort order")
		return h.errorResponse(msg.GetID(), "Failed to process sort order")
	}

	if err := h.storage.Put("personal-data/_sort_order", sortOrderBytes); err != nil {
		log.Error().Err(err).Msg("Failed to store sort order")
		return h.errorResponse(msg.GetID(), "Failed to store sort order")
	}

	log.Info().Int("fields", len(req.SortOrder)).Msg("Personal data sort order updated")

	resp := map[string]interface{}{
		"success":        true,
		"fields_updated": len(req.SortOrder),
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleGetSortOrder handles personal-data.get-sort-order messages
// Returns the stored display order of personal data fields
func (h *PersonalDataHandler) HandleGetSortOrder(msg *IncomingMessage) (*OutgoingMessage, error) {
	log.Info().Str("owner_space", h.ownerSpace).Msg("PersonalDataHandler.HandleGetSortOrder called")

	sortOrder := make(map[string]int)

	data, err := h.storage.Get("personal-data/_sort_order")
	if err == nil {
		if err := json.Unmarshal(data, &sortOrder); err != nil {
			log.Warn().Err(err).Msg("Failed to unmarshal sort order")
		}
	}

	resp := map[string]interface{}{
		"success":    true,
		"sort_order": sortOrder,
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

