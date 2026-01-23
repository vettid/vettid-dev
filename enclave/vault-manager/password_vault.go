package main

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// DEV-040: Password Vault (User Secrets) Data Model
// User-managed password vault for storing credentials, API keys, secure notes, etc.
// This is distinct from SecretsHandler (secrets.go) which handles critical vault secrets.

// --- Password Vault Categories ---

// PasswordCategory defines the type of password vault entry
type PasswordCategory string

const (
	PasswordCategoryLogin      PasswordCategory = "login"
	PasswordCategoryCard       PasswordCategory = "card"
	PasswordCategoryIdentity   PasswordCategory = "identity"
	PasswordCategorySecureNote PasswordCategory = "secure_note"
	PasswordCategoryAPIKey     PasswordCategory = "api_key"
	PasswordCategoryCrypto     PasswordCategory = "crypto_wallet"
	PasswordCategoryCustom     PasswordCategory = "custom"
)

// PasswordFieldType defines the type of field for UI rendering
type PasswordFieldType string

const (
	PasswordFieldText     PasswordFieldType = "text"
	PasswordFieldPassword PasswordFieldType = "password"
	PasswordFieldURL      PasswordFieldType = "url"
	PasswordFieldEmail    PasswordFieldType = "email"
	PasswordFieldPhone    PasswordFieldType = "phone"
	PasswordFieldDate     PasswordFieldType = "date"
	PasswordFieldTOTP     PasswordFieldType = "totp"     // Time-based OTP secret
	PasswordFieldNumber   PasswordFieldType = "number"
	PasswordFieldTextArea PasswordFieldType = "textarea"
)

// PasswordField represents a single field in a password entry
type PasswordField struct {
	Name    string            `json:"name"`
	Value   string            `json:"value"`   // Encrypted at rest
	Type    PasswordFieldType `json:"type"`
	Visible bool              `json:"visible"` // Show in list view
}

// PasswordEntry represents a stored password/secret (DEV-040)
type PasswordEntry struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Category    PasswordCategory `json:"category"`
	Fields      []PasswordField  `json:"fields"`
	Notes       string           `json:"notes,omitempty"`
	Tags        []string         `json:"tags,omitempty"`
	Favorite    bool             `json:"favorite"`
	CreatedAt   time.Time        `json:"created_at"`
	UpdatedAt   time.Time        `json:"updated_at"`
	LastViewed  *time.Time       `json:"last_viewed,omitempty"`
	DeletedAt   *time.Time       `json:"deleted_at,omitempty"` // Soft delete for sync
	SyncVersion int64            `json:"sync_version"`
}

// PasswordSummary is a lightweight version for list views (no field values)
type PasswordSummary struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Category    PasswordCategory `json:"category"`
	Tags        []string         `json:"tags,omitempty"`
	Favorite    bool             `json:"favorite"`
	UpdatedAt   time.Time        `json:"updated_at"`
	LastViewed  *time.Time       `json:"last_viewed,omitempty"`
	SyncVersion int64            `json:"sync_version"`
}

// PasswordChange represents a change for sync protocol (DEV-042)
type PasswordChange struct {
	EntryID    string         `json:"entry_id"`
	ChangeType PasswordChangeType `json:"change_type"`
	Timestamp  time.Time      `json:"timestamp"`
	DeviceID   string         `json:"device_id"`
	Data       *PasswordEntry `json:"data,omitempty"`
}

// PasswordChangeType for sync
type PasswordChangeType string

const (
	PasswordChangeCreate PasswordChangeType = "create"
	PasswordChangeUpdate PasswordChangeType = "update"
	PasswordChangeDelete PasswordChangeType = "delete"
)

// --- Request/Response Types ---

// CreatePasswordRequest is the payload for password.create
type CreatePasswordRequest struct {
	Name     string           `json:"name"`
	Category PasswordCategory `json:"category"`
	Fields   []PasswordField  `json:"fields"`
	Notes    string           `json:"notes,omitempty"`
	Tags     []string         `json:"tags,omitempty"`
	Favorite bool             `json:"favorite,omitempty"`
}

// CreatePasswordResponse is the response for password.create
type CreatePasswordResponse struct {
	ID          string    `json:"id"`
	SyncVersion int64     `json:"sync_version"`
	CreatedAt   time.Time `json:"created_at"`
}

// GetPasswordRequest is the payload for password.get
type GetPasswordRequest struct {
	ID string `json:"id"`
}

// GetPasswordResponse is the response for password.get
type GetPasswordResponse struct {
	Entry PasswordEntry `json:"entry"`
}

// UpdatePasswordRequest is the payload for password.update
type UpdatePasswordRequest struct {
	ID       string            `json:"id"`
	Name     *string           `json:"name,omitempty"`
	Category *PasswordCategory `json:"category,omitempty"`
	Fields   *[]PasswordField  `json:"fields,omitempty"`
	Notes    *string           `json:"notes,omitempty"`
	Tags     *[]string         `json:"tags,omitempty"`
	Favorite *bool             `json:"favorite,omitempty"`
}

// UpdatePasswordResponse is the response for password.update
type UpdatePasswordResponse struct {
	Success     bool      `json:"success"`
	SyncVersion int64     `json:"sync_version"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// DeletePasswordRequest is the payload for password.delete
type DeletePasswordRequest struct {
	ID         string `json:"id"`
	HardDelete bool   `json:"hard_delete,omitempty"` // true = permanent, false = soft delete
}

// DeletePasswordResponse is the response for password.delete
type DeletePasswordResponse struct {
	Success     bool  `json:"success"`
	SyncVersion int64 `json:"sync_version"`
}

// ListPasswordsRequest is the payload for password.list
type ListPasswordsRequest struct {
	Category *PasswordCategory `json:"category,omitempty"`
	Tag      *string           `json:"tag,omitempty"`
	Favorite *bool             `json:"favorite,omitempty"`
	Offset   int               `json:"offset,omitempty"`
	Limit    int               `json:"limit,omitempty"`
}

// ListPasswordsResponse is the response for password.list
type ListPasswordsResponse struct {
	Entries []PasswordSummary `json:"entries"`
	Total   int               `json:"total"`
	HasMore bool              `json:"has_more"`
}

// SearchPasswordsRequest is the payload for password.search
type SearchPasswordsRequest struct {
	Query string `json:"query"`
	Limit int    `json:"limit,omitempty"`
}

// SearchPasswordsResponse is the response for password.search
type SearchPasswordsResponse struct {
	Entries []PasswordSummary `json:"entries"`
}

// SyncPasswordsRequest is the payload for password.sync (DEV-042)
type SyncPasswordsRequest struct {
	LastSyncVersion int64  `json:"last_sync_version"`
	DeviceID        string `json:"device_id"`
}

// SyncPasswordsResponse is the response for password.sync
type SyncPasswordsResponse struct {
	Changes       []PasswordChange `json:"changes"`
	LatestVersion int64            `json:"latest_version"`
	HasMore       bool             `json:"has_more"`
}

// --- Password Vault Handler ---

// PasswordVaultHandler handles password vault operations (DEV-040/041)
type PasswordVaultHandler struct {
	ownerSpace string
	storage    *EncryptedStorage
}

// NewPasswordVaultHandler creates a new password vault handler
func NewPasswordVaultHandler(ownerSpace string, storage *EncryptedStorage) *PasswordVaultHandler {
	return &PasswordVaultHandler{
		ownerSpace: ownerSpace,
		storage:    storage,
	}
}

func (h *PasswordVaultHandler) errorResponse(requestID, message string) (*OutgoingMessage, error) {
	resp := map[string]interface{}{
		"success": false,
		"error":   message,
	}
	respBytes, _ := json.Marshal(resp)
	return &OutgoingMessage{
		RequestID: requestID,
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleCreate handles password.create
func (h *PasswordVaultHandler) HandleCreate(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req CreatePasswordRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.Name == "" {
		return h.errorResponse(msg.GetID(), "name is required")
	}
	if req.Category == "" {
		return h.errorResponse(msg.GetID(), "category is required")
	}
	if !isValidPasswordCategory(req.Category) {
		return h.errorResponse(msg.GetID(), "invalid category")
	}

	now := time.Now()
	id := generateUUID()
	entry := PasswordEntry{
		ID:          id,
		Name:        req.Name,
		Category:    req.Category,
		Fields:      req.Fields,
		Notes:       req.Notes,
		Tags:        req.Tags,
		Favorite:    req.Favorite,
		CreatedAt:   now,
		UpdatedAt:   now,
		SyncVersion: 1,
	}

	if err := h.storeEntry(&entry); err != nil {
		log.Error().Err(err).Str("name", req.Name).Msg("Failed to store password entry")
		return h.errorResponse(msg.GetID(), "Failed to create entry")
	}

	h.addToIndex(id)

	log.Info().Str("id", entry.ID).Str("category", string(req.Category)).Msg("Password entry created")

	resp := CreatePasswordResponse{
		ID:          entry.ID,
		SyncVersion: entry.SyncVersion,
		CreatedAt:   entry.CreatedAt,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleGet handles password.get
func (h *PasswordVaultHandler) HandleGet(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req GetPasswordRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ID == "" {
		return h.errorResponse(msg.GetID(), "id is required")
	}

	entry, err := h.getEntry(req.ID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Entry not found")
	}

	// Update last_viewed timestamp
	now := time.Now()
	entry.LastViewed = &now
	h.storeEntry(entry)

	resp := GetPasswordResponse{Entry: *entry}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleUpdate handles password.update
func (h *PasswordVaultHandler) HandleUpdate(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req UpdatePasswordRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ID == "" {
		return h.errorResponse(msg.GetID(), "id is required")
	}

	entry, err := h.getEntry(req.ID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Entry not found")
	}

	// Apply partial updates
	if req.Name != nil {
		entry.Name = *req.Name
	}
	if req.Category != nil {
		if !isValidPasswordCategory(*req.Category) {
			return h.errorResponse(msg.GetID(), "invalid category")
		}
		entry.Category = *req.Category
	}
	if req.Fields != nil {
		entry.Fields = *req.Fields
	}
	if req.Notes != nil {
		entry.Notes = *req.Notes
	}
	if req.Tags != nil {
		entry.Tags = *req.Tags
	}
	if req.Favorite != nil {
		entry.Favorite = *req.Favorite
	}

	entry.UpdatedAt = time.Now()
	entry.SyncVersion++

	if err := h.storeEntry(entry); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to update entry")
	}

	log.Info().Str("id", entry.ID).Int64("sync_version", entry.SyncVersion).Msg("Password entry updated")

	resp := UpdatePasswordResponse{
		Success:     true,
		SyncVersion: entry.SyncVersion,
		UpdatedAt:   entry.UpdatedAt,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleDelete handles password.delete
func (h *PasswordVaultHandler) HandleDelete(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req DeletePasswordRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ID == "" {
		return h.errorResponse(msg.GetID(), "id is required")
	}

	entry, err := h.getEntry(req.ID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Entry not found")
	}

	if req.HardDelete {
		if err := h.storage.Delete("passwords/" + req.ID); err != nil {
			return h.errorResponse(msg.GetID(), "Failed to delete entry")
		}
		h.removeFromIndex(req.ID)
	} else {
		// Soft delete (tombstone for sync)
		now := time.Now()
		entry.DeletedAt = &now
		entry.SyncVersion++
		if err := h.storeEntry(entry); err != nil {
			return h.errorResponse(msg.GetID(), "Failed to delete entry")
		}
	}

	log.Info().Str("id", req.ID).Bool("hard_delete", req.HardDelete).Msg("Password entry deleted")

	resp := DeletePasswordResponse{
		Success:     true,
		SyncVersion: entry.SyncVersion,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleList handles password.list
func (h *PasswordVaultHandler) HandleList(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req ListPasswordsRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		req = ListPasswordsRequest{Limit: 50}
	}

	if req.Limit <= 0 {
		req.Limit = 50
	}
	if req.Limit > 100 {
		req.Limit = 100
	}

	entries, total, err := h.listEntries(req)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to list entries")
	}

	resp := ListPasswordsResponse{
		Entries: entries,
		Total:   total,
		HasMore: req.Offset+len(entries) < total,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleSearch handles password.search
func (h *PasswordVaultHandler) HandleSearch(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req SearchPasswordsRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.Query == "" {
		return h.errorResponse(msg.GetID(), "query is required")
	}
	if req.Limit <= 0 {
		req.Limit = 20
	}

	entries, err := h.searchEntries(req.Query, req.Limit)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Search failed")
	}

	resp := SearchPasswordsResponse{Entries: entries}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// --- Storage Helpers ---

func (h *PasswordVaultHandler) storeEntry(entry *PasswordEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	return h.storage.Put("passwords/"+entry.ID, data)
}

func (h *PasswordVaultHandler) getEntry(id string) (*PasswordEntry, error) {
	data, err := h.storage.Get("passwords/" + id)
	if err != nil {
		return nil, err
	}

	var entry PasswordEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, err
	}

	return &entry, nil
}

func (h *PasswordVaultHandler) addToIndex(entryID string) error {
	indexKey := "passwords/_index"
	indexData, _ := h.storage.Get(indexKey)

	var entryIDs []string
	if indexData != nil {
		json.Unmarshal(indexData, &entryIDs)
	}

	for _, id := range entryIDs {
		if id == entryID {
			return nil
		}
	}

	entryIDs = append(entryIDs, entryID)
	newIndexData, _ := json.Marshal(entryIDs)
	return h.storage.Put(indexKey, newIndexData)
}

func (h *PasswordVaultHandler) removeFromIndex(entryID string) error {
	indexKey := "passwords/_index"
	indexData, _ := h.storage.Get(indexKey)

	var entryIDs []string
	if indexData != nil {
		json.Unmarshal(indexData, &entryIDs)
	}

	var newIDs []string
	for _, id := range entryIDs {
		if id != entryID {
			newIDs = append(newIDs, id)
		}
	}

	newIndexData, _ := json.Marshal(newIDs)
	return h.storage.Put(indexKey, newIndexData)
}

func (h *PasswordVaultHandler) listEntries(req ListPasswordsRequest) ([]PasswordSummary, int, error) {
	indexData, err := h.storage.Get("passwords/_index")
	var entryIDs []string
	if err == nil {
		json.Unmarshal(indexData, &entryIDs)
	}

	var summaries []PasswordSummary
	for _, id := range entryIDs {
		entry, err := h.getEntry(id)
		if err != nil || entry.DeletedAt != nil {
			continue
		}

		// Apply filters
		if req.Category != nil && entry.Category != *req.Category {
			continue
		}
		if req.Favorite != nil && entry.Favorite != *req.Favorite {
			continue
		}
		if req.Tag != nil {
			hasTag := false
			for _, t := range entry.Tags {
				if t == *req.Tag {
					hasTag = true
					break
				}
			}
			if !hasTag {
				continue
			}
		}

		summaries = append(summaries, PasswordSummary{
			ID:          entry.ID,
			Name:        entry.Name,
			Category:    entry.Category,
			Tags:        entry.Tags,
			Favorite:    entry.Favorite,
			UpdatedAt:   entry.UpdatedAt,
			LastViewed:  entry.LastViewed,
			SyncVersion: entry.SyncVersion,
		})
	}

	total := len(summaries)

	start := req.Offset
	if start > total {
		start = total
	}
	end := start + req.Limit
	if end > total {
		end = total
	}

	if start >= len(summaries) {
		return []PasswordSummary{}, total, nil
	}

	return summaries[start:end], total, nil
}

func (h *PasswordVaultHandler) searchEntries(query string, limit int) ([]PasswordSummary, error) {
	indexData, err := h.storage.Get("passwords/_index")
	var entryIDs []string
	if err == nil {
		json.Unmarshal(indexData, &entryIDs)
	}

	queryLower := strings.ToLower(query)
	var results []PasswordSummary
	for _, id := range entryIDs {
		if len(results) >= limit {
			break
		}

		entry, err := h.getEntry(id)
		if err != nil || entry.DeletedAt != nil {
			continue
		}

		// Check if name or tags contain query (case-insensitive)
		matches := strings.Contains(strings.ToLower(entry.Name), queryLower)
		if !matches {
			for _, tag := range entry.Tags {
				if strings.Contains(strings.ToLower(tag), queryLower) {
					matches = true
					break
				}
			}
		}

		if matches {
			results = append(results, PasswordSummary{
				ID:          entry.ID,
				Name:        entry.Name,
				Category:    entry.Category,
				Tags:        entry.Tags,
				Favorite:    entry.Favorite,
				UpdatedAt:   entry.UpdatedAt,
				LastViewed:  entry.LastViewed,
				SyncVersion: entry.SyncVersion,
			})
		}
	}

	return results, nil
}

// =======================================
// DEV-042: Sync Protocol
// =======================================

// HandleSync handles password.sync for multi-device synchronization
func (h *PasswordVaultHandler) HandleSync(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req SyncPasswordsRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.DeviceID == "" {
		return h.errorResponse(msg.GetID(), "device_id is required")
	}

	// Get all changes since last sync version
	changes, latestVersion, err := h.getChangesSince(req.LastSyncVersion)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to get changes")
	}

	// Tag changes with requesting device ID for conflict tracking
	for i := range changes {
		changes[i].DeviceID = req.DeviceID
	}

	resp := SyncPasswordsResponse{
		Changes:       changes,
		LatestVersion: latestVersion,
		HasMore:       false, // Would be true if paginating large changesets
	}
	respBytes, _ := json.Marshal(resp)

	log.Info().
		Str("device_id", req.DeviceID).
		Int64("from_version", req.LastSyncVersion).
		Int("changes", len(changes)).
		Msg("Password sync completed")

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// getChangesSince returns all password entries changed since the given sync version
func (h *PasswordVaultHandler) getChangesSince(sinceVersion int64) ([]PasswordChange, int64, error) {
	indexData, err := h.storage.Get("passwords/_index")
	var entryIDs []string
	if err == nil {
		json.Unmarshal(indexData, &entryIDs)
	}

	var changes []PasswordChange
	var latestVersion int64 = sinceVersion

	for _, id := range entryIDs {
		entry, err := h.getEntry(id)
		if err != nil {
			continue
		}

		// Track latest version seen
		if entry.SyncVersion > latestVersion {
			latestVersion = entry.SyncVersion
		}

		// Only include entries changed since requested version
		if entry.SyncVersion <= sinceVersion {
			continue
		}

		var changeType PasswordChangeType
		if entry.DeletedAt != nil {
			changeType = PasswordChangeDelete
		} else if entry.SyncVersion == 1 {
			changeType = PasswordChangeCreate
		} else {
			changeType = PasswordChangeUpdate
		}

		changes = append(changes, PasswordChange{
			EntryID:    entry.ID,
			ChangeType: changeType,
			Timestamp:  entry.UpdatedAt,
			Data:       entry,
		})
	}

	return changes, latestVersion, nil
}

// ApplyRemoteChanges applies changes received from another device
// Implements last-write-wins conflict resolution
func (h *PasswordVaultHandler) ApplyRemoteChanges(changes []PasswordChange) error {
	for _, change := range changes {
		switch change.ChangeType {
		case PasswordChangeCreate, PasswordChangeUpdate:
			if change.Data == nil {
				continue
			}

			// Check for conflict with local version
			existingEntry, err := h.getEntry(change.EntryID)
			if err == nil {
				// Entry exists locally - use last-write-wins
				if existingEntry.UpdatedAt.After(change.Timestamp) {
					// Local version is newer, skip remote change
					log.Debug().
						Str("entry_id", change.EntryID).
						Msg("Skipping remote change - local version is newer")
					continue
				}
			}

			// Apply remote change
			if err := h.storeEntry(change.Data); err != nil {
				log.Error().Err(err).Str("entry_id", change.EntryID).Msg("Failed to apply remote change")
				continue
			}

			// Ensure entry is in index
			h.addToIndex(change.EntryID)

		case PasswordChangeDelete:
			// For deletes, we soft-delete to preserve tombstone
			existingEntry, err := h.getEntry(change.EntryID)
			if err != nil {
				continue // Already deleted or doesn't exist
			}

			// Check if local has newer changes
			if existingEntry.UpdatedAt.After(change.Timestamp) && existingEntry.DeletedAt == nil {
				// Local has been updated after delete was issued
				log.Debug().
					Str("entry_id", change.EntryID).
					Msg("Skipping remote delete - local version is newer")
				continue
			}

			// Apply soft delete
			existingEntry.DeletedAt = &change.Timestamp
			existingEntry.SyncVersion++
			h.storeEntry(existingEntry)
		}
	}

	return nil
}

// GetSyncVersion returns the current highest sync version
func (h *PasswordVaultHandler) GetSyncVersion() int64 {
	indexData, err := h.storage.Get("passwords/_index")
	var entryIDs []string
	if err == nil {
		json.Unmarshal(indexData, &entryIDs)
	}

	var maxVersion int64 = 0
	for _, id := range entryIDs {
		entry, err := h.getEntry(id)
		if err != nil {
			continue
		}
		if entry.SyncVersion > maxVersion {
			maxVersion = entry.SyncVersion
		}
	}

	return maxVersion
}

// CleanupTombstones removes soft-deleted entries older than the retention period
// Should be called periodically (e.g., once per day)
func (h *PasswordVaultHandler) CleanupTombstones(retentionDays int) (int, error) {
	indexData, err := h.storage.Get("passwords/_index")
	var entryIDs []string
	if err == nil {
		json.Unmarshal(indexData, &entryIDs)
	}

	cutoff := time.Now().AddDate(0, 0, -retentionDays)
	var cleaned int

	for _, id := range entryIDs {
		entry, err := h.getEntry(id)
		if err != nil {
			continue
		}

		// Only clean up tombstones (soft-deleted entries)
		if entry.DeletedAt != nil && entry.DeletedAt.Before(cutoff) {
			h.storage.Delete("passwords/" + id)
			h.removeFromIndex(id)
			cleaned++
		}
	}

	if cleaned > 0 {
		log.Info().Int("cleaned", cleaned).Int("retention_days", retentionDays).Msg("Cleaned up password tombstones")
	}

	return cleaned, nil
}

// --- Helper Functions ---

func isValidPasswordCategory(cat PasswordCategory) bool {
	switch cat {
	case PasswordCategoryLogin, PasswordCategoryCard, PasswordCategoryIdentity,
		PasswordCategorySecureNote, PasswordCategoryAPIKey, PasswordCategoryCrypto,
		PasswordCategoryCustom:
		return true
	}
	return false
}
