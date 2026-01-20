package main

import (
	"encoding/json"
	"time"

	"github.com/rs/zerolog/log"
)

// SettingsHandler handles user settings and preferences.
// This includes notification settings and other user-configurable options.
type SettingsHandler struct {
	ownerSpace string
	storage    *EncryptedStorage
}

// NewSettingsHandler creates a new settings handler
func NewSettingsHandler(ownerSpace string, storage *EncryptedStorage) *SettingsHandler {
	return &SettingsHandler{
		ownerSpace: ownerSpace,
		storage:    storage,
	}
}

// --- Storage types ---

// NotificationSettings controls notification preferences
type NotificationSettings struct {
	GlobalEnabled       bool              `json:"global_enabled"`
	QuietHoursEnabled   bool              `json:"quiet_hours_enabled"`
	QuietHoursStart     string            `json:"quiet_hours_start"` // "22:00" format
	QuietHoursEnd       string            `json:"quiet_hours_end"`   // "08:00" format
	DigestMode          string            `json:"digest_mode"`       // "realtime", "hourly", "daily"
	ConnectionOverrides map[string]string `json:"connection_overrides"` // connection_id -> "all", "important", "none"
	PriorityConnections []string          `json:"priority_connections"` // connections that bypass quiet hours
	UpdatedAt           int64             `json:"updated_at"`
}

// DigestEntry represents a single notification in a digest
type DigestEntry struct {
	EventID      string `json:"event_id"`
	Type         string `json:"type"`
	ConnectionID string `json:"connection_id,omitempty"`
	Title        string `json:"title"`
	Body         string `json:"body,omitempty"`
	Timestamp    string `json:"timestamp"`
	IsRead       bool   `json:"is_read"`
}

// --- Request/Response types ---

// NotificationSettingsUpdateRequest is the payload for settings.notifications.update
type NotificationSettingsUpdateRequest struct {
	GlobalEnabled       *bool             `json:"global_enabled,omitempty"`
	QuietHoursEnabled   *bool             `json:"quiet_hours_enabled,omitempty"`
	QuietHoursStart     string            `json:"quiet_hours_start,omitempty"`
	QuietHoursEnd       string            `json:"quiet_hours_end,omitempty"`
	DigestMode          string            `json:"digest_mode,omitempty"`
	ConnectionOverrides map[string]string `json:"connection_overrides,omitempty"`
	PriorityConnections []string          `json:"priority_connections,omitempty"`
}

// NotificationDigestRequest is the payload for notifications.digest
type NotificationDigestRequest struct {
	Since string `json:"since,omitempty"` // RFC3339 timestamp
	Limit int    `json:"limit,omitempty"`
}

// NotificationDigestResponse is the response for notifications.digest
type NotificationDigestResponse struct {
	Entries     []DigestEntry `json:"entries"`
	Total       int           `json:"total"`
	UnreadCount int           `json:"unread_count"`
	Since       string        `json:"since"`
	Until       string        `json:"until"`
}

// --- Handler methods ---

// HandleNotificationsUpdate handles settings.notifications.update messages
func (h *SettingsHandler) HandleNotificationsUpdate(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req NotificationSettingsUpdateRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	// Load existing settings
	settings, err := h.loadNotificationSettings()
	if err != nil {
		// Initialize with defaults
		settings = &NotificationSettings{
			GlobalEnabled:       true,
			QuietHoursEnabled:   false,
			QuietHoursStart:     "22:00",
			QuietHoursEnd:       "08:00",
			DigestMode:          "realtime",
			ConnectionOverrides: make(map[string]string),
			PriorityConnections: []string{},
		}
	}

	// Apply updates
	if req.GlobalEnabled != nil {
		settings.GlobalEnabled = *req.GlobalEnabled
	}
	if req.QuietHoursEnabled != nil {
		settings.QuietHoursEnabled = *req.QuietHoursEnabled
	}
	if req.QuietHoursStart != "" {
		settings.QuietHoursStart = req.QuietHoursStart
	}
	if req.QuietHoursEnd != "" {
		settings.QuietHoursEnd = req.QuietHoursEnd
	}
	if req.DigestMode != "" {
		// Validate digest mode
		validModes := map[string]bool{"realtime": true, "hourly": true, "daily": true}
		if !validModes[req.DigestMode] {
			return h.errorResponse(msg.GetID(), "Invalid digest_mode")
		}
		settings.DigestMode = req.DigestMode
	}
	if req.ConnectionOverrides != nil {
		settings.ConnectionOverrides = req.ConnectionOverrides
	}
	if req.PriorityConnections != nil {
		settings.PriorityConnections = req.PriorityConnections
	}

	settings.UpdatedAt = time.Now().Unix()

	// Save settings
	data, err := json.Marshal(settings)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to marshal settings")
	}

	if err := h.storage.Put("settings/notifications", data); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to save settings")
	}

	log.Info().Msg("Notification settings updated")

	resp := map[string]interface{}{
		"success":  true,
		"settings": settings,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleNotificationsGet handles settings.notifications.get messages
func (h *SettingsHandler) HandleNotificationsGet(msg *IncomingMessage) (*OutgoingMessage, error) {
	settings, err := h.loadNotificationSettings()
	if err != nil {
		// Return defaults if no settings exist
		settings = &NotificationSettings{
			GlobalEnabled:       true,
			QuietHoursEnabled:   false,
			QuietHoursStart:     "22:00",
			QuietHoursEnd:       "08:00",
			DigestMode:          "realtime",
			ConnectionOverrides: make(map[string]string),
			PriorityConnections: []string{},
		}
	}

	respBytes, _ := json.Marshal(settings)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleNotificationsDigest handles notifications.digest messages
func (h *SettingsHandler) HandleNotificationsDigest(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req NotificationDigestRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		// Allow empty payload
		req = NotificationDigestRequest{}
	}

	// Default to last 24 hours if no since time provided
	var sinceTime time.Time
	if req.Since != "" {
		var err error
		sinceTime, err = time.Parse(time.RFC3339, req.Since)
		if err != nil {
			return h.errorResponse(msg.GetID(), "Invalid since timestamp format")
		}
	} else {
		sinceTime = time.Now().Add(-24 * time.Hour)
	}

	limit := req.Limit
	if limit <= 0 {
		limit = 50
	}

	// Get digest entries from storage
	entries, unreadCount, err := h.collectDigestEntries(sinceTime, limit)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to collect digest entries")
	}

	resp := NotificationDigestResponse{
		Entries:     entries,
		Total:       len(entries),
		UnreadCount: unreadCount,
		Since:       sinceTime.Format(time.RFC3339),
		Until:       time.Now().Format(time.RFC3339),
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// collectDigestEntries collects notification entries from feed events
func (h *SettingsHandler) collectDigestEntries(since time.Time, limit int) ([]DigestEntry, int, error) {
	// Get feed events index
	indexData, err := h.storage.Get("feed/_index")
	if err != nil {
		// No events yet
		return []DigestEntry{}, 0, nil
	}

	var eventIDs []string
	if err := json.Unmarshal(indexData, &eventIDs); err != nil {
		return []DigestEntry{}, 0, err
	}

	entries := make([]DigestEntry, 0)
	unreadCount := 0

	for _, eventID := range eventIDs {
		if len(entries) >= limit {
			break
		}

		data, err := h.storage.Get("feed/" + eventID)
		if err != nil {
			continue
		}

		var event struct {
			EventID      string `json:"event_id"`
			Type         string `json:"type"`
			ConnectionID string `json:"connection_id,omitempty"`
			Title        string `json:"title"`
			Body         string `json:"body,omitempty"`
			Timestamp    string `json:"timestamp"`
			IsRead       bool   `json:"is_read"`
		}

		if err := json.Unmarshal(data, &event); err != nil {
			continue
		}

		// Parse timestamp
		eventTime, err := time.Parse(time.RFC3339, event.Timestamp)
		if err != nil {
			continue
		}

		// Skip events before since time
		if eventTime.Before(since) {
			continue
		}

		entry := DigestEntry{
			EventID:      event.EventID,
			Type:         event.Type,
			ConnectionID: event.ConnectionID,
			Title:        event.Title,
			Body:         event.Body,
			Timestamp:    event.Timestamp,
			IsRead:       event.IsRead,
		}

		entries = append(entries, entry)

		if !event.IsRead {
			unreadCount++
		}
	}

	return entries, unreadCount, nil
}

// IsInQuietHours checks if the current time is within quiet hours
func (h *SettingsHandler) IsInQuietHours() bool {
	settings, err := h.loadNotificationSettings()
	if err != nil || !settings.QuietHoursEnabled {
		return false
	}

	now := time.Now()
	currentTime := now.Format("15:04")

	start := settings.QuietHoursStart
	end := settings.QuietHoursEnd

	// Handle overnight quiet hours (e.g., 22:00 to 08:00)
	if start > end {
		return currentTime >= start || currentTime < end
	}

	return currentTime >= start && currentTime < end
}

// ShouldNotify checks if notifications should be sent for a connection
func (h *SettingsHandler) ShouldNotify(connectionID string) bool {
	settings, err := h.loadNotificationSettings()
	if err != nil {
		return true // Default to allowing notifications
	}

	if !settings.GlobalEnabled {
		return false
	}

	// Check if connection has override
	if override, exists := settings.ConnectionOverrides[connectionID]; exists {
		if override == "none" {
			return false
		}
	}

	// Check quiet hours
	if h.IsInQuietHours() {
		// Check if connection is in priority list
		for _, priorityID := range settings.PriorityConnections {
			if priorityID == connectionID {
				return true // Priority connections bypass quiet hours
			}
		}
		return false
	}

	return true
}

// --- Helper methods ---

func (h *SettingsHandler) loadNotificationSettings() (*NotificationSettings, error) {
	data, err := h.storage.Get("settings/notifications")
	if err != nil {
		return nil, err
	}

	var settings NotificationSettings
	if err := json.Unmarshal(data, &settings); err != nil {
		return nil, err
	}

	return &settings, nil
}

func (h *SettingsHandler) errorResponse(id string, message string) (*OutgoingMessage, error) {
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
