package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/mesmerverse/vettid-dev/enclave/vault-manager/storage"
	"github.com/rs/zerolog/log"
)

// EventHandler manages the unified event system for audit logging and user feed.
// It provides a single interface for logging events that automatically handles
// classification, storage, and push notifications.
type EventHandler struct {
	ownerSpace string
	storage    *EncryptedStorage
	publisher  *VsockPublisher
	settings   *FeedSettings

	// Sync sequence is managed atomically
	mu           sync.Mutex
	syncSequence int64
}

// NewEventHandler creates a new event handler
func NewEventHandler(ownerSpace string, storage *EncryptedStorage, publisher *VsockPublisher) *EventHandler {
	h := &EventHandler{
		ownerSpace: ownerSpace,
		storage:    storage,
		publisher:  publisher,
		settings:   DefaultFeedSettings(),
	}

	// Load settings from storage if available
	h.loadSettings()

	return h
}

// loadSettings loads feed settings from storage
func (h *EventHandler) loadSettings() {
	data, err := h.storage.Get("feed_settings")
	if err != nil {
		return // Use defaults
	}

	var settings FeedSettings
	if json.Unmarshal(data, &settings) == nil {
		h.settings = &settings
	}
}

// saveSettings persists feed settings to storage
func (h *EventHandler) saveSettings() error {
	data, err := json.Marshal(h.settings)
	if err != nil {
		return fmt.Errorf("failed to marshal settings: %w", err)
	}
	return h.storage.Put("feed_settings", data)
}

// GetSettings returns current feed settings
func (h *EventHandler) GetSettings() *FeedSettings {
	return h.settings
}

// UpdateSettings updates feed settings
func (h *EventHandler) UpdateSettings(settings *FeedSettings) error {
	settings.UpdatedAt = time.Now().Unix()
	h.settings = settings
	return h.saveSettings()
}

// LogEvent records an event with automatic feed classification.
// This is the primary method for logging events in the system.
func (h *EventHandler) LogEvent(ctx context.Context, e *Event) error {
	// Generate event ID if not provided
	if e.EventID == "" {
		e.EventID = fmt.Sprintf("evt-%d-%s", time.Now().UnixNano(), randomSuffix())
	}

	// Set created timestamp
	if e.CreatedAt == 0 {
		e.CreatedAt = time.Now().Unix()
	}

	// Get sync sequence
	h.mu.Lock()
	seq, err := h.storage.SQLite().IncrementSyncSequence()
	if err != nil {
		h.mu.Unlock()
		return fmt.Errorf("failed to get sync sequence: %w", err)
	}
	e.SyncSequence = seq
	h.syncSequence = seq
	h.mu.Unlock()

	// Auto-classify based on event type
	h.classifyEvent(e)

	// Marshal payload
	payload := EventPayload{
		Title:    e.Title,
		Message:  e.Message,
		Metadata: e.Metadata,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Create storage record
	record := &storage.EventRecord{
		EventID:        e.EventID,
		EventType:      string(e.EventType),
		SourceType:     e.SourceType,
		SourceID:       e.SourceID,
		Payload:        payloadBytes,
		FeedStatus:     string(e.FeedStatus),
		ActionType:     string(e.ActionType),
		Priority:       int(e.Priority),
		CreatedAt:      e.CreatedAt,
		SyncSequence:   e.SyncSequence,
		RetentionClass: string(e.RetentionClass),
	}

	if e.ExpiresAt > 0 {
		record.ExpiresAt = &e.ExpiresAt
	}

	// Store the event
	if err := h.storage.SQLite().StoreEvent(record); err != nil {
		return fmt.Errorf("failed to store event: %w", err)
	}

	log.Debug().
		Str("event_id", e.EventID).
		Str("event_type", string(e.EventType)).
		Str("feed_status", string(e.FeedStatus)).
		Int64("sync_seq", e.SyncSequence).
		Msg("Event logged")

	// Send push notification for actionable events
	if e.FeedStatus == FeedStatusActive && h.publisher != nil {
		h.notifyApp(ctx, "feed.new", e)
	}

	return nil
}

// classifyEvent applies default classification based on event type
func (h *EventHandler) classifyEvent(e *Event) {
	class := GetEventClassification(e.EventType)

	// Only set if not already specified
	if e.FeedStatus == "" {
		e.FeedStatus = class.FeedStatus
	}
	if e.ActionType == "" {
		e.ActionType = class.ActionType
	}
	if e.Priority == 0 && class.Priority != 0 {
		e.Priority = class.Priority
	}
	if e.RetentionClass == "" {
		e.RetentionClass = class.RetentionClass
	}
}

// notifyApp sends a push notification to the app
func (h *EventHandler) notifyApp(ctx context.Context, eventType string, e *Event) {
	notification := map[string]interface{}{
		"event_id":   e.EventID,
		"event_type": e.EventType,
		"title":      e.Title,
		"message":    e.Message,
		"priority":   e.Priority,
		"action":     e.ActionType,
		"created_at": e.CreatedAt,
	}

	data, err := json.Marshal(notification)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to marshal feed notification")
		return
	}

	if err := h.publisher.PublishToApp(ctx, eventType, data); err != nil {
		log.Warn().Err(err).Str("event_type", eventType).Msg("Failed to send feed notification")
	}
}

// --- Feed Operations ---

// ListFeed returns feed events for the user
func (h *EventHandler) ListFeed(ctx context.Context, req *FeedListRequest) (*FeedListResponse, error) {
	statuses := make([]string, len(req.Status))
	for i, s := range req.Status {
		statuses[i] = string(s)
	}
	if len(statuses) == 0 {
		statuses = []string{string(FeedStatusActive), string(FeedStatusRead)}
	}

	limit := req.Limit
	if limit <= 0 {
		limit = 50
	}

	events, total, err := h.storage.SQLite().ListFeedEvents(statuses, limit, req.Offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list feed events: %w", err)
	}

	result := make([]Event, len(events))
	for i, rec := range events {
		result[i] = h.recordToEvent(&rec)
	}

	return &FeedListResponse{
		Events:  result,
		Total:   total,
		HasMore: len(events) == limit && req.Offset+limit < total,
	}, nil
}

// GetEvent retrieves a single event by ID
func (h *EventHandler) GetEvent(ctx context.Context, eventID string) (*Event, error) {
	rec, err := h.storage.SQLite().GetEvent(eventID)
	if err != nil {
		return nil, fmt.Errorf("failed to get event: %w", err)
	}
	if rec == nil {
		return nil, nil
	}

	event := h.recordToEvent(rec)
	return &event, nil
}

// MarkRead marks an event as read
func (h *EventHandler) MarkRead(ctx context.Context, eventID string) error {
	now := time.Now().Unix()
	if err := h.storage.SQLite().UpdateEventStatus(eventID, string(FeedStatusRead), now); err != nil {
		return fmt.Errorf("failed to mark event read: %w", err)
	}

	// Log status change for audit trail
	h.logStatusChange(ctx, eventID, EventTypeFeedItemRead, "read")

	// Notify app of status change
	if h.publisher != nil {
		h.notifyStatusChange(ctx, eventID, FeedStatusRead)
	}

	return nil
}

// Archive archives an event
func (h *EventHandler) Archive(ctx context.Context, eventID string) error {
	now := time.Now().Unix()
	if err := h.storage.SQLite().UpdateEventStatus(eventID, string(FeedStatusArchived), now); err != nil {
		return fmt.Errorf("failed to archive event: %w", err)
	}

	// Log status change for audit trail
	h.logStatusChange(ctx, eventID, EventTypeFeedItemArchived, "archived")

	if h.publisher != nil {
		h.notifyStatusChange(ctx, eventID, FeedStatusArchived)
	}

	return nil
}

// Delete soft-deletes an event
func (h *EventHandler) Delete(ctx context.Context, eventID string) error {
	now := time.Now().Unix()
	if err := h.storage.SQLite().UpdateEventStatus(eventID, string(FeedStatusDeleted), now); err != nil {
		return fmt.Errorf("failed to delete event: %w", err)
	}

	// Log status change for audit trail
	h.logStatusChange(ctx, eventID, EventTypeFeedItemDeleted, "deleted")

	if h.publisher != nil {
		h.notifyStatusChange(ctx, eventID, FeedStatusDeleted)
	}

	return nil
}

// ExecuteAction marks an event as actioned with replay prevention
func (h *EventHandler) ExecuteAction(ctx context.Context, eventID string, action string) error {
	// SECURITY: Replay prevention - create unique action key
	actionKey := fmt.Sprintf("action:%s:%s", eventID, action)

	// Check if this action was already processed
	if alreadyProcessed, err := h.storage.IsEventProcessed(actionKey); err == nil && alreadyProcessed {
		log.Info().
			Str("event_id", eventID).
			Str("action", action).
			Msg("Duplicate action detected - ignoring replay")
		return fmt.Errorf("action already processed")
	}

	now := time.Now().Unix()
	if err := h.storage.SQLite().UpdateEventActioned(eventID, now); err != nil {
		return fmt.Errorf("failed to mark event actioned: %w", err)
	}

	// SECURITY: Mark action as processed to prevent future replays
	if err := h.storage.MarkEventProcessed(actionKey, "feed_action"); err != nil {
		log.Warn().Err(err).Str("action_key", actionKey).Msg("Failed to mark action as processed")
	}

	// Log action for audit trail
	h.LogEvent(ctx, &Event{
		EventType:  EventTypeFeedActionTaken,
		SourceType: "feed",
		SourceID:   eventID,
		Title:      fmt.Sprintf("Action: %s", action),
		Metadata: map[string]string{
			"target_event_id": eventID,
			"action":          action,
		},
	})

	log.Info().
		Str("event_id", eventID).
		Str("action", action).
		Msg("Event action executed")

	return nil
}

// notifyStatusChange sends status update notification to app
func (h *EventHandler) notifyStatusChange(ctx context.Context, eventID string, newStatus FeedStatus) {
	notification := map[string]interface{}{
		"event_id":   eventID,
		"new_status": newStatus,
		"updated_at": time.Now().Unix(),
	}

	data, _ := json.Marshal(notification)
	h.publisher.PublishToApp(ctx, "feed.updated", data)
}

// logStatusChange logs a feed status change for audit trail
func (h *EventHandler) logStatusChange(ctx context.Context, eventID string, eventType EventType, newStatus string) {
	// Log status change as a separate audit event (non-blocking)
	go func() {
		err := h.LogEvent(ctx, &Event{
			EventType:  eventType,
			SourceType: "feed",
			SourceID:   eventID,
			Title:      fmt.Sprintf("Feed item %s", newStatus),
			Metadata: map[string]string{
				"target_event_id": eventID,
				"new_status":      newStatus,
			},
		})
		if err != nil {
			log.Warn().Err(err).Str("event_id", eventID).Msg("Failed to log status change")
		}
	}()
}

// --- Sync Operations ---

// Sync returns events since a given sequence number
func (h *EventHandler) Sync(ctx context.Context, req *FeedSyncRequest) (*FeedSyncResponse, error) {
	limit := req.Limit
	if limit <= 0 {
		limit = 100
	}

	// Get events since sequence (request 1 more than limit to check hasMore)
	records, err := h.storage.SQLite().GetEventsSince(req.LastSequence, limit+1)
	if err != nil {
		return nil, fmt.Errorf("failed to sync events: %w", err)
	}

	hasMore := len(records) > limit
	if hasMore {
		records = records[:limit]
	}

	events := make([]Event, len(records))
	for i, rec := range records {
		events[i] = h.recordToEvent(&rec)
	}

	// Get latest sequence
	latestSeq, _ := h.storage.SQLite().GetSyncSequence()

	return &FeedSyncResponse{
		Events:         events,
		LatestSequence: latestSeq,
		HasMore:        hasMore,
	}, nil
}

// --- Audit Operations ---

// QueryAudit queries events for audit purposes
func (h *EventHandler) QueryAudit(ctx context.Context, req *AuditQueryRequest) (*AuditQueryResponse, error) {
	eventTypes := make([]string, len(req.EventTypes))
	for i, et := range req.EventTypes {
		eventTypes[i] = string(et)
	}

	limit := req.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	records, total, err := h.storage.SQLite().QueryAuditEvents(
		eventTypes, req.StartTime, req.EndTime, req.SourceID, limit, req.Offset,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query audit events: %w", err)
	}

	events := make([]Event, len(records))
	for i, rec := range records {
		events[i] = h.recordToEvent(&rec)
	}

	return &AuditQueryResponse{
		Events:  events,
		Total:   total,
		HasMore: len(events) == limit && req.Offset+limit < total,
	}, nil
}

// ExportAudit exports events for audit purposes (max 1000)
func (h *EventHandler) ExportAudit(ctx context.Context, req *AuditExportRequest) (*AuditExportResponse, error) {
	eventTypes := make([]string, len(req.EventTypes))
	for i, et := range req.EventTypes {
		eventTypes[i] = string(et)
	}

	// Always limit to 1000 for exports
	records, _, err := h.storage.SQLite().QueryAuditEvents(
		eventTypes, req.StartTime, req.EndTime, "", 1000, 0,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to export audit events: %w", err)
	}

	events := make([]Event, len(records))
	for i, rec := range records {
		events[i] = h.recordToEvent(&rec)
	}

	var data []byte
	switch req.Format {
	case "csv":
		data = h.eventsToCSV(events)
	default:
		data, _ = json.Marshal(events)
	}

	return &AuditExportResponse{
		Data:       data,
		Format:     req.Format,
		EventCount: len(events),
	}, nil
}

// eventsToCSV converts events to CSV format
func (h *EventHandler) eventsToCSV(events []Event) []byte {
	var csv string
	csv = "event_id,event_type,source_type,source_id,title,message,feed_status,priority,created_at\n"

	for _, e := range events {
		csv += fmt.Sprintf("%s,%s,%s,%s,\"%s\",\"%s\",%s,%d,%d\n",
			e.EventID, e.EventType, e.SourceType, e.SourceID,
			escapeCSV(e.Title), escapeCSV(e.Message),
			e.FeedStatus, e.Priority, e.CreatedAt,
		)
	}

	return []byte(csv)
}

// escapeCSV escapes a string for CSV output
func escapeCSV(s string) string {
	// Simple escape: replace quotes with double quotes
	result := ""
	for _, c := range s {
		if c == '"' {
			result += "\"\""
		} else if c == '\n' {
			result += "\\n"
		} else {
			result += string(c)
		}
	}
	return result
}

// --- Cleanup Operations ---

// RunCleanup performs event cleanup based on retention settings
func (h *EventHandler) RunCleanup(ctx context.Context) (int64, error) {
	deleted, err := h.storage.SQLite().CleanupEvents(
		h.settings.FeedRetentionDays,
		h.settings.AuditRetentionDays,
		h.settings.AutoArchiveEnabled,
	)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup events: %w", err)
	}

	if deleted > 0 {
		log.Info().Int64("deleted", deleted).Msg("Event cleanup completed")
	}

	return deleted, nil
}

// --- Helper Methods ---

// recordToEvent converts a storage record to an Event
func (h *EventHandler) recordToEvent(rec *storage.EventRecord) Event {
	var payload EventPayload
	json.Unmarshal(rec.Payload, &payload)

	event := Event{
		EventID:        rec.EventID,
		EventType:      EventType(rec.EventType),
		SourceType:     rec.SourceType,
		SourceID:       rec.SourceID,
		Title:          payload.Title,
		Message:        payload.Message,
		Metadata:       payload.Metadata,
		FeedStatus:     FeedStatus(rec.FeedStatus),
		ActionType:     ActionType(rec.ActionType),
		Priority:       Priority(rec.Priority),
		CreatedAt:      rec.CreatedAt,
		SyncSequence:   rec.SyncSequence,
		RetentionClass: RetentionClass(rec.RetentionClass),
	}

	if rec.ReadAt != nil {
		event.ReadAt = *rec.ReadAt
	}
	if rec.ActionedAt != nil {
		event.ActionedAt = *rec.ActionedAt
	}
	if rec.ArchivedAt != nil {
		event.ArchivedAt = *rec.ArchivedAt
	}
	if rec.ExpiresAt != nil {
		event.ExpiresAt = *rec.ExpiresAt
	}

	return event
}

// randomSuffix generates a short random suffix for event IDs
func randomSuffix() string {
	return fmt.Sprintf("%x", time.Now().UnixNano()%0xFFFF)
}

// --- Convenience Methods for Common Event Types ---

// LogCallEvent logs a call-related event
func (h *EventHandler) LogCallEvent(ctx context.Context, eventType EventType, callID, peerID, title string, metadata map[string]string) error {
	if metadata == nil {
		metadata = make(map[string]string)
	}
	metadata["call_id"] = callID
	metadata["peer_id"] = peerID

	return h.LogEvent(ctx, &Event{
		EventType:  eventType,
		SourceType: "call",
		SourceID:   callID,
		Title:      title,
		Metadata:   metadata,
	})
}

// LogConnectionEvent logs a connection-related event
func (h *EventHandler) LogConnectionEvent(ctx context.Context, eventType EventType, connectionID, peerID, title string) error {
	return h.LogEvent(ctx, &Event{
		EventType:  eventType,
		SourceType: "connection",
		SourceID:   connectionID,
		Title:      title,
		Metadata: map[string]string{
			"connection_id": connectionID,
			"peer_id":       peerID,
		},
	})
}

// LogMessageEvent logs a message-related event
func (h *EventHandler) LogMessageEvent(ctx context.Context, eventType EventType, messageID, connectionID, preview string) error {
	return h.LogEvent(ctx, &Event{
		EventType:  eventType,
		SourceType: "message",
		SourceID:   connectionID,
		Title:      "New Message",
		Message:    preview,
		Metadata: map[string]string{
			"message_id":    messageID,
			"connection_id": connectionID,
		},
	})
}

// LogSecretEvent logs a secret access event
func (h *EventHandler) LogSecretEvent(ctx context.Context, eventType EventType, secretID, secretName, category string) error {
	return h.LogEvent(ctx, &Event{
		EventType:  eventType,
		SourceType: "secret",
		SourceID:   secretID,
		Title:      fmt.Sprintf("Secret: %s", secretName),
		Metadata: map[string]string{
			"secret_id":       secretID,
			"secret_name":     secretName,
			"secret_category": category,
		},
	})
}

// LogSecurityEvent logs a security-related event
func (h *EventHandler) LogSecurityEvent(ctx context.Context, eventType EventType, title, message string) error {
	return h.LogEvent(ctx, &Event{
		EventType:  eventType,
		SourceType: "system",
		Title:      title,
		Message:    message,
	})
}
