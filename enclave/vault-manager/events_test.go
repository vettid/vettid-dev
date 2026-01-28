package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/vettid/vettid-dev/enclave/vault-manager/storage"
)

// setupEventHandler creates a test EventHandler with initialized storage
func setupEventHandler(t *testing.T) (*EventHandler, func()) {
	t.Helper()

	// Create DEK
	dek := make([]byte, 32)
	rand.Read(dek)

	// Create storage
	store, err := storage.NewSQLiteStorage("test-owner", dek)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}

	// Create encrypted storage wrapper
	encStorage := &EncryptedStorage{
		sqlite:     store,
		ownerSpace: "test-owner",
	}

	// Create event handler (no publisher for tests)
	handler := NewEventHandler("test-owner", encStorage, nil)

	cleanup := func() {
		store.Close()
	}

	return handler, cleanup
}

func TestEventHandler_LogEvent(t *testing.T) {
	handler, cleanup := setupEventHandler(t)
	defer cleanup()

	ctx := context.Background()

	// Log an event
	event := &Event{
		EventType:  EventTypeCallIncoming,
		SourceType: "call",
		SourceID:   "call-123",
		Title:      "Incoming call from Alice",
		Message:    "Alice is calling",
		Metadata: map[string]string{
			"caller_name": "Alice",
		},
	}

	err := handler.LogEvent(ctx, event)
	if err != nil {
		t.Fatalf("Failed to log event: %v", err)
	}

	// Verify event was assigned an ID
	if event.EventID == "" {
		t.Error("Expected event ID to be assigned")
	}

	// Verify sync sequence was assigned
	if event.SyncSequence == 0 {
		t.Error("Expected sync sequence to be assigned")
	}

	// Verify auto-classification
	if event.FeedStatus != FeedStatusActive {
		t.Errorf("Expected feed status 'active', got '%s'", event.FeedStatus)
	}
	if event.ActionType != ActionTypeAcceptDecline {
		t.Errorf("Expected action type 'accept_decline', got '%s'", event.ActionType)
	}
	if event.Priority != PriorityHigh {
		t.Errorf("Expected priority high (1), got %d", event.Priority)
	}

	// Retrieve and verify
	retrieved, err := handler.GetEvent(ctx, event.EventID)
	if err != nil {
		t.Fatalf("Failed to get event: %v", err)
	}
	if retrieved == nil {
		t.Fatal("Expected event, got nil")
	}
	if retrieved.Title != "Incoming call from Alice" {
		t.Errorf("Expected title 'Incoming call from Alice', got '%s'", retrieved.Title)
	}
	if retrieved.Metadata["caller_name"] != "Alice" {
		t.Error("Metadata not preserved correctly")
	}
}

func TestEventHandler_LogEventAutoClassification(t *testing.T) {
	handler, cleanup := setupEventHandler(t)
	defer cleanup()

	ctx := context.Background()

	tests := []struct {
		eventType      EventType
		expectedStatus FeedStatus
		expectedAction ActionType
		expectedPrio   Priority
	}{
		{EventTypeCallIncoming, FeedStatusActive, ActionTypeAcceptDecline, PriorityHigh},
		{EventTypeCallMissed, FeedStatusActive, ActionTypeView, PriorityNormal},
		{EventTypeCallOutgoing, FeedStatusHidden, ActionTypeNone, PriorityNormal},
		{EventTypeConnectionRequest, FeedStatusActive, ActionTypeAcceptDecline, PriorityNormal},
		{EventTypeMessageReceived, FeedStatusActive, ActionTypeReply, PriorityLow},
		{EventTypeSecurityAlert, FeedStatusActive, ActionTypeAcknowledge, PriorityUrgent},
		{EventTypeSecretAccessed, FeedStatusActive, ActionTypeAcknowledge, PriorityNormal},
	}

	for _, tc := range tests {
		t.Run(string(tc.eventType), func(t *testing.T) {
			event := &Event{
				EventType: tc.eventType,
				Title:     "Test event",
			}

			err := handler.LogEvent(ctx, event)
			if err != nil {
				t.Fatalf("Failed to log event: %v", err)
			}

			if event.FeedStatus != tc.expectedStatus {
				t.Errorf("Expected status %s, got %s", tc.expectedStatus, event.FeedStatus)
			}
			if event.ActionType != tc.expectedAction {
				t.Errorf("Expected action %s, got %s", tc.expectedAction, event.ActionType)
			}
			if event.Priority != tc.expectedPrio {
				t.Errorf("Expected priority %d, got %d", tc.expectedPrio, event.Priority)
			}
		})
	}
}

func TestEventHandler_ListFeed(t *testing.T) {
	handler, cleanup := setupEventHandler(t)
	defer cleanup()

	ctx := context.Background()

	// Log multiple events
	events := []struct {
		eventType EventType
		title     string
	}{
		{EventTypeCallIncoming, "Incoming call"},      // active, high priority
		{EventTypeMessageReceived, "New message"},     // active, low priority
		{EventTypeCallOutgoing, "Outgoing call"},      // hidden
		{EventTypeSecurityAlert, "Security alert"},    // active, urgent
		{EventTypeConnectionAccepted, "Connected"},    // hidden
	}

	for _, e := range events {
		err := handler.LogEvent(ctx, &Event{
			EventType: e.eventType,
			Title:     e.title,
		})
		if err != nil {
			t.Fatalf("Failed to log event: %v", err)
		}
	}

	// List feed (default: active + read)
	resp, err := handler.ListFeed(ctx, &FeedListRequest{})
	if err != nil {
		t.Fatalf("Failed to list feed: %v", err)
	}

	// Should have 3 active events (not hidden ones)
	if resp.Total != 3 {
		t.Errorf("Expected 3 feed events, got %d", resp.Total)
	}

	// Verify ordering: urgent first, then high, then low
	if len(resp.Events) >= 3 {
		if resp.Events[0].Priority != PriorityUrgent {
			t.Errorf("Expected first event to be urgent, got priority %d", resp.Events[0].Priority)
		}
		if resp.Events[1].Priority != PriorityHigh {
			t.Errorf("Expected second event to be high priority, got priority %d", resp.Events[1].Priority)
		}
	}
}

func TestEventHandler_MarkRead(t *testing.T) {
	handler, cleanup := setupEventHandler(t)
	defer cleanup()

	ctx := context.Background()

	// Log an event
	event := &Event{
		EventType: EventTypeCallIncoming,
		Title:     "Test call",
	}
	handler.LogEvent(ctx, event)

	// Mark as read
	err := handler.MarkRead(ctx, event.EventID)
	if err != nil {
		t.Fatalf("Failed to mark read: %v", err)
	}

	// Verify
	retrieved, _ := handler.GetEvent(ctx, event.EventID)
	if retrieved.FeedStatus != FeedStatusRead {
		t.Errorf("Expected status 'read', got '%s'", retrieved.FeedStatus)
	}
	if retrieved.ReadAt == 0 {
		t.Error("Expected ReadAt to be set")
	}
}

func TestEventHandler_Archive(t *testing.T) {
	handler, cleanup := setupEventHandler(t)
	defer cleanup()

	ctx := context.Background()

	// Log an event
	event := &Event{
		EventType: EventTypeMessageReceived,
		Title:     "Test message",
	}
	handler.LogEvent(ctx, event)

	// Archive
	err := handler.Archive(ctx, event.EventID)
	if err != nil {
		t.Fatalf("Failed to archive: %v", err)
	}

	// Verify
	retrieved, _ := handler.GetEvent(ctx, event.EventID)
	if retrieved.FeedStatus != FeedStatusArchived {
		t.Errorf("Expected status 'archived', got '%s'", retrieved.FeedStatus)
	}
	if retrieved.ArchivedAt == 0 {
		t.Error("Expected ArchivedAt to be set")
	}

	// Verify not in default feed list
	resp, _ := handler.ListFeed(ctx, &FeedListRequest{})
	for _, e := range resp.Events {
		if e.EventID == event.EventID {
			t.Error("Archived event should not appear in default feed")
		}
	}
}

func TestEventHandler_Delete(t *testing.T) {
	handler, cleanup := setupEventHandler(t)
	defer cleanup()

	ctx := context.Background()

	// Log an event
	event := &Event{
		EventType: EventTypeCallMissed,
		Title:     "Missed call",
	}
	handler.LogEvent(ctx, event)

	// Delete
	err := handler.Delete(ctx, event.EventID)
	if err != nil {
		t.Fatalf("Failed to delete: %v", err)
	}

	// Verify status changed to deleted
	retrieved, _ := handler.GetEvent(ctx, event.EventID)
	if retrieved.FeedStatus != FeedStatusDeleted {
		t.Errorf("Expected status 'deleted', got '%s'", retrieved.FeedStatus)
	}
}

func TestEventHandler_ExecuteAction(t *testing.T) {
	handler, cleanup := setupEventHandler(t)
	defer cleanup()

	ctx := context.Background()

	// Log an actionable event
	event := &Event{
		EventType: EventTypeConnectionRequest,
		Title:     "Connection request",
	}
	handler.LogEvent(ctx, event)

	// Execute action
	err := handler.ExecuteAction(ctx, event.EventID, "accept")
	if err != nil {
		t.Fatalf("Failed to execute action: %v", err)
	}

	// Verify actionedAt is set
	retrieved, _ := handler.GetEvent(ctx, event.EventID)
	if retrieved.ActionedAt == 0 {
		t.Error("Expected ActionedAt to be set")
	}
}

func TestEventHandler_Sync(t *testing.T) {
	handler, cleanup := setupEventHandler(t)
	defer cleanup()

	ctx := context.Background()

	// Log multiple events
	for i := 0; i < 5; i++ {
		handler.LogEvent(ctx, &Event{
			EventType: EventTypeCallOutgoing,
			Title:     "Call " + string(rune('1'+i)),
		})
	}

	// Sync from beginning
	resp, err := handler.Sync(ctx, &FeedSyncRequest{LastSequence: 0, Limit: 10})
	if err != nil {
		t.Fatalf("Failed to sync: %v", err)
	}

	if len(resp.Events) != 5 {
		t.Errorf("Expected 5 events, got %d", len(resp.Events))
	}
	if resp.LatestSequence != 5 {
		t.Errorf("Expected latest sequence 5, got %d", resp.LatestSequence)
	}
	if resp.HasMore {
		t.Error("Expected HasMore to be false")
	}

	// Sync from middle
	resp, err = handler.Sync(ctx, &FeedSyncRequest{LastSequence: 3, Limit: 10})
	if err != nil {
		t.Fatalf("Failed to sync from middle: %v", err)
	}

	if len(resp.Events) != 2 {
		t.Errorf("Expected 2 events (seq 4,5), got %d", len(resp.Events))
	}

	// Sync with limit
	resp, err = handler.Sync(ctx, &FeedSyncRequest{LastSequence: 0, Limit: 2})
	if err != nil {
		t.Fatalf("Failed to sync with limit: %v", err)
	}

	if len(resp.Events) != 2 {
		t.Errorf("Expected 2 events (limited), got %d", len(resp.Events))
	}
	if !resp.HasMore {
		t.Error("Expected HasMore to be true")
	}
}

func TestEventHandler_QueryAudit(t *testing.T) {
	handler, cleanup := setupEventHandler(t)
	defer cleanup()

	ctx := context.Background()

	// Log events of different types
	eventTypes := []EventType{
		EventTypeCallIncoming,
		EventTypeCallOutgoing,
		EventTypeMessageReceived,
		EventTypeCallIncoming,
		EventTypeSecretAccessed,
	}

	for _, et := range eventTypes {
		handler.LogEvent(ctx, &Event{
			EventType: et,
			Title:     "Test " + string(et),
		})
	}

	// Query all
	resp, err := handler.QueryAudit(ctx, &AuditQueryRequest{})
	if err != nil {
		t.Fatalf("Failed to query audit: %v", err)
	}
	if resp.Total != 5 {
		t.Errorf("Expected 5 events, got %d", resp.Total)
	}

	// Query by type
	resp, err = handler.QueryAudit(ctx, &AuditQueryRequest{
		EventTypes: []EventType{EventTypeCallIncoming},
	})
	if err != nil {
		t.Fatalf("Failed to query by type: %v", err)
	}
	if resp.Total != 2 {
		t.Errorf("Expected 2 call.incoming events, got %d", resp.Total)
	}
}

func TestEventHandler_ExportAudit(t *testing.T) {
	handler, cleanup := setupEventHandler(t)
	defer cleanup()

	ctx := context.Background()

	// Log some events
	for i := 0; i < 3; i++ {
		handler.LogEvent(ctx, &Event{
			EventType: EventTypeCallOutgoing,
			Title:     "Call " + string(rune('1'+i)),
		})
	}

	// Export as JSON
	resp, err := handler.ExportAudit(ctx, &AuditExportRequest{Format: "json"})
	if err != nil {
		t.Fatalf("Failed to export: %v", err)
	}
	if resp.EventCount != 3 {
		t.Errorf("Expected 3 events exported, got %d", resp.EventCount)
	}
	if resp.Format != "json" {
		t.Errorf("Expected format 'json', got '%s'", resp.Format)
	}

	// Verify JSON is valid
	var events []Event
	if err := json.Unmarshal(resp.Data, &events); err != nil {
		t.Errorf("Export data is not valid JSON: %v", err)
	}
	if len(events) != 3 {
		t.Errorf("Expected 3 events in JSON, got %d", len(events))
	}

	// Export as CSV
	resp, err = handler.ExportAudit(ctx, &AuditExportRequest{Format: "csv"})
	if err != nil {
		t.Fatalf("Failed to export CSV: %v", err)
	}
	if resp.Format != "csv" {
		t.Errorf("Expected format 'csv', got '%s'", resp.Format)
	}
	// CSV should have header + 3 rows
	csvData := string(resp.Data)
	if len(csvData) == 0 {
		t.Error("CSV export is empty")
	}
}

func TestEventHandler_Settings(t *testing.T) {
	handler, cleanup := setupEventHandler(t)
	defer cleanup()

	// Get default settings
	settings := handler.GetSettings()
	if settings.FeedRetentionDays != 30 {
		t.Errorf("Expected default feed retention 30, got %d", settings.FeedRetentionDays)
	}
	if settings.AuditRetentionDays != 90 {
		t.Errorf("Expected default audit retention 90, got %d", settings.AuditRetentionDays)
	}

	// Update settings
	newSettings := &FeedSettings{
		FeedRetentionDays:  14,
		AuditRetentionDays: 60,
		ArchiveBehavior:    "delete",
		AutoArchiveEnabled: false,
	}
	err := handler.UpdateSettings(newSettings)
	if err != nil {
		t.Fatalf("Failed to update settings: %v", err)
	}

	// Verify
	settings = handler.GetSettings()
	if settings.FeedRetentionDays != 14 {
		t.Errorf("Expected feed retention 14, got %d", settings.FeedRetentionDays)
	}
	if settings.AutoArchiveEnabled {
		t.Error("Expected auto archive to be disabled")
	}
	if settings.UpdatedAt == 0 {
		t.Error("Expected UpdatedAt to be set")
	}
}

func TestEventHandler_ConvenienceMethods(t *testing.T) {
	handler, cleanup := setupEventHandler(t)
	defer cleanup()

	ctx := context.Background()

	// Test LogCallEvent
	err := handler.LogCallEvent(ctx, EventTypeCallIncoming, "call-1", "peer-1", "Incoming call", nil)
	if err != nil {
		t.Fatalf("Failed to log call event: %v", err)
	}

	// Test LogConnectionEvent
	err = handler.LogConnectionEvent(ctx, EventTypeConnectionRequest, "conn-1", "peer-2", "Connection request")
	if err != nil {
		t.Fatalf("Failed to log connection event: %v", err)
	}

	// Test LogMessageEvent
	err = handler.LogMessageEvent(ctx, EventTypeMessageReceived, "msg-1", "conn-1", "Hello!")
	if err != nil {
		t.Fatalf("Failed to log message event: %v", err)
	}

	// Test LogSecretEvent
	err = handler.LogSecretEvent(ctx, EventTypeSecretAccessed, "secret-1", "My Password", "MASTER_PASSWORD")
	if err != nil {
		t.Fatalf("Failed to log secret event: %v", err)
	}

	// Test LogSecurityEvent
	err = handler.LogSecurityEvent(ctx, EventTypeSecurityAlert, "Suspicious Activity", "Multiple failed login attempts")
	if err != nil {
		t.Fatalf("Failed to log security event: %v", err)
	}

	// Verify all were logged
	resp, _ := handler.QueryAudit(ctx, &AuditQueryRequest{})
	if resp.Total != 5 {
		t.Errorf("Expected 5 events from convenience methods, got %d", resp.Total)
	}
}

func TestEventHandler_Cleanup(t *testing.T) {
	handler, cleanup := setupEventHandler(t)
	defer cleanup()

	ctx := context.Background()
	now := time.Now().Unix()

	// Log events that should be cleaned up
	// We need to directly use storage to set old timestamps

	// Log a recent event (should not be cleaned)
	handler.LogEvent(ctx, &Event{
		EventType: EventTypeCallOutgoing,
		Title:     "Recent call",
	})

	// For cleanup testing, we need events with old timestamps
	// The EventHandler doesn't allow setting CreatedAt directly, so we test
	// that cleanup doesn't delete recent events
	deleted, err := handler.RunCleanup(ctx)
	if err != nil {
		t.Fatalf("Failed to run cleanup: %v", err)
	}

	// No events should be deleted (all are recent)
	if deleted != 0 {
		t.Errorf("Expected 0 events deleted (all recent), got %d", deleted)
	}

	// Verify the recent event still exists
	resp, _ := handler.QueryAudit(ctx, &AuditQueryRequest{})
	if resp.Total != 1 {
		t.Errorf("Expected 1 event to remain, got %d", resp.Total)
	}

	_ = now // Used for documentation
}

func TestEventHandler_RetentionClasses(t *testing.T) {
	handler, cleanup := setupEventHandler(t)
	defer cleanup()

	ctx := context.Background()

	// Log events with different retention classes based on type
	// Security events should be permanent
	handler.LogEvent(ctx, &Event{
		EventType: EventTypeSecurityAlert,
		Title:     "Security alert",
	})

	// Message read events should be ephemeral
	handler.LogEvent(ctx, &Event{
		EventType: EventTypeMessageRead,
		Title:     "Message read",
	})

	// Regular events should be standard
	handler.LogEvent(ctx, &Event{
		EventType: EventTypeCallOutgoing,
		Title:     "Outgoing call",
	})

	// Query and verify retention classes
	resp, _ := handler.QueryAudit(ctx, &AuditQueryRequest{})

	retentionCounts := make(map[RetentionClass]int)
	for _, e := range resp.Events {
		retentionCounts[e.RetentionClass]++
	}

	if retentionCounts[RetentionPermanent] != 1 {
		t.Errorf("Expected 1 permanent event, got %d", retentionCounts[RetentionPermanent])
	}
	if retentionCounts[RetentionEphemeral] != 1 {
		t.Errorf("Expected 1 ephemeral event, got %d", retentionCounts[RetentionEphemeral])
	}
	if retentionCounts[RetentionStandard] != 1 {
		t.Errorf("Expected 1 standard event, got %d", retentionCounts[RetentionStandard])
	}
}

func TestEventHandler_Pagination(t *testing.T) {
	handler, cleanup := setupEventHandler(t)
	defer cleanup()

	ctx := context.Background()

	// Log 10 events
	for i := 0; i < 10; i++ {
		handler.LogEvent(ctx, &Event{
			EventType: EventTypeCallIncoming,
			Title:     "Call " + string(rune('0'+i)),
		})
	}

	// Test pagination
	page1, _ := handler.ListFeed(ctx, &FeedListRequest{Limit: 3, Offset: 0})
	if len(page1.Events) != 3 {
		t.Errorf("Expected 3 events on page 1, got %d", len(page1.Events))
	}
	if !page1.HasMore {
		t.Error("Expected HasMore to be true for page 1")
	}

	page2, _ := handler.ListFeed(ctx, &FeedListRequest{Limit: 3, Offset: 3})
	if len(page2.Events) != 3 {
		t.Errorf("Expected 3 events on page 2, got %d", len(page2.Events))
	}

	// Verify different events on each page
	if page1.Events[0].EventID == page2.Events[0].EventID {
		t.Error("Page 1 and page 2 should have different events")
	}

	// Last page
	lastPage, _ := handler.ListFeed(ctx, &FeedListRequest{Limit: 3, Offset: 9})
	if len(lastPage.Events) != 1 {
		t.Errorf("Expected 1 event on last page, got %d", len(lastPage.Events))
	}
	if lastPage.HasMore {
		t.Error("Expected HasMore to be false for last page")
	}
}
