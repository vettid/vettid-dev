package main

import (
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/vettid/vettid-dev/enclave/vault-manager/storage"
)

// setupAuditHandler builds an AuditHandler over a fresh in-memory vault
// so each test starts from a clean slate. Mirrors setupEventHandler.
func setupAuditHandler(t *testing.T) (*AuditHandler, *AuditLog, func()) {
	t.Helper()

	dek := make([]byte, 32)
	rand.Read(dek)

	sqliteStore, err := storage.NewSQLiteStorage("test-owner", dek)
	if err != nil {
		t.Fatalf("create storage: %v", err)
	}
	encStorage := &EncryptedStorage{
		sqlite:     sqliteStore,
		ownerSpace: "test-owner",
	}

	auditLog := NewAuditLog(encStorage)
	handler := NewAuditHandler("test-owner", auditLog)
	return handler, auditLog, func() { sqliteStore.Close() }
}

func seedAudit(t *testing.T, log *AuditLog, connID, entryID, eventType string, createdAt int64, body string) {
	t.Helper()
	log.Append(AuditEntry{
		EntryID:      entryID,
		ConnectionID: connID,
		EventType:    eventType,
		Title:        entryID,
		Body:         body,
		CreatedAt:    createdAt,
	})
}

func auditRequest(t *testing.T, payload interface{}) *IncomingMessage {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return &IncomingMessage{
		RequestID: "req-1",
		Payload:   raw,
	}
}

func decodeAuditList(t *testing.T, msg *OutgoingMessage) AuditListResponse {
	t.Helper()
	if msg.Type == MessageTypeError {
		t.Fatalf("handler returned error: %s", msg.Error)
	}
	var resp AuditListResponse
	if err := json.Unmarshal(msg.Payload, &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp
}

func TestAuditHandler_List_RequiresConnectionID(t *testing.T) {
	handler, _, cleanup := setupAuditHandler(t)
	defer cleanup()

	resp, _ := handler.HandleList(auditRequest(t, AuditListRequest{Limit: 10}))
	if resp.Type != MessageTypeError {
		t.Fatalf("expected error response, got %+v", resp)
	}
}

func TestAuditHandler_List_ReturnsSeededEntries(t *testing.T) {
	handler, log, cleanup := setupAuditHandler(t)
	defer cleanup()

	now := time.Now().Unix()
	seedAudit(t, log, "conn-1", "e1", "message.sent", now-30, "")
	seedAudit(t, log, "conn-1", "e2", "call.voice.completed", now-20, "")
	seedAudit(t, log, "conn-2", "o1", "message.sent", now-10, "")

	resp, _ := handler.HandleList(auditRequest(t, AuditListRequest{
		ConnectionID: "conn-1",
		Limit:        10,
	}))
	body := decodeAuditList(t, resp)

	if len(body.Entries) != 2 {
		t.Fatalf("expected 2 entries for conn-1, got %d", len(body.Entries))
	}
	if body.TotalEstimate != 2 {
		t.Fatalf("expected total=2, got %d", body.TotalEstimate)
	}
	// Newest first.
	if body.Entries[0].EventType != "call.voice.completed" {
		t.Fatalf("expected newest first, got %s", body.Entries[0].EventType)
	}
}

func TestAuditHandler_List_EventTypePrefixFilter(t *testing.T) {
	handler, log, cleanup := setupAuditHandler(t)
	defer cleanup()

	now := time.Now().Unix()
	seedAudit(t, log, "c", "m1", "message.sent", now-20, "")
	seedAudit(t, log, "c", "c1", "call.voice.completed", now-10, "")

	resp, _ := handler.HandleList(auditRequest(t, AuditListRequest{
		ConnectionID: "c",
		EventTypes:   []string{"call."},
		Limit:        10,
	}))
	body := decodeAuditList(t, resp)

	if len(body.Entries) != 1 || body.Entries[0].EntryID != "c1" {
		t.Fatalf("expected single call entry, got %+v", body.Entries)
	}
}

func TestAuditHandler_Search_MatchesBodyText(t *testing.T) {
	handler, log, cleanup := setupAuditHandler(t)
	defer cleanup()

	now := time.Now().Unix()
	seedAudit(t, log, "c", "m1", "message.received", now-20, "invoice for march please")
	seedAudit(t, log, "c", "m2", "message.sent", now-10, "sure will send files tomorrow")

	resp, _ := handler.HandleSearch(auditRequest(t, AuditSearchRequest{
		ConnectionID: "c",
		Query:        "invoice",
		Limit:        10,
	}))
	body := decodeAuditList(t, resp)

	if len(body.Entries) != 1 || body.Entries[0].EntryID != "m1" {
		t.Fatalf("expected single match on m1, got %+v", body.Entries)
	}
}

func TestAuditHandler_Search_EmptyQueryDegradesToList(t *testing.T) {
	handler, log, cleanup := setupAuditHandler(t)
	defer cleanup()

	now := time.Now().Unix()
	seedAudit(t, log, "c", "m1", "message.sent", now-20, "")
	seedAudit(t, log, "c", "m2", "message.received", now-10, "")

	resp, _ := handler.HandleSearch(auditRequest(t, AuditSearchRequest{
		ConnectionID: "c",
		Query:        "",
		Limit:        10,
	}))
	body := decodeAuditList(t, resp)

	if len(body.Entries) != 2 {
		t.Fatalf("expected empty-query to return all entries, got %d", len(body.Entries))
	}
}

func TestAuditLog_AppendFillsDefaults(t *testing.T) {
	_, log, cleanup := setupAuditHandler(t)
	defer cleanup()

	// Leave EntryID + CreatedAt unset; Append should fill both.
	log.Append(AuditEntry{
		ConnectionID: "c",
		EventType:    "message.sent",
		Title:        "t",
	})

	entries, _, err := log.List(storage.AuditListOptions{ConnectionID: "c", Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].EntryID == "" {
		t.Fatalf("expected generated entry_id, got empty")
	}
	if entries[0].CreatedAt == 0 {
		t.Fatalf("expected generated created_at, got 0")
	}
}

func TestAuditLog_AppendClampsBody(t *testing.T) {
	_, log, cleanup := setupAuditHandler(t)
	defer cleanup()

	long := make([]byte, 500)
	for i := range long {
		long[i] = 'a'
	}
	log.Append(AuditEntry{
		ConnectionID: "c",
		EventType:    "message.received",
		Title:        "t",
		Body:         string(long),
	})

	entries, _, err := log.List(storage.AuditListOptions{ConnectionID: "c", Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	// 120 char cap + the "…" suffix. Ensure it shrank substantially.
	if len(entries[0].Body) > 130 {
		t.Fatalf("expected body to be clamped, got length %d", len(entries[0].Body))
	}
}
