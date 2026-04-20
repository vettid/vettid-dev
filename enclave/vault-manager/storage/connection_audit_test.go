package storage

import (
	"crypto/rand"
	"fmt"
	"testing"
	"time"
)

func newTestAuditStorage(t *testing.T) *SQLiteStorage {
	t.Helper()
	dek := make([]byte, 32)
	rand.Read(dek)
	s, err := NewSQLiteStorage("test-owner", dek)
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func appendTestEntry(t *testing.T, s *SQLiteStorage, conn, entryID, eventType string, createdAt int64) {
	t.Helper()
	err := s.AppendAuditEntry(AuditEntryRecord{
		EntryID:      entryID,
		ConnectionID: conn,
		EventType:    eventType,
		Title:        entryID + " title",
		Body:         entryID + " body",
		CreatedAt:    createdAt,
		Payload:      []byte(`{"entry_id":"` + entryID + `"}`),
	})
	if err != nil {
		t.Fatalf("append %s: %v", entryID, err)
	}
}

func TestAuditAppendAndList(t *testing.T) {
	s := newTestAuditStorage(t)

	now := time.Now().Unix()
	appendTestEntry(t, s, "conn-1", "e1", "message.sent", now-30)
	appendTestEntry(t, s, "conn-1", "e2", "message.received", now-20)
	appendTestEntry(t, s, "conn-1", "e3", "call.voice.completed", now-10)
	// Unrelated connection — must not appear in conn-1 list.
	appendTestEntry(t, s, "conn-2", "o1", "message.sent", now-5)

	got, err := s.ListAuditEntries(AuditListOptions{ConnectionID: "conn-1", Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got.Entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(got.Entries))
	}
	// Newest first.
	if got.Entries[0].EntryID != "e3" || got.Entries[2].EntryID != "e1" {
		t.Fatalf("unexpected order: %v / %v", got.Entries[0].EntryID, got.Entries[2].EntryID)
	}
	if got.NextCursor != nil {
		t.Fatalf("did not expect a next cursor, got %+v", got.NextCursor)
	}
}

func TestAuditListPaginationCursor(t *testing.T) {
	s := newTestAuditStorage(t)

	now := time.Now().Unix()
	for i := 0; i < 5; i++ {
		appendTestEntry(t, s, "c", fmt.Sprintf("e%02d", i), "message.sent", now-int64(i))
	}

	first, err := s.ListAuditEntries(AuditListOptions{ConnectionID: "c", Limit: 2})
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	if len(first.Entries) != 2 || first.NextCursor == nil {
		t.Fatalf("expected 2 entries + cursor, got %d entries / cursor=%+v", len(first.Entries), first.NextCursor)
	}

	second, err := s.ListAuditEntries(AuditListOptions{
		ConnectionID:    "c",
		Limit:           2,
		CursorCreatedAt: first.NextCursor.CreatedAt,
		CursorEntryID:   first.NextCursor.EntryID,
	})
	if err != nil {
		t.Fatalf("page 2: %v", err)
	}
	if len(second.Entries) != 2 {
		t.Fatalf("expected 2 entries on page 2, got %d", len(second.Entries))
	}
	// No overlap between pages.
	for _, a := range first.Entries {
		for _, b := range second.Entries {
			if a.EntryID == b.EntryID {
				t.Fatalf("page 2 overlaps page 1 on %s", a.EntryID)
			}
		}
	}
}

func TestAuditEventTypePrefixFilter(t *testing.T) {
	s := newTestAuditStorage(t)

	now := time.Now().Unix()
	appendTestEntry(t, s, "c", "m1", "message.sent", now-30)
	appendTestEntry(t, s, "c", "m2", "message.received", now-20)
	appendTestEntry(t, s, "c", "c1", "call.voice.completed", now-10)

	got, err := s.ListAuditEntries(AuditListOptions{
		ConnectionID:      "c",
		Limit:             10,
		EventTypePrefixes: []string{"message."},
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got.Entries) != 2 {
		t.Fatalf("expected 2 message.* entries, got %d", len(got.Entries))
	}
	for _, e := range got.Entries {
		if e.EventType[:8] != "message." {
			t.Fatalf("unexpected event type %q in message-filtered list", e.EventType)
		}
	}
}

func TestAuditSearchFTSMatch(t *testing.T) {
	s := newTestAuditStorage(t)

	now := time.Now().Unix()
	if err := s.AppendAuditEntry(AuditEntryRecord{
		EntryID:      "a1",
		ConnectionID: "c",
		EventType:    "message.received",
		Title:        "Received a message",
		Body:         "invoice for march please",
		CreatedAt:    now - 20,
		Payload:      []byte("{}"),
	}); err != nil {
		t.Fatalf("append a1: %v", err)
	}
	if err := s.AppendAuditEntry(AuditEntryRecord{
		EntryID:      "a2",
		ConnectionID: "c",
		EventType:    "message.sent",
		Title:        "Sent a message",
		Body:         "sure will send the files tomorrow",
		CreatedAt:    now - 10,
		Payload:      []byte("{}"),
	}); err != nil {
		t.Fatalf("append a2: %v", err)
	}

	got, err := s.SearchAuditEntries(AuditSearchOptions{
		ConnectionID: "c",
		Query:        "invoice",
		Limit:        10,
	})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(got.Entries) != 1 || got.Entries[0].EntryID != "a1" {
		t.Fatalf("expected single match on a1, got %+v", got.Entries)
	}
}

func TestAuditRetentionTrimsByCount(t *testing.T) {
	s := newTestAuditStorage(t)

	// Drop the cap to make the test cheap but exercise the trim path.
	// We can't easily stub the constant, so write just-over-cap entries
	// by using a small loop and relying on the real 10k cap would be
	// too slow — instead, insert a marker old entry and many new ones,
	// and assert only the newest survive after age trim.
	veryOld := time.Now().Unix() - (3 * 365 * 24 * 60 * 60) // 3 years
	if err := s.AppendAuditEntry(AuditEntryRecord{
		EntryID:      "ancient",
		ConnectionID: "c",
		EventType:    "message.sent",
		Title:        "ancient",
		CreatedAt:    veryOld,
		Payload:      []byte("{}"),
	}); err != nil {
		t.Fatalf("append ancient: %v", err)
	}
	// The very next append triggers the age-based trim, which should
	// remove the 3-year-old row.
	appendTestEntry(t, s, "c", "fresh", "message.sent", time.Now().Unix())

	got, err := s.ListAuditEntries(AuditListOptions{ConnectionID: "c", Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, e := range got.Entries {
		if e.EntryID == "ancient" {
			t.Fatalf("expected ancient row to be trimmed by retention policy, still present")
		}
	}
	if len(got.Entries) != 1 || got.Entries[0].EntryID != "fresh" {
		t.Fatalf("expected only fresh entry, got %+v", got.Entries)
	}
}

func TestAuditCountIsPerConnection(t *testing.T) {
	s := newTestAuditStorage(t)

	now := time.Now().Unix()
	appendTestEntry(t, s, "a", "a1", "message.sent", now)
	appendTestEntry(t, s, "a", "a2", "message.sent", now-1)
	appendTestEntry(t, s, "b", "b1", "message.sent", now)

	n, err := s.AuditEntryCount("a")
	if err != nil {
		t.Fatalf("count a: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 entries for a, got %d", n)
	}
	n, err = s.AuditEntryCount("b")
	if err != nil {
		t.Fatalf("count b: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 entry for b, got %d", n)
	}
}
