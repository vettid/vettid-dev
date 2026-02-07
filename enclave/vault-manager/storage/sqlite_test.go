package storage

import (
	"crypto/rand"
	"testing"
	"time"
)

func TestNewSQLiteStorage(t *testing.T) {
	dek := make([]byte, 32)
	rand.Read(dek)

	storage, err := NewSQLiteStorage("test-owner", dek)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer storage.Close()

	if storage.ownerSpace != "test-owner" {
		t.Errorf("Expected owner space 'test-owner', got '%s'", storage.ownerSpace)
	}
}

func TestNewSQLiteStorage_InvalidDEK(t *testing.T) {
	dek := make([]byte, 16) // Wrong size
	rand.Read(dek)

	_, err := NewSQLiteStorage("test-owner", dek)
	if err == nil {
		t.Fatal("Expected error for invalid DEK size")
	}
}

func TestCEKKeypairOperations(t *testing.T) {
	dek := make([]byte, 32)
	rand.Read(dek)

	storage, err := NewSQLiteStorage("test-owner", dek)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer storage.Close()

	// Generate test keys
	privateKey := make([]byte, 32)
	publicKey := make([]byte, 32)
	rand.Read(privateKey)
	rand.Read(publicKey)

	// Store CEK keypair
	version, err := storage.StoreCEKKeypair(privateKey, publicKey, true)
	if err != nil {
		t.Fatalf("Failed to store CEK keypair: %v", err)
	}
	if version != 1 {
		t.Errorf("Expected version 1, got %d", version)
	}

	// Get current CEK
	cek, err := storage.GetCurrentCEK()
	if err != nil {
		t.Fatalf("Failed to get current CEK: %v", err)
	}
	if cek == nil {
		t.Fatal("Expected CEK, got nil")
	}
	if !bytesEqual(cek.PrivateKey, privateKey) {
		t.Error("Private key mismatch")
	}
	if !bytesEqual(cek.PublicKey, publicKey) {
		t.Error("Public key mismatch")
	}
	if !cek.IsCurrent {
		t.Error("Expected CEK to be current")
	}

	// Get CEK by version
	cek2, err := storage.GetCEKByVersion(version)
	if err != nil {
		t.Fatalf("Failed to get CEK by version: %v", err)
	}
	if cek2 == nil {
		t.Fatal("Expected CEK, got nil")
	}
	if cek2.Version != version {
		t.Errorf("Expected version %d, got %d", version, cek2.Version)
	}

	// Store another CEK as current (should unset previous)
	privateKey2 := make([]byte, 32)
	publicKey2 := make([]byte, 32)
	rand.Read(privateKey2)
	rand.Read(publicKey2)

	version2, err := storage.StoreCEKKeypair(privateKey2, publicKey2, true)
	if err != nil {
		t.Fatalf("Failed to store second CEK keypair: %v", err)
	}
	if version2 != 2 {
		t.Errorf("Expected version 2, got %d", version2)
	}

	// Verify new current CEK
	currentCEK, err := storage.GetCurrentCEK()
	if err != nil {
		t.Fatalf("Failed to get current CEK: %v", err)
	}
	if currentCEK.Version != version2 {
		t.Errorf("Expected current CEK version %d, got %d", version2, currentCEK.Version)
	}

	// Verify old CEK is no longer current
	oldCEK, err := storage.GetCEKByVersion(version)
	if err != nil {
		t.Fatalf("Failed to get old CEK: %v", err)
	}
	if oldCEK.IsCurrent {
		t.Error("Old CEK should not be current")
	}
}

func TestTransportKeyOperations(t *testing.T) {
	dek := make([]byte, 32)
	rand.Read(dek)

	storage, err := NewSQLiteStorage("test-owner", dek)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer storage.Close()

	// Generate test keys
	privateKey := make([]byte, 32)
	publicKey := make([]byte, 32)
	rand.Read(privateKey)
	rand.Read(publicKey)

	// Store UTK
	err = storage.StoreTransportKey("utk-1", "UTK", privateKey, publicKey)
	if err != nil {
		t.Fatalf("Failed to store transport key: %v", err)
	}

	// Count unused UTKs
	count, err := storage.CountUnusedTransportKeys("UTK")
	if err != nil {
		t.Fatalf("Failed to count unused UTKs: %v", err)
	}
	if count != 1 {
		t.Errorf("Expected 1 unused UTK, got %d", count)
	}

	// Get unused UTK
	utk, err := storage.GetUnusedTransportKey("UTK")
	if err != nil {
		t.Fatalf("Failed to get unused UTK: %v", err)
	}
	if utk == nil {
		t.Fatal("Expected UTK, got nil")
	}
	if utk.KeyID != "utk-1" {
		t.Errorf("Expected key ID 'utk-1', got '%s'", utk.KeyID)
	}
	if utk.Used {
		t.Error("UTK should not be marked as used")
	}

	// Mark as used
	err = storage.MarkTransportKeyUsed("utk-1")
	if err != nil {
		t.Fatalf("Failed to mark UTK as used: %v", err)
	}

	// Verify no more unused UTKs
	count, err = storage.CountUnusedTransportKeys("UTK")
	if err != nil {
		t.Fatalf("Failed to count unused UTKs: %v", err)
	}
	if count != 0 {
		t.Errorf("Expected 0 unused UTKs, got %d", count)
	}

	// Get unused should return nil
	utk, err = storage.GetUnusedTransportKey("UTK")
	if err != nil {
		t.Fatalf("Failed to get unused UTK: %v", err)
	}
	if utk != nil {
		t.Error("Expected nil UTK when all are used")
	}
}

func TestTransportKeyInvalidType(t *testing.T) {
	dek := make([]byte, 32)
	rand.Read(dek)

	storage, err := NewSQLiteStorage("test-owner", dek)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer storage.Close()

	privateKey := make([]byte, 32)
	publicKey := make([]byte, 32)
	rand.Read(privateKey)
	rand.Read(publicKey)

	err = storage.StoreTransportKey("key-1", "INVALID", privateKey, publicKey)
	if err == nil {
		t.Fatal("Expected error for invalid key type")
	}
}

func TestLedgerEntryOperations(t *testing.T) {
	dek := make([]byte, 32)
	rand.Read(dek)

	storage, err := NewSQLiteStorage("test-owner", dek)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer storage.Close()

	// Store ledger entry
	payload := []byte(`{"action": "test", "data": "hello"}`)
	err = storage.StoreLedgerEntry("entry-1", "call_record", payload)
	if err != nil {
		t.Fatalf("Failed to store ledger entry: %v", err)
	}

	// Get ledger entry
	entry, err := storage.GetLedgerEntry("entry-1")
	if err != nil {
		t.Fatalf("Failed to get ledger entry: %v", err)
	}
	if entry == nil {
		t.Fatal("Expected entry, got nil")
	}
	if entry.EntryID != "entry-1" {
		t.Errorf("Expected entry ID 'entry-1', got '%s'", entry.EntryID)
	}
	if entry.EntryType != "call_record" {
		t.Errorf("Expected entry type 'call_record', got '%s'", entry.EntryType)
	}
	if !bytesEqual(entry.Payload, payload) {
		t.Error("Payload mismatch")
	}

	// Store more entries
	for i := 2; i <= 5; i++ {
		payload := []byte(`{"index": ` + string(rune('0'+i)) + `}`)
		err = storage.StoreLedgerEntry("entry-"+string(rune('0'+i)), "call_record", payload)
		if err != nil {
			t.Fatalf("Failed to store ledger entry %d: %v", i, err)
		}
	}

	// List entries
	entries, err := storage.ListLedgerEntries("call_record", 3)
	if err != nil {
		t.Fatalf("Failed to list ledger entries: %v", err)
	}
	if len(entries) != 3 {
		t.Errorf("Expected 3 entries, got %d", len(entries))
	}

	// Verify non-existent entry returns nil
	entry, err = storage.GetLedgerEntry("non-existent")
	if err != nil {
		t.Fatalf("Failed to get non-existent entry: %v", err)
	}
	if entry != nil {
		t.Error("Expected nil for non-existent entry")
	}
}

func TestHandlerStateOperations(t *testing.T) {
	dek := make([]byte, 32)
	rand.Read(dek)

	storage, err := NewSQLiteStorage("test-owner", dek)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer storage.Close()

	// Store handler state
	state := []byte(`{"connections": [], "sessions": {}}`)
	err = storage.StoreHandlerState("handler-1", state)
	if err != nil {
		t.Fatalf("Failed to store handler state: %v", err)
	}

	// Get handler state
	hs, err := storage.GetHandlerState("handler-1")
	if err != nil {
		t.Fatalf("Failed to get handler state: %v", err)
	}
	if hs == nil {
		t.Fatal("Expected handler state, got nil")
	}
	if hs.HandlerID != "handler-1" {
		t.Errorf("Expected handler ID 'handler-1', got '%s'", hs.HandlerID)
	}
	if !bytesEqual(hs.State, state) {
		t.Error("State mismatch")
	}

	// Update handler state
	newState := []byte(`{"connections": ["conn-1"], "sessions": {"s1": {}}}`)
	err = storage.StoreHandlerState("handler-1", newState)
	if err != nil {
		t.Fatalf("Failed to update handler state: %v", err)
	}

	// Verify update
	hs, err = storage.GetHandlerState("handler-1")
	if err != nil {
		t.Fatalf("Failed to get updated handler state: %v", err)
	}
	if !bytesEqual(hs.State, newState) {
		t.Error("Updated state mismatch")
	}

	// Delete handler state
	err = storage.DeleteHandlerState("handler-1")
	if err != nil {
		t.Fatalf("Failed to delete handler state: %v", err)
	}

	// Verify deletion
	hs, err = storage.GetHandlerState("handler-1")
	if err != nil {
		t.Fatalf("Failed to get deleted handler state: %v", err)
	}
	if hs != nil {
		t.Error("Expected nil after deletion")
	}
}

func TestBackupAndRestore(t *testing.T) {
	dek := make([]byte, 32)
	rand.Read(dek)

	storage, err := NewSQLiteStorage("test-owner", dek)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer storage.Close()

	// Add some data
	privateKey := make([]byte, 32)
	publicKey := make([]byte, 32)
	rand.Read(privateKey)
	rand.Read(publicKey)

	_, err = storage.StoreCEKKeypair(privateKey, publicKey, true)
	if err != nil {
		t.Fatalf("Failed to store CEK: %v", err)
	}

	err = storage.StoreTransportKey("utk-1", "UTK", privateKey, publicKey)
	if err != nil {
		t.Fatalf("Failed to store UTK: %v", err)
	}

	// Create backup
	backup, err := storage.CreateBackup()
	if err != nil {
		t.Fatalf("Failed to create backup: %v", err)
	}

	if backup.Version != 1 {
		t.Errorf("Expected backup version 1, got %d", backup.Version)
	}
	if backup.OwnerSpace != "test-owner" {
		t.Errorf("Expected owner space 'test-owner', got '%s'", backup.OwnerSpace)
	}
	if len(backup.Data) == 0 {
		t.Error("Expected non-empty backup data")
	}
	if len(backup.HMAC) != 32 {
		t.Errorf("Expected 32-byte HMAC, got %d bytes", len(backup.HMAC))
	}

	// Rollback counter should have been incremented
	if backup.RollbackCounter < 2 { // At least 2 operations
		t.Errorf("Expected rollback counter >= 2, got %d", backup.RollbackCounter)
	}
}

func TestRollbackProtection(t *testing.T) {
	dek := make([]byte, 32)
	rand.Read(dek)

	storage, err := NewSQLiteStorage("test-owner", dek)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer storage.Close()

	// Initial rollback counter should be 0
	counter := storage.GetRollbackCounter()
	if counter != 0 {
		t.Errorf("Expected initial rollback counter 0, got %d", counter)
	}

	// Store some data (should increment counter)
	privateKey := make([]byte, 32)
	publicKey := make([]byte, 32)
	rand.Read(privateKey)
	rand.Read(publicKey)

	_, err = storage.StoreCEKKeypair(privateKey, publicKey, true)
	if err != nil {
		t.Fatalf("Failed to store CEK: %v", err)
	}

	counter = storage.GetRollbackCounter()
	if counter != 1 {
		t.Errorf("Expected rollback counter 1, got %d", counter)
	}

	// Create a backup with old counter
	oldBackup := &BackupData{
		Version:         1,
		OwnerSpace:      "test-owner",
		RollbackCounter: 0, // Old counter
		Data:            []byte{},
		HMAC:            []byte{},
		CreatedAt:       0,
	}

	err = storage.RestoreBackup(oldBackup)
	if err == nil {
		t.Fatal("Expected rollback protection to reject old backup")
	}
}

func TestEncryptionDecryption(t *testing.T) {
	dek := make([]byte, 32)
	rand.Read(dek)

	storage, err := NewSQLiteStorage("test-owner", dek)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer storage.Close()

	// Test that data is actually encrypted by checking raw database
	privateKey := make([]byte, 32)
	publicKey := make([]byte, 32)
	rand.Read(privateKey)
	rand.Read(publicKey)

	_, err = storage.StoreCEKKeypair(privateKey, publicKey, true)
	if err != nil {
		t.Fatalf("Failed to store CEK: %v", err)
	}

	// Query raw data from database
	var rawPrivate, rawPublic []byte
	err = storage.db.QueryRow(`
		SELECT private_key, public_key FROM cek_keypairs WHERE is_current = 1
	`).Scan(&rawPrivate, &rawPublic)
	if err != nil {
		t.Fatalf("Failed to query raw data: %v", err)
	}

	// Raw data should NOT equal the original (because it's encrypted)
	if bytesEqual(rawPrivate, privateKey) {
		t.Error("Private key was stored unencrypted!")
	}
	if bytesEqual(rawPublic, publicKey) {
		t.Error("Public key was stored unencrypted!")
	}

	// But decrypted data should match
	cek, err := storage.GetCurrentCEK()
	if err != nil {
		t.Fatalf("Failed to get CEK: %v", err)
	}
	if !bytesEqual(cek.PrivateKey, privateKey) {
		t.Error("Decrypted private key doesn't match original")
	}
	if !bytesEqual(cek.PublicKey, publicKey) {
		t.Error("Decrypted public key doesn't match original")
	}
}

// Helper function to compare byte slices
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ================================
// Event System Tests
// ================================

func TestEventOperations(t *testing.T) {
	dek := make([]byte, 32)
	rand.Read(dek)

	storage, err := NewSQLiteStorage("test-owner", dek)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer storage.Close()

	// Store an event
	event := &EventRecord{
		EventID:        "evt-1",
		EventType:      "call.incoming",
		SourceType:     "call",
		SourceID:       "call-123",
		Payload:        []byte(`{"title":"Incoming call","message":"From Alice"}`),
		FeedStatus:     "active",
		ActionType:     "accept_decline",
		Priority:       1,
		CreatedAt:      1705680000,
		SyncSequence:   1,
		RetentionClass: "standard",
	}

	err = storage.StoreEvent(event)
	if err != nil {
		t.Fatalf("Failed to store event: %v", err)
	}

	// Get the event
	retrieved, err := storage.GetEvent("evt-1")
	if err != nil {
		t.Fatalf("Failed to get event: %v", err)
	}
	if retrieved == nil {
		t.Fatal("Expected event, got nil")
	}
	if retrieved.EventID != "evt-1" {
		t.Errorf("Expected event ID 'evt-1', got '%s'", retrieved.EventID)
	}
	if retrieved.EventType != "call.incoming" {
		t.Errorf("Expected event type 'call.incoming', got '%s'", retrieved.EventType)
	}
	if retrieved.FeedStatus != "active" {
		t.Errorf("Expected feed status 'active', got '%s'", retrieved.FeedStatus)
	}
	if retrieved.Priority != 1 {
		t.Errorf("Expected priority 1, got %d", retrieved.Priority)
	}

	// Verify payload was decrypted correctly
	if !bytesEqual(retrieved.Payload, event.Payload) {
		t.Error("Payload mismatch after decryption")
	}
}

func TestEventNotFound(t *testing.T) {
	dek := make([]byte, 32)
	rand.Read(dek)

	storage, err := NewSQLiteStorage("test-owner", dek)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer storage.Close()

	// Get non-existent event
	event, err := storage.GetEvent("non-existent")
	if err != nil {
		t.Fatalf("Failed to get non-existent event: %v", err)
	}
	if event != nil {
		t.Error("Expected nil for non-existent event")
	}
}

func TestListFeedEvents(t *testing.T) {
	dek := make([]byte, 32)
	rand.Read(dek)

	storage, err := NewSQLiteStorage("test-owner", dek)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer storage.Close()

	// Store multiple events with different statuses
	events := []struct {
		id       string
		status   string
		priority int
	}{
		{"evt-1", "active", 2},   // Urgent
		{"evt-2", "active", 0},   // Normal
		{"evt-3", "read", 1},     // High
		{"evt-4", "hidden", 0},   // Should not appear in feed
		{"evt-5", "archived", 0}, // Should not appear by default
	}

	for i, e := range events {
		event := &EventRecord{
			EventID:        e.id,
			EventType:      "test.event",
			Payload:        []byte(`{}`),
			FeedStatus:     e.status,
			Priority:       e.priority,
			CreatedAt:      int64(1705680000 + i),
			SyncSequence:   int64(i + 1),
			RetentionClass: "standard",
		}
		if err := storage.StoreEvent(event); err != nil {
			t.Fatalf("Failed to store event %s: %v", e.id, err)
		}
	}

	// List active and read events (default)
	feedEvents, total, err := storage.ListFeedEvents([]string{"active", "read"}, 10, 0)
	if err != nil {
		t.Fatalf("Failed to list feed events: %v", err)
	}
	if total != 3 {
		t.Errorf("Expected total 3, got %d", total)
	}
	if len(feedEvents) != 3 {
		t.Errorf("Expected 3 events, got %d", len(feedEvents))
	}

	// Verify ordering by priority (descending)
	if feedEvents[0].EventID != "evt-1" {
		t.Errorf("Expected first event to be evt-1 (highest priority), got %s", feedEvents[0].EventID)
	}
	if feedEvents[1].EventID != "evt-3" {
		t.Errorf("Expected second event to be evt-3 (priority 1), got %s", feedEvents[1].EventID)
	}

	// List only archived
	archivedEvents, total, err := storage.ListFeedEvents([]string{"archived"}, 10, 0)
	if err != nil {
		t.Fatalf("Failed to list archived events: %v", err)
	}
	if total != 1 {
		t.Errorf("Expected total 1 archived, got %d", total)
	}
	if len(archivedEvents) != 1 {
		t.Errorf("Expected 1 archived event, got %d", len(archivedEvents))
	}
}

func TestQueryAuditEvents(t *testing.T) {
	dek := make([]byte, 32)
	rand.Read(dek)

	storage, err := NewSQLiteStorage("test-owner", dek)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer storage.Close()

	// Store events of different types with specific timestamps
	// evt-1: call.incoming at 1705680000
	// evt-2: call.outgoing at 1705681000
	// evt-3: message.received at 1705682000
	// evt-4: call.incoming at 1705683000
	eventTypes := []string{"call.incoming", "call.outgoing", "message.received", "call.incoming"}
	for i, et := range eventTypes {
		event := &EventRecord{
			EventID:        "evt-" + string(rune('1'+i)),
			EventType:      et,
			Payload:        []byte(`{}`),
			FeedStatus:     "hidden",
			CreatedAt:      int64(1705680000 + i*1000),
			SyncSequence:   int64(i + 1),
			RetentionClass: "standard",
		}
		if err := storage.StoreEvent(event); err != nil {
			t.Fatalf("Failed to store event: %v", err)
		}
	}

	// Query by event type
	events, total, err := storage.QueryAuditEvents([]string{"call.incoming"}, 0, 0, "", 100, 0)
	if err != nil {
		t.Fatalf("Failed to query audit events: %v", err)
	}
	if total != 2 {
		t.Errorf("Expected 2 call.incoming events, got %d", total)
	}
	if len(events) != 2 {
		t.Errorf("Expected 2 events in result, got %d", len(events))
	}

	// Query by time range (should include evt-2 at 1705681000 and evt-3 at 1705682000)
	events, total, err = storage.QueryAuditEvents(nil, 1705680500, 1705682500, "", 100, 0)
	if err != nil {
		t.Fatalf("Failed to query audit events by time: %v", err)
	}
	if total != 2 {
		t.Errorf("Expected 2 events in time range, got %d", total)
	}

	// Query all
	events, total, err = storage.QueryAuditEvents(nil, 0, 0, "", 100, 0)
	if err != nil {
		t.Fatalf("Failed to query all audit events: %v", err)
	}
	if total != 4 {
		t.Errorf("Expected 4 total events, got %d", total)
	}
}

func TestEventStatusUpdates(t *testing.T) {
	dek := make([]byte, 32)
	rand.Read(dek)

	storage, err := NewSQLiteStorage("test-owner", dek)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer storage.Close()

	// Store an event
	event := &EventRecord{
		EventID:        "evt-status",
		EventType:      "test.event",
		Payload:        []byte(`{}`),
		FeedStatus:     "active",
		CreatedAt:      1705680000,
		SyncSequence:   1,
		RetentionClass: "standard",
	}
	if err := storage.StoreEvent(event); err != nil {
		t.Fatalf("Failed to store event: %v", err)
	}

	// Update to read
	err = storage.UpdateEventStatus("evt-status", "read", 1705680100)
	if err != nil {
		t.Fatalf("Failed to update event status to read: %v", err)
	}

	// Verify
	retrieved, _ := storage.GetEvent("evt-status")
	if retrieved.FeedStatus != "read" {
		t.Errorf("Expected status 'read', got '%s'", retrieved.FeedStatus)
	}
	if retrieved.ReadAt == nil || *retrieved.ReadAt != 1705680100 {
		t.Error("ReadAt not set correctly")
	}

	// Update to archived
	err = storage.UpdateEventStatus("evt-status", "archived", 1705680200)
	if err != nil {
		t.Fatalf("Failed to update event status to archived: %v", err)
	}

	// Verify
	retrieved, _ = storage.GetEvent("evt-status")
	if retrieved.FeedStatus != "archived" {
		t.Errorf("Expected status 'archived', got '%s'", retrieved.FeedStatus)
	}
	if retrieved.ArchivedAt == nil || *retrieved.ArchivedAt != 1705680200 {
		t.Error("ArchivedAt not set correctly")
	}
}

func TestEventActioned(t *testing.T) {
	dek := make([]byte, 32)
	rand.Read(dek)

	storage, err := NewSQLiteStorage("test-owner", dek)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer storage.Close()

	// Store an event
	event := &EventRecord{
		EventID:        "evt-action",
		EventType:      "call.incoming",
		Payload:        []byte(`{}`),
		FeedStatus:     "active",
		ActionType:     "accept_decline",
		CreatedAt:      1705680000,
		SyncSequence:   1,
		RetentionClass: "standard",
	}
	if err := storage.StoreEvent(event); err != nil {
		t.Fatalf("Failed to store event: %v", err)
	}

	// Mark as actioned
	err = storage.UpdateEventActioned("evt-action", 1705680100)
	if err != nil {
		t.Fatalf("Failed to mark event actioned: %v", err)
	}

	// Verify
	retrieved, _ := storage.GetEvent("evt-action")
	if retrieved.ActionedAt == nil || *retrieved.ActionedAt != 1705680100 {
		t.Error("ActionedAt not set correctly")
	}
}

func TestSyncSequence(t *testing.T) {
	dek := make([]byte, 32)
	rand.Read(dek)

	storage, err := NewSQLiteStorage("test-owner", dek)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer storage.Close()

	// Get initial sequence
	seq, err := storage.GetSyncSequence()
	if err != nil {
		t.Fatalf("Failed to get sync sequence: %v", err)
	}
	if seq != 0 {
		t.Errorf("Expected initial sequence 0, got %d", seq)
	}

	// Increment
	newSeq, err := storage.IncrementSyncSequence()
	if err != nil {
		t.Fatalf("Failed to increment sync sequence: %v", err)
	}
	if newSeq != 1 {
		t.Errorf("Expected new sequence 1, got %d", newSeq)
	}

	// Increment again
	newSeq, err = storage.IncrementSyncSequence()
	if err != nil {
		t.Fatalf("Failed to increment sync sequence: %v", err)
	}
	if newSeq != 2 {
		t.Errorf("Expected new sequence 2, got %d", newSeq)
	}

	// Verify persisted
	seq, _ = storage.GetSyncSequence()
	if seq != 2 {
		t.Errorf("Expected persisted sequence 2, got %d", seq)
	}
}

func TestGetEventsSince(t *testing.T) {
	dek := make([]byte, 32)
	rand.Read(dek)

	storage, err := NewSQLiteStorage("test-owner", dek)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer storage.Close()

	// Store events with increasing sync sequences
	for i := 1; i <= 5; i++ {
		event := &EventRecord{
			EventID:        "evt-" + string(rune('0'+i)),
			EventType:      "test.event",
			Payload:        []byte(`{}`),
			FeedStatus:     "active",
			CreatedAt:      int64(1705680000 + i),
			SyncSequence:   int64(i),
			RetentionClass: "standard",
		}
		if err := storage.StoreEvent(event); err != nil {
			t.Fatalf("Failed to store event: %v", err)
		}
	}

	// Get events since sequence 2 (include hidden)
	events, err := storage.GetEventsSince(2, 10, true)
	if err != nil {
		t.Fatalf("Failed to get events since: %v", err)
	}
	if len(events) != 3 {
		t.Errorf("Expected 3 events (seq 3,4,5), got %d", len(events))
	}

	// Verify ordering by sequence ascending
	if events[0].SyncSequence != 3 {
		t.Errorf("Expected first event sequence 3, got %d", events[0].SyncSequence)
	}
	if events[2].SyncSequence != 5 {
		t.Errorf("Expected last event sequence 5, got %d", events[2].SyncSequence)
	}

	// Test limit
	events, err = storage.GetEventsSince(0, 2, true)
	if err != nil {
		t.Fatalf("Failed to get events with limit: %v", err)
	}
	if len(events) != 2 {
		t.Errorf("Expected 2 events (limited), got %d", len(events))
	}
}

func TestEventCleanup(t *testing.T) {
	dek := make([]byte, 32)
	rand.Read(dek)

	storage, err := NewSQLiteStorage("test-owner", dek)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer storage.Close()

	// Use current time since CleanupEvents uses time.Now() internally
	now := currentTimeUnix()

	// Store events with different retention classes and statuses
	events := []struct {
		id         string
		status     string
		retention  string
		createdAt  int64
		shouldKeep bool
	}{
		// Deleted events older than 7 days - should be removed
		{"evt-deleted-old", "deleted", "standard", now - 8*24*3600, false},
		// Deleted events newer than 7 days - should keep
		{"evt-deleted-new", "deleted", "standard", now - 1*24*3600, true},
		// Ephemeral events older than 24 hours - should be removed
		{"evt-ephemeral-old", "hidden", "ephemeral", now - 25*3600, false},
		// Ephemeral events newer than 24 hours - should keep
		{"evt-ephemeral-new", "hidden", "ephemeral", now - 12*3600, true},
		// Hidden events older than audit retention (90 days) - should be removed
		{"evt-hidden-old", "hidden", "standard", now - 91*24*3600, false},
		// Hidden events newer than audit retention - should keep
		{"evt-hidden-new", "hidden", "standard", now - 30*24*3600, true},
		// Permanent events should never be deleted regardless of age
		{"evt-permanent", "hidden", "permanent", now - 365*24*3600, true},
		// Active events - should not be deleted
		{"evt-active", "active", "standard", now - 60*24*3600, true},
	}

	for i, e := range events {
		event := &EventRecord{
			EventID:        e.id,
			EventType:      "test.event",
			Payload:        []byte(`{}`),
			FeedStatus:     e.status,
			CreatedAt:      e.createdAt,
			SyncSequence:   int64(i + 1),
			RetentionClass: e.retention,
		}
		if err := storage.StoreEvent(event); err != nil {
			t.Fatalf("Failed to store event %s: %v", e.id, err)
		}
	}

	// Run cleanup
	deleted, err := storage.CleanupEvents(30, 90, false)
	if err != nil {
		t.Fatalf("Failed to cleanup events: %v", err)
	}

	// Should have deleted 3 events
	if deleted != 3 {
		t.Errorf("Expected 3 events deleted, got %d", deleted)
	}

	// Verify correct events remain
	for _, e := range events {
		event, _ := storage.GetEvent(e.id)
		if e.shouldKeep && event == nil {
			t.Errorf("Event %s should have been kept but was deleted", e.id)
		}
		if !e.shouldKeep && event != nil {
			t.Errorf("Event %s should have been deleted but was kept", e.id)
		}
	}
}

// currentTimeUnix returns the current Unix timestamp
func currentTimeUnix() int64 {
	return time.Now().Unix()
}
