package storage

import (
	"crypto/rand"
	"testing"
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
