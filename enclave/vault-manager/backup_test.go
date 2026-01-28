package main

import (
	"context"
	"crypto/rand"
	"sync/atomic"
	"testing"

	"github.com/vettid/vettid-dev/enclave/vault-manager/storage"
)

// mockBackupPublisher implements BackupPublisher for testing
type mockBackupPublisher struct {
	appMessages     [][]byte
	backendMessages [][]byte
	failApp         bool
	failBackend     bool
	callCount       int32
}

func (m *mockBackupPublisher) PublishToApp(ctx context.Context, eventType string, payload []byte) error {
	atomic.AddInt32(&m.callCount, 1)
	if m.failApp {
		return ErrStorageNotInitialized // Reuse error for testing
	}
	m.appMessages = append(m.appMessages, payload)
	return nil
}

func (m *mockBackupPublisher) PublishToBackend(ctx context.Context, eventType string, payload []byte) error {
	atomic.AddInt32(&m.callCount, 1)
	if m.failBackend {
		return ErrStorageNotInitialized
	}
	m.backendMessages = append(m.backendMessages, payload)
	return nil
}

func TestBackupManager_TriggerBackup(t *testing.T) {
	dek := make([]byte, 32)
	rand.Read(dek)

	sqlite, err := storage.NewSQLiteStorage("test-owner", dek)
	if err != nil {
		t.Fatalf("Failed to create SQLite storage: %v", err)
	}
	defer sqlite.Close()

	encStorage := &EncryptedStorage{
		sqlite:     sqlite,
		ownerSpace: "test-owner",
	}

	publisher := &mockBackupPublisher{}
	bm := NewBackupManager("test-owner", encStorage, publisher)

	ctx := context.Background()
	notification, err := bm.TriggerBackup(ctx)
	if err != nil {
		t.Fatalf("TriggerBackup failed: %v", err)
	}

	if notification == nil {
		t.Fatal("Expected notification, got nil")
	}

	if notification.Type != "backup_created" {
		t.Errorf("Expected type 'backup_created', got '%s'", notification.Type)
	}

	if notification.RollbackCounter < 0 {
		t.Error("Rollback counter should be >= 0")
	}

	// Verify both app and backend were called
	if len(publisher.appMessages) != 1 {
		t.Errorf("Expected 1 app message, got %d", len(publisher.appMessages))
	}
	if len(publisher.backendMessages) != 1 {
		t.Errorf("Expected 1 backend message, got %d", len(publisher.backendMessages))
	}
}

func TestBackupManager_BackendFailure(t *testing.T) {
	dek := make([]byte, 32)
	rand.Read(dek)

	sqlite, err := storage.NewSQLiteStorage("test-owner", dek)
	if err != nil {
		t.Fatalf("Failed to create SQLite storage: %v", err)
	}
	defer sqlite.Close()

	encStorage := &EncryptedStorage{
		sqlite:     sqlite,
		ownerSpace: "test-owner",
	}

	publisher := &mockBackupPublisher{failBackend: true}
	bm := NewBackupManager("test-owner", encStorage, publisher)

	ctx := context.Background()
	_, err = bm.TriggerBackup(ctx)
	if err == nil {
		t.Error("Expected error when backend fails")
	}
}

func TestBackupManager_NoPublisher(t *testing.T) {
	dek := make([]byte, 32)
	rand.Read(dek)

	sqlite, err := storage.NewSQLiteStorage("test-owner", dek)
	if err != nil {
		t.Fatalf("Failed to create SQLite storage: %v", err)
	}
	defer sqlite.Close()

	encStorage := &EncryptedStorage{
		sqlite:     sqlite,
		ownerSpace: "test-owner",
	}

	// No publisher - backup should still succeed (used for local-only mode)
	bm := NewBackupManager("test-owner", encStorage, nil)

	ctx := context.Background()
	notification, err := bm.TriggerBackup(ctx)
	if err != nil {
		t.Fatalf("Expected success with no publisher, got error: %v", err)
	}

	if notification == nil {
		t.Fatal("Expected notification")
	}

	if notification.Type != "backup_created" {
		t.Errorf("Expected type 'backup_created', got '%s'", notification.Type)
	}
}

func TestBackupManager_AutoBackupConfig(t *testing.T) {
	dek := make([]byte, 32)
	rand.Read(dek)

	sqlite, err := storage.NewSQLiteStorage("test-owner", dek)
	if err != nil {
		t.Fatalf("Failed to create SQLite storage: %v", err)
	}
	defer sqlite.Close()

	encStorage := &EncryptedStorage{
		sqlite:     sqlite,
		ownerSpace: "test-owner",
	}

	bm := NewBackupManager("test-owner", encStorage, nil)

	// Default should be enabled
	if !bm.IsAutoBackupEnabled() {
		t.Error("Auto backup should be enabled by default")
	}

	bm.SetAutoBackup(false)
	if bm.IsAutoBackupEnabled() {
		t.Error("Auto backup should be disabled after SetAutoBackup(false)")
	}

	bm.SetAutoBackup(true)
	if !bm.IsAutoBackupEnabled() {
		t.Error("Auto backup should be enabled after SetAutoBackup(true)")
	}
}

func TestBackupManager_GetLastBackupInfo(t *testing.T) {
	dek := make([]byte, 32)
	rand.Read(dek)

	sqlite, err := storage.NewSQLiteStorage("test-owner", dek)
	if err != nil {
		t.Fatalf("Failed to create SQLite storage: %v", err)
	}
	defer sqlite.Close()

	encStorage := &EncryptedStorage{
		sqlite:     sqlite,
		ownerSpace: "test-owner",
	}

	bm := NewBackupManager("test-owner", encStorage, nil)

	counter, err := bm.GetLastBackupInfo()
	if err != nil {
		t.Fatalf("GetLastBackupInfo failed: %v", err)
	}

	// Initial counter should be 0
	if counter != 0 {
		t.Errorf("Expected initial counter 0, got %d", counter)
	}

	// Store some data to increment counter
	sqlite.Put("test-key", []byte("test-value"))

	counter, err = bm.GetLastBackupInfo()
	if err != nil {
		t.Fatalf("GetLastBackupInfo failed: %v", err)
	}

	if counter < 1 {
		t.Errorf("Expected counter >= 1 after Put, got %d", counter)
	}
}

func TestBackupHandler_HandleTrigger(t *testing.T) {
	dek := make([]byte, 32)
	rand.Read(dek)

	sqlite, err := storage.NewSQLiteStorage("test-owner", dek)
	if err != nil {
		t.Fatalf("Failed to create SQLite storage: %v", err)
	}
	defer sqlite.Close()

	encStorage := &EncryptedStorage{
		sqlite:     sqlite,
		ownerSpace: "test-owner",
	}

	publisher := &mockBackupPublisher{}
	bm := NewBackupManager("test-owner", encStorage, publisher)
	handler := NewBackupHandler("test-owner", bm)

	msg := &IncomingMessage{
		ID:      "msg-1",
		Type:    MessageTypeVaultOp,
		Subject: "OwnerSpace.test.forVault.backup.trigger",
		Payload: []byte("{}"),
	}

	ctx := context.Background()
	resp, err := handler.HandleTrigger(ctx, msg)
	if err != nil {
		t.Fatalf("HandleTrigger failed: %v", err)
	}

	if resp.Type != MessageTypeResponse {
		t.Errorf("Expected response type, got %s", resp.Type)
	}
}
