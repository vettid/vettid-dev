package migration

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// mockSealer implements Sealer for testing
type mockSealer struct {
	unsealFunc  func([]byte) ([]byte, error)
	sealFunc    func([]byte, *PCRValues) ([]byte, error)
}

func (m *mockSealer) Unseal(data []byte) ([]byte, error) {
	if m.unsealFunc != nil {
		return m.unsealFunc(data)
	}
	// Default: return data as-is (simulating successful unseal)
	return append([]byte{}, data...), nil
}

func (m *mockSealer) SealForPCRs(plaintext []byte, pcrs *PCRValues) ([]byte, error) {
	if m.sealFunc != nil {
		return m.sealFunc(plaintext, pcrs)
	}
	// Default: return data with a marker (simulating successful seal)
	return append([]byte("sealed:"), plaintext...), nil
}

func TestLockManager_AcquireAndRelease(t *testing.T) {
	store := NewInMemoryLockStore()
	manager := NewLockManager(store, "enclave-1")
	manager.SetDefaultTTL(1 * time.Minute)

	lock, err := manager.AcquireUserMigrationLock("user-123", 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to acquire lock: %v", err)
	}

	if lock.IsReleased() {
		t.Error("Lock should not be released yet")
	}

	// Release
	if err := lock.Release(); err != nil {
		t.Errorf("Failed to release lock: %v", err)
	}

	if !lock.IsReleased() {
		t.Error("Lock should be released")
	}

	// Multiple releases should be safe
	if err := lock.Release(); err != nil {
		t.Errorf("Second release should not error: %v", err)
	}
}

func TestLockManager_ConcurrentLocking(t *testing.T) {
	store := NewInMemoryLockStore()

	// Two lock managers (simulating two enclave instances)
	manager1 := NewLockManager(store, "enclave-1")
	manager2 := NewLockManager(store, "enclave-2")
	manager1.SetDefaultTTL(1 * time.Minute)
	manager2.SetDefaultTTL(1 * time.Minute)

	// First manager acquires lock
	lock1, err := manager1.AcquireUserMigrationLock("user-456", 1*time.Second)
	if err != nil {
		t.Fatalf("Manager 1 failed to acquire lock: %v", err)
	}
	defer lock1.Release()

	// Second manager should fail to acquire (timeout)
	_, err = manager2.AcquireUserMigrationLock("user-456", 100*time.Millisecond)
	if err == nil {
		t.Error("Manager 2 should have failed to acquire lock")
	}

	// Release and try again
	lock1.Release()

	lock2, err := manager2.AcquireUserMigrationLock("user-456", 1*time.Second)
	if err != nil {
		t.Fatalf("Manager 2 should acquire lock after release: %v", err)
	}
	lock2.Release()
}

func TestLockManager_LockExpiry(t *testing.T) {
	store := NewInMemoryLockStore()
	manager := NewLockManager(store, "enclave-1")
	manager.SetDefaultTTL(50 * time.Millisecond) // Very short TTL
	manager.SetRefreshInterval(1 * time.Hour)    // Disable refresh

	lock, err := manager.AcquireUserMigrationLock("user-789", 100*time.Millisecond)
	if err != nil {
		t.Fatalf("Failed to acquire lock: %v", err)
	}

	// Wait for lock to expire
	time.Sleep(100 * time.Millisecond)

	// Another manager should be able to acquire
	manager2 := NewLockManager(store, "enclave-2")
	manager2.SetDefaultTTL(1 * time.Minute)

	lock2, err := manager2.AcquireUserMigrationLock("user-789", 100*time.Millisecond)
	if err != nil {
		t.Fatalf("Should acquire expired lock: %v", err)
	}
	lock2.Release()
	lock.Release()
}

func TestMigrator_MigrateUser(t *testing.T) {
	// Setup
	lockStore := NewInMemoryLockStore()
	lockManager := NewLockManager(lockStore, "test-enclave")
	stateStore := NewInMemoryMigrationStateStore()
	materialStorage := newMockStorage()
	materialMgr := NewSealedMaterialManager(materialStorage)
	sealer := &mockSealer{}

	config := &MigrationConfig{
		TargetPCRs: &PCRValues{
			PCR0: testNewPCR0,
			PCR1: testNewPCR1,
			PCR2: testNewPCR2,
		},
		CurrentPCRs: &PCRValues{
			PCR0: testPCR0,
			PCR1: testPCR1,
			PCR2: testPCR2,
		},
		EnclaveInstanceID: "test-enclave",
		LockTimeout:       5 * time.Second,
		MaxRetries:        3,
	}

	migrator := NewMigrator(config, lockManager, stateStore, materialMgr, sealer)

	// Setup: Create initial sealed material
	userID := "user-migrate-test"
	initialVersion := &SealedMaterialVersion{
		Version:    1,
		PCRVersion: PCRVersionID(testPCR0),
		SealedData: []byte("initial-sealed-data"),
		CreatedAt:  time.Now(),
	}
	materialMgr.StoreVersion(userID, initialVersion)
	materialMgr.MarkVersionVerified(userID, 1)

	// Add user to pending state
	stateStore.AddPendingUser(userID)

	// Run migration
	ctx := context.Background()
	err := migrator.MigrateUser(ctx, userID)
	if err != nil {
		t.Fatalf("MigrateUser failed: %v", err)
	}

	// Verify state
	state, _ := stateStore.GetUserState(userID)
	if state.MigrationStatus != MigrationStatusVerifying {
		t.Errorf("Expected status verifying, got %s", state.MigrationStatus)
	}

	if state.TargetVersion != 2 {
		t.Errorf("Expected target version 2, got %d", state.TargetVersion)
	}

	// Verify new version was stored
	newVersion, err := materialMgr.GetVersion(userID, 2)
	if err != nil {
		t.Fatalf("Failed to get new version: %v", err)
	}

	if newVersion.PCRVersion != PCRVersionID(testNewPCR0) {
		t.Errorf("Expected new PCR version, got %s", newVersion.PCRVersion)
	}
}

func TestMigrator_MigrateAll(t *testing.T) {
	// Setup
	lockStore := NewInMemoryLockStore()
	lockManager := NewLockManager(lockStore, "test-enclave")
	stateStore := NewInMemoryMigrationStateStore()
	materialStorage := newMockStorage()
	materialMgr := NewSealedMaterialManager(materialStorage)
	sealer := &mockSealer{}

	config := &MigrationConfig{
		TargetPCRs: &PCRValues{
			PCR0: testNewPCR0,
			PCR1: testNewPCR1,
			PCR2: testNewPCR2,
		},
		EnclaveInstanceID: "test-enclave",
		LockTimeout:       5 * time.Second,
		MaxRetries:        3,
		ConcurrentWorkers: 2,
	}

	migrator := NewMigrator(config, lockManager, stateStore, materialMgr, sealer)

	// Setup: Create 5 users
	users := []string{"user-1", "user-2", "user-3", "user-4", "user-5"}
	for _, userID := range users {
		v := &SealedMaterialVersion{
			Version:    1,
			PCRVersion: PCRVersionID(testPCR0),
			SealedData: []byte("data-" + userID),
			CreatedAt:  time.Now(),
		}
		materialMgr.StoreVersion(userID, v)
		materialMgr.MarkVersionVerified(userID, 1)
		stateStore.AddPendingUser(userID)
	}

	// Track progress
	var completed int32
	migrator.SetCallbacks(
		nil,
		func(userID string, success bool, err error) {
			if success {
				atomic.AddInt32(&completed, 1)
			}
		},
		nil,
	)

	// Run migration
	ctx := context.Background()
	stats, err := migrator.MigrateAll(ctx)
	if err != nil {
		t.Fatalf("MigrateAll failed: %v", err)
	}

	if stats.Verifying != 5 {
		t.Errorf("Expected 5 verifying, got %d", stats.Verifying)
	}

	if atomic.LoadInt32(&completed) != 5 {
		t.Errorf("Expected 5 completed callbacks, got %d", completed)
	}
}

func TestMigrator_SkipAlreadyProcessed(t *testing.T) {
	lockStore := NewInMemoryLockStore()
	lockManager := NewLockManager(lockStore, "test-enclave")
	stateStore := NewInMemoryMigrationStateStore()
	materialStorage := newMockStorage()
	materialMgr := NewSealedMaterialManager(materialStorage)
	sealer := &mockSealer{}

	config := DefaultMigrationConfig()
	config.TargetPCRs = &PCRValues{PCR0: testNewPCR0, PCR1: testNewPCR1, PCR2: testNewPCR2}
	config.EnclaveInstanceID = "test-enclave"

	migrator := NewMigrator(config, lockManager, stateStore, materialMgr, sealer)

	// Create user already in verifying state
	stateStore.SaveUserState(&UserMigrationState{
		UserID:          "user-verifying",
		MigrationStatus: MigrationStatusVerifying,
		UpdatedAt:       time.Now(),
	})

	// Should not error, just skip
	err := migrator.MigrateUser(context.Background(), "user-verifying")
	if err != nil {
		t.Errorf("Should skip without error: %v", err)
	}

	// State should be unchanged
	state, _ := stateStore.GetUserState("user-verifying")
	if state.MigrationStatus != MigrationStatusVerifying {
		t.Errorf("Status should remain verifying, got %s", state.MigrationStatus)
	}
}

func TestMigrator_MaxRetries(t *testing.T) {
	lockStore := NewInMemoryLockStore()
	lockManager := NewLockManager(lockStore, "test-enclave")
	stateStore := NewInMemoryMigrationStateStore()
	materialStorage := newMockStorage()
	materialMgr := NewSealedMaterialManager(materialStorage)
	sealer := &mockSealer{}

	config := DefaultMigrationConfig()
	config.TargetPCRs = &PCRValues{PCR0: testNewPCR0, PCR1: testNewPCR1, PCR2: testNewPCR2}
	config.EnclaveInstanceID = "test-enclave"
	config.MaxRetries = 2

	migrator := NewMigrator(config, lockManager, stateStore, materialMgr, sealer)

	// Create user that has already failed max times
	stateStore.SaveUserState(&UserMigrationState{
		UserID:          "user-maxed",
		MigrationStatus: MigrationStatusFailed,
		AttemptCount:    2,
		UpdatedAt:       time.Now(),
	})

	err := migrator.MigrateUser(context.Background(), "user-maxed")
	if err == nil {
		t.Error("Should error when max retries exceeded")
	}
}

func TestMigrator_MarkUserVerified(t *testing.T) {
	lockStore := NewInMemoryLockStore()
	lockManager := NewLockManager(lockStore, "test-enclave")
	stateStore := NewInMemoryMigrationStateStore()
	materialStorage := newMockStorage()
	materialMgr := NewSealedMaterialManager(materialStorage)
	sealer := &mockSealer{}

	config := DefaultMigrationConfig()
	config.TargetPCRs = &PCRValues{PCR0: testNewPCR0, PCR1: testNewPCR1, PCR2: testNewPCR2}
	config.EnclaveInstanceID = "test-enclave"

	migrator := NewMigrator(config, lockManager, stateStore, materialMgr, sealer)

	userID := "user-verify"

	// Setup: Create versions and state
	materialMgr.StoreVersion(userID, &SealedMaterialVersion{
		Version:    1,
		PCRVersion: "old",
		SealedData: []byte("v1"),
		CreatedAt:  time.Now(),
	})
	materialMgr.MarkVersionVerified(userID, 1)

	materialMgr.StoreVersion(userID, &SealedMaterialVersion{
		Version:    2,
		PCRVersion: "new",
		SealedData: []byte("v2"),
		CreatedAt:  time.Now(),
	})

	stateStore.SaveUserState(&UserMigrationState{
		UserID:          userID,
		MigrationStatus: MigrationStatusVerifying,
		TargetVersion:   2,
		UpdatedAt:       time.Now(),
	})

	// Mark as verified
	err := migrator.MarkUserVerified(userID)
	if err != nil {
		t.Fatalf("MarkUserVerified failed: %v", err)
	}

	// Check state
	state, _ := stateStore.GetUserState(userID)
	if state.MigrationStatus != MigrationStatusComplete {
		t.Errorf("Expected complete status, got %s", state.MigrationStatus)
	}

	// Check version is now active
	current, _ := materialMgr.GetCurrentVersion(userID)
	if current.Version != 2 {
		t.Errorf("Expected version 2 active, got %d", current.Version)
	}
}

func TestZeroize(t *testing.T) {
	data := []byte("sensitive data here")
	original := make([]byte, len(data))
	copy(original, data)

	zeroize(data)

	for i, b := range data {
		if b != 0 {
			t.Errorf("Byte %d not zeroed: got %d", i, b)
		}
	}
}

func TestInMemoryMigrationStateStore(t *testing.T) {
	store := NewInMemoryMigrationStateStore()

	// Test GetUserState for non-existent user
	_, err := store.GetUserState("nonexistent")
	if err == nil {
		t.Error("Expected error for non-existent user")
	}

	// Test SaveUserState and GetUserState
	state := &UserMigrationState{
		UserID:          "user-1",
		MigrationStatus: MigrationStatusPending,
		UpdatedAt:       time.Now(),
	}
	store.SaveUserState(state)

	retrieved, err := store.GetUserState("user-1")
	if err != nil {
		t.Fatalf("GetUserState failed: %v", err)
	}
	if retrieved.UserID != "user-1" {
		t.Error("Wrong user ID retrieved")
	}

	// Test ListUsersNeedingMigration
	store.SaveUserState(&UserMigrationState{
		UserID:          "user-2",
		MigrationStatus: MigrationStatusFailed,
		UpdatedAt:       time.Now(),
	})
	store.SaveUserState(&UserMigrationState{
		UserID:          "user-3",
		MigrationStatus: MigrationStatusComplete,
		UpdatedAt:       time.Now(),
	})

	needsMigration, _ := store.ListUsersNeedingMigration()
	if len(needsMigration) != 2 { // user-1 (pending) and user-2 (failed)
		t.Errorf("Expected 2 users needing migration, got %d", len(needsMigration))
	}

	// Test GetMigrationStats
	stats, _ := store.GetMigrationStats()
	if stats.TotalUsers != 3 {
		t.Errorf("Expected 3 total users, got %d", stats.TotalUsers)
	}
	if stats.Pending != 1 {
		t.Errorf("Expected 1 pending, got %d", stats.Pending)
	}
	if stats.Failed != 1 {
		t.Errorf("Expected 1 failed, got %d", stats.Failed)
	}
	if stats.Complete != 1 {
		t.Errorf("Expected 1 complete, got %d", stats.Complete)
	}
}

func TestConcurrentMigrations(t *testing.T) {
	// Test that concurrent migrations to the same user are properly serialized
	lockStore := NewInMemoryLockStore()
	lockManager := NewLockManager(lockStore, "test-enclave")
	lockManager.SetDefaultTTL(1 * time.Second)

	var wg sync.WaitGroup
	lockCount := int32(0)
	failCount := int32(0)

	// Try to acquire lock from 10 goroutines
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lock, err := lockManager.AcquireUserMigrationLock("contested-user", 50*time.Millisecond)
			if err != nil {
				atomic.AddInt32(&failCount, 1)
				return
			}
			atomic.AddInt32(&lockCount, 1)
			time.Sleep(20 * time.Millisecond)
			lock.Release()
		}()
	}

	wg.Wait()

	// Due to timing, some should succeed and some should fail
	// The exact numbers depend on timing, but we should have at least some of each
	t.Logf("Locks acquired: %d, Failed: %d", lockCount, failCount)

	if lockCount == 0 {
		t.Error("At least one goroutine should have acquired the lock")
	}
}
