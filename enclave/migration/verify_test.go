package migration

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestVerifier_VerifyUser_Success(t *testing.T) {
	// Setup
	stateStore := NewInMemoryMigrationStateStore()
	materialStorage := newMockStorage()
	materialMgr := NewSealedMaterialManager(materialStorage)
	sealer := &mockSealer{}

	verifier := NewVerifier(sealer, materialMgr, stateStore, nil)

	userID := "user-verify-1"

	// Setup: Create migrated material (unverified)
	materialMgr.StoreVersion(userID, &SealedMaterialVersion{
		Version:    1,
		PCRVersion: "old-pcr",
		SealedData: []byte("old-sealed-data-here-32-bytes!!!"),
		CreatedAt:  time.Now().Add(-1 * time.Hour),
	})
	materialMgr.MarkVersionVerified(userID, 1)

	// Store migrated version (unverified)
	materialMgr.StoreVersion(userID, &SealedMaterialVersion{
		Version:    2,
		PCRVersion: "new-pcr",
		SealedData: []byte("new-sealed-data-here-32-bytes!!!"),
		CreatedAt:  time.Now(),
	})

	// Set state to verifying
	stateStore.SaveUserState(&UserMigrationState{
		UserID:          userID,
		MigrationStatus: MigrationStatusVerifying,
		TargetVersion:   2,
		UpdatedAt:       time.Now(),
	})

	// Run verification
	ctx := context.Background()
	result, err := verifier.VerifyUser(ctx, userID)
	if err != nil {
		t.Fatalf("VerifyUser failed: %v", err)
	}

	if !result.Success {
		t.Errorf("Expected success, got failure: %v", result.Error)
	}

	if result.Version != 2 {
		t.Errorf("Expected version 2, got %d", result.Version)
	}

	// Check state is now complete
	state, _ := stateStore.GetUserState(userID)
	if state.MigrationStatus != MigrationStatusComplete {
		t.Errorf("Expected complete status, got %s", state.MigrationStatus)
	}

	// Check version is now verified and active
	current, _ := materialMgr.GetCurrentVersion(userID)
	if current.Version != 2 {
		t.Errorf("Expected version 2 active, got %d", current.Version)
	}
}

func TestVerifier_VerifyUser_UnsealFailure(t *testing.T) {
	stateStore := NewInMemoryMigrationStateStore()
	materialStorage := newMockStorage()
	materialMgr := NewSealedMaterialManager(materialStorage)

	// Sealer that fails to unseal
	sealer := &mockSealer{
		unsealFunc: func(data []byte) ([]byte, error) {
			return nil, errors.New("unseal failed: PCR mismatch")
		},
	}

	verifier := NewVerifier(sealer, materialMgr, stateStore, nil)

	userID := "user-unseal-fail"

	// Setup
	materialMgr.StoreVersion(userID, &SealedMaterialVersion{
		Version:    1,
		PCRVersion: "pcr",
		SealedData: []byte("sealed-data-at-least-32-bytes!!!"),
		CreatedAt:  time.Now(),
	})

	stateStore.SaveUserState(&UserMigrationState{
		UserID:          userID,
		MigrationStatus: MigrationStatusVerifying,
		UpdatedAt:       time.Now(),
	})

	// Run verification
	result, _ := verifier.VerifyUser(context.Background(), userID)

	if result.Success {
		t.Error("Expected failure due to unseal error")
	}

	if result.Error == nil {
		t.Error("Expected error to be set")
	}

	// Check state is now failed
	state, _ := stateStore.GetUserState(userID)
	if state.MigrationStatus != MigrationStatusFailed {
		t.Errorf("Expected failed status, got %s", state.MigrationStatus)
	}
}

func TestVerifier_VerifyUser_AlreadyComplete(t *testing.T) {
	stateStore := NewInMemoryMigrationStateStore()
	materialStorage := newMockStorage()
	materialMgr := NewSealedMaterialManager(materialStorage)
	sealer := &mockSealer{}

	verifier := NewVerifier(sealer, materialMgr, stateStore, nil)

	userID := "user-already-complete"

	// Set state to already complete
	stateStore.SaveUserState(&UserMigrationState{
		UserID:          userID,
		MigrationStatus: MigrationStatusComplete,
		UpdatedAt:       time.Now(),
	})

	// Run verification - should succeed without doing work
	result, err := verifier.VerifyUser(context.Background(), userID)
	if err != nil {
		t.Fatalf("VerifyUser failed: %v", err)
	}

	if !result.Success {
		t.Error("Expected success for already complete user")
	}
}

func TestVerifier_VerifyUser_WrongState(t *testing.T) {
	stateStore := NewInMemoryMigrationStateStore()
	materialStorage := newMockStorage()
	materialMgr := NewSealedMaterialManager(materialStorage)
	sealer := &mockSealer{}

	verifier := NewVerifier(sealer, materialMgr, stateStore, nil)

	userID := "user-wrong-state"

	// Set state to pending (not verifying)
	stateStore.SaveUserState(&UserMigrationState{
		UserID:          userID,
		MigrationStatus: MigrationStatusPending,
		UpdatedAt:       time.Now(),
	})

	// Run verification - should fail due to wrong state
	result, _ := verifier.VerifyUser(context.Background(), userID)

	if result.Success {
		t.Error("Expected failure for user in wrong state")
	}
}

func TestVerifier_VerifyUser_IntegrityFailure(t *testing.T) {
	stateStore := NewInMemoryMigrationStateStore()
	materialStorage := newMockStorage()
	materialMgr := NewSealedMaterialManager(materialStorage)

	// Sealer returns empty data (fails integrity check)
	sealer := &mockSealer{
		unsealFunc: func(data []byte) ([]byte, error) {
			return []byte{}, nil // Empty = fails integrity
		},
	}

	verifier := NewVerifier(sealer, materialMgr, stateStore, nil)

	userID := "user-integrity-fail"

	materialMgr.StoreVersion(userID, &SealedMaterialVersion{
		Version:    1,
		PCRVersion: "pcr",
		SealedData: []byte("sealed-data-at-least-32-bytes!!!"),
		CreatedAt:  time.Now(),
	})

	stateStore.SaveUserState(&UserMigrationState{
		UserID:          userID,
		MigrationStatus: MigrationStatusVerifying,
		UpdatedAt:       time.Now(),
	})

	result, _ := verifier.VerifyUser(context.Background(), userID)

	if result.Success {
		t.Error("Expected failure due to integrity check")
	}

	state, _ := stateStore.GetUserState(userID)
	if state.MigrationStatus != MigrationStatusFailed {
		t.Errorf("Expected failed status, got %s", state.MigrationStatus)
	}
}

func TestVerifier_VerifyAll(t *testing.T) {
	stateStore := NewInMemoryMigrationStateStore()
	materialStorage := newMockStorage()
	materialMgr := NewSealedMaterialManager(materialStorage)
	sealer := &mockSealer{}

	config := &VerifierConfig{
		ConcurrentWorkers: 2,
		ExpiryDuration:    7 * 24 * time.Hour,
	}
	verifier := NewVerifier(sealer, materialMgr, stateStore, config)

	// Setup: Create 5 users in verifying state
	users := []string{"user-1", "user-2", "user-3", "user-4", "user-5"}
	for _, userID := range users {
		// Create initial version
		materialMgr.StoreVersion(userID, &SealedMaterialVersion{
			Version:    1,
			PCRVersion: "old",
			SealedData: []byte("old-data-at-least-32-bytes-long!"),
			CreatedAt:  time.Now().Add(-1 * time.Hour),
		})
		materialMgr.MarkVersionVerified(userID, 1)

		// Create migrated version
		materialMgr.StoreVersion(userID, &SealedMaterialVersion{
			Version:    2,
			PCRVersion: "new",
			SealedData: []byte("new-data-at-least-32-bytes-long!"),
			CreatedAt:  time.Now(),
		})

		stateStore.SaveUserState(&UserMigrationState{
			UserID:          userID,
			MigrationStatus: MigrationStatusVerifying,
			TargetVersion:   2,
			UpdatedAt:       time.Now(),
		})
	}

	// Track callbacks
	var verified int32
	verifier.SetCallbacks(
		func(userID string, success bool, err error) {
			if success {
				atomic.AddInt32(&verified, 1)
			}
		},
		nil,
	)

	// Run batch verification
	result, err := verifier.VerifyAll(context.Background())
	if err != nil {
		t.Fatalf("VerifyAll failed: %v", err)
	}

	if result.Verified != 5 {
		t.Errorf("Expected 5 verified, got %d", result.Verified)
	}

	if result.Failed != 0 {
		t.Errorf("Expected 0 failed, got %d", result.Failed)
	}

	if atomic.LoadInt32(&verified) != 5 {
		t.Errorf("Expected 5 callbacks, got %d", verified)
	}

	// Check all states are complete
	stats, _ := stateStore.GetMigrationStats()
	if stats.Complete != 5 {
		t.Errorf("Expected 5 complete, got %d", stats.Complete)
	}
}

func TestVerifier_VerifyAll_MixedResults(t *testing.T) {
	stateStore := NewInMemoryMigrationStateStore()
	materialStorage := newMockStorage()
	materialMgr := NewSealedMaterialManager(materialStorage)

	// Sealer that fails for specific users
	failUsers := map[string]bool{"user-fail-1": true, "user-fail-2": true}
	sealer := &mockSealer{
		unsealFunc: func(data []byte) ([]byte, error) {
			// Check if this is a "fail" user by checking the data content
			if string(data[:4]) == "fail" {
				return nil, errors.New("intentional failure")
			}
			return data, nil
		},
	}

	verifier := NewVerifier(sealer, materialMgr, stateStore, nil)

	// Setup: 3 success, 2 fail
	for i, userID := range []string{"user-ok-1", "user-ok-2", "user-ok-3", "user-fail-1", "user-fail-2"} {
		var data []byte
		if failUsers[userID] {
			data = []byte("fail-data-at-least-32-bytes-long")
		} else {
			data = []byte("good-data-at-least-32-bytes-long")
		}

		materialMgr.StoreVersion(userID, &SealedMaterialVersion{
			Version:    1,
			PCRVersion: "pcr",
			SealedData: data,
			CreatedAt:  time.Now(),
		})

		stateStore.SaveUserState(&UserMigrationState{
			UserID:          userID,
			MigrationStatus: MigrationStatusVerifying,
			UpdatedAt:       time.Now(),
		})
		_ = i
	}

	result, _ := verifier.VerifyAll(context.Background())

	if result.Verified != 3 {
		t.Errorf("Expected 3 verified, got %d", result.Verified)
	}

	if result.Failed != 2 {
		t.Errorf("Expected 2 failed, got %d", result.Failed)
	}
}

func TestVerifier_NoUsersToVerify(t *testing.T) {
	stateStore := NewInMemoryMigrationStateStore()
	materialStorage := newMockStorage()
	materialMgr := NewSealedMaterialManager(materialStorage)
	sealer := &mockSealer{}

	verifier := NewVerifier(sealer, materialMgr, stateStore, nil)

	// No users in verifying state
	result, err := verifier.VerifyAll(context.Background())
	if err != nil {
		t.Fatalf("VerifyAll failed: %v", err)
	}

	if result.TotalUsers != 0 {
		t.Errorf("Expected 0 total users, got %d", result.TotalUsers)
	}
}

func TestComputeMaterialChecksum(t *testing.T) {
	data := []byte("test data for checksum")
	checksum := ComputeMaterialChecksum(data)

	// Should return first 8 bytes of SHA256 as hex (16 chars)
	if len(checksum) != 16 {
		t.Errorf("Expected 16 char checksum, got %d", len(checksum))
	}

	// Same data should produce same checksum
	checksum2 := ComputeMaterialChecksum(data)
	if checksum != checksum2 {
		t.Error("Same data should produce same checksum")
	}

	// Different data should produce different checksum
	checksum3 := ComputeMaterialChecksum([]byte("different data"))
	if checksum == checksum3 {
		t.Error("Different data should produce different checksum")
	}
}

func TestVerifier_MaterialIntegrity(t *testing.T) {
	verifier := &Verifier{}

	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{"empty", []byte{}, false},
		{"too short", []byte("short"), false},
		{"exactly 32 bytes", make([]byte, 32), true},
		{"longer than 32", make([]byte, 64), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := verifier.verifyMaterialIntegrity(tt.data)
			if result != tt.expected {
				t.Errorf("verifyMaterialIntegrity(%d bytes) = %v, want %v",
					len(tt.data), result, tt.expected)
			}
		})
	}
}
