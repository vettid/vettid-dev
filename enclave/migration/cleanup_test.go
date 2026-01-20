package migration

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestCleaner_Run_NoExpiredVersions(t *testing.T) {
	stateStore := NewInMemoryMigrationStateStore()
	materialStorage := newMockStorage()
	materialMgr := NewSealedMaterialManager(materialStorage)

	cleaner := NewCleaner(materialMgr, stateStore, nil)

	result, err := cleaner.Run(context.Background())
	if err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	if result.TotalScanned != 0 {
		t.Errorf("Expected 0 scanned, got %d", result.TotalScanned)
	}

	if result.Deleted != 0 {
		t.Errorf("Expected 0 deleted, got %d", result.Deleted)
	}
}

func TestCleaner_Run_DeletesExpiredVersion(t *testing.T) {
	stateStore := NewInMemoryMigrationStateStore()
	materialStorage := newMockStorage()
	materialMgr := NewSealedMaterialManager(materialStorage)

	config := &CleanerConfig{
		MinRetention:   24 * time.Hour,
		SafetyCheckAge: 0, // No safety check age for this test
		BatchSize:      100,
		WorkerCount:    2,
	}
	cleaner := NewCleaner(materialMgr, stateStore, config)

	userID := "user-cleanup-1"

	// Create version 1 (old, will be expired)
	materialMgr.StoreVersion(userID, &SealedMaterialVersion{
		Version:    1,
		PCRVersion: "old-pcr",
		SealedData: []byte("old-data-at-least-32-bytes-long!"),
		CreatedAt:  time.Now().Add(-10 * 24 * time.Hour),
	})
	materialMgr.MarkVersionVerified(userID, 1)

	// Create version 2 (new, verified 2 hours ago)
	verifiedAt := time.Now().Add(-2 * time.Hour)
	materialMgr.StoreVersion(userID, &SealedMaterialVersion{
		Version:    2,
		PCRVersion: "new-pcr",
		SealedData: []byte("new-data-at-least-32-bytes-long!"),
		CreatedAt:  time.Now().Add(-3 * time.Hour),
		VerifiedAt: &verifiedAt,
	})
	materialMgr.MarkVersionVerified(userID, 2)

	// Now manually set version 1 to be expired (after MarkVersionVerified to avoid overwrite)
	expiredTime := time.Now().Add(-48 * time.Hour) // Expired 2 days ago
	materialMgr.ScheduleVersionExpiry(userID, 1, expiredTime)

	// Set migration as complete
	stateStore.SaveUserState(&UserMigrationState{
		UserID:          userID,
		MigrationStatus: MigrationStatusComplete,
		UpdatedAt:       time.Now(),
	})

	// Track callback
	var deletedVersion int32
	cleaner.SetCallbacks(
		func(uid string, version int) {
			atomic.StoreInt32(&deletedVersion, int32(version))
		},
		nil,
	)

	// Run cleanup
	result, err := cleaner.Run(context.Background())
	if err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	if result.Deleted != 1 {
		t.Errorf("Expected 1 deleted, got %d", result.Deleted)
	}

	if atomic.LoadInt32(&deletedVersion) != 1 {
		t.Errorf("Expected version 1 deleted, got %d", deletedVersion)
	}

	// Verify version 1 is actually gone
	versions, _ := materialMgr.ListVersions(userID)
	for _, v := range versions {
		if v.Version == 1 {
			t.Error("Version 1 should have been deleted")
		}
	}
}

func TestCleaner_Run_SkipsIfNewerNotVerified(t *testing.T) {
	stateStore := NewInMemoryMigrationStateStore()
	materialStorage := newMockStorage()
	materialMgr := NewSealedMaterialManager(materialStorage)

	config := &CleanerConfig{
		MinRetention:   1 * time.Hour,
		SafetyCheckAge: 1 * time.Minute,
		BatchSize:      100,
		WorkerCount:    2,
	}
	cleaner := NewCleaner(materialMgr, stateStore, config)

	userID := "user-no-newer-verified"

	// Create version 1 (expired)
	expiredTime := time.Now().Add(-24 * time.Hour)
	materialMgr.StoreVersion(userID, &SealedMaterialVersion{
		Version:    1,
		PCRVersion: "old-pcr",
		SealedData: []byte("old-data-at-least-32-bytes-long!"),
		CreatedAt:  time.Now().Add(-48 * time.Hour),
	})
	materialMgr.MarkVersionVerified(userID, 1)
	materialMgr.ScheduleVersionExpiry(userID, 1, expiredTime)

	// Create version 2 but do NOT verify it
	materialMgr.StoreVersion(userID, &SealedMaterialVersion{
		Version:    2,
		PCRVersion: "new-pcr",
		SealedData: []byte("new-data-at-least-32-bytes-long!"),
		CreatedAt:  time.Now().Add(-1 * time.Hour),
		// VerifiedAt: nil - not verified
	})

	// Mark complete even though verification didn't happen (edge case)
	stateStore.SaveUserState(&UserMigrationState{
		UserID:          userID,
		MigrationStatus: MigrationStatusComplete,
		UpdatedAt:       time.Now(),
	})

	var skippedVersion int32
	var skipReason string
	cleaner.SetCallbacks(
		nil,
		func(uid string, version int, reason string) {
			atomic.StoreInt32(&skippedVersion, int32(version))
			skipReason = reason
		},
	)

	result, err := cleaner.Run(context.Background())
	if err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	if result.Skipped != 1 {
		t.Errorf("Expected 1 skipped, got %d", result.Skipped)
	}

	if result.Deleted != 0 {
		t.Errorf("Expected 0 deleted, got %d", result.Deleted)
	}

	if atomic.LoadInt32(&skippedVersion) != 1 {
		t.Errorf("Expected version 1 skipped, got %d", skippedVersion)
	}

	if skipReason != "newer version not verified" {
		t.Errorf("Expected 'newer version not verified' reason, got '%s'", skipReason)
	}
}

func TestCleaner_Run_SkipsIfNewerTooRecentlyVerified(t *testing.T) {
	stateStore := NewInMemoryMigrationStateStore()
	materialStorage := newMockStorage()
	materialMgr := NewSealedMaterialManager(materialStorage)

	config := &CleanerConfig{
		MinRetention:   1 * time.Hour,
		SafetyCheckAge: 48 * time.Hour, // Require 48 hours
		BatchSize:      100,
		WorkerCount:    2,
	}
	cleaner := NewCleaner(materialMgr, stateStore, config)

	userID := "user-newer-too-recent"

	// Create version 1
	materialMgr.StoreVersion(userID, &SealedMaterialVersion{
		Version:    1,
		PCRVersion: "old-pcr",
		SealedData: []byte("old-data-at-least-32-bytes-long!"),
		CreatedAt:  time.Now().Add(-72 * time.Hour),
	})
	materialMgr.MarkVersionVerified(userID, 1)

	// Create version 2, verified only 1 hour ago (less than 48 hour requirement)
	verifiedAt := time.Now().Add(-1 * time.Hour)
	materialMgr.StoreVersion(userID, &SealedMaterialVersion{
		Version:    2,
		PCRVersion: "new-pcr",
		SealedData: []byte("new-data-at-least-32-bytes-long!"),
		CreatedAt:  time.Now().Add(-2 * time.Hour),
		VerifiedAt: &verifiedAt,
	})
	materialMgr.MarkVersionVerified(userID, 2)

	// Schedule version 1 expiry AFTER version 2 is verified (to avoid overwrite)
	expiredTime := time.Now().Add(-24 * time.Hour)
	materialMgr.ScheduleVersionExpiry(userID, 1, expiredTime)

	stateStore.SaveUserState(&UserMigrationState{
		UserID:          userID,
		MigrationStatus: MigrationStatusComplete,
		UpdatedAt:       time.Now(),
	})

	result, err := cleaner.Run(context.Background())
	if err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	if result.Skipped != 1 {
		t.Errorf("Expected 1 skipped, got %d", result.Skipped)
	}

	if result.Deleted != 0 {
		t.Errorf("Expected 0 deleted (newer too recently verified), got %d", result.Deleted)
	}
}

func TestCleaner_Run_CannotDeleteActiveVersion(t *testing.T) {
	stateStore := NewInMemoryMigrationStateStore()
	materialStorage := newMockStorage()
	materialMgr := NewSealedMaterialManager(materialStorage)

	config := &CleanerConfig{
		MinRetention:   1 * time.Hour,
		SafetyCheckAge: 1 * time.Minute,
		BatchSize:      100,
		WorkerCount:    2,
	}
	cleaner := NewCleaner(materialMgr, stateStore, config)

	userID := "user-active-version"

	// Create only version 1, make it both active AND expired (edge case)
	expiredTime := time.Now().Add(-24 * time.Hour)
	materialMgr.StoreVersion(userID, &SealedMaterialVersion{
		Version:    1,
		PCRVersion: "pcr",
		SealedData: []byte("data-at-least-32-bytes-long!!!!!"),
		CreatedAt:  time.Now().Add(-72 * time.Hour),
	})
	materialMgr.MarkVersionVerified(userID, 1)
	materialMgr.ScheduleVersionExpiry(userID, 1, expiredTime)

	stateStore.SaveUserState(&UserMigrationState{
		UserID:          userID,
		MigrationStatus: MigrationStatusComplete,
		UpdatedAt:       time.Now(),
	})

	result, err := cleaner.Run(context.Background())
	if err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	// Should be skipped because no newer version exists
	if result.Skipped != 1 {
		t.Errorf("Expected 1 skipped, got %d", result.Skipped)
	}

	if result.Deleted != 0 {
		t.Errorf("Expected 0 deleted (active version), got %d", result.Deleted)
	}
}

func TestCleaner_Run_BatchSizeLimit(t *testing.T) {
	stateStore := NewInMemoryMigrationStateStore()
	materialStorage := newMockStorage()
	materialMgr := NewSealedMaterialManager(materialStorage)

	config := &CleanerConfig{
		MinRetention:   1 * time.Hour,
		SafetyCheckAge: 0, // No safety check age for this test
		BatchSize:      2, // Only process 2 users per run
		WorkerCount:    2,
	}
	cleaner := NewCleaner(materialMgr, stateStore, config)

	// Create 5 users with expired versions
	for i := 1; i <= 5; i++ {
		userID := "user-batch-" + string(rune('0'+i))

		verifiedAt := time.Now().Add(-48 * time.Hour)

		materialMgr.StoreVersion(userID, &SealedMaterialVersion{
			Version:    1,
			PCRVersion: "old",
			SealedData: []byte("old-data-at-least-32-bytes-long!"),
			CreatedAt:  time.Now().Add(-72 * time.Hour),
		})
		materialMgr.MarkVersionVerified(userID, 1)

		materialMgr.StoreVersion(userID, &SealedMaterialVersion{
			Version:    2,
			PCRVersion: "new",
			SealedData: []byte("new-data-at-least-32-bytes-long!"),
			CreatedAt:  time.Now().Add(-48 * time.Hour),
			VerifiedAt: &verifiedAt,
		})
		materialMgr.MarkVersionVerified(userID, 2)

		// Schedule expiry AFTER version 2 is verified
		expiredTime := time.Now().Add(-24 * time.Hour)
		materialMgr.ScheduleVersionExpiry(userID, 1, expiredTime)

		stateStore.SaveUserState(&UserMigrationState{
			UserID:          userID,
			MigrationStatus: MigrationStatusComplete,
			UpdatedAt:       time.Now(),
		})
	}

	result, err := cleaner.Run(context.Background())
	if err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	// BatchSize limits to 2
	if result.Deleted > 2 {
		t.Errorf("Expected at most 2 deleted (batch limit), got %d", result.Deleted)
	}
}

func TestCleaner_Stats(t *testing.T) {
	stateStore := NewInMemoryMigrationStateStore()
	materialStorage := newMockStorage()
	materialMgr := NewSealedMaterialManager(materialStorage)

	cleaner := NewCleaner(materialMgr, stateStore, nil)

	deleted, skipped := cleaner.Stats()
	if deleted != 0 || skipped != 0 {
		t.Errorf("Expected 0/0 stats initially, got %d/%d", deleted, skipped)
	}

	// Run cleanup (no data, so nothing happens)
	cleaner.Run(context.Background())

	deleted, skipped = cleaner.Stats()
	if deleted != 0 || skipped != 0 {
		t.Errorf("Expected 0/0 stats after empty run, got %d/%d", deleted, skipped)
	}

	cleaner.ResetStats()

	deleted, skipped = cleaner.Stats()
	if deleted != 0 || skipped != 0 {
		t.Errorf("Expected 0/0 stats after reset, got %d/%d", deleted, skipped)
	}
}

func TestDefaultCleanerConfig(t *testing.T) {
	config := DefaultCleanerConfig()

	if config.MinRetention != 7*24*time.Hour {
		t.Errorf("Expected 7 day retention, got %v", config.MinRetention)
	}

	if config.BatchSize != 1000 {
		t.Errorf("Expected batch size 1000, got %d", config.BatchSize)
	}

	if config.WorkerCount != 4 {
		t.Errorf("Expected 4 workers, got %d", config.WorkerCount)
	}

	if config.SafetyCheckAge != 24*time.Hour {
		t.Errorf("Expected 24 hour safety check age, got %v", config.SafetyCheckAge)
	}
}
