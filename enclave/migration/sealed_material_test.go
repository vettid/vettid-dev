package migration

import (
	"fmt"
	"testing"
	"time"
)

// mockStorage implements Storage interface for testing
type mockStorage struct {
	metadata map[string][]byte
	sealed   map[string][]byte
	users    []string
}

func newMockStorage() *mockStorage {
	return &mockStorage{
		metadata: make(map[string][]byte),
		sealed:   make(map[string][]byte),
		users:    []string{},
	}
}

func (m *mockStorage) GetMetadata(userID string) ([]byte, error) {
	data, ok := m.metadata[userID]
	if !ok {
		return nil, fmt.Errorf("metadata not found for user %s", userID)
	}
	return data, nil
}

func (m *mockStorage) PutMetadata(userID string, data []byte) error {
	m.metadata[userID] = data
	// Track user if new
	found := false
	for _, u := range m.users {
		if u == userID {
			found = true
			break
		}
	}
	if !found {
		m.users = append(m.users, userID)
	}
	return nil
}

func (m *mockStorage) GetSealedMaterial(userID string, version int) ([]byte, error) {
	key := fmt.Sprintf("%s/v%d", userID, version)
	data, ok := m.sealed[key]
	if !ok {
		return nil, fmt.Errorf("sealed material not found: %s", key)
	}
	return data, nil
}

func (m *mockStorage) PutSealedMaterial(userID string, version int, data []byte) error {
	key := fmt.Sprintf("%s/v%d", userID, version)
	m.sealed[key] = data
	return nil
}

func (m *mockStorage) DeleteSealedMaterial(userID string, version int) error {
	key := fmt.Sprintf("%s/v%d", userID, version)
	delete(m.sealed, key)
	return nil
}

func (m *mockStorage) ListUsers() ([]string, error) {
	return m.users, nil
}

func TestSealedMaterialVersion_States(t *testing.T) {
	now := time.Now()
	past := now.Add(-1 * time.Hour)
	future := now.Add(1 * time.Hour)

	tests := []struct {
		name       string
		version    SealedMaterialVersion
		isVerified bool
		isExpired  bool
		isActive   bool
	}{
		{
			name: "unverified",
			version: SealedMaterialVersion{
				Version:    1,
				VerifiedAt: nil,
				ExpiresAt:  nil,
			},
			isVerified: false,
			isExpired:  false,
			isActive:   false,
		},
		{
			name: "verified not expired",
			version: SealedMaterialVersion{
				Version:    1,
				VerifiedAt: &past,
				ExpiresAt:  nil,
			},
			isVerified: true,
			isExpired:  false,
			isActive:   true,
		},
		{
			name: "verified with future expiry",
			version: SealedMaterialVersion{
				Version:    1,
				VerifiedAt: &past,
				ExpiresAt:  &future,
			},
			isVerified: true,
			isExpired:  false,
			isActive:   true,
		},
		{
			name: "verified but expired",
			version: SealedMaterialVersion{
				Version:    1,
				VerifiedAt: &past,
				ExpiresAt:  &past,
			},
			isVerified: true,
			isExpired:  true,
			isActive:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.version.IsVerified(); got != tt.isVerified {
				t.Errorf("IsVerified() = %v, want %v", got, tt.isVerified)
			}
			if got := tt.version.IsExpired(); got != tt.isExpired {
				t.Errorf("IsExpired() = %v, want %v", got, tt.isExpired)
			}
			if got := tt.version.IsActive(); got != tt.isActive {
				t.Errorf("IsActive() = %v, want %v", got, tt.isActive)
			}
		})
	}
}

func TestSealedMaterialManager_StoreAndRetrieve(t *testing.T) {
	storage := newMockStorage()
	manager := NewSealedMaterialManager(storage)

	userID := "user-123"
	sealedData := []byte("encrypted-dek-data")

	// Store version 1
	version := &SealedMaterialVersion{
		Version:    1,
		PCRVersion: "c7b2f3d8e9a1b4c5",
		SealedData: sealedData,
		CreatedAt:  time.Now(),
	}

	if err := manager.StoreVersion(userID, version); err != nil {
		t.Fatalf("StoreVersion failed: %v", err)
	}

	// Retrieve it
	retrieved, err := manager.GetVersion(userID, 1)
	if err != nil {
		t.Fatalf("GetVersion failed: %v", err)
	}

	if retrieved.Version != 1 {
		t.Errorf("Expected version 1, got %d", retrieved.Version)
	}

	if string(retrieved.SealedData) != string(sealedData) {
		t.Error("Sealed data mismatch")
	}

	if retrieved.PCRVersion != "c7b2f3d8e9a1b4c5" {
		t.Errorf("Expected PCR version c7b2f3d8e9a1b4c5, got %s", retrieved.PCRVersion)
	}
}

func TestSealedMaterialManager_VersionVerification(t *testing.T) {
	storage := newMockStorage()
	manager := NewSealedMaterialManager(storage)

	userID := "user-456"

	// Store version 1
	v1 := &SealedMaterialVersion{
		Version:    1,
		PCRVersion: "aaaa",
		SealedData: []byte("v1-data"),
		CreatedAt:  time.Now(),
	}
	manager.StoreVersion(userID, v1)

	// Mark as verified
	if err := manager.MarkVersionVerified(userID, 1); err != nil {
		t.Fatalf("MarkVersionVerified failed: %v", err)
	}

	// Get current (active) version
	current, err := manager.GetCurrentVersion(userID)
	if err != nil {
		t.Fatalf("GetCurrentVersion failed: %v", err)
	}

	if current.Version != 1 {
		t.Errorf("Expected active version 1, got %d", current.Version)
	}

	if !current.IsVerified() {
		t.Error("Expected version to be verified")
	}
}

func TestSealedMaterialManager_MigrationFlow(t *testing.T) {
	storage := newMockStorage()
	manager := NewSealedMaterialManager(storage)
	manager.ExpiryDuration = 1 * time.Hour // Short for testing

	userID := "user-789"

	// Step 1: Store and verify version 1 (old enclave)
	v1 := &SealedMaterialVersion{
		Version:    1,
		PCRVersion: "old-pcr",
		SealedData: []byte("v1-sealed"),
		CreatedAt:  time.Now(),
	}
	manager.StoreVersion(userID, v1)
	manager.MarkVersionVerified(userID, 1)

	// Step 2: Store version 2 (migrated for new enclave)
	v2 := &SealedMaterialVersion{
		Version:    2,
		PCRVersion: "new-pcr",
		SealedData: []byte("v2-sealed"),
		CreatedAt:  time.Now(),
	}
	manager.StoreVersion(userID, v2)

	// Latest should be v2 (unverified)
	latest, _ := manager.GetLatestVersion(userID)
	if latest.Version != 2 {
		t.Errorf("Expected latest version 2, got %d", latest.Version)
	}

	// Current (active) should still be v1
	current, _ := manager.GetCurrentVersion(userID)
	if current.Version != 1 {
		t.Errorf("Expected active version 1, got %d", current.Version)
	}

	// Step 3: Mark v2 as verified (new enclave warmup passed)
	manager.MarkVersionVerified(userID, 2)

	// Now current should be v2
	current, _ = manager.GetCurrentVersion(userID)
	if current.Version != 2 {
		t.Errorf("Expected active version 2 after verification, got %d", current.Version)
	}

	// v1 should be scheduled for expiry
	v1Retrieved, _ := manager.GetVersion(userID, 1)
	if v1Retrieved.ExpiresAt == nil {
		t.Error("Expected v1 to have expiry set")
	}
}

func TestSealedMaterialManager_DeleteVersion(t *testing.T) {
	storage := newMockStorage()
	manager := NewSealedMaterialManager(storage)

	userID := "user-del"

	// Store and verify version 1
	v1 := &SealedMaterialVersion{
		Version:    1,
		PCRVersion: "pcr1",
		SealedData: []byte("v1"),
		CreatedAt:  time.Now(),
	}
	manager.StoreVersion(userID, v1)
	manager.MarkVersionVerified(userID, 1)

	// Store version 2
	v2 := &SealedMaterialVersion{
		Version:    2,
		PCRVersion: "pcr2",
		SealedData: []byte("v2"),
		CreatedAt:  time.Now(),
	}
	manager.StoreVersion(userID, v2)
	manager.MarkVersionVerified(userID, 2)

	// Try to delete active version - should fail
	if err := manager.DeleteVersion(userID, 2); err == nil {
		t.Error("Expected error when deleting active version")
	}

	// Delete v1 (not active) - should succeed
	if err := manager.DeleteVersion(userID, 1); err != nil {
		t.Errorf("DeleteVersion failed: %v", err)
	}

	// v1 should no longer exist
	if _, err := manager.GetVersion(userID, 1); err == nil {
		t.Error("Expected error when retrieving deleted version")
	}
}

func TestSealedMaterialManager_GetNextVersionNumber(t *testing.T) {
	storage := newMockStorage()
	manager := NewSealedMaterialManager(storage)

	userID := "user-next"

	// No versions yet
	next, err := manager.GetNextVersionNumber(userID)
	if err != nil {
		t.Fatalf("GetNextVersionNumber failed: %v", err)
	}
	if next != 1 {
		t.Errorf("Expected next version 1, got %d", next)
	}

	// Add version 1
	manager.StoreVersion(userID, &SealedMaterialVersion{
		Version:    1,
		PCRVersion: "pcr",
		SealedData: []byte("data"),
		CreatedAt:  time.Now(),
	})

	next, _ = manager.GetNextVersionNumber(userID)
	if next != 2 {
		t.Errorf("Expected next version 2, got %d", next)
	}

	// Add version 2
	manager.StoreVersion(userID, &SealedMaterialVersion{
		Version:    2,
		PCRVersion: "pcr",
		SealedData: []byte("data"),
		CreatedAt:  time.Now(),
	})

	next, _ = manager.GetNextVersionNumber(userID)
	if next != 3 {
		t.Errorf("Expected next version 3, got %d", next)
	}
}

func TestSealedMaterialManager_MigrationRecording(t *testing.T) {
	storage := newMockStorage()
	manager := NewSealedMaterialManager(storage)

	userID := "user-migrate"

	// Setup initial version
	manager.StoreVersion(userID, &SealedMaterialVersion{
		Version:    1,
		PCRVersion: "old",
		SealedData: []byte("data"),
		CreatedAt:  time.Now(),
	})
	manager.MarkVersionVerified(userID, 1)

	// Record migration start
	err := manager.RecordMigrationStart(userID, 1, 2, "old", "new")
	if err != nil {
		t.Fatalf("RecordMigrationStart failed: %v", err)
	}

	// Record migration complete
	err = manager.RecordMigrationComplete(userID, true, "")
	if err != nil {
		t.Fatalf("RecordMigrationComplete failed: %v", err)
	}
}

func TestSealedMaterialManager_ValidationErrors(t *testing.T) {
	storage := newMockStorage()
	manager := NewSealedMaterialManager(storage)

	userID := "user-val"

	// Invalid version number
	err := manager.StoreVersion(userID, &SealedMaterialVersion{
		Version:    0,
		PCRVersion: "pcr",
		SealedData: []byte("data"),
		CreatedAt:  time.Now(),
	})
	if err == nil {
		t.Error("Expected error for version 0")
	}

	// Empty sealed data
	err = manager.StoreVersion(userID, &SealedMaterialVersion{
		Version:    1,
		PCRVersion: "pcr",
		SealedData: []byte{},
		CreatedAt:  time.Now(),
	})
	if err == nil {
		t.Error("Expected error for empty sealed data")
	}

	// Empty PCR version
	err = manager.StoreVersion(userID, &SealedMaterialVersion{
		Version:    1,
		PCRVersion: "",
		SealedData: []byte("data"),
		CreatedAt:  time.Now(),
	})
	if err == nil {
		t.Error("Expected error for empty PCR version")
	}
}

func TestSealedMaterialManager_DuplicateVersion(t *testing.T) {
	storage := newMockStorage()
	manager := NewSealedMaterialManager(storage)

	userID := "user-dup"

	// Store version 1
	v1 := &SealedMaterialVersion{
		Version:    1,
		PCRVersion: "pcr",
		SealedData: []byte("v1"),
		CreatedAt:  time.Now(),
	}
	manager.StoreVersion(userID, v1)

	// Try to store version 1 again
	v1Dup := &SealedMaterialVersion{
		Version:    1,
		PCRVersion: "pcr",
		SealedData: []byte("v1-duplicate"),
		CreatedAt:  time.Now(),
	}
	if err := manager.StoreVersion(userID, v1Dup); err == nil {
		t.Error("Expected error when storing duplicate version")
	}
}

func TestSealedMaterialMetadata_GetExpiredVersions(t *testing.T) {
	now := time.Now()
	past := now.Add(-1 * time.Hour)
	future := now.Add(1 * time.Hour)

	metadata := &SealedMaterialMetadata{
		UserID:        "user",
		ActiveVersion: 3,
		Versions: []VersionInfo{
			{Version: 1, ExpiresAt: &past},   // Expired
			{Version: 2, ExpiresAt: &past},   // Expired
			{Version: 3, ExpiresAt: nil},     // No expiry (active)
			{Version: 4, ExpiresAt: &future}, // Future expiry
		},
	}

	expired := metadata.GetExpiredVersions()
	if len(expired) != 2 {
		t.Errorf("Expected 2 expired versions, got %d", len(expired))
	}
}

func TestPCRVersionID(t *testing.T) {
	tests := []struct {
		pcr0     string
		expected string
	}{
		{
			pcr0:     "c7b2f3d8e9a1b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5",
			expected: "c7b2f3d8e9a1b4c5",
		},
		{
			pcr0:     "short",
			expected: "short",
		},
		{
			pcr0:     "1234567890123456",
			expected: "1234567890123456",
		},
	}

	for _, tt := range tests {
		result := PCRVersionID(tt.pcr0)
		if result != tt.expected {
			t.Errorf("PCRVersionID(%s) = %s, want %s", tt.pcr0[:min(16, len(tt.pcr0))], result, tt.expected)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
