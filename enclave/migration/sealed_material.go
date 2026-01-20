package migration

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/rs/zerolog/log"
)

// SealedMaterialVersion represents a single version of sealed material.
// Multiple versions may exist during migration to support rollback.
type SealedMaterialVersion struct {
	// Version is the monotonically increasing version number
	Version int `json:"version"`

	// PCRVersion identifies which enclave PCRs this material was sealed for
	// Format: first 16 chars of PCR0 hash (e.g., "c7b2f3d8e9a1b4c5")
	PCRVersion string `json:"pcr_version"`

	// SealedData is the encrypted material (DEK encrypted by KMS)
	SealedData []byte `json:"sealed_data"`

	// CreatedAt is when this version was created
	CreatedAt time.Time `json:"created_at"`

	// VerifiedAt is when warmup verification passed on the new enclave
	// nil means this version hasn't been verified yet
	VerifiedAt *time.Time `json:"verified_at,omitempty"`

	// ExpiresAt is when this version should be deleted
	// Set after a newer version is verified (typically 7 days later)
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// IsVerified returns true if this version has been successfully verified
func (v *SealedMaterialVersion) IsVerified() bool {
	return v.VerifiedAt != nil
}

// IsExpired returns true if this version has passed its expiry time
func (v *SealedMaterialVersion) IsExpired() bool {
	if v.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*v.ExpiresAt)
}

// IsActive returns true if this version is verified and not expired
func (v *SealedMaterialVersion) IsActive() bool {
	return v.IsVerified() && !v.IsExpired()
}

// SealedMaterialMetadata tracks all versions of sealed material for a user.
// Stored as sealed_material.meta.json in S3.
type SealedMaterialMetadata struct {
	// UserID is the owner of this sealed material
	UserID string `json:"user_id"`

	// ActiveVersion is the version currently in use
	// This is the highest verified version number
	ActiveVersion int `json:"active_version"`

	// Versions contains metadata for all versions (without the actual sealed data)
	Versions []VersionInfo `json:"versions"`

	// LastMigration records the most recent migration attempt
	LastMigration *MigrationRecord `json:"last_migration,omitempty"`

	// UpdatedAt is when this metadata was last modified
	UpdatedAt time.Time `json:"updated_at"`
}

// VersionInfo contains metadata about a version without the sealed data itself.
// The actual sealed data is stored separately as sealed_material.v{N}.bin
type VersionInfo struct {
	Version    int        `json:"version"`
	PCRVersion string     `json:"pcr_version"`
	CreatedAt  time.Time  `json:"created_at"`
	VerifiedAt *time.Time `json:"verified_at,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

// MigrationRecord tracks a migration attempt
type MigrationRecord struct {
	FromVersion    int       `json:"from_version"`
	ToVersion      int       `json:"to_version"`
	FromPCRVersion string    `json:"from_pcr_version"`
	ToPCRVersion   string    `json:"to_pcr_version"`
	StartedAt      time.Time `json:"started_at"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
	Status         string    `json:"status"` // "pending", "completed", "failed"
	Error          string    `json:"error,omitempty"`
}

// GetActiveVersionInfo returns the currently active version info
func (m *SealedMaterialMetadata) GetActiveVersionInfo() *VersionInfo {
	for i := range m.Versions {
		if m.Versions[i].Version == m.ActiveVersion {
			return &m.Versions[i]
		}
	}
	return nil
}

// GetLatestVersionInfo returns the highest version number (may be unverified)
func (m *SealedMaterialMetadata) GetLatestVersionInfo() *VersionInfo {
	if len(m.Versions) == 0 {
		return nil
	}

	latest := &m.Versions[0]
	for i := range m.Versions {
		if m.Versions[i].Version > latest.Version {
			latest = &m.Versions[i]
		}
	}
	return latest
}

// GetExpiredVersions returns versions that have passed their expiry time
func (m *SealedMaterialMetadata) GetExpiredVersions() []VersionInfo {
	now := time.Now()
	var expired []VersionInfo

	for _, v := range m.Versions {
		if v.ExpiresAt != nil && now.After(*v.ExpiresAt) {
			expired = append(expired, v)
		}
	}
	return expired
}

// Storage defines the interface for sealed material storage operations.
// Implemented by the parent process which has access to S3.
type Storage interface {
	// GetMetadata retrieves the version metadata for a user
	GetMetadata(userID string) ([]byte, error)

	// PutMetadata stores the version metadata for a user
	PutMetadata(userID string, data []byte) error

	// GetSealedMaterial retrieves a specific version of sealed material
	GetSealedMaterial(userID string, version int) ([]byte, error)

	// PutSealedMaterial stores a specific version of sealed material
	PutSealedMaterial(userID string, version int, data []byte) error

	// DeleteSealedMaterial removes a specific version of sealed material
	DeleteSealedMaterial(userID string, version int) error

	// ListUsers returns all user IDs with sealed material
	ListUsers() ([]string, error)
}

// SealedMaterialManager handles versioned sealed material operations.
type SealedMaterialManager struct {
	storage Storage

	// ExpiryDuration is how long to keep old versions after new version is verified
	ExpiryDuration time.Duration
}

// NewSealedMaterialManager creates a new manager with the given storage backend.
func NewSealedMaterialManager(storage Storage) *SealedMaterialManager {
	return &SealedMaterialManager{
		storage:        storage,
		ExpiryDuration: 7 * 24 * time.Hour, // 7 days default
	}
}

// GetCurrentVersion retrieves the current active sealed material for a user.
// Returns the highest verified version.
func (m *SealedMaterialManager) GetCurrentVersion(userID string) (*SealedMaterialVersion, error) {
	metadata, err := m.loadMetadata(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to load metadata: %w", err)
	}

	if metadata.ActiveVersion == 0 {
		return nil, fmt.Errorf("no active version for user %s", userID)
	}

	return m.loadVersion(userID, metadata.ActiveVersion, metadata)
}

// GetLatestVersion retrieves the latest sealed material version (may be unverified).
func (m *SealedMaterialManager) GetLatestVersion(userID string) (*SealedMaterialVersion, error) {
	metadata, err := m.loadMetadata(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to load metadata: %w", err)
	}

	latest := metadata.GetLatestVersionInfo()
	if latest == nil {
		return nil, fmt.Errorf("no versions for user %s", userID)
	}

	return m.loadVersion(userID, latest.Version, metadata)
}

// GetVersion retrieves a specific version of sealed material.
func (m *SealedMaterialManager) GetVersion(userID string, version int) (*SealedMaterialVersion, error) {
	metadata, err := m.loadMetadata(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to load metadata: %w", err)
	}

	return m.loadVersion(userID, version, metadata)
}

// StoreVersion stores a new version of sealed material.
// Does NOT automatically mark it as verified or active.
func (m *SealedMaterialManager) StoreVersion(userID string, version *SealedMaterialVersion) error {
	if version.Version <= 0 {
		return fmt.Errorf("version must be positive")
	}

	if len(version.SealedData) == 0 {
		return fmt.Errorf("sealed data is required")
	}

	if version.PCRVersion == "" {
		return fmt.Errorf("PCR version is required")
	}

	// Load or create metadata
	metadata, err := m.loadMetadata(userID)
	if err != nil {
		// Create new metadata if doesn't exist
		metadata = &SealedMaterialMetadata{
			UserID:    userID,
			Versions:  []VersionInfo{},
			UpdatedAt: time.Now(),
		}
	}

	// Check version doesn't already exist
	for _, v := range metadata.Versions {
		if v.Version == version.Version {
			return fmt.Errorf("version %d already exists", version.Version)
		}
	}

	// Store the sealed data
	if err := m.storage.PutSealedMaterial(userID, version.Version, version.SealedData); err != nil {
		return fmt.Errorf("failed to store sealed material: %w", err)
	}

	// Add version info to metadata
	metadata.Versions = append(metadata.Versions, VersionInfo{
		Version:    version.Version,
		PCRVersion: version.PCRVersion,
		CreatedAt:  version.CreatedAt,
		VerifiedAt: version.VerifiedAt,
		ExpiresAt:  version.ExpiresAt,
	})

	// Sort versions by version number
	sort.Slice(metadata.Versions, func(i, j int) bool {
		return metadata.Versions[i].Version < metadata.Versions[j].Version
	})

	metadata.UpdatedAt = time.Now()

	// Save metadata
	if err := m.saveMetadata(userID, metadata); err != nil {
		return fmt.Errorf("failed to save metadata: %w", err)
	}

	log.Info().
		Str("user_id", userID).
		Int("version", version.Version).
		Str("pcr_version", version.PCRVersion).
		Msg("Stored new sealed material version")

	return nil
}

// MarkVersionVerified marks a version as verified and sets it as active.
// Also schedules the previous active version for expiry.
func (m *SealedMaterialManager) MarkVersionVerified(userID string, version int) error {
	metadata, err := m.loadMetadata(userID)
	if err != nil {
		return fmt.Errorf("failed to load metadata: %w", err)
	}

	// Find the version
	var targetIdx int = -1
	for i := range metadata.Versions {
		if metadata.Versions[i].Version == version {
			targetIdx = i
			break
		}
	}

	if targetIdx == -1 {
		return fmt.Errorf("version %d not found", version)
	}

	now := time.Now()

	// Mark as verified
	metadata.Versions[targetIdx].VerifiedAt = &now

	// Schedule previous active version for expiry
	if metadata.ActiveVersion > 0 && metadata.ActiveVersion != version {
		for i := range metadata.Versions {
			if metadata.Versions[i].Version == metadata.ActiveVersion {
				expiresAt := now.Add(m.ExpiryDuration)
				metadata.Versions[i].ExpiresAt = &expiresAt
				log.Info().
					Str("user_id", userID).
					Int("version", metadata.ActiveVersion).
					Time("expires_at", expiresAt).
					Msg("Scheduled old version for expiry")
				break
			}
		}
	}

	// Set new active version
	previousActive := metadata.ActiveVersion
	metadata.ActiveVersion = version
	metadata.UpdatedAt = now

	// Save metadata
	if err := m.saveMetadata(userID, metadata); err != nil {
		return fmt.Errorf("failed to save metadata: %w", err)
	}

	log.Info().
		Str("user_id", userID).
		Int("version", version).
		Int("previous_active", previousActive).
		Msg("Marked version as verified and active")

	return nil
}

// ScheduleVersionExpiry sets an expiry time for a specific version.
func (m *SealedMaterialManager) ScheduleVersionExpiry(userID string, version int, expiresAt time.Time) error {
	metadata, err := m.loadMetadata(userID)
	if err != nil {
		return fmt.Errorf("failed to load metadata: %w", err)
	}

	// Find and update the version
	found := false
	for i := range metadata.Versions {
		if metadata.Versions[i].Version == version {
			metadata.Versions[i].ExpiresAt = &expiresAt
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("version %d not found", version)
	}

	metadata.UpdatedAt = time.Now()

	if err := m.saveMetadata(userID, metadata); err != nil {
		return fmt.Errorf("failed to save metadata: %w", err)
	}

	log.Info().
		Str("user_id", userID).
		Int("version", version).
		Time("expires_at", expiresAt).
		Msg("Scheduled version for expiry")

	return nil
}

// DeleteVersion removes a specific version of sealed material.
// Cannot delete the active version.
func (m *SealedMaterialManager) DeleteVersion(userID string, version int) error {
	metadata, err := m.loadMetadata(userID)
	if err != nil {
		return fmt.Errorf("failed to load metadata: %w", err)
	}

	if metadata.ActiveVersion == version {
		return fmt.Errorf("cannot delete active version %d", version)
	}

	// Find and remove from metadata
	found := false
	newVersions := make([]VersionInfo, 0, len(metadata.Versions)-1)
	for _, v := range metadata.Versions {
		if v.Version == version {
			found = true
			continue
		}
		newVersions = append(newVersions, v)
	}

	if !found {
		return fmt.Errorf("version %d not found", version)
	}

	// Delete the sealed data
	if err := m.storage.DeleteSealedMaterial(userID, version); err != nil {
		return fmt.Errorf("failed to delete sealed material: %w", err)
	}

	metadata.Versions = newVersions
	metadata.UpdatedAt = time.Now()

	if err := m.saveMetadata(userID, metadata); err != nil {
		return fmt.Errorf("failed to save metadata: %w", err)
	}

	log.Info().
		Str("user_id", userID).
		Int("version", version).
		Msg("Deleted sealed material version")

	return nil
}

// CleanupExpiredVersions removes all expired versions for a user.
// Returns the number of versions deleted.
func (m *SealedMaterialManager) CleanupExpiredVersions(userID string) (int, error) {
	metadata, err := m.loadMetadata(userID)
	if err != nil {
		return 0, fmt.Errorf("failed to load metadata: %w", err)
	}

	expired := metadata.GetExpiredVersions()
	deleted := 0

	for _, v := range expired {
		if v.Version == metadata.ActiveVersion {
			// Safety check - never delete active version even if expired
			log.Warn().
				Str("user_id", userID).
				Int("version", v.Version).
				Msg("Skipping deletion of expired active version")
			continue
		}

		if err := m.DeleteVersion(userID, v.Version); err != nil {
			log.Error().Err(err).
				Str("user_id", userID).
				Int("version", v.Version).
				Msg("Failed to delete expired version")
			continue
		}
		deleted++
	}

	return deleted, nil
}

// ListVersions returns all versions of sealed material for a user.
func (m *SealedMaterialManager) ListVersions(userID string) ([]*SealedMaterialVersion, error) {
	metadata, err := m.loadMetadata(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to load metadata: %w", err)
	}

	versions := make([]*SealedMaterialVersion, 0, len(metadata.Versions))
	for _, info := range metadata.Versions {
		v := &SealedMaterialVersion{
			Version:    info.Version,
			PCRVersion: info.PCRVersion,
			CreatedAt:  info.CreatedAt,
			VerifiedAt: info.VerifiedAt,
			ExpiresAt:  info.ExpiresAt,
		}
		// Note: SealedData is not loaded here for efficiency
		// Use GetVersion() to get full data for a specific version
		versions = append(versions, v)
	}

	return versions, nil
}

// GetNextVersionNumber returns the next version number to use for a new version.
func (m *SealedMaterialManager) GetNextVersionNumber(userID string) (int, error) {
	metadata, err := m.loadMetadata(userID)
	if err != nil {
		// No metadata yet, start at version 1
		return 1, nil
	}

	latest := metadata.GetLatestVersionInfo()
	if latest == nil {
		return 1, nil
	}

	return latest.Version + 1, nil
}

// RecordMigrationStart records that a migration has started.
func (m *SealedMaterialManager) RecordMigrationStart(userID string, fromVersion, toVersion int, fromPCR, toPCR string) error {
	metadata, err := m.loadMetadata(userID)
	if err != nil {
		return fmt.Errorf("failed to load metadata: %w", err)
	}

	metadata.LastMigration = &MigrationRecord{
		FromVersion:    fromVersion,
		ToVersion:      toVersion,
		FromPCRVersion: fromPCR,
		ToPCRVersion:   toPCR,
		StartedAt:      time.Now(),
		Status:         "pending",
	}
	metadata.UpdatedAt = time.Now()

	if err := m.saveMetadata(userID, metadata); err != nil {
		return fmt.Errorf("failed to save metadata: %w", err)
	}

	return nil
}

// RecordMigrationComplete records that a migration has completed.
func (m *SealedMaterialManager) RecordMigrationComplete(userID string, success bool, errMsg string) error {
	metadata, err := m.loadMetadata(userID)
	if err != nil {
		return fmt.Errorf("failed to load metadata: %w", err)
	}

	if metadata.LastMigration == nil {
		return fmt.Errorf("no migration in progress")
	}

	now := time.Now()
	metadata.LastMigration.CompletedAt = &now

	if success {
		metadata.LastMigration.Status = "completed"
	} else {
		metadata.LastMigration.Status = "failed"
		metadata.LastMigration.Error = errMsg
	}

	metadata.UpdatedAt = now

	if err := m.saveMetadata(userID, metadata); err != nil {
		return fmt.Errorf("failed to save metadata: %w", err)
	}

	return nil
}

// loadMetadata loads the metadata for a user from storage.
func (m *SealedMaterialManager) loadMetadata(userID string) (*SealedMaterialMetadata, error) {
	data, err := m.storage.GetMetadata(userID)
	if err != nil {
		return nil, err
	}

	var metadata SealedMaterialMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	return &metadata, nil
}

// saveMetadata saves the metadata for a user to storage.
func (m *SealedMaterialManager) saveMetadata(userID string, metadata *SealedMaterialMetadata) error {
	data, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	return m.storage.PutMetadata(userID, data)
}

// loadVersion loads a specific version with its sealed data.
func (m *SealedMaterialManager) loadVersion(userID string, version int, metadata *SealedMaterialMetadata) (*SealedMaterialVersion, error) {
	// Find version info
	var info *VersionInfo
	for i := range metadata.Versions {
		if metadata.Versions[i].Version == version {
			info = &metadata.Versions[i]
			break
		}
	}

	if info == nil {
		return nil, fmt.Errorf("version %d not found in metadata", version)
	}

	// Load sealed data
	sealedData, err := m.storage.GetSealedMaterial(userID, version)
	if err != nil {
		return nil, fmt.Errorf("failed to load sealed material: %w", err)
	}

	return &SealedMaterialVersion{
		Version:    info.Version,
		PCRVersion: info.PCRVersion,
		SealedData: sealedData,
		CreatedAt:  info.CreatedAt,
		VerifiedAt: info.VerifiedAt,
		ExpiresAt:  info.ExpiresAt,
	}, nil
}

// PCRVersionID generates a short identifier from PCR0 for version tracking.
// Returns the first 16 characters of the PCR0 hex string.
func PCRVersionID(pcr0 string) string {
	if len(pcr0) >= 16 {
		return pcr0[:16]
	}
	return pcr0
}
