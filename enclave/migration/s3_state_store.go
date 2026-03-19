package migration

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// S3StateStore persists per-user migration state to S3.
// Each user's state is stored at vaults/{ownerSpace}/migration_state.json.
//
// This store is used by the batch Migrator for tracking migration progress
// across restarts. The user-consent flow uses EncryptedStorage within the
// vault-manager instead (already DEK-encrypted per-user).
type S3StateStore struct {
	storage StorageClient
	mu      sync.RWMutex
	// In-memory cache of known user states
	cache map[string]*UserMigrationState
}

// StorageClient abstracts S3 get/put operations.
// Implemented by the parent process proxy.
type StorageClient interface {
	Get(key string) ([]byte, error)
	Put(key string, data []byte) error
	List(prefix string) ([]string, error)
}

// NewS3StateStore creates a new S3-backed migration state store.
func NewS3StateStore(storage StorageClient) *S3StateStore {
	return &S3StateStore{
		storage: storage,
		cache:   make(map[string]*UserMigrationState),
	}
}

func (s *S3StateStore) stateKey(userID string) string {
	return fmt.Sprintf("vaults/%s/migration_state.json", userID)
}

// GetUserState retrieves the migration state for a user.
func (s *S3StateStore) GetUserState(userID string) (*UserMigrationState, error) {
	// Check cache first
	s.mu.RLock()
	if state, ok := s.cache[userID]; ok {
		s.mu.RUnlock()
		copy := *state
		return &copy, nil
	}
	s.mu.RUnlock()

	// Load from S3
	key := s.stateKey(userID)
	data, err := s.storage.Get(key)
	if err != nil {
		return nil, fmt.Errorf("state not found for user %s: %w", userID, err)
	}

	var state UserMigrationState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to parse state for user %s: %w", userID, err)
	}

	// Update cache
	s.mu.Lock()
	s.cache[userID] = &state
	s.mu.Unlock()

	copy := state
	return &copy, nil
}

// SaveUserState persists the migration state for a user.
func (s *S3StateStore) SaveUserState(state *UserMigrationState) error {
	state.UpdatedAt = time.Now()

	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}

	key := s.stateKey(state.UserID)
	if err := s.storage.Put(key, data); err != nil {
		return fmt.Errorf("failed to store state for user %s: %w", state.UserID, err)
	}

	// Update cache
	s.mu.Lock()
	copy := *state
	s.cache[state.UserID] = &copy
	s.mu.Unlock()

	log.Debug().
		Str("user_id", state.UserID).
		Str("status", string(state.MigrationStatus)).
		Msg("Migration state saved to S3")

	return nil
}

// ListUsersNeedingMigration returns users in pending or failed state.
// Uses the in-memory cache populated by prior GetUserState/SaveUserState calls.
func (s *S3StateStore) ListUsersNeedingMigration() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var users []string
	for userID, state := range s.cache {
		if state.MigrationStatus == MigrationStatusPending ||
			state.MigrationStatus == MigrationStatusFailed {
			users = append(users, userID)
		}
	}
	return users, nil
}

// GetMigrationStats returns aggregate statistics from the cache.
func (s *S3StateStore) GetMigrationStats() (*MigrationStats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := &MigrationStats{
		TotalUsers: len(s.cache),
	}

	for _, state := range s.cache {
		switch state.MigrationStatus {
		case MigrationStatusPending:
			stats.Pending++
		case MigrationStatusMigrating:
			stats.Migrating++
		case MigrationStatusVerifying:
			stats.Verifying++
		case MigrationStatusComplete:
			stats.Complete++
		case MigrationStatusFailed:
			stats.Failed++
		case MigrationStatusSkipped:
			stats.Skipped++
		}
	}

	return stats, nil
}

// LoadAllUsers populates the cache by listing migration state files from S3.
// This should be called during startup for the batch migration path.
func (s *S3StateStore) LoadAllUsers() error {
	keys, err := s.storage.List("vaults/")
	if err != nil {
		return fmt.Errorf("failed to list vault directories: %w", err)
	}

	loaded := 0
	for _, key := range keys {
		// Only process migration_state.json files
		if len(key) < len("vaults//migration_state.json") {
			continue
		}

		data, err := s.storage.Get(key)
		if err != nil {
			log.Warn().Err(err).Str("key", key).Msg("Failed to load migration state")
			continue
		}

		var state UserMigrationState
		if err := json.Unmarshal(data, &state); err != nil {
			log.Warn().Err(err).Str("key", key).Msg("Failed to parse migration state")
			continue
		}

		s.mu.Lock()
		s.cache[state.UserID] = &state
		s.mu.Unlock()
		loaded++
	}

	log.Info().Int("loaded", loaded).Msg("Loaded migration states from S3")
	return nil
}
