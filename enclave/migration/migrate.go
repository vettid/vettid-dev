package migration

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// MigrationStatus represents the state of a user's migration.
type MigrationStatus string

const (
	MigrationStatusPending   MigrationStatus = "pending"   // Waiting to be migrated
	MigrationStatusMigrating MigrationStatus = "migrating" // Migration in progress
	MigrationStatusVerifying MigrationStatus = "verifying" // Waiting for new enclave verification
	MigrationStatusComplete  MigrationStatus = "complete"  // Migration successful
	MigrationStatusFailed    MigrationStatus = "failed"    // Migration failed
	MigrationStatusSkipped   MigrationStatus = "skipped"   // Skipped (already migrated or not needed)
)

// UserMigrationState tracks the migration state for a single user.
type UserMigrationState struct {
	UserID          string          `json:"user_id"`
	CurrentVersion  int             `json:"current_version"`
	TargetVersion   int             `json:"target_version,omitempty"`
	MigrationStatus MigrationStatus `json:"status"`
	LockedAt        *time.Time      `json:"locked_at,omitempty"`
	LockedBy        string          `json:"locked_by,omitempty"`
	LastError       string          `json:"last_error,omitempty"`
	AttemptCount    int             `json:"attempt_count"`
	StartedAt       *time.Time      `json:"started_at,omitempty"`
	CompletedAt     *time.Time      `json:"completed_at,omitempty"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

// MigrationStateStore persists user migration states.
type MigrationStateStore interface {
	// GetUserState retrieves the migration state for a user.
	GetUserState(userID string) (*UserMigrationState, error)

	// SaveUserState persists the migration state for a user.
	SaveUserState(state *UserMigrationState) error

	// ListUsersNeedingMigration returns users in pending or failed state.
	ListUsersNeedingMigration() ([]string, error)

	// GetMigrationStats returns aggregate statistics.
	GetMigrationStats() (*MigrationStats, error)
}

// MigrationStats contains aggregate migration statistics.
type MigrationStats struct {
	TotalUsers     int `json:"total_users"`
	Pending        int `json:"pending"`
	Migrating      int `json:"migrating"`
	Verifying      int `json:"verifying"`
	Complete       int `json:"complete"`
	Failed         int `json:"failed"`
	Skipped        int `json:"skipped"`
}

// Sealer handles cryptographic sealing operations.
type Sealer interface {
	// Unseal decrypts sealed material using current enclave attestation.
	Unseal(sealedData []byte) ([]byte, error)

	// SealForPCRs encrypts material for specific PCR values.
	// Used to seal for the NEW enclave's PCRs during migration.
	SealForPCRs(plaintext []byte, targetPCRs *PCRValues) ([]byte, error)
}

// MigrationConfig configures the migration process.
type MigrationConfig struct {
	// TargetPCRs are the PCR values of the new enclave.
	TargetPCRs *PCRValues

	// CurrentPCRs are the PCR values of the current (old) enclave.
	CurrentPCRs *PCRValues

	// EnclaveInstanceID uniquely identifies this enclave instance.
	EnclaveInstanceID string

	// LockTimeout is how long to wait for per-user locks.
	LockTimeout time.Duration

	// MaxRetries is the maximum number of retry attempts per user.
	MaxRetries int

	// ConcurrentWorkers is the number of concurrent migration workers.
	ConcurrentWorkers int

	// BatchSize is how many users to process in each batch.
	BatchSize int
}

// DefaultMigrationConfig returns sensible defaults.
func DefaultMigrationConfig() *MigrationConfig {
	return &MigrationConfig{
		LockTimeout:       5 * time.Minute,
		MaxRetries:        3,
		ConcurrentWorkers: 4,
		BatchSize:         100,
	}
}

// Migrator handles the migration of sealed material between enclave versions.
type Migrator struct {
	config        *MigrationConfig
	lockManager   *LockManager
	stateStore    MigrationStateStore
	materialMgr   *SealedMaterialManager
	sealer        Sealer

	// Callbacks for progress reporting
	onUserStart    func(userID string)
	onUserComplete func(userID string, success bool, err error)
	onProgress     func(stats *MigrationStats)
}

// NewMigrator creates a new migrator.
func NewMigrator(
	config *MigrationConfig,
	lockManager *LockManager,
	stateStore MigrationStateStore,
	materialMgr *SealedMaterialManager,
	sealer Sealer,
) *Migrator {
	if config == nil {
		config = DefaultMigrationConfig()
	}

	return &Migrator{
		config:      config,
		lockManager: lockManager,
		stateStore:  stateStore,
		materialMgr: materialMgr,
		sealer:      sealer,
	}
}

// SetCallbacks sets progress callbacks.
func (m *Migrator) SetCallbacks(
	onStart func(userID string),
	onComplete func(userID string, success bool, err error),
	onProgress func(stats *MigrationStats),
) {
	m.onUserStart = onStart
	m.onUserComplete = onComplete
	m.onProgress = onProgress
}

// MigrateAll migrates all users that need migration.
// Runs until all users are processed or context is cancelled.
func (m *Migrator) MigrateAll(ctx context.Context) (*MigrationStats, error) {
	if m.config.TargetPCRs == nil {
		return nil, fmt.Errorf("target PCRs not configured")
	}

	log.Info().
		Str("target_pcr0", m.config.TargetPCRs.PCR0[:16]+"...").
		Int("workers", m.config.ConcurrentWorkers).
		Msg("Starting migration for all users")

	// Get users needing migration
	users, err := m.stateStore.ListUsersNeedingMigration()
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	if len(users) == 0 {
		log.Info().Msg("No users need migration")
		return m.stateStore.GetMigrationStats()
	}

	log.Info().Int("users", len(users)).Msg("Found users needing migration")

	// Process users with worker pool
	userChan := make(chan string, len(users))
	for _, u := range users {
		userChan <- u
	}
	close(userChan)

	var wg sync.WaitGroup
	for i := 0; i < m.config.ConcurrentWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			m.migrationWorker(ctx, workerID, userChan)
		}(i)
	}

	wg.Wait()

	// Get final stats
	stats, err := m.stateStore.GetMigrationStats()
	if err != nil {
		log.Warn().Err(err).Msg("Failed to get final migration stats")
	}

	log.Info().
		Int("complete", stats.Complete).
		Int("failed", stats.Failed).
		Int("verifying", stats.Verifying).
		Msg("Migration batch completed")

	return stats, nil
}

// migrationWorker processes users from the channel.
func (m *Migrator) migrationWorker(ctx context.Context, workerID int, users <-chan string) {
	for userID := range users {
		select {
		case <-ctx.Done():
			log.Info().Int("worker", workerID).Msg("Migration worker cancelled")
			return
		default:
		}

		if m.onUserStart != nil {
			m.onUserStart(userID)
		}

		err := m.MigrateUser(ctx, userID)

		if m.onUserComplete != nil {
			m.onUserComplete(userID, err == nil, err)
		}

		if m.onProgress != nil {
			if stats, err := m.stateStore.GetMigrationStats(); err == nil {
				m.onProgress(stats)
			}
		}
	}
}

// MigrateUser migrates a single user's sealed material.
func (m *Migrator) MigrateUser(ctx context.Context, userID string) error {
	log.Info().Str("user_id", userID).Msg("Starting user migration")

	// Get or create state
	state, err := m.stateStore.GetUserState(userID)
	if err != nil {
		// Create new state
		state = &UserMigrationState{
			UserID:          userID,
			MigrationStatus: MigrationStatusPending,
			UpdatedAt:       time.Now(),
		}
	}

	// Skip if already complete or verifying
	if state.MigrationStatus == MigrationStatusComplete ||
		state.MigrationStatus == MigrationStatusVerifying {
		log.Info().
			Str("user_id", userID).
			Str("status", string(state.MigrationStatus)).
			Msg("Skipping user - already processed")
		return nil
	}

	// Check retry count
	if state.AttemptCount >= m.config.MaxRetries {
		log.Warn().
			Str("user_id", userID).
			Int("attempts", state.AttemptCount).
			Msg("Max retries exceeded, skipping user")
		return fmt.Errorf("max retries exceeded (%d attempts)", state.AttemptCount)
	}

	// Acquire per-user lock
	lock, err := m.lockManager.AcquireUserMigrationLock(userID, m.config.LockTimeout)
	if err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer lock.Release()

	// Update state to migrating
	now := time.Now()
	state.MigrationStatus = MigrationStatusMigrating
	state.LockedAt = &now
	state.LockedBy = m.config.EnclaveInstanceID
	state.AttemptCount++
	state.StartedAt = &now
	state.UpdatedAt = now
	state.LastError = ""

	if err := m.stateStore.SaveUserState(state); err != nil {
		return fmt.Errorf("failed to save state: %w", err)
	}

	// Perform the actual migration
	if err := m.performMigration(ctx, userID, state); err != nil {
		// Update state to failed
		state.MigrationStatus = MigrationStatusFailed
		state.LastError = err.Error()
		state.UpdatedAt = time.Now()
		m.stateStore.SaveUserState(state)

		log.Error().Err(err).
			Str("user_id", userID).
			Int("attempt", state.AttemptCount).
			Msg("Migration failed")

		return err
	}

	// Update state to verifying (new enclave must verify)
	completedAt := time.Now()
	state.MigrationStatus = MigrationStatusVerifying
	state.CompletedAt = &completedAt
	state.UpdatedAt = completedAt
	state.LockedAt = nil
	state.LockedBy = ""

	if err := m.stateStore.SaveUserState(state); err != nil {
		return fmt.Errorf("failed to save completion state: %w", err)
	}

	log.Info().
		Str("user_id", userID).
		Int("target_version", state.TargetVersion).
		Msg("User migration completed, awaiting verification")

	return nil
}

// performMigration does the actual unsealing and resealing.
func (m *Migrator) performMigration(ctx context.Context, userID string, state *UserMigrationState) error {
	// 1. Get current sealed material
	currentVersion, err := m.materialMgr.GetCurrentVersion(userID)
	if err != nil {
		return fmt.Errorf("failed to get current version: %w", err)
	}

	state.CurrentVersion = currentVersion.Version

	log.Debug().
		Str("user_id", userID).
		Int("version", currentVersion.Version).
		Str("pcr_version", currentVersion.PCRVersion).
		Msg("Loaded current sealed material")

	// 2. Unseal with current (old) attestation
	plaintext, err := m.sealer.Unseal(currentVersion.SealedData)
	if err != nil {
		return fmt.Errorf("failed to unseal: %w", err)
	}

	// 3. Re-seal for new PCRs
	newSealedData, err := m.sealer.SealForPCRs(plaintext, m.config.TargetPCRs)

	// 4. CRITICAL: Zero out plaintext immediately
	zeroize(plaintext)

	if err != nil {
		return fmt.Errorf("failed to re-seal: %w", err)
	}

	// 5. Get next version number
	nextVersion, err := m.materialMgr.GetNextVersionNumber(userID)
	if err != nil {
		return fmt.Errorf("failed to get next version: %w", err)
	}

	state.TargetVersion = nextVersion

	// 6. Record migration start
	targetPCRVersion := PCRVersionID(m.config.TargetPCRs.PCR0)
	if err := m.materialMgr.RecordMigrationStart(
		userID,
		currentVersion.Version,
		nextVersion,
		currentVersion.PCRVersion,
		targetPCRVersion,
	); err != nil {
		log.Warn().Err(err).Msg("Failed to record migration start")
	}

	// 7. Store new version (unverified)
	newVersion := &SealedMaterialVersion{
		Version:    nextVersion,
		PCRVersion: targetPCRVersion,
		SealedData: newSealedData,
		CreatedAt:  time.Now(),
	}

	if err := m.materialMgr.StoreVersion(userID, newVersion); err != nil {
		m.materialMgr.RecordMigrationComplete(userID, false, err.Error())
		return fmt.Errorf("failed to store new version: %w", err)
	}

	// 8. Record migration complete (awaiting verification)
	m.materialMgr.RecordMigrationComplete(userID, true, "")

	log.Info().
		Str("user_id", userID).
		Int("from_version", currentVersion.Version).
		Int("to_version", nextVersion).
		Str("target_pcr", targetPCRVersion).
		Msg("Sealed material migrated successfully")

	return nil
}

// MarkUserVerified marks a user's migration as verified by the new enclave.
// Called by the NEW enclave after successful warmup.
func (m *Migrator) MarkUserVerified(userID string) error {
	state, err := m.stateStore.GetUserState(userID)
	if err != nil {
		return fmt.Errorf("failed to get user state: %w", err)
	}

	if state.MigrationStatus != MigrationStatusVerifying {
		return fmt.Errorf("unexpected status: %s", state.MigrationStatus)
	}

	// Mark the sealed material version as verified
	if err := m.materialMgr.MarkVersionVerified(userID, state.TargetVersion); err != nil {
		return fmt.Errorf("failed to mark version verified: %w", err)
	}

	// Update migration state
	state.MigrationStatus = MigrationStatusComplete
	state.UpdatedAt = time.Now()

	if err := m.stateStore.SaveUserState(state); err != nil {
		return fmt.Errorf("failed to save state: %w", err)
	}

	log.Info().
		Str("user_id", userID).
		Int("version", state.TargetVersion).
		Msg("User migration verified and complete")

	return nil
}

// zeroize securely clears sensitive data from memory.
func zeroize(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

// InMemoryMigrationStateStore is a simple in-memory state store for testing.
type InMemoryMigrationStateStore struct {
	states map[string]*UserMigrationState
	mu     sync.RWMutex
}

// NewInMemoryMigrationStateStore creates a new in-memory state store.
func NewInMemoryMigrationStateStore() *InMemoryMigrationStateStore {
	return &InMemoryMigrationStateStore{
		states: make(map[string]*UserMigrationState),
	}
}

func (s *InMemoryMigrationStateStore) GetUserState(userID string) (*UserMigrationState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	state, ok := s.states[userID]
	if !ok {
		return nil, fmt.Errorf("state not found for user %s", userID)
	}

	// Return a copy
	copy := *state
	return &copy, nil
}

func (s *InMemoryMigrationStateStore) SaveUserState(state *UserMigrationState) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Store a copy
	copy := *state
	s.states[state.UserID] = &copy
	return nil
}

func (s *InMemoryMigrationStateStore) ListUsersNeedingMigration() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var users []string
	for userID, state := range s.states {
		if state.MigrationStatus == MigrationStatusPending ||
			state.MigrationStatus == MigrationStatusFailed {
			users = append(users, userID)
		}
	}
	return users, nil
}

func (s *InMemoryMigrationStateStore) GetMigrationStats() (*MigrationStats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := &MigrationStats{
		TotalUsers: len(s.states),
	}

	for _, state := range s.states {
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

// AddPendingUser adds a user in pending state (for testing).
func (s *InMemoryMigrationStateStore) AddPendingUser(userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.states[userID] = &UserMigrationState{
		UserID:          userID,
		MigrationStatus: MigrationStatusPending,
		UpdatedAt:       time.Now(),
	}
}
