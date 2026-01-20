package migration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

// Verifier handles warmup verification in the NEW enclave.
// It verifies that migrated sealed material can be unsealed correctly.
type Verifier struct {
	sealer      Sealer
	materialMgr *SealedMaterialManager
	stateStore  MigrationStateStore

	// Configuration
	concurrentWorkers int
	expiryDuration    time.Duration

	// Callbacks
	onUserVerified func(userID string, success bool, err error)
	onProgress     func(verified, failed, remaining int)
}

// VerifierConfig configures the verifier.
type VerifierConfig struct {
	// ConcurrentWorkers is the number of parallel verification workers.
	ConcurrentWorkers int

	// ExpiryDuration is how long to keep old versions after verification.
	ExpiryDuration time.Duration
}

// DefaultVerifierConfig returns sensible defaults.
func DefaultVerifierConfig() *VerifierConfig {
	return &VerifierConfig{
		ConcurrentWorkers: 4,
		ExpiryDuration:    7 * 24 * time.Hour,
	}
}

// NewVerifier creates a new verifier for warmup verification.
func NewVerifier(
	sealer Sealer,
	materialMgr *SealedMaterialManager,
	stateStore MigrationStateStore,
	config *VerifierConfig,
) *Verifier {
	if config == nil {
		config = DefaultVerifierConfig()
	}

	return &Verifier{
		sealer:            sealer,
		materialMgr:       materialMgr,
		stateStore:        stateStore,
		concurrentWorkers: config.ConcurrentWorkers,
		expiryDuration:    config.ExpiryDuration,
	}
}

// SetCallbacks sets progress callbacks.
func (v *Verifier) SetCallbacks(
	onUserVerified func(userID string, success bool, err error),
	onProgress func(verified, failed, remaining int),
) {
	v.onUserVerified = onUserVerified
	v.onProgress = onProgress
}

// VerificationResult contains the result of verifying a single user.
type VerificationResult struct {
	UserID    string
	Success   bool
	Error     error
	Duration  time.Duration
	Version   int
}

// BatchVerificationResult contains the results of batch verification.
type BatchVerificationResult struct {
	TotalUsers   int
	Verified     int
	Failed       int
	Skipped      int
	Results      []VerificationResult
	Duration     time.Duration
}

// VerifyUser verifies a single user's migrated sealed material.
// This should be called by the NEW enclave after migration.
func (v *Verifier) VerifyUser(ctx context.Context, userID string) (*VerificationResult, error) {
	start := time.Now()
	result := &VerificationResult{
		UserID: userID,
	}

	log.Info().Str("user_id", userID).Msg("Starting warmup verification")

	// 1. Get user's migration state
	state, err := v.stateStore.GetUserState(userID)
	if err != nil {
		result.Error = fmt.Errorf("failed to get user state: %w", err)
		return result, result.Error
	}

	// 2. Check if already verified
	if state.MigrationStatus == MigrationStatusComplete {
		log.Debug().Str("user_id", userID).Msg("Already verified, skipping")
		result.Success = true
		result.Duration = time.Since(start)
		return result, nil
	}

	// 3. Must be in verifying state
	if state.MigrationStatus != MigrationStatusVerifying {
		result.Error = fmt.Errorf("unexpected status: %s", state.MigrationStatus)
		return result, result.Error
	}

	// 4. Get the latest (migrated) version
	latestVersion, err := v.materialMgr.GetLatestVersion(userID)
	if err != nil {
		result.Error = fmt.Errorf("failed to get latest version: %w", err)
		v.markVerificationFailed(userID, state, result.Error.Error())
		return result, result.Error
	}

	result.Version = latestVersion.Version

	// 5. Skip if already verified at material level
	if latestVersion.IsVerified() {
		log.Debug().
			Str("user_id", userID).
			Int("version", latestVersion.Version).
			Msg("Material already verified")
		result.Success = true
		result.Duration = time.Since(start)
		return result, nil
	}

	// 6. Unseal with new enclave (proves new PCRs work)
	plaintext, err := v.sealer.Unseal(latestVersion.SealedData)
	if err != nil {
		result.Error = fmt.Errorf("unseal failed: %w", err)
		v.markVerificationFailed(userID, state, result.Error.Error())
		return result, result.Error
	}

	// 7. Verify integrity (check it's valid material)
	if !v.verifyMaterialIntegrity(plaintext) {
		zeroize(plaintext)
		result.Error = fmt.Errorf("integrity check failed")
		v.markVerificationFailed(userID, state, result.Error.Error())
		return result, result.Error
	}

	// 8. Zero out plaintext immediately
	zeroize(plaintext)

	// 9. Mark version as verified (this also sets it as active and schedules old for expiry)
	if err := v.materialMgr.MarkVersionVerified(userID, latestVersion.Version); err != nil {
		result.Error = fmt.Errorf("failed to mark verified: %w", err)
		v.markVerificationFailed(userID, state, result.Error.Error())
		return result, result.Error
	}

	// 10. Update migration state to complete
	state.MigrationStatus = MigrationStatusComplete
	state.UpdatedAt = time.Now()
	if err := v.stateStore.SaveUserState(state); err != nil {
		log.Warn().Err(err).Str("user_id", userID).Msg("Failed to update state to complete")
		// Don't fail - the material is verified
	}

	result.Success = true
	result.Duration = time.Since(start)

	log.Info().
		Str("user_id", userID).
		Int("version", latestVersion.Version).
		Dur("duration", result.Duration).
		Msg("Warmup verification successful")

	return result, nil
}

// verifyMaterialIntegrity checks if unsealed material is valid.
// At minimum, checks it's non-empty and has expected structure.
func (v *Verifier) verifyMaterialIntegrity(plaintext []byte) bool {
	// Basic check: must have content
	if len(plaintext) == 0 {
		return false
	}

	// The sealed material should be at least 32 bytes (a DEK)
	if len(plaintext) < 32 {
		return false
	}

	// Could add more checks here (e.g., JSON parsing, magic bytes)
	return true
}

// markVerificationFailed updates state to failed.
func (v *Verifier) markVerificationFailed(userID string, state *UserMigrationState, errMsg string) {
	state.MigrationStatus = MigrationStatusFailed
	state.LastError = errMsg
	state.UpdatedAt = time.Now()

	if err := v.stateStore.SaveUserState(state); err != nil {
		log.Error().Err(err).Str("user_id", userID).Msg("Failed to save failed state")
	}
}

// VerifyAll runs verification for all users in "verifying" state.
func (v *Verifier) VerifyAll(ctx context.Context) (*BatchVerificationResult, error) {
	start := time.Now()

	// Get users needing verification
	users, err := v.listUsersNeedingVerification()
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	result := &BatchVerificationResult{
		TotalUsers: len(users),
		Results:    make([]VerificationResult, 0, len(users)),
	}

	if len(users) == 0 {
		log.Info().Msg("No users need verification")
		result.Duration = time.Since(start)
		return result, nil
	}

	log.Info().Int("users", len(users)).Msg("Starting batch verification")

	// Process with worker pool
	userChan := make(chan string, len(users))
	resultChan := make(chan VerificationResult, len(users))

	for _, u := range users {
		userChan <- u
	}
	close(userChan)

	var wg sync.WaitGroup
	var verified, failed int32

	for i := 0; i < v.concurrentWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for userID := range userChan {
				select {
				case <-ctx.Done():
					return
				default:
				}

				vr, _ := v.VerifyUser(ctx, userID)
				resultChan <- *vr

				if vr.Success {
					atomic.AddInt32(&verified, 1)
				} else {
					atomic.AddInt32(&failed, 1)
				}

				if v.onUserVerified != nil {
					v.onUserVerified(userID, vr.Success, vr.Error)
				}

				if v.onProgress != nil {
					v.onProgress(
						int(atomic.LoadInt32(&verified)),
						int(atomic.LoadInt32(&failed)),
						len(users)-int(atomic.LoadInt32(&verified))-int(atomic.LoadInt32(&failed)),
					)
				}
			}
		}()
	}

	// Collect results
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	for vr := range resultChan {
		result.Results = append(result.Results, vr)
	}

	result.Verified = int(verified)
	result.Failed = int(failed)
	result.Duration = time.Since(start)

	log.Info().
		Int("verified", result.Verified).
		Int("failed", result.Failed).
		Dur("duration", result.Duration).
		Msg("Batch verification completed")

	return result, nil
}

// listUsersNeedingVerification returns users in "verifying" state.
func (v *Verifier) listUsersNeedingVerification() ([]string, error) {
	stats, err := v.stateStore.GetMigrationStats()
	if err != nil {
		return nil, err
	}

	if stats.Verifying == 0 {
		return []string{}, nil
	}

	// Get all users and filter to verifying state
	// Note: In production, MigrationStateStore should have a method for this
	return v.listUsersInState(MigrationStatusVerifying)
}

// listUsersInState returns all users in the given state.
func (v *Verifier) listUsersInState(status MigrationStatus) ([]string, error) {
	// This is a workaround - ideally MigrationStateStore would have this method
	// For now, we rely on the in-memory implementation's internal access
	if store, ok := v.stateStore.(*InMemoryMigrationStateStore); ok {
		return store.listUsersInState(status), nil
	}

	// Fallback: would need to iterate all users
	return nil, fmt.Errorf("listUsersInState not implemented for this store type")
}

// Add method to InMemoryMigrationStateStore to list users by state
func (s *InMemoryMigrationStateStore) listUsersInState(status MigrationStatus) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var users []string
	for userID, state := range s.states {
		if state.MigrationStatus == status {
			users = append(users, userID)
		}
	}
	return users
}

// ComputeMaterialChecksum computes a checksum of material for logging.
// Does NOT log the actual material, only a hash for debugging.
func ComputeMaterialChecksum(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:8]) // First 8 bytes only
}

// VerificationStats returns current verification statistics.
func (v *Verifier) VerificationStats() (*MigrationStats, error) {
	return v.stateStore.GetMigrationStats()
}
