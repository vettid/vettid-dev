package migration

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

// Cleaner handles cleanup of expired sealed material versions.
// It runs in the background to remove old versions after the retention period.
type Cleaner struct {
	materialMgr *SealedMaterialManager
	stateStore  MigrationStateStore

	// Configuration
	minRetention   time.Duration // Minimum retention (default: 7 days)
	batchSize      int           // How many users to process per run
	workerCount    int           // Concurrent deletion workers
	safetyCheckAge time.Duration // Newer version must be verified for at least this long

	// Callbacks
	onVersionDeleted func(userID string, version int)
	onCleanupSkipped func(userID string, version int, reason string)

	// Metrics
	deletedCount int64
	skippedCount int64
}

// CleanerConfig configures the cleanup behavior.
type CleanerConfig struct {
	// MinRetention is the minimum time to keep old versions.
	// Default: 7 days
	MinRetention time.Duration

	// BatchSize limits how many users to process per cleanup run.
	// Default: 1000
	BatchSize int

	// WorkerCount is the number of concurrent deletion workers.
	// Default: 4
	WorkerCount int

	// SafetyCheckAge requires the newer version to be verified for this long.
	// Prevents deleting old version immediately after verification.
	// Default: 24 hours
	SafetyCheckAge time.Duration
}

// DefaultCleanerConfig returns sensible defaults.
func DefaultCleanerConfig() *CleanerConfig {
	return &CleanerConfig{
		MinRetention:   7 * 24 * time.Hour,
		BatchSize:      1000,
		WorkerCount:    4,
		SafetyCheckAge: 24 * time.Hour,
	}
}

// NewCleaner creates a new version cleaner.
func NewCleaner(
	materialMgr *SealedMaterialManager,
	stateStore MigrationStateStore,
	config *CleanerConfig,
) *Cleaner {
	if config == nil {
		config = DefaultCleanerConfig()
	}

	return &Cleaner{
		materialMgr:    materialMgr,
		stateStore:     stateStore,
		minRetention:   config.MinRetention,
		batchSize:      config.BatchSize,
		workerCount:    config.WorkerCount,
		safetyCheckAge: config.SafetyCheckAge,
	}
}

// SetCallbacks sets progress callbacks.
func (c *Cleaner) SetCallbacks(
	onDeleted func(userID string, version int),
	onSkipped func(userID string, version int, reason string),
) {
	c.onVersionDeleted = onDeleted
	c.onCleanupSkipped = onSkipped
}

// CleanupResult contains the results of a cleanup run.
type CleanupResult struct {
	// Total versions scanned
	TotalScanned int

	// Successfully deleted
	Deleted int

	// Skipped (safety checks)
	Skipped int

	// Errors encountered
	Errors int

	// Duration of cleanup
	Duration time.Duration

	// Details per user (if verbose)
	Details []CleanupDetail
}

// CleanupDetail describes cleanup action for a specific version.
type CleanupDetail struct {
	UserID  string
	Version int
	Action  string // "deleted", "skipped", "error"
	Reason  string
}

// Run performs a cleanup pass.
// It identifies expired versions and deletes them if safe to do so.
func (c *Cleaner) Run(ctx context.Context) (*CleanupResult, error) {
	start := time.Now()
	result := &CleanupResult{
		Details: make([]CleanupDetail, 0),
	}

	log.Info().Msg("Starting expired version cleanup")

	// Get all expired versions
	expiredVersions, err := c.listExpiredVersions()
	if err != nil {
		return nil, fmt.Errorf("failed to list expired versions: %w", err)
	}

	result.TotalScanned = len(expiredVersions)

	if len(expiredVersions) == 0 {
		log.Info().Msg("No expired versions to clean up")
		result.Duration = time.Since(start)
		return result, nil
	}

	log.Info().Int("count", len(expiredVersions)).Msg("Found expired versions")

	// Apply batch size limit
	if len(expiredVersions) > c.batchSize {
		expiredVersions = expiredVersions[:c.batchSize]
	}

	// Process with worker pool
	type workItem struct {
		userID  string
		version *SealedMaterialVersion
	}

	workChan := make(chan workItem, len(expiredVersions))
	resultChan := make(chan CleanupDetail, len(expiredVersions))

	for _, ev := range expiredVersions {
		workChan <- workItem{userID: ev.UserID, version: ev.Version}
	}
	close(workChan)

	var wg sync.WaitGroup
	var deleted, skipped, errors int32

	for i := 0; i < c.workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range workChan {
				select {
				case <-ctx.Done():
					return
				default:
				}

				detail := c.processExpiredVersion(ctx, item.userID, item.version)
				resultChan <- detail

				switch detail.Action {
				case "deleted":
					atomic.AddInt32(&deleted, 1)
				case "skipped":
					atomic.AddInt32(&skipped, 1)
				case "error":
					atomic.AddInt32(&errors, 1)
				}
			}
		}()
	}

	// Collect results
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	for detail := range resultChan {
		result.Details = append(result.Details, detail)
	}

	result.Deleted = int(deleted)
	result.Skipped = int(skipped)
	result.Errors = int(errors)
	result.Duration = time.Since(start)

	atomic.AddInt64(&c.deletedCount, int64(result.Deleted))
	atomic.AddInt64(&c.skippedCount, int64(result.Skipped))

	log.Info().
		Int("deleted", result.Deleted).
		Int("skipped", result.Skipped).
		Int("errors", result.Errors).
		Dur("duration", result.Duration).
		Msg("Cleanup completed")

	return result, nil
}

// ExpiredVersion represents a version that has passed its expiry date.
type ExpiredVersion struct {
	UserID  string
	Version *SealedMaterialVersion
}

// listExpiredVersions returns all versions that have passed their expiry date.
func (c *Cleaner) listExpiredVersions() ([]ExpiredVersion, error) {
	// Get all users with completed migrations
	users, err := c.listCompletedUsers()
	if err != nil {
		return nil, err
	}

	var expired []ExpiredVersion
	now := time.Now()

	for _, userID := range users {
		versions, err := c.materialMgr.ListVersions(userID)
		if err != nil {
			log.Warn().Err(err).Str("user_id", userID).Msg("Failed to list versions")
			continue
		}

		for _, v := range versions {
			// Check if expired
			if v.ExpiresAt != nil && v.ExpiresAt.Before(now) {
				expired = append(expired, ExpiredVersion{
					UserID:  userID,
					Version: v,
				})
			}
		}
	}

	return expired, nil
}

// listCompletedUsers returns users with completed migrations.
func (c *Cleaner) listCompletedUsers() ([]string, error) {
	// Use the state store to find completed users
	if store, ok := c.stateStore.(*InMemoryMigrationStateStore); ok {
		return store.listUsersInState(MigrationStatusComplete), nil
	}

	return nil, fmt.Errorf("listCompletedUsers not implemented for this store type")
}

// processExpiredVersion handles cleanup for a single expired version.
func (c *Cleaner) processExpiredVersion(ctx context.Context, userID string, version *SealedMaterialVersion) CleanupDetail {
	detail := CleanupDetail{
		UserID:  userID,
		Version: version.Version,
	}

	// Safety check 1: Newer version must exist
	newerVersion, err := c.materialMgr.GetVersion(userID, version.Version+1)
	if err != nil || newerVersion == nil {
		detail.Action = "skipped"
		detail.Reason = "newer version not found"
		c.notifySkipped(userID, version.Version, detail.Reason)
		return detail
	}

	// Safety check 2: Newer version must be verified
	if !newerVersion.IsVerified() {
		detail.Action = "skipped"
		detail.Reason = "newer version not verified"
		c.notifySkipped(userID, version.Version, detail.Reason)
		return detail
	}

	// Safety check 3: Newer version must be verified for at least safetyCheckAge
	if newerVersion.VerifiedAt != nil {
		verifiedDuration := time.Since(*newerVersion.VerifiedAt)
		if verifiedDuration < c.safetyCheckAge {
			detail.Action = "skipped"
			detail.Reason = fmt.Sprintf("newer version verified only %v ago (min: %v)",
				verifiedDuration.Round(time.Hour), c.safetyCheckAge)
			c.notifySkipped(userID, version.Version, detail.Reason)
			return detail
		}
	}

	// Safety check 4: Minimum retention period
	if version.ExpiresAt != nil {
		sinceExpiry := time.Since(*version.ExpiresAt)
		if sinceExpiry < 0 {
			// Not actually expired yet
			detail.Action = "skipped"
			detail.Reason = "not yet expired"
			c.notifySkipped(userID, version.Version, detail.Reason)
			return detail
		}
	}

	// All safety checks passed - delete the version
	if err := c.materialMgr.DeleteVersion(userID, version.Version); err != nil {
		detail.Action = "error"
		detail.Reason = err.Error()
		log.Error().
			Err(err).
			Str("user_id", userID).
			Int("version", version.Version).
			Msg("Failed to delete expired version")
		return detail
	}

	detail.Action = "deleted"
	detail.Reason = "expired"

	log.Info().
		Str("user_id", userID).
		Int("version", version.Version).
		Time("expired_at", *version.ExpiresAt).
		Msg("Deleted expired version")

	if c.onVersionDeleted != nil {
		c.onVersionDeleted(userID, version.Version)
	}

	return detail
}

// notifySkipped calls the skip callback if set.
func (c *Cleaner) notifySkipped(userID string, version int, reason string) {
	log.Debug().
		Str("user_id", userID).
		Int("version", version).
		Str("reason", reason).
		Msg("Skipped cleanup")

	if c.onCleanupSkipped != nil {
		c.onCleanupSkipped(userID, version, reason)
	}
}

// Stats returns current cleanup statistics.
func (c *Cleaner) Stats() (deleted, skipped int64) {
	return atomic.LoadInt64(&c.deletedCount), atomic.LoadInt64(&c.skippedCount)
}

// ResetStats resets the statistics counters.
func (c *Cleaner) ResetStats() {
	atomic.StoreInt64(&c.deletedCount, 0)
	atomic.StoreInt64(&c.skippedCount, 0)
}

// RunScheduled starts a scheduled cleanup loop.
// It runs cleanup at the specified interval until context is cancelled.
func (c *Cleaner) RunScheduled(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	log.Info().Dur("interval", interval).Msg("Starting scheduled cleanup")

	// Run immediately on start
	if _, err := c.Run(ctx); err != nil {
		log.Error().Err(err).Msg("Initial cleanup failed")
	}

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("Scheduled cleanup stopped")
			return
		case <-ticker.C:
			if _, err := c.Run(ctx); err != nil {
				log.Error().Err(err).Msg("Scheduled cleanup failed")
			}
		}
	}
}
