package migration

import (
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// LockStore defines the interface for distributed lock storage.
// Implementations may use DynamoDB, Redis, or in-memory for testing.
type LockStore interface {
	// TryAcquire attempts to acquire a lock for the given key.
	// Returns true if lock was acquired, false if already held by another holder.
	TryAcquire(key string, holder string, ttl time.Duration) (bool, error)

	// Release releases a lock. Only succeeds if holder matches.
	Release(key string, holder string) error

	// Refresh extends the TTL of a held lock.
	Refresh(key string, holder string, ttl time.Duration) error

	// GetLockInfo returns information about a lock, or nil if not held.
	GetLockInfo(key string) (*LockInfo, error)
}

// LockInfo contains information about a held lock.
type LockInfo struct {
	Key       string    `json:"key"`
	Holder    string    `json:"holder"`
	AcquiredAt time.Time `json:"acquired_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// IsExpired returns true if the lock has expired.
func (l *LockInfo) IsExpired() bool {
	return time.Now().After(l.ExpiresAt)
}

// Lock represents a held distributed lock with automatic refresh.
type Lock struct {
	key        string
	holder     string
	store      LockStore
	ttl        time.Duration
	released   bool
	stopRefresh chan struct{}
	mu         sync.Mutex
}

// Release releases the lock. Safe to call multiple times.
func (l *Lock) Release() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.released {
		return nil
	}

	// Stop the refresh goroutine
	if l.stopRefresh != nil {
		close(l.stopRefresh)
	}

	l.released = true

	if err := l.store.Release(l.key, l.holder); err != nil {
		log.Warn().Err(err).
			Str("key", l.key).
			Str("holder", l.holder).
			Msg("Failed to release lock")
		return err
	}

	log.Debug().
		Str("key", l.key).
		Str("holder", l.holder).
		Msg("Lock released")

	return nil
}

// IsReleased returns true if the lock has been released.
func (l *Lock) IsReleased() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.released
}

// LockManager manages distributed locks for migration.
type LockManager struct {
	store        LockStore
	holderID     string // Unique identifier for this enclave instance
	defaultTTL   time.Duration
	refreshInterval time.Duration
}

// NewLockManager creates a new lock manager.
// holderID should be unique per enclave instance (e.g., instance ID or UUID).
func NewLockManager(store LockStore, holderID string) *LockManager {
	return &LockManager{
		store:           store,
		holderID:        holderID,
		defaultTTL:      5 * time.Minute,
		refreshInterval: 1 * time.Minute,
	}
}

// SetDefaultTTL sets the default lock TTL.
func (m *LockManager) SetDefaultTTL(ttl time.Duration) {
	m.defaultTTL = ttl
}

// SetRefreshInterval sets how often locks are refreshed.
func (m *LockManager) SetRefreshInterval(interval time.Duration) {
	m.refreshInterval = interval
}

// AcquireUserMigrationLock acquires a lock for migrating a user's sealed material.
// Returns a Lock that must be released when done.
func (m *LockManager) AcquireUserMigrationLock(userID string, timeout time.Duration) (*Lock, error) {
	key := fmt.Sprintf("migration:user:%s", userID)
	return m.acquireLock(key, timeout)
}

// AcquireGlobalMigrationLock acquires a global lock for migration coordination.
// Only one enclave should run migration at a time.
func (m *LockManager) AcquireGlobalMigrationLock(timeout time.Duration) (*Lock, error) {
	return m.acquireLock("migration:global", timeout)
}

// acquireLock attempts to acquire a lock with retry until timeout.
func (m *LockManager) acquireLock(key string, timeout time.Duration) (*Lock, error) {
	deadline := time.Now().Add(timeout)
	retryInterval := 100 * time.Millisecond
	maxRetryInterval := 2 * time.Second

	for {
		acquired, err := m.store.TryAcquire(key, m.holderID, m.defaultTTL)
		if err != nil {
			return nil, fmt.Errorf("failed to try acquire lock: %w", err)
		}

		if acquired {
			lock := &Lock{
				key:         key,
				holder:      m.holderID,
				store:       m.store,
				ttl:         m.defaultTTL,
				stopRefresh: make(chan struct{}),
			}

			// Start background refresh
			go m.refreshLoop(lock)

			log.Info().
				Str("key", key).
				Str("holder", m.holderID).
				Dur("ttl", m.defaultTTL).
				Msg("Lock acquired")

			return lock, nil
		}

		// Check timeout
		if time.Now().After(deadline) {
			// Get info about who holds the lock
			info, _ := m.store.GetLockInfo(key)
			if info != nil {
				return nil, fmt.Errorf("lock acquisition timeout: held by %s since %s",
					info.Holder, info.AcquiredAt.Format(time.RFC3339))
			}
			return nil, fmt.Errorf("lock acquisition timeout for key %s", key)
		}

		// Exponential backoff with cap
		time.Sleep(retryInterval)
		retryInterval = retryInterval * 2
		if retryInterval > maxRetryInterval {
			retryInterval = maxRetryInterval
		}
	}
}

// refreshLoop periodically refreshes the lock TTL until released.
func (m *LockManager) refreshLoop(lock *Lock) {
	ticker := time.NewTicker(m.refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-lock.stopRefresh:
			return
		case <-ticker.C:
			lock.mu.Lock()
			if lock.released {
				lock.mu.Unlock()
				return
			}
			lock.mu.Unlock()

			if err := m.store.Refresh(lock.key, lock.holder, m.defaultTTL); err != nil {
				log.Warn().Err(err).
					Str("key", lock.key).
					Msg("Failed to refresh lock")
			} else {
				log.Debug().
					Str("key", lock.key).
					Msg("Lock refreshed")
			}
		}
	}
}

// InMemoryLockStore is a simple in-memory lock store for testing.
type InMemoryLockStore struct {
	locks map[string]*LockInfo
	mu    sync.Mutex
}

// NewInMemoryLockStore creates a new in-memory lock store.
func NewInMemoryLockStore() *InMemoryLockStore {
	return &InMemoryLockStore{
		locks: make(map[string]*LockInfo),
	}
}

func (s *InMemoryLockStore) TryAcquire(key string, holder string, ttl time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	// Check if lock exists and is not expired
	if existing, ok := s.locks[key]; ok {
		if !existing.IsExpired() && existing.Holder != holder {
			return false, nil
		}
	}

	// Acquire or re-acquire the lock
	s.locks[key] = &LockInfo{
		Key:        key,
		Holder:     holder,
		AcquiredAt: now,
		ExpiresAt:  now.Add(ttl),
	}

	return true, nil
}

func (s *InMemoryLockStore) Release(key string, holder string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.locks[key]; ok {
		if existing.Holder != holder {
			return fmt.Errorf("lock held by different holder: %s", existing.Holder)
		}
		delete(s.locks, key)
	}

	return nil
}

func (s *InMemoryLockStore) Refresh(key string, holder string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.locks[key]
	if !ok {
		return fmt.Errorf("lock not found: %s", key)
	}

	if existing.Holder != holder {
		return fmt.Errorf("lock held by different holder: %s", existing.Holder)
	}

	existing.ExpiresAt = time.Now().Add(ttl)
	return nil
}

func (s *InMemoryLockStore) GetLockInfo(key string) (*LockInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if info, ok := s.locks[key]; ok {
		// Return a copy
		return &LockInfo{
			Key:        info.Key,
			Holder:     info.Holder,
			AcquiredAt: info.AcquiredAt,
			ExpiresAt:  info.ExpiresAt,
		}, nil
	}

	return nil, nil
}
