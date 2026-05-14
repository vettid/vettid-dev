package main

import (
	"encoding/json"

	"github.com/vettid/vettid-dev/enclave/vault-manager/storage"
	"github.com/rs/zerolog/log"
)

// EncryptedStorage wraps the SQLite storage for the vault manager.
// It provides encrypted, persistent storage for vault data using
// an in-memory SQLite database that can be synced to S3.
type EncryptedStorage struct {
	sqlite     *storage.SQLiteStorage
	ownerSpace string

	// entrySigner is the audit-chain signing closure. It is OWNED here
	// (not just on the SQLiteStorage) because the SQLiteStorage is
	// created lazily — InitializeWithDEK / ResetWithDEK build it at
	// pin-setup / cold-unlock time, long AFTER MessageHandler wires up
	// the signer. Holding it on EncryptedStorage lets every freshly
	// created SQLiteStorage inherit it. Without this, a fresh-spawned
	// subprocess registered the signer against a nil SQLite (skipped),
	// the real SQLite came up signer-less, and every audit row was
	// written unsigned → client shows a spurious "chain unsigned" pill
	// (2026-05-14).
	entrySigner func(entryHashBytes []byte) []byte
}

// NewEncryptedStorage creates a new encrypted storage for the vault
func NewEncryptedStorage(ownerSpace string) (*EncryptedStorage, error) {
	// DEK will be set when credential is unsealed
	// For now, create with a placeholder
	return &EncryptedStorage{
		ownerSpace: ownerSpace,
	}, nil
}

// SetEntrySigner registers the audit-chain signing closure. Stored on
// EncryptedStorage AND applied to the current SQLiteStorage if one
// exists; InitializeWithDEK / ResetWithDEK re-apply it to every
// SQLiteStorage they create, so the signer survives lazy storage
// creation and cold-unlock storage resets. Safe to call before the
// SQLite exists — it'll be applied when it's created.
func (s *EncryptedStorage) SetEntrySigner(fn func(entryHashBytes []byte) []byte) {
	s.entrySigner = fn
	if s.sqlite != nil {
		s.sqlite.SetEntrySigner(fn)
	}
}

// InitializeWithDEK initializes storage with the data encryption key.
// This creates the SQLite database with the DEK for encryption.
// If storage is already initialized, it is preserved (idempotent) —
// but ONLY when the DEK matches. A mismatch means the existing
// storage was keyed with a stale DEK (see ResetWithDEK + the
// 2026-05-14 migration corruption); preserving it would silently
// keep encrypting row payloads + HMACing the backup with the wrong
// key. The warm-unlock path is the only legitimate caller that hits
// the already-initialized branch, and there the DEK always matches —
// so a mismatch here is a bug worth shouting about. Callers that
// MUST get fresh storage keyed to a freshly-derived DEK (the
// cold-unlock path) should use ResetWithDEK instead.
func (s *EncryptedStorage) InitializeWithDEK(dek []byte) error {
	if s.sqlite != nil {
		if !s.sqlite.DEKEquals(dek) {
			log.Error().Str("owner_space", s.ownerSpace).
				Msg("SECURITY: InitializeWithDEK called with a DEK that does NOT match existing storage — keeping existing (stale) storage; cold-unlock paths must use ResetWithDEK")
		} else {
			log.Debug().Str("owner_space", s.ownerSpace).Msg("Storage already initialized with matching DEK, preserving existing data")
		}
		return nil
	}

	sqlite, err := storage.NewSQLiteStorage(s.ownerSpace, dek)
	if err != nil {
		return err
	}
	s.sqlite = sqlite
	// Re-apply the audit-chain signer to the freshly-created SQLite —
	// it was registered on EncryptedStorage before this storage
	// existed (see SetEntrySigner).
	if s.entrySigner != nil {
		s.sqlite.SetEntrySigner(s.entrySigner)
	}
	log.Info().Str("owner_space", s.ownerSpace).Msg("Storage initialized with DEK")
	return nil
}

// ResetWithDEK forces fresh SQLite storage keyed to dek, discarding
// any existing in-memory database. Used by the cold-unlock path:
// a "cold" vault (ECIES not in memory) may still carry an s.sqlite
// from an earlier lifecycle of the SAME subprocess, keyed with a
// now-stale DEK. The idempotent InitializeWithDEK would keep that
// stale storage, so the cold-load's RestoreBackup would verify the
// backup HMAC against the wrong key and every restored row payload
// would be undecryptable — the 2026-05-14 migration corruption
// ("backup HMAC verification failed", empty vault). Discarding the
// stale DB is correct: the cold path's whole job is to rebuild from
// the S3 backup, and stale-keyed rows are unrecoverable anyway.
func (s *EncryptedStorage) ResetWithDEK(dek []byte) error {
	if s.sqlite != nil {
		if s.sqlite.DEKEquals(dek) {
			// Already fresh-and-correct (e.g. a retried cold unlock
			// within the same subprocess). Nothing to discard.
			return nil
		}
		log.Warn().Str("owner_space", s.ownerSpace).
			Msg("ResetWithDEK: discarding stale-keyed storage and re-creating with the freshly-derived DEK (cold unlock)")
		_ = s.sqlite.Close()
		s.sqlite = nil
	}
	sqlite, err := storage.NewSQLiteStorage(s.ownerSpace, dek)
	if err != nil {
		return err
	}
	s.sqlite = sqlite
	// Re-apply the audit-chain signer to the freshly-created SQLite.
	if s.entrySigner != nil {
		s.sqlite.SetEntrySigner(s.entrySigner)
	}
	log.Info().Str("owner_space", s.ownerSpace).Msg("Storage (re)initialized fresh with DEK for cold unlock")
	return nil
}

// Get retrieves and decrypts data by key
func (s *EncryptedStorage) Get(key string) ([]byte, error) {
	if s.sqlite == nil {
		return nil, ErrStorageNotInitialized
	}
	data, err := s.sqlite.Get(key)
	if err == storage.ErrKeyNotFound {
		return nil, ErrKeyNotFound
	}
	return data, err
}

// Put encrypts and stores data by key
func (s *EncryptedStorage) Put(key string, value []byte) error {
	if s.sqlite == nil {
		return ErrStorageNotInitialized
	}
	return s.sqlite.Put(key, value)
}

// Delete removes data by key
func (s *EncryptedStorage) Delete(key string) error {
	if s.sqlite == nil {
		return ErrStorageNotInitialized
	}
	return s.sqlite.Delete(key)
}

// SQLite returns the underlying SQLite storage for domain-specific operations.
// Use this for CEK keypair, transport key, and ledger entry operations.
func (s *EncryptedStorage) SQLite() *storage.SQLiteStorage {
	return s.sqlite
}

// CreateBackup creates an encrypted backup of the database
func (s *EncryptedStorage) CreateBackup() (*storage.BackupData, error) {
	if s.sqlite == nil {
		return nil, ErrStorageNotInitialized
	}
	return s.sqlite.CreateBackup()
}

// RestoreBackup restores the database from a backup
func (s *EncryptedStorage) RestoreBackup(backup *storage.BackupData) error {
	if s.sqlite == nil {
		return ErrStorageNotInitialized
	}
	return s.sqlite.RestoreBackup(backup)
}

// Close closes the storage
func (s *EncryptedStorage) Close() error {
	if s.sqlite != nil {
		return s.sqlite.Close()
	}
	return nil
}

// ===============================
// Replay Attack Prevention
// ===============================

// IsEventProcessed checks if an event has already been processed (replay detection)
func (s *EncryptedStorage) IsEventProcessed(eventID string) (bool, error) {
	if s.sqlite == nil {
		return false, ErrStorageNotInitialized
	}
	return s.sqlite.IsEventProcessed(eventID)
}

// MarkEventProcessed marks an event as processed to prevent replay
func (s *EncryptedStorage) MarkEventProcessed(eventID, eventType string) error {
	if s.sqlite == nil {
		return ErrStorageNotInitialized
	}
	return s.sqlite.MarkEventProcessed(eventID, eventType)
}

// CleanupExpiredEvents removes processed events older than TTL
func (s *EncryptedStorage) CleanupExpiredEvents() (int64, error) {
	if s.sqlite == nil {
		return 0, ErrStorageNotInitialized
	}
	return s.sqlite.CleanupExpiredEvents()
}

// ===============================
// Unified Event System
// ===============================

// StoreEvent stores a new event in the events table
func (s *EncryptedStorage) StoreEvent(event *storage.EventRecord) error {
	if s.sqlite == nil {
		return ErrStorageNotInitialized
	}
	return s.sqlite.StoreEvent(event)
}

// GetEventByID retrieves a single event by ID
func (s *EncryptedStorage) GetEventByID(eventID string) (*storage.EventRecord, error) {
	if s.sqlite == nil {
		return nil, ErrStorageNotInitialized
	}
	return s.sqlite.GetEvent(eventID)
}

// ListFeedEvents returns events for the user feed
func (s *EncryptedStorage) ListFeedEvents(statuses []string, limit, offset int) ([]storage.EventRecord, int, error) {
	if s.sqlite == nil {
		return nil, 0, ErrStorageNotInitialized
	}
	return s.sqlite.ListFeedEvents(statuses, limit, offset)
}

// QueryAuditEvents returns events for audit purposes
func (s *EncryptedStorage) QueryAuditEvents(eventTypes []string, startTime, endTime int64, sourceID string, limit, offset int) ([]storage.EventRecord, int, error) {
	if s.sqlite == nil {
		return nil, 0, ErrStorageNotInitialized
	}
	return s.sqlite.QueryAuditEvents(eventTypes, startTime, endTime, sourceID, limit, offset)
}

// GetEventsSince returns events with sync_sequence > lastSeq for sync
func (s *EncryptedStorage) GetEventsSince(lastSeq int64, limit int, includeHidden bool) ([]storage.EventRecord, error) {
	if s.sqlite == nil {
		return nil, ErrStorageNotInitialized
	}
	return s.sqlite.GetEventsSince(lastSeq, limit, includeHidden)
}

// UpdateEventStatus updates the feed_status and related timestamps
func (s *EncryptedStorage) UpdateEventStatus(eventID string, newStatus string, timestamp int64) error {
	if s.sqlite == nil {
		return ErrStorageNotInitialized
	}
	return s.sqlite.UpdateEventStatus(eventID, newStatus, timestamp)
}

// UpdateEventActioned marks an event as actioned
func (s *EncryptedStorage) UpdateEventActioned(eventID string, timestamp int64) error {
	if s.sqlite == nil {
		return ErrStorageNotInitialized
	}
	return s.sqlite.UpdateEventActioned(eventID, timestamp)
}

// GetSyncSequence returns the current sync sequence number
func (s *EncryptedStorage) GetSyncSequence() (int64, error) {
	if s.sqlite == nil {
		return 0, ErrStorageNotInitialized
	}
	return s.sqlite.GetSyncSequence()
}

// IncrementSyncSequence increments and returns the new sync sequence
func (s *EncryptedStorage) IncrementSyncSequence() (int64, error) {
	if s.sqlite == nil {
		return 0, ErrStorageNotInitialized
	}
	return s.sqlite.IncrementSyncSequence()
}

// CleanupEvents removes old events based on retention policies
func (s *EncryptedStorage) CleanupEvents(feedRetentionDays, auditRetentionDays int, autoArchive bool) (int64, error) {
	if s.sqlite == nil {
		return 0, ErrStorageNotInitialized
	}
	return s.sqlite.CleanupEvents(feedRetentionDays, auditRetentionDays, autoArchive)
}

// ===============================
// Index Helpers (for lists)
// ===============================

// GetIndex returns the IDs stored in an index key as a string slice
func (s *EncryptedStorage) GetIndex(indexKey string) ([]string, error) {
	data, err := s.Get(indexKey)
	if err == ErrKeyNotFound {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	if data == nil || len(data) == 0 {
		return []string{}, nil
	}
	var ids []string
	if err := json.Unmarshal(data, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// AddToIndex adds an ID to an index if not already present
func (s *EncryptedStorage) AddToIndex(indexKey, id string) error {
	ids, err := s.GetIndex(indexKey)
	if err != nil {
		return err
	}
	// Check if already exists
	for _, existing := range ids {
		if existing == id {
			return nil
		}
	}
	ids = append(ids, id)
	data, err := json.Marshal(ids)
	if err != nil {
		return err
	}
	return s.Put(indexKey, data)
}

// RemoveFromIndex removes an ID from an index
func (s *EncryptedStorage) RemoveFromIndex(indexKey, id string) error {
	ids, err := s.GetIndex(indexKey)
	if err != nil {
		return err
	}
	var newIDs []string
	for _, existing := range ids {
		if existing != id {
			newIDs = append(newIDs, existing)
		}
	}
	data, err := json.Marshal(newIDs)
	if err != nil {
		return err
	}
	return s.Put(indexKey, data)
}

// PutJSON marshals and stores a value as JSON
func (s *EncryptedStorage) PutJSON(key string, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.Put(key, data)
}

// GetJSON retrieves and unmarshals a JSON value
func (s *EncryptedStorage) GetJSON(key string, v interface{}) error {
	data, err := s.Get(key)
	if err != nil {
		return err
	}
	if data == nil {
		return ErrKeyNotFound
	}
	return json.Unmarshal(data, v)
}

// Errors
var (
	ErrStorageNotInitialized = &StorageError{Message: "storage not initialized - unseal credential first"}
	ErrKeyNotFound           = &StorageError{Message: "key not found"}
)

// StorageError represents a storage error
type StorageError struct {
	Message string
}

func (e *StorageError) Error() string {
	return e.Message
}
