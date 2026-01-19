package main

import (
	"github.com/mesmerverse/vettid-dev/enclave/vault-manager/storage"
)

// EncryptedStorage wraps the SQLite storage for the vault manager.
// It provides encrypted, persistent storage for vault data using
// an in-memory SQLite database that can be synced to S3.
type EncryptedStorage struct {
	sqlite     *storage.SQLiteStorage
	ownerSpace string
}

// NewEncryptedStorage creates a new encrypted storage for the vault
func NewEncryptedStorage(ownerSpace string) (*EncryptedStorage, error) {
	// DEK will be set when credential is unsealed
	// For now, create with a placeholder
	return &EncryptedStorage{
		ownerSpace: ownerSpace,
	}, nil
}

// InitializeWithDEK initializes storage with the data encryption key.
// This creates the SQLite database with the DEK for encryption.
func (s *EncryptedStorage) InitializeWithDEK(dek []byte) error {
	sqlite, err := storage.NewSQLiteStorage(s.ownerSpace, dek)
	if err != nil {
		return err
	}
	s.sqlite = sqlite
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
func (s *EncryptedStorage) GetEventsSince(lastSeq int64, limit int) ([]storage.EventRecord, error) {
	if s.sqlite == nil {
		return nil, ErrStorageNotInitialized
	}
	return s.sqlite.GetEventsSince(lastSeq, limit)
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
