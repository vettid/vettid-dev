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
