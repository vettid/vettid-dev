package main

import (
	"github.com/mesmerverse/vettid-dev/enclave/vault-manager/storage"
)

// EncryptedStorage wraps the storage adapter for the vault manager
type EncryptedStorage struct {
	adapter    *storage.EncryptedStorageAdapter
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

// InitializeWithDEK initializes storage with the data encryption key
func (s *EncryptedStorage) InitializeWithDEK(dek []byte) error {
	adapter, err := storage.NewEncryptedStorageAdapter(s.ownerSpace, dek)
	if err != nil {
		return err
	}
	s.adapter = adapter
	return nil
}

// Get retrieves and decrypts data
func (s *EncryptedStorage) Get(key string) ([]byte, error) {
	if s.adapter == nil {
		return nil, ErrStorageNotInitialized
	}
	return s.adapter.Get(key)
}

// Put encrypts and stores data
func (s *EncryptedStorage) Put(key string, value []byte) error {
	if s.adapter == nil {
		return ErrStorageNotInitialized
	}
	return s.adapter.Put(key, value)
}

// Delete removes data
func (s *EncryptedStorage) Delete(key string) error {
	if s.adapter == nil {
		return ErrStorageNotInitialized
	}
	return s.adapter.Delete(key)
}

// Errors
var ErrStorageNotInitialized = &StorageError{Message: "storage not initialized - unseal credential first"}

// StorageError represents a storage error
type StorageError struct {
	Message string
}

func (e *StorageError) Error() string {
	return e.Message
}
