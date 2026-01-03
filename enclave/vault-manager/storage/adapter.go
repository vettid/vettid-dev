package storage

import (
	"crypto/rand"
	"fmt"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

// EncryptedStorageAdapter encrypts all data before sending to external storage
// The DEK (Data Encryption Key) is derived from the user's vault master secret
type EncryptedStorageAdapter struct {
	ownerSpace string
	dek        []byte // Data Encryption Key - 32 bytes
	cache      *LRUCache
	mu         sync.RWMutex
}

// StorageRequest is a request to read/write encrypted data
type StorageRequest struct {
	Operation string `json:"operation"` // "get", "put", "delete", "list"
	Key       string `json:"key"`
	Value     []byte `json:"value,omitempty"`
}

// StorageResponse is the response from a storage operation
type StorageResponse struct {
	Success bool   `json:"success"`
	Key     string `json:"key,omitempty"`
	Value   []byte `json:"value,omitempty"`
	Error   string `json:"error,omitempty"`
}

// NewEncryptedStorageAdapter creates a new encrypted storage adapter
func NewEncryptedStorageAdapter(ownerSpace string, dek []byte) (*EncryptedStorageAdapter, error) {
	if len(dek) != 32 {
		return nil, fmt.Errorf("DEK must be 32 bytes")
	}

	return &EncryptedStorageAdapter{
		ownerSpace: ownerSpace,
		dek:        dek,
		cache:      NewLRUCache(100), // Cache up to 100 items
	}, nil
}

// Get retrieves and decrypts data
func (s *EncryptedStorageAdapter) Get(key string) ([]byte, error) {
	// Check cache first
	if cached, ok := s.cache.Get(key); ok {
		return cached, nil
	}

	// Request from external storage via vsock
	// This will be implemented to communicate with the parent process
	encryptedData, err := s.requestFromParent("get", key, nil)
	if err != nil {
		return nil, err
	}

	// Decrypt
	plaintext, err := s.decrypt(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	// Cache the result
	s.cache.Put(key, plaintext)

	return plaintext, nil
}

// Put encrypts and stores data
func (s *EncryptedStorageAdapter) Put(key string, value []byte) error {
	// Encrypt
	ciphertext, err := s.encrypt(value)
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	// Send to external storage via vsock
	_, err = s.requestFromParent("put", key, ciphertext)
	if err != nil {
		return err
	}

	// Update cache
	s.cache.Put(key, value)

	return nil
}

// Delete removes data
func (s *EncryptedStorageAdapter) Delete(key string) error {
	// Remove from external storage via vsock
	_, err := s.requestFromParent("delete", key, nil)
	if err != nil {
		return err
	}

	// Remove from cache
	s.cache.Delete(key)

	return nil
}

// encrypt encrypts data using ChaCha20-Poly1305
func (s *EncryptedStorageAdapter) encrypt(plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(s.dek)
	if err != nil {
		return nil, err
	}

	// Generate random nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// Encrypt and prepend nonce
	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// decrypt decrypts data using ChaCha20-Poly1305
func (s *EncryptedStorageAdapter) decrypt(ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(s.dek)
	if err != nil {
		return nil, err
	}

	nonceSize := aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertext[:nonceSize]
	ciphertext = ciphertext[nonceSize:]

	return aead.Open(nil, nonce, ciphertext, nil)
}

// requestFromParent sends a storage request to the parent process via vsock
func (s *EncryptedStorageAdapter) requestFromParent(operation, key string, value []byte) ([]byte, error) {
	// TODO: Implement vsock communication with parent
	// This will send requests like:
	// { "operation": "get", "key": "vaults/{owner_space}/credential.sealed" }
	// And receive responses with encrypted data
	return nil, fmt.Errorf("parent communication not implemented")
}

// SetDEK updates the data encryption key
func (s *EncryptedStorageAdapter) SetDEK(dek []byte) error {
	if len(dek) != 32 {
		return fmt.Errorf("DEK must be 32 bytes")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dek = dek
	s.cache.Clear() // Clear cache as data is encrypted with different key
	return nil
}
