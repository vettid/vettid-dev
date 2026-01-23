package main

import (
	"encoding/json"
	"fmt"
	"sync"
)

// EncryptedStorage provides encrypted key-value storage for service vaults.
// In production, this uses the same S3-backed encrypted SQLite as user vaults.
// For now, this is an in-memory implementation for development.
type EncryptedStorage struct {
	ownerSpace string
	data       map[string][]byte
	mu         sync.RWMutex
}

// NewEncryptedStorage creates a new encrypted storage adapter
func NewEncryptedStorage(ownerSpace string) (*EncryptedStorage, error) {
	return &EncryptedStorage{
		ownerSpace: ownerSpace,
		data:       make(map[string][]byte),
	}, nil
}

// Get retrieves a value by key
func (s *EncryptedStorage) Get(key string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, exists := s.data[key]
	if !exists {
		return nil, nil // Key not found
	}

	// Return a copy to prevent mutation
	result := make([]byte, len(data))
	copy(result, data)
	return result, nil
}

// Put stores a value by key
func (s *EncryptedStorage) Put(key string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Store a copy
	data := make([]byte, len(value))
	copy(data, value)
	s.data[key] = data
	return nil
}

// Delete removes a key
func (s *EncryptedStorage) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.data, key)
	return nil
}

// List returns all keys with a given prefix
func (s *EncryptedStorage) List(prefix string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var keys []string
	for key := range s.data {
		if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

// GetJSON retrieves and unmarshals a JSON value
func (s *EncryptedStorage) GetJSON(key string, v interface{}) error {
	data, err := s.Get(key)
	if err != nil {
		return err
	}
	if data == nil {
		return fmt.Errorf("key not found: %s", key)
	}
	return json.Unmarshal(data, v)
}

// PutJSON marshals and stores a JSON value
func (s *EncryptedStorage) PutJSON(key string, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("failed to marshal: %w", err)
	}
	return s.Put(key, data)
}

// --- Index Helpers ---

// AddToIndex adds an ID to a string index
func (s *EncryptedStorage) AddToIndex(indexKey, id string) error {
	var index []string
	data, err := s.Get(indexKey)
	if err != nil {
		return err
	}
	if data != nil {
		if err := json.Unmarshal(data, &index); err != nil {
			return err
		}
	}

	// Check if already exists
	for _, existing := range index {
		if existing == id {
			return nil // Already in index
		}
	}

	index = append(index, id)
	return s.PutJSON(indexKey, index)
}

// RemoveFromIndex removes an ID from a string index
func (s *EncryptedStorage) RemoveFromIndex(indexKey, id string) error {
	var index []string
	data, err := s.Get(indexKey)
	if err != nil {
		return err
	}
	if data == nil {
		return nil // Index doesn't exist
	}
	if err := json.Unmarshal(data, &index); err != nil {
		return err
	}

	// Remove the ID
	var newIndex []string
	for _, existing := range index {
		if existing != id {
			newIndex = append(newIndex, existing)
		}
	}

	return s.PutJSON(indexKey, newIndex)
}

// GetIndex returns all IDs in an index
func (s *EncryptedStorage) GetIndex(indexKey string) ([]string, error) {
	var index []string
	data, err := s.Get(indexKey)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return []string{}, nil
	}
	if err := json.Unmarshal(data, &index); err != nil {
		return nil, err
	}
	return index, nil
}
