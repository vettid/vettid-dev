package main

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/mesmerverse/vettid-dev/enclave/vault-manager/storage"
)

func TestCEKManager_Initialize(t *testing.T) {
	// Create storage with DEK
	dek := make([]byte, 32)
	rand.Read(dek)

	sqlite, err := storage.NewSQLiteStorage("test-owner", dek)
	if err != nil {
		t.Fatalf("Failed to create SQLite storage: %v", err)
	}
	defer sqlite.Close()

	encStorage := &EncryptedStorage{
		sqlite:     sqlite,
		ownerSpace: "test-owner",
	}

	cekManager := NewCEKManager("test-owner", encStorage)

	// Initialize should create first CEK
	if err := cekManager.Initialize(); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Verify CEK was created
	pubKey, version, err := cekManager.GetCurrentCEKPublicKey()
	if err != nil {
		t.Fatalf("GetCurrentCEKPublicKey failed: %v", err)
	}
	if len(pubKey) != 32 {
		t.Errorf("Expected 32-byte public key, got %d bytes", len(pubKey))
	}
	if version != 1 {
		t.Errorf("Expected version 1, got %d", version)
	}

	// Second initialize should be idempotent
	if err := cekManager.Initialize(); err != nil {
		t.Fatalf("Second Initialize failed: %v", err)
	}

	// Version should still be 1
	_, version2, _ := cekManager.GetCurrentCEKPublicKey()
	if version2 != 1 {
		t.Errorf("Expected version still 1 after idempotent init, got %d", version2)
	}
}

func TestCEKManager_EncryptDecrypt(t *testing.T) {
	dek := make([]byte, 32)
	rand.Read(dek)

	sqlite, err := storage.NewSQLiteStorage("test-owner", dek)
	if err != nil {
		t.Fatalf("Failed to create SQLite storage: %v", err)
	}
	defer sqlite.Close()

	encStorage := &EncryptedStorage{
		sqlite:     sqlite,
		ownerSpace: "test-owner",
	}

	cekManager := NewCEKManager("test-owner", encStorage)
	if err := cekManager.Initialize(); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Create test credential
	cred := &DecryptedCredential{
		UserID:          "user-123",
		PasswordHash:    []byte("hash-bytes"),
		PasswordSalt:    []byte("salt-bytes"),
		IdentityPrivate: []byte("private-key-data"),
		IdentityPublic:  []byte("public-key-data"),
		Session: &CredentialSession{
			Token:     []byte("session-token"),
			CreatedAt: time.Now().Unix(),
			ExpiresAt: time.Now().Add(7 * 24 * time.Hour).Unix(),
		},
		Metadata: map[string]string{
			"device": "test-device",
		},
		CreatedAt: time.Now().Unix(),
		Version:   1,
	}

	// Encrypt
	blob, err := cekManager.EncryptCredential(cred)
	if err != nil {
		t.Fatalf("EncryptCredential failed: %v", err)
	}

	if blob.Version != 1 {
		t.Errorf("Expected blob version 1, got %d", blob.Version)
	}
	if len(blob.Ciphertext) == 0 {
		t.Error("Ciphertext is empty")
	}
	if len(blob.Nonce) != 24 {
		t.Errorf("Expected 24-byte nonce, got %d bytes", len(blob.Nonce))
	}
	if len(blob.PublicKey) != 32 {
		t.Errorf("Expected 32-byte public key, got %d bytes", len(blob.PublicKey))
	}

	// Decrypt
	decrypted, err := cekManager.DecryptCredential(blob)
	if err != nil {
		t.Fatalf("DecryptCredential failed: %v", err)
	}

	// Verify fields
	if decrypted.UserID != cred.UserID {
		t.Errorf("UserID mismatch: got %s, want %s", decrypted.UserID, cred.UserID)
	}
	if string(decrypted.PasswordHash) != string(cred.PasswordHash) {
		t.Error("PasswordHash mismatch")
	}
	if decrypted.Session == nil {
		t.Fatal("Session is nil")
	}
	if string(decrypted.Session.Token) != string(cred.Session.Token) {
		t.Error("Session token mismatch")
	}
}

func TestCEKManager_RotationOnEveryOperation(t *testing.T) {
	dek := make([]byte, 32)
	rand.Read(dek)

	sqlite, err := storage.NewSQLiteStorage("test-owner", dek)
	if err != nil {
		t.Fatalf("Failed to create SQLite storage: %v", err)
	}
	defer sqlite.Close()

	encStorage := &EncryptedStorage{
		sqlite:     sqlite,
		ownerSpace: "test-owner",
	}

	cekManager := NewCEKManager("test-owner", encStorage)
	if err := cekManager.Initialize(); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	_, version1, _ := cekManager.GetCurrentCEKPublicKey()
	if version1 != 1 {
		t.Errorf("Expected initial version 1, got %d", version1)
	}

	cred := &DecryptedCredential{
		UserID:  "user-123",
		Version: 1,
	}

	// First encryption - should rotate CEK
	blob1, err := cekManager.EncryptCredential(cred)
	if err != nil {
		t.Fatalf("First EncryptCredential failed: %v", err)
	}

	_, version2, _ := cekManager.GetCurrentCEKPublicKey()
	if version2 != 2 {
		t.Errorf("Expected version 2 after first encrypt, got %d", version2)
	}

	// Decrypt should also rotate
	_, err = cekManager.DecryptCredential(blob1)
	if err != nil {
		t.Fatalf("DecryptCredential failed: %v", err)
	}

	_, version3, _ := cekManager.GetCurrentCEKPublicKey()
	if version3 != 3 {
		t.Errorf("Expected version 3 after decrypt, got %d", version3)
	}

	// Second encryption with another rotate
	blob2, err := cekManager.EncryptCredential(cred)
	if err != nil {
		t.Fatalf("Second EncryptCredential failed: %v", err)
	}

	_, version4, _ := cekManager.GetCurrentCEKPublicKey()
	if version4 != 4 {
		t.Errorf("Expected version 4 after second encrypt, got %d", version4)
	}

	// Can still decrypt old blob (CEK version 1 still in storage)
	_, err = cekManager.DecryptCredential(blob1)
	if err != nil {
		t.Fatalf("Decrypt old blob failed: %v", err)
	}

	// Can decrypt new blob too
	_, err = cekManager.DecryptCredential(blob2)
	if err != nil {
		t.Fatalf("Decrypt new blob failed: %v", err)
	}
}

func TestCEKManager_DecryptAndReencrypt(t *testing.T) {
	dek := make([]byte, 32)
	rand.Read(dek)

	sqlite, err := storage.NewSQLiteStorage("test-owner", dek)
	if err != nil {
		t.Fatalf("Failed to create SQLite storage: %v", err)
	}
	defer sqlite.Close()

	encStorage := &EncryptedStorage{
		sqlite:     sqlite,
		ownerSpace: "test-owner",
	}

	cekManager := NewCEKManager("test-owner", encStorage)
	if err := cekManager.Initialize(); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	cred := &DecryptedCredential{
		UserID:  "user-123",
		Version: 1,
		Metadata: map[string]string{
			"key": "original-value",
		},
	}

	// Encrypt original
	blob, err := cekManager.EncryptCredential(cred)
	if err != nil {
		t.Fatalf("EncryptCredential failed: %v", err)
	}
	originalVersion := blob.Version

	// Decrypt, modify, and re-encrypt
	newBlob, err := cekManager.DecryptAndReencrypt(blob, func(c *DecryptedCredential) error {
		c.Metadata["key"] = "modified-value"
		c.Version = 2
		return nil
	})
	if err != nil {
		t.Fatalf("DecryptAndReencrypt failed: %v", err)
	}

	// New blob should have higher version
	if newBlob.Version <= originalVersion {
		t.Errorf("New blob version %d should be > original %d", newBlob.Version, originalVersion)
	}

	// Decrypt and verify modification
	decrypted, err := cekManager.DecryptCredential(newBlob)
	if err != nil {
		t.Fatalf("Decrypt modified blob failed: %v", err)
	}

	if decrypted.Metadata["key"] != "modified-value" {
		t.Errorf("Expected modified-value, got %s", decrypted.Metadata["key"])
	}
	if decrypted.Version != 2 {
		t.Errorf("Expected version 2, got %d", decrypted.Version)
	}
}

func TestCEKManager_BlobEncoding(t *testing.T) {
	blob := &CEKEncryptedBlob{
		Version:    42,
		Ciphertext: []byte("test-ciphertext"),
		Nonce:      make([]byte, 24),
		PublicKey:  make([]byte, 32),
	}
	rand.Read(blob.Nonce)
	rand.Read(blob.PublicKey)

	// Encode to string
	encoded, err := EncodeBlobToString(blob)
	if err != nil {
		t.Fatalf("EncodeBlobToString failed: %v", err)
	}

	// Decode back
	decoded, err := DecodeBlobFromString(encoded)
	if err != nil {
		t.Fatalf("DecodeBlobFromString failed: %v", err)
	}

	if decoded.Version != blob.Version {
		t.Errorf("Version mismatch: got %d, want %d", decoded.Version, blob.Version)
	}
	if string(decoded.Ciphertext) != string(blob.Ciphertext) {
		t.Error("Ciphertext mismatch")
	}
}

func TestCEKManager_InvalidBlob(t *testing.T) {
	dek := make([]byte, 32)
	rand.Read(dek)

	sqlite, err := storage.NewSQLiteStorage("test-owner", dek)
	if err != nil {
		t.Fatalf("Failed to create SQLite storage: %v", err)
	}
	defer sqlite.Close()

	encStorage := &EncryptedStorage{
		sqlite:     sqlite,
		ownerSpace: "test-owner",
	}

	cekManager := NewCEKManager("test-owner", encStorage)
	if err := cekManager.Initialize(); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Try to decrypt blob with non-existent version
	invalidBlob := &CEKEncryptedBlob{
		Version:    999,
		Ciphertext: []byte("garbage"),
		Nonce:      make([]byte, 24),
		PublicKey:  make([]byte, 32),
	}

	_, err = cekManager.DecryptCredential(invalidBlob)
	if err == nil {
		t.Error("Expected error for invalid blob version")
	}
}
