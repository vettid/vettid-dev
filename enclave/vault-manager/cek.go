package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// CEKManager handles Credential Encryption Key management per Architecture v2.0 Section 5.5.
// The CEK is an X25519 keypair held entirely by the vault-manager.
// The app NEVER has the CEK - it only receives CEK-encrypted credential blobs.
// The CEK rotates after every credential operation.
type CEKManager struct {
	storage    *EncryptedStorage
	ownerSpace string
	mu         sync.Mutex
}

// CEKEncryptedBlob represents a credential encrypted with the CEK
type CEKEncryptedBlob struct {
	Version    int64  `json:"version"`     // CEK version used for encryption
	Ciphertext []byte `json:"ciphertext"`  // ChaCha20-Poly1305 encrypted credential
	Nonce      []byte `json:"nonce"`       // 24-byte nonce for XChaCha20
	PublicKey  []byte `json:"public_key"`  // Ephemeral public key for ECDH
}

// DecryptedCredential represents the plaintext credential structure
type DecryptedCredential struct {
	UserID          string            `json:"user_id"`
	PasswordHash    []byte            `json:"password_hash"`
	PasswordSalt    []byte            `json:"password_salt"`
	IdentityPrivate []byte            `json:"identity_private"`
	IdentityPublic  []byte            `json:"identity_public"`
	Session         *CredentialSession `json:"session,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
	CreatedAt       int64             `json:"created_at"`
	Version         int               `json:"version"`
}

// CredentialSession represents the embedded session token per Architecture v2.0 Section 5.17
type CredentialSession struct {
	Token     []byte `json:"token"`
	CreatedAt int64  `json:"created_at"`
	ExpiresAt int64  `json:"expires_at"`
}

// NewCEKManager creates a new CEK manager
func NewCEKManager(ownerSpace string, storage *EncryptedStorage) *CEKManager {
	return &CEKManager{
		storage:    storage,
		ownerSpace: ownerSpace,
	}
}

// Initialize generates the initial CEK keypair if none exists
func (m *CEKManager) Initialize() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	sqlite := m.storage.SQLite()
	if sqlite == nil {
		return ErrStorageNotInitialized
	}

	// Check if we already have a current CEK
	currentCEK, err := sqlite.GetCurrentCEK()
	if err != nil {
		return fmt.Errorf("failed to check current CEK: %w", err)
	}

	if currentCEK != nil {
		// Already initialized
		return nil
	}

	// Generate initial CEK keypair
	privateKey, publicKey, err := generateX25519Keypair()
	if err != nil {
		return fmt.Errorf("failed to generate initial CEK: %w", err)
	}

	_, err = sqlite.StoreCEKKeypair(privateKey, publicKey, true)
	if err != nil {
		return fmt.Errorf("failed to store initial CEK: %w", err)
	}

	return nil
}

// EncryptCredential encrypts a credential with the current CEK and returns the blob.
// After encryption, it automatically rotates to a new CEK.
// Per Architecture v2.0 Section 5.5: CEK rotates after every credential access.
func (m *CEKManager) EncryptCredential(cred *DecryptedCredential) (*CEKEncryptedBlob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	sqlite := m.storage.SQLite()
	if sqlite == nil {
		return nil, ErrStorageNotInitialized
	}

	// Get current CEK
	currentCEK, err := sqlite.GetCurrentCEK()
	if err != nil {
		return nil, fmt.Errorf("failed to get current CEK: %w", err)
	}
	if currentCEK == nil {
		return nil, fmt.Errorf("no current CEK - call Initialize first")
	}

	// Serialize credential
	plaintext, err := json.Marshal(cred)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credential: %w", err)
	}

	// Generate ephemeral keypair for ECDH
	ephemeralPrivate, ephemeralPublic, err := generateX25519Keypair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral keypair: %w", err)
	}

	// Derive shared secret using ECDH: ephemeral_private * CEK_public
	sharedSecret, err := curve25519.X25519(ephemeralPrivate, currentCEK.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive shared secret: %w", err)
	}

	// Encrypt with XChaCha20-Poly1305 using shared secret as key
	aead, err := chacha20poly1305.NewX(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	blob := &CEKEncryptedBlob{
		Version:    currentCEK.Version,
		Ciphertext: ciphertext,
		Nonce:      nonce,
		PublicKey:  ephemeralPublic,
	}

	// ROTATE CEK: Generate new keypair for next operation
	if err := m.rotateUnlocked(sqlite); err != nil {
		// Log but don't fail - the encryption succeeded
		// Rotation will happen on next operation
		fmt.Printf("warning: CEK rotation failed: %v\n", err)
	}

	return blob, nil
}

// DecryptCredential decrypts a CEK-encrypted blob and returns the credential.
// After decryption, it automatically rotates to a new CEK.
// Per Architecture v2.0 Section 5.5: CEK rotates after every credential access.
func (m *CEKManager) DecryptCredential(blob *CEKEncryptedBlob) (*DecryptedCredential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	sqlite := m.storage.SQLite()
	if sqlite == nil {
		return nil, ErrStorageNotInitialized
	}

	// Get CEK by version (may not be current if blob is older)
	cek, err := sqlite.GetCEKByVersion(blob.Version)
	if err != nil {
		return nil, fmt.Errorf("failed to get CEK version %d: %w", blob.Version, err)
	}
	if cek == nil {
		return nil, fmt.Errorf("CEK version %d not found", blob.Version)
	}

	// Derive shared secret using ECDH: CEK_private * ephemeral_public
	sharedSecret, err := curve25519.X25519(cek.PrivateKey, blob.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive shared secret: %w", err)
	}

	// Decrypt with XChaCha20-Poly1305
	aead, err := chacha20poly1305.NewX(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD: %w", err)
	}

	plaintext, err := aead.Open(nil, blob.Nonce, blob.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	// Deserialize credential
	var cred DecryptedCredential
	if err := json.Unmarshal(plaintext, &cred); err != nil {
		return nil, fmt.Errorf("failed to unmarshal credential: %w", err)
	}

	// ROTATE CEK: Generate new keypair for next operation
	if err := m.rotateUnlocked(sqlite); err != nil {
		// Log but don't fail - the decryption succeeded
		fmt.Printf("warning: CEK rotation failed: %v\n", err)
	}

	return &cred, nil
}

// DecryptAndReencrypt decrypts a blob, allows modification, then re-encrypts with new CEK.
// This is the primary operation pattern per Architecture v2.0:
// 1. Decrypt credential with current CEK
// 2. Perform operation (caller modifies credential)
// 3. Re-encrypt with NEW CEK
// 4. Return new blob for app to store
func (m *CEKManager) DecryptAndReencrypt(blob *CEKEncryptedBlob, modify func(*DecryptedCredential) error) (*CEKEncryptedBlob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	sqlite := m.storage.SQLite()
	if sqlite == nil {
		return nil, ErrStorageNotInitialized
	}

	// Get CEK by version for decryption
	cek, err := sqlite.GetCEKByVersion(blob.Version)
	if err != nil {
		return nil, fmt.Errorf("failed to get CEK version %d: %w", blob.Version, err)
	}
	if cek == nil {
		return nil, fmt.Errorf("CEK version %d not found", blob.Version)
	}

	// Derive shared secret for decryption
	sharedSecret, err := curve25519.X25519(cek.PrivateKey, blob.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive shared secret: %w", err)
	}

	// Decrypt
	aead, err := chacha20poly1305.NewX(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD: %w", err)
	}

	plaintext, err := aead.Open(nil, blob.Nonce, blob.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	var cred DecryptedCredential
	if err := json.Unmarshal(plaintext, &cred); err != nil {
		return nil, fmt.Errorf("failed to unmarshal credential: %w", err)
	}

	// Allow caller to modify the credential
	if modify != nil {
		if err := modify(&cred); err != nil {
			return nil, fmt.Errorf("modification failed: %w", err)
		}
	}

	// ROTATE CEK before re-encryption
	if err := m.rotateUnlocked(sqlite); err != nil {
		return nil, fmt.Errorf("CEK rotation failed: %w", err)
	}

	// Get the NEW current CEK for re-encryption
	newCEK, err := sqlite.GetCurrentCEK()
	if err != nil {
		return nil, fmt.Errorf("failed to get new CEK: %w", err)
	}

	// Generate new ephemeral keypair
	ephemeralPrivate, ephemeralPublic, err := generateX25519Keypair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral keypair: %w", err)
	}

	// Derive new shared secret
	newSharedSecret, err := curve25519.X25519(ephemeralPrivate, newCEK.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive new shared secret: %w", err)
	}

	// Re-serialize and re-encrypt
	newPlaintext, err := json.Marshal(cred)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credential: %w", err)
	}

	newAead, err := chacha20poly1305.NewX(newSharedSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to create new AEAD: %w", err)
	}

	newNonce := make([]byte, newAead.NonceSize())
	if _, err := rand.Read(newNonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	newCiphertext := newAead.Seal(nil, newNonce, newPlaintext, nil)

	return &CEKEncryptedBlob{
		Version:    newCEK.Version,
		Ciphertext: newCiphertext,
		Nonce:      newNonce,
		PublicKey:  ephemeralPublic,
	}, nil
}

// GetCurrentCEKPublicKey returns the current CEK public key.
// This can be shared with the app for initial encryption during enrollment.
func (m *CEKManager) GetCurrentCEKPublicKey() ([]byte, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	sqlite := m.storage.SQLite()
	if sqlite == nil {
		return nil, 0, ErrStorageNotInitialized
	}

	cek, err := sqlite.GetCurrentCEK()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get current CEK: %w", err)
	}
	if cek == nil {
		return nil, 0, fmt.Errorf("no current CEK")
	}

	return cek.PublicKey, cek.Version, nil
}

// rotateUnlocked generates a new CEK keypair and makes it current.
// Caller must hold the lock.
func (m *CEKManager) rotateUnlocked(sqlite interface {
	StoreCEKKeypair(privateKey, publicKey []byte, isCurrent bool) (int64, error)
}) error {
	privateKey, publicKey, err := generateX25519Keypair()
	if err != nil {
		return fmt.Errorf("failed to generate new CEK: %w", err)
	}

	_, err = sqlite.StoreCEKKeypair(privateKey, publicKey, true)
	if err != nil {
		return fmt.Errorf("failed to store new CEK: %w", err)
	}

	return nil
}

// generateX25519Keypair generates an X25519 keypair for ECDH
func generateX25519Keypair() (privateKey, publicKey []byte, err error) {
	privateKey = make([]byte, 32)
	if _, err := rand.Read(privateKey); err != nil {
		return nil, nil, err
	}

	publicKey, err = curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}

	return privateKey, publicKey, nil
}

// EncodeBlobToString encodes a CEK encrypted blob to a base64 string for transport
func EncodeBlobToString(blob *CEKEncryptedBlob) (string, error) {
	data, err := json.Marshal(blob)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

// DecodeBlobFromString decodes a base64 string to a CEK encrypted blob
func DecodeBlobFromString(s string) (*CEKEncryptedBlob, error) {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	var blob CEKEncryptedBlob
	if err := json.Unmarshal(data, &blob); err != nil {
		return nil, err
	}
	return &blob, nil
}
