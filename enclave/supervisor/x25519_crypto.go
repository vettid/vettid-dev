package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// X25519 + AES-256-GCM encrypted format (matches vault-manager's decryptWithECIES):
// Bytes 0-31:   Ephemeral public key (X25519)
// Bytes 32-43:  Nonce (12 bytes for AES-GCM)
// Bytes 44+:    AES-256-GCM ciphertext (with 16-byte auth tag)
const (
	x25519PublicKeySize = 32
	aesGCMNonceSize     = 12
	aesGCMTagSize       = 16
	minEncryptedSize    = x25519PublicKeySize + aesGCMNonceSize + aesGCMTagSize
)

var (
	ErrInvalidCiphertext = errors.New("invalid ciphertext format")
	ErrDecryptionFailed  = errors.New("decryption failed")
)

// X25519Decrypt decrypts data encrypted with X25519 + AES-256-GCM
// This matches the format used by vault-manager's decryptWithECIES
// Format: [32-byte ephemeral pubkey][12-byte nonce][ciphertext+tag]
func X25519Decrypt(recipientPrivate []byte, encrypted []byte) ([]byte, error) {
	if len(recipientPrivate) != 32 {
		return nil, fmt.Errorf("%w: invalid private key length", ErrInvalidCiphertext)
	}

	if len(encrypted) < minEncryptedSize {
		return nil, fmt.Errorf("%w: ciphertext too short (min %d bytes)", ErrInvalidCiphertext, minEncryptedSize)
	}

	// Extract ephemeral public key (first 32 bytes)
	ephemeralPublic := encrypted[:x25519PublicKeySize]
	nonce := encrypted[x25519PublicKeySize : x25519PublicKeySize+aesGCMNonceSize]
	ciphertext := encrypted[x25519PublicKeySize+aesGCMNonceSize:]

	// Compute shared secret using X25519
	sharedSecret, err := curve25519.X25519(recipientPrivate, ephemeralPublic)
	if err != nil {
		return nil, fmt.Errorf("X25519 key exchange failed: %w", err)
	}
	// SECURITY: Zero shared secret after use
	defer zeroBytesCrypto(sharedSecret)

	// Derive AES key using HKDF-SHA256 (matches vault-manager format)
	// Info includes ephemeral public key for domain separation
	info := append([]byte("vettid-ecies-encryption"), ephemeralPublic...)
	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, info)
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, aesKey); err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}
	// SECURITY: Zero AES key after use
	defer zeroBytesCrypto(aesKey)

	// Decrypt with AES-256-GCM
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("cipher creation failed: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM creation failed: %w", err)
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	return plaintext, nil
}

// X25519Encrypt encrypts data with X25519 + AES-256-GCM
// This matches the format used by vault-manager's encryptWithECIES
// Used for testing and response encryption
func X25519Encrypt(recipientPublic []byte, plaintext []byte) ([]byte, error) {
	if len(recipientPublic) != 32 {
		return nil, fmt.Errorf("%w: invalid public key length", ErrInvalidCiphertext)
	}

	// Generate ephemeral X25519 keypair
	ephemeralPrivate := make([]byte, 32)
	if _, err := rand.Read(ephemeralPrivate); err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}
	defer zeroBytesCrypto(ephemeralPrivate)

	ephemeralPublic, err := curve25519.X25519(ephemeralPrivate, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("failed to derive ephemeral public key: %w", err)
	}

	// Compute shared secret
	sharedSecret, err := curve25519.X25519(ephemeralPrivate, recipientPublic)
	if err != nil {
		return nil, fmt.Errorf("X25519 key exchange failed: %w", err)
	}
	defer zeroBytesCrypto(sharedSecret)

	// Derive AES key (matches vault-manager format)
	info := append([]byte("vettid-ecies-encryption"), ephemeralPublic...)
	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, info)
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, aesKey); err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}
	defer zeroBytesCrypto(aesKey)

	// Create cipher
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("cipher creation failed: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM creation failed: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, aesGCMNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	// Build output: ephemeral_public || nonce || ciphertext
	result := make([]byte, 0, x25519PublicKeySize+aesGCMNonceSize+len(ciphertext))
	result = append(result, ephemeralPublic...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return result, nil
}

// zeroBytesCrypto overwrites a byte slice with zeros
// SECURITY: Used to clear sensitive cryptographic material from memory
func zeroBytesCrypto(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
