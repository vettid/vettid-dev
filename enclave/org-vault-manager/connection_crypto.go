package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// DomainOrgVault is the HKDF context for org vault operator connections.
// MUST match vettid-healthcare-demo/service/connection_crypto.go:DomainOrgVault.
// A distinct domain prevents key reuse with user vault agent connections
// (which use DomainAgent).
const DomainOrgVault = "vettid-org-vault-v1"

// deriveConnectionKey derives a 32-byte XChaCha20-Poly1305 key from the
// X25519 ECDH shared secret using HKDF-SHA256. Both sides of the connection
// (org vault and the demo service acting on the operator's behalf) call this
// with the same shared secret and produce the same key.
func deriveConnectionKey(sharedSecret []byte) ([]byte, error) {
	if len(sharedSecret) == 0 {
		return nil, fmt.Errorf("shared secret is empty")
	}
	r := hkdf.New(sha256.New, sharedSecret, nil, []byte(DomainOrgVault))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("hkdf read: %w", err)
	}
	return key, nil
}

// encryptXChaCha20 encrypts plaintext with XChaCha20-Poly1305.
// Output format: [nonce(24) || ciphertext+tag]
func encryptXChaCha20(key, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("new aead: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

// decryptXChaCha20 decrypts ciphertext produced by encryptXChaCha20.
// Expects format: [nonce(24) || ciphertext+tag]
func decryptXChaCha20(key, ciphertext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("new aead: %w", err)
	}
	if len(ciphertext) < aead.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short: %d < %d", len(ciphertext), aead.NonceSize())
	}
	nonce := ciphertext[:aead.NonceSize()]
	ct := ciphertext[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	return plaintext, nil
}
