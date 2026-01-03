package main

import (
	"crypto/rand"
	"fmt"
	"os"

	"golang.org/x/crypto/chacha20poly1305"
)

// Nitro KMS sealing/unsealing
// In a real Nitro enclave, this uses /dev/nsm to seal data to PCR values
// The sealed data can only be unsealed by an enclave with the same PCR values

// sealToNitroKMS seals data using Nitro KMS
// The sealed data is bound to the enclave's PCR values
func sealToNitroKMS(plaintext []byte) ([]byte, error) {
	if isNitroEnclaveEnv() {
		return nitroKMSSeal(plaintext)
	}
	// Development mode: use simple encryption
	return devModeSeal(plaintext)
}

// unsealFromNitroKMS unseals data using Nitro KMS
// Only succeeds if current PCR values match those used during sealing
func unsealFromNitroKMS(ciphertext []byte) ([]byte, error) {
	if isNitroEnclaveEnv() {
		return nitroKMSUnseal(ciphertext)
	}
	// Development mode: use simple decryption
	return devModeUnseal(ciphertext)
}

// isNitroEnclaveEnv checks if we're running in a Nitro enclave
func isNitroEnclaveEnv() bool {
	_, err := os.Stat("/dev/nsm")
	return err == nil
}

// nitroKMSSeal seals data using the actual Nitro secure module
func nitroKMSSeal(plaintext []byte) ([]byte, error) {
	// TODO: Implement actual Nitro KMS sealing
	// This requires:
	// 1. Opening /dev/nsm
	// 2. Generating an attestation document
	// 3. Using AWS KMS with attestation-based key policy
	// 4. Encrypting data with the derived key
	//
	// The key is derived from:
	// - PCR0: Enclave image hash
	// - PCR1: Kernel hash
	// - PCR2: Application hash
	//
	// Only an enclave with matching PCRs can unseal
	return nil, fmt.Errorf("Nitro KMS sealing not yet implemented")
}

// nitroKMSUnseal unseals data using the actual Nitro secure module
func nitroKMSUnseal(ciphertext []byte) ([]byte, error) {
	// TODO: Implement actual Nitro KMS unsealing
	return nil, fmt.Errorf("Nitro KMS unsealing not yet implemented")
}

// Development mode encryption/decryption
// Uses a fixed key for development only - NOT SECURE FOR PRODUCTION

var devModeKey = []byte("vettid-dev-mode-key-32-bytes!!!") // Must be 32 bytes

// devModeSeal encrypts data for development mode
func devModeSeal(plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(devModeKey)
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

// devModeUnseal decrypts data for development mode
func devModeUnseal(ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(devModeKey)
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

// SealedBlob represents a sealed credential blob
type SealedBlob struct {
	Version    int    `json:"version"`
	Algorithm  string `json:"algorithm"`
	PCRBound   bool   `json:"pcr_bound"`
	Ciphertext []byte `json:"ciphertext"`
}
