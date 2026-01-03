package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"time"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters (matching mobile apps)
const (
	Argon2idTime    = 3
	Argon2idMemory  = 262144 // 256 MB
	Argon2idThreads = 4
	Argon2idKeyLen  = 32
)

// generateIdentityKeypair generates an Ed25519 keypair for vault identity
func generateIdentityKeypair() (privateKey, publicKey []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}

// generateMasterSecret generates a random 32-byte master secret
func generateMasterSecret() ([]byte, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	return secret, nil
}

// generateSalt generates a random 16-byte salt
func generateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// generateSecureToken generates a random token of the specified length
func generateSecureToken(length int) ([]byte, error) {
	token := make([]byte, length)
	if _, err := rand.Read(token); err != nil {
		return nil, err
	}
	return token, nil
}

// hashAuthInput hashes the auth input (PIN/password/pattern) using Argon2id
func hashAuthInput(input, salt []byte) []byte {
	return argon2.IDKey(input, salt, Argon2idTime, Argon2idMemory, Argon2idThreads, Argon2idKeyLen)
}

// verifyAuthHash verifies the auth input against the stored hash
// Uses constant-time comparison to prevent timing attacks
func verifyAuthHash(input, salt, expectedHash []byte) bool {
	computedHash := hashAuthInput(input, salt)
	return timingSafeEqual(computedHash, expectedHash)
}

// timingSafeEqual performs a constant-time comparison of two byte slices
func timingSafeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// currentTimestamp returns the current Unix timestamp
func currentTimestamp() int64 {
	return time.Now().Unix()
}
