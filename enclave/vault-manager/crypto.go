package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
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
// SECURITY: Zeroizes computed hash after comparison to prevent memory leakage
func verifyAuthHash(input, salt, expectedHash []byte) bool {
	computedHash := hashAuthInput(input, salt)
	defer zeroBytes(computedHash) // SECURITY: Zero hash after use
	return timingSafeEqual(computedHash, expectedHash)
}

// zeroBytes overwrites a byte slice with zeros
// SECURITY: Used to clear sensitive data from memory
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
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

// --- ECIES Encryption/Decryption (X25519 + AES-GCM) ---

// decryptWithECIES decrypts data using the vault's ECIES private key
// Format: ephemeral_pubkey (32) || nonce (12) || encrypted_data
// SECURITY: Zeroizes all intermediate key material after use
func decryptWithECIES(privateKey []byte, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 32+12 {
		return nil, fmt.Errorf("ciphertext too short")
	}

	ephemeralPubKey := ciphertext[:32]
	nonce := ciphertext[32:44]
	encrypted := ciphertext[44:]

	// X25519 key exchange
	sharedSecret, err := curve25519.X25519(privateKey, ephemeralPubKey)
	if err != nil {
		return nil, fmt.Errorf("key exchange failed: %w", err)
	}
	// SECURITY: Zero shared secret after use
	defer zeroBytes(sharedSecret)

	// Derive AES key using HKDF-SHA256
	info := append([]byte("vettid-ecies-encryption"), ephemeralPubKey...)
	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, info)
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, aesKey); err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}
	// SECURITY: Zero AES key after use
	defer zeroBytes(aesKey)

	// Decrypt using AES-256-GCM
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("cipher creation failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM creation failed: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// encryptWithECIES encrypts data using a recipient's ECIES public key
// Returns: ephemeral_pubkey (32) || nonce (12) || encrypted_data
// SECURITY: Zeroizes all intermediate key material after use
func encryptWithECIES(recipientPubKey []byte, plaintext []byte) ([]byte, error) {
	// Generate ephemeral keypair
	ephemeralPrivate := make([]byte, 32)
	if _, err := rand.Read(ephemeralPrivate); err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}
	// SECURITY: Zero ephemeral private key after use
	defer zeroBytes(ephemeralPrivate)

	ephemeralPublic, err := curve25519.X25519(ephemeralPrivate, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("failed to derive ephemeral public key: %w", err)
	}

	// X25519 key exchange
	sharedSecret, err := curve25519.X25519(ephemeralPrivate, recipientPubKey)
	if err != nil {
		return nil, fmt.Errorf("key exchange failed: %w", err)
	}
	// SECURITY: Zero shared secret after use
	defer zeroBytes(sharedSecret)

	// Derive AES key using HKDF-SHA256
	info := append([]byte("vettid-ecies-encryption"), ephemeralPublic...)
	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, info)
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, aesKey); err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}
	// SECURITY: Zero AES key after use
	defer zeroBytes(aesKey)

	// Encrypt using AES-256-GCM
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("cipher creation failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM creation failed: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Format: ephemeral_pubkey || nonce || ciphertext
	result := make([]byte, 0, 32+len(nonce)+len(ciphertext))
	result = append(result, ephemeralPublic...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return result, nil
}

// --- DEK Encryption/Decryption (AES-256-GCM) ---

// encryptWithDEK encrypts data with the Data Encryption Key using AES-256-GCM
func encryptWithDEK(dek []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("cipher creation failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM creation failed: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Format: nonce || ciphertext
	result := make([]byte, 0, len(nonce)+len(ciphertext))
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return result, nil
}

// decryptWithDEK decrypts data with the Data Encryption Key using AES-256-GCM
// Format: nonce (12) || ciphertext
func decryptWithDEK(dek []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("cipher creation failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM creation failed: %w", err)
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertext[:gcm.NonceSize()]
	encrypted := ciphertext[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// --- CEK Operations ---

// encryptWithCEK encrypts credential data with the CEK using ECIES
func encryptWithCEK(cekPublicKey []byte, plaintext []byte) ([]byte, error) {
	return encryptWithECIES(cekPublicKey, plaintext)
}

// decryptWithCEK decrypts credential data with the CEK private key
func decryptWithCEK(cekPrivateKey []byte, ciphertext []byte) ([]byte, error) {
	return decryptWithECIES(cekPrivateKey, ciphertext)
}

// NOTE: generateX25519Keypair is defined in cek.go

// --- Hash Utilities ---

// hashSHA256 computes SHA-256 hash
func hashSHA256(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// constantTimeCompare performs constant-time comparison using crypto/subtle
func constantTimeCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// isAllDigits checks if a byte slice contains only ASCII digits
func isAllDigits(b []byte) bool {
	for _, c := range b {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
