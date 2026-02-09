package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// Argon2id parameters (matching mobile apps)
// OWASP recommended minimum: t=3, m=65536 (64MB), p=4
// 64MB chosen for device compatibility (works on 2GB RAM phones)
const (
	Argon2idTime    = 3
	Argon2idMemory  = 65536 // 64 MB (OWASP recommended minimum)
	Argon2idThreads = 4
	Argon2idKeyLen  = 32
)

// Domain constants for X25519 encryption (per architecture doc Section 5.5)
// Domain separation prevents key confusion attacks between different encryption contexts
// Each domain produces different derived keys even with the same shared secret
const (
	// DomainCEK is used for CEK encrypting Protean Credential
	DomainCEK = "vettid-cek-v1"
	// DomainUTK is used for UTK encrypting password/challenge payloads
	DomainUTK = "vettid-utk-v1"
	// DomainPIN is used for attestation-bound PIN encryption
	DomainPIN = "vettid-pin-v1"
)

// Legacy ECIES constants for backward compatibility
// DEPRECATED: Use domain-specific encryption functions instead
const (
	ECIESHKDFSalt = "VettID-HKDF-Salt-v1"
	ECIESHKDFInfo = "enclave-encryption-v1"
)

// XChaCha20-Poly1305 nonce size (24 bytes vs 12 for standard ChaCha20)
const XChaCha20NonceSize = 24

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

// timingSafeEqual performs a constant-time comparison of two byte slices.
// Uses crypto/subtle.ConstantTimeCompare which safely handles different-length inputs
// without leaking length information through timing.
func timingSafeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// currentTimestamp returns the current Unix timestamp
func currentTimestamp() int64 {
	return time.Now().Unix()
}

// --- ECIES Encryption/Decryption (X25519 + ChaCha20-Poly1305) ---
// Parameters match Android CryptoManager.encryptToPublicKey()

// decryptWithECIES decrypts data using the vault's ECIES private key
// Format: ephemeral_pubkey (32) || nonce (12) || encrypted_data
// Uses ChaCha20-Poly1305 with HKDF key derivation matching Android
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

	// Derive encryption key using HKDF-SHA256 with Android-compatible parameters
	// Salt: "VettID-HKDF-Salt-v1" (cross-platform constant)
	// Info: "enclave-encryption-v1" (context for this encryption type)
	hkdfReader := hkdf.New(sha256.New, sharedSecret, []byte(ECIESHKDFSalt), []byte(ECIESHKDFInfo))
	encKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, encKey); err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}
	// SECURITY: Zero encryption key after use
	defer zeroBytes(encKey)

	// Decrypt using ChaCha20-Poly1305 (matching Android's chaChaEncrypt)
	aead, err := chacha20poly1305.New(encKey)
	if err != nil {
		return nil, fmt.Errorf("cipher creation failed: %w", err)
	}

	plaintext, err := aead.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// encryptWithECIES encrypts data using a recipient's ECIES public key
// Returns: ephemeral_pubkey (32) || nonce (12) || encrypted_data
// Uses ChaCha20-Poly1305 with HKDF key derivation matching Android
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

	// Derive encryption key using HKDF-SHA256 with Android-compatible parameters
	// Salt: "VettID-HKDF-Salt-v1" (cross-platform constant)
	// Info: "enclave-encryption-v1" (context for this encryption type)
	hkdfReader := hkdf.New(sha256.New, sharedSecret, []byte(ECIESHKDFSalt), []byte(ECIESHKDFInfo))
	encKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, encKey); err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}
	// SECURITY: Zero encryption key after use
	defer zeroBytes(encKey)

	// Encrypt using ChaCha20-Poly1305 (matching Android's chaChaEncrypt)
	aead, err := chacha20poly1305.New(encKey)
	if err != nil {
		return nil, fmt.Errorf("cipher creation failed: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

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

// --- XChaCha20-Poly1305 Domain-Separated Encryption ---
// These functions use domain separation for HKDF and XChaCha20-Poly1305 for encryption
// Format: ephemeral_pubkey (32) || nonce (24) || ciphertext

// encryptWithDomain encrypts data using XChaCha20-Poly1305 with domain-separated HKDF
// Returns: ephemeral_pubkey (32) || nonce (24) || ciphertext
// SECURITY: Zeroizes all intermediate key material after use
func encryptWithDomain(recipientPubKey []byte, plaintext []byte, domain string) ([]byte, error) {
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

	// Derive encryption key using HKDF-SHA256 with domain separation
	// Salt: domain string (e.g., "vettid-cek-v1")
	// Info: nil (domain in salt provides sufficient separation)
	hkdfReader := hkdf.New(sha256.New, sharedSecret, []byte(domain), nil)
	encKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(hkdfReader, encKey); err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}
	// SECURITY: Zero encryption key after use
	defer zeroBytes(encKey)

	// Encrypt using XChaCha20-Poly1305 (24-byte nonce)
	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return nil, fmt.Errorf("cipher creation failed: %w", err)
	}

	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	// Format: ephemeral_pubkey (32) || nonce (24) || ciphertext
	result := make([]byte, 0, 32+chacha20poly1305.NonceSizeX+len(ciphertext))
	result = append(result, ephemeralPublic...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return result, nil
}

// decryptWithDomain decrypts data using XChaCha20-Poly1305 with domain-separated HKDF
// Format: ephemeral_pubkey (32) || nonce (24) || ciphertext
// SECURITY: Zeroizes all intermediate key material after use
func decryptWithDomain(privateKey []byte, ciphertext []byte, domain string) ([]byte, error) {
	log.Debug().
		Str("domain", domain).
		Int("ciphertext_len", len(ciphertext)).
		Int("private_key_len", len(privateKey)).
		Msg("DEBUG: decryptWithDomain called")

	minLen := 32 + chacha20poly1305.NonceSizeX
	if len(ciphertext) < minLen {
		log.Warn().
			Int("min_len", minLen).
			Int("actual_len", len(ciphertext)).
			Msg("DEBUG: ciphertext too short")
		return nil, fmt.Errorf("ciphertext too short: need at least %d bytes, got %d", minLen, len(ciphertext))
	}

	ephemeralPubKey := ciphertext[:32]
	nonce := ciphertext[32 : 32+chacha20poly1305.NonceSizeX]
	encrypted := ciphertext[32+chacha20poly1305.NonceSizeX:]

	log.Debug().
		Int("ephemeral_key_len", len(ephemeralPubKey)).
		Int("nonce_len", len(nonce)).
		Int("encrypted_len", len(encrypted)).
		Msg("DEBUG: Parsed ciphertext components")

	// X25519 key exchange
	sharedSecret, err := curve25519.X25519(privateKey, ephemeralPubKey)
	if err != nil {
		log.Warn().Err(err).Msg("DEBUG: X25519 key exchange failed")
		return nil, fmt.Errorf("key exchange failed: %w", err)
	}
	// SECURITY: Zero shared secret after use
	defer zeroBytes(sharedSecret)

	log.Debug().Int("shared_secret_len", len(sharedSecret)).Msg("DEBUG: X25519 key exchange succeeded")

	// Derive encryption key using HKDF-SHA256 with domain separation
	hkdfReader := hkdf.New(sha256.New, sharedSecret, []byte(domain), nil)
	encKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(hkdfReader, encKey); err != nil {
		log.Warn().Err(err).Msg("DEBUG: HKDF key derivation failed")
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}
	// SECURITY: Zero encryption key after use
	defer zeroBytes(encKey)

	// Decrypt using XChaCha20-Poly1305
	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		log.Warn().Err(err).Msg("DEBUG: Cipher creation failed")
		return nil, fmt.Errorf("cipher creation failed: %w", err)
	}

	plaintext, err := aead.Open(nil, nonce, encrypted, nil)
	if err != nil {
		log.Warn().Err(err).Str("domain", domain).Msg("DEBUG: AEAD decryption failed")
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	log.Debug().
		Str("domain", domain).
		Int("plaintext_len", len(plaintext)).
		Msg("DEBUG: decryptWithDomain succeeded")

	return plaintext, nil
}

// --- CEK Operations ---

// encryptWithCEK encrypts credential data with the CEK using XChaCha20-Poly1305
// Uses DomainCEK for HKDF key derivation
func encryptWithCEK(cekPublicKey []byte, plaintext []byte) ([]byte, error) {
	return encryptWithDomain(cekPublicKey, plaintext, DomainCEK)
}

// decryptWithCEK decrypts credential data with the CEK private key
// Uses DomainCEK for HKDF key derivation
func decryptWithCEK(cekPrivateKey []byte, ciphertext []byte) ([]byte, error) {
	return decryptWithDomain(cekPrivateKey, ciphertext, DomainCEK)
}

// --- UTK Operations ---

// encryptWithUTK encrypts payload data with a UTK using XChaCha20-Poly1305
// Uses DomainUTK for HKDF key derivation
func encryptWithUTK(utkPublicKey []byte, plaintext []byte) ([]byte, error) {
	return encryptWithDomain(utkPublicKey, plaintext, DomainUTK)
}

// decryptWithUTK decrypts payload data with the corresponding LTK
// Uses DomainUTK for HKDF key derivation
func decryptWithUTK(ltkPrivateKey []byte, ciphertext []byte) ([]byte, error) {
	return decryptWithDomain(ltkPrivateKey, ciphertext, DomainUTK)
}

// --- PIN Encryption Operations ---

// encryptWithPINDomain encrypts PIN-related data using XChaCha20-Poly1305
// Uses DomainPIN for HKDF key derivation
func encryptWithPINDomain(recipientPubKey []byte, plaintext []byte) ([]byte, error) {
	return encryptWithDomain(recipientPubKey, plaintext, DomainPIN)
}

// decryptWithPINDomain decrypts PIN-related data
// Uses DomainPIN for HKDF key derivation
func decryptWithPINDomain(privateKey []byte, ciphertext []byte) ([]byte, error) {
	return decryptWithDomain(privateKey, ciphertext, DomainPIN)
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

// --- PHC String Format Parsing ---
// PHC format: $argon2id$v=19$m=65536,t=3,p=4$<base64-salt>$<base64-hash>

// PHCParams holds parsed Argon2id parameters from a PHC string
type PHCParams struct {
	Algorithm   string // "argon2id"
	Version     int    // 19 (0x13)
	MemoryCost  uint32 // m parameter in KB
	TimeCost    uint32 // t parameter (iterations)
	Parallelism uint8  // p parameter (threads)
	Salt        []byte // Decoded salt
	Hash        []byte // Decoded hash
}

// parsePHCString parses an Argon2id PHC string and extracts all parameters
// Format: $argon2id$v=19$m=65536,t=3,p=4$<base64-salt>$<base64-hash>
func parsePHCString(phc string) (*PHCParams, error) {
	if !strings.HasPrefix(phc, "$argon2id$") {
		return nil, fmt.Errorf("invalid PHC string: must start with $argon2id$")
	}

	// Split by $ (first element is empty due to leading $)
	parts := strings.Split(phc, "$")
	if len(parts) != 6 {
		return nil, fmt.Errorf("invalid PHC string: expected 6 parts, got %d", len(parts))
	}

	// parts[0] = ""
	// parts[1] = "argon2id"
	// parts[2] = "v=19"
	// parts[3] = "m=65536,t=3,p=4"
	// parts[4] = base64 salt
	// parts[5] = base64 hash

	params := &PHCParams{
		Algorithm: parts[1],
	}

	// Parse version
	if !strings.HasPrefix(parts[2], "v=") {
		return nil, fmt.Errorf("invalid PHC string: missing version")
	}
	version, err := strconv.Atoi(strings.TrimPrefix(parts[2], "v="))
	if err != nil {
		return nil, fmt.Errorf("invalid PHC string: invalid version: %w", err)
	}
	params.Version = version

	// Parse m, t, p parameters
	paramParts := strings.Split(parts[3], ",")
	for _, p := range paramParts {
		kv := strings.SplitN(p, "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("invalid PHC string: malformed parameter: %s", p)
		}
		val, err := strconv.ParseUint(kv[1], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid PHC string: invalid parameter value: %s", p)
		}
		switch kv[0] {
		case "m":
			params.MemoryCost = uint32(val)
		case "t":
			params.TimeCost = uint32(val)
		case "p":
			params.Parallelism = uint8(val)
		default:
			// Ignore unknown parameters for forward compatibility
		}
	}

	// Decode salt (base64 without padding, as per PHC spec)
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, fmt.Errorf("invalid PHC string: invalid salt encoding: %w", err)
	}
	params.Salt = salt

	// Decode hash
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, fmt.Errorf("invalid PHC string: invalid hash encoding: %w", err)
	}
	params.Hash = hash

	return params, nil
}

// validatePHCString validates a PHC string meets minimum security requirements
// Returns nil if valid, error otherwise
func validatePHCString(phc string) error {
	params, err := parsePHCString(phc)
	if err != nil {
		return err
	}

	if params.Algorithm != "argon2id" {
		return fmt.Errorf("invalid algorithm: must use argon2id, got %s", params.Algorithm)
	}

	// Version 19 (0x13) is the current Argon2 version
	if params.Version != 19 {
		return fmt.Errorf("invalid version: expected 19, got %d", params.Version)
	}

	// Enforce minimum security parameters
	if params.MemoryCost < 65536 {
		return fmt.Errorf("memory cost too low: minimum 65536 KB (64 MB), got %d KB", params.MemoryCost)
	}

	if params.TimeCost < 3 {
		return fmt.Errorf("time cost too low: minimum 3 iterations, got %d", params.TimeCost)
	}

	if params.Parallelism < 1 {
		return fmt.Errorf("parallelism too low: minimum 1, got %d", params.Parallelism)
	}

	// Validate salt and hash lengths
	if len(params.Salt) < 16 {
		return fmt.Errorf("salt too short: minimum 16 bytes, got %d", len(params.Salt))
	}

	if len(params.Hash) != 32 {
		return fmt.Errorf("hash length invalid: expected 32 bytes, got %d", len(params.Hash))
	}

	return nil
}

// verifyPHCHash verifies a password against a PHC string
// SECURITY: Uses constant-time comparison to prevent timing attacks
func verifyPHCHash(password []byte, phc string) (bool, error) {
	params, err := parsePHCString(phc)
	if err != nil {
		return false, err
	}

	// Recompute hash with same parameters
	computedHash := argon2.IDKey(
		password,
		params.Salt,
		params.TimeCost,
		params.MemoryCost,
		params.Parallelism,
		uint32(len(params.Hash)),
	)
	defer zeroBytes(computedHash) // SECURITY: Zero after comparison

	// Constant-time comparison
	return constantTimeCompare(computedHash, params.Hash), nil
}
