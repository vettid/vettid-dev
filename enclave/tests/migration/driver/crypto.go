package main

// Crypto primitives the driver needs to mimic the Android app on the
// wire: X25519 ECDH, XChaCha20-Poly1305 AEAD, ECIES (ephemeral-X25519 +
// HKDF + AEAD), and Argon2id PHC. These match the vault's expectations
// so a driver-produced message decodes successfully on the vault side.
//
// Ported from vettid-agent/internal/crypto (can't import directly —
// internal/ packages are module-scoped). Algorithm choices and domain
// separation labels MUST stay in lock-step with the vault; the test
// `harness_crypto_test.go` (added later) round-trips a few fixtures to
// catch drift.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	keySize   = 32 // X25519 + ChaCha20 key
	nonceSize = 24 // XChaCha20-Poly1305 nonce
)

// generateRandomBytes returns n random bytes from the OS CSPRNG.
func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("rand.Read: %w", err)
	}
	return b, nil
}

// x25519KeyPair holds an X25519 keypair for ECDH.
type x25519KeyPair struct {
	PublicKey  []byte // 32 bytes
	PrivateKey []byte // 32 bytes
}

// newX25519KeyPair generates a fresh X25519 keypair.
func newX25519KeyPair() (*x25519KeyPair, error) {
	priv, err := generateRandomBytes(keySize)
	if err != nil {
		return nil, err
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("derive X25519 pub: %w", err)
	}
	return &x25519KeyPair{PublicKey: pub, PrivateKey: priv}, nil
}

// hkdfDerive runs HKDF-SHA256(secret, salt, info=domain) → 32 bytes.
// Matches the enclave's HKDF usage: no explicit salt by default
// (high-entropy IKM), domain string as the info parameter.
func hkdfDerive(secret, salt []byte, domain string) ([]byte, error) {
	r := hkdf.New(sha256.New, secret, salt, []byte(domain))
	out := make([]byte, keySize)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("hkdf read: %w", err)
	}
	return out, nil
}

// eciesEncrypt encrypts plaintext for a recipient identified by their
// X25519 public key. Output layout matches the vault's parser exactly:
//
//	ephemeral_pubkey (32) || nonce (24) || ciphertext+tag
//
// The domain string provides cryptographic domain separation through
// HKDF — must match the vault's decrypt-side domain or AEAD fails.
func eciesEncrypt(recipientPub, plaintext []byte, domain string) ([]byte, error) {
	if len(recipientPub) != keySize {
		return nil, fmt.Errorf("recipient pub must be %d bytes, got %d", keySize, len(recipientPub))
	}

	ephPriv, err := generateRandomBytes(keySize)
	if err != nil {
		return nil, err
	}
	ephPub, err := curve25519.X25519(ephPriv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("derive ephemeral pub: %w", err)
	}

	shared, err := curve25519.X25519(ephPriv, recipientPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}

	encKey, err := hkdfDerive(shared, nil, domain)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return nil, fmt.Errorf("XChaCha20Poly1305: %w", err)
	}

	nonce, err := generateRandomBytes(aead.NonceSize())
	if err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce, plaintext, nil)

	out := make([]byte, 0, len(ephPub)+len(nonce)+len(ct))
	out = append(out, ephPub...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// utkEncrypt produces a payload compatible with the vault's
// decryptWithUTK / encryptWithDomain(DomainUTK):
//
//   - X25519 ECDH(ephemeral_priv, utk_pub)
//   - HKDF-SHA256(shared, salt="vettid-utk-v1", info=nil) → 32-byte key
//   - XChaCha20-Poly1305 with 24-byte nonce
//   - Layout: ephemeral_pubkey (32) || nonce (24) || ciphertext+tag
//
// MUST stay in lock-step with vault-manager/crypto.go's DomainUTK
// constant. Used for credential.create (single base64 field) and
// pin.unlock (driver split form below).
func utkEncrypt(utkPublicKey, plaintext []byte) ([]byte, error) {
	return encryptWithUTKDomain(utkPublicKey, plaintext)
}

// encryptWithUTKDomain is the shared implementation. Kept separate
// from utkEncrypt so the named entry-point is self-documenting and
// future domain variants (PIN, CEK) can copy this and just swap the
// salt string.
func encryptWithUTKDomain(recipientPub, plaintext []byte) ([]byte, error) {
	if len(recipientPub) != keySize {
		return nil, fmt.Errorf("UTK pub must be %d bytes, got %d", keySize, len(recipientPub))
	}

	ephPriv, err := generateRandomBytes(keySize)
	if err != nil {
		return nil, err
	}
	ephPub, err := curve25519.X25519(ephPriv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("derive ephemeral pub: %w", err)
	}
	shared, err := curve25519.X25519(ephPriv, recipientPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}

	// Vault's encryptWithDomain passes domain as the HKDF *salt* and
	// nil info. Drift on either parameter breaks decryption with an
	// opaque AEAD failure.
	r := hkdf.New(sha256.New, shared, []byte("vettid-utk-v1"), nil)
	encKey := make([]byte, keySize)
	if _, err := io.ReadFull(r, encKey); err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}

	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return nil, fmt.Errorf("XChaCha20Poly1305: %w", err)
	}
	nonce, err := generateRandomBytes(aead.NonceSize())
	if err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce, plaintext, nil)

	out := make([]byte, 0, len(ephPub)+len(nonce)+len(ct))
	out = append(out, ephPub...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// pinECIESEncrypt encrypts plaintext for the vault's mobile PIN
// decryption path. Matches the vault's decryptWithECIES exactly:
//
//   - standard ChaCha20-Poly1305 (12-byte nonce, NOT XChaCha20)
//   - HKDF-SHA256 with salt "VettID-HKDF-Salt-v1" and info
//     "enclave-encryption-v1"
//
// Returns the three components as separate base64 strings, matching
// the wire field split (encrypted_pin, ephemeral_public_key, nonce)
// the vault's HandlePINSetup expects.
func pinECIESEncrypt(recipientPub, plaintext []byte) (encB64, ephPubB64, nonceB64 string, err error) {
	if len(recipientPub) != keySize {
		return "", "", "", fmt.Errorf("recipient pub must be %d bytes, got %d", keySize, len(recipientPub))
	}

	ephPriv, err := generateRandomBytes(keySize)
	if err != nil {
		return "", "", "", err
	}
	ephPub, err := curve25519.X25519(ephPriv, curve25519.Basepoint)
	if err != nil {
		return "", "", "", fmt.Errorf("derive ephemeral pub: %w", err)
	}

	shared, err := curve25519.X25519(ephPriv, recipientPub)
	if err != nil {
		return "", "", "", fmt.Errorf("ECDH: %w", err)
	}

	// HKDF-SHA256 with the vault-specific salt+info pair. These must
	// stay in lock-step with vault-manager/crypto.go's constants
	// (ECIESHKDFSalt + ECIESHKDFInfo) — drift on either side breaks
	// PIN decryption with an opaque "decryption failed" error.
	r := hkdf.New(sha256.New, shared,
		[]byte("VettID-HKDF-Salt-v1"),
		[]byte("enclave-encryption-v1"))
	encKey := make([]byte, keySize)
	if _, err := io.ReadFull(r, encKey); err != nil {
		return "", "", "", fmt.Errorf("hkdf read: %w", err)
	}

	// Standard ChaCha20-Poly1305 has a 12-byte nonce.
	aead, err := chacha20poly1305.New(encKey)
	if err != nil {
		return "", "", "", fmt.Errorf("ChaCha20Poly1305: %w", err)
	}
	nonce, err := generateRandomBytes(aead.NonceSize())
	if err != nil {
		return "", "", "", err
	}
	ct := aead.Seal(nil, nonce, plaintext, nil)

	return base64.StdEncoding.EncodeToString(ct),
		base64.StdEncoding.EncodeToString(ephPub),
		base64.StdEncoding.EncodeToString(nonce),
		nil
}

// utkEncryptSplit returns the three components the Android app sends
// as separate base64 fields: encryptedPasswordHash (the ciphertext+tag
// alone), ephemeralPublicKey, nonce. This matches the wire format
// verifyPasswordAgainstCredential in the vault expects.
func utkEncryptSplit(utkPublicKey, plaintext []byte) (encPwHashB64, ephPubB64, nonceB64 string, err error) {
	combined, err := utkEncrypt(utkPublicKey, plaintext)
	if err != nil {
		return "", "", "", err
	}
	ephPub := combined[:keySize]
	nonce := combined[keySize : keySize+nonceSize]
	ct := combined[keySize+nonceSize:]
	return base64.StdEncoding.EncodeToString(ct),
		base64.StdEncoding.EncodeToString(ephPub),
		base64.StdEncoding.EncodeToString(nonce),
		nil
}

// argon2idPHC produces a PHC-formatted Argon2id hash of the password
// using the supplied salt and the same params the Android app uses.
// Returns the canonical PHC string (matches what the vault stores in
// credential.Auth.Hash). Default params: m=64MiB, t=3, p=4, 32-byte hash.
func argon2idPHC(password, salt []byte) string {
	const (
		time    uint32 = 3
		memory  uint32 = 64 * 1024 // 64 MiB
		threads uint8  = 4
		keyLen  uint32 = 32
	)
	hash := argon2.IDKey(password, salt, time, memory, threads, keyLen)
	return fmt.Sprintf(
		"$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		memory, time, threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)
}

// hmacSHA256 is a tiny convenience wrapper for the connection-key
// derivations the driver may need later.
func hmacSHA256(key, message []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(message)
	return h.Sum(nil)
}
