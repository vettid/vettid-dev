package main

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestDeriveConnectionKey_DeterministicForSameSecret(t *testing.T) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("rand: %v", err)
	}

	key1, err := deriveConnectionKey(secret)
	if err != nil {
		t.Fatalf("first derive: %v", err)
	}
	key2, err := deriveConnectionKey(secret)
	if err != nil {
		t.Fatalf("second derive: %v", err)
	}

	if !bytes.Equal(key1, key2) {
		t.Errorf("expected same key for same secret, got different")
	}
	if len(key1) != 32 {
		t.Errorf("expected 32-byte key, got %d", len(key1))
	}
}

func TestDeriveConnectionKey_DifferentForDifferentSecrets(t *testing.T) {
	secret1 := make([]byte, 32)
	secret2 := make([]byte, 32)
	rand.Read(secret1)
	rand.Read(secret2)

	key1, _ := deriveConnectionKey(secret1)
	key2, _ := deriveConnectionKey(secret2)

	if bytes.Equal(key1, key2) {
		t.Error("expected different keys for different secrets, got equal")
	}
}

func TestDeriveConnectionKey_RejectsEmptySecret(t *testing.T) {
	_, err := deriveConnectionKey([]byte{})
	if err == nil {
		t.Error("expected error for empty secret")
	}
}

func TestEncryptDecrypt_Roundtrip(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	plaintext := []byte("the quick brown fox jumps over the lazy patient record")

	ciphertext, err := encryptXChaCha20(key, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if bytes.Equal(ciphertext, plaintext) {
		t.Error("ciphertext should differ from plaintext")
	}

	// Ciphertext should be longer (24-byte nonce + 16-byte tag = 40 bytes overhead)
	if len(ciphertext) < len(plaintext)+40 {
		t.Errorf("ciphertext too short: %d (expected at least %d)", len(ciphertext), len(plaintext)+40)
	}

	decrypted, err := decryptXChaCha20(key, ciphertext)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("roundtrip failed: got %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptDecrypt_FailsWithWrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)

	plaintext := []byte("secret patient data")
	ciphertext, _ := encryptXChaCha20(key1, plaintext)

	_, err := decryptXChaCha20(key2, ciphertext)
	if err == nil {
		t.Error("expected decrypt to fail with wrong key")
	}
}

func TestEncryptDecrypt_DifferentNoncesEachCall(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	plaintext := []byte("same plaintext")

	ct1, _ := encryptXChaCha20(key, plaintext)
	ct2, _ := encryptXChaCha20(key, plaintext)

	if bytes.Equal(ct1, ct2) {
		t.Error("two encryptions of the same plaintext should produce different ciphertexts (random nonce)")
	}

	// First 24 bytes are the nonce; they must differ
	if bytes.Equal(ct1[:24], ct2[:24]) {
		t.Error("nonces should be different between calls")
	}
}

func TestEncryptDecrypt_RejectsBadKeySize(t *testing.T) {
	plaintext := []byte("test")

	_, err := encryptXChaCha20([]byte("short"), plaintext)
	if err == nil {
		t.Error("expected error for short key")
	}
}

func TestDecrypt_RejectsTruncatedCiphertext(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	_, err := decryptXChaCha20(key, []byte("too short"))
	if err == nil {
		t.Error("expected error for truncated ciphertext")
	}
}
