package main

import (
	"bytes"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"crypto/sha256"
	"io"
)

// TestECIES_RoundTripWithAADv1 confirms encryptWithECIES/decryptWithECIES
// round-trip under eciesAADv1 binding.
func TestECIES_RoundTripWithAADv1(t *testing.T) {
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatalf("rand: %v", err)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("derive pub: %v", err)
	}
	msg := []byte("hello vault — testing #72 AAD binding")
	ct, err := encryptWithECIES(pub, msg)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	pt, err := decryptWithECIES(priv, ct)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(pt, msg) {
		t.Errorf("round-trip mismatch: got %q want %q", pt, msg)
	}
}

// TestECIES_DecryptAcceptsLegacyNilAAD confirms the decrypt path falls
// back to nil-AAD ciphertexts produced before #72 landed.
func TestECIES_DecryptAcceptsLegacyNilAAD(t *testing.T) {
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatalf("rand: %v", err)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("derive pub: %v", err)
	}

	// Re-implement the pre-#72 encrypt path with nil AAD.
	ephPriv := make([]byte, 32)
	if _, err := rand.Read(ephPriv); err != nil {
		t.Fatalf("rand eph: %v", err)
	}
	ephPub, err := curve25519.X25519(ephPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("derive eph pub: %v", err)
	}
	shared, err := curve25519.X25519(ephPriv, pub)
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}
	r := hkdf.New(sha256.New, shared, []byte(ECIESHKDFSalt), []byte(ECIESHKDFInfo))
	encKey := make([]byte, 32)
	if _, err := io.ReadFull(r, encKey); err != nil {
		t.Fatalf("hkdf: %v", err)
	}
	aead, err := chacha20poly1305.New(encKey)
	if err != nil {
		t.Fatalf("aead new: %v", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand nonce: %v", err)
	}
	msg := []byte("pre-#72 ciphertext")
	ct := aead.Seal(nil, nonce, msg, nil) // legacy: nil AAD
	legacyBlob := append([]byte{}, ephPub...)
	legacyBlob = append(legacyBlob, nonce...)
	legacyBlob = append(legacyBlob, ct...)

	pt, err := decryptWithECIES(priv, legacyBlob)
	if err != nil {
		t.Fatalf("legacy decrypt: %v", err)
	}
	if !bytes.Equal(pt, msg) {
		t.Errorf("legacy round-trip mismatch")
	}
}

// TestECIES_DecryptRejectsTamperedAAD confirms that a ciphertext sealed
// under eciesAADv1 won't accidentally decrypt under a different AAD.
// (Effectively: the tag really does cover the AAD.)
func TestECIES_DecryptRejectsTamperedAAD(t *testing.T) {
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatalf("rand: %v", err)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("derive pub: %v", err)
	}
	msg := []byte("v1-sealed message")
	ct, err := encryptWithECIES(pub, msg)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Manually re-parse the ciphertext and confirm that an AEAD.Open
	// with a deliberately-wrong AAD fails. This sanity-checks that
	// the eciesAADv1 binding is enforced at the tag level.
	ephPub := ct[:32]
	nonce := ct[32:44]
	encrypted := ct[44:]
	shared, err := curve25519.X25519(priv, ephPub)
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}
	r := hkdf.New(sha256.New, shared, []byte(ECIESHKDFSalt), []byte(ECIESHKDFInfo))
	encKey := make([]byte, 32)
	if _, err := io.ReadFull(r, encKey); err != nil {
		t.Fatalf("hkdf: %v", err)
	}
	aead, err := chacha20poly1305.New(encKey)
	if err != nil {
		t.Fatalf("aead new: %v", err)
	}
	if _, err := aead.Open(nil, nonce, encrypted, []byte("not-the-right-aad")); err == nil {
		t.Errorf("AEAD accepted a wrong AAD — tag binding broken")
	}
}
