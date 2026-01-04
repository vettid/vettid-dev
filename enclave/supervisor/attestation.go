package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
	"github.com/rs/zerolog/log"
)

// GenerateAttestation generates a Nitro attestation document
// In a real Nitro enclave, this calls /dev/nsm to get a signed attestation
// For development, this returns a mock attestation
func GenerateAttestation(nonce []byte) (*Attestation, error) {
	// Check if we're in a real Nitro enclave
	if isNitroEnclave() {
		return generateNitroAttestation(nonce)
	}

	// Development mode - generate mock attestation
	log.Warn().Msg("Generating mock attestation (not in Nitro enclave)")
	return generateMockAttestation(nonce)
}

// isNitroEnclave checks if we're running in a Nitro enclave
func isNitroEnclave() bool {
	// Check for NSM device (Nitro Secure Module)
	_, err := os.Stat("/dev/nsm")
	return err == nil
}

// generateNitroAttestation generates a real Nitro attestation document
func generateNitroAttestation(nonce []byte) (*Attestation, error) {
	// Open the NSM (Nitro Security Module) device
	sess, err := nsm.OpenDefaultSession()
	if err != nil {
		return nil, fmt.Errorf("failed to open NSM session: %w", err)
	}
	defer sess.Close()

	// Generate an ephemeral ECDSA key pair for the session
	// This public key will be embedded in the attestation document
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate session key: %w", err)
	}

	// Marshal the public key
	pubKeyBytes := elliptic.Marshal(elliptic.P256(), privateKey.PublicKey.X, privateKey.PublicKey.Y)

	// Request attestation from NSM
	// The nonce is included to ensure freshness
	// The public key is included so clients can encrypt session data to it
	res, err := sess.Send(&request.Attestation{
		Nonce:     nonce,
		PublicKey: pubKeyBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get attestation from NSM: %w", err)
	}

	// Extract the attestation document
	if res.Attestation == nil || res.Attestation.Document == nil {
		return nil, fmt.Errorf("NSM returned empty attestation document")
	}

	log.Debug().
		Int("doc_len", len(res.Attestation.Document)).
		Int("pubkey_len", len(pubKeyBytes)).
		Msg("Generated Nitro attestation document")

	return &Attestation{
		Document:  res.Attestation.Document,
		PublicKey: pubKeyBytes,
	}, nil
}

// generateMockAttestation generates a mock attestation for development
func generateMockAttestation(nonce []byte) (*Attestation, error) {
	// Generate ephemeral key pair for session encryption
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Encode public key
	pubKeyBytes := elliptic.Marshal(elliptic.P256(), privateKey.PublicKey.X, privateKey.PublicKey.Y)

	// Create mock attestation document
	// In reality, this would be a CBOR-encoded COSE Sign1 structure
	mockDoc := MockAttestationDocument{
		ModuleID:  "mock-enclave",
		Timestamp: time.Now().Unix(),
		Nonce:     nonce,
		PCRs: map[int]string{
			0: base64.StdEncoding.EncodeToString(mockPCR(0)),
			1: base64.StdEncoding.EncodeToString(mockPCR(1)),
			2: base64.StdEncoding.EncodeToString(mockPCR(2)),
		},
		PublicKey: base64.StdEncoding.EncodeToString(pubKeyBytes),
	}

	// In production, this would be signed by AWS Nitro
	// For mock, we just serialize it
	docBytes := serializeMockDoc(mockDoc)

	return &Attestation{
		Document:  docBytes,
		PublicKey: pubKeyBytes,
	}, nil
}

// MockAttestationDocument represents a mock attestation document
type MockAttestationDocument struct {
	ModuleID  string         `json:"module_id"`
	Timestamp int64          `json:"timestamp"`
	Nonce     []byte         `json:"nonce"`
	PCRs      map[int]string `json:"pcrs"`
	PublicKey string         `json:"public_key"`
}

// mockPCR generates a mock PCR value
func mockPCR(index int) []byte {
	// In reality, PCRs are SHA-384 hashes of enclave components
	// PCR0: Enclave image
	// PCR1: Linux kernel and bootstrap
	// PCR2: Application
	data := fmt.Sprintf("mock-pcr-%d-development", index)
	hash := sha256.Sum256([]byte(data))
	return hash[:]
}

// serializeMockDoc serializes a mock attestation document
func serializeMockDoc(doc MockAttestationDocument) []byte {
	// In production, this would be CBOR + COSE
	// For development, we use a simple format
	return []byte(fmt.Sprintf(
		"MOCK_ATTESTATION:module_id=%s,timestamp=%d,pcr0=%s,pcr1=%s,pcr2=%s,pubkey=%s",
		doc.ModuleID,
		doc.Timestamp,
		doc.PCRs[0],
		doc.PCRs[1],
		doc.PCRs[2],
		doc.PublicKey,
	))
}

// VerifyAttestation verifies an attestation document
// This is typically done on the client side, but the enclave can also verify
// attestations from other enclaves for peer-to-peer scenarios
func VerifyAttestation(attestation *Attestation, expectedPCRs map[int][]byte) error {
	// TODO: Implement attestation verification
	// 1. Verify COSE signature using AWS Nitro root CA
	// 2. Parse CBOR document
	// 3. Compare PCR values against expected
	// 4. Check timestamp is recent (within acceptable window)
	// 5. Verify nonce matches expected (if provided)

	return nil
}

// PCRValues holds expected PCR values for verification
type PCRValues struct {
	PCR0 []byte // Enclave image hash
	PCR1 []byte // Kernel hash
	PCR2 []byte // Application hash
}

// LoadExpectedPCRs loads expected PCR values from configuration
func LoadExpectedPCRs(configPath string) (*PCRValues, error) {
	// TODO: Load from configuration file
	// These values are generated when building the enclave image
	return &PCRValues{}, nil
}
