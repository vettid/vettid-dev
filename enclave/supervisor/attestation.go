package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
	"github.com/rs/zerolog/log"
)

// SECURITY: Maximum age for attestation documents (5 minutes)
const maxAttestationAgeSeconds = 300

// SECURITY: AWS Nitro Attestation Root CA (embedded for trust anchor)
// This is the root certificate used to verify Nitro attestation signatures
// Source: https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
const awsNitroRootCAPEM = `-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----`

var (
	// ErrInvalidAttestation indicates the attestation document is invalid
	ErrInvalidAttestation = errors.New("invalid attestation document")
	// ErrPCRMismatch indicates PCR values don't match expected
	ErrPCRMismatch = errors.New("PCR values do not match expected")
	// ErrAttestationExpired indicates the attestation is too old
	ErrAttestationExpired = errors.New("attestation document expired")
	// ErrInvalidSignature indicates the signature verification failed
	ErrInvalidSignature = errors.New("attestation signature verification failed")
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

// COSESign1 represents a COSE_Sign1 structure (RFC 8152)
type COSESign1 struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected map[interface{}]interface{}
	Payload     []byte
	Signature   []byte
}

// AttestationDocument represents the payload of a Nitro attestation
type AttestationDocument struct {
	ModuleID    string          `cbor:"module_id"`
	Timestamp   uint64          `cbor:"timestamp"`
	Digest      string          `cbor:"digest"`
	PCRs        map[int][]byte  `cbor:"pcrs"`
	Certificate []byte          `cbor:"certificate"`
	CABundle    [][]byte        `cbor:"cabundle"`
	PublicKey   []byte          `cbor:"public_key,omitempty"`
	UserData    []byte          `cbor:"user_data,omitempty"`
	Nonce       []byte          `cbor:"nonce,omitempty"`
}

// VerifyAttestation verifies a Nitro attestation document
// SECURITY: This is critical - it validates the enclave's identity
func VerifyAttestation(attestation *Attestation, expectedPCRs map[int][]byte) error {
	if attestation == nil || len(attestation.Document) == 0 {
		return ErrInvalidAttestation
	}

	// Check for mock attestation (development only)
	if bytes.HasPrefix(attestation.Document, []byte("MOCK_ATTESTATION:")) {
		return verifyMockAttestation(attestation, expectedPCRs)
	}

	// Parse COSE_Sign1 structure
	var coseSign1 COSESign1
	if err := cbor.Unmarshal(attestation.Document, &coseSign1); err != nil {
		log.Error().Err(err).Msg("Failed to parse COSE_Sign1 structure")
		return fmt.Errorf("%w: failed to parse COSE_Sign1", ErrInvalidAttestation)
	}

	// Parse the attestation document payload
	var attDoc AttestationDocument
	if err := cbor.Unmarshal(coseSign1.Payload, &attDoc); err != nil {
		log.Error().Err(err).Msg("Failed to parse attestation document payload")
		return fmt.Errorf("%w: failed to parse payload", ErrInvalidAttestation)
	}

	// 1. Verify certificate chain against AWS Nitro root CA
	if err := verifyCertificateChain(attDoc.Certificate, attDoc.CABundle); err != nil {
		log.Error().Err(err).Msg("Certificate chain verification failed")
		return fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}

	// 2. Verify COSE signature using the leaf certificate's public key
	if err := verifyCOSESignature(&coseSign1, attDoc.Certificate); err != nil {
		log.Error().Err(err).Msg("COSE signature verification failed")
		return fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}

	// 3. Validate timestamp (freshness check)
	// NOTE: Nitro attestation document timestamp is in milliseconds since epoch
	now := uint64(time.Now().UnixMilli())
	docAge := (now - attDoc.Timestamp) / 1000 // Convert to seconds for comparison
	if docAge > maxAttestationAgeSeconds {
		log.Error().
			Uint64("doc_timestamp", attDoc.Timestamp).
			Uint64("now", now).
			Uint64("age_seconds", docAge).
			Msg("Attestation document too old")
		return fmt.Errorf("%w: document is %d seconds old (max %d)",
			ErrAttestationExpired, docAge, maxAttestationAgeSeconds)
	}

	// 4. Verify PCR values
	if err := verifyPCRs(attDoc.PCRs, expectedPCRs); err != nil {
		return err
	}

	log.Info().
		Str("module_id", attDoc.ModuleID).
		Uint64("timestamp", attDoc.Timestamp).
		Msg("Attestation verification successful")

	return nil
}

// verifyCertificateChain verifies the certificate chain against AWS Nitro root CA
func verifyCertificateChain(leafCertDER []byte, caBundle [][]byte) error {
	// Parse the AWS Nitro root CA
	rootPool := x509.NewCertPool()
	if !rootPool.AppendCertsFromPEM([]byte(awsNitroRootCAPEM)) {
		return errors.New("failed to parse AWS Nitro root CA")
	}

	// Parse the leaf certificate
	leafCert, err := x509.ParseCertificate(leafCertDER)
	if err != nil {
		return fmt.Errorf("failed to parse leaf certificate: %w", err)
	}

	// Build intermediate certificate pool from CA bundle
	intermediatePool := x509.NewCertPool()
	for i, certDER := range caBundle {
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return fmt.Errorf("failed to parse intermediate cert %d: %w", i, err)
		}
		intermediatePool.AddCert(cert)
	}

	// Verify the certificate chain
	opts := x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediatePool,
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	if _, err := leafCert.Verify(opts); err != nil {
		return fmt.Errorf("certificate chain verification failed: %w", err)
	}

	return nil
}

// verifyCOSESignature verifies the COSE_Sign1 signature
func verifyCOSESignature(coseSign1 *COSESign1, certDER []byte) error {
	// Parse the certificate to get the public key
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Get ECDSA public key (Nitro uses P-384)
	ecdsaPubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("certificate does not contain ECDSA public key")
	}

	// Build Sig_structure for verification (COSE specification)
	// Sig_structure = ["Signature1", protected, external_aad, payload]
	sigStructure := []interface{}{
		"Signature1",
		coseSign1.Protected,
		[]byte{}, // external_aad (empty for attestation)
		coseSign1.Payload,
	}

	sigStructureBytes, err := cbor.Marshal(sigStructure)
	if err != nil {
		return fmt.Errorf("failed to build Sig_structure: %w", err)
	}

	// Hash with SHA-384 (P-384 curve uses SHA-384)
	hash := sha512.Sum384(sigStructureBytes)

	// The signature is in raw R||S format, each 48 bytes for P-384
	if len(coseSign1.Signature) != 96 {
		return fmt.Errorf("invalid signature length: expected 96, got %d", len(coseSign1.Signature))
	}

	// Parse R and S from signature
	r := new(big.Int).SetBytes(coseSign1.Signature[:48])
	s := new(big.Int).SetBytes(coseSign1.Signature[48:])

	// Verify signature
	if !ecdsa.Verify(ecdsaPubKey, hash[:], r, s) {
		return errors.New("ECDSA signature verification failed")
	}

	return nil
}

// verifyPCRs compares actual PCR values against expected
func verifyPCRs(actualPCRs map[int][]byte, expectedPCRs map[int][]byte) error {
	for index, expected := range expectedPCRs {
		actual, ok := actualPCRs[index]
		if !ok {
			log.Error().Int("pcr_index", index).Msg("Missing PCR value")
			return fmt.Errorf("%w: PCR%d not present in attestation", ErrPCRMismatch, index)
		}

		if !bytes.Equal(actual, expected) {
			log.Error().
				Int("pcr_index", index).
				Str("expected", hex.EncodeToString(expected)).
				Str("actual", hex.EncodeToString(actual)).
				Msg("PCR value mismatch")
			return fmt.Errorf("%w: PCR%d mismatch", ErrPCRMismatch, index)
		}
	}

	log.Debug().
		Int("pcr_count", len(expectedPCRs)).
		Msg("All PCR values verified")

	return nil
}

// verifyMockAttestation verifies a mock attestation (development only)
// SECURITY: This should never be used in production
func verifyMockAttestation(attestation *Attestation, expectedPCRs map[int][]byte) error {
	log.Warn().Msg("SECURITY WARNING: Verifying mock attestation - development mode only")

	// Parse the mock attestation format
	docStr := string(attestation.Document)
	if !strings.HasPrefix(docStr, "MOCK_ATTESTATION:") {
		return ErrInvalidAttestation
	}

	// In development, we accept mock attestations but log a warning
	// This allows testing without actual Nitro hardware
	// SECURITY: Production builds should reject mock attestations
	if os.Getenv("VETTID_PRODUCTION") == "true" {
		return errors.New("mock attestations not allowed in production")
	}

	return nil
}

// PCRValues holds expected PCR values for verification
type PCRValues struct {
	PCR0 []byte // Enclave image hash
	PCR1 []byte // Kernel hash
	PCR2 []byte // Application hash
}

// LoadExpectedPCRs would load expected PCR values from configuration.
// Currently unused because PCR validation happens at the KMS key policy level:
// - The KMS sealing key has a policy condition requiring PCR0 to match
// - This is enforced by AWS KMS during Decrypt operations
// - The enclave doesn't verify other enclaves, so it doesn't need to load PCRs
//
// This function is preserved for reference in case future features require
// enclave-to-enclave verification or local PCR validation.
func LoadExpectedPCRs(configPath string) (*PCRValues, error) {
	// PCR values are generated during enclave build (nitro-cli build-enclave)
	// and stored in the SSM parameter /vettid/enclave/pcr0
	// The KMS key policy references this value for attestation-based decryption
	return &PCRValues{}, nil
}
