// Package migration provides enclave-to-enclave credential migration support.
//
// When enclave code is updated, PCRs change and sealed DEKs bound to old PCRs
// cannot be unsealed by new code. This package handles secure migration of
// sealed material between enclave versions.
package migration

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// PCRValues contains the PCR measurements for an enclave image.
// PCR0 = enclave image hash, PCR1 = kernel/OS hash, PCR2 = app hash
type PCRValues struct {
	PCR0 string `json:"pcr0"` // Hex-encoded PCR0 (48 bytes = 96 hex chars)
	PCR1 string `json:"pcr1"` // Hex-encoded PCR1
	PCR2 string `json:"pcr2"` // Hex-encoded PCR2
}

// Validate checks that PCR values are properly formatted
func (p *PCRValues) Validate() error {
	for i, pcr := range []struct {
		name  string
		value string
	}{
		{"PCR0", p.PCR0},
		{"PCR1", p.PCR1},
		{"PCR2", p.PCR2},
	} {
		if pcr.value == "" {
			return fmt.Errorf("%s is required", pcr.name)
		}

		// PCRs should be 48 bytes = 96 hex characters
		if len(pcr.value) != 96 {
			return fmt.Errorf("%s must be 96 hex characters, got %d", pcr.name, len(pcr.value))
		}

		// Validate hex encoding
		if _, err := hex.DecodeString(pcr.value); err != nil {
			return fmt.Errorf("%s is not valid hex: %w", pcr.name, err)
		}

		_ = i // silence unused variable warning
	}

	return nil
}

// Equals checks if two PCRValues are identical
func (p *PCRValues) Equals(other *PCRValues) bool {
	if other == nil {
		return false
	}
	return strings.EqualFold(p.PCR0, other.PCR0) &&
		strings.EqualFold(p.PCR1, other.PCR1) &&
		strings.EqualFold(p.PCR2, other.PCR2)
}

// SignedPCRConfig contains signed PCR configuration for enclave migration.
// This is fetched from AWS Secrets Manager and verified before use.
type SignedPCRConfig struct {
	// NewPCRs are the PCR values for the new enclave version
	NewPCRs PCRValues `json:"new_pcrs"`

	// OldPCRs are the PCR values for the current/old enclave version
	// Used for validation - must match the running enclave
	OldPCRs PCRValues `json:"old_pcrs"`

	// ValidFrom is when this config becomes valid (prevents replay attacks)
	ValidFrom time.Time `json:"valid_from"`

	// ExpiresAt is when this config expires (optional, zero means no expiry)
	ExpiresAt time.Time `json:"expires_at,omitempty"`

	// Version identifier for this migration (e.g., "v2.1.0")
	Version string `json:"version"`

	// Signature is the Ed25519 signature over the config (base64-encoded)
	Signature string `json:"signature"`
}

// signedPayload returns the canonical bytes to be signed/verified.
// This excludes the signature field itself.
func (c *SignedPCRConfig) signedPayload() ([]byte, error) {
	// Create a copy without the signature for canonical serialization
	payload := struct {
		NewPCRs   PCRValues `json:"new_pcrs"`
		OldPCRs   PCRValues `json:"old_pcrs"`
		ValidFrom time.Time `json:"valid_from"`
		ExpiresAt time.Time `json:"expires_at,omitempty"`
		Version   string    `json:"version"`
	}{
		NewPCRs:   c.NewPCRs,
		OldPCRs:   c.OldPCRs,
		ValidFrom: c.ValidFrom,
		ExpiresAt: c.ExpiresAt,
		Version:   c.Version,
	}

	return json.Marshal(payload)
}

// PCRConfigVerifier verifies signed PCR configurations.
type PCRConfigVerifier struct {
	// publicKey is the Ed25519 public key used to verify signatures.
	// This key is embedded at build time from CI/CD.
	publicKey ed25519.PublicKey

	// currentPCRs are the PCR values of the currently running enclave.
	// Used to validate that OldPCRs in the config match.
	currentPCRs *PCRValues
}

// NewPCRConfigVerifier creates a new verifier with the given public key and current PCRs.
//
// The publicKey should be the deployment signing key's public key, embedded at build time.
// The currentPCRs should be obtained from the enclave's attestation document.
func NewPCRConfigVerifier(publicKey ed25519.PublicKey, currentPCRs *PCRValues) (*PCRConfigVerifier, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size: expected %d, got %d", ed25519.PublicKeySize, len(publicKey))
	}

	if currentPCRs == nil {
		return nil, fmt.Errorf("currentPCRs is required")
	}

	if err := currentPCRs.Validate(); err != nil {
		return nil, fmt.Errorf("invalid currentPCRs: %w", err)
	}

	return &PCRConfigVerifier{
		publicKey:   publicKey,
		currentPCRs: currentPCRs,
	}, nil
}

// Verify validates a signed PCR configuration.
// Returns nil if the config is valid, or an error describing why it's invalid.
func (v *PCRConfigVerifier) Verify(config *SignedPCRConfig) error {
	// Validate PCR formats
	if err := config.NewPCRs.Validate(); err != nil {
		return fmt.Errorf("invalid new_pcrs: %w", err)
	}

	if err := config.OldPCRs.Validate(); err != nil {
		return fmt.Errorf("invalid old_pcrs: %w", err)
	}

	// Verify OldPCRs match the current enclave
	if !config.OldPCRs.Equals(v.currentPCRs) {
		return fmt.Errorf("old_pcrs do not match current enclave PCRs")
	}

	// Verify time window
	now := time.Now()
	if now.Before(config.ValidFrom) {
		return fmt.Errorf("config not yet valid: valid_from is %s", config.ValidFrom.Format(time.RFC3339))
	}

	if !config.ExpiresAt.IsZero() && now.After(config.ExpiresAt) {
		return fmt.Errorf("config has expired: expires_at was %s", config.ExpiresAt.Format(time.RFC3339))
	}

	// Verify signature
	if err := v.verifySignature(config); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	log.Info().
		Str("version", config.Version).
		Str("valid_from", config.ValidFrom.Format(time.RFC3339)).
		Msg("PCR config verified successfully")

	return nil
}

// verifySignature verifies the Ed25519 signature on the config.
func (v *PCRConfigVerifier) verifySignature(config *SignedPCRConfig) error {
	// Decode base64 signature
	signature, err := base64.StdEncoding.DecodeString(config.Signature)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}

	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature size: expected %d, got %d", ed25519.SignatureSize, len(signature))
	}

	// Get canonical payload bytes
	payload, err := config.signedPayload()
	if err != nil {
		return fmt.Errorf("failed to serialize payload: %w", err)
	}

	// Verify signature
	if !ed25519.Verify(v.publicKey, payload, signature) {
		return fmt.Errorf("signature does not match")
	}

	return nil
}

// ParseSignedPCRConfig parses a JSON-encoded signed PCR configuration.
func ParseSignedPCRConfig(data []byte) (*SignedPCRConfig, error) {
	var config SignedPCRConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse PCR config: %w", err)
	}
	return &config, nil
}

// SignPCRConfig signs a PCR configuration with the given private key.
// This is used by CI/CD to create signed configurations.
func SignPCRConfig(config *SignedPCRConfig, privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid private key size")
	}

	// Get canonical payload bytes
	payload, err := config.signedPayload()
	if err != nil {
		return fmt.Errorf("failed to serialize payload: %w", err)
	}

	// Sign the payload
	signature := ed25519.Sign(privateKey, payload)

	// Store as base64
	config.Signature = base64.StdEncoding.EncodeToString(signature)

	return nil
}
