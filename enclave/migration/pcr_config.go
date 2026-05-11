// Package migration provides enclave-to-enclave credential migration support.
//
// When enclave code is updated, PCRs change and sealed DEKs bound to old PCRs
// cannot be unsealed by new code. This package handles secure migration of
// sealed material between enclave versions.
package migration

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
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

	// Version identifier for this migration (e.g., "2026-03-19-v2")
	Version string `json:"version"`

	// Summary is a human-readable description of what changed
	Summary string `json:"summary,omitempty"`

	// DetailsURL links to a page with full release notes
	DetailsURL string `json:"details_url,omitempty"`

	// PublishedAt is when this config was published
	PublishedAt time.Time `json:"published_at,omitempty"`

	// MandatoryAfter is when the update becomes required (user can't defer)
	MandatoryAfter time.Time `json:"mandatory_after,omitempty"`

	// Signature is the Ed25519 signature over the config (base64-encoded)
	Signature string `json:"signature"`
}

// signedPayload returns the canonical bytes to be signed/verified.
// This excludes the signature field itself.
//
// CRITICAL: must produce byte-for-byte the same output as the signer
// (enclave/scripts/sign-pcr-config.sh) — `jq -cS 'del(.signature)'`,
// which emits compact JSON with **alphabetically-sorted** top-level
// keys. Go's default struct marshal emits fields in declaration
// order; before this change the verifier's canonical bytes differed
// from the signer's, every signature failed verification, and
// dispatchMigrateConsent silently returned "not_requested" — every
// migration was a no-op (incident 2026-05-11).
//
// The fix uses the standard marshal-into-map-then-marshal trick:
// json.Marshal of a `map[string]json.RawMessage` emits keys in
// sorted order. PCRValues nested keys (pcr0/pcr1/pcr2) are already
// in alphabetical declaration order, so the inner objects match
// jq's recursive sort automatically. A test in
// pcr_config_signing_test.go pins this byte-for-byte against the
// jq output so a future struct reorder can't silently break it.
func (c *SignedPCRConfig) signedPayload() ([]byte, error) {
	// Build directly as a map for two reasons:
	//
	// 1. json.Marshal of map[string]interface{} sorts keys
	//    alphabetically; struct marshal emits them in declaration
	//    order. The signer uses `jq -cS` (recursive sort) so we
	//    must match.
	//
	// 2. `json:",omitempty"` on time.Time is a well-known Go
	//    gotcha — it does NOT omit zero times; the marshaler emits
	//    `"0001-01-01T00:00:00Z"`. The signer's source JSON simply
	//    has no such field for zero values, so jq doesn't see one.
	//    A struct-based approach therefore injects a phantom
	//    `expires_at` and breaks signature verification. Building
	//    the map manually with explicit IsZero() / != "" checks
	//    keeps the canonical bytes byte-for-byte aligned.
	m := map[string]interface{}{
		"new_pcrs":   c.NewPCRs,
		"old_pcrs":   c.OldPCRs,
		"valid_from": c.ValidFrom,
		"version":    c.Version,
	}
	if !c.ExpiresAt.IsZero() {
		m["expires_at"] = c.ExpiresAt
	}
	if c.Summary != "" {
		m["summary"] = c.Summary
	}
	if c.DetailsURL != "" {
		m["details_url"] = c.DetailsURL
	}
	if !c.PublishedAt.IsZero() {
		m["published_at"] = c.PublishedAt
	}
	if !c.MandatoryAfter.IsZero() {
		m["mandatory_after"] = c.MandatoryAfter
	}
	return json.Marshal(m)
}

// PCRConfigVerifier verifies signed PCR configurations.
// Supports both ECDSA P-256 (KMS) and Ed25519 (legacy) signatures.
type PCRConfigVerifier struct {
	// ecdsaKey is the ECDSA P-256 public key (from KMS) — preferred
	ecdsaKey *ecdsa.PublicKey

	// ed25519Key is the legacy Ed25519 public key — fallback
	ed25519Key ed25519.PublicKey

	// currentPCRs are the PCR values of the currently running enclave.
	currentPCRs *PCRValues
}

// NewPCRConfigVerifier creates a new verifier with the given public key and current PCRs.
// The publicKey can be either an ECDSA P-256 DER/PEM key or an Ed25519 raw key.
func NewPCRConfigVerifier(publicKey []byte, currentPCRs *PCRValues) (*PCRConfigVerifier, error) {
	if currentPCRs == nil {
		return nil, fmt.Errorf("currentPCRs is required")
	}

	if err := currentPCRs.Validate(); err != nil {
		return nil, fmt.Errorf("invalid currentPCRs: %w", err)
	}

	v := &PCRConfigVerifier{currentPCRs: currentPCRs}

	// Try parsing as DER-encoded ECDSA public key first
	if parsed, err := x509.ParsePKIXPublicKey(publicKey); err == nil {
		if ecKey, ok := parsed.(*ecdsa.PublicKey); ok {
			v.ecdsaKey = ecKey
			return v, nil
		}
	}

	// Try parsing as PEM-encoded key
	if block, _ := pem.Decode(publicKey); block != nil {
		if parsed, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
			if ecKey, ok := parsed.(*ecdsa.PublicKey); ok {
				v.ecdsaKey = ecKey
				return v, nil
			}
		}
	}

	// Fallback: treat as raw Ed25519 public key
	if len(publicKey) == ed25519.PublicKeySize {
		v.ed25519Key = publicKey
		return v, nil
	}

	return nil, fmt.Errorf("unsupported public key format (expected ECDSA P-256 or Ed25519, got %d bytes)", len(publicKey))
}

// NewSignatureOnlyVerifier builds a verifier that skips the OldPCRs
// match. Use this when the caller doesn't have access to the running
// enclave's PCR values (e.g. inside vault-manager, which doesn't talk
// to NSM directly). The signature + time-window checks alone are
// enough to reject the F1 attack — an attacker who can write the
// config but doesn't hold the KMS signing key cannot forge a passing
// signature.
//
// Callers that DO have access to the running PCRs should still prefer
// `Verify` for full defense-in-depth.
func NewSignatureOnlyVerifier(publicKey []byte) (*PCRConfigVerifier, error) {
	v := &PCRConfigVerifier{}
	if parsed, err := x509.ParsePKIXPublicKey(publicKey); err == nil {
		if ecKey, ok := parsed.(*ecdsa.PublicKey); ok {
			v.ecdsaKey = ecKey
			return v, nil
		}
	}
	if block, _ := pem.Decode(publicKey); block != nil {
		if parsed, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
			if ecKey, ok := parsed.(*ecdsa.PublicKey); ok {
				v.ecdsaKey = ecKey
				return v, nil
			}
		}
	}
	if len(publicKey) == ed25519.PublicKeySize {
		v.ed25519Key = publicKey
		return v, nil
	}
	return nil, fmt.Errorf("unsupported public key format (expected ECDSA P-256 or Ed25519, got %d bytes)", len(publicKey))
}

// VerifySignatureAndTime runs every check Verify does EXCEPT the
// OldPCRs equality check. See NewSignatureOnlyVerifier for context.
func (v *PCRConfigVerifier) VerifySignatureAndTime(config *SignedPCRConfig) error {
	if err := config.NewPCRs.Validate(); err != nil {
		return fmt.Errorf("invalid new_pcrs: %w", err)
	}
	if err := config.OldPCRs.Validate(); err != nil {
		return fmt.Errorf("invalid old_pcrs: %w", err)
	}
	now := time.Now()
	if now.Before(config.ValidFrom) {
		return fmt.Errorf("config not yet valid: valid_from is %s", config.ValidFrom.Format(time.RFC3339))
	}
	if !config.ExpiresAt.IsZero() && now.After(config.ExpiresAt) {
		return fmt.Errorf("config has expired: expires_at was %s", config.ExpiresAt.Format(time.RFC3339))
	}
	if err := v.verifySignature(config); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	log.Info().
		Str("version", config.Version).
		Str("valid_from", config.ValidFrom.Format(time.RFC3339)).
		Msg("PCR config signature + time-window verified")
	return nil
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

// verifySignature verifies the signature on the config.
// Supports ECDSA P-256 (KMS) and Ed25519 (legacy).
func (v *PCRConfigVerifier) verifySignature(config *SignedPCRConfig) error {
	// Decode base64 signature
	signature, err := base64.StdEncoding.DecodeString(config.Signature)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}

	// Get canonical payload bytes
	payload, err := config.signedPayload()
	if err != nil {
		return fmt.Errorf("failed to serialize payload: %w", err)
	}

	// ECDSA P-256 verification (KMS)
	if v.ecdsaKey != nil {
		hash := sha256.Sum256(payload)
		// KMS returns DER-encoded ECDSA signature — parse r and s
		if !ecdsa.VerifyASN1(v.ecdsaKey, hash[:], signature) {
			// Try raw r||s format as fallback
			if len(signature) == 64 {
				r := new(big.Int).SetBytes(signature[:32])
				s := new(big.Int).SetBytes(signature[32:])
				if !ecdsa.Verify(v.ecdsaKey, hash[:], r, s) {
					return fmt.Errorf("ECDSA signature does not match")
				}
			} else {
				return fmt.Errorf("ECDSA signature does not match")
			}
		}
		return nil
	}

	// Ed25519 verification (legacy)
	if v.ed25519Key != nil {
		if len(signature) != ed25519.SignatureSize {
			return fmt.Errorf("invalid Ed25519 signature size: expected %d, got %d", ed25519.SignatureSize, len(signature))
		}
		if !ed25519.Verify(v.ed25519Key, payload, signature) {
			return fmt.Errorf("Ed25519 signature does not match")
		}
		return nil
	}

	return fmt.Errorf("no public key configured for verification")
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
