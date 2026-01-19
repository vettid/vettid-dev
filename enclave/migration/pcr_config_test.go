package migration

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// Test PCR values (valid 48-byte hex strings = 96 characters)
var (
	testPCR0 = "c7b2f3d8e9a1b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5"
	testPCR1 = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8"
	testPCR2 = "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1"

	testNewPCR0 = "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111aa"
	testNewPCR1 = "2222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222bb"
	testNewPCR2 = "3333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333cc"
)

func TestPCRValues_Validate(t *testing.T) {
	tests := []struct {
		name    string
		pcrs    PCRValues
		wantErr bool
	}{
		{
			name: "valid PCRs",
			pcrs: PCRValues{
				PCR0: testPCR0,
				PCR1: testPCR1,
				PCR2: testPCR2,
			},
			wantErr: false,
		},
		{
			name: "empty PCR0",
			pcrs: PCRValues{
				PCR0: "",
				PCR1: testPCR1,
				PCR2: testPCR2,
			},
			wantErr: true,
		},
		{
			name: "invalid hex",
			pcrs: PCRValues{
				PCR0: "invalidhex!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
				PCR1: testPCR1,
				PCR2: testPCR2,
			},
			wantErr: true,
		},
		{
			name: "wrong length",
			pcrs: PCRValues{
				PCR0: "c7b2f3d8e9a1b4c5", // Too short
				PCR1: testPCR1,
				PCR2: testPCR2,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.pcrs.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPCRValues_Equals(t *testing.T) {
	pcr1 := &PCRValues{PCR0: testPCR0, PCR1: testPCR1, PCR2: testPCR2}
	pcr2 := &PCRValues{PCR0: testPCR0, PCR1: testPCR1, PCR2: testPCR2}
	pcr3 := &PCRValues{PCR0: testNewPCR0, PCR1: testNewPCR1, PCR2: testNewPCR2}

	if !pcr1.Equals(pcr2) {
		t.Error("Expected equal PCRValues to be equal")
	}

	if pcr1.Equals(pcr3) {
		t.Error("Expected different PCRValues to not be equal")
	}

	if pcr1.Equals(nil) {
		t.Error("Expected PCRValues to not equal nil")
	}
}

func TestSignedPCRConfig_SignAndVerify(t *testing.T) {
	// Generate test keypair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	currentPCRs := &PCRValues{PCR0: testPCR0, PCR1: testPCR1, PCR2: testPCR2}

	config := &SignedPCRConfig{
		NewPCRs:   PCRValues{PCR0: testNewPCR0, PCR1: testNewPCR1, PCR2: testNewPCR2},
		OldPCRs:   *currentPCRs,
		ValidFrom: time.Now().Add(-1 * time.Hour),
		Version:   "v2.0.0",
	}

	// Sign the config
	if err := SignPCRConfig(config, privateKey); err != nil {
		t.Fatalf("Failed to sign config: %v", err)
	}

	if config.Signature == "" {
		t.Error("Expected signature to be set after signing")
	}

	// Verify the config
	verifier, err := NewPCRConfigVerifier(publicKey, currentPCRs)
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}

	if err := verifier.Verify(config); err != nil {
		t.Errorf("Verification failed: %v", err)
	}
}

func TestPCRConfigVerifier_InvalidSignature(t *testing.T) {
	// Generate two different keypairs
	publicKey1, _, _ := ed25519.GenerateKey(rand.Reader)
	_, privateKey2, _ := ed25519.GenerateKey(rand.Reader)

	currentPCRs := &PCRValues{PCR0: testPCR0, PCR1: testPCR1, PCR2: testPCR2}

	config := &SignedPCRConfig{
		NewPCRs:   PCRValues{PCR0: testNewPCR0, PCR1: testNewPCR1, PCR2: testNewPCR2},
		OldPCRs:   *currentPCRs,
		ValidFrom: time.Now().Add(-1 * time.Hour),
		Version:   "v2.0.0",
	}

	// Sign with privateKey2
	SignPCRConfig(config, privateKey2)

	// Verify with publicKey1 - should fail
	verifier, _ := NewPCRConfigVerifier(publicKey1, currentPCRs)

	if err := verifier.Verify(config); err == nil {
		t.Error("Expected verification to fail with mismatched keys")
	}
}

func TestPCRConfigVerifier_OldPCRsMismatch(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)

	currentPCRs := &PCRValues{PCR0: testPCR0, PCR1: testPCR1, PCR2: testPCR2}
	differentPCRs := &PCRValues{PCR0: testNewPCR0, PCR1: testNewPCR1, PCR2: testNewPCR2}

	config := &SignedPCRConfig{
		NewPCRs:   PCRValues{PCR0: testNewPCR0, PCR1: testNewPCR1, PCR2: testNewPCR2},
		OldPCRs:   *differentPCRs, // Not matching currentPCRs
		ValidFrom: time.Now().Add(-1 * time.Hour),
		Version:   "v2.0.0",
	}

	SignPCRConfig(config, privateKey)

	verifier, _ := NewPCRConfigVerifier(publicKey, currentPCRs)

	if err := verifier.Verify(config); err == nil {
		t.Error("Expected verification to fail when old PCRs don't match current")
	}
}

func TestPCRConfigVerifier_NotYetValid(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)

	currentPCRs := &PCRValues{PCR0: testPCR0, PCR1: testPCR1, PCR2: testPCR2}

	config := &SignedPCRConfig{
		NewPCRs:   PCRValues{PCR0: testNewPCR0, PCR1: testNewPCR1, PCR2: testNewPCR2},
		OldPCRs:   *currentPCRs,
		ValidFrom: time.Now().Add(1 * time.Hour), // Future time
		Version:   "v2.0.0",
	}

	SignPCRConfig(config, privateKey)

	verifier, _ := NewPCRConfigVerifier(publicKey, currentPCRs)

	if err := verifier.Verify(config); err == nil {
		t.Error("Expected verification to fail when config is not yet valid")
	}
}

func TestPCRConfigVerifier_Expired(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)

	currentPCRs := &PCRValues{PCR0: testPCR0, PCR1: testPCR1, PCR2: testPCR2}

	config := &SignedPCRConfig{
		NewPCRs:   PCRValues{PCR0: testNewPCR0, PCR1: testNewPCR1, PCR2: testNewPCR2},
		OldPCRs:   *currentPCRs,
		ValidFrom: time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Already expired
		Version:   "v2.0.0",
	}

	SignPCRConfig(config, privateKey)

	verifier, _ := NewPCRConfigVerifier(publicKey, currentPCRs)

	if err := verifier.Verify(config); err == nil {
		t.Error("Expected verification to fail when config is expired")
	}
}

func TestParseSignedPCRConfig(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)

	currentPCRs := &PCRValues{PCR0: testPCR0, PCR1: testPCR1, PCR2: testPCR2}

	config := &SignedPCRConfig{
		NewPCRs:   PCRValues{PCR0: testNewPCR0, PCR1: testNewPCR1, PCR2: testNewPCR2},
		OldPCRs:   *currentPCRs,
		ValidFrom: time.Now().Add(-1 * time.Hour),
		Version:   "v2.0.0",
	}

	SignPCRConfig(config, privateKey)

	// Serialize to JSON
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}

	// Parse back
	parsed, err := ParseSignedPCRConfig(data)
	if err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	// Verify parsed config
	verifier, _ := NewPCRConfigVerifier(publicKey, currentPCRs)

	if err := verifier.Verify(parsed); err != nil {
		t.Errorf("Parsed config verification failed: %v", err)
	}
}

func TestNewPCRConfigVerifier_InvalidKey(t *testing.T) {
	currentPCRs := &PCRValues{PCR0: testPCR0, PCR1: testPCR1, PCR2: testPCR2}

	// Try with wrong size key
	_, err := NewPCRConfigVerifier([]byte("too short"), currentPCRs)
	if err == nil {
		t.Error("Expected error for invalid key size")
	}

	// Try with nil PCRs
	publicKey, _, _ := ed25519.GenerateKey(rand.Reader)
	_, err = NewPCRConfigVerifier(publicKey, nil)
	if err == nil {
		t.Error("Expected error for nil PCRs")
	}
}

func TestSignedPCRConfig_TamperedPayload(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)

	currentPCRs := &PCRValues{PCR0: testPCR0, PCR1: testPCR1, PCR2: testPCR2}

	config := &SignedPCRConfig{
		NewPCRs:   PCRValues{PCR0: testNewPCR0, PCR1: testNewPCR1, PCR2: testNewPCR2},
		OldPCRs:   *currentPCRs,
		ValidFrom: time.Now().Add(-1 * time.Hour),
		Version:   "v2.0.0",
	}

	SignPCRConfig(config, privateKey)

	// Tamper with the version after signing
	config.Version = "v3.0.0-tampered"

	verifier, _ := NewPCRConfigVerifier(publicKey, currentPCRs)

	if err := verifier.Verify(config); err == nil {
		t.Error("Expected verification to fail when payload is tampered")
	}
}

func TestSignature_InvalidBase64(t *testing.T) {
	publicKey, _, _ := ed25519.GenerateKey(rand.Reader)

	currentPCRs := &PCRValues{PCR0: testPCR0, PCR1: testPCR1, PCR2: testPCR2}

	config := &SignedPCRConfig{
		NewPCRs:   PCRValues{PCR0: testNewPCR0, PCR1: testNewPCR1, PCR2: testNewPCR2},
		OldPCRs:   *currentPCRs,
		ValidFrom: time.Now().Add(-1 * time.Hour),
		Version:   "v2.0.0",
		Signature: "not-valid-base64!!!",
	}

	verifier, _ := NewPCRConfigVerifier(publicKey, currentPCRs)

	if err := verifier.Verify(config); err == nil {
		t.Error("Expected verification to fail with invalid base64 signature")
	}
}

func TestSignature_WrongSize(t *testing.T) {
	publicKey, _, _ := ed25519.GenerateKey(rand.Reader)

	currentPCRs := &PCRValues{PCR0: testPCR0, PCR1: testPCR1, PCR2: testPCR2}

	// Create signature of wrong size
	wrongSizeSig := base64.StdEncoding.EncodeToString([]byte("too short"))

	config := &SignedPCRConfig{
		NewPCRs:   PCRValues{PCR0: testNewPCR0, PCR1: testNewPCR1, PCR2: testNewPCR2},
		OldPCRs:   *currentPCRs,
		ValidFrom: time.Now().Add(-1 * time.Hour),
		Version:   "v2.0.0",
		Signature: wrongSizeSig,
	}

	verifier, _ := NewPCRConfigVerifier(publicKey, currentPCRs)

	if err := verifier.Verify(config); err == nil {
		t.Error("Expected verification to fail with wrong size signature")
	}
}
