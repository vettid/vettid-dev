package main

// Enrollment driver — mimics the Android app's three-stage flow:
//
//   1. Attestation request: send a nonce, get back an attestation
//      document. Use the document's PCR0 to confirm which enclave
//      answered + extract its X25519 public key for stage 2.
//   2. PIN setup: ECIES-encrypt the PIN to the attested enclave
//      pubkey, send `pin.setup`. Vault returns a pool of UTKs (User
//      Transaction Keys) the requester uses to encrypt the password
//      hash in stage 3.
//   3. Credential create: Argon2id-hash the password, UTK-encrypt the
//      hash to a chosen UTK, send `credential.create`. Vault returns
//      the sealed credential blob the app would normally persist.
//
// Stages are built up across separate commits so each one can be
// validated against the live stack before the next layers on top.
// This file currently implements stage 1.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
)

// EnrolledUser collects the state a happy-path scenario derives over
// its three stages and threads through subsequent assertions
// (migration publish, pin-unlock, marker check, etc.).
type EnrolledUser struct {
	OwnerSpace string // the user's guid (driver-generated)
	PIN        string // 4-8 digits — chosen at PIN setup
	Password   string // arbitrary string — chosen at credential create

	// Populated by stage 1 (attestation):
	AttestationDocument string // base64 CBOR/COSE document the vault returned
	EnclavePublicKey    []byte // X25519 pubkey extracted from the attestation
	EnclavePCR0         string // hex PCR0 the vault attested to

	// Populated by stage 2 (pin.setup):
	UTKs []UTKInfo // user transaction keys the vault returns for stage 3
}

// UTKInfo is one entry in the UTK pool returned by pin.setup. The
// driver picks one of these to encrypt the password hash in stage 3.
// Mirrors vault-manager/credential_types.go's UTKPublic — two fields,
// no algorithm tag (it's always X25519 in this codebase).
type UTKInfo struct {
	ID        string `json:"id"`
	PublicKey string `json:"public_key"` // base64 X25519 pub
}

// newEnrolledUser allocates a state holder with a freshly-generated
// guid + sensible default PIN/password for tests. Scenarios can
// override PIN/Password before driving the stages.
func newEnrolledUser() *EnrolledUser {
	return &EnrolledUser{
		OwnerSpace: uuid.NewString(),
		PIN:        "1234",
		Password:   "harness-password-7d4a9c",
	}
}

// requestAttestation drives stage 1. The driver picks a 32-byte
// nonce, sends it through publishAndAwait, and parses the vault's
// JSON response into the EnrolledUser fields. Returns an error if
// the round-trip fails or the response payload is malformed.
//
// Response shape from the vault's formatEnclaveResponse:
//   {
//     "type": "attestation_response",
//     "event_id": "<echoed>",
//     "timestamp": "...",
//     "attestation": {
//        "document":   "<base64 CBOR/COSE>",
//        "public_key": "<base64 X25519 pubkey>"
//     },
//     "module_id": "...",
//     ...
//   }
//
// Field names follow the parent's formatAttestationResponseEnvelope.
func (u *EnrolledUser) requestAttestation(ctx context.Context, h *Harness) error {
	nonce, err := generateRandomBytes(32)
	if err != nil {
		return fmt.Errorf("nonce: %w", err)
	}
	reqPayload := map[string]string{
		"nonce": base64.StdEncoding.EncodeToString(nonce),
	}

	respBytes, err := h.publishAndAwait(ctx, u.OwnerSpace, "attestation", reqPayload)
	if err != nil {
		return fmt.Errorf("publish attestation: %w", err)
	}

	// Response shape from the parent's formatEnclaveResponse:
	//   { "attestation":   "<base64 attestation document or MOCK_ATTESTATION:... string in dev>",
	//     "public_key":    "<base64 X25519 enclave pubkey>",
	//     "event_id":      "<echoed>",
	//     "timestamp":     "..." }
	var resp struct {
		Attestation string `json:"attestation"`
		PublicKey   string `json:"public_key"`
		EventID     string `json:"event_id"`
		Error       string `json:"error"`
	}
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		return fmt.Errorf("unmarshal attestation response: %w\n  raw=%s", err, string(respBytes))
	}
	if resp.Error != "" {
		return fmt.Errorf("vault returned error: %s", resp.Error)
	}
	if resp.Attestation == "" || resp.PublicKey == "" {
		return fmt.Errorf("attestation response missing attestation/public_key — raw=%s", string(respBytes))
	}

	pub, err := base64.StdEncoding.DecodeString(resp.PublicKey)
	if err != nil {
		return fmt.Errorf("decode enclave pub: %w", err)
	}
	if len(pub) != keySize {
		return fmt.Errorf("enclave pub wrong length: got %d, want %d", len(pub), keySize)
	}

	u.AttestationDocument = resp.Attestation
	u.EnclavePublicKey = pub
	// PCR0 is inside the CBOR document; we don't parse it here —
	// scenarios that need it for migration assertions can pull it
	// from the FAKE_PCR0_HEX env-baked container values directly.
	return nil
}

// setupPIN drives stage 2. The PIN payload is JSON of the form
// {"pin": "1234"}, ECIES-encrypted to the attested enclave pubkey,
// then sent split into three base64 fields (encrypted_pin,
// ephemeral_public_key, nonce) the way the vault's
// decryptMobileFormat expects.
//
// Response shape (best-effort discovery — adjust as needed when the
// first run produces the actual JSON):
//
//	{ "type": "...response",
//	  "event_id": "...",
//	  "utks":     [{"key_id": "...", "public_key": "...", "algorithm": "X25519"}, ...],
//	  ... }
func (u *EnrolledUser) setupPIN(ctx context.Context, h *Harness) error {
	if len(u.EnclavePublicKey) != keySize {
		return fmt.Errorf("setupPIN: enclave pubkey not set (run requestAttestation first)")
	}

	// Inner JSON the vault decrypts and unmarshals into PINSetupPayload.
	innerJSON, err := json.Marshal(map[string]any{
		"pin": u.PIN,
	})
	if err != nil {
		return fmt.Errorf("marshal pin payload: %w", err)
	}
	encB64, ephPubB64, nonceB64, err := pinECIESEncrypt(u.EnclavePublicKey, innerJSON)
	if err != nil {
		return fmt.Errorf("encrypt pin: %w", err)
	}

	// Inner payload the vault unmarshals into PINSetupPayload — the
	// three b64 fields only. The disambiguating `type: pin.setup` lives
	// on the *envelope* (envType arg below) because the vault's central
	// unwrapPayload promotes the envelope `type` to msg.PayloadType,
	// which is what handlePinOperation switches on.
	reqPayload := map[string]any{
		"encrypted_pin":        encB64,
		"ephemeral_public_key": ephPubB64,
		"nonce":                nonceB64,
	}

	respBytes, err := h.publishWithType(
		ctx, u.OwnerSpace,
		"pin",       // forVault subject suffix
		"pin",       // forApp response suffix
		"pin.setup", // envelope `type` — drives PIN dispatcher
		reqPayload,
	)
	if err != nil {
		return fmt.Errorf("publish pin.setup: %w", err)
	}

	var resp struct {
		Type    string    `json:"type"`
		EventID string    `json:"event_id"`
		UTKs    []UTKInfo `json:"utks"`
		Error   string    `json:"error"`
	}
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		return fmt.Errorf("unmarshal pin.setup response: %w\n  raw=%s", err, string(respBytes))
	}
	if resp.Error != "" {
		return fmt.Errorf("vault returned error: %s", resp.Error)
	}
	if len(resp.UTKs) == 0 {
		return fmt.Errorf("pin.setup response has no UTKs — raw=%s", string(respBytes))
	}

	u.UTKs = resp.UTKs
	return nil
}
