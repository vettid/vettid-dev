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

	// Populated by stage 1 (attestation):
	AttestationDocument string // base64 CBOR/COSE document the vault returned
	EnclavePublicKey    []byte // X25519 pubkey extracted from the attestation
	EnclavePCR0         string // hex PCR0 the vault attested to
}

// newEnrolledUser allocates a state holder with a freshly-generated
// guid. Use the same instance through all three stages so derived
// material (UTKs, sealed credential) accumulates in one place.
func newEnrolledUser() *EnrolledUser {
	return &EnrolledUser{OwnerSpace: uuid.NewString()}
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
