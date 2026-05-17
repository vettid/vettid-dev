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
	UTKs        []UTKInfo // user transaction keys the vault returns for stage 3
	ECIESPubKey []byte    // PIN-unlock ECIES recipient pubkey (decoded from b64)

	// Populated by stage 3 (credential.create):
	EncryptedCredential string    // CEK-encrypted Protean Credential blob (base64)
	NewUTKs             []UTKInfo // refreshed UTK pool the app would persist
	PasswordHashPHC     string    // PHC string the vault now stores (debug/migration assertions)
	PasswordSalt        []byte    // salt used in the PHC (kept so happy-path can re-hash on unlock)

	// Populated after pin.unlock — handy for assertions in the
	// migration scenario. MigrationStatus values are documented on
	// PINUnlockResponse in vault-manager/credential_types.go.
	LastUnlockStatus     string // "unlocked" on success
	LastMigrationStatus  string // "" / "completed" / "pending_new_enclave" / "not_requested" / "failed"
	LastMigrationVersion string // version field from the matched migration config
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
		Type           string    `json:"type"`
		EventID        string    `json:"event_id"`
		UTKs           []UTKInfo `json:"utks"`
		ECIESPublicKey string    `json:"ecies_public_key"`
		Error          string    `json:"error"`
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
	if resp.ECIESPublicKey != "" {
		pub, err := base64.StdEncoding.DecodeString(resp.ECIESPublicKey)
		if err != nil {
			return fmt.Errorf("decode ECIES pub: %w", err)
		}
		if len(pub) != keySize {
			return fmt.Errorf("ECIES pub wrong length: got %d, want %d", len(pub), keySize)
		}
		u.ECIESPubKey = pub
	}
	return nil
}

// unlockPIN drives the PIN-unlock path that fires migrate_consent
// handling when the vault sees a published migration config. The
// payload format matches pin.setup (ECIES-encrypted PIN), but
// crucially uses the *ECIESPublicKey* the vault returned from
// pin.setup — NOT the attestation pubkey. That key is what vault-side
// state.eciesPrivateKey corresponds to; using the attestation key
// here MAC-fails at decryptWithECIES.
//
// If consent=true, vault sees migrate_consent on the request and (if
// a migration config is published + applicable) reseals carve-outs or
// emits a routing handoff to the new enclave.
func (u *EnrolledUser) unlockPIN(ctx context.Context, h *Harness, consent bool) error {
	if u.ECIESPubKey == nil {
		return fmt.Errorf("unlockPIN: no ECIES pub captured (run setupPIN first)")
	}
	if len(u.UTKs) == 0 {
		return fmt.Errorf("unlockPIN: no UTKs (run setupPIN first)")
	}

	innerJSON, err := json.Marshal(map[string]any{"pin": u.PIN})
	if err != nil {
		return fmt.Errorf("marshal pin payload: %w", err)
	}
	encB64, ephPubB64, nonceB64, err := pinECIESEncrypt(u.ECIESPubKey, innerJSON)
	if err != nil {
		return fmt.Errorf("encrypt pin: %w", err)
	}

	// pin.unlock payload mirrors PINUnlockRequest in
	// vault-manager/credential_types.go: utk_id + encrypted_payload
	// (single combined b64 = ephemeral_pub || nonce || ciphertext) +
	// optional migrate_consent + optional encrypted_credential.
	combined := make([]byte, 0, 32+12+len(encB64))
	rawCT, err := base64.StdEncoding.DecodeString(encB64)
	if err != nil {
		return fmt.Errorf("decode encB64: %w", err)
	}
	rawEphPub, err := base64.StdEncoding.DecodeString(ephPubB64)
	if err != nil {
		return fmt.Errorf("decode ephPubB64: %w", err)
	}
	rawNonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return fmt.Errorf("decode nonceB64: %w", err)
	}
	combined = append(combined, rawEphPub...)
	combined = append(combined, rawNonce...)
	combined = append(combined, rawCT...)
	encryptedPayloadB64 := base64.StdEncoding.EncodeToString(combined)

	reqPayload := map[string]any{
		"utk_id":            u.UTKs[0].ID,
		"encrypted_payload": encryptedPayloadB64,
	}
	if consent {
		reqPayload["migrate_consent"] = true
	}
	if u.EncryptedCredential != "" {
		// Optional self-heal aid — vault uses this to restore
		// credential carve-outs on warm unlock when storage doesn't
		// have the sealed blob (Tier-2 supervisors don't share state).
		reqPayload["encrypted_credential"] = u.EncryptedCredential
	}

	respBytes, err := h.publishWithType(
		ctx, u.OwnerSpace,
		"pin",        // subject suffix (same as setup)
		"pin",        // response suffix
		"pin.unlock", // envelope type — distinguishes from setup/change
		reqPayload,
	)
	if err != nil {
		return fmt.Errorf("publish pin.unlock: %w", err)
	}
	// new_utks comes back as the legacy EncodeUTKs format
	// ("utk-id:base64pub") — vault-manager's PIN unlock path uses the
	// older wire encoding here, distinct from PINSetupResponse's
	// structured UTKPublic. The driver doesn't *use* these for
	// anything yet, so the slice-of-strings shape is enough.
	//
	// migration_status values (see PINUnlockResponse docs):
	//   "completed"            - re-seal landed on this enclave.
	//   "pending_new_enclave"  - landed on OLD; handoff emitted.
	//   "failed"               - re-seal errored (unlock still ok).
	//   "not_requested"        - consent=false or no config published.
	//   "" (omitted)           - no migration in flight at all.
	var resp struct {
		Status           string   `json:"status"`
		MigrationStatus  string   `json:"migration_status"`
		MigrationVersion string   `json:"migration_version"`
		NewUTKs          []string `json:"new_utks"`
		Error            string   `json:"error"`
	}
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		return fmt.Errorf("unmarshal pin.unlock response: %w\n  raw=%s", err, string(respBytes))
	}
	if resp.Error != "" {
		return fmt.Errorf("vault returned error: %s", resp.Error)
	}
	u.LastUnlockStatus = resp.Status
	u.LastMigrationStatus = resp.MigrationStatus
	u.LastMigrationVersion = resp.MigrationVersion
	return nil
}

// createCredential drives stage 3. Picks the first UTK from the pool,
// argon2id-hashes the password into a PHC string, UTK-encrypts that
// PHC, and sends `credential.create`. The vault returns the
// CEK-encrypted Protean Credential blob (the same opaque blob the app
// re-presents on every subsequent unlock) plus a fresh UTK pool.
func (u *EnrolledUser) createCredential(ctx context.Context, h *Harness) error {
	if len(u.UTKs) == 0 {
		return fmt.Errorf("createCredential: no UTKs (run setupPIN first)")
	}
	utk := u.UTKs[0]
	utkPub, err := base64.StdEncoding.DecodeString(utk.PublicKey)
	if err != nil {
		return fmt.Errorf("decode UTK pub: %w", err)
	}

	// PHC string with a fresh 16-byte salt. Stash both so a later
	// pin.unlock scenario can rebuild the same hash deterministically.
	salt, err := generateRandomBytes(16)
	if err != nil {
		return fmt.Errorf("password salt: %w", err)
	}
	phc := argon2idPHC([]byte(u.Password), salt)
	u.PasswordHashPHC = phc
	u.PasswordSalt = salt

	innerJSON, err := json.Marshal(map[string]any{
		"password_hash": phc,
	})
	if err != nil {
		return fmt.Errorf("marshal credential payload: %w", err)
	}

	ct, err := utkEncrypt(utkPub, innerJSON)
	if err != nil {
		return fmt.Errorf("UTK encrypt: %w", err)
	}

	reqPayload := map[string]any{
		"utk_id":            utk.ID,
		"encrypted_payload": base64.StdEncoding.EncodeToString(ct),
	}

	// Subject suffix and envelope `type` both match
	// "credential.create" — the dispatcher routes on the subject path
	// (parts after .forVault.), not on payload type. Keep publishCore
	// happy by setting envType identically.
	respBytes, err := h.publishWithType(
		ctx, u.OwnerSpace,
		"credential.create",
		"credential.create",
		"credential.create",
		reqPayload,
	)
	if err != nil {
		return fmt.Errorf("publish credential.create: %w", err)
	}

	var resp struct {
		Status              string    `json:"status"`
		EncryptedCredential string    `json:"encrypted_credential"`
		NewUTKs             []UTKInfo `json:"new_utks"`
		Error               string    `json:"error"`
	}
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		return fmt.Errorf("unmarshal credential.create response: %w\n  raw=%s", err, string(respBytes))
	}
	if resp.Error != "" {
		return fmt.Errorf("vault returned error: %s", resp.Error)
	}
	if resp.EncryptedCredential == "" {
		return fmt.Errorf("credential.create response has no encrypted_credential — raw=%s", string(respBytes))
	}

	u.EncryptedCredential = resp.EncryptedCredential
	u.NewUTKs = resp.NewUTKs
	return nil
}
