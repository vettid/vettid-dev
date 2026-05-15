package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
)

// ProteanCredentialHandler handles Protean Credential creation (Phase 3 of enrollment)
// This is separate from CredentialHandler which handles storage/sync operations
type ProteanCredentialHandler struct {
	ownerSpace string
	state      *VaultState
	bootstrap  *BootstrapHandler
	storage    *EncryptedStorage // for identity_public_key fallback (set via SetStorage)
}

// SetStorage wires the encrypted storage so HandleCredentialCreate can
// persist the identity public key as a fallback for BuildPublishedProfile
// when vaultState.identityPublicKey is empty (multi-instance migration
// window). Wired post-construction because messages.go creates this
// handler before storage is available in some paths.
func (h *ProteanCredentialHandler) SetStorage(s *EncryptedStorage) {
	h.storage = s
}

// decryptCredentialBlob decrypts a CEK-encrypted credential blob the
// caller supplied and returns the V2 plaintext. Mirrors the helper on
// CredentialSecretHandler — the two handlers share the CEK on
// vaultState but each carries its own decrypt entry point so neither
// has to import the other.
func (h *ProteanCredentialHandler) decryptCredentialBlob(encryptedBase64 string) (*ProteanCredentialV2, error) {
	encryptedBytes, err := base64.StdEncoding.DecodeString(encryptedBase64)
	if err != nil {
		return nil, fmt.Errorf("invalid credential encoding: %w", err)
	}
	h.state.mu.RLock()
	cekPair := h.state.cekPair
	h.state.mu.RUnlock()
	if cekPair == nil {
		return nil, fmt.Errorf("CEK not available")
	}
	plaintext, err := decryptWithCEK(cekPair.PrivateKey, encryptedBytes)
	if err != nil {
		return nil, fmt.Errorf("CEK decryption failed: %w", err)
	}
	defer zeroBytes(plaintext)

	var cred ProteanCredentialV2
	if err := json.Unmarshal(plaintext, &cred); err != nil {
		return nil, fmt.Errorf("failed to parse credential: %w", err)
	}
	if cred.FormatVersion < 2 {
		return nil, fmt.Errorf("unsupported credential format version: %d (need 2)", cred.FormatVersion)
	}
	return &cred, nil
}

// NewProteanCredentialHandler creates a new Protean Credential handler
func NewProteanCredentialHandler(ownerSpace string, state *VaultState, bootstrap *BootstrapHandler) *ProteanCredentialHandler {
	return &ProteanCredentialHandler{
		ownerSpace: ownerSpace,
		state:      state,
		bootstrap:  bootstrap,
	}
}

// HandleCredentialCreate processes credential creation requests (Phase 3 of enrollment)
// Prerequisites: PIN setup must be complete (DEK and CEK available in state)
//
// Flow:
// 1. Verify vault is ready (DEK exists from PIN setup)
// 2. Decrypt password hash using UTK
// 3. Generate Ed25519 identity keypair
// 4. Generate vault master secret
// 5. Create UnsealedCredential with password hash
// 6. Encrypt credential with CEK for app storage
// 7. Store credential in vault state (encrypted with DEK for persistence)
// 8. Return encrypted credential + new UTKs
//
// SECURITY: The password hash is for operation authorization (different from PIN for vault unlock)
func (h *ProteanCredentialHandler) HandleCredentialCreate(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	log.Info().Str("owner_space", h.ownerSpace).Msg("Credential creation requested (Phase 3)")

	// Parse request
	var req CredentialCreateRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleCredentialCreate"); err != nil {
		return h.errorResponse(msg.GetID(), "invalid request format")
	}

	// Validate UTK
	ltk, found := h.bootstrap.GetLTKForUTK(req.UTKID)
	if !found {
		return h.errorResponse(msg.GetID(), "invalid or expired UTK")
	}

	// Check vault is ready (DEK must exist from PIN setup)
	h.state.mu.RLock()
	dek := h.state.dek
	cekPair := h.state.cekPair
	hasIdentityKey := len(h.state.identityPublicKey) > 0
	h.state.mu.RUnlock()

	if dek == nil {
		log.Error().Str("owner_space", h.ownerSpace).Msg("DEK not found - PIN setup must complete first")
		return h.errorResponse(msg.GetID(), "vault not ready - complete PIN setup first")
	}

	if cekPair == nil {
		log.Error().Str("owner_space", h.ownerSpace).Msg("CEK not found - PIN setup must complete first")
		return h.errorResponse(msg.GetID(), "vault not initialized - complete PIN setup first")
	}

	// Phase D: detect "credential already exists" via the identity-
	// public-key carve-out (set at PIN unlock + credential creation)
	// rather than the full credential plaintext.
	if hasIdentityKey {
		log.Warn().Str("owner_space", h.ownerSpace).Msg("Credential already exists")
		return h.errorResponse(msg.GetID(), "credential already exists")
	}

	// Decode and decrypt payload using UTK's corresponding LTK
	encryptedPayload, err := base64.StdEncoding.DecodeString(req.EncryptedPayload)
	if err != nil {
		return h.errorResponse(msg.GetID(), "invalid payload encoding")
	}

	// Decrypt using XChaCha20-Poly1305 with UTK domain separation
	payloadBytes, err := decryptWithUTK(ltk, encryptedPayload)
	if err != nil {
		log.Error().Err(err).Msg("Failed to decrypt credential payload")
		return h.errorResponse(msg.GetID(), "decryption failed")
	}
	defer zeroBytes(payloadBytes) // SECURITY: Clear plaintext after use

	// Parse decrypted payload
	var payload CredentialCreatePayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return h.errorResponse(msg.GetID(), "invalid payload format")
	}

	// Validate PHC string format and minimum security requirements
	if payload.PasswordHash == "" {
		return h.errorResponse(msg.GetID(), "password_hash is required")
	}

	if err := validatePHCString(payload.PasswordHash); err != nil {
		log.Error().Err(err).Msg("Invalid PHC string format")
		return h.errorResponse(msg.GetID(), "invalid password hash format")
	}

	// Mark UTK as used (single-use for security)
	h.bootstrap.MarkUTKUsed(req.UTKID)

	// Generate Ed25519 identity keypair
	identityPrivateKey, identityPublicKey, err := generateIdentityKeypair()
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate identity keypair")
		return h.errorResponse(msg.GetID(), "key generation failed")
	}

	// Generate vault master secret (for future key derivation)
	masterSecret, err := generateMasterSecret()
	if err != nil {
		zeroBytes(identityPrivateKey)
		log.Error().Err(err).Msg("Failed to generate master secret")
		return h.errorResponse(msg.GetID(), "secret generation failed")
	}

	// Mint the credential directly in V2 format. Pull whatever PIN
	// auth hash/salt the PIN setup phase left on vaultState carve-outs
	// so the on-disk credential blob is the durable backup of the PIN
	// verifier alongside the password PHC.
	now := time.Now()
	h.state.mu.RLock()
	pinHash := append([]byte(nil), h.state.pinAuthHash...)
	pinSalt := append([]byte(nil), h.state.pinAuthSalt...)
	h.state.mu.RUnlock()

	credential := &ProteanCredentialV2{
		FormatVersion:  2,
		Identity:       CredentialIdentity{PrivateKey: identityPrivateKey, PublicKey: identityPublicKey},
		MasterSecret:   masterSecret,
		Auth:           CredentialAuth{Type: "password", Hash: payload.PasswordHash, PinHash: pinHash, PinSalt: pinSalt},
		CryptoMetadata: DefaultCryptoMetadata(),
		Binding:        &CredentialBinding{VaultID: h.ownerSpace, BoundAt: now.Unix()},
		CryptoKeys:     []CryptoKeyV2{},
		Timestamps:     CredentialTimestamps{CreatedAt: now.Unix(), LastModified: now.Unix(), AuthChangedAt: now.Unix()},
		Version:        1,
	}

	// Phase D: populate the narrow carve-outs.
	// Phase E: also start the identity-key TTL window — the user just
	// authenticated to create the credential.
	h.state.mu.Lock()
	h.state.identityPrivateKey = append([]byte(nil), credential.Identity.PrivateKey...)
	h.state.identityPublicKey = append([]byte(nil), credential.Identity.PublicKey...)
	h.state.identityKeyExpiresAt = now.Unix() + 300
	// Derive the audit-signing subkey here too, not only at PIN unlock.
	// Without this, the audit events written during the rest of
	// enrollment (and the first session before any lock/unlock cycle)
	// are unsigned — the client then shows an alarming "chain unsigned"
	// pill for what are really just the first legitimate rows. See
	// audit_key.go; mirrors restoreCredentialCarveOuts in pin_handler.go.
	var auditPubForPersist, auditSigForPersist []byte
	if auditPriv, auditPub, derr := deriveAuditKey(credential.Identity.PrivateKey); derr == nil {
		h.state.auditPrivateKey = append([]byte(nil), auditPriv...)
		h.state.auditPublicKey = append([]byte(nil), auditPub...)
		h.state.auditBindingSignature = computeAuditBindingSignature(
			ed25519.PrivateKey(credential.Identity.PrivateKey),
			auditPub,
		)
		h.state.auditBindingEmitted = false
		auditPubForPersist = append([]byte(nil), h.state.auditPublicKey...)
		auditSigForPersist = append([]byte(nil), h.state.auditBindingSignature...)
	} else {
		log.Warn().Err(derr).Str("owner_space", h.ownerSpace).
			Msg("audit key derivation failed at credential.create; audit chain unsigned until next PIN unlock")
	}
	h.state.mu.Unlock()

	// Persist the (public) audit anchor so audit.query can serve a
	// verifiable anchor even after vault state cycles. Outside the
	// lock — it does storage I/O.
	persistAuditAnchor(h.storage, h.ownerSpace, auditPubForPersist, auditSigForPersist)

	// Persist the identity public key to vault storage too. Used as a
	// fallback by BuildPublishedProfile when vaultState.identityPublicKey
	// is empty — which can happen when profile.publish lands on an
	// enclave instance that hasn't loaded the user's vault state for
	// this session (multi-instance ASG during a migration window). Without
	// this, the broadcast cache on peers ends up with no public_key and
	// the connection-detail screen on the peer side can't render the
	// identity key. Public material; no encryption needed beyond the
	// at-rest DEK already covering the SQLite store.
	if h.storage != nil {
		// Write the base64-encoded form so BuildPublishedProfile's
		// fallback (which reads via `string(pkData)`) returns a
		// proper base64 string. Writing raw bytes here would
		// silently corrupt the broadcast: the fallback would
		// interpret raw bytes as UTF-8, producing garbled
		// characters on the peer's connection-detail view
		// (observed 2026-05-10 testing).
		pkB64 := base64.StdEncoding.EncodeToString(credential.Identity.PublicKey)
		if err := h.storage.Put("identity_public_key", []byte(pkB64)); err != nil {
			log.Warn().Err(err).Str("owner_space", h.ownerSpace).Msg("Failed to persist identity_public_key for storage fallback (non-fatal)")
		}
	}

	// Serialize credential for encryption
	credentialBytes, err := json.Marshal(credential)
	if err != nil {
		log.Error().Err(err).Msg("Failed to serialize credential")
		return h.errorResponse(msg.GetID(), "serialization failed")
	}
	defer zeroBytes(credentialBytes) // SECURITY: Clear after encryption

	// Encrypt credential with CEK (ECIES) for app storage
	// The app will store this and use it for credential operations
	encryptedCredential, err := encryptWithCEK(cekPair.PublicKey, credentialBytes)
	if err != nil {
		log.Error().Err(err).Msg("Failed to encrypt credential with CEK")
		return h.errorResponse(msg.GetID(), "encryption failed")
	}

	// Phase D persistence: store the sealed credential blob in vault
	// storage so cold-unlock's restoreCredentialCarveOuts can rebuild
	// the narrow carve-outs (identity keys + PIN verifier) on a fresh
	// enclave after migration. Previously this only happened when a
	// critical secret was added/refreshed — users who never touched a
	// critical secret had no blob, so the post-migration cold-unlock
	// left identityPublicKey empty and audit.query returned an empty
	// identity_pub → the client showed a spurious "chain unsigned"
	// pill. The stored form is base64 to match the read path in
	// restoreCredentialCarveOuts (and the writes in
	// credential_secret_handler.encryptCredentialBlob → Put).
	encryptedCredentialB64 := base64.StdEncoding.EncodeToString(encryptedCredential)
	if h.storage != nil {
		if err := h.storage.Put("credential/sealed_blob", []byte(encryptedCredentialB64)); err != nil {
			log.Warn().Err(err).Str("owner_space", h.ownerSpace).Msg("Failed to persist credential/sealed_blob at credential.create (non-fatal)")
		}
	}

	// NOTE: DEK is NOT cleared here - it's needed for vault state persistence
	// The caller (messages.go) will clear DEK after persisting vault state for cold recovery

	// Generate fresh UTKs for future operations and return ONLY the new ones.
	newPairs, err := h.bootstrap.GenerateMoreUTKs(5)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to generate new UTKs")
	}
	utkPublics := EncodeUTKPublics(newPairs)

	response := CredentialCreateResponse{
		Status:              "created",
		EncryptedCredential: base64.StdEncoding.EncodeToString(encryptedCredential),
		NewUTKs:             utkPublics,
	}

	responseBytes, err := json.Marshal(response)
	if err != nil {
		return h.errorResponse(msg.GetID(), "response serialization failed")
	}

	log.Info().
		Str("owner_space", h.ownerSpace).
		Int("utk_count", len(utkPublics)).
		Int("credential_version", credential.Version).
		Str("identity_public_key", base64.StdEncoding.EncodeToString(identityPublicKey)[:16]+"...").
		Msg("Protean Credential created successfully (Phase 3 complete)")

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   responseBytes,
	}, nil
}

// HandlePasswordChange processes credential password change requests
// Flow:
// 1. Decrypt payload containing old and new password hashes using UTK
// 2. Verify old password hash matches credential's stored PasswordHash
// 3. Update credential PasswordHash to new value
// 4. Re-encrypt credential with CEK for app storage
// 5. Return updated encrypted credential + new UTKs
//
// SECURITY: Password hashes are in PHC format (Argon2id), hashed by the app before sending.
// Both old and new hashes are transported encrypted via UTK.
func (h *ProteanCredentialHandler) HandlePasswordChange(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	log.Info().Str("owner_space", h.ownerSpace).Msg("Credential password change requested")

	// Parse request
	var req PasswordChangeRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandlePasswordChange"); err != nil {
		return h.errorResponse(msg.GetID(), "invalid request format")
	}

	// Validate UTK
	ltk, found := h.bootstrap.GetLTKForUTK(req.UTKID)
	if !found {
		return h.errorResponse(msg.GetID(), "invalid or expired UTK")
	}

	if req.EncryptedCredential == "" {
		return h.errorResponse(msg.GetID(), "encrypted_credential is required")
	}

	// CEK still lives in vault state (it's session-scoped, not the
	// credential plaintext) and is needed to decrypt + re-encrypt
	// the request-supplied blob.
	h.state.mu.RLock()
	cekPair := h.state.cekPair
	h.state.mu.RUnlock()
	if cekPair == nil {
		return h.errorResponse(msg.GetID(), "CEK not available")
	}

	// Decode + decrypt payload (old + new password hashes) using
	// the UTK's LTK.
	encryptedPayload, err := base64.StdEncoding.DecodeString(req.EncryptedPayload)
	if err != nil {
		return h.errorResponse(msg.GetID(), "invalid payload encoding")
	}
	payloadBytes, err := decryptWithUTK(ltk, encryptedPayload)
	if err != nil {
		log.Error().Err(err).Msg("Failed to decrypt password change payload")
		return h.errorResponse(msg.GetID(), "decryption failed")
	}
	defer zeroBytes(payloadBytes)

	var payload PasswordChangePayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return h.errorResponse(msg.GetID(), "invalid payload format")
	}
	if payload.OldPasswordHash == "" {
		return h.errorResponse(msg.GetID(), "old_password_hash is required")
	}
	if payload.NewPasswordHash == "" {
		return h.errorResponse(msg.GetID(), "new_password_hash is required")
	}
	if err := validatePHCString(payload.OldPasswordHash); err != nil {
		return h.errorResponse(msg.GetID(), "invalid old password hash format")
	}
	if err := validatePHCString(payload.NewPasswordHash); err != nil {
		return h.errorResponse(msg.GetID(), "invalid new password hash format")
	}

	h.bootstrap.MarkUTKUsed(req.UTKID)

	// Phase D: decrypt the request-supplied credential blob, verify
	// the old password against it, mutate, re-encrypt — never
	// reading vaultState.credential.
	cred, err := h.decryptCredentialBlob(req.EncryptedCredential)
	if err != nil {
		log.Warn().Err(err).Str("owner_space", h.ownerSpace).Msg("HandlePasswordChange: failed to decrypt credential")
		return h.errorResponse(msg.GetID(), "credential decrypt failed")
	}
	defer cred.SecureErase()

	if !timingSafeEqualStrings(payload.OldPasswordHash, cred.Auth.Hash) {
		log.Warn().Str("owner_space", h.ownerSpace).Msg("Password change failed - old password mismatch")
		return h.errorResponse(msg.GetID(), "current password is incorrect")
	}

	cred.Auth.Hash = payload.NewPasswordHash
	cred.Timestamps.LastModified = time.Now().Unix()
	cred.Timestamps.AuthChangedAt = cred.Timestamps.LastModified
	cred.Version++

	credentialBytes, err := json.Marshal(cred)
	if err != nil {
		log.Error().Err(err).Msg("Failed to serialize credential")
		return h.errorResponse(msg.GetID(), "serialization failed")
	}
	defer zeroBytes(credentialBytes)

	encryptedCredential, err := encryptWithCEK(cekPair.PublicKey, credentialBytes)
	if err != nil {
		log.Error().Err(err).Msg("Failed to encrypt credential with CEK")
		return h.errorResponse(msg.GetID(), "encryption failed")
	}

	newPairs, err := h.bootstrap.GenerateMoreUTKs(5)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to generate new UTKs")
	}
	utkPublics := EncodeUTKPublics(newPairs)

	response := PasswordChangeResponse{
		Status:              "password_changed",
		EncryptedCredential: base64.StdEncoding.EncodeToString(encryptedCredential),
		NewUTKs:             utkPublics,
	}
	responseBytes, err := json.Marshal(response)
	if err != nil {
		return h.errorResponse(msg.GetID(), "response serialization failed")
	}

	log.Info().
		Str("owner_space", h.ownerSpace).
		Int("credential_version", cred.Version).
		Int("utk_count", len(utkPublics)).
		Msg("Credential password changed successfully")

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   responseBytes,
	}, nil
}

func (h *ProteanCredentialHandler) errorResponse(requestID string, errMsg string) (*OutgoingMessage, error) {
	return &OutgoingMessage{
		RequestID: requestID,
		Type:      MessageTypeError,
		Error:     errMsg,
	}, nil
}

// ClearCredential securely erases the credential from vault state (for decommission)
// SECURITY: This zeros all cryptographic material and clears the credential reference
func (h *ProteanCredentialHandler) ClearCredential() {
	h.state.mu.Lock()
	defer h.state.mu.Unlock()

	// Phase D: full credential plaintext is no longer cached, but the
	// narrow carve-outs are. Wipe them.
	if h.state.identityPrivateKey != nil {
		zeroBytes(h.state.identityPrivateKey)
		h.state.identityPrivateKey = nil
	}
	h.state.identityPublicKey = nil
	h.state.identityKeyExpiresAt = 0
	if h.state.pinAuthHash != nil {
		zeroBytes(h.state.pinAuthHash)
		h.state.pinAuthHash = nil
	}
	if h.state.pinAuthSalt != nil {
		zeroBytes(h.state.pinAuthSalt)
		h.state.pinAuthSalt = nil
	}
	log.Info().Str("owner_space", h.ownerSpace).Msg("In-memory credential carve-outs cleared for decommission")

	// Also clear CEK pair since it's no longer needed
	if h.state.cekPair != nil {
		zeroBytes(h.state.cekPair.PrivateKey)
		zeroBytes(h.state.cekPair.PublicKey)
		h.state.cekPair = nil
		log.Debug().Msg("CEK pair cleared")
	}

	// Clear DEK if present
	if h.state.dek != nil {
		zeroBytes(h.state.dek)
		h.state.dek = nil
		log.Debug().Msg("DEK cleared")
	}
}
