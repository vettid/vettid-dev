package main

import (
	"context"
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
	var credV2 ProteanCredentialV2
	if err := json.Unmarshal(plaintext, &credV2); err != nil {
		return nil, fmt.Errorf("failed to parse credential: %w", err)
	}
	return &credV2, nil
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

	// Create the Protean Credential
	credential := &UnsealedCredential{
		IdentityPrivateKey: identityPrivateKey,
		IdentityPublicKey:  identityPublicKey,
		VaultMasterSecret:  masterSecret,
		PasswordHash:       payload.PasswordHash, // PHC string format: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
		AuthType:           "password",
		CryptoKeys:         make([]CryptoKey, 0),
		CreatedAt:          time.Now().Unix(),
		Version:            1,
	}

	// Phase D: populate the narrow carve-outs (identity keypair +
	// PIN auth hash/salt) so the rest of the system can read them
	// without retaining the full credential plaintext in memory.
	h.state.mu.Lock()
	h.state.identityPrivateKey = append([]byte(nil), credential.IdentityPrivateKey...)
	h.state.identityPublicKey = append([]byte(nil), credential.IdentityPublicKey...)
	h.state.pinAuthHash = append([]byte(nil), credential.AuthHash...)
	h.state.pinAuthSalt = append([]byte(nil), credential.AuthSalt...)
	h.state.mu.Unlock()

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
