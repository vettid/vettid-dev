package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
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
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
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
	existingCredential := h.state.credential
	h.state.mu.RUnlock()

	if dek == nil {
		log.Error().Str("owner_space", h.ownerSpace).Msg("DEK not found - PIN setup must complete first")
		return h.errorResponse(msg.GetID(), "vault not ready - complete PIN setup first")
	}

	if cekPair == nil {
		log.Error().Str("owner_space", h.ownerSpace).Msg("CEK not found - PIN setup must complete first")
		return h.errorResponse(msg.GetID(), "vault not initialized - complete PIN setup first")
	}

	if existingCredential != nil {
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

	// Store credential in vault state
	h.state.mu.Lock()
	h.state.credential = credential
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

	// Generate fresh UTKs for future operations
	if err := h.bootstrap.GenerateMoreUTKs(5); err != nil {
		log.Warn().Err(err).Msg("Failed to generate new UTKs")
	}

	// Build response with new UTKs
	utks := h.bootstrap.GetUnusedUTKPairs()
	utkPublics := make([]UTKPublic, len(utks))
	for i, utk := range utks {
		utkPublics[i] = UTKPublic{
			ID:        utk.ID,
			PublicKey: base64.StdEncoding.EncodeToString(utk.UTK),
		}
	}

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
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "invalid request format")
	}

	// Validate UTK
	ltk, found := h.bootstrap.GetLTKForUTK(req.UTKID)
	if !found {
		return h.errorResponse(msg.GetID(), "invalid or expired UTK")
	}

	// Check vault state
	h.state.mu.RLock()
	credential := h.state.credential
	cekPair := h.state.cekPair
	h.state.mu.RUnlock()

	if credential == nil {
		return h.errorResponse(msg.GetID(), "credential not loaded - unlock vault first")
	}
	if cekPair == nil {
		return h.errorResponse(msg.GetID(), "CEK not available")
	}

	// Decode and decrypt payload using UTK's corresponding LTK
	encryptedPayload, err := base64.StdEncoding.DecodeString(req.EncryptedPayload)
	if err != nil {
		return h.errorResponse(msg.GetID(), "invalid payload encoding")
	}

	payloadBytes, err := decryptWithUTK(ltk, encryptedPayload)
	if err != nil {
		log.Error().Err(err).Msg("Failed to decrypt password change payload")
		return h.errorResponse(msg.GetID(), "decryption failed")
	}
	defer zeroBytes(payloadBytes) // SECURITY: Clear plaintext after use

	// Parse decrypted payload
	var payload PasswordChangePayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return h.errorResponse(msg.GetID(), "invalid payload format")
	}

	// Validate both password hashes are in PHC format
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

	// Mark UTK as used (single-use for security)
	h.bootstrap.MarkUTKUsed(req.UTKID)

	// SECURITY: Verify old password hash matches stored credential
	if !timingSafeEqualStrings(payload.OldPasswordHash, credential.PasswordHash) {
		log.Warn().Str("owner_space", h.ownerSpace).Msg("Password change failed - old password mismatch")
		return h.errorResponse(msg.GetID(), "current password is incorrect")
	}

	// Update credential with new password hash
	h.state.mu.Lock()
	h.state.credential.PasswordHash = payload.NewPasswordHash
	h.state.credential.Version++
	h.state.mu.Unlock()

	// Serialize updated credential for encryption
	credentialBytes, err := json.Marshal(credential)
	if err != nil {
		log.Error().Err(err).Msg("Failed to serialize credential")
		return h.errorResponse(msg.GetID(), "serialization failed")
	}
	defer zeroBytes(credentialBytes) // SECURITY: Clear after encryption

	// Re-encrypt credential with CEK for app storage
	encryptedCredential, err := encryptWithCEK(cekPair.PublicKey, credentialBytes)
	if err != nil {
		log.Error().Err(err).Msg("Failed to encrypt credential with CEK")
		return h.errorResponse(msg.GetID(), "encryption failed")
	}

	// Generate fresh UTKs for future operations
	if err := h.bootstrap.GenerateMoreUTKs(5); err != nil {
		log.Warn().Err(err).Msg("Failed to generate new UTKs")
	}

	// Build response with new UTKs
	utks := h.bootstrap.GetUnusedUTKPairs()
	utkPublics := make([]UTKPublic, len(utks))
	for i, utk := range utks {
		utkPublics[i] = UTKPublic{
			ID:        utk.ID,
			PublicKey: base64.StdEncoding.EncodeToString(utk.UTK),
		}
	}

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
		Int("credential_version", credential.Version).
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

	// Securely erase existing credential if present
	if h.state.credential != nil {
		h.state.credential.SecureErase()
		h.state.credential = nil
		log.Info().Str("owner_space", h.ownerSpace).Msg("In-memory credential cleared for decommission")
	}

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
