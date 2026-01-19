package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/rs/zerolog/log"
)

// PINHandler handles PIN-related operations (setup, unlock, change)
// PIN operations require the sealer proxy because DEK derivation uses KMS
type PINHandler struct {
	ownerSpace   string
	state        *VaultState
	bootstrap    *BootstrapHandler
	sealerProxy  *SealerProxy
}

// NewPINHandler creates a new PIN handler
func NewPINHandler(ownerSpace string, state *VaultState, bootstrap *BootstrapHandler, sealerProxy *SealerProxy) *PINHandler {
	return &PINHandler{
		ownerSpace:  ownerSpace,
		state:       state,
		bootstrap:   bootstrap,
		sealerProxy: sealerProxy,
	}
}

// HandlePINSetup processes initial PIN setup (Phase 2 of enrollment)
// Flow:
// 1. Decrypt PIN using ECIES (with app's ephemeral key + our private key)
// 2. Request sealed material from supervisor (KMS-bound)
// 3. Derive DEK from PIN + sealed material
// 4. Initialize vault-manager with DEK (SQLite, CEK keypair, UTKs)
// 5. Return vault_ready + UTKs for credential creation
//
// NOTE: This does NOT create the Protean Credential - that happens in credential.create (Phase 3)
// The PIN is for DEK derivation (vault unlock), credential password is for operation authorization
func (h *PINHandler) HandlePINSetup(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	log.Info().Str("owner_space", h.ownerSpace).Msg("PIN setup requested (Phase 2)")

	// Decrypt PIN using attestation key (mobile enrollment flow)
	// Format: {"type": "pin.setup", "payload": {"encrypted_pin": "...", "ephemeral_public_key": "...", "nonce": "..."}}
	if len(msg.AttestationPrivateKey) == 0 {
		log.Error().Str("owner_space", h.ownerSpace).Msg("No attestation key for PIN setup")
		return h.errorResponse(msg.GetID(), "attestation key required - did attestation complete?")
	}

	payloadBytes, err := h.decryptMobileFormat(msg)
	if err != nil {
		log.Error().Err(err).Msg("Failed to decrypt PIN payload")
		return h.errorResponse(msg.GetID(), "decryption failed: "+err.Error())
	}
	defer zeroBytes(payloadBytes) // SECURITY: Clear plaintext after use

	var payload PINSetupPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return h.errorResponse(msg.GetID(), "invalid payload format")
	}
	// SECURITY: Zero PIN after use (deferred to ensure cleanup on all exit paths)
	defer payload.PIN.Zero()

	// Validate PIN format (must be digits only, 4-8 characters)
	if len(payload.PIN) < 4 || len(payload.PIN) > 8 {
		return h.errorResponse(msg.GetID(), "PIN must be 4-8 digits")
	}
	if !isAllDigits([]byte(payload.PIN)) {
		return h.errorResponse(msg.GetID(), "PIN must contain only digits")
	}

	// Request sealed material from supervisor (KMS-bound operation)
	sealedMaterial, err := h.sealerProxy.GenerateSealedMaterial()
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate sealed material")
		return h.errorResponse(msg.GetID(), "KMS operation failed")
	}

	// Derive DEK from PIN + sealed material (KMS-bound operation)
	// SECURITY: Pass PIN as []byte so both ends can zero it
	dek, err := h.sealerProxy.DeriveDEKFromPIN(sealedMaterial, []byte(payload.PIN))
	if err != nil {
		log.Error().Err(err).Msg("Failed to derive DEK")
		return h.errorResponse(msg.GetID(), fmt.Sprintf("key derivation failed: %v", err))
	}
	// NOTE: DEK is NOT zeroed here - it's stored for credential.create (Phase 3)
	// SECURITY: DEK will be cleared after credential creation or on timeout

	// Store sealed material and DEK for credential creation
	// Make a copy of DEK since we're storing it
	dekCopy := make([]byte, len(dek))
	copy(dekCopy, dek)
	zeroBytes(dek) // Zero the original

	h.state.mu.Lock()
	h.state.sealedMaterial = sealedMaterial
	h.state.dek = dekCopy // Store DEK copy for credential.create
	h.state.mu.Unlock()

	// Generate CEK keypair for encrypting the Protean Credential
	if err := h.bootstrap.GenerateCEKPair(); err != nil {
		log.Error().Err(err).Msg("Failed to generate CEK keypair")
		return h.errorResponse(msg.GetID(), "CEK generation failed")
	}

	// Generate UTKs for credential creation
	if err := h.bootstrap.GenerateMoreUTKs(5); err != nil {
		log.Warn().Err(err).Msg("Failed to generate UTKs")
	}

	// Build response with UTKs in the new format
	utks := h.bootstrap.GetUnusedUTKPairs()
	utkPublics := make([]UTKPublic, len(utks))
	for i, utk := range utks {
		utkPublics[i] = UTKPublic{
			ID:        utk.ID,
			PublicKey: base64.StdEncoding.EncodeToString(utk.UTK),
		}
	}

	response := PINSetupResponse{
		Status: "vault_ready",
		UTKs:   utkPublics,
	}

	responseBytes, err := json.Marshal(response)
	if err != nil {
		return h.errorResponse(msg.GetID(), "response serialization failed")
	}

	log.Info().
		Str("owner_space", h.ownerSpace).
		Int("utk_count", len(utkPublics)).
		Msg("PIN setup completed - vault ready for credential creation (Phase 3)")

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   responseBytes,
	}, nil
}

// HandlePINUnlock processes PIN unlock requests
// Flow:
// 1. Decrypt PIN using ECIES
// 2. Derive DEK from PIN + stored sealed material
// 3. Decrypt credential with DEK
// 4. Verify auth hash matches
// 5. Return success with new UTKs
func (h *PINHandler) HandlePINUnlock(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	log.Info().Str("owner_space", h.ownerSpace).Msg("PIN unlock requested")

	var req PINUnlockRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "invalid request format")
	}

	// Validate UTK
	_, found := h.bootstrap.GetLTKForUTK(req.UTKID)
	if !found {
		return h.errorResponse(msg.GetID(), "invalid UTK")
	}

	// Decode and decrypt payload
	encryptedPayload, err := base64.StdEncoding.DecodeString(req.EncryptedPayload)
	if err != nil {
		return h.errorResponse(msg.GetID(), "invalid payload encoding")
	}

	h.state.mu.RLock()
	eciesPrivateKey := h.state.eciesPrivateKey
	sealedMaterial := h.state.sealedMaterial
	storedCredential := h.state.credential
	h.state.mu.RUnlock()

	if eciesPrivateKey == nil || sealedMaterial == nil {
		return h.errorResponse(msg.GetID(), "vault not initialized")
	}

	payloadBytes, err := decryptWithECIES(eciesPrivateKey, encryptedPayload)
	if err != nil {
		return h.errorResponse(msg.GetID(), "decryption failed")
	}
	defer zeroBytes(payloadBytes)

	var payload PINSetupPayload // Same format as setup (just PIN)
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return h.errorResponse(msg.GetID(), "invalid payload format")
	}
	// SECURITY: Zero PIN after use
	defer payload.PIN.Zero()

	// Mark UTK as used
	h.bootstrap.MarkUTKUsed(req.UTKID)

	// Derive DEK from PIN + sealed material
	// SECURITY: Pass PIN as []byte so both ends can zero it
	dek, err := h.sealerProxy.DeriveDEKFromPIN(sealedMaterial, []byte(payload.PIN))
	if err != nil {
		log.Warn().Err(err).Msg("DEK derivation failed - likely wrong PIN")
		return h.errorResponse(msg.GetID(), "invalid PIN")
	}
	defer zeroBytes(dek)

	// If we have credential in memory, verify auth hash
	if storedCredential != nil {
		// SECURITY: payload.PIN is already []byte (SensitiveBytes), passed directly
		if !verifyAuthHash(payload.PIN, storedCredential.AuthSalt, storedCredential.AuthHash) {
			return h.errorResponse(msg.GetID(), "invalid PIN")
		}
	}

	// Generate more UTKs
	if err := h.bootstrap.GenerateMoreUTKs(3); err != nil {
		log.Warn().Err(err).Msg("Failed to generate new UTKs")
	}

	response := PINUnlockResponse{
		Status:  "unlocked",
		NewUTKs: h.bootstrap.GetUnusedUTKs(),
	}

	// If credential exists, include encrypted version
	if storedCredential != nil {
		credBytes, err := json.Marshal(storedCredential)
		if err == nil {
			encryptedCred, err := encryptWithDEK(dek, credBytes)
			if err == nil {
				response.EncryptedCredential = base64.StdEncoding.EncodeToString(encryptedCred)
			}
			zeroBytes(credBytes)
		}
	}

	responseBytes, err := json.Marshal(response)
	if err != nil {
		return h.errorResponse(msg.GetID(), "response serialization failed")
	}

	log.Info().Str("owner_space", h.ownerSpace).Msg("PIN unlock successful")

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   responseBytes,
	}, nil
}

// HandlePINChange processes PIN change requests
// Flow:
// 1. Decrypt payload containing old and new PIN
// 2. Verify old PIN is correct
// 3. Generate new sealed material with new PIN
// 4. Re-encrypt credential with new DEK
// 5. Return re-encrypted credential
func (h *PINHandler) HandlePINChange(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	log.Info().Str("owner_space", h.ownerSpace).Msg("PIN change requested")

	var req PINChangeRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "invalid request format")
	}

	// Validate UTK
	_, found := h.bootstrap.GetLTKForUTK(req.UTKID)
	if !found {
		return h.errorResponse(msg.GetID(), "invalid UTK")
	}

	// Decode and decrypt payload
	encryptedPayload, err := base64.StdEncoding.DecodeString(req.EncryptedPayload)
	if err != nil {
		return h.errorResponse(msg.GetID(), "invalid payload encoding")
	}

	h.state.mu.RLock()
	eciesPrivateKey := h.state.eciesPrivateKey
	sealedMaterial := h.state.sealedMaterial
	credential := h.state.credential
	h.state.mu.RUnlock()

	if eciesPrivateKey == nil || credential == nil {
		return h.errorResponse(msg.GetID(), "vault not initialized")
	}

	payloadBytes, err := decryptWithECIES(eciesPrivateKey, encryptedPayload)
	if err != nil {
		return h.errorResponse(msg.GetID(), "decryption failed")
	}
	defer zeroBytes(payloadBytes)

	var payload PINChangePayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return h.errorResponse(msg.GetID(), "invalid payload format")
	}
	// SECURITY: Zero both PINs after use
	defer payload.OldPIN.Zero()
	defer payload.NewPIN.Zero()

	// Validate new PIN format
	if len(payload.NewPIN) < 4 || len(payload.NewPIN) > 8 {
		return h.errorResponse(msg.GetID(), "new PIN must be 4-8 digits")
	}
	if !isAllDigits([]byte(payload.NewPIN)) {
		return h.errorResponse(msg.GetID(), "new PIN must contain only digits")
	}

	// Mark UTK as used
	h.bootstrap.MarkUTKUsed(req.UTKID)

	// Verify old PIN
	// SECURITY: payload.OldPIN is already []byte (SensitiveBytes)
	if !verifyAuthHash(payload.OldPIN, credential.AuthSalt, credential.AuthHash) {
		return h.errorResponse(msg.GetID(), "invalid current PIN")
	}

	// Derive old DEK to verify (optional additional check)
	if sealedMaterial != nil {
		// SECURITY: Pass PIN as []byte so both ends can zero it
		oldDEK, err := h.sealerProxy.DeriveDEKFromPIN(sealedMaterial, []byte(payload.OldPIN))
		if err != nil {
			return h.errorResponse(msg.GetID(), "verification failed")
		}
		zeroBytes(oldDEK)
	}

	// Generate new sealed material for new PIN
	newSealedMaterial, err := h.sealerProxy.GenerateSealedMaterial()
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate new sealed material")
		return h.errorResponse(msg.GetID(), "KMS operation failed")
	}

	// Derive new DEK
	// SECURITY: Pass PIN as []byte so both ends can zero it
	newDEK, err := h.sealerProxy.DeriveDEKFromPIN(newSealedMaterial, []byte(payload.NewPIN))
	if err != nil {
		log.Error().Err(err).Msg("Failed to derive new DEK")
		return h.errorResponse(msg.GetID(), "key derivation failed")
	}
	defer zeroBytes(newDEK)

	// Update credential auth hash
	newSalt, err := generateSalt()
	if err != nil {
		return h.errorResponse(msg.GetID(), "salt generation failed")
	}
	// SECURITY: payload.NewPIN is already []byte (SensitiveBytes)
	newAuthHash := hashAuthInput(payload.NewPIN, newSalt)

	h.state.mu.Lock()
	h.state.credential.AuthHash = newAuthHash
	h.state.credential.AuthSalt = newSalt
	h.state.credential.Version++
	h.state.sealedMaterial = newSealedMaterial
	h.state.mu.Unlock()

	// Re-encrypt credential with new DEK
	credBytes, err := json.Marshal(credential)
	if err != nil {
		return h.errorResponse(msg.GetID(), "serialization failed")
	}
	defer zeroBytes(credBytes)

	encryptedCred, err := encryptWithDEK(newDEK, credBytes)
	if err != nil {
		return h.errorResponse(msg.GetID(), "encryption failed")
	}

	// Generate fresh UTKs
	if err := h.bootstrap.GenerateMoreUTKs(5); err != nil {
		log.Warn().Err(err).Msg("Failed to generate new UTKs")
	}

	response := PINChangeResponse{
		Status:              "pin_changed",
		EncryptedCredential: base64.StdEncoding.EncodeToString(encryptedCred),
		NewUTKs:             h.bootstrap.GetUnusedUTKs(),
	}

	responseBytes, err := json.Marshal(response)
	if err != nil {
		return h.errorResponse(msg.GetID(), "response serialization failed")
	}

	log.Info().
		Str("owner_space", h.ownerSpace).
		Int("credential_version", credential.Version).
		Msg("PIN change completed")

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   responseBytes,
	}, nil
}

func (h *PINHandler) errorResponse(requestID string, errMsg string) (*OutgoingMessage, error) {
	return &OutgoingMessage{
		RequestID: requestID,
		Type:      MessageTypeError,
		Error:     errMsg,
	}, nil
}

// decryptMobileFormat handles the mobile app's attestation-based PIN encryption
// Mobile format: {"type": "pin.setup", "payload": {"encrypted_pin": "...", "ephemeral_public_key": "...", "nonce": "..."}}
func (h *PINHandler) decryptMobileFormat(msg *IncomingMessage) ([]byte, error) {
	// Parse the outer envelope
	var envelope struct {
		Type    string `json:"type"`
		Payload struct {
			EncryptedPIN       string `json:"encrypted_pin"`
			EphemeralPublicKey string `json:"ephemeral_public_key"`
			Nonce              string `json:"nonce"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(msg.Payload, &envelope); err != nil {
		return nil, fmt.Errorf("invalid mobile payload format: %w", err)
	}

	log.Debug().
		Str("owner_space", h.ownerSpace).
		Str("type", envelope.Type).
		Int("encrypted_pin_len", len(envelope.Payload.EncryptedPIN)).
		Int("ephemeral_key_len", len(envelope.Payload.EphemeralPublicKey)).
		Int("nonce_len", len(envelope.Payload.Nonce)).
		Msg("Decrypting mobile PIN format")

	// Decode components
	ephemeralPub, err := base64.StdEncoding.DecodeString(envelope.Payload.EphemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid ephemeral public key encoding: %w", err)
	}
	if len(ephemeralPub) != 32 {
		return nil, fmt.Errorf("invalid ephemeral public key length: %d", len(ephemeralPub))
	}

	nonce, err := base64.StdEncoding.DecodeString(envelope.Payload.Nonce)
	if err != nil {
		return nil, fmt.Errorf("invalid nonce encoding: %w", err)
	}
	if len(nonce) != 12 {
		return nil, fmt.Errorf("invalid nonce length: %d", len(nonce))
	}

	ciphertext, err := base64.StdEncoding.DecodeString(envelope.Payload.EncryptedPIN)
	if err != nil {
		return nil, fmt.Errorf("invalid encrypted PIN encoding: %w", err)
	}

	// Reconstruct ECIES format: [32-byte ephemeral pubkey][12-byte nonce][ciphertext]
	encrypted := make([]byte, 0, 32+12+len(ciphertext))
	encrypted = append(encrypted, ephemeralPub...)
	encrypted = append(encrypted, nonce...)
	encrypted = append(encrypted, ciphertext...)

	// Decrypt using the attestation private key
	plaintext, err := decryptWithECIES(msg.AttestationPrivateKey, encrypted)
	if err != nil {
		return nil, fmt.Errorf("ECIES decryption failed: %w", err)
	}

	return plaintext, nil
}

