package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

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

// HandlePINSetup processes initial PIN setup
// Flow:
// 1. Decrypt PIN using ECIES (with app's ephemeral key + our private key)
// 2. Request sealed material from supervisor (KMS-bound)
// 3. Derive DEK from PIN + sealed material
// 4. Generate identity keypair and credential
// 5. Encrypt credential with DEK
// 6. Return encrypted credential to app
func (h *PINHandler) HandlePINSetup(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	log.Info().Str("owner_space", h.ownerSpace).Msg("PIN setup requested")

	var req PINSetupRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "invalid request format")
	}

	// Validate UTK
	ltk, found := h.bootstrap.GetLTKForUTK(req.UTKID)
	if !found {
		return h.errorResponse(msg.GetID(), "invalid UTK")
	}

	// Decode encrypted payload
	encryptedPayload, err := base64.StdEncoding.DecodeString(req.EncryptedPayload)
	if err != nil {
		return h.errorResponse(msg.GetID(), "invalid payload encoding")
	}

	// Decrypt payload using LTK (ECIES decryption)
	h.state.mu.RLock()
	eciesPrivateKey := h.state.eciesPrivateKey
	h.state.mu.RUnlock()

	if eciesPrivateKey == nil {
		return h.errorResponse(msg.GetID(), "vault not bootstrapped")
	}

	// The payload is encrypted with ECIES using our public key
	payloadBytes, err := decryptWithECIES(eciesPrivateKey, encryptedPayload)
	if err != nil {
		log.Error().Err(err).Msg("Failed to decrypt PIN payload")
		return h.errorResponse(msg.GetID(), "decryption failed")
	}
	defer zeroBytes(payloadBytes) // SECURITY: Clear plaintext after use

	var payload PINSetupPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return h.errorResponse(msg.GetID(), "invalid payload format")
	}

	// Validate PIN format (must be digits only, 4-8 characters)
	if len(payload.PIN) < 4 || len(payload.PIN) > 8 {
		return h.errorResponse(msg.GetID(), "PIN must be 4-8 digits")
	}
	if !isAllDigits([]byte(payload.PIN)) {
		return h.errorResponse(msg.GetID(), "PIN must contain only digits")
	}

	// Mark UTK as used (one-time use for transport encryption)
	h.bootstrap.MarkUTKUsed(req.UTKID)
	_ = ltk // LTK could be used for additional key agreement if needed

	// Request sealed material from supervisor (KMS-bound operation)
	sealedMaterial, err := h.sealerProxy.GenerateSealedMaterial()
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate sealed material")
		return h.errorResponse(msg.GetID(), "KMS operation failed")
	}

	// Derive DEK from PIN + sealed material (KMS-bound operation)
	dek, err := h.sealerProxy.DeriveDEKFromPIN(sealedMaterial, payload.PIN)
	if err != nil {
		log.Error().Err(err).Msg("Failed to derive DEK")
		// Include the actual error for debugging
		return h.errorResponse(msg.GetID(), fmt.Sprintf("key derivation failed: %v", err))
	}
	defer zeroBytes(dek) // SECURITY: Clear DEK after use

	// Generate identity keypair for the vault
	identityPriv, identityPub, err := generateIdentityKeypair()
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate identity keypair")
		return h.errorResponse(msg.GetID(), "keypair generation failed")
	}

	// Generate vault master secret
	masterSecret, err := generateMasterSecret()
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate master secret")
		return h.errorResponse(msg.GetID(), "secret generation failed")
	}

	// Generate auth salt and hash the PIN for verification
	authSalt, err := generateSalt()
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate auth salt")
		return h.errorResponse(msg.GetID(), "salt generation failed")
	}
	authHash := hashAuthInput([]byte(payload.PIN), authSalt)

	// Create the credential
	h.state.mu.Lock()
	h.state.credential = &UnsealedCredential{
		IdentityPrivateKey: identityPriv,
		IdentityPublicKey:  identityPub,
		VaultMasterSecret:  masterSecret,
		AuthHash:           authHash,
		AuthSalt:           authSalt,
		AuthType:           "pin",
		CryptoKeys:         []CryptoKey{},
		CreatedAt:          time.Now().Unix(),
		Version:            1,
	}

	// Store sealed material for future unlock operations
	h.state.sealedMaterial = sealedMaterial
	h.state.mu.Unlock()

	// Serialize and encrypt credential with DEK
	credBytes, err := json.Marshal(h.state.credential)
	if err != nil {
		log.Error().Err(err).Msg("Failed to serialize credential")
		return h.errorResponse(msg.GetID(), "serialization failed")
	}
	defer zeroBytes(credBytes)

	encryptedCred, err := encryptWithDEK(dek, credBytes)
	if err != nil {
		log.Error().Err(err).Msg("Failed to encrypt credential")
		return h.errorResponse(msg.GetID(), "encryption failed")
	}

	// Generate more UTKs for the response
	if err := h.bootstrap.GenerateMoreUTKs(5); err != nil {
		log.Warn().Err(err).Msg("Failed to generate new UTKs")
	}

	response := PINSetupResponse{
		Status:              "pin_set",
		EncryptedCredential: base64.StdEncoding.EncodeToString(encryptedCred),
		NewUTKs:             h.bootstrap.GetUnusedUTKs(),
	}

	responseBytes, err := json.Marshal(response)
	if err != nil {
		return h.errorResponse(msg.GetID(), "response serialization failed")
	}

	log.Info().
		Str("owner_space", h.ownerSpace).
		Str("identity_pub", base64.StdEncoding.EncodeToString(identityPub)[:16]+"...").
		Msg("PIN setup completed")

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

	// Mark UTK as used
	h.bootstrap.MarkUTKUsed(req.UTKID)

	// Derive DEK from PIN + sealed material
	dek, err := h.sealerProxy.DeriveDEKFromPIN(sealedMaterial, payload.PIN)
	if err != nil {
		log.Warn().Err(err).Msg("DEK derivation failed - likely wrong PIN")
		return h.errorResponse(msg.GetID(), "invalid PIN")
	}
	defer zeroBytes(dek)

	// If we have credential in memory, verify auth hash
	if storedCredential != nil {
		if !verifyAuthHash([]byte(payload.PIN), storedCredential.AuthSalt, storedCredential.AuthHash) {
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
	if !verifyAuthHash([]byte(payload.OldPIN), credential.AuthSalt, credential.AuthHash) {
		return h.errorResponse(msg.GetID(), "invalid current PIN")
	}

	// Derive old DEK to verify (optional additional check)
	if sealedMaterial != nil {
		oldDEK, err := h.sealerProxy.DeriveDEKFromPIN(sealedMaterial, payload.OldPIN)
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
	newDEK, err := h.sealerProxy.DeriveDEKFromPIN(newSealedMaterial, payload.NewPIN)
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
	newAuthHash := hashAuthInput([]byte(payload.NewPIN), newSalt)

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
