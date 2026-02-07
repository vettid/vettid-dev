package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/vettid/vettid-dev/enclave/vault-manager/storage"
	"github.com/rs/zerolog/log"
)

// PINHandler handles PIN-related operations (setup, unlock, change)
// PIN operations require the sealer proxy because DEK derivation uses KMS
type PINHandler struct {
	ownerSpace   string
	state        *VaultState
	bootstrap    *BootstrapHandler
	sealerProxy  *SealerProxy
	storage      *EncryptedStorage
}

// NewPINHandler creates a new PIN handler
func NewPINHandler(ownerSpace string, state *VaultState, bootstrap *BootstrapHandler, sealerProxy *SealerProxy, storage *EncryptedStorage) *PINHandler {
	return &PINHandler{
		ownerSpace:  ownerSpace,
		state:       state,
		bootstrap:   bootstrap,
		sealerProxy: sealerProxy,
		storage:     storage,
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
	// Clear any existing credential for fresh enrollment retries.
	// This allows users to retry enrollment if credential.create succeeded
	// but a later step (like finalize) failed.
	if h.state.credential != nil {
		log.Info().Str("owner_space", h.ownerSpace).Msg("Clearing existing credential for fresh enrollment")
		h.state.credential = nil
	}
	h.state.mu.Unlock()

	// Initialize encrypted storage with DEK so feed/events are accessible
	// This creates the in-memory SQLite database with encryption
	if err := h.storage.InitializeWithDEK(dekCopy); err != nil {
		log.Error().Err(err).Str("owner_space", h.ownerSpace).Msg("Failed to initialize storage with DEK")
		return h.errorResponse(msg.GetID(), "storage initialization failed")
	}
	log.Info().Str("owner_space", h.ownerSpace).Msg("Storage initialized with DEK")

	// Store registration profile if provided (from enrollment)
	// This ensures the vault has the user's name and email from registration
	if payload.Profile != nil {
		if err := h.storeRegistrationProfile(payload.Profile); err != nil {
			log.Warn().Err(err).Str("owner_space", h.ownerSpace).Msg("Failed to store registration profile - can be synced later")
			// Don't fail PIN setup if profile storage fails - it can be synced later
		} else {
			log.Info().
				Str("owner_space", h.ownerSpace).
				Str("first_name", payload.Profile.FirstName).
				Str("email", payload.Profile.Email).
				Msg("Registration profile stored to vault")
		}
	}

	// Generate CEK keypair for encrypting the Protean Credential
	if err := h.bootstrap.GenerateCEKPair(); err != nil {
		log.Error().Err(err).Msg("Failed to generate CEK keypair")
		return h.errorResponse(msg.GetID(), "CEK generation failed")
	}

	// Generate UTKs for credential creation
	if err := h.bootstrap.GenerateMoreUTKs(5); err != nil {
		log.Warn().Err(err).Msg("Failed to generate UTKs")
	}

	// Store sealed material to S3 for cold vault recovery
	// This replaces sending it to the app - the enclave loads from S3 on cold unlock
	if err := h.sealerProxy.StoreSealedMaterial(sealedMaterial); err != nil {
		log.Warn().Err(err).Msg("Failed to store sealed material to S3 - cold unlock may not work")
		// Don't fail PIN setup if S3 storage fails - vault is still usable while warm
	} else {
		log.Info().Str("owner_space", h.ownerSpace).Msg("Sealed material stored to S3 for cold vault recovery")
	}

	// Generate ECIES keypair for cold vault recovery
	// This allows the vault to decrypt PINs even after enclave restart
	generated, err := h.bootstrap.GenerateECIESKeypairIfNeeded()
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate ECIES keypair")
		return h.errorResponse(msg.GetID(), "ECIES generation failed")
	}

	// Store ECIES keys to S3 if generated (or always store to ensure they exist)
	if generated || true { // Always store to ensure keys are persisted
		eciesPrivate, eciesPublic := h.bootstrap.GetECIESKeys()
		if eciesPrivate != nil && eciesPublic != nil {
			// Marshal ECIES keys
			eciesKeys := struct {
				PrivateKey []byte `json:"private_key"`
				PublicKey  []byte `json:"public_key"`
			}{
				PrivateKey: eciesPrivate,
				PublicKey:  eciesPublic,
			}
			eciesData, err := json.Marshal(eciesKeys)
			if err != nil {
				log.Warn().Err(err).Str("owner_space", h.ownerSpace).Msg("Failed to marshal ECIES keys")
			} else {
				defer zeroBytes(eciesData)
				defer zeroBytes(eciesPrivate)

				// Seal with KMS
				sealedECIES, err := h.sealerProxy.SealCredential(eciesData)
				if err != nil {
					log.Warn().Err(err).Str("owner_space", h.ownerSpace).Msg("Failed to seal ECIES keys")
				} else {
					// Store sealed ECIES keys to S3
					if err := h.sealerProxy.StoreSealedECIES(sealedECIES); err != nil {
						log.Warn().Err(err).Str("owner_space", h.ownerSpace).Msg("Failed to store ECIES keys to S3 - cold vault unlock may not work")
					} else {
						log.Info().Str("owner_space", h.ownerSpace).Msg("ECIES keys sealed and stored to S3 for cold vault recovery")
					}
				}
			}
		}
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

	// Get ECIES public key for PIN unlock (this is different from the attestation key!)
	_, eciesPublic := h.bootstrap.GetECIESKeys()
	eciesPublicB64 := ""
	if eciesPublic != nil {
		eciesPublicB64 = base64.StdEncoding.EncodeToString(eciesPublic)
	}

	response := PINSetupResponse{
		Status:         "vault_ready",
		UTKs:           utkPublics,
		ECIESPublicKey: eciesPublicB64,
	}

	responseBytes, err := json.Marshal(response)
	if err != nil {
		return h.errorResponse(msg.GetID(), "response serialization failed")
	}

	log.Info().
		Str("owner_space", h.ownerSpace).
		Int("utk_count", len(utkPublics)).
		Bool("has_ecies_key", eciesPublicB64 != "").
		Msg("PIN setup completed - vault ready for credential creation (Phase 3)")

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   responseBytes,
	}, nil
}

// HandlePINUnlock processes PIN unlock requests
// Supports two modes:
// 1. Warm vault: ECIES keys are in memory, standard unlock flow
// 2. Cold vault: ECIES keys need to be restored from KMS-sealed storage first
//
// Flow for warm vault:
// 1. Decrypt PIN using ECIES
// 2. Derive DEK from PIN + stored sealed material
// 3. Verify auth hash matches
// 4. Return success with new UTKs
//
// Flow for cold vault:
// 1. Restore ECIES keys from KMS-sealed storage
// 2. Decrypt PIN using ECIES
// 3. Derive DEK from PIN + sealed material (from request)
// 4. Restore full vault state from DEK-encrypted storage
// 5. Return success with new UTKs
func (h *PINHandler) HandlePINUnlock(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	log.Info().Str("owner_space", h.ownerSpace).Msg("PIN unlock requested")

	var req PINUnlockRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		log.Error().Err(err).Str("payload", string(msg.Payload)).Msg("Failed to unmarshal PIN unlock request")
		return h.errorResponse(msg.GetID(), "invalid request format")
	}

	log.Debug().Str("owner_space", h.ownerSpace).Str("utk_id", req.UTKID).Msg("DEBUG: Parsed PIN unlock request")

	// Check if vault is warm (has ECIES keys in memory)
	h.state.mu.RLock()
	eciesPrivateKey := h.state.eciesPrivateKey
	sealedMaterial := h.state.sealedMaterial
	storedCredential := h.state.credential
	isWarmVault := eciesPrivateKey != nil && sealedMaterial != nil
	h.state.mu.RUnlock()

	// Handle cold vault unlock - load state from S3
	if !isWarmVault {
		log.Info().Str("owner_space", h.ownerSpace).Msg("Cold vault detected, loading state from S3")

		// Load sealed ECIES keys from S3
		sealedECIESBytes, err := h.sealerProxy.LoadSealedECIES()
		if err != nil {
			log.Error().Err(err).Msg("Failed to load sealed ECIES keys from S3")
			return h.errorResponse(msg.GetID(), "vault not initialized - no recovery data in storage")
		}

		// Unseal ECIES keys using KMS
		eciesData, err := h.sealerProxy.UnsealCredential(sealedECIESBytes)
		if err != nil {
			log.Error().Err(err).Msg("Failed to unseal ECIES keys")
			return h.errorResponse(msg.GetID(), "failed to restore vault keys")
		}
		defer zeroBytes(eciesData)

		// Parse ECIES keys
		var eciesKeys struct {
			PrivateKey []byte `json:"private_key"`
			PublicKey  []byte `json:"public_key"`
		}
		if err := json.Unmarshal(eciesData, &eciesKeys); err != nil {
			return h.errorResponse(msg.GetID(), "invalid ECIES keys format")
		}

		// Restore ECIES keys to vault state
		h.state.mu.Lock()
		h.state.eciesPrivateKey = eciesKeys.PrivateKey
		h.state.eciesPublicKey = eciesKeys.PublicKey
		eciesPrivateKey = h.state.eciesPrivateKey
		h.state.mu.Unlock()

		log.Info().Str("owner_space", h.ownerSpace).Msg("ECIES keys restored from S3 + KMS")

		// Load sealed material from S3
		sealedMaterialBytes, err := h.sealerProxy.LoadSealedMaterial()
		if err != nil {
			log.Error().Err(err).Msg("Failed to load sealed material from S3")
			return h.errorResponse(msg.GetID(), "failed to load vault recovery data")
		}
		sealedMaterial = sealedMaterialBytes
	}

	// Validate UTK (may fail for cold vault if UTKs aren't restored yet)
	_, found := h.bootstrap.GetLTKForUTK(req.UTKID)
	if !found && isWarmVault {
		// Only fail for warm vault - cold vault may not have UTKs yet
		return h.errorResponse(msg.GetID(), "invalid UTK")
	}

	// Decode and decrypt payload
	encryptedPayload, err := base64.StdEncoding.DecodeString(req.EncryptedPayload)
	if err != nil {
		return h.errorResponse(msg.GetID(), "invalid payload encoding")
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

	// Mark UTK as used (if it exists)
	if found {
		h.bootstrap.MarkUTKUsed(req.UTKID)
	}

	// Derive DEK from PIN + sealed material
	// SECURITY: Pass PIN as []byte so both ends can zero it
	dek, err := h.sealerProxy.DeriveDEKFromPIN(sealedMaterial, []byte(payload.PIN))
	if err != nil {
		log.Warn().Err(err).Msg("DEK derivation failed - likely wrong PIN")
		return h.errorResponse(msg.GetID(), "invalid PIN")
	}
	defer zeroBytes(dek)

	// For cold vault, restore full vault state from S3
	var databaseBackup json.RawMessage // Captured from persisted state for post-init restore
	if !isWarmVault {
		encryptedStateBytes, err := h.sealerProxy.LoadVaultState()
		if err != nil {
			log.Warn().Err(err).Msg("Failed to load encrypted vault state from S3 - vault may have incomplete state")
			// Don't fail - we can still continue with just ECIES and sealed material
		} else {
			// Decrypt vault state with DEK
			stateData, err := decryptWithDEK(dek, encryptedStateBytes)
			if err != nil {
				log.Warn().Err(err).Msg("Failed to decrypt vault state - wrong PIN or corrupted data")
				return h.errorResponse(msg.GetID(), "invalid PIN")
			}
			defer zeroBytes(stateData)

			// Parse and restore vault state
			var persistedState struct {
				CEKPrivateKey  []byte `json:"cek_private_key"`
				CEKPublicKey   []byte `json:"cek_public_key"`
				UTKPairs       []struct {
					ID        string `json:"id"`
					UTK       []byte `json:"utk"`
					LTK       []byte `json:"ltk"`
					UsedAt    int64  `json:"used_at"`
					CreatedAt int64  `json:"created_at"`
				} `json:"utk_pairs"`
				Credential     *UnsealedCredential `json:"credential,omitempty"`
				SealedMaterial []byte              `json:"sealed_material"`
				DatabaseBackup json.RawMessage     `json:"database_backup,omitempty"`
			}
			if err := json.Unmarshal(stateData, &persistedState); err != nil {
				return h.errorResponse(msg.GetID(), "invalid vault state format")
			}

			// Capture database backup for restore after storage init
			if len(persistedState.DatabaseBackup) > 0 {
				databaseBackup = persistedState.DatabaseBackup
				log.Info().Str("owner_space", h.ownerSpace).Int("backup_size", len(databaseBackup)).Msg("Database backup found in vault state")
			}

			// Apply restored state
			h.state.mu.Lock()
			if len(persistedState.CEKPrivateKey) > 0 {
				h.state.cekPair = &CEKPair{
					PrivateKey: persistedState.CEKPrivateKey,
					PublicKey:  persistedState.CEKPublicKey,
				}
			}
			h.state.utkPairs = nil
			for _, utk := range persistedState.UTKPairs {
				h.state.utkPairs = append(h.state.utkPairs, &UTKPair{
					ID:        utk.ID,
					UTK:       utk.UTK,
					LTK:       utk.LTK,
					UsedAt:    utk.UsedAt,
					CreatedAt: utk.CreatedAt,
				})
			}
			if persistedState.Credential != nil {
				h.state.credential = persistedState.Credential
				storedCredential = persistedState.Credential
			}
			if len(persistedState.SealedMaterial) > 0 {
				h.state.sealedMaterial = persistedState.SealedMaterial
			} else {
				h.state.sealedMaterial = sealedMaterial
			}
			h.state.mu.Unlock()

			log.Info().
				Str("owner_space", h.ownerSpace).
				Int("utk_count", len(persistedState.UTKPairs)).
				Bool("has_credential", persistedState.Credential != nil).
				Bool("has_db_backup", len(databaseBackup) > 0).
				Msg("Vault state restored from S3")
		}
	}

	// Initialize encrypted storage with DEK so feed/events are accessible
	// This must happen before any storage operations
	if err := h.storage.InitializeWithDEK(dek); err != nil {
		log.Error().Err(err).Str("owner_space", h.ownerSpace).Msg("Failed to initialize storage with DEK on unlock")
		return h.errorResponse(msg.GetID(), "storage initialization failed")
	}
	log.Info().Str("owner_space", h.ownerSpace).Msg("Storage initialized with DEK on unlock")

	// Restore database backup after storage initialization (cold vault only)
	if len(databaseBackup) > 0 {
		var backup storage.BackupData
		if err := json.Unmarshal(databaseBackup, &backup); err != nil {
			log.Warn().Err(err).Str("owner_space", h.ownerSpace).Msg("Failed to unmarshal database backup")
		} else {
			if err := h.storage.RestoreBackup(&backup); err != nil {
				log.Warn().Err(err).Str("owner_space", h.ownerSpace).Msg("Failed to restore database backup")
			} else {
				log.Info().Str("owner_space", h.ownerSpace).Msg("Database backup restored successfully - vault data recovered")
			}
		}
	}

	// If we have credential in memory AND it has auth hash set, verify auth hash
	// Note: DEK derivation (line 327) already validates the PIN through KMS
	// The auth hash is an additional check that may not be set for older credentials
	if storedCredential != nil && len(storedCredential.AuthHash) > 0 && len(storedCredential.AuthSalt) > 0 {
		// SECURITY: payload.PIN is already []byte (SensitiveBytes), passed directly
		if !verifyAuthHash(payload.PIN, storedCredential.AuthSalt, storedCredential.AuthHash) {
			log.Warn().Str("owner_space", h.ownerSpace).Msg("PIN auth hash verification failed (DEK derivation succeeded)")
			return h.errorResponse(msg.GetID(), "invalid PIN")
		}
		log.Debug().Str("owner_space", h.ownerSpace).Msg("PIN auth hash verification passed")
	} else if storedCredential != nil {
		// Credential exists but no auth hash - DEK derivation already validated PIN
		log.Debug().Str("owner_space", h.ownerSpace).Msg("Skipping auth hash verification (not set) - PIN validated via DEK derivation")
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
	if len(credential.AuthHash) == 0 || len(credential.AuthSalt) == 0 {
		// AuthHash was never set (pre-existing vaults enrolled before auth hash was added).
		// Verify old PIN by attempting DEK derivation (same as pin-unlock cold path).
		if sealedMaterial == nil {
			return h.errorResponse(msg.GetID(), "vault not initialized - no sealed material")
		}
		oldDEK, err := h.sealerProxy.DeriveDEKFromPIN(sealedMaterial, []byte(payload.OldPIN))
		if err != nil {
			return h.errorResponse(msg.GetID(), "invalid current PIN")
		}
		zeroBytes(oldDEK)
		log.Debug().Str("owner_space", h.ownerSpace).Msg("Old PIN verified via DEK derivation (no auth hash)")
	} else {
		if !verifyAuthHash(payload.OldPIN, credential.AuthSalt, credential.AuthHash) {
			return h.errorResponse(msg.GetID(), "invalid current PIN")
		}
		// Additional DEK derivation check
		if sealedMaterial != nil {
			// SECURITY: Pass PIN as []byte so both ends can zero it
			oldDEK, err := h.sealerProxy.DeriveDEKFromPIN(sealedMaterial, []byte(payload.OldPIN))
			if err != nil {
				return h.errorResponse(msg.GetID(), "verification failed")
			}
			zeroBytes(oldDEK)
		}
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
// msg.Payload is already unwrapped by central unwrapPayload, so it contains:
// {"encrypted_pin": "...", "ephemeral_public_key": "...", "nonce": "..."}
func (h *PINHandler) decryptMobileFormat(msg *IncomingMessage) ([]byte, error) {
	var payload struct {
		EncryptedPIN       string `json:"encrypted_pin"`
		EphemeralPublicKey string `json:"ephemeral_public_key"`
		Nonce              string `json:"nonce"`
	}
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return nil, fmt.Errorf("invalid mobile payload format: %w", err)
	}

	log.Debug().
		Str("owner_space", h.ownerSpace).
		Int("encrypted_pin_len", len(payload.EncryptedPIN)).
		Int("ephemeral_key_len", len(payload.EphemeralPublicKey)).
		Int("nonce_len", len(payload.Nonce)).
		Msg("Decrypting mobile PIN format")

	// Decode components
	ephemeralPub, err := base64.StdEncoding.DecodeString(payload.EphemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid ephemeral public key encoding: %w", err)
	}
	if len(ephemeralPub) != 32 {
		return nil, fmt.Errorf("invalid ephemeral public key length: %d", len(ephemeralPub))
	}

	nonce, err := base64.StdEncoding.DecodeString(payload.Nonce)
	if err != nil {
		return nil, fmt.Errorf("invalid nonce encoding: %w", err)
	}
	if len(nonce) != 12 {
		return nil, fmt.Errorf("invalid nonce length: %d", len(nonce))
	}

	ciphertext, err := base64.StdEncoding.DecodeString(payload.EncryptedPIN)
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

// storeRegistrationProfile stores the user's registration profile to encrypted storage
// The profile is stored as system fields with _system_ prefix, marking them as read-only
func (h *PINHandler) storeRegistrationProfile(profile *RegistrationProfile) error {
	if profile == nil {
		return nil
	}

	// Create profile handler using the PINHandler's storage
	profileHandler := NewProfileHandler(h.ownerSpace, h.storage)

	// Build fields map with _system_ prefix for read-only fields
	fields := map[string]string{
		"_system_first_name": profile.FirstName,
		"_system_last_name":  profile.LastName,
		"_system_email":      profile.Email,
		"_system_stored_at":  fmt.Sprintf("%d", currentTimestamp()),
	}

	// Create update request
	req := ProfileUpdateRequest{Fields: fields}
	payload, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal profile request: %w", err)
	}

	// Create synthetic message for the profile handler
	msg := &IncomingMessage{
		RequestID: "profile_init_" + h.ownerSpace,
		Payload:   payload,
	}

	// Store the profile fields
	resp, err := profileHandler.HandleUpdate(msg)
	if err != nil {
		return fmt.Errorf("profile update failed: %w", err)
	}

	// Check for error response
	if resp.Type == MessageTypeError {
		return fmt.Errorf("profile update error: %s", resp.Error)
	}

	return nil
}

