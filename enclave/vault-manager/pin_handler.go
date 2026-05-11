package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/vettid/vettid-dev/enclave/vault-manager/storage"
)

// PINHandler handles PIN-related operations (setup, unlock, change)
// PIN operations require the sealer proxy because DEK derivation uses KMS
type PINHandler struct {
	ownerSpace       string
	state            *VaultState
	bootstrap        *BootstrapHandler
	sealerProxy      *SealerProxy
	storage          *EncryptedStorage
	natsProxy        *NATSProxy
	migrationHandler *MigrationHandler // wired post-construction; may be nil before SetMigrationHandler
}

// NewPINHandler creates a new PIN handler
func NewPINHandler(ownerSpace string, state *VaultState, bootstrap *BootstrapHandler, sealerProxy *SealerProxy, storage *EncryptedStorage, natsProxy *NATSProxy) *PINHandler {
	return &PINHandler{
		ownerSpace:  ownerSpace,
		state:       state,
		bootstrap:   bootstrap,
		sealerProxy: sealerProxy,
		storage:     storage,
		natsProxy:   natsProxy,
	}
}

// SetMigrationHandler wires the migration handler so HandlePINUnlock
// can dispatch the M1 PIN-coupled re-seal flow when the request
// carries migrate_consent=true. Wiring is deferred because
// PINHandler is constructed before MigrationHandler in messages.go.
func (h *PINHandler) SetMigrationHandler(m *MigrationHandler) {
	h.migrationHandler = m
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

	// Compute the PIN auth hash + salt up-front so the post-unlock
	// belt-and-braces check has a known-good comparator.
	//
	// SECURITY: without this, fresh enrollments leave Auth.PinHash
	// empty until the first PIN change, which short-circuits the
	// check at HandlePINUnlock and lets a wrong PIN warm-unlock the
	// vault on a Pixel that already had a successful unlock recently
	// (sealed material is loaded, no DEK-decrypt of vault state
	// happens, KMS happily returns *some* DEK for any input). The
	// hash check below was designed to catch that case but only
	// fired after the user had changed their PIN.
	pinSetupSalt, err := generateSalt()
	if err != nil {
		return h.errorResponse(msg.GetID(), "salt generation failed")
	}
	pinSetupAuthHash := hashAuthInput([]byte(payload.PIN), pinSetupSalt)

	h.state.mu.Lock()
	h.state.sealedMaterial = sealedMaterial
	h.state.dek = dekCopy // Store DEK copy for credential.create
	// Clear any existing credential carve-outs for fresh enrollment
	// retries. This lets users retry enrollment if credential.create
	// succeeded but a later step (like finalize) failed.
	if h.state.identityPrivateKey != nil {
		zeroBytes(h.state.identityPrivateKey)
		h.state.identityPrivateKey = nil
	}
	h.state.identityPublicKey = nil
	if h.state.pinAuthHash != nil {
		zeroBytes(h.state.pinAuthHash)
	}
	if h.state.pinAuthSalt != nil {
		zeroBytes(h.state.pinAuthSalt)
	}
	h.state.pinAuthHash = pinSetupAuthHash
	h.state.pinAuthSalt = pinSetupSalt
	// Fresh enrollment: this instance "owns" the user's data from the
	// moment of pin-setup forward, so persistVaultStateToS3 is allowed
	// to write the initial state.
	h.state.vaultDataLoaded = true
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

	// Generate fresh UTKs for credential creation. Bootstrap already gave the
	// app an initial batch (HandleBootstrap), so we only return the newly
	// generated ones here to avoid duplicate entries in the app's pool.
	newPairs, err := h.bootstrap.GenerateMoreUTKs(5)
	if err != nil {
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

	// Return ONLY the freshly-generated UTKs (not the full pool).
	utkPublics := EncodeUTKPublics(newPairs)

	// Get ECIES public key for PIN unlock (this is different from the attestation key!)
	_, eciesPublic := h.bootstrap.GetECIESKeys()
	eciesPublicB64 := ""
	if eciesPublic != nil {
		eciesPublicB64 = base64.StdEncoding.EncodeToString(eciesPublic)
	}

	// Architect F4/F5 — fresh enrollment doesn't trigger
	// migrate_consent (the EnclaveUpdateRequired prompt only fires
	// when current PCR0 isn't in the user's trusted set, and a
	// fresh enrollment bootstraps trust to the running PCR0). So
	// the M1 PIN-unlock-coupled path never has a chance to write a
	// marker for these users — they'd remain "pending" forever from
	// auto-finalize's view, blocking ASG scale-down. Idempotently
	// write the marker here when a migration config is published
	// and our running PCR0 matches the config's NewPCR0.
	h.writeFreshEnrollmentMigrationMarker()

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

// writeFreshEnrollmentMigrationMarker writes the per-version migration
// marker for the currently-published migration config, if any, when the
// running enclave's PCR0 matches that config's NewPCR0. Idempotent;
// safe to call from both fresh enrollment and unlock paths.
//
// Architect F5 self-heal: even when the M1 PIN-unlock-coupled flow
// completes a re-seal, the marker write itself is non-fatal and may
// have failed (transient S3, KMS Sign hiccup). Calling this from the
// unlock path on every successful unlock recovers without operator
// intervention. Multiple writes hit the same S3 key with the same
// content — no extra cost, no race.
func (h *PINHandler) writeFreshEnrollmentMigrationMarker() {
	if h.migrationHandler == nil {
		return
	}
	cfg, _, err := h.migrationHandler.fetchAndVerifyMigrationConfig()
	if err != nil || cfg == nil || cfg.Version == "" {
		return
	}
	runningPCR0, err := h.sealerProxy.GetRunningPCR0()
	if err != nil || runningPCR0 == "" {
		return
	}
	if runningPCR0 != cfg.NewPCRs.PCR0 {
		// We're on OLD enclave. The user hasn't actually migrated to
		// the new version — don't claim they have. The M1 dispatch
		// will write the marker after re-seal lands on a NEW
		// instance (or, post-finalize, this branch goes away).
		return
	}
	if err := h.sealerProxy.WriteMigrationMarker(cfg.Version); err != nil {
		log.Warn().Err(err).Str("owner_space", h.ownerSpace).Str("version", cfg.Version).Msg("Migration marker write failed (non-fatal — will retry on next unlock)")
		return
	}
	log.Info().Str("owner_space", h.ownerSpace).Str("version", cfg.Version).Msg("Migration marker written (fresh enrollment / self-heal)")
}

// restoreCredentialCarveOuts decrypts the CEK-sealed credential blob
// from `credential/sealed_blob` and populates vaultState's narrow
// carve-outs (identity keypair, PIN auth hash + salt). Used by the
// cold-unlock path to fix the Phase D refactor gap where the credential
// plaintext was moved out of the persisted vault state but the cold-load
// restore was never updated to read the sealed blob back. Without this,
// every cold-unlock leaves identityPublicKey empty and the user's own
// profile preview shows "..." for the identity public key, while peer
// broadcasts omit public_key entirely.
//
// Best-effort: any failure (no blob, missing CEK, decrypt error) leaves
// vaultState as-is and logs a warning. The unlock itself is not
// invalidated — non-warm vaults still satisfy the PIN check via DEK
// decryption of vault_state.enc earlier in the flow.
func (h *PINHandler) restoreCredentialCarveOuts() {
	if h.storage == nil {
		return
	}
	sealed, err := h.storage.Get("credential/sealed_blob")
	if err != nil || len(sealed) == 0 {
		log.Debug().Str("owner_space", h.ownerSpace).Msg("No credential/sealed_blob to restore (legacy or pre-credential-create unlock)")
		return
	}

	// Pull the CEK private key from the just-restored vaultState.
	h.state.mu.RLock()
	cekPair := h.state.cekPair
	h.state.mu.RUnlock()
	if cekPair == nil || len(cekPair.PrivateKey) == 0 {
		log.Warn().Str("owner_space", h.ownerSpace).Msg("restoreCredentialCarveOuts: CEK not loaded — skipping (warm vault?)")
		return
	}

	// The blob is stored as base64-encoded ECIES ciphertext (matching
	// what credential_secret_handler / authenticate.go decode).
	encBytes, err := base64.StdEncoding.DecodeString(string(sealed))
	if err != nil {
		log.Warn().Err(err).Str("owner_space", h.ownerSpace).Msg("restoreCredentialCarveOuts: invalid base64 in sealed blob")
		return
	}
	plaintext, err := decryptWithCEK(cekPair.PrivateKey, encBytes)
	if err != nil {
		log.Warn().Err(err).Str("owner_space", h.ownerSpace).Msg("restoreCredentialCarveOuts: CEK decrypt failed")
		return
	}
	defer zeroBytes(plaintext)

	var cred ProteanCredentialV2
	if err := json.Unmarshal(plaintext, &cred); err != nil {
		log.Warn().Err(err).Str("owner_space", h.ownerSpace).Msg("restoreCredentialCarveOuts: credential unmarshal failed")
		return
	}

	h.state.mu.Lock()
	h.state.identityPrivateKey = append([]byte(nil), cred.Identity.PrivateKey...)
	h.state.identityPublicKey = append([]byte(nil), cred.Identity.PublicKey...)
	h.state.pinAuthHash = append([]byte(nil), cred.Auth.PinHash...)
	h.state.pinAuthSalt = append([]byte(nil), cred.Auth.PinSalt...)
	h.state.identityKeyExpiresAt = time.Now().Unix() + loadSessionTTLSeconds(h.storage)
	h.state.mu.Unlock()

	// Persist identity_public_key as a storage fallback for
	// BuildPublishedProfile. Must be base64-encoded — the fallback
	// reads via `string(pkData)` and broadcasts whatever comes out.
	// Raw bytes here would render as garbled characters on the
	// peer's connection-detail view.
	pkB64 := base64.StdEncoding.EncodeToString(cred.Identity.PublicKey)
	if err := h.storage.Put("identity_public_key", []byte(pkB64)); err != nil {
		log.Debug().Err(err).Str("owner_space", h.ownerSpace).Msg("restoreCredentialCarveOuts: identity_public_key fallback write failed (non-fatal)")
	}

	cred.SecureErase()
	log.Info().Str("owner_space", h.ownerSpace).Int("id_pub_len", len(h.state.identityPublicKey)).Msg("Credential carve-outs restored from credential/sealed_blob")
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
	if err := unmarshalRequest(msg.Payload, &req, "HandlePINUnlock"); err != nil {
		log.Error().Err(err).Str("payload", string(msg.Payload)).Msg("Failed to unmarshal PIN unlock request")
		return h.errorResponse(msg.GetID(), "invalid request format")
	}

	log.Debug().Str("owner_space", h.ownerSpace).Str("utk_id", req.UTKID).Msg("DEBUG: Parsed PIN unlock request")

	// Check if vault is warm (has ECIES keys in memory)
	h.state.mu.RLock()
	eciesPrivateKey := h.state.eciesPrivateKey
	sealedMaterial := h.state.sealedMaterial
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

	// Validate UTK — warn if not found but don't reject.
	// After instance refresh, vault_state may have stale UTKs while the phone
	// has newer ones. The real security check is DEK derivation from PIN + KMS-sealed material.
	_, found := h.bootstrap.GetLTKForUTK(req.UTKID)
	if !found {
		log.Warn().Str("utk_id", req.UTKID).Bool("warm_vault", isWarmVault).Str("owner_space", h.ownerSpace).Msg("UTK not found — proceeding with PIN unlock (DEK derivation is the real auth)")
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

			// Record the size of what we just loaded so the shrink guard
			// in persistVaultStateToS3 has a reference for "this instance
			// previously knew the state was N bytes." See architect §3
			// storage invariants.
			h.state.mu.Lock()
			h.state.loadedVaultStateSize = int64(len(encryptedStateBytes))
			h.state.mu.Unlock()

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
				Credential     *ProteanCredentialV2 `json:"credential,omitempty"`
				SealedMaterial []byte               `json:"sealed_material"`
				DatabaseBackup json.RawMessage      `json:"database_backup,omitempty"`
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
			// Skip used-UTK tombstones from legacy state blobs. Current
			// vaults remove pairs on MarkUTKUsed, but older persisted state
			// in S3 may still carry them.
			h.state.utkPairs = nil
			for _, utk := range persistedState.UTKPairs {
				if utk.UsedAt != 0 {
					continue
				}
				h.state.utkPairs = append(h.state.utkPairs, &UTKPair{
					ID:        utk.ID,
					UTK:       utk.UTK,
					LTK:       utk.LTK,
					UsedAt:    utk.UsedAt,
					CreatedAt: utk.CreatedAt,
				})
			}
			if persistedState.Credential != nil {
				// Phase D: pull narrow carve-outs from V2 credential
				// (identity keypair + PIN verifier) into vaultState
				// and then drop the full struct. Nothing else needs
				// the credential plaintext in memory.
				h.state.identityPrivateKey = append([]byte(nil), persistedState.Credential.Identity.PrivateKey...)
				h.state.identityPublicKey = append([]byte(nil), persistedState.Credential.Identity.PublicKey...)
				h.state.pinAuthHash = append([]byte(nil), persistedState.Credential.Auth.PinHash...)
				h.state.pinAuthSalt = append([]byte(nil), persistedState.Credential.Auth.PinSalt...)
				// Phase E: gate identity-key signing on a user-configurable
				// sliding TTL (settings.credential.session_ttl_seconds).
				// PIN unlock starts the window; subsequent signed ops slide
				// it forward via consumeIdentityKey().
				h.state.identityKeyExpiresAt = time.Now().Unix() + loadSessionTTLSeconds(h.storage)
				// Self-heal: persist identity public key as a storage
				// fallback so BuildPublishedProfile can find it even
				// from instances that haven't loaded the credential
				// carve-out yet (multi-instance migration window).
				// Existing users enrolled before this lands need a
				// PIN-unlock to populate the fallback.
				// Base64-encoded form for the fallback path; raw bytes
				// would be misinterpreted as a UTF-8 string by
				// BuildPublishedProfile and rendered as garbled output
				// on the peer-side connection detail.
				pkB64 := base64.StdEncoding.EncodeToString(persistedState.Credential.Identity.PublicKey)
				if err := h.storage.Put("identity_public_key", []byte(pkB64)); err != nil {
					log.Warn().Err(err).Str("owner_space", h.ownerSpace).Msg("Failed to persist identity_public_key fallback at cold-load (non-fatal)")
				}
				persistedState.Credential.SecureErase()
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

	// Store DEK in vault state so persistVaultStateToS3 and vault_locked checks work.
	// Also flag that this instance has loaded the user's data — required for any
	// later persistVaultStateToS3 to actually write (see VaultState.vaultDataLoaded
	// docstring). For cold unlock the SQLite backup restore happens just below;
	// for warm unlock storage was already populated on a prior unlock.
	dekCopy := make([]byte, len(dek))
	copy(dekCopy, dek)
	h.state.mu.Lock()
	h.state.dek = dekCopy
	h.state.vaultDataLoaded = true
	h.state.mu.Unlock()

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

	// Phase D restore (gap fix, 2026-05-10): the encrypted vault state
	// no longer carries the credential plaintext (createEncryptedVaultState
	// in messages.go declares the field as `omitempty` but never
	// populates it — the comment there says "PIN unlock reads it back
	// from `credential/sealed_blob`"). The cold-load path here was
	// updated to consult persistedState.Credential, but never to read
	// the sealed blob from storage. Net effect: every cold-unlock left
	// vaultState.identityPublicKey + identityPrivateKey + pinAuthHash
	// + pinAuthSalt empty. Symptoms: own profile preview rendered "..."
	// for the identity public key; profile broadcasts went out without
	// public_key; warm-vault auth fell back to the hash-empty branch
	// (which currently lets unlock through on cold-via-DEK proof).
	//
	// Restore the carve-outs here. Storage is initialized + backup
	// restored above, so credential/sealed_blob is readable. We CEK-
	// decrypt with the just-restored CEK pair.
	//
	// Two-tier fallback: the block ~80 lines above (line 599-622)
	// ALREADY populates the same carve-outs from
	// persistedState.Credential when present (legacy vault_state.enc
	// blobs from the pre-Phase-D era still carry that field).
	// restoreCredentialCarveOuts is the fallback for the
	// post-Phase-D case where persistedState.Credential is nil and
	// the carve-outs must come from credential/sealed_blob. Both
	// paths populate the SAME vaultState fields with the SAME data;
	// running the fallback after the primary is harmless (it just
	// re-reads + re-writes the same bytes). When both vaults
	// migrate off the legacy format the primary path will become
	// dead code.
	if !isWarmVault {
		h.restoreCredentialCarveOuts()
	}

	// Verify the PIN against the carve-out auth hash.
	//
	// SECURITY: in cold-unlock, DEK decryption of the persisted vault
	// state at line 377 already proved the PIN was right (a wrong DEK
	// can't decrypt). In warm-unlock no decrypt happens — the only
	// gate left is this hash check, so it MUST be present. If the
	// carve-out is empty in warm mode, fail closed: the user's
	// credential was minted before PIN-setup hash stamping landed and
	// needs to be re-enrolled. Letting them through would let any
	// random PIN warm-unlock the vault.
	h.state.mu.RLock()
	pinAuthHash := append([]byte(nil), h.state.pinAuthHash...)
	pinAuthSalt := append([]byte(nil), h.state.pinAuthSalt...)
	h.state.mu.RUnlock()
	if len(pinAuthHash) > 0 && len(pinAuthSalt) > 0 {
		if !verifyAuthHash(payload.PIN, pinAuthSalt, pinAuthHash) {
			log.Warn().Str("owner_space", h.ownerSpace).Msg("PIN auth hash verification failed")
			return h.errorResponse(msg.GetID(), "invalid PIN")
		}
		log.Debug().Str("owner_space", h.ownerSpace).Msg("PIN auth hash verification passed")
	} else if isWarmVault {
		log.Warn().Str("owner_space", h.ownerSpace).Msg("Warm-unlock attempted but no PIN hash on record — refusing to accept the PIN unverified")
		return h.errorResponse(msg.GetID(), "vault needs re-enrollment (no PIN hash stored)")
	} else {
		log.Debug().Str("owner_space", h.ownerSpace).Msg("Cold-unlock proved PIN via DEK-decrypt; skipping hash check (carve-out empty)")
	}

	// M1: PIN-coupled migration dispatch. Runs only after PIN has been
	// proven (above). Failures here never invalidate the unlock — the
	// user is auth'd; we just report what happened in migration_status.
	migrationStatus, migrationVersion := h.dispatchMigrateConsent(ctx, req.MigrateConsent)

	// Architect F5 self-heal: write the migration marker on every
	// successful unlock when the running PCR0 matches the published
	// config's NewPCR0. Idempotent. Recovers from cases where the
	// initial M1 dispatch's marker write failed (transient S3 / KMS
	// hiccup), AND covers fresh enrollments that never trigger
	// migrate_consent (current PCR0 already trusted, no
	// EnclaveUpdateRequired prompt).
	h.writeFreshEnrollmentMigrationMarker()

	// Generate more UTKs and return ONLY those to the app.
	// Returning GetUnusedUTKs() here caused the app pool to balloon to ~14k
	// entries because it appended the full vault pool on every unlock.
	newPairs, err := h.bootstrap.GenerateMoreUTKs(3)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to generate new UTKs")
	}

	response := PINUnlockResponse{
		Status:           "unlocked",
		NewUTKs:          EncodeUTKs(newPairs),
		MigrationStatus:  migrationStatus,
		MigrationVersion: migrationVersion,
	}

	// SECURITY: Issue full NATS credentials from the vault.
	// The vault is the sole authority for full OwnerSpace/MessageSpace access.
	// Lambda can only issue narrow bootstrap credentials for PIN unlock.
	accountSeed := h.loadAccountSeed()
	if accountSeed != "" {
		credsFile, err := GenerateFullAppCredentials(
			accountSeed,
			"OwnerSpace."+h.ownerSpace,
			"MessageSpace."+h.ownerSpace,
			time.Now().Add(7*24*time.Hour),
		)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to generate NATS credentials - continuing without")
		} else {
			response.NatsCredentials = credsFile
			response.NatsEndpoint = h.natsProxy.GetNATSEndpoint()
			response.OwnerSpace = "OwnerSpace." + h.ownerSpace
			response.MessageSpace = "MessageSpace." + h.ownerSpace
			response.CredentialsTTL = 7 * 24 * 3600 // 7 days
			log.Info().Str("owner_space", h.ownerSpace).Msg("Vault-issued NATS credentials included in PIN unlock response")
		}
	} else {
		log.Warn().Str("owner_space", h.ownerSpace).Msg("Account seed unavailable - PIN unlock response without NATS credentials")
	}

	// Phase D: pass through the CEK-sealed credential blob from
	// storage instead of re-encrypting an in-memory plaintext (which
	// is no longer cached). The blob is what subsequent password-
	// gated ops (wallet.create, credential.secret.add, etc.) supply
	// back to the enclave for per-op decrypt.
	if sealed, err := h.storage.Get("credential/sealed_blob"); err == nil && len(sealed) > 0 {
		response.EncryptedCredential = string(sealed)
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

// loadAccountSeed loads the NATS account seed using a 3-tier strategy:
// 1. In-memory cache (NATSProxy)
// 2. Encrypted vault storage
// 3. DynamoDB + KMS via sealer proxy (parent process)
// Returns empty string if unavailable (credential generation will be skipped).
func (h *PINHandler) loadAccountSeed() string {
	// Tier 1: Check in-memory cache
	if h.natsProxy.HasAccountSeed() {
		return h.natsProxy.GetAccountSeed()
	}

	// Tier 2: Check encrypted vault storage (may fail on cold start before DEK init)
	if h.storage != nil {
		seedData, err := h.storage.Get("nats_account_seed")
		if err == nil && len(seedData) > 0 {
			h.natsProxy.SetAccountSeed(string(seedData))
			return string(seedData)
		}
	}

	// Tier 3: Load via sealer proxy (DynamoDB + KMS through parent)
	seed, err := h.sealerProxy.LoadAccountSeed()
	if err != nil {
		log.Warn().Err(err).Msg("Failed to load account seed via sealer proxy")
		return ""
	}
	if seed == "" {
		log.Warn().Msg("Account seed not found in DynamoDB")
		return ""
	}

	// Cache for future use
	h.natsProxy.SetAccountSeed(seed)
	if h.storage != nil {
		if storeErr := h.storage.Put("nats_account_seed", []byte(seed)); storeErr != nil {
			log.Warn().Err(storeErr).Msg("Failed to cache account seed in vault storage")
		}
	}

	return seed
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
	if err := unmarshalRequest(msg.Payload, &req, "HandlePINChange"); err != nil {
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
	pinAuthHash := append([]byte(nil), h.state.pinAuthHash...)
	pinAuthSalt := append([]byte(nil), h.state.pinAuthSalt...)
	cekPair := h.state.cekPair
	h.state.mu.RUnlock()

	if eciesPrivateKey == nil {
		return h.errorResponse(msg.GetID(), "vault not initialized")
	}
	if cekPair == nil {
		return h.errorResponse(msg.GetID(), "CEK not available")
	}
	if req.EncryptedCredential == "" {
		return h.errorResponse(msg.GetID(), "encrypted_credential is required")
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

	// Verify old PIN — Phase D reads from the auth carve-out
	// (populated at PIN unlock) instead of the full credential.
	if len(pinAuthHash) == 0 || len(pinAuthSalt) == 0 {
		// Auth hash was never set (pre-existing vaults enrolled before
		// auth hash was added). Fall back to DEK-derivation: getting
		// the same DEK back proves PIN knowledge.
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
		if !verifyAuthHash(payload.OldPIN, pinAuthSalt, pinAuthHash) {
			return h.errorResponse(msg.GetID(), "invalid current PIN")
		}
		// Additional DEK derivation check
		if sealedMaterial != nil {
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

	// Update credential auth hash
	newSalt, err := generateSalt()
	if err != nil {
		zeroBytes(newDEK)
		return h.errorResponse(msg.GetID(), "salt generation failed")
	}
	// SECURITY: payload.NewPIN is already []byte (SensitiveBytes)
	newAuthHash := hashAuthInput(payload.NewPIN, newSalt)

	// SECURITY: Persist sealed material to S3 BEFORE updating in-memory state.
	// This ensures that if the persist fails, the in-memory DEK stays consistent
	// with the sealed material in S3 (both still use old PIN). Otherwise,
	// persistVaultStateToS3() would encrypt with the new DEK while S3 still has
	// old sealed material, making the vault unrecoverable on cold restart.
	if err := h.sealerProxy.StoreSealedMaterial(newSealedMaterial); err != nil {
		log.Error().Err(err).Str("owner_space", h.ownerSpace).Msg("Failed to store new sealed material to S3 - PIN change aborted")
		zeroBytes(newDEK)
		return h.errorResponse(msg.GetID(), "failed to persist PIN change - please try again")
	}
	log.Info().Str("owner_space", h.ownerSpace).Msg("New sealed material stored to S3 for cold vault recovery")

	// SECURITY: Update DEK, sealed material, and credential atomically.
	// The DEK must be updated so that persistVaultStateToS3() encrypts with the
	// new DEK matching the new sealed material. Without this, cold vault recovery
	// would fail because the vault state would be encrypted with the old DEK while
	// the sealed material expects the new PIN.
	newDEKCopy := make([]byte, len(newDEK))
	copy(newDEKCopy, newDEK)

	// Decrypt the request-supplied credential blob with CEK, swap
	// the PIN auth fields (Auth.PinHash + Auth.PinSalt), bump Version,
	// re-encrypt with CEK, ship the new blob back to the app. The
	// password's Auth.Hash is untouched.
	encBlobBytes, err := base64.StdEncoding.DecodeString(req.EncryptedCredential)
	if err != nil {
		return h.errorResponse(msg.GetID(), "invalid encrypted_credential encoding")
	}
	credPlain, err := decryptWithCEK(cekPair.PrivateKey, encBlobBytes)
	if err != nil {
		log.Warn().Err(err).Str("owner_space", h.ownerSpace).Msg("HandlePINChange: failed to decrypt credential blob")
		return h.errorResponse(msg.GetID(), "credential decrypt failed")
	}
	defer zeroBytes(credPlain)
	var credForChange ProteanCredentialV2
	if err := json.Unmarshal(credPlain, &credForChange); err != nil {
		return h.errorResponse(msg.GetID(), "credential parse failed")
	}
	if credForChange.FormatVersion < 2 {
		return h.errorResponse(msg.GetID(), fmt.Sprintf("unsupported credential format version: %d", credForChange.FormatVersion))
	}
	defer credForChange.SecureErase()
	credForChange.Auth.PinHash = newAuthHash
	credForChange.Auth.PinSalt = newSalt
	credForChange.Timestamps.LastModified = time.Now().Unix()
	credForChange.Timestamps.AuthChangedAt = credForChange.Timestamps.LastModified
	credForChange.Version++

	h.state.mu.Lock()
	oldDEKRef := h.state.dek
	h.state.pinAuthHash = append([]byte(nil), newAuthHash...)
	h.state.pinAuthSalt = append([]byte(nil), newSalt...)
	h.state.sealedMaterial = newSealedMaterial
	h.state.dek = newDEKCopy
	h.state.mu.Unlock()

	if oldDEKRef != nil {
		zeroBytes(oldDEKRef)
	}

	// Re-encrypt credential with CEK (not DEK) and return to client.
	// The app-side blob is always CEK-encrypted — every other handler
	// that decrypts this blob calls decryptWithCEK. Re-encrypting with
	// the new DEK shipped a blob the rest of the system couldn't read,
	// which forced the app to silently keep its pre-change blob and
	// drift out of sync with the vault on AuthHash/AuthSalt.
	credBytes, err := json.Marshal(&credForChange)
	if err != nil {
		return h.errorResponse(msg.GetID(), "serialization failed")
	}
	defer zeroBytes(credBytes)

	encryptedCred, err := encryptWithCEK(cekPair.PublicKey, credBytes)
	// SECURITY: Zero the local newDEK copy now that we no longer need it
	// for blob encryption. h.state.dek already holds newDEKCopy for
	// vault-state persistence.
	zeroBytes(newDEK)
	if err != nil {
		return h.errorResponse(msg.GetID(), "encryption failed")
	}

	// Generate fresh UTKs and return ONLY the new ones (not the full pool).
	newPairs, err := h.bootstrap.GenerateMoreUTKs(5)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to generate new UTKs")
	}

	response := PINChangeResponse{
		Status:              "pin_changed",
		EncryptedCredential: base64.StdEncoding.EncodeToString(encryptedCred),
		NewUTKs:             EncodeUTKs(newPairs),
	}

	responseBytes, err := json.Marshal(response)
	if err != nil {
		return h.errorResponse(msg.GetID(), "response serialization failed")
	}

	log.Info().
		Str("owner_space", h.ownerSpace).
		Int("credential_version", credForChange.Version).
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

// dispatchMigrateConsent implements the M1 PIN-coupled migration flow.
// Called from HandlePINUnlock after the PIN has been proven (DEK derive
// + auth-hash verify). Returns (status, version) for the response.
//
// Branches:
//   - migrate_consent=false (or no migration handler wired): "" / ""
//   - no published / verifiable migration config: "not_requested"
//   - running_pcr0 == config.NewPCR0: re-seal + write marker → "completed"
//   - running_pcr0 != config.NewPCR0: emit routing handoff → "pending_new_enclave"
//
// SECURITY invariant: regardless of branch, this function never calls
// persistVaultStateToS3, never returns an error to the caller, and
// never invalidates the successful unlock above. The unlock has
// already happened; migration is best-effort tacked on. App reports
// the result as a hint; failure just means user retries next session.
func (h *PINHandler) dispatchMigrateConsent(ctx context.Context, consent bool) (string, string) {
	if !consent {
		return "", ""
	}
	if h.migrationHandler == nil {
		log.Warn().Str("owner_space", h.ownerSpace).Msg("migrate_consent received but no migration handler wired")
		return "not_requested", ""
	}

	verifiedConfig, _, err := h.migrationHandler.fetchAndVerifyMigrationConfig()
	if err != nil {
		log.Warn().Err(err).Str("owner_space", h.ownerSpace).Msg("migrate_consent: config verification failed; treating as not_requested")
		return "not_requested", ""
	}
	if verifiedConfig == nil {
		log.Debug().Str("owner_space", h.ownerSpace).Msg("migrate_consent: no migration config published; nothing to do")
		return "not_requested", ""
	}

	runningPCR0, err := h.sealerProxy.GetRunningPCR0()
	if err != nil {
		log.Warn().Err(err).Str("owner_space", h.ownerSpace).Msg("migrate_consent: could not read running PCR0; treating as not_requested")
		return "not_requested", ""
	}

	configVersion := verifiedConfig.Version
	newPCR0 := verifiedConfig.NewPCRs.PCR0

	// Branch B (architect M1): request landed on the OLD enclave. Don't
	// re-seal — only NEW can produce NEW-bound ciphertext. Emit a
	// routing handoff so NEW reclaims the user, return
	// pending_new_enclave so the app retries.
	if runningPCR0 != newPCR0 {
		log.Info().
			Str("owner_space", h.ownerSpace).
			Str("running_pcr0", runningPCR0).
			Str("new_pcr0", newPCR0).
			Msg("migrate_consent: landed on OLD enclave; emitting routing handoff for NEW reclaim")
		if h.migrationHandler.sendToParent != nil && newPCR0 != "" {
			handoffMsg := &OutgoingMessage{
				Type:             MessageTypeRoutingHandoff,
				OwnerSpace:       h.ownerSpace,
				TargetInstanceID: "",
				NewPCR0:          newPCR0,
			}
			if err := h.migrationHandler.sendToParent(handoffMsg); err != nil {
				log.Warn().Err(err).Str("owner_space", h.ownerSpace).Msg("routing handoff failed (non-fatal — lease expiry covers it)")
			}
		}
		return "pending_new_enclave", configVersion
	}

	// Branch A (architect M1): we are NEW. Re-seal inline.
	//
	// resealMaterial is idempotent: if the wrapper's SealedToPCR0
	// already equals our running PCR0, it returns nil without burning
	// KMS quota. That handles the F4/F5 partial-failure recovery case
	// where re-seal succeeded on a previous unlock but the marker
	// write didn't land — we still write the marker below.
	log.Info().
		Str("owner_space", h.ownerSpace).
		Str("running_pcr0", runningPCR0).
		Str("version", configVersion).
		Msg("migrate_consent: re-sealing on NEW enclave")

	if err := h.migrationHandler.resealMaterial(ctx, configVersion); err != nil {
		log.Error().Err(err).Str("owner_space", h.ownerSpace).Msg("inline re-seal failed; user remains on OLD-bound material")
		return "failed", configVersion
	}

	// resealECIES has no idempotency guard (the format is raw KMS
	// ciphertext, no wrapper to inspect) but unseal+reseal under the
	// AnyOf KMS policy is harmless on either branch. Failure is
	// non-fatal because the user can re-derive ECIES from scratch on
	// next unlock.
	if err := h.migrationHandler.resealECIES(ctx); err != nil {
		log.Warn().Err(err).Str("owner_space", h.ownerSpace).Msg("inline ECIES re-seal failed (non-fatal)")
	}

	// Marker write intentionally NOT done here. HandlePINUnlock's
	// next step calls writeFreshEnrollmentMigrationMarker (F5
	// self-heal) which does exactly the same WriteMigrationMarker
	// call with the same preconditions (config verified + running
	// PCR0 == NewPCR0). Doing it twice produced two KMS Sign + two
	// S3 PUT per unlock for no benefit. F5 is the single canonical
	// marker-writer; if its write fails, the next unlock retries
	// naturally because F5 fires on every successful unlock that
	// matches the gate.

	// Audit entry on the system connection so the user has a history
	// row for this update. Mirrors the legacy HandleStart behavior.
	if h.migrationHandler.auditLog != nil {
		title := "Vault security update applied"
		if configVersion != "" {
			title = title + " (" + configVersion + ")"
		}
		refs := map[string]string{}
		if configVersion != "" {
			refs["version"] = configVersion
		}
		h.migrationHandler.auditLog.AppendSystem(AuditEntry{
			EventType: AuditTypeSystemMigrationFinalized,
			Title:     title,
			Body:      "The vault has been re-sealed for the new enclave version.",
			Refs:      refs,
		})
	}

	log.Info().
		Str("owner_space", h.ownerSpace).
		Str("version", configVersion).
		Msg("migrate_consent: re-seal completed inline with PIN unlock")
	return "completed", configVersion
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
	if err := unmarshalRequest(msg.Payload, &payload, "decryptMobileFormat"); err != nil {
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

