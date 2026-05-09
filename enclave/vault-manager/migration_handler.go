package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/vettid/vettid-dev/enclave/migration"
)

// MigrationHandler handles migration-related NATS operations.
// Provides status checks, acknowledgments, and emergency recovery for migrated users.
type MigrationHandler struct {
	ownerSpace   string
	storage      *EncryptedStorage
	vaultState   *VaultState
	sealerProxy  *SealerProxy
	auditLog     *AuditLog
	sendToParent func(msg *OutgoingMessage) error // callback to emit routing-handoff to parent

	// pcrSigningPublicKey is the DER-encoded SPKI bytes for the
	// migration-config signing key. Lazily fetched from the parent
	// (KMS GetPublicKey) on first use; cached for the process
	// lifetime since the public material only changes on KMS-key
	// rotation, which requires redeploy.
	pcrPubKeyMu        sync.Mutex
	pcrSigningPublicDER []byte
}

// SetAuditLog wires the per-connection audit trail so migration
// required/finalized events land on the VettID system connection.
func (h *MigrationHandler) SetAuditLog(a *AuditLog) { h.auditLog = a }

// NewMigrationHandler creates a new migration handler.
func NewMigrationHandler(
	ownerSpace string,
	storage *EncryptedStorage,
	vaultState *VaultState,
	sealerProxy *SealerProxy,
) *MigrationHandler {
	return &MigrationHandler{
		ownerSpace:  ownerSpace,
		storage:     storage,
		vaultState:  vaultState,
		sealerProxy: sealerProxy,
	}
}

// SetSendToParent wires the callback used to emit routing-handoff
// messages after a successful migration. The message tells parent to
// release ownership in the `vault-routing` KV bucket so an instance
// attesting to the new PCR can take over.
func (h *MigrationHandler) SetSendToParent(fn func(msg *OutgoingMessage) error) {
	h.sendToParent = fn
}

// fetchAndVerifyMigrationConfig fetches the migration config from S3
// AND verifies its ECDSA signature against the KMS-managed signing
// key before returning the parsed struct. This is the single chokepoint
// every migration code path goes through — there is no path that
// trusts the config based on shape alone.
//
// Returns (nil, nil) when no migration config exists on S3 (the
// normal "no update available" case).
//
// SECURITY: bypassing this and reading FetchMigrationConfig directly
// would re-introduce the unsigned-overwrite vulnerability where an
// attacker with S3 write access could direct the enclave at a
// PCR0 they control. Don't.
func (h *MigrationHandler) fetchAndVerifyMigrationConfig() (*migration.SignedPCRConfig, []byte, error) {
	configData, err := h.sealerProxy.FetchMigrationConfig()
	if err != nil {
		return nil, nil, err
	}
	if len(configData) == 0 {
		return nil, nil, nil
	}

	// Lazy-load + cache the signing public key.
	h.pcrPubKeyMu.Lock()
	if len(h.pcrSigningPublicDER) == 0 {
		der, kerr := h.sealerProxy.FetchPCRSigningPublicKey()
		if kerr != nil {
			h.pcrPubKeyMu.Unlock()
			return nil, nil, fmt.Errorf("fetch pcr signing public key: %w", kerr)
		}
		h.pcrSigningPublicDER = der
	}
	pubKey := h.pcrSigningPublicDER
	h.pcrPubKeyMu.Unlock()

	parsed, err := migration.ParseSignedPCRConfig(configData)
	if err != nil {
		return nil, nil, fmt.Errorf("parse migration config: %w", err)
	}

	// Verify signature + time-window. We can't verify OldPCRs match
	// the running enclave from inside vault-manager (it doesn't have
	// direct NSM access; PCR plumbing through the supervisor is a
	// future hardening). The signature + ValidFrom/ExpiresAt window
	// reject the F1 attack outright since an attacker without the
	// KMS signing key cannot mint a config that passes ECDSA verify.
	verifier, err := migration.NewSignatureOnlyVerifier(pubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("init verifier: %w", err)
	}
	if err := verifier.VerifySignatureAndTime(parsed); err != nil {
		log.Warn().Err(err).Str("owner_space", h.ownerSpace).Msg("Migration config rejected — signature/time-window verification failed")
		return nil, nil, fmt.Errorf("migration config verification failed: %w", err)
	}

	return parsed, configData, nil
}

// MigrationUserStatus represents the status of a user's migration.
type MigrationUserStatus string

const (
	MigrationUserStatusNone                      MigrationUserStatus = "none"
	MigrationUserStatusInProgress                MigrationUserStatus = "in_progress"
	MigrationUserStatusComplete                  MigrationUserStatus = "complete"
	MigrationUserStatusEmergencyRecoveryRequired MigrationUserStatus = "emergency_recovery_required"
)

// MigrationStatusResponse is the response for migration.status requests.
type MigrationStatusResponse struct {
	Status         MigrationUserStatus `json:"status"`
	MigratedAt     *time.Time          `json:"migrated_at,omitempty"`
	UserNotified   bool                `json:"user_notified"`
	FromPCRVersion string              `json:"from_pcr_version,omitempty"`
	ToPCRVersion   string              `json:"to_pcr_version,omitempty"`
}

// MigrationState is stored per-user to track their migration status.
type MigrationState struct {
	Status           MigrationUserStatus `json:"status"`
	MigratedAt       *time.Time          `json:"migrated_at,omitempty"`
	UserNotified     bool                `json:"user_notified"`
	UserAcknowledged bool                `json:"user_acknowledged"`
	AcknowledgedAt   *time.Time          `json:"acknowledged_at,omitempty"`
	FromPCRVersion   string              `json:"from_pcr_version,omitempty"`
	ToPCRVersion     string              `json:"to_pcr_version,omitempty"`
}

const migrationStateKey = "migration_state"

// HandleStatus handles credential.migration.status requests.
// Returns the current migration status for the user.
func (h *MigrationHandler) HandleStatus(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	log.Debug().
		Str("owner_space", h.ownerSpace).
		Msg("Handling migration.status request")

	// Load migration state from storage
	state, err := h.loadMigrationState(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("No migration state found, assuming none")
		state = &MigrationState{
			Status: MigrationUserStatusNone,
		}
	}

	resp := MigrationStatusResponse{
		Status:         state.Status,
		MigratedAt:     state.MigratedAt,
		UserNotified:   state.UserNotified,
		FromPCRVersion: state.FromPCRVersion,
		ToPCRVersion:   state.ToPCRVersion,
	}

	respBytes, _ := json.Marshal(resp)
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// AcknowledgeRequest is the request format for migration.acknowledge.
type AcknowledgeRequest struct {
	Acknowledged   bool  `json:"acknowledged"`
	AcknowledgedAt int64 `json:"acknowledged_at,omitempty"`
}

// AcknowledgeResponse is the response for migration.acknowledge requests.
type AcknowledgeResponse struct {
	Success bool `json:"success"`
}

// HandleAcknowledge handles credential.migration.acknowledge requests.
// Marks the user as having acknowledged the migration notification.
func (h *MigrationHandler) HandleAcknowledge(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	log.Debug().
		Str("owner_space", h.ownerSpace).
		Msg("Handling migration.acknowledge request")

	var req AcknowledgeRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleAcknowledge"); err != nil {
		return h.errorResponse(msg.GetID(), "invalid request format")
	}

	// Load existing state
	state, err := h.loadMigrationState(ctx)
	if err != nil {
		state = &MigrationState{
			Status: MigrationUserStatusNone,
		}
	}

	// Update acknowledgment
	state.UserAcknowledged = req.Acknowledged
	if req.Acknowledged {
		now := time.Now()
		if req.AcknowledgedAt > 0 {
			// Use provided timestamp if given
			ackTime := time.UnixMilli(req.AcknowledgedAt)
			state.AcknowledgedAt = &ackTime
		} else {
			state.AcknowledgedAt = &now
		}
		state.UserNotified = true
	}

	// Save state
	if err := h.saveMigrationState(ctx, state); err != nil {
		return h.errorResponse(msg.GetID(), "failed to save state")
	}

	log.Info().
		Str("owner_space", h.ownerSpace).
		Bool("acknowledged", req.Acknowledged).
		Msg("Migration acknowledgment recorded")

	resp := AcknowledgeResponse{Success: true}
	respBytes, _ := json.Marshal(resp)
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// EmergencyRecoveryRequest is the request format for emergency_recovery.
type EmergencyRecoveryRequest struct {
	EncryptedPINHash   string `json:"encrypted_pin_hash"`
	EphemeralPublicKey string `json:"ephemeral_public_key"`
	Nonce              string `json:"nonce"`
}

// EmergencyRecoveryResponse is the response for emergency_recovery requests.
type EmergencyRecoveryResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// HandleEmergencyRecovery handles credential.emergency_recovery requests.
// This is used when both old and new enclaves are unavailable.
// The user provides their PIN to re-derive the DEK.
func (h *MigrationHandler) HandleEmergencyRecovery(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	log.Info().
		Str("owner_space", h.ownerSpace).
		Msg("Handling emergency_recovery request")

	var req EmergencyRecoveryRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleEmergencyRecovery"); err != nil {
		return h.errorResponse(msg.GetID(), "invalid request format")
	}

	// Validate required fields
	if req.EncryptedPINHash == "" || req.EphemeralPublicKey == "" || req.Nonce == "" {
		return h.errorResponse(msg.GetID(), "missing required fields")
	}

	// Rate limiting check
	// TODO: Implement rate limiting for emergency recovery attempts
	// to prevent PIN brute force attacks

	// Device attestation check
	// TODO: Verify device attestation to ensure request is from legitimate device

	// Emergency recovery process:
	// 1. Decrypt PIN hash using attestation private key
	// 2. Re-derive DEK from PIN
	// 3. Verify DEK by attempting to decrypt vault data
	// 4. If successful, update vault state and mark as recovered

	// For now, return a placeholder response indicating the operation
	// is not yet fully implemented but the structure is in place
	log.Warn().
		Str("owner_space", h.ownerSpace).
		Msg("Emergency recovery requested - full implementation pending")

	// Check migration state
	state, err := h.loadMigrationState(ctx)
	if err != nil || state.Status != MigrationUserStatusEmergencyRecoveryRequired {
		return h.errorResponse(msg.GetID(), "emergency recovery not applicable")
	}

	// TODO: Implement actual PIN verification and DEK re-derivation
	// This requires:
	// 1. Decrypting the PIN hash using the attestation key
	// 2. Re-deriving the DEK using the PIN-based KDF
	// 3. Verifying the DEK works by decrypting test data
	// 4. Updating vault state with the recovered DEK

	// For now, indicate success structure (implementation in follow-up)
	resp := EmergencyRecoveryResponse{
		Success: false,
		Message: "Emergency recovery requires PIN verification - implementation pending",
	}

	respBytes, _ := json.Marshal(resp)
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// MigrationConfigResponse is returned to the app for credential.migration.config requests.
type MigrationConfigResponse struct {
	Available      bool   `json:"available"`
	Version        string `json:"version,omitempty"`
	Summary        string `json:"summary,omitempty"`
	DetailsURL     string `json:"details_url,omitempty"`
	PublishedAt    string `json:"published_at,omitempty"`
	MandatoryAfter string `json:"mandatory_after,omitempty"`
	// NewPCR0 is the PCR0 of the enclave the user is being asked to approve.
	// The app uses this to tell whether the user has already trusted this
	// enclave via the pre-PIN consent dialog, so it can skip a redundant
	// second prompt and auto-apply the migration.
	NewPCR0 string `json:"new_pcr0,omitempty"`
}

// MigrationStartResponse is returned after credential.migration.start.
type MigrationStartResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Version string `json:"version,omitempty"`
}

// HandleGetConfig handles credential.migration.config requests.
// Returns the current migration config if an update is available.
func (h *MigrationHandler) HandleGetConfig(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	log.Debug().
		Str("owner_space", h.ownerSpace).
		Msg("Handling migration.config request")

	state, _ := h.loadMigrationState(ctx)

	// Fetch + verify migration config (signature + time window). Any
	// integrity failure surfaces as "not available" — same shape as
	// the no-config case so a forged blob doesn't leak diagnostic
	// information to the caller. The detailed error is logged in
	// fetchAndVerifyMigrationConfig.
	verifiedConfig, _, err := h.fetchAndVerifyMigrationConfig()
	if err != nil || verifiedConfig == nil {
		resp := MigrationConfigResponse{Available: false}
		respBytes, _ := json.Marshal(resp)
		return &OutgoingMessage{
			RequestID: msg.GetID(),
			Type:      MessageTypeResponse,
			Payload:   respBytes,
		}, nil
	}

	// User already migrated to THIS published version — nothing to do.
	if state != nil && state.Status == MigrationUserStatusComplete && state.ToPCRVersion == verifiedConfig.Version {
		resp := MigrationConfigResponse{Available: false}
		respBytes, _ := json.Marshal(resp)
		return &OutgoingMessage{
			RequestID: msg.GetID(),
			Type:      MessageTypeResponse,
			Payload:   respBytes,
		}, nil
	}

	log.Info().
		Str("owner_space", h.ownerSpace).
		Str("version", verifiedConfig.Version).
		Msg("Migration config available for user")

	publishedAt := ""
	if !verifiedConfig.PublishedAt.IsZero() {
		publishedAt = verifiedConfig.PublishedAt.Format(time.RFC3339)
	}
	mandatoryAfter := ""
	if !verifiedConfig.MandatoryAfter.IsZero() {
		mandatoryAfter = verifiedConfig.MandatoryAfter.Format(time.RFC3339)
	}
	resp := MigrationConfigResponse{
		Available:      true,
		Version:        verifiedConfig.Version,
		Summary:        verifiedConfig.Summary,
		DetailsURL:     verifiedConfig.DetailsURL,
		PublishedAt:    publishedAt,
		MandatoryAfter: mandatoryAfter,
		NewPCR0:        verifiedConfig.NewPCRs.PCR0,
	}

	respBytes, _ := json.Marshal(resp)
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleStart handles credential.migration.start requests.
// Unseals current sealed material and ECIES keys, re-seals them (KMS Encrypt
// without attestation), and stores the new versions. The new sealed blobs can
// be decrypted by any enclave whose PCR0 is in the KMS key policy.
func (h *MigrationHandler) HandleStart(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	log.Info().
		Str("owner_space", h.ownerSpace).
		Msg("Handling migration.start request — re-sealing vault for new enclave")

	// Check current migration state. Only short-circuit when the user already
	// migrated to the CURRENTLY-published version; a new published version
	// should re-run migration.
	state, _ := h.loadMigrationState(ctx)
	verifiedConfig, _, err := h.fetchAndVerifyMigrationConfig()
	if err != nil {
		// Verification failed — refuse the migration. Without a signed
		// config we have no proof that the new PCR0 is one we deployed.
		log.Warn().Err(err).Str("owner_space", h.ownerSpace).Msg("Refusing migration.start — config verification failed")
		return h.errorResponse(msg.GetID(), "migration config verification failed")
	}
	if verifiedConfig == nil {
		// No config published — nothing to migrate to.
		resp := MigrationStartResponse{
			Success: true,
			Message: "No migration available",
		}
		respBytes, _ := json.Marshal(resp)
		return &OutgoingMessage{
			RequestID: msg.GetID(),
			Type:      MessageTypeResponse,
			Payload:   respBytes,
		}, nil
	}
	currentVersion := verifiedConfig.Version
	if state != nil && state.Status == MigrationUserStatusComplete && currentVersion != "" && state.ToPCRVersion == currentVersion {
		resp := MigrationStartResponse{
			Success: true,
			Message: "Migration already completed",
		}
		respBytes, _ := json.Marshal(resp)
		return &OutgoingMessage{
			RequestID: msg.GetID(),
			Type:      MessageTypeResponse,
			Payload:   respBytes,
		}, nil
	}

	// Mark migration as in progress
	if state == nil {
		state = &MigrationState{}
	}
	state.Status = MigrationUserStatusInProgress
	h.saveMigrationState(ctx, state)

	// 1. Re-seal the sealed material (contains KMS-encrypted random bytes for DEK derivation)
	if err := h.resealMaterial(ctx); err != nil {
		state.Status = MigrationUserStatusNone
		h.saveMigrationState(ctx, state)
		log.Error().Err(err).Str("owner_space", h.ownerSpace).Msg("Failed to re-seal material")
		return h.errorResponse(msg.GetID(), "migration failed: "+err.Error())
	}

	// 2. Re-seal the ECIES keys (KMS-sealed asymmetric keys for cold vault recovery)
	if err := h.resealECIES(ctx); err != nil {
		// ECIES re-sealing is critical but we don't roll back material
		// since the user can re-derive ECIES from scratch on next unlock
		log.Warn().Err(err).Str("owner_space", h.ownerSpace).Msg("Failed to re-seal ECIES keys (non-fatal)")
	}

	// 3. Use the already-verified config from earlier in this handler
	// for state tracking + routing handoff. Re-fetching here would
	// just re-run the verifier; the values can't change mid-call.
	configVersion := verifiedConfig.Version
	newPCR0 := verifiedConfig.NewPCRs.PCR0

	// 4. Mark migration complete
	now := time.Now()
	state.Status = MigrationUserStatusComplete
	state.MigratedAt = &now
	state.UserNotified = false
	state.ToPCRVersion = configVersion
	if err := h.saveMigrationState(ctx, state); err != nil {
		log.Error().Err(err).Msg("Failed to save migration state")
	}

	// SECURITY: migration MUST NOT call persistVaultStateToS3.
	// Re-sealing only modifies sealed_material.bin and sealed_ecies.bin;
	// vault_state.enc is unchanged. Two data-loss incidents (2026-05-08,
	// 2026-05-09) traced to a stale-enclave persistFn here overwriting
	// a healthy ~220KB vault_state.enc with a ~12KB stub. The marker
	// write below is the only durability artifact migration produces.

	// Publish an unencrypted marker so the auto-finalize Lambda can tell that
	// this user is done. The marker is per-version, so old markers don't
	// satisfy future migrations.
	if configVersion != "" {
		if err := h.sealerProxy.WriteMigrationMarker(configVersion); err != nil {
			log.Warn().Err(err).Str("owner_space", h.ownerSpace).Msg("Failed to write migration marker (non-fatal)")
		}
	}

	// Routing handoff: the user's state is now sealed to the new
	// PCR, so the parent should release ownership in the
	// vault-routing KV. TargetInstanceID="" means "release for
	// reclaim" — any instance attesting to the new PCR will then
	// take over the user's subscription. NewPCR0 is the actual PCR0
	// hex hash (not the version string) so parent's canClaim() gate
	// can match it against an instance's attested PCR0.
	if h.sendToParent != nil && newPCR0 != "" {
		handoffMsg := &OutgoingMessage{
			Type:             MessageTypeRoutingHandoff,
			OwnerSpace:       h.ownerSpace,
			TargetInstanceID: "",
			NewPCR0:          newPCR0,
		}
		if err := h.sendToParent(handoffMsg); err != nil {
			log.Warn().
				Err(err).
				Str("owner_space", h.ownerSpace).
				Msg("routing handoff send failed (non-fatal — lease expiry will cover it)")
		}
	} else if h.sendToParent != nil {
		log.Warn().
			Str("owner_space", h.ownerSpace).
			Str("config_version", configVersion).
			Msg("migration config missing new PCR0 — skipping routing handoff (sweeper will reclaim)")
	}

	log.Info().
		Str("owner_space", h.ownerSpace).
		Str("version", configVersion).
		Msg("Migration completed successfully — vault re-sealed for new enclave")

	// Record the finalization on the VettID system connection so the
	// user has a history entry showing they applied this update.
	if h.auditLog != nil {
		title := "Vault security update applied"
		if configVersion != "" {
			title = title + " (" + configVersion + ")"
		}
		refs := map[string]string{}
		if configVersion != "" {
			refs["version"] = configVersion
		}
		h.auditLog.AppendSystem(AuditEntry{
			EventType: AuditTypeSystemMigrationFinalized,
			Title:     title,
			Body:      "The vault has been re-sealed for the new enclave version.",
			Refs:      refs,
		})
	}

	resp := MigrationStartResponse{
		Success: true,
		Message: "Vault security update applied successfully",
		Version: configVersion,
	}

	respBytes, _ := json.Marshal(resp)
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// resealMaterial loads sealed material from S3, unseals with current enclave
// attestation, re-seals (no attestation), and stores the new version.
func (h *MigrationHandler) resealMaterial(ctx context.Context) error {
	// Load current sealed material blob from S3
	sealedBlob, err := h.sealerProxy.LoadSealedMaterial()
	if err != nil {
		return fmt.Errorf("failed to load sealed material: %w", err)
	}

	// Unseal the inner sealed material using the new UnsealMaterial operation.
	// This passes the full blob via SealedMaterial field (same path as DeriveDEKFromPIN)
	// to avoid base64-encoding issues with the Data []byte field.
	plaintext, err := h.sealerProxy.UnsealMaterial(sealedBlob)
	if err != nil {
		return fmt.Errorf("failed to unseal material: %w", err)
	}

	// Re-seal with KMS Encrypt
	newSealedData, err := h.sealerProxy.SealCredential(plaintext)

	// SECURITY: Zero plaintext immediately regardless of seal success
	for i := range plaintext {
		plaintext[i] = 0
	}

	if err != nil {
		return fmt.Errorf("failed to re-seal material: %w", err)
	}

	// Parse original blob to preserve owner_id and version
	var smData struct {
		Version int    `json:"version"`
		OwnerID string `json:"owner_id"`
	}
	if err := json.Unmarshal(sealedBlob, &smData); err != nil {
		return fmt.Errorf("failed to parse sealed material metadata: %w", err)
	}

	// Reassemble the SealedMaterialData with the new sealed data
	newSmData := struct {
		Version        int    `json:"version"`
		SealedMaterial []byte `json:"sealed_material"`
		OwnerID        string `json:"owner_id"`
		CreatedAt      int64  `json:"created_at"`
	}{
		Version:        smData.Version,
		SealedMaterial: newSealedData,
		OwnerID:        smData.OwnerID,
		CreatedAt:      time.Now().Unix(),
	}

	newBlob, err := json.Marshal(newSmData)
	if err != nil {
		return fmt.Errorf("failed to marshal new sealed material: %w", err)
	}

	// Store the re-sealed material back to S3
	if err := h.sealerProxy.StoreSealedMaterial(newBlob); err != nil {
		return fmt.Errorf("failed to store re-sealed material: %w", err)
	}

	log.Info().
		Str("owner_space", h.ownerSpace).
		Str("owner_id", smData.OwnerID).
		Msg("Sealed material re-sealed successfully")

	return nil
}

// resealECIES re-seals the KMS-encrypted ECIES keys for the new enclave.
func (h *MigrationHandler) resealECIES(ctx context.Context) error {
	// Load KMS-sealed ECIES keys from S3
	sealedECIES, err := h.sealerProxy.LoadSealedECIES()
	if err != nil {
		return fmt.Errorf("failed to load sealed ECIES: %w", err)
	}

	if len(sealedECIES) == 0 {
		log.Debug().Msg("No ECIES keys to re-seal (warm vault only)")
		return nil
	}

	// Unseal with current enclave attestation
	eciesPlaintext, err := h.sealerProxy.UnsealCredential(sealedECIES)
	if err != nil {
		return fmt.Errorf("failed to unseal ECIES: %w", err)
	}

	// Re-seal
	newSealedECIES, err := h.sealerProxy.SealCredential(eciesPlaintext)

	// SECURITY: Zero plaintext immediately
	for i := range eciesPlaintext {
		eciesPlaintext[i] = 0
	}

	if err != nil {
		return fmt.Errorf("failed to re-seal ECIES: %w", err)
	}

	// Store back
	if err := h.sealerProxy.StoreSealedECIES(newSealedECIES); err != nil {
		return fmt.Errorf("failed to store re-sealed ECIES: %w", err)
	}

	log.Info().
		Str("owner_space", h.ownerSpace).
		Msg("ECIES keys re-sealed successfully")

	return nil
}

// MarkMigrationComplete marks a user's migration as complete.
// Called by the migration system after successful verification.
func (h *MigrationHandler) MarkMigrationComplete(ctx context.Context, fromPCR, toPCR string) error {
	now := time.Now()
	state := &MigrationState{
		Status:         MigrationUserStatusComplete,
		MigratedAt:     &now,
		UserNotified:   false,
		FromPCRVersion: fromPCR,
		ToPCRVersion:   toPCR,
	}

	if err := h.saveMigrationState(ctx, state); err != nil {
		return err
	}

	log.Info().
		Str("owner_space", h.ownerSpace).
		Str("from_pcr", fromPCR).
		Str("to_pcr", toPCR).
		Msg("User migration marked as complete")

	return nil
}

// MarkEmergencyRecoveryRequired marks a user as needing emergency recovery.
// Called when both enclaves become unavailable.
func (h *MigrationHandler) MarkEmergencyRecoveryRequired(ctx context.Context) error {
	state, _ := h.loadMigrationState(ctx)
	if state == nil {
		state = &MigrationState{}
	}

	state.Status = MigrationUserStatusEmergencyRecoveryRequired

	if err := h.saveMigrationState(ctx, state); err != nil {
		return err
	}

	log.Warn().
		Str("owner_space", h.ownerSpace).
		Msg("User marked as requiring emergency recovery")

	return nil
}

// loadMigrationState loads the migration state from storage.
func (h *MigrationHandler) loadMigrationState(_ context.Context) (*MigrationState, error) {
	data, err := h.storage.Get(migrationStateKey)
	if err != nil {
		return nil, err
	}

	var state MigrationState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}

	return &state, nil
}

// saveMigrationState saves the migration state to storage.
func (h *MigrationHandler) saveMigrationState(_ context.Context, state *MigrationState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}

	return h.storage.Put(migrationStateKey, data)
}

// errorResponse creates an error response.
func (h *MigrationHandler) errorResponse(id string, errMsg string) (*OutgoingMessage, error) {
	return &OutgoingMessage{
		RequestID: id,
		Type:      MessageTypeError,
		Error:     errMsg,
	}, nil
}
