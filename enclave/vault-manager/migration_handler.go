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
// Provides config retrieval and the deprecated start/status endpoints.
// Per the 2026-05-09 architect redesign, migration is coupled to PIN
// unlock (M1); this handler retains the legacy entry points for the
// deprecation window. There is no longer any in-vault migration state
// (M2) — the per-version S3 marker at
// `_migration/completed/{version}/{ownerSpace}.json` is the sole
// record of completion.
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

// MigrationUserStatus represents a user's migration status as
// reported by the deprecated credential.migration.status endpoint.
// Post-redesign, completion is signaled via the pin-unlock response;
// this enum exists only to preserve wire compatibility with older apps.
type MigrationUserStatus string

const (
	MigrationUserStatusNone     MigrationUserStatus = "none"
	MigrationUserStatusComplete MigrationUserStatus = "complete"
)

// MigrationStatusResponse is the response for the deprecated
// migration.status request. Only Status is populated post-M2; the
// other fields stay on the wire as zero values for backward compat.
type MigrationStatusResponse struct {
	Status         MigrationUserStatus `json:"status"`
	MigratedAt     *time.Time          `json:"migrated_at,omitempty"`
	UserNotified   bool                `json:"user_notified"`
	FromPCRVersion string              `json:"from_pcr_version,omitempty"`
	ToPCRVersion   string              `json:"to_pcr_version,omitempty"`
}

// HandleStatus handles credential.migration.status requests.
//
// Deprecated. Per the 2026-05-09 architect redesign, the canonical
// migration completion signal is the `migration_status` field in the
// pin-unlock response (M1). With M2, there is no in-vault state to
// query — the per-version S3 marker is the sole record of completion.
// This handler returns "none" so that old clients still polling it
// stay quiet; they will learn about an available migration via
// credential.migration.config and complete it via the unlock flow.
func (h *MigrationHandler) HandleStatus(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	log.Debug().
		Str("owner_space", h.ownerSpace).
		Msg("Handling deprecated migration.status request — returning 'none'")

	resp := MigrationStatusResponse{Status: MigrationUserStatusNone}
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
//
// Post-M2 there is no in-vault state; the per-version S3 marker is the
// only completion record. The "already migrated" short-circuit was
// removed here because it depended on `migration_state`. The trade-off:
// a user who has already migrated still sees a published config as
// "available". The pin-unlock dispatcher (M1) is the authoritative
// gate — when it sees `sealed_to_pcr0 == running PCR0`, it skips
// re-seal and reports `migration_status: completed` to the app, which
// then dismisses the prompt and adds the PCR0 to its trusted set.
func (h *MigrationHandler) HandleGetConfig(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	log.Debug().
		Str("owner_space", h.ownerSpace).
		Msg("Handling migration.config request")

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
// Unseals current sealed material and ECIES keys, re-seals them, and
// stores the new versions. The new sealed blobs can be decrypted only
// by enclaves whose PCR0 is in the KMS key policy.
//
// Deprecated. The 2026-05-09 architect redesign couples re-seal to PIN
// unlock (M1). This entry point is kept for the deprecation window so
// older app builds that still call `credential.migration.start`
// continue to work. New apps should not call it. With M2 there is no
// in-vault migration state to maintain — the only durability artifact
// is the per-version S3 marker written below.
func (h *MigrationHandler) HandleStart(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	log.Info().
		Str("owner_space", h.ownerSpace).
		Msg("Handling deprecated migration.start request — re-sealing vault for new enclave")

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

	// 1. Re-seal the sealed material (contains KMS-encrypted random bytes for DEK derivation)
	if err := h.resealMaterial(ctx, verifiedConfig.Version); err != nil {
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
	// for routing handoff. Re-fetching here would just re-run the
	// verifier; the values can't change mid-call.
	configVersion := verifiedConfig.Version
	newPCR0 := verifiedConfig.NewPCRs.PCR0

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

// sealedMaterialWrapper mirrors supervisor.SealedMaterialData (M3 v2
// format). Defined locally because vault-manager and supervisor are
// separate Go packages but share the on-disk JSON shape. Legacy v1
// wrappers (no Generation/SealedToPCR0/SealedToVersion fields) parse
// cleanly via json.Unmarshal — missing keys default to zero values.
type sealedMaterialWrapper struct {
	Version         int    `json:"version"`
	SealedMaterial  []byte `json:"sealed_material"`
	OwnerID         string `json:"owner_id"`
	CreatedAt       int64  `json:"created_at"`
	Generation      int    `json:"generation,omitempty"`
	SealedToPCR0    string `json:"sealed_to_pcr0,omitempty"`
	SealedToVersion string `json:"sealed_to_version,omitempty"`
}

// resealMaterial loads sealed material from S3, unseals with current enclave
// attestation, re-seals against the running enclave's PCR0, and stores
// the new wrapper with Generation+1, SealedToPCR0 = running PCR0, and
// SealedToVersion = migrationVersion.
//
// Idempotency guard (M3 §3): if the existing wrapper's SealedToPCR0
// already equals the running PCR0, this is a no-op. Logs and returns
// nil. The caller's outer flow handles "already migrated" reporting.
func (h *MigrationHandler) resealMaterial(ctx context.Context, migrationVersion string) error {
	runningPCR0, err := h.sealerProxy.GetRunningPCR0()
	if err != nil {
		return fmt.Errorf("failed to read running PCR0: %w", err)
	}

	// Load current sealed material blob from S3
	sealedBlob, err := h.sealerProxy.LoadSealedMaterial()
	if err != nil {
		return fmt.Errorf("failed to load sealed material: %w", err)
	}

	// Parse the existing wrapper (handles both v1 legacy and v2 new
	// format because the new fields are omitempty + tolerated as
	// missing on read).
	var existing sealedMaterialWrapper
	if err := json.Unmarshal(sealedBlob, &existing); err != nil {
		return fmt.Errorf("failed to parse sealed material metadata: %w", err)
	}

	// Idempotency: nothing to do if material is already bound to our
	// PCR0. Don't burn KMS quota or risk a needless write race.
	if existing.SealedToPCR0 != "" && existing.SealedToPCR0 == runningPCR0 {
		log.Info().
			Str("owner_space", h.ownerSpace).
			Str("running_pcr0", runningPCR0).
			Int("generation", existing.Generation).
			Msg("Sealed material already bound to running PCR0; skipping re-seal")
		return nil
	}

	// Unseal the inner sealed material using the existing UnsealMaterial operation.
	// This passes the full blob via SealedMaterial field (same path as DeriveDEKFromPIN)
	// to avoid base64-encoding issues with the Data []byte field.
	plaintext, err := h.sealerProxy.UnsealMaterial(sealedBlob)
	if err != nil {
		return fmt.Errorf("failed to unseal material: %w", err)
	}

	// Re-seal with KMS Encrypt — succeeds only if the running enclave
	// can produce an attestation matching the KMS Encrypt policy
	// condition. This is the cryptographic gate that ensures only an
	// enclave attesting to the new PCR0 can produce NEW-bound
	// ciphertext.
	newSealedData, err := h.sealerProxy.SealCredential(plaintext)

	// SECURITY: Zero plaintext immediately regardless of seal success
	for i := range plaintext {
		plaintext[i] = 0
	}

	if err != nil {
		return fmt.Errorf("failed to re-seal material: %w", err)
	}

	// Reassemble the wrapper with the new sealed data and M3 stamps.
	// Generation increments monotonically; legacy v1 wrappers parse as
	// Generation=0, so the first re-seal yields Generation=1.
	updated := sealedMaterialWrapper{
		Version:         existing.Version,
		SealedMaterial:  newSealedData,
		OwnerID:         existing.OwnerID,
		CreatedAt:       time.Now().Unix(),
		Generation:      existing.Generation + 1,
		SealedToPCR0:    runningPCR0,
		SealedToVersion: migrationVersion,
	}
	if updated.Version == 0 {
		// Legacy wrappers may have set Version=0 (or omitted the
		// field). Promote to 1 so the on-disk layout matches what
		// fresh enrollments produce.
		updated.Version = 1
	}

	newBlob, err := json.Marshal(updated)
	if err != nil {
		return fmt.Errorf("failed to marshal new sealed material: %w", err)
	}

	// Store the re-sealed material back to S3
	if err := h.sealerProxy.StoreSealedMaterial(newBlob); err != nil {
		return fmt.Errorf("failed to store re-sealed material: %w", err)
	}

	log.Info().
		Str("owner_space", h.ownerSpace).
		Str("owner_id", existing.OwnerID).
		Int("generation", updated.Generation).
		Str("sealed_to_pcr0", runningPCR0).
		Str("sealed_to_version", migrationVersion).
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

// errorResponse creates an error response.
func (h *MigrationHandler) errorResponse(id string, errMsg string) (*OutgoingMessage, error) {
	return &OutgoingMessage{
		RequestID: id,
		Type:      MessageTypeError,
		Error:     errMsg,
	}, nil
}
