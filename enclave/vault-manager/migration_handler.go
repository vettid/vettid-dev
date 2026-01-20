package main

import (
	"context"
	"encoding/json"
	"time"

	"github.com/rs/zerolog/log"
)

// MigrationHandler handles migration-related NATS operations.
// Provides status checks, acknowledgments, and emergency recovery for migrated users.
type MigrationHandler struct {
	ownerSpace  string
	storage     *EncryptedStorage
	vaultState  *VaultState
	sealerProxy *SealerProxy
}

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
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
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
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
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
