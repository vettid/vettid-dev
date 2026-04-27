package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// WalletBackupSeedRequest carries the same auth tokens any
// credential.secret.* operation uses, plus the wallet to back up.
// The vault verifies the password before reading the wallet's
// BIP39 mnemonic from storage and writing it into the credential's
// Secrets list (where it surfaces in Critical Secrets).
type WalletBackupSeedRequest struct {
	WalletID              string `json:"wallet_id"`
	EncryptedCredential   string `json:"encrypted_credential"`
	EncryptedPasswordHash string `json:"encrypted_password_hash"`
	EphemeralPublicKey    string `json:"ephemeral_public_key"`
	Nonce                 string `json:"nonce"`
	KeyID                 string `json:"key_id"`
}

// WalletBackupSeedResponse mirrors the shape of credential.secret.add's
// response so the app reuses its existing handling — same updated
// encrypted credential, same new UTKs.
type WalletBackupSeedResponse struct {
	WalletID            string      `json:"wallet_id"`
	SecretID            string      `json:"secret_id"`
	EncryptedCredential string      `json:"encrypted_credential"`
	NewUTKs             []UTKPublic `json:"new_utks,omitempty"`
	BackedUpAt          int64       `json:"backed_up_at"`
	AlreadyBackedUp     bool        `json:"already_backed_up,omitempty"`
}

// WalletRevokeBackupRequest is the inverse of backup-seed. Same auth
// path; removes the secret from the credential.
type WalletRevokeBackupRequest = WalletBackupSeedRequest

// WalletRevokeBackupResponse parallels credential.secret.delete.
type WalletRevokeBackupResponse struct {
	WalletID            string      `json:"wallet_id"`
	EncryptedCredential string      `json:"encrypted_credential"`
	NewUTKs             []UTKPublic `json:"new_utks,omitempty"`
}

// HandleBackupSeed adds the wallet's BIP39 mnemonic to the user's
// Critical Secrets list. Requires fresh password re-auth — the same
// gate the user faces when revealing any other Critical Secret.
// Idempotent: a second call on an already-backed-up wallet returns
// the existing secret_id without mutating the credential.
func (h *WalletHandler) HandleBackupSeed(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req WalletBackupSeedRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleBackupSeed"); err != nil {
		return errorResponse(msg.GetID(), "invalid request: "+err.Error()), nil
	}
	if req.WalletID == "" {
		return errorResponse(msg.GetID(), "wallet_id is required"), nil
	}
	if h.credentialSecretHandler == nil {
		return errorResponse(msg.GetID(), "credential secret handler not available"), nil
	}

	// Load the wallet record. The mnemonic only ever leaves the
	// vault DEK by being copied into the credential blob (which is
	// itself sealed by CEK + password).
	walletJSON, err := h.storage.Get(walletStorageKey(req.WalletID))
	if err != nil || len(walletJSON) == 0 {
		return errorResponse(msg.GetID(), "wallet not found"), nil
	}
	var record WalletRecord
	if err := json.Unmarshal(walletJSON, &record); err != nil {
		return errorResponse(msg.GetID(), "wallet record corrupt"), nil
	}
	if record.BIP39Mnemonic == "" {
		return errorResponse(msg.GetID(), "this wallet has no mnemonic to back up — recreate it"), nil
	}
	if record.SeedBackedUpAt > 0 && record.SeedBackupSecretID != "" {
		// Already backed up — return the existing reference idempotently.
		respBytes, _ := json.Marshal(WalletBackupSeedResponse{
			WalletID:        req.WalletID,
			SecretID:        record.SeedBackupSecretID,
			BackedUpAt:      record.SeedBackedUpAt,
			AlreadyBackedUp: true,
		})
		return &OutgoingMessage{
			RequestID: msg.GetID(),
			Type:      MessageTypeResponse,
			Payload:   respBytes,
		}, nil
	}

	newSecretID := uuid.New().String()
	secretName := fmt.Sprintf("BTC Wallet — %s", record.Label)
	now := time.Now()

	result, err := h.credentialSecretHandler.MutateSecrets(
		req.EncryptedCredential, req.EncryptedPasswordHash,
		req.EphemeralPublicKey, req.Nonce, req.KeyID,
		func(cred *ProteanCredentialV2) error {
			cred.Secrets = append(cred.Secrets, CredentialSecretEntry{
				ID:          newSecretID,
				Name:        secretName,
				Category:    SecretCategorySeedPhrase,
				Description: "BIP39 12-word seed phrase. Restorable in any BIP84 (P2WPKH) wallet.",
				Value:       []byte(record.BIP39Mnemonic),
				Owner:       "user",
				CreatedAt:   now.Unix(),
				UpdatedAt:   now.Unix(),
			})
			return nil
		},
	)
	if err != nil {
		log.Warn().Err(err).Str("wallet_id", req.WalletID).Msg("Failed to back up wallet seed to credential")
		return errorResponse(msg.GetID(), err.Error()), nil
	}

	// Mirror to metadata index so the secret surfaces in
	// credential.secret.list immediately.
	h.credentialSecretHandler.StoreSecretMetadata(SecretMetadataRecord{
		ID:          newSecretID,
		Name:        secretName,
		Category:    string(SecretCategorySeedPhrase),
		Description: "BIP39 seed phrase",
		Owner:       "user",
		CreatedAt:   now.Unix(),
	})

	// Update the wallet record with the backup pointer.
	record.SeedBackedUpAt = now.Unix()
	record.SeedBackupSecretID = newSecretID
	if data, err := json.Marshal(record); err == nil {
		_ = h.storage.Put(walletStorageKey(req.WalletID), data)
	}

	if h.eventHandler != nil {
		h.eventHandler.LogEvent(ctx, &Event{
			EventType: EventTypeSecretAdded,
			Metadata: map[string]string{
				"wallet_id":  req.WalletID,
				"secret_id":  newSecretID,
				"category":   string(SecretCategorySeedPhrase),
				"reason":     "wallet_seed_backup",
			},
		})
	}

	resp := WalletBackupSeedResponse{
		WalletID:            req.WalletID,
		SecretID:            newSecretID,
		EncryptedCredential: result.EncryptedCredential,
		NewUTKs:             result.NewUTKs,
		BackedUpAt:          record.SeedBackedUpAt,
	}
	respBytes, _ := json.Marshal(resp)
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleRevokeBackup removes the wallet's seed phrase from the user's
// Critical Secrets. Requires the same password re-auth as backup. The
// mnemonic stays in the wallet record (vault-DEK-encrypted) so the
// wallet keeps working — only the user-visible Critical Secret entry
// is removed.
func (h *WalletHandler) HandleRevokeBackup(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req WalletRevokeBackupRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleRevokeBackup"); err != nil {
		return errorResponse(msg.GetID(), "invalid request: "+err.Error()), nil
	}
	if req.WalletID == "" {
		return errorResponse(msg.GetID(), "wallet_id is required"), nil
	}
	if h.credentialSecretHandler == nil {
		return errorResponse(msg.GetID(), "credential secret handler not available"), nil
	}

	walletJSON, err := h.storage.Get(walletStorageKey(req.WalletID))
	if err != nil || len(walletJSON) == 0 {
		return errorResponse(msg.GetID(), "wallet not found"), nil
	}
	var record WalletRecord
	if err := json.Unmarshal(walletJSON, &record); err != nil {
		return errorResponse(msg.GetID(), "wallet record corrupt"), nil
	}
	if record.SeedBackupSecretID == "" {
		return errorResponse(msg.GetID(), "this wallet's seed is not currently backed up"), nil
	}

	targetSecretID := record.SeedBackupSecretID
	result, err := h.credentialSecretHandler.MutateSecrets(
		req.EncryptedCredential, req.EncryptedPasswordHash,
		req.EphemeralPublicKey, req.Nonce, req.KeyID,
		func(cred *ProteanCredentialV2) error {
			out := make([]CredentialSecretEntry, 0, len(cred.Secrets))
			removed := false
			for _, s := range cred.Secrets {
				if s.ID == targetSecretID {
					zeroBytes(s.Value)
					removed = true
					continue
				}
				out = append(out, s)
			}
			if !removed {
				return fmt.Errorf("backup secret not found in credential")
			}
			cred.Secrets = out
			return nil
		},
	)
	if err != nil {
		log.Warn().Err(err).Str("wallet_id", req.WalletID).Msg("Failed to revoke wallet seed backup")
		return errorResponse(msg.GetID(), err.Error()), nil
	}

	h.credentialSecretHandler.RemoveSecretMetadata(targetSecretID)

	record.SeedBackedUpAt = 0
	record.SeedBackupSecretID = ""
	if data, err := json.Marshal(record); err == nil {
		_ = h.storage.Put(walletStorageKey(req.WalletID), data)
	}

	if h.eventHandler != nil {
		h.eventHandler.LogEvent(ctx, &Event{
			EventType: EventTypeSecretDeleted,
			Metadata: map[string]string{
				"wallet_id":  req.WalletID,
				"secret_id":  targetSecretID,
				"reason":     "wallet_seed_backup_revoked",
			},
		})
	}

	resp := WalletRevokeBackupResponse{
		WalletID:            req.WalletID,
		EncryptedCredential: result.EncryptedCredential,
		NewUTKs:             result.NewUTKs,
	}
	respBytes, _ := json.Marshal(resp)
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}
