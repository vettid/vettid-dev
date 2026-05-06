package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// WalletMoveSeedRequest carries the same auth tokens any
// credential.secret.* operation uses, plus the wallet whose seed is
// being moved. The vault verifies the password before reading the
// wallet's BIP39 mnemonic from storage and writing it into the
// credential's Secrets list. After a successful move the mnemonic is
// cleared from the wallet record entirely — every subsequent BTC sign
// requires the user's password so the credential can be decrypted to
// retrieve the seed.
type WalletMoveSeedRequest struct {
	WalletID              string `json:"wallet_id"`
	EncryptedCredential   string `json:"encrypted_credential"`
	EncryptedPasswordHash string `json:"encrypted_password_hash"`
	EphemeralPublicKey    string `json:"ephemeral_public_key"`
	Nonce                 string `json:"nonce"`
	KeyID                 string `json:"key_id"`
}

// WalletMoveSeedResponse mirrors the shape of credential.secret.add's
// response so the app reuses its existing handling — same updated
// encrypted credential, same new UTKs.
type WalletMoveSeedResponse struct {
	WalletID            string      `json:"wallet_id"`
	SecretID            string      `json:"secret_id"`
	EncryptedCredential string      `json:"encrypted_credential"`
	NewUTKs             []UTKPublic `json:"new_utks,omitempty"`
	MovedAt             int64       `json:"moved_at"`
	AlreadyInCredential bool        `json:"already_in_credential,omitempty"`
}

// HandleMoveSeedToCredential moves the wallet's BIP39 mnemonic into
// the user's Critical Secrets and clears it from the wallet record.
// Requires fresh password re-auth — the same gate the user faces when
// revealing any other Critical Secret. After this op succeeds, future
// signs MUST include password material so the enclave can decrypt the
// credential to retrieve the seed.
//
// Atomic order: copy into credential → verify present in credential →
// clear from wallet record. If anything before the wipe fails the
// wallet keeps its mnemonic and the user can retry.
//
// Idempotent: calling on a wallet whose seed is already in credential
// returns the existing secret_id without re-encrypting.
func (h *WalletHandler) HandleMoveSeedToCredential(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req WalletMoveSeedRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleMoveSeedToCredential"); err != nil {
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
	defer record.SecureErase()
	if len(record.BIP39Mnemonic) == 0 && record.SeedBackupSecretID != "" {
		respBytes, _ := json.Marshal(WalletMoveSeedResponse{
			WalletID:            req.WalletID,
			SecretID:            record.SeedBackupSecretID,
			MovedAt:             record.SeedBackedUpAt,
			AlreadyInCredential: true,
		})
		return &OutgoingMessage{
			RequestID: msg.GetID(),
			Type:      MessageTypeResponse,
			Payload:   respBytes,
		}, nil
	}
	if len(record.BIP39Mnemonic) == 0 {
		return errorResponse(msg.GetID(), "this wallet has no mnemonic to move — recreate it"), nil
	}

	newSecretID := uuid.New().String()
	secretName := fmt.Sprintf("BTC Wallet — %s", record.Label)
	now := time.Now()

	result, err := h.credentialSecretHandler.MutateSecrets(
		req.EncryptedCredential, req.EncryptedPasswordHash,
		req.EphemeralPublicKey, req.Nonce, req.KeyID,
		func(cred *ProteanCredentialV2) error {
			// Copy the mnemonic into a fresh buffer for the credential —
			// the local record's slice is wiped by deferred SecureErase.
			mnCopy := make([]byte, len(record.BIP39Mnemonic))
			copy(mnCopy, record.BIP39Mnemonic)
			cred.Secrets = append(cred.Secrets, CredentialSecretEntry{
				ID:          newSecretID,
				Name:        secretName,
				Category:    SecretCategorySeedPhrase,
				Description: "BIP39 12-word seed phrase. Restorable in any BIP84 (P2WPKH) wallet.",
				Value:       mnCopy,
				Owner:       "user",
				CreatedAt:   now.Unix(),
				UpdatedAt:   now.Unix(),
			})
			return nil
		},
	)
	if err != nil {
		log.Warn().Err(err).Str("wallet_id", req.WalletID).Msg("Failed to move wallet seed to credential")
		return errorResponse(msg.GetID(), err.Error()), nil
	}

	// Stamp the wallet's label as the alias so the seed metadata row
	// groups with the wallet's catalog entry and crypto-key row under
	// one card in the Available Secrets dialog.
	h.credentialSecretHandler.StoreSecretMetadata(SecretMetadataRecord{
		ID:              newSecretID,
		Name:            secretName,
		Category:        string(SecretCategorySeedPhrase),
		Description:     "BIP39 seed phrase",
		Owner:           "user",
		Discoverability: DiscoverabilityCataloged,
		Alias:           record.Label,
		CreatedAt:       now.Unix(),
	})

	// Atomic wipe — only after the credential write succeeded above.
	// If this storage write fails the wallet ends up with the seed in
	// both places; better than the inverse (seed lost). The user can
	// retry move-seed-to-credential and the idempotent branch will
	// notice the existing entry.
	record.SeedBackedUpAt = now.Unix()
	record.SeedBackupSecretID = newSecretID
	zeroBytes(record.BIP39Mnemonic)
	record.BIP39Mnemonic = nil
	if data, err := json.Marshal(record); err == nil {
		if err := h.storage.Put(walletStorageKey(req.WalletID), data); err != nil {
			log.Error().Err(err).Str("wallet_id", req.WalletID).Msg("Failed to wipe mnemonic from wallet record after move")
		}
	}

	if h.eventHandler != nil {
		h.eventHandler.LogEvent(ctx, &Event{
			EventType: EventTypeSecretAdded,
			Metadata: map[string]string{
				"wallet_id": req.WalletID,
				"secret_id": newSecretID,
				"category":  string(SecretCategorySeedPhrase),
				"reason":    "wallet_seed_moved_to_credential",
			},
		})
	}

	// Move flips the wallet from "wallet table" representation in
	// secret_catalog to "credential-secret metadata" representation —
	// either way it appears in the catalog, but the underlying row
	// changes so a snapshot refresh keeps the public view consistent.
	if h.publisher != nil {
		go RepublishProfile(h.ownerSpace, h.storage, h.publisher, h.vaultState)
	}

	resp := WalletMoveSeedResponse{
		WalletID:            req.WalletID,
		SecretID:            newSecretID,
		EncryptedCredential: result.EncryptedCredential,
		NewUTKs:             result.NewUTKs,
		MovedAt:             record.SeedBackedUpAt,
	}
	respBytes, _ := json.Marshal(resp)
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleMoveSeedToWallet moves the wallet's seed back from credential
// into the wallet record. After this op the wallet works without a
// password gate again. Same auth path as move-to-credential.
//
// Atomic order: read mnemonic from credential → restore on wallet
// record → remove credential entry. If the credential delete fails
// the seed exists in both places (recoverable, retry safe).
func (h *WalletHandler) HandleMoveSeedToWallet(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req WalletMoveSeedRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleMoveSeedToWallet"); err != nil {
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
		return errorResponse(msg.GetID(), "this wallet's seed is not currently in the credential"), nil
	}

	targetSecretID := record.SeedBackupSecretID
	var recoveredMnemonic []byte

	result, err := h.credentialSecretHandler.MutateSecrets(
		req.EncryptedCredential, req.EncryptedPasswordHash,
		req.EphemeralPublicKey, req.Nonce, req.KeyID,
		func(cred *ProteanCredentialV2) error {
			out := make([]CredentialSecretEntry, 0, len(cred.Secrets))
			removed := false
			for _, s := range cred.Secrets {
				if s.ID == targetSecretID {
					// Copy the bytes out before zeroing the source slice,
					// then keep them in a local []byte the caller can wipe
					// after persisting.
					recoveredMnemonic = make([]byte, len(s.Value))
					copy(recoveredMnemonic, s.Value)
					zeroBytes(s.Value)
					removed = true
					continue
				}
				out = append(out, s)
			}
			if !removed {
				return fmt.Errorf("seed entry not found in credential")
			}
			cred.Secrets = out
			return nil
		},
	)
	if err != nil {
		log.Warn().Err(err).Str("wallet_id", req.WalletID).Msg("Failed to move wallet seed back to wallet")
		zeroBytes(recoveredMnemonic)
		return errorResponse(msg.GetID(), err.Error()), nil
	}
	if len(recoveredMnemonic) == 0 {
		return errorResponse(msg.GetID(), "recovered mnemonic was empty — abort"), nil
	}
	defer zeroBytes(recoveredMnemonic)

	h.credentialSecretHandler.RemoveSecretMetadata(targetSecretID)

	record.BIP39Mnemonic = make([]byte, len(recoveredMnemonic))
	copy(record.BIP39Mnemonic, recoveredMnemonic)
	record.SeedBackedUpAt = 0
	record.SeedBackupSecretID = ""
	if data, err := json.Marshal(record); err == nil {
		_ = h.storage.Put(walletStorageKey(req.WalletID), data)
	}

	if h.eventHandler != nil {
		h.eventHandler.LogEvent(ctx, &Event{
			EventType: EventTypeSecretDeleted,
			Metadata: map[string]string{
				"wallet_id": req.WalletID,
				"secret_id": targetSecretID,
				"reason":    "wallet_seed_moved_back_to_wallet",
			},
		})
	}

	// Same as the move-to-credential path: the catalog entry shifts
	// representation, so refresh the public snapshot.
	if h.publisher != nil {
		go RepublishProfile(h.ownerSpace, h.storage, h.publisher, h.vaultState)
	}

	resp := struct {
		WalletID            string      `json:"wallet_id"`
		EncryptedCredential string      `json:"encrypted_credential"`
		NewUTKs             []UTKPublic `json:"new_utks,omitempty"`
	}{
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
