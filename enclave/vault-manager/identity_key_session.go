package main

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/rs/zerolog/log"
)

// loadSessionTTLSeconds reads the user's configured identity-key TTL
// directly from encrypted storage so callers that don't hold a
// SettingsHandler (PIN unlock, identity-unlock) can also honor it.
// Falls back to 300s if missing or out of range.
func loadSessionTTLSeconds(storage *EncryptedStorage) int64 {
	if storage == nil {
		return 300
	}
	data, err := storage.Get("settings/credential")
	if err != nil {
		return 300
	}
	var s CredentialSettings
	if err := json.Unmarshal(data, &s); err != nil {
		return 300
	}
	if s.SessionTtlSeconds < 30 || s.SessionTtlSeconds > 3600 {
		return 300
	}
	return int64(s.SessionTtlSeconds)
}

// ErrIdentityLocked is returned when a signing operation is attempted
// but the identity-key TTL has expired (or PIN unlock has been
// cleared). Clients should prompt the user for their password and
// call credential.identity-unlock to refresh the in-memory key.
var ErrIdentityLocked = errors.New("identity_locked")

// loadIdentityKeyTTL reads the per-vault session TTL from credential
// settings. Returns the configured value (30s–3600s) or 300s if unset.
func (mh *MessageHandler) loadIdentityKeyTTL() int64 {
	if mh == nil || mh.settingsHandler == nil {
		return 300
	}
	return int64(mh.settingsHandler.SessionTTLSeconds())
}

// loadIdentityKeyToState populates the carve-out fields and starts a
// fresh sliding TTL window using the user's configured session TTL.
// The free-function form lets PIN unlock + identity-unlock callers
// share the same logic without holding a MessageHandler.
func loadIdentityKeyToState(state *VaultState, storage *EncryptedStorage, idPriv, idPub []byte) {
	ttl := loadSessionTTLSeconds(storage)
	state.mu.Lock()
	defer state.mu.Unlock()
	zeroBytes(state.identityPrivateKey)
	state.identityPrivateKey = append([]byte(nil), idPriv...)
	if len(idPub) > 0 {
		state.identityPublicKey = append([]byte(nil), idPub...)
	}
	state.identityKeyExpiresAt = time.Now().Unix() + ttl
}

// consumeIdentityKeyFromState returns a fresh copy of the identity
// private key for one signing operation, and extends the TTL window.
// Returns ErrIdentityLocked if the key is not loaded or the window
// has lapsed. Caller owns the returned slice — defer zeroBytes(out).
func consumeIdentityKeyFromState(state *VaultState, storage *EncryptedStorage) ([]byte, error) {
	now := time.Now().Unix()
	state.mu.Lock()
	defer state.mu.Unlock()
	if len(state.identityPrivateKey) == 0 {
		return nil, ErrIdentityLocked
	}
	if state.identityKeyExpiresAt > 0 && now >= state.identityKeyExpiresAt {
		zeroBytes(state.identityPrivateKey)
		state.identityPrivateKey = nil
		state.identityKeyExpiresAt = 0
		log.Info().Msg("identity key TTL expired; requiring re-auth")
		return nil, ErrIdentityLocked
	}
	out := make([]byte, len(state.identityPrivateKey))
	copy(out, state.identityPrivateKey)
	state.identityKeyExpiresAt = now + loadSessionTTLSeconds(storage)
	return out, nil
}

// clearIdentityKeyFromState wipes the in-memory identity private key.
// The public key remains so non-signing reads keep working.
func clearIdentityKeyFromState(state *VaultState) {
	state.mu.Lock()
	defer state.mu.Unlock()
	zeroBytes(state.identityPrivateKey)
	state.identityPrivateKey = nil
	state.identityKeyExpiresAt = 0
}

// MessageHandler-bound shims for callers that already hold mh.

func (mh *MessageHandler) loadIdentityKey(idPriv, idPub []byte) {
	loadIdentityKeyToState(mh.vaultState, mh.storage, idPriv, idPub)
}

func (mh *MessageHandler) consumeIdentityKey() ([]byte, error) {
	return consumeIdentityKeyFromState(mh.vaultState, mh.storage)
}

func (mh *MessageHandler) clearIdentityKey() {
	clearIdentityKeyFromState(mh.vaultState)
}

// IdentityUnlockRequest is the payload for credential.identity-unlock.
type IdentityUnlockRequest struct {
	EncryptedCredential   string `json:"encrypted_credential"`
	EncryptedPasswordHash string `json:"encrypted_password_hash"`
	EphemeralPublicKey    string `json:"ephemeral_public_key"`
	Nonce                 string `json:"nonce"`
	KeyID                 string `json:"key_id"`
}

// IdentityUnlockResponse confirms the identity key is loaded and tells
// the client when to expect it to expire so the UI can show a
// session-locked indicator without round-tripping for every action.
type IdentityUnlockResponse struct {
	Success    bool  `json:"success"`
	ExpiresAt  int64 `json:"expires_at"`  // unix seconds
	TtlSeconds int64 `json:"ttl_seconds"` // window length the user picked
}

// handleCredentialIdentityUnlock decrypts the request-supplied
// credential blob, verifies the password against it, and copies the
// identity keypair into vaultState carve-outs with a fresh TTL window.
// On success the in-memory identity key is usable for signed ops
// (action invoke, contract sign, vote) until the window lapses or
// clearIdentityKey is called.
func (mh *MessageHandler) handleCredentialIdentityUnlock(_ context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req IdentityUnlockRequest
	if err := unmarshalRequest(msg.Payload, &req, "credential.identity-unlock"); err != nil {
		return mh.errorResponse(msg.GetID(), "invalid request format")
	}
	if req.EncryptedCredential == "" || req.EncryptedPasswordHash == "" ||
		req.EphemeralPublicKey == "" || req.Nonce == "" || req.KeyID == "" {
		return mh.errorResponse(msg.GetID(), "missing required fields")
	}

	idKey, err := mh.credentialSecretHandler.RevealIdentityPrivateKey(
		req.EncryptedCredential,
		req.EncryptedPasswordHash,
		req.EphemeralPublicKey,
		req.Nonce,
		req.KeyID,
	)
	if err != nil {
		log.Warn().Err(err).Str("owner_space", mh.ownerSpace).Msg("identity-unlock failed")
		return mh.errorResponse(msg.GetID(), err.Error())
	}
	defer zeroBytes(idKey)

	// Identity public key is already on the carve-out from PIN unlock,
	// but pass it along too in case this is the first time we're
	// populating after a forced clear.
	mh.vaultState.mu.RLock()
	idPub := append([]byte(nil), mh.vaultState.identityPublicKey...)
	mh.vaultState.mu.RUnlock()

	mh.loadIdentityKey(idKey, idPub)

	ttl := loadSessionTTLSeconds(mh.storage)
	resp := IdentityUnlockResponse{
		Success:    true,
		ExpiresAt:  time.Now().Unix() + ttl,
		TtlSeconds: ttl,
	}
	body, _ := json.Marshal(resp)
	log.Info().Str("owner_space", mh.ownerSpace).Int64("ttl_seconds", ttl).Msg("identity key unlocked")
	return mh.successResponse(msg.GetID(), body)
}
