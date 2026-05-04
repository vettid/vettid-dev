package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// CredentialSecretHandler handles critical secret storage within the Protean Credential.
// Architecture: Two-layer storage model
//   - Metadata index (vault SQLite) - Names, categories, owners. Allows listing without credential.
//   - Actual secret values (inside Protean Credential blob on device) - Only accessible via password-verified operations.
//
// The vault decrypts the credential in memory to operate on its contents,
// then re-encrypts with CEK and returns the updated blob to the app.
type CredentialSecretHandler struct {
	ownerSpace   string
	storage      *EncryptedStorage
	state        *VaultState
	bootstrap    *BootstrapHandler
	eventHandler *EventHandler
	publisher    *VsockPublisher // optional — used to refresh broadcast snapshots after metadata mutations
}

// NewCredentialSecretHandler creates a new credential secret handler
func NewCredentialSecretHandler(ownerSpace string, storage *EncryptedStorage, state *VaultState, bootstrap *BootstrapHandler, eventHandler *EventHandler) *CredentialSecretHandler {
	return &CredentialSecretHandler{
		ownerSpace:   ownerSpace,
		storage:      storage,
		state:        state,
		bootstrap:    bootstrap,
		eventHandler: eventHandler,
	}
}

// SetPublisher wires the vsock publisher post-construction. Optional —
// only used to fan out fresh published-profile snapshots after a
// metadata mutation. No-op if never called.
func (h *CredentialSecretHandler) SetPublisher(p *VsockPublisher) {
	h.publisher = p
}

// HandleAdd handles credential.secret.add messages
// Flow:
//  1. Verify password (decrypt credential -> check Auth.Hash)
//  2. Add secret to credential.Secrets[]
//  3. Store METADATA ONLY in vault SQLite (name, category, owner)
//  4. Re-encrypt credential with CEK
//  5. Return new encrypted credential blob + new UTKs
func (h *CredentialSecretHandler) HandleAdd(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req CredentialSecretAddRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleAdd"); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	// Validate required fields
	if req.Name == "" {
		return h.errorResponse(msg.GetID(), "name is required")
	}
	if req.Category == "" {
		return h.errorResponse(msg.GetID(), "category is required")
	}
	if req.Value == "" {
		return h.errorResponse(msg.GetID(), "value is required")
	}
	if req.EncryptedCredential == "" {
		return h.errorResponse(msg.GetID(), "encrypted_credential is required")
	}
	if req.EncryptedPasswordHash == "" {
		return h.errorResponse(msg.GetID(), "encrypted_password_hash is required")
	}
	if req.KeyID == "" {
		return h.errorResponse(msg.GetID(), "key_id is required")
	}

	// Validate category
	if !isValidSecretCategory(req.Category) {
		return h.errorResponse(msg.GetID(), "invalid category: must be SEED_PHRASE, PRIVATE_KEY, SIGNING_KEY, MASTER_PASSWORD, RECOVERY_KEY, or OTHER")
	}

	// Decrypt the credential blob using CEK
	credentialV2, err := h.decryptCredentialBlob(req.EncryptedCredential)
	if err != nil {
		log.Error().Err(err).Str("owner_space", h.ownerSpace).Msg("Failed to decrypt credential for secret add")
		return h.errorResponse(msg.GetID(), "Failed to decrypt credential")
	}
	defer credentialV2.SecureErase()

	// Verify password against the credential's auth hash
	if err := h.verifyPasswordAgainstCredential(req.EncryptedPasswordHash, req.EphemeralPublicKey, req.Nonce, req.KeyID, credentialV2); err != nil {
		log.Warn().Err(err).Str("owner_space", h.ownerSpace).Msg("Password verification failed for secret add")
		h.eventHandler.LogSecurityEvent(
			context.Background(),
			EventTypeAuthAttemptFailed,
			"Secret add denied",
			fmt.Sprintf("Failed password verification for secret add: %s", req.Name),
		)
		return h.errorResponse(msg.GetID(), "Password verification failed")
	}

	// Decode the secret value (transport-encrypted via UTK, already decrypted by verifyPassword)
	valueBytes, err := base64.StdEncoding.DecodeString(req.Value)
	if err != nil {
		return h.errorResponse(msg.GetID(), "invalid value encoding")
	}

	// Generate secret ID
	secretID := uuid.New().String()
	now := time.Now()

	// Create the secret entry for the credential blob
	secretEntry := CredentialSecretEntry{
		ID:          secretID,
		Name:        req.Name,
		Category:    SecretCategory(req.Category),
		Description: req.Description,
		Value:       valueBytes,
		Owner:       "user",
		CreatedAt:   now.Unix(),
		UpdatedAt:   now.Unix(),
	}

	// Add secret to credential's Secrets array
	credentialV2.Secrets = append(credentialV2.Secrets, secretEntry)
	credentialV2.Timestamps.LastModified = now.Unix()
	credentialV2.Version++

	// Re-encrypt credential with CEK
	encryptedCredential, err := h.encryptCredentialBlob(credentialV2)
	if err != nil {
		log.Error().Err(err).Msg("Failed to re-encrypt credential after secret add")
		return h.errorResponse(msg.GetID(), "Failed to re-encrypt credential")
	}

	// Store sealed credential blob in vault storage for backup inclusion.
	// This ensures the backup system automatically includes the latest credential.
	if err := h.storage.Put("credential/sealed_blob", []byte(encryptedCredential)); err != nil {
		log.Warn().Err(err).Str("owner_space", h.ownerSpace).Msg("Failed to store credential blob for backup (non-fatal)")
	}

	// Store metadata in vault SQLite (NO values - just metadata for listing).
	// Default discoverability to "cataloged" — peers see the metadata
	// row and can request the value through a future capability flow.
	// Owners can flip it to "public" (publish on profile) or "private"
	// (hide from any peer-visible catalog).
	metadataRecord := SecretMetadataRecord{
		ID:              secretID,
		Name:            req.Name,
		Category:        req.Category,
		Description:     req.Description,
		Owner:           "user",
		Discoverability: DiscoverabilityCataloged,
		Alias:           req.Alias,
		CreatedAt:       now.Unix(),
	}
	h.storeMetadataRecord(metadataRecord)

	log.Info().
		Str("secret_id", secretID).
		Str("category", req.Category).
		Str("owner_space", h.ownerSpace).
		Msg("Credential secret added to credential blob")

	// Critical-secret metadata feeds the published secret_catalog —
	// refresh existing peers and outstanding invitation broker
	// payloads so the user doesn't have to manually publish.
	if h.publisher != nil {
		go RepublishProfile(h.ownerSpace, h.storage, h.publisher, h.state)
	}

	// Generate fresh UTKs and return ONLY the new ones.
	newPairs, err := h.bootstrap.GenerateMoreUTKs(3)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to generate replacement UTKs")
	}
	utkPublics := EncodeUTKPublics(newPairs)

	resp := CredentialSecretAddResponse{
		ID:                  secretID,
		CreatedAt:           now.Format(time.RFC3339),
		EncryptedCredential: encryptedCredential,
		NewUTKs:             utkPublics,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleGet handles credential.secret.get messages
// Flow:
//  1. Check metadata index (does this secret exist?)
//  2. Verify password (decrypt credential -> check Auth.Hash)
//  3. Find secret in credential.Secrets[] by ID
//  4. Return the actual value + new UTKs
func (h *CredentialSecretHandler) HandleGet(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req CredentialSecretGetRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleGet"); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	// Validate required fields
	if req.ID == "" {
		return h.errorResponse(msg.GetID(), "id is required")
	}
	if req.EncryptedCredential == "" {
		return h.errorResponse(msg.GetID(), "encrypted_credential is required")
	}
	if req.EncryptedPasswordHash == "" {
		return h.errorResponse(msg.GetID(), "encrypted_password_hash is required")
	}
	if req.KeyID == "" {
		return h.errorResponse(msg.GetID(), "key_id is required")
	}

	// Check metadata index first (quick check without decrypting credential)
	if !h.secretExistsInMetadata(req.ID) {
		return h.errorResponse(msg.GetID(), "Secret not found")
	}

	// Decrypt the credential blob using CEK
	credentialV2, err := h.decryptCredentialBlob(req.EncryptedCredential)
	if err != nil {
		log.Error().Err(err).Str("owner_space", h.ownerSpace).Msg("Failed to decrypt credential for secret get")
		return h.errorResponse(msg.GetID(), "Failed to decrypt credential")
	}
	defer credentialV2.SecureErase()

	// Verify password
	if err := h.verifyPasswordAgainstCredential(req.EncryptedPasswordHash, req.EphemeralPublicKey, req.Nonce, req.KeyID, credentialV2); err != nil {
		log.Warn().Err(err).Str("owner_space", h.ownerSpace).Msg("Password verification failed for secret access")
		h.eventHandler.LogSecurityEvent(
			context.Background(),
			EventTypeAuthAttemptFailed,
			"Secret access denied",
			fmt.Sprintf("Failed password verification for secret ID: %s", req.ID),
		)
		return h.errorResponse(msg.GetID(), "Password verification failed")
	}

	// Find secret in credential's Secrets array
	var foundSecret *CredentialSecretEntry
	for i := range credentialV2.Secrets {
		if credentialV2.Secrets[i].ID == req.ID {
			foundSecret = &credentialV2.Secrets[i]
			break
		}
	}

	if foundSecret == nil {
		return h.errorResponse(msg.GetID(), "Secret not found in credential")
	}

	// Generate fresh UTKs and return ONLY the new ones.
	newPairs, err := h.bootstrap.GenerateMoreUTKs(3)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to generate replacement UTKs")
	}
	utkPublics := EncodeUTKPublics(newPairs)

	resp := CredentialSecretGetResponse{
		ID:       foundSecret.ID,
		Name:     foundSecret.Name,
		Category: string(foundSecret.Category),
		Value:    base64.StdEncoding.EncodeToString(foundSecret.Value),
		NewUTKs:  utkPublics,
	}
	respBytes, _ := json.Marshal(resp)

	log.Info().
		Str("secret_id", req.ID).
		Str("owner_space", h.ownerSpace).
		Msg("Credential secret retrieved (password verified)")

	// Log audit event for secret access (do NOT log the actual secret value)
	h.eventHandler.LogSecretEvent(
		context.Background(),
		EventTypeSecretAccessed,
		foundSecret.ID,
		foundSecret.Name,
		string(foundSecret.Category),
	)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleList handles credential.secret.list messages
// Reads metadata index from vault SQLite - no credential needed.
// Returns names, categories, owners, timestamps. Also returns crypto key metadata
// and credential info if password is verified.
func (h *CredentialSecretHandler) HandleList(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req CredentialSecretListRequest
	// Allow empty payload
	unmarshalRequest(msg.Payload, &req, "HandleList")

	// Phase D: when the caller wants the enriched response (crypto
	// keys + credential info), they supply the encrypted credential
	// alongside the password material so we can decrypt and verify
	// per-op without holding the credential in memory.
	var verifiedCred *ProteanCredentialV2
	if req.EncryptedCredential != "" && req.EncryptedPasswordHash != "" && req.KeyID != "" {
		cred, err := h.decryptCredentialBlob(req.EncryptedCredential)
		if err != nil {
			log.Warn().Err(err).Str("owner_space", h.ownerSpace).Msg("HandleList: failed to decrypt credential")
			return h.errorResponse(msg.GetID(), "credential decrypt failed")
		}
		if err := h.verifyPasswordAgainstCredential(req.EncryptedPasswordHash, req.EphemeralPublicKey, req.Nonce, req.KeyID, cred); err != nil {
			cred.SecureErase()
			log.Warn().Err(err).Str("owner_space", h.ownerSpace).Msg("Password verification failed for secret list")
			return h.errorResponse(msg.GetID(), "Password verification failed")
		}
		verifiedCred = cred
		// Wipe at the end of this handler — the caller doesn't see
		// the live struct.
		defer verifiedCred.SecureErase()
	}
	passwordVerified := verifiedCred != nil

	// Read metadata from vault SQLite
	metadataRecords := h.getAllMetadataRecords()
	secrets := make([]CredentialSecretMetadata, 0, len(metadataRecords))
	for _, record := range metadataRecords {
		// Legacy rows pre-discoverability default to "cataloged".
		disc := record.Discoverability
		if disc == "" {
			disc = DiscoverabilityCataloged
		}
		secrets = append(secrets, CredentialSecretMetadata{
			ID:              record.ID,
			Name:            record.Name,
			Category:        record.Category,
			Description:     record.Description,
			Owner:           record.Owner,
			Discoverability: disc,
			Alias:           record.Alias,
			CreatedAt:       time.Unix(record.CreatedAt, 0).Format(time.RFC3339),
		})
	}

	resp := CredentialSecretListResponse{
		Secrets: secrets,
	}

	// If password verified, surface crypto-key metadata + credential
	// info from the per-op-decrypted blob (Phase D — no read of
	// vaultState.credential).
	if passwordVerified && verifiedCred != nil {
		cryptoKeys := make([]CryptoKeyMetadata, len(verifiedCred.CryptoKeys))
		for i, k := range verifiedCred.CryptoKeys {
			cryptoKeys[i] = CryptoKeyMetadata{
				ID:        fmt.Sprintf("key-%d", i),
				Label:     k.Label,
				Type:      k.Type,
				CreatedAt: time.Unix(k.CreatedAt, 0).Format(time.RFC3339),
			}
		}
		resp.CryptoKeys = cryptoKeys

		fingerprint := sha256.Sum256(verifiedCred.Identity.PublicKey)
		resp.Credential = &CredentialInfoMetadata{
			IdentityFingerprint: hex.EncodeToString(fingerprint[:8]),
			Version:             verifiedCred.Version,
			CreatedAt:           time.Unix(verifiedCred.Timestamps.CreatedAt, 0).Format(time.RFC3339),
			LastModified:        time.Unix(verifiedCred.Timestamps.LastModified, 0).Format(time.RFC3339),
		}
	}

	respBytes, _ := json.Marshal(resp)

	log.Debug().
		Int("count", len(secrets)).
		Bool("password_verified", passwordVerified).
		Str("owner_space", h.ownerSpace).
		Msg("Listed credential secrets")

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleSetDiscoverability handles credential.secret.set-discoverability.
// Updates only the metadata row's Discoverability flag — no password
// is required because the credential blob (and the secret value) are
// not touched. The owner uses this to flip a critical secret between
// public (published on profile), cataloged (peers see metadata only),
// and private (hidden from any peer-visible catalog).
func (h *CredentialSecretHandler) HandleSetDiscoverability(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req CredentialSecretSetDiscoverabilityRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleSetDiscoverability"); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}
	if req.ID == "" {
		return h.errorResponse(msg.GetID(), "id is required")
	}
	// Critical secret VALUES must never reach the published profile —
	// the credential is the trust boundary, not the broadcast surface.
	// Only "cataloged" (peers see metadata: this secret exists) or
	// "private" (peers see nothing) are valid here. "public" is
	// rejected even if the client tries.
	switch req.Discoverability {
	case DiscoverabilityCataloged, DiscoverabilityPrivate:
		// ok
	default:
		return h.errorResponse(msg.GetID(), "discoverability must be cataloged or private")
	}

	records := h.getAllMetadataRecords()
	found := false
	for i := range records {
		if records[i].ID == req.ID {
			records[i].Discoverability = req.Discoverability
			found = true
			break
		}
	}
	if !found {
		return h.errorResponse(msg.GetID(), "Secret not found")
	}
	h.saveMetadataRecords(records)

	// Wrap with `success: true` so the Android client's standard
	// VaultResponse parsing (which checks `success` first, falling
	// through to typed dispatch otherwise) picks this up as a
	// HandlerResult. Without it, the optimistic update path on the
	// segmented control silently no-ops.
	respBytes, _ := json.Marshal(map[string]interface{}{
		"success":         true,
		"id":              req.ID,
		"discoverability": string(req.Discoverability),
	})

	log.Info().
		Str("secret_id", req.ID).
		Str("discoverability", string(req.Discoverability)).
		Str("owner_space", h.ownerSpace).
		Msg("Critical secret discoverability updated")

	// Toggling discoverability flips whether peers see the metadata
	// row in secret_catalog — push the updated snapshot.
	if h.publisher != nil {
		go RepublishProfile(h.ownerSpace, h.storage, h.publisher, h.state)
	}

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleDelete handles credential.secret.delete messages
// Flow:
//  1. Verify password
//  2. Remove from credential.Secrets[]
//  3. Remove from vault SQLite metadata index
//  4. Re-encrypt credential
//  5. Return new encrypted credential blob + new UTKs
func (h *CredentialSecretHandler) HandleDelete(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req CredentialSecretDeleteRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleDelete"); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	// Validate required fields
	if req.ID == "" {
		return h.errorResponse(msg.GetID(), "id is required")
	}
	if req.EncryptedCredential == "" {
		return h.errorResponse(msg.GetID(), "encrypted_credential is required")
	}
	if req.EncryptedPasswordHash == "" {
		return h.errorResponse(msg.GetID(), "encrypted_password_hash is required")
	}
	if req.KeyID == "" {
		return h.errorResponse(msg.GetID(), "key_id is required")
	}

	// Check metadata index first
	if !h.secretExistsInMetadata(req.ID) {
		return h.errorResponse(msg.GetID(), "Secret not found")
	}

	// Decrypt the credential blob using CEK
	credentialV2, err := h.decryptCredentialBlob(req.EncryptedCredential)
	if err != nil {
		log.Error().Err(err).Str("owner_space", h.ownerSpace).Msg("Failed to decrypt credential for secret delete")
		return h.errorResponse(msg.GetID(), "Failed to decrypt credential")
	}
	defer credentialV2.SecureErase()

	// Verify password
	if err := h.verifyPasswordAgainstCredential(req.EncryptedPasswordHash, req.EphemeralPublicKey, req.Nonce, req.KeyID, credentialV2); err != nil {
		log.Warn().Err(err).Str("owner_space", h.ownerSpace).Msg("Password verification failed for secret deletion")
		h.eventHandler.LogSecurityEvent(
			context.Background(),
			EventTypeAuthAttemptFailed,
			"Secret deletion denied",
			fmt.Sprintf("Failed password verification for secret deletion ID: %s", req.ID),
		)
		return h.errorResponse(msg.GetID(), "Password verification failed")
	}

	// Find and record metadata for audit, then remove from credential's Secrets array
	var deletedName, deletedCategory string
	newSecrets := make([]CredentialSecretEntry, 0, len(credentialV2.Secrets))
	for _, s := range credentialV2.Secrets {
		if s.ID == req.ID {
			deletedName = s.Name
			deletedCategory = string(s.Category)
			// Zero the value before discarding
			zeroBytes(s.Value)
			continue
		}
		newSecrets = append(newSecrets, s)
	}

	if deletedName == "" {
		return h.errorResponse(msg.GetID(), "Secret not found in credential")
	}

	credentialV2.Secrets = newSecrets
	credentialV2.Timestamps.LastModified = time.Now().Unix()
	credentialV2.Version++

	// Re-encrypt credential with CEK
	encryptedCredential, err := h.encryptCredentialBlob(credentialV2)
	if err != nil {
		log.Error().Err(err).Msg("Failed to re-encrypt credential after secret delete")
		return h.errorResponse(msg.GetID(), "Failed to re-encrypt credential")
	}

	// Store sealed credential blob in vault storage for backup inclusion
	if err := h.storage.Put("credential/sealed_blob", []byte(encryptedCredential)); err != nil {
		log.Warn().Err(err).Str("owner_space", h.ownerSpace).Msg("Failed to store credential blob for backup (non-fatal)")
	}

	// Remove from vault SQLite metadata index
	h.removeMetadataRecord(req.ID)

	log.Info().
		Str("secret_id", req.ID).
		Str("owner_space", h.ownerSpace).
		Msg("Credential secret deleted (password verified)")

	// Removing a critical secret drops its row from secret_catalog —
	// push the fresh snapshot so peers / outstanding invites stop
	// advertising it.
	if h.publisher != nil {
		go RepublishProfile(h.ownerSpace, h.storage, h.publisher, h.state)
	}

	// Log audit event for secret deletion
	h.eventHandler.LogSecretEvent(
		context.Background(),
		EventTypeSecretDeleted,
		req.ID,
		deletedName,
		deletedCategory,
	)

	// Generate fresh UTKs and return ONLY the new ones.
	newPairs, err := h.bootstrap.GenerateMoreUTKs(3)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to generate replacement UTKs")
	}
	utkPublics := EncodeUTKPublics(newPairs)

	resp := CredentialSecretDeleteResponse{
		Success:             true,
		EncryptedCredential: encryptedCredential,
		NewUTKs:             utkPublics,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// MutateSecretsResult is what MutateSecrets returns to the caller.
type MutateSecretsResult struct {
	EncryptedCredential string
	NewUTKs             []UTKPublic
}

// MutateSecrets is the shared entry point for any vault op that needs
// to add, remove, or update an entry on the credential's Secrets list
// (e.g. wallet.backup-seed reusing the auth path that powers Critical
// Secrets directly). Wraps decrypt → password verify → mutate →
// re-encrypt → UTK rotation in a single helper so handlers don't
// re-implement the cycle. The mutator runs against the decrypted
// credential; return any error to abort (the credential isn't
// re-encrypted on error).
func (h *CredentialSecretHandler) MutateSecrets(
	encryptedCredential, encryptedPasswordHash, ephemeralPublicKey, nonce, keyID string,
	mutate func(*ProteanCredentialV2) error,
) (MutateSecretsResult, error) {
	var out MutateSecretsResult

	if encryptedCredential == "" || encryptedPasswordHash == "" || keyID == "" {
		return out, fmt.Errorf("missing credential auth fields")
	}

	cred, err := h.decryptCredentialBlob(encryptedCredential)
	if err != nil {
		return out, fmt.Errorf("decrypt credential: %w", err)
	}
	defer cred.SecureErase()

	if err := h.verifyPasswordAgainstCredential(encryptedPasswordHash, ephemeralPublicKey, nonce, keyID, cred); err != nil {
		return out, fmt.Errorf("password verification: %w", err)
	}

	if err := mutate(cred); err != nil {
		return out, err
	}

	cred.Timestamps.LastModified = time.Now().Unix()
	cred.Version++

	sealed, err := h.encryptCredentialBlob(cred)
	if err != nil {
		return out, fmt.Errorf("re-encrypt credential: %w", err)
	}
	if err := h.storage.Put("credential/sealed_blob", []byte(sealed)); err != nil {
		log.Warn().Err(err).Msg("Failed to store credential blob for backup (non-fatal)")
	}

	newPairs, err := h.bootstrap.GenerateMoreUTKs(3)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to generate replacement UTKs")
	}
	out.EncryptedCredential = sealed
	out.NewUTKs = EncodeUTKPublics(newPairs)
	return out, nil
}

// StoreSecretMetadata exposes the metadata index for handlers (like
// the wallet backup-seed path) that mutate Secrets through MutateSecrets
// instead of calling HandleAdd directly.
func (h *CredentialSecretHandler) StoreSecretMetadata(record SecretMetadataRecord) {
	h.storeMetadataRecord(record)
}

// RevealSecretValue is the read-only counterpart to MutateSecrets.
// Given the password material the caller already collected, it
// decrypts the credential blob, finds the entry by ID, returns its
// value as a string, and zeroes the in-memory credential. Used by
// wallet signing when the seed has been moved into the credential.
//
// Caller is responsible for zeroing the returned bytes.
func (h *CredentialSecretHandler) RevealSecretValue(
	secretID, encryptedCredential, encryptedPasswordHash, ephemeralPublicKey, nonce, keyID string,
) (string, error) {
	if secretID == "" {
		return "", fmt.Errorf("secret_id is required")
	}
	credentialV2, err := h.decryptCredentialBlob(encryptedCredential)
	if err != nil {
		return "", fmt.Errorf("decrypt credential: %w", err)
	}
	defer credentialV2.SecureErase()

	if err := h.verifyPasswordAgainstCredential(encryptedPasswordHash, ephemeralPublicKey, nonce, keyID, credentialV2); err != nil {
		return "", fmt.Errorf("password verification failed")
	}

	for i := range credentialV2.Secrets {
		if credentialV2.Secrets[i].ID == secretID {
			value := string(credentialV2.Secrets[i].Value)
			return value, nil
		}
	}
	return "", fmt.Errorf("secret not found in credential")
}

// RemoveSecretMetadata is the counterpart to StoreSecretMetadata for
// the wallet revoke-backup path.
func (h *CredentialSecretHandler) RemoveSecretMetadata(secretID string) {
	h.removeMetadataRecord(secretID)
}

// --- Credential blob operations ---

// decryptCredentialBlob decrypts a CEK-encrypted credential blob and returns V2 format.
// Supports both V1 (UnsealedCredential) and V2 (ProteanCredentialV2) blobs.
// V1 credentials are auto-migrated to V2 using MigrateV1ToV2.
func (h *CredentialSecretHandler) decryptCredentialBlob(encryptedBase64 string) (*ProteanCredentialV2, error) {
	encryptedBytes, err := base64.StdEncoding.DecodeString(encryptedBase64)
	if err != nil {
		return nil, fmt.Errorf("invalid credential encoding: %w", err)
	}

	h.state.mu.RLock()
	cekPair := h.state.cekPair
	h.state.mu.RUnlock()

	if cekPair == nil {
		return nil, fmt.Errorf("CEK not available")
	}

	plaintext, err := decryptWithCEK(cekPair.PrivateKey, encryptedBytes)
	if err != nil {
		return nil, fmt.Errorf("CEK decryption failed: %w", err)
	}
	defer zeroBytes(plaintext)

	// Try V2 format first
	var credV2 ProteanCredentialV2
	if err := json.Unmarshal(plaintext, &credV2); err != nil {
		return nil, fmt.Errorf("failed to parse credential: %w", err)
	}

	if credV2.FormatVersion >= 2 {
		return &credV2, nil
	}

	// V1 credential (format_version 0 or 1) - auto-migrate to V2
	log.Info().Int("format_version", credV2.FormatVersion).Str("owner_space", h.ownerSpace).
		Msg("Auto-migrating V1 credential to V2 format")

	var credV1 UnsealedCredential
	if err := json.Unmarshal(plaintext, &credV1); err != nil {
		return nil, fmt.Errorf("failed to parse V1 credential: %w", err)
	}

	migrated := MigrateV1ToV2(&credV1, h.ownerSpace)
	return migrated, nil
}

// encryptCredentialBlob encrypts a V2 credential with CEK and returns base64
func (h *CredentialSecretHandler) encryptCredentialBlob(cred *ProteanCredentialV2) (string, error) {
	h.state.mu.RLock()
	cekPair := h.state.cekPair
	h.state.mu.RUnlock()

	if cekPair == nil {
		return "", fmt.Errorf("CEK not available")
	}

	credBytes, err := json.Marshal(cred)
	if err != nil {
		return "", fmt.Errorf("failed to serialize credential: %w", err)
	}
	defer zeroBytes(credBytes)

	encryptedBytes, err := encryptWithCEK(cekPair.PublicKey, credBytes)
	if err != nil {
		return "", fmt.Errorf("CEK encryption failed: %w", err)
	}

	return base64.StdEncoding.EncodeToString(encryptedBytes), nil
}

// --- Password verification ---

// verifyPasswordAgainstCredential verifies the password against the credential's Auth.Hash
// The app sends three separate base64-encoded components: ciphertext, ephemeral public key, and nonce.
// These must be combined into the format expected by decryptWithUTK: [ephemeralPubKey(32) | nonce(24) | ciphertext]
func (h *CredentialSecretHandler) verifyPasswordAgainstCredential(encryptedPasswordHash, ephemeralPublicKey, nonce, keyID string, cred *ProteanCredentialV2) error {
	// Get the LTK for the provided UTK ID
	ltk, found := h.bootstrap.GetLTKForUTK(keyID)
	if !found {
		return fmt.Errorf("invalid or expired UTK")
	}

	// Decode the three separate base64-encoded components
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedPasswordHash)
	if err != nil {
		return fmt.Errorf("invalid encrypted_password_hash encoding")
	}

	ephPubKey, err := base64.StdEncoding.DecodeString(ephemeralPublicKey)
	if err != nil {
		return fmt.Errorf("invalid ephemeral_public_key encoding")
	}

	nonceBytes, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		return fmt.Errorf("invalid nonce encoding")
	}

	// Combine into format expected by decryptWithUTK: pubkey(32) || nonce(24) || ciphertext
	combinedPayload := make([]byte, 0, len(ephPubKey)+len(nonceBytes)+len(ciphertext))
	combinedPayload = append(combinedPayload, ephPubKey...)
	combinedPayload = append(combinedPayload, nonceBytes...)
	combinedPayload = append(combinedPayload, ciphertext...)

	// Decrypt using the LTK
	passwordHashBytes, err := decryptWithUTK(ltk, combinedPayload)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}
	defer zeroBytes(passwordHashBytes)

	// Parse decrypted payload - the app sends a PHC string (may be raw or JSON-wrapped)
	passwordHash := string(passwordHashBytes)
	var payload struct {
		PasswordHash string `json:"password_hash"`
	}
	if err := json.Unmarshal(passwordHashBytes, &payload); err == nil && payload.PasswordHash != "" {
		passwordHash = payload.PasswordHash
	}

	// Verify against the credential's PHC hash
	storedHash := cred.Auth.Hash
	if storedHash == "" {
		return fmt.Errorf("credential has no password hash")
	}

	// Compare PHC strings directly (constant-time comparison)
	if !timingSafeEqualStrings(passwordHash, storedHash) {
		return fmt.Errorf("incorrect password")
	}

	// Mark UTK as used (single-use for security)
	h.bootstrap.MarkUTKUsed(keyID)

	return nil
}

// verifyPassword (Phase D: removed). All callers now go through
// verifyPasswordAgainstCredential after decrypting the request-
// supplied credential blob in-flight; the in-memory credential is
// no longer cached.

// --- Metadata index operations (vault SQLite) ---

// storeMetadataRecord stores a metadata record in vault SQLite. When
// upserting over an existing row (same ID) we preserve any prior
// Discoverability the user had set, unless the caller explicitly sets
// a non-empty value. This guards against indirect callers (e.g. the
// wallet backup path) inadvertently resetting a user-chosen "private"
// flag back to default by passing a zero-value record.
func (h *CredentialSecretHandler) storeMetadataRecord(record SecretMetadataRecord) {
	records := h.getAllMetadataRecords()

	for i, r := range records {
		if r.ID == record.ID {
			if record.Discoverability == "" {
				record.Discoverability = r.Discoverability
			}
			records[i] = record
			h.saveMetadataRecords(records)
			return
		}
	}

	if record.Discoverability == "" {
		record.Discoverability = DiscoverabilityCataloged
	}
	records = append(records, record)
	h.saveMetadataRecords(records)
}

// removeMetadataRecord removes a metadata record from vault SQLite
func (h *CredentialSecretHandler) removeMetadataRecord(secretID string) {
	records := h.getAllMetadataRecords()
	newRecords := make([]SecretMetadataRecord, 0, len(records))
	for _, r := range records {
		if r.ID != secretID {
			newRecords = append(newRecords, r)
		}
	}
	h.saveMetadataRecords(newRecords)
}

// secretExistsInMetadata checks if a secret exists in the metadata index
func (h *CredentialSecretHandler) secretExistsInMetadata(secretID string) bool {
	records := h.getAllMetadataRecords()
	for _, r := range records {
		if r.ID == secretID {
			return true
		}
	}
	return false
}

// getAllMetadataRecords returns all metadata records from vault SQLite
func (h *CredentialSecretHandler) getAllMetadataRecords() []SecretMetadataRecord {
	data, err := h.storage.Get("credential-secrets/_metadata")
	if err != nil {
		return nil
	}

	var records []SecretMetadataRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return nil
	}
	return records
}

// saveMetadataRecords persists metadata records to vault SQLite
func (h *CredentialSecretHandler) saveMetadataRecords(records []SecretMetadataRecord) {
	data, _ := json.Marshal(records)
	h.storage.Put("credential-secrets/_metadata", data)
}

// isValidSecretCategory validates the secret category
func isValidSecretCategory(category string) bool {
	switch SecretCategory(category) {
	case SecretCategorySeedPhrase,
		SecretCategoryPrivateKey,
		SecretCategorySigningKey,
		SecretCategoryMasterPassword,
		SecretCategoryRecoveryKey,
		SecretCategoryOther:
		return true
	default:
		return false
	}
}

func (h *CredentialSecretHandler) errorResponse(requestID string, errMsg string) (*OutgoingMessage, error) {
	return &OutgoingMessage{
		RequestID: requestID,
		Type:      MessageTypeError,
		Error:     errMsg,
	}, nil
}
