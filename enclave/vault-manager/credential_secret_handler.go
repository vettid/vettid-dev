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

// HandleAdd handles credential.secret.add messages
// Flow:
//  1. Verify password (decrypt credential -> check Auth.Hash)
//  2. Add secret to credential.Secrets[]
//  3. Store METADATA ONLY in vault SQLite (name, category, owner)
//  4. Re-encrypt credential with CEK
//  5. Return new encrypted credential blob + new UTKs
func (h *CredentialSecretHandler) HandleAdd(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req CredentialSecretAddRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
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
		return h.errorResponse(msg.GetID(), "invalid category: must be SEED_PHRASE, PRIVATE_KEY, SIGNING_KEY, MASTER_PASSWORD, or OTHER")
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

	// Store metadata in vault SQLite (NO values - just metadata for listing)
	metadataRecord := SecretMetadataRecord{
		ID:          secretID,
		Name:        req.Name,
		Category:    req.Category,
		Description: req.Description,
		Owner:       "user",
		CreatedAt:   now.Unix(),
	}
	h.storeMetadataRecord(metadataRecord)

	log.Info().
		Str("secret_id", secretID).
		Str("category", req.Category).
		Str("owner_space", h.ownerSpace).
		Msg("Credential secret added to credential blob")

	// Generate fresh UTKs
	if err := h.bootstrap.GenerateMoreUTKs(3); err != nil {
		log.Warn().Err(err).Msg("Failed to generate replacement UTKs")
	}
	utks := h.bootstrap.GetUnusedUTKPairs()
	utkPublics := make([]UTKPublic, len(utks))
	for i, utk := range utks {
		utkPublics[i] = UTKPublic{
			ID:        utk.ID,
			PublicKey: base64.StdEncoding.EncodeToString(utk.UTK),
		}
	}

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
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
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

	// Generate fresh UTKs
	if err := h.bootstrap.GenerateMoreUTKs(3); err != nil {
		log.Warn().Err(err).Msg("Failed to generate replacement UTKs")
	}
	utks := h.bootstrap.GetUnusedUTKPairs()
	utkPublics := make([]UTKPublic, len(utks))
	for i, utk := range utks {
		utkPublics[i] = UTKPublic{
			ID:        utk.ID,
			PublicKey: base64.StdEncoding.EncodeToString(utk.UTK),
		}
	}

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
	json.Unmarshal(msg.Payload, &req)

	// Verify password if provided (for enhanced metadata)
	var passwordVerified bool
	if req.EncryptedPasswordHash != "" && req.KeyID != "" {
		if err := h.verifyPassword(req.EncryptedPasswordHash, req.EphemeralPublicKey, req.Nonce, req.KeyID); err != nil {
			log.Warn().Err(err).Str("owner_space", h.ownerSpace).Msg("Password verification failed for secret list")
			return h.errorResponse(msg.GetID(), "Password verification failed")
		}
		passwordVerified = true
	}

	// Read metadata from vault SQLite
	metadataRecords := h.getAllMetadataRecords()
	secrets := make([]CredentialSecretMetadata, 0, len(metadataRecords))
	for _, record := range metadataRecords {
		secrets = append(secrets, CredentialSecretMetadata{
			ID:          record.ID,
			Name:        record.Name,
			Category:    record.Category,
			Description: record.Description,
			Owner:       record.Owner,
			CreatedAt:   time.Unix(record.CreatedAt, 0).Format(time.RFC3339),
		})
	}

	resp := CredentialSecretListResponse{
		Secrets: secrets,
	}

	// If password verified, include crypto key metadata and credential info from in-memory state
	if passwordVerified {
		h.state.mu.RLock()
		credential := h.state.credential
		h.state.mu.RUnlock()

		if credential != nil {
			// Crypto key metadata (public info only)
			// Use V1 credential's crypto keys
			cryptoKeys := make([]CryptoKeyMetadata, len(credential.CryptoKeys))
			for i, k := range credential.CryptoKeys {
				cryptoKeys[i] = CryptoKeyMetadata{
					ID:        fmt.Sprintf("key-%d", i),
					Label:     k.Label,
					Type:      k.Type,
					CreatedAt: time.Unix(k.CreatedAt, 0).Format(time.RFC3339),
				}
			}
			resp.CryptoKeys = cryptoKeys

			// Credential info metadata
			fingerprint := sha256.Sum256(credential.IdentityPublicKey)
			resp.Credential = &CredentialInfoMetadata{
				IdentityFingerprint: hex.EncodeToString(fingerprint[:8]),
				Version:             credential.Version,
				CreatedAt:           time.Unix(credential.CreatedAt, 0).Format(time.RFC3339),
				LastModified:        time.Unix(credential.CreatedAt, 0).Format(time.RFC3339),
			}
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

// HandleDelete handles credential.secret.delete messages
// Flow:
//  1. Verify password
//  2. Remove from credential.Secrets[]
//  3. Remove from vault SQLite metadata index
//  4. Re-encrypt credential
//  5. Return new encrypted credential blob + new UTKs
func (h *CredentialSecretHandler) HandleDelete(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req CredentialSecretDeleteRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
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

	// Remove from vault SQLite metadata index
	h.removeMetadataRecord(req.ID)

	log.Info().
		Str("secret_id", req.ID).
		Str("owner_space", h.ownerSpace).
		Msg("Credential secret deleted (password verified)")

	// Log audit event for secret deletion
	h.eventHandler.LogSecretEvent(
		context.Background(),
		EventTypeSecretDeleted,
		req.ID,
		deletedName,
		deletedCategory,
	)

	// Generate fresh UTKs
	if err := h.bootstrap.GenerateMoreUTKs(3); err != nil {
		log.Warn().Err(err).Msg("Failed to generate replacement UTKs")
	}
	utks := h.bootstrap.GetUnusedUTKPairs()
	utkPublics := make([]UTKPublic, len(utks))
	for i, utk := range utks {
		utkPublics[i] = UTKPublic{
			ID:        utk.ID,
			PublicKey: base64.StdEncoding.EncodeToString(utk.UTK),
		}
	}

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

// --- Credential blob operations ---

// decryptCredentialBlob decrypts a CEK-encrypted credential blob and returns V2 format
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

	var credV2 ProteanCredentialV2
	if err := json.Unmarshal(plaintext, &credV2); err != nil {
		return nil, fmt.Errorf("failed to parse credential: %w", err)
	}
	if credV2.FormatVersion < 2 {
		return nil, fmt.Errorf("unsupported credential format version %d (expected >= 2)", credV2.FormatVersion)
	}
	return &credV2, nil
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

// verifyPassword verifies the password against the in-memory credential (for list operation)
// The app sends three separate base64-encoded components: ciphertext, ephemeral public key, and nonce.
func (h *CredentialSecretHandler) verifyPassword(encryptedPasswordHash, ephemeralPublicKey, nonce, keyID string) error {
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

	// Get the stored credential's password hash
	h.state.mu.RLock()
	credential := h.state.credential
	h.state.mu.RUnlock()

	if credential == nil {
		return fmt.Errorf("no credential available")
	}

	// Compare PHC strings directly (constant-time comparison)
	if !timingSafeEqualStrings(passwordHash, credential.PasswordHash) {
		return fmt.Errorf("incorrect password")
	}

	// Mark UTK as used (single-use for security)
	h.bootstrap.MarkUTKUsed(keyID)

	return nil
}

// --- Metadata index operations (vault SQLite) ---

// storeMetadataRecord stores a metadata record in vault SQLite
func (h *CredentialSecretHandler) storeMetadataRecord(record SecretMetadataRecord) {
	records := h.getAllMetadataRecords()

	// Check if already exists
	for i, r := range records {
		if r.ID == record.ID {
			records[i] = record
			h.saveMetadataRecords(records)
			return
		}
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
