package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// CredentialSecretHandler handles critical secret storage within the Protean Credential.
// These secrets (seed phrases, private keys, etc.) require password verification for access.
type CredentialSecretHandler struct {
	ownerSpace string
	storage    *EncryptedStorage
	state      *VaultState
	bootstrap  *BootstrapHandler
}

// NewCredentialSecretHandler creates a new credential secret handler
func NewCredentialSecretHandler(ownerSpace string, storage *EncryptedStorage, state *VaultState, bootstrap *BootstrapHandler) *CredentialSecretHandler {
	return &CredentialSecretHandler{
		ownerSpace: ownerSpace,
		storage:    storage,
		state:      state,
		bootstrap:  bootstrap,
	}
}

// HandleAdd handles credential.secret.add messages
// Stores a pre-encrypted secret with metadata
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
	if req.EncryptedValue == "" {
		return h.errorResponse(msg.GetID(), "encrypted_value is required")
	}
	if req.EphemeralPublicKey == "" {
		return h.errorResponse(msg.GetID(), "ephemeral_public_key is required")
	}
	if req.Nonce == "" {
		return h.errorResponse(msg.GetID(), "nonce is required")
	}

	// Validate category
	if !isValidSecretCategory(req.Category) {
		return h.errorResponse(msg.GetID(), "invalid category: must be SEED_PHRASE, PRIVATE_KEY, SIGNING_KEY, MASTER_PASSWORD, or OTHER")
	}

	// Decode base64 values
	encryptedValue, err := base64.StdEncoding.DecodeString(req.EncryptedValue)
	if err != nil {
		return h.errorResponse(msg.GetID(), "invalid encrypted_value encoding")
	}
	ephemeralPublicKey, err := base64.StdEncoding.DecodeString(req.EphemeralPublicKey)
	if err != nil {
		return h.errorResponse(msg.GetID(), "invalid ephemeral_public_key encoding")
	}
	nonce, err := base64.StdEncoding.DecodeString(req.Nonce)
	if err != nil {
		return h.errorResponse(msg.GetID(), "invalid nonce encoding")
	}

	// Generate secret ID
	secretID := uuid.New().String()
	now := time.Now()

	// Create the secret record
	secret := CredentialSecret{
		ID:                 secretID,
		Name:               req.Name,
		Category:           SecretCategory(req.Category),
		Description:        req.Description,
		EncryptedValue:     encryptedValue,
		EphemeralPublicKey: ephemeralPublicKey,
		Nonce:              nonce,
		CreatedAt:          now.Unix(),
		UpdatedAt:          now.Unix(),
	}

	// Marshal and store
	data, err := json.Marshal(secret)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to marshal secret")
	}

	storageKey := "credential-secrets/" + secretID
	if err := h.storage.Put(storageKey, data); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to store secret")
	}

	// Add to index
	h.addToSecretIndex(secretID)

	log.Info().
		Str("secret_id", secretID).
		Str("category", req.Category).
		Str("owner_space", h.ownerSpace).
		Msg("Credential secret stored")

	resp := CredentialSecretAddResponse{
		ID:        secretID,
		CreatedAt: now.Format(time.RFC3339),
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleGet handles credential.secret.get messages
// Requires password verification before returning the encrypted secret
func (h *CredentialSecretHandler) HandleGet(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req CredentialSecretGetRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	// Validate required fields
	if req.ID == "" {
		return h.errorResponse(msg.GetID(), "id is required")
	}
	if req.EncryptedPasswordHash == "" {
		return h.errorResponse(msg.GetID(), "encrypted_password_hash is required")
	}
	if req.KeyID == "" {
		return h.errorResponse(msg.GetID(), "key_id is required")
	}

	// Verify password
	if err := h.verifyPassword(req.EncryptedPasswordHash, req.KeyID); err != nil {
		log.Warn().Err(err).Str("owner_space", h.ownerSpace).Msg("Password verification failed for secret access")
		return h.errorResponse(msg.GetID(), "Password verification failed")
	}

	// Retrieve the secret
	storageKey := "credential-secrets/" + req.ID
	data, err := h.storage.Get(storageKey)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Secret not found")
	}

	var secret CredentialSecret
	if err := json.Unmarshal(data, &secret); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to unmarshal secret")
	}

	resp := CredentialSecretGetResponse{
		ID:                 secret.ID,
		Name:               secret.Name,
		Category:           string(secret.Category),
		EncryptedValue:     base64.StdEncoding.EncodeToString(secret.EncryptedValue),
		EphemeralPublicKey: base64.StdEncoding.EncodeToString(secret.EphemeralPublicKey),
		Nonce:              base64.StdEncoding.EncodeToString(secret.Nonce),
	}
	respBytes, _ := json.Marshal(resp)

	log.Info().
		Str("secret_id", req.ID).
		Str("owner_space", h.ownerSpace).
		Msg("Credential secret retrieved (password verified)")

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleList handles credential.secret.list messages
// Returns metadata only (no password required)
func (h *CredentialSecretHandler) HandleList(msg *IncomingMessage) (*OutgoingMessage, error) {
	// Get the secret IDs from index
	var index []string
	indexData, err := h.storage.Get("credential-secrets/_index")
	if err == nil {
		json.Unmarshal(indexData, &index)
	}

	secrets := make([]CredentialSecretMetadata, 0, len(index))

	for _, secretID := range index {
		storageKey := "credential-secrets/" + secretID
		data, err := h.storage.Get(storageKey)
		if err != nil {
			// Skip missing secrets (might have been deleted)
			continue
		}

		var secret CredentialSecret
		if err := json.Unmarshal(data, &secret); err != nil {
			continue
		}

		secrets = append(secrets, CredentialSecretMetadata{
			ID:          secret.ID,
			Name:        secret.Name,
			Category:    string(secret.Category),
			Description: secret.Description,
			CreatedAt:   time.Unix(secret.CreatedAt, 0).Format(time.RFC3339),
		})
	}

	resp := CredentialSecretListResponse{
		Secrets: secrets,
	}
	respBytes, _ := json.Marshal(resp)

	log.Debug().
		Int("count", len(secrets)).
		Str("owner_space", h.ownerSpace).
		Msg("Listed credential secrets")

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleDelete handles credential.secret.delete messages
// Requires password verification before deleting
func (h *CredentialSecretHandler) HandleDelete(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req CredentialSecretDeleteRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	// Validate required fields
	if req.ID == "" {
		return h.errorResponse(msg.GetID(), "id is required")
	}
	if req.EncryptedPasswordHash == "" {
		return h.errorResponse(msg.GetID(), "encrypted_password_hash is required")
	}
	if req.KeyID == "" {
		return h.errorResponse(msg.GetID(), "key_id is required")
	}

	// Verify password
	if err := h.verifyPassword(req.EncryptedPasswordHash, req.KeyID); err != nil {
		log.Warn().Err(err).Str("owner_space", h.ownerSpace).Msg("Password verification failed for secret deletion")
		return h.errorResponse(msg.GetID(), "Password verification failed")
	}

	// Delete the secret
	storageKey := "credential-secrets/" + req.ID
	if err := h.storage.Delete(storageKey); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to delete secret")
	}

	// Remove from index
	h.removeFromSecretIndex(req.ID)

	log.Info().
		Str("secret_id", req.ID).
		Str("owner_space", h.ownerSpace).
		Msg("Credential secret deleted (password verified)")

	resp := CredentialSecretDeleteResponse{
		Success: true,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// verifyPassword decrypts and verifies the password against the stored credential
func (h *CredentialSecretHandler) verifyPassword(encryptedPasswordHash, keyID string) error {
	// Get the LTK for the provided UTK ID
	ltk, found := h.bootstrap.GetLTKForUTK(keyID)
	if !found {
		return fmt.Errorf("invalid or expired UTK")
	}

	// Decode the encrypted password hash
	encryptedBytes, err := base64.StdEncoding.DecodeString(encryptedPasswordHash)
	if err != nil {
		return fmt.Errorf("invalid encrypted_password_hash encoding")
	}

	// Decrypt using the LTK
	passwordBytes, err := decryptWithUTK(ltk, encryptedBytes)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}
	defer zeroBytes(passwordBytes)

	// Get the stored credential's password hash
	h.state.mu.RLock()
	credential := h.state.credential
	h.state.mu.RUnlock()

	if credential == nil {
		return fmt.Errorf("no credential available")
	}

	// Verify the password against the stored PHC hash
	valid, err := verifyPHCHash(passwordBytes, credential.PasswordHash)
	if err != nil {
		return fmt.Errorf("password verification error: %w", err)
	}
	if !valid {
		return fmt.Errorf("incorrect password")
	}

	// Mark UTK as used (single-use for security)
	h.bootstrap.MarkUTKUsed(keyID)

	return nil
}

// addToSecretIndex adds a secret ID to the index
func (h *CredentialSecretHandler) addToSecretIndex(secretID string) {
	var index []string
	indexData, err := h.storage.Get("credential-secrets/_index")
	if err == nil {
		json.Unmarshal(indexData, &index)
	}

	// Check if already in index
	for _, id := range index {
		if id == secretID {
			return
		}
	}

	index = append(index, secretID)
	newIndexData, _ := json.Marshal(index)
	h.storage.Put("credential-secrets/_index", newIndexData)
}

// removeFromSecretIndex removes a secret ID from the index
func (h *CredentialSecretHandler) removeFromSecretIndex(secretID string) {
	var index []string
	indexData, err := h.storage.Get("credential-secrets/_index")
	if err == nil {
		json.Unmarshal(indexData, &index)
	}

	// Remove the ID
	newIndex := make([]string, 0, len(index))
	for _, id := range index {
		if id != secretID {
			newIndex = append(newIndex, id)
		}
	}

	newIndexData, _ := json.Marshal(newIndex)
	h.storage.Put("credential-secrets/_index", newIndexData)
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
