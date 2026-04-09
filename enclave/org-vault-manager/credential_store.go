package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
)

// CredentialStore manages encrypted credential storage within the org vault.
// Credentials are stored with metadata (visible) and secret values (encrypted,
// only decrypted in-memory during proxy operations).
type CredentialStore struct {
	ownerSpace string
	storage    *EncryptedStorage
}

// NewCredentialStore creates a new credential store.
func NewCredentialStore(ownerSpace string, storage *EncryptedStorage) *CredentialStore {
	return &CredentialStore{
		ownerSpace: ownerSpace,
		storage:    storage,
	}
}

// StoreCredential stores a credential's metadata and secret values separately.
func (cs *CredentialStore) StoreCredential(cred *StoredCredential, secretData []byte) error {
	// Store metadata
	if err := cs.storage.PutJSON(KeyCredentialPrefix+cred.CredentialID, cred); err != nil {
		return fmt.Errorf("failed to store credential metadata: %w", err)
	}

	// Store secret value separately
	if err := cs.storage.Put(KeyCredentialSecret+cred.CredentialID, secretData); err != nil {
		return fmt.Errorf("failed to store credential secret: %w", err)
	}

	// Add to index
	if err := cs.storage.AddToIndex(KeyCredentialIndex, cred.CredentialID); err != nil {
		return fmt.Errorf("failed to update credential index: %w", err)
	}

	log.Info().
		Str("credential_id", cred.CredentialID).
		Str("type", cred.CredentialType).
		Str("label", cred.Label).
		Msg("Credential stored")

	return nil
}

// GetCredentialMetadata retrieves credential metadata (no secrets).
func (cs *CredentialStore) GetCredentialMetadata(credentialID string) (*StoredCredential, error) {
	var cred StoredCredential
	if err := cs.storage.GetJSON(KeyCredentialPrefix+credentialID, &cred); err != nil {
		return nil, fmt.Errorf("credential not found: %s", credentialID)
	}
	return &cred, nil
}

// GetCredentialSecret retrieves and decrypts a credential's secret value.
// SECURITY: The returned bytes should be zeroed after use.
func (cs *CredentialStore) GetCredentialSecret(credentialID string) ([]byte, error) {
	data, err := cs.storage.Get(KeyCredentialSecret + credentialID)
	if err != nil {
		return nil, fmt.Errorf("failed to get credential secret: %w", err)
	}
	if data == nil {
		return nil, fmt.Errorf("credential secret not found: %s", credentialID)
	}
	return data, nil
}

// ListCredentials returns metadata for all stored credentials (no secrets).
func (cs *CredentialStore) ListCredentials() ([]StoredCredential, error) {
	ids, err := cs.storage.GetIndex(KeyCredentialIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to read credential index: %w", err)
	}

	var creds []StoredCredential
	for _, id := range ids {
		var cred StoredCredential
		if err := cs.storage.GetJSON(KeyCredentialPrefix+id, &cred); err != nil {
			log.Warn().Str("credential_id", id).Err(err).Msg("Failed to read credential, skipping")
			continue
		}
		creds = append(creds, cred)
	}
	return creds, nil
}

// RotateCredential atomically replaces a credential's secret value.
func (cs *CredentialStore) RotateCredential(credentialID string, newSecretData []byte) error {
	// Verify credential exists
	cred, err := cs.GetCredentialMetadata(credentialID)
	if err != nil {
		return err
	}

	// SECURITY: Delete old secret (zeroed in storage.Delete)
	if err := cs.storage.Delete(KeyCredentialSecret + credentialID); err != nil {
		return fmt.Errorf("failed to remove old secret: %w", err)
	}

	// Store new secret
	if err := cs.storage.Put(KeyCredentialSecret+credentialID, newSecretData); err != nil {
		return fmt.Errorf("failed to store new secret: %w", err)
	}

	// Update rotation timestamp
	cred.RotatedAt = time.Now()
	if err := cs.storage.PutJSON(KeyCredentialPrefix+credentialID, cred); err != nil {
		return fmt.Errorf("failed to update credential metadata: %w", err)
	}

	log.Info().
		Str("credential_id", credentialID).
		Msg("Credential rotated")

	return nil
}

// DeleteCredential removes a credential and its secret value.
func (cs *CredentialStore) DeleteCredential(credentialID string) error {
	// Remove secret (zeroed in storage.Delete)
	if err := cs.storage.Delete(KeyCredentialSecret + credentialID); err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	// Remove metadata
	if err := cs.storage.Delete(KeyCredentialPrefix + credentialID); err != nil {
		return fmt.Errorf("failed to delete metadata: %w", err)
	}

	// Remove from index
	if err := cs.storage.RemoveFromIndex(KeyCredentialIndex, credentialID); err != nil {
		return fmt.Errorf("failed to update index: %w", err)
	}

	log.Info().
		Str("credential_id", credentialID).
		Msg("Credential deleted")

	return nil
}

// --- Message Handlers ---

// HandleStore handles a credential.store request.
func (cs *CredentialStore) HandleStore(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		CredentialID   string            `json:"credential_id"`
		CredentialType string            `json:"credential_type"`
		Label          string            `json:"label"`
		Metadata       map[string]string `json:"metadata"`
		AccessPolicy   AccessPolicy      `json:"access_policy"`
		SecretData     json.RawMessage   `json:"secret_data"` // The actual credential values
	}

	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return errorResponse(msg.GetID(), "invalid request: "+err.Error())
	}

	if req.CredentialID == "" {
		req.CredentialID = generateID()
	}
	if req.CredentialType == "" {
		return errorResponse(msg.GetID(), "credential_type is required")
	}

	now := time.Now()
	cred := &StoredCredential{
		CredentialID:   req.CredentialID,
		CredentialType: req.CredentialType,
		Label:          req.Label,
		Metadata:       req.Metadata,
		AccessPolicy:   req.AccessPolicy,
		CreatedAt:      now,
		RotatedAt:      now,
	}

	if err := cs.StoreCredential(cred, []byte(req.SecretData)); err != nil {
		return errorResponse(msg.GetID(), "failed to store credential: "+err.Error())
	}

	return successResponse(msg.GetID(), map[string]interface{}{
		"success":       true,
		"credential_id": cred.CredentialID,
	})
}

// HandleList handles a credential.list request.
func (cs *CredentialStore) HandleList(msg *IncomingMessage) (*OutgoingMessage, error) {
	creds, err := cs.ListCredentials()
	if err != nil {
		return errorResponse(msg.GetID(), "failed to list credentials: "+err.Error())
	}

	return successResponse(msg.GetID(), map[string]interface{}{
		"success":     true,
		"credentials": creds,
		"count":       len(creds),
	})
}

// HandleRotate handles a credential.rotate request.
func (cs *CredentialStore) HandleRotate(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		CredentialID string          `json:"credential_id"`
		SecretData   json.RawMessage `json:"secret_data"`
	}

	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return errorResponse(msg.GetID(), "invalid request: "+err.Error())
	}

	if req.CredentialID == "" {
		return errorResponse(msg.GetID(), "credential_id is required")
	}

	if err := cs.RotateCredential(req.CredentialID, []byte(req.SecretData)); err != nil {
		return errorResponse(msg.GetID(), "failed to rotate credential: "+err.Error())
	}

	return successResponse(msg.GetID(), map[string]interface{}{
		"success":       true,
		"credential_id": req.CredentialID,
		"rotated_at":    time.Now(),
	})
}

// HandleDelete handles a credential.delete request.
func (cs *CredentialStore) HandleDelete(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		CredentialID string `json:"credential_id"`
	}

	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return errorResponse(msg.GetID(), "invalid request: "+err.Error())
	}

	if req.CredentialID == "" {
		return errorResponse(msg.GetID(), "credential_id is required")
	}

	if err := cs.DeleteCredential(req.CredentialID); err != nil {
		return errorResponse(msg.GetID(), "failed to delete credential: "+err.Error())
	}

	return successResponse(msg.GetID(), map[string]interface{}{
		"success":       true,
		"credential_id": req.CredentialID,
	})
}

// --- Helpers ---

func errorResponse(requestID, message string) (*OutgoingMessage, error) {
	return &OutgoingMessage{
		RequestID: requestID,
		Type:      MessageTypeResponse,
		Payload:   mustMarshal(map[string]interface{}{"success": false, "error": message}),
	}, nil
}

func successResponse(requestID string, payload interface{}) (*OutgoingMessage, error) {
	return &OutgoingMessage{
		RequestID: requestID,
		Type:      MessageTypeResponse,
		Payload:   mustMarshal(payload),
	}, nil
}
