package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/chacha20poly1305"
)

// AuthenticateRequest is the payload for app.authenticate
// Used during credential restore to verify identity inside the enclave
type AuthenticateRequest struct {
	DeviceID            string `json:"device_id"`             // New device identifier
	DeviceType          string `json:"device_type"`           // "android" or "ios"
	AppVersion          string `json:"app_version"`           // App version
	EncryptedCredential string `json:"encrypted_credential"`  // Base64 encrypted credential blob
	PasswordHash        string `json:"password_hash"`         // Base64 Argon2id password hash from user
	Nonce               string `json:"nonce"`                 // Base64 encryption nonce

	// The backup key is passed from the parent process (fetched from storage)
	BackupKey           string `json:"backup_key"`            // Base64 32-byte decryption key
}

// AuthenticateResponse is the response for app.authenticate
type AuthenticateResponse struct {
	Success      bool   `json:"success"`
	Message      string `json:"message"`
	UserGUID     string `json:"user_guid,omitempty"`      // User identifier for credential generation
	DeviceID     string `json:"device_id,omitempty"`      // Echo back device ID
	DeviceType   string `json:"device_type,omitempty"`    // Echo back device type
}

// DecryptedCredentialBlob represents the structure inside an encrypted credential blob
// This matches the Protean Credential format from credential backup
type DecryptedCredentialBlob struct {
	Version      int    `json:"version"`
	UserGUID     string `json:"user_guid"`
	PasswordHash string `json:"password_hash"` // Base64 stored password hash for verification
	CreatedAt    string `json:"created_at"`
}

// handleAuthenticate handles app.authenticate messages for credential restore
//
// Security flow:
// 1. App receives encrypted credential blob from Lambda (via restoreConfirm)
// 2. App connects to vault with short-lived bootstrap credentials
// 3. App sends encrypted credential + password hash to vault via NATS
// 4. Parent process looks up backup decryption key and passes to enclave
// 5. Enclave decrypts credential and verifies password hash matches
// 6. On success: returns user_guid to parent which issues NATS credentials
//
// This keeps password verification inside the enclave for maximum security.
func (mh *MessageHandler) handleAuthenticate(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req AuthenticateRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return mh.authErrorResponse(msg.GetID(), "Invalid request format")
	}

	// Validate required fields
	if req.DeviceID == "" {
		return mh.authErrorResponse(msg.GetID(), "device_id is required")
	}
	if req.EncryptedCredential == "" {
		return mh.authErrorResponse(msg.GetID(), "encrypted_credential is required")
	}
	if req.PasswordHash == "" {
		return mh.authErrorResponse(msg.GetID(), "password_hash is required")
	}
	if req.Nonce == "" {
		return mh.authErrorResponse(msg.GetID(), "nonce is required")
	}
	if req.BackupKey == "" {
		return mh.authErrorResponse(msg.GetID(), "backup_key is required")
	}

	log.Info().
		Str("device_id", req.DeviceID).
		Str("device_type", req.DeviceType).
		Msg("Processing restore authentication request in enclave")

	// Step 1: Decode base64 inputs
	encryptedCred, err := base64.StdEncoding.DecodeString(req.EncryptedCredential)
	if err != nil {
		log.Warn().Err(err).Msg("Invalid encrypted_credential encoding")
		return mh.authErrorResponse(msg.GetID(), "Invalid encrypted_credential encoding")
	}

	nonce, err := base64.StdEncoding.DecodeString(req.Nonce)
	if err != nil {
		log.Warn().Err(err).Msg("Invalid nonce encoding")
		return mh.authErrorResponse(msg.GetID(), "Invalid nonce encoding")
	}

	backupKey, err := base64.StdEncoding.DecodeString(req.BackupKey)
	if err != nil {
		log.Warn().Err(err).Msg("Invalid backup_key encoding")
		return mh.authErrorResponse(msg.GetID(), "Invalid backup_key encoding")
	}

	if len(backupKey) != 32 {
		log.Warn().Int("key_len", len(backupKey)).Msg("Invalid backup key length")
		return mh.authErrorResponse(msg.GetID(), "Invalid backup key")
	}

	providedHash, err := base64.StdEncoding.DecodeString(req.PasswordHash)
	if err != nil {
		log.Warn().Err(err).Msg("Invalid password_hash encoding")
		return mh.authErrorResponse(msg.GetID(), "Invalid password_hash encoding")
	}

	// Step 2: Decrypt the credential blob using ChaCha20-Poly1305
	credentialBytes, err := decryptWithKey(backupKey, encryptedCred, nonce)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to decrypt credential backup")
		return mh.authErrorResponse(msg.GetID(), "Failed to decrypt credential - invalid key or corrupted backup")
	}
	// SECURITY: Zero the backup key after use
	defer zeroBytes(backupKey)

	// Step 3: Parse the decrypted credential
	var credential DecryptedCredentialBlob
	if err := json.Unmarshal(credentialBytes, &credential); err != nil {
		log.Warn().Err(err).Msg("Failed to parse decrypted credential")
		return mh.authErrorResponse(msg.GetID(), "Invalid credential format")
	}
	// SECURITY: Zero the credential bytes after parsing
	defer zeroBytes(credentialBytes)

	// Step 4: Verify the password hash matches
	storedHash, err := base64.StdEncoding.DecodeString(credential.PasswordHash)
	if err != nil {
		log.Error().Msg("Stored password hash has invalid encoding")
		return mh.authErrorResponse(msg.GetID(), "Credential data corrupted")
	}

	// Constant-time comparison to prevent timing attacks
	if !timingSafeEqual(providedHash, storedHash) {
		log.Warn().
			Str("device_id", req.DeviceID).
			Str("user_guid", credential.UserGUID).
			Msg("Password verification failed during restore")
		return mh.authErrorResponse(msg.GetID(), "Password verification failed")
	}

	log.Info().
		Str("device_id", req.DeviceID).
		Str("user_guid", credential.UserGUID).
		Msg("Password verified successfully in enclave")

	// Step 5: Return success with user_guid
	// The parent process will use this to generate NATS credentials
	resp := AuthenticateResponse{
		Success:    true,
		Message:    "Authentication successful",
		UserGUID:   credential.UserGUID,
		DeviceID:   req.DeviceID,
		DeviceType: req.DeviceType,
	}

	respBytes, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response: %w", err)
	}

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// authErrorResponse creates an authentication error response
func (mh *MessageHandler) authErrorResponse(id string, message string) (*OutgoingMessage, error) {
	resp := AuthenticateResponse{
		Success: false,
		Message: message,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: id,
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// decryptWithKey decrypts data using ChaCha20-Poly1305
func decryptWithKey(key, ciphertext, nonce []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("invalid nonce size: expected %d, got %d", aead.NonceSize(), len(nonce))
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}
