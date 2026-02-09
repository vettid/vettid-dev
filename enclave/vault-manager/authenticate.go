package main

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/chacha20poly1305"
)

// AuthenticateRequest is the payload for app.authenticate
// Supports two modes:
// 1. Post-enrollment verification: Uses UTK-encrypted password (key_id + encrypted_password_hash)
// 2. Credential restore: Uses plain password hash + backup_key
type AuthenticateRequest struct {
	DeviceID            string `json:"device_id"`             // New device identifier
	DeviceType          string `json:"device_type"`           // "android" or "ios"
	AppVersion          string `json:"app_version"`           // App version
	EncryptedCredential string `json:"encrypted_credential"`  // Base64 encrypted credential blob

	// Mode 1: Post-enrollment verification (UTK-encrypted password)
	KeyID                 string `json:"key_id,omitempty"`                 // UTK ID for decryption
	EncryptedPasswordHash string `json:"encrypted_password_hash,omitempty"` // UTK-encrypted password hash
	EphemeralPublicKey    string `json:"ephemeral_public_key,omitempty"`   // X25519 ephemeral public key
	Nonce                 string `json:"nonce,omitempty"`                  // Base64 encryption nonce

	// Mode 2: Credential restore (plain password hash + backup key)
	PasswordHash        string `json:"password_hash,omitempty"`  // Base64 Argon2id password hash from user
	BackupKey           string `json:"backup_key,omitempty"`     // Base64 32-byte decryption key (from parent)
}

// AuthenticateResponse is the response for app.authenticate
type AuthenticateResponse struct {
	Success      bool     `json:"success"`
	Message      string   `json:"message"`
	UserGUID     string   `json:"user_guid,omitempty"`      // User identifier for credential generation
	DeviceID     string   `json:"device_id,omitempty"`      // Echo back device ID
	DeviceType   string   `json:"device_type,omitempty"`    // Echo back device type
	NewUTKs      []string `json:"new_utks,omitempty"`       // Replacement UTKs after consumption
}

// DecryptedCredentialBlob represents the structure inside an encrypted credential blob
// This matches the Protean Credential format from credential backup
type DecryptedCredentialBlob struct {
	Version      int    `json:"version"`
	UserGUID     string `json:"user_guid"`
	PasswordHash string `json:"password_hash"` // Base64 stored password hash for verification
	CreatedAt    string `json:"created_at"`
}

// handleAuthenticate handles app.authenticate messages
// Supports two modes:
// Mode 1 - Post-enrollment verification: Uses UTK-encrypted password
// Mode 2 - Credential restore: Uses plain password hash + backup key
//
// Security: Password verification happens inside the enclave for maximum security.
func (mh *MessageHandler) handleAuthenticate(msg *IncomingMessage) (*OutgoingMessage, error) {
	// msg.Payload is already unwrapped by central unwrapPayload in handleVaultOp
	var req AuthenticateRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return mh.authErrorResponse(msg.GetID(), "Invalid request payload format")
	}

	// Validate common required fields
	if req.DeviceID == "" {
		return mh.authErrorResponse(msg.GetID(), "device_id is required")
	}
	if req.EncryptedCredential == "" {
		return mh.authErrorResponse(msg.GetID(), "encrypted_credential is required")
	}

	// Determine mode based on fields present
	isUTKMode := req.KeyID != "" && req.EncryptedPasswordHash != ""
	isRestoreMode := req.BackupKey != "" && req.PasswordHash != ""

	if !isUTKMode && !isRestoreMode {
		return mh.authErrorResponse(msg.GetID(), "Either UTK fields (key_id, encrypted_password_hash) or restore fields (backup_key, password_hash) required")
	}

	if isUTKMode {
		return mh.handleUTKAuthenticate(msg.GetID(), &req)
	}
	return mh.handleRestoreAuthenticate(msg.GetID(), &req)
}

// handleUTKAuthenticate handles post-enrollment verification using UTK-encrypted password
func (mh *MessageHandler) handleUTKAuthenticate(requestID string, req *AuthenticateRequest) (*OutgoingMessage, error) {
	log.Info().
		Str("device_id", req.DeviceID).
		Str("device_type", req.DeviceType).
		Str("key_id", req.KeyID).
		Msg("Processing post-enrollment verification (UTK mode)")

	// Get the LTK for the provided UTK ID
	ltk, found := mh.bootstrapHandler.GetLTKForUTK(req.KeyID)
	if !found {
		log.Warn().Str("key_id", req.KeyID).Msg("Invalid or expired UTK")
		return mh.authErrorResponse(requestID, "Invalid or expired UTK")
	}

	// Decode the separate components sent by the app
	// App sends: encrypted_password_hash (ciphertext), ephemeral_public_key, nonce
	// decryptWithUTK expects: ephemeral_pubkey (32) || nonce (24) || ciphertext
	ciphertext, err := base64.StdEncoding.DecodeString(req.EncryptedPasswordHash)
	if err != nil {
		log.Warn().Err(err).Msg("Invalid encrypted_password_hash encoding")
		return mh.authErrorResponse(requestID, "Invalid encrypted_password_hash encoding")
	}

	ephemeralPubKey, err := base64.StdEncoding.DecodeString(req.EphemeralPublicKey)
	if err != nil {
		log.Warn().Err(err).Msg("Invalid ephemeral_public_key encoding")
		return mh.authErrorResponse(requestID, "Invalid ephemeral_public_key encoding")
	}

	nonce, err := base64.StdEncoding.DecodeString(req.Nonce)
	if err != nil {
		log.Warn().Err(err).Msg("Invalid nonce encoding")
		return mh.authErrorResponse(requestID, "Invalid nonce encoding")
	}

	// Combine into the format expected by decryptWithUTK: pubkey (32) || nonce (24) || ciphertext
	combinedPayload := make([]byte, 0, len(ephemeralPubKey)+len(nonce)+len(ciphertext))
	combinedPayload = append(combinedPayload, ephemeralPubKey...)
	combinedPayload = append(combinedPayload, nonce...)
	combinedPayload = append(combinedPayload, ciphertext...)

	// Decrypt using the LTK
	passwordHashBytes, err := decryptWithUTK(ltk, combinedPayload)
	if err != nil {
		log.Warn().Msg("Failed to decrypt password hash")
		return mh.authErrorResponse(requestID, "Authentication failed")
	}
	defer zeroBytes(passwordHashBytes)

	// Parse the decrypted payload - it contains {"password_hash": "PHC string"}
	var payload struct {
		PasswordHash string `json:"password_hash"`
	}
	if err := json.Unmarshal(passwordHashBytes, &payload); err != nil {
		// Try interpreting as raw PHC string
		payload.PasswordHash = string(passwordHashBytes)
		log.Debug().Msg("JSON unmarshal failed, using raw string")
	}

	log.Debug().
		Int("payload_hash_len", len(payload.PasswordHash)).
		Msg("Decrypted password hash from app")

	// Get the stored credential to verify against
	// First decrypt the encrypted_credential using CEK
	encryptedCred, err := base64.StdEncoding.DecodeString(req.EncryptedCredential)
	if err != nil {
		log.Warn().Err(err).Msg("Invalid encrypted_credential encoding")
		return mh.authErrorResponse(requestID, "Invalid encrypted_credential encoding")
	}

	log.Debug().Int("encrypted_cred_len", len(encryptedCred)).Msg("Decoded encrypted credential")

	// Check if CEK is available
	hasCEK := mh.vaultState != nil && mh.vaultState.cekPair != nil
	log.Debug().Bool("has_cek", hasCEK).Msg("DEBUG: Checking CEK availability")

	// Decrypt credential with CEK
	credentialBytes, err := mh.decryptCredentialWithCEK(encryptedCred)
	if err != nil {
		log.Warn().Msg("Failed to decrypt credential")
		return mh.authErrorResponse(requestID, "Authentication failed")
	}
	defer zeroBytes(credentialBytes)

	log.Debug().Int("credential_bytes_len", len(credentialBytes)).Msg("Decrypted credential")

	// Parse the credential
	var credential struct {
		PasswordHash string `json:"password_hash"`
		UserGUID     string `json:"user_guid"`
	}
	if err := json.Unmarshal(credentialBytes, &credential); err != nil {
		log.Warn().Err(err).Msg("Failed to parse credential")
		return mh.authErrorResponse(requestID, "Invalid credential format")
	}

	log.Debug().
		Bool("has_stored_hash", len(credential.PasswordHash) > 0).
		Msg("Retrieved stored credential for verification")

	// Verify the password hash matches (constant-time for PHC strings)
	if !timingSafeEqualStrings(payload.PasswordHash, credential.PasswordHash) {
		log.Warn().
			Str("device_id", req.DeviceID).
			Msg("Password verification failed")
		return mh.authErrorResponse(requestID, "Authentication failed")
	}

	// Mark UTK as used
	mh.bootstrapHandler.MarkUTKUsed(req.KeyID)

	log.Info().
		Str("device_id", req.DeviceID).
		Str("user_guid", credential.UserGUID).
		Msg("Post-enrollment verification successful")

	// Get replacement UTKs to replenish the app's pool
	newUTKs := mh.bootstrapHandler.GetUnusedUTKs()
	log.Debug().Int("new_utks_count", len(newUTKs)).Msg("Including replacement UTKs in auth response")

	resp := AuthenticateResponse{
		Success:    true,
		Message:    "Authentication successful",
		UserGUID:   credential.UserGUID,
		DeviceID:   req.DeviceID,
		DeviceType: req.DeviceType,
		NewUTKs:    newUTKs,
	}

	respBytes, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response: %w", err)
	}

	return &OutgoingMessage{
		RequestID: requestID,
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// handleRestoreAuthenticate handles credential restore using backup key
func (mh *MessageHandler) handleRestoreAuthenticate(requestID string, req *AuthenticateRequest) (*OutgoingMessage, error) {
	log.Info().
		Str("device_id", req.DeviceID).
		Str("device_type", req.DeviceType).
		Msg("Processing restore authentication request in enclave")

	// Validate restore-specific fields
	if req.Nonce == "" {
		return mh.authErrorResponse(requestID, "nonce is required for restore")
	}

	// Step 1: Decode base64 inputs
	encryptedCred, err := base64.StdEncoding.DecodeString(req.EncryptedCredential)
	if err != nil {
		log.Warn().Err(err).Msg("Invalid encrypted_credential encoding")
		return mh.authErrorResponse(requestID, "Invalid encrypted_credential encoding")
	}

	nonce, err := base64.StdEncoding.DecodeString(req.Nonce)
	if err != nil {
		log.Warn().Err(err).Msg("Invalid nonce encoding")
		return mh.authErrorResponse(requestID, "Invalid nonce encoding")
	}

	backupKey, err := base64.StdEncoding.DecodeString(req.BackupKey)
	if err != nil {
		log.Warn().Err(err).Msg("Invalid backup_key encoding")
		return mh.authErrorResponse(requestID, "Invalid backup_key encoding")
	}

	if len(backupKey) != 32 {
		log.Warn().Int("key_len", len(backupKey)).Msg("Invalid backup key length")
		return mh.authErrorResponse(requestID, "Invalid backup key")
	}

	providedHash, err := base64.StdEncoding.DecodeString(req.PasswordHash)
	if err != nil {
		log.Warn().Err(err).Msg("Invalid password_hash encoding")
		return mh.authErrorResponse(requestID, "Invalid password_hash encoding")
	}

	// Step 2: Decrypt the credential blob using ChaCha20-Poly1305
	credentialBytes, err := decryptWithKey(backupKey, encryptedCred, nonce)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to decrypt credential backup")
		return mh.authErrorResponse(requestID, "Failed to decrypt credential - invalid key or corrupted backup")
	}
	// SECURITY: Zero the backup key after use
	defer zeroBytes(backupKey)

	// Step 3: Parse the decrypted credential
	var credential DecryptedCredentialBlob
	if err := json.Unmarshal(credentialBytes, &credential); err != nil {
		log.Warn().Err(err).Msg("Failed to parse decrypted credential")
		return mh.authErrorResponse(requestID, "Invalid credential format")
	}
	// SECURITY: Zero the credential bytes after parsing
	defer zeroBytes(credentialBytes)

	// Step 4: Verify the password hash matches
	storedHash, err := base64.StdEncoding.DecodeString(credential.PasswordHash)
	if err != nil {
		log.Error().Msg("Stored password hash has invalid encoding")
		return mh.authErrorResponse(requestID, "Credential data corrupted")
	}

	// Constant-time comparison to prevent timing attacks
	if !timingSafeEqual(providedHash, storedHash) {
		log.Warn().
			Str("device_id", req.DeviceID).
			Str("user_guid", credential.UserGUID).
			Msg("Password verification failed during restore")
		return mh.authErrorResponse(requestID, "Password verification failed")
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
		RequestID: requestID,
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// decryptCredentialWithCEK decrypts the credential blob using the CEK
func (mh *MessageHandler) decryptCredentialWithCEK(encryptedCred []byte) ([]byte, error) {
	if mh.vaultState == nil || mh.vaultState.cekPair == nil {
		return nil, fmt.Errorf("CEK not available")
	}
	return decryptWithCEK(mh.vaultState.cekPair.PrivateKey, encryptedCred)
}

// timingSafeEqualStrings compares two strings in constant time.
// SECURITY: Uses crypto/subtle.ConstantTimeCompare which does not leak
// length information through timing (returns 0 for different-length inputs).
func timingSafeEqualStrings(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
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
