package main

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// testEncryptWithKey encrypts data for testing
func testEncryptWithKey(t *testing.T, key, plaintext, nonce []byte) []byte {
	t.Helper()

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}

	return aead.Seal(nil, nonce, plaintext, nil)
}

// createTestCredential creates an encrypted credential for testing
func createTestCredential(t *testing.T, key []byte, userGUID, passwordHash string) (ciphertext, nonce string) {
	t.Helper()

	cred := DecryptedCredentialBlob{
		Version:      1,
		UserGUID:     userGUID,
		PasswordHash: passwordHash,
		CreatedAt:    "2024-01-01T00:00:00Z",
	}

	credBytes, err := json.Marshal(cred)
	if err != nil {
		t.Fatalf("Failed to marshal credential: %v", err)
	}

	// Generate nonce
	nonceBytes := make([]byte, 12)
	for i := range nonceBytes {
		nonceBytes[i] = byte(i + 1)
	}

	encryptedBytes := testEncryptWithKey(t, key, credBytes, nonceBytes)

	return base64.StdEncoding.EncodeToString(encryptedBytes),
		base64.StdEncoding.EncodeToString(nonceBytes)
}

func TestAuthenticateHandler_Success(t *testing.T) {
	// Create test encryption key
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}

	// Create test password hash
	passwordHash := make([]byte, 32)
	copy(passwordHash, []byte("MySecurePassword123!"))
	passwordHashB64 := base64.StdEncoding.EncodeToString(passwordHash)

	// Create encrypted credential with matching password hash
	encryptedCred, nonce := createTestCredential(t, key, "user-guid-456", passwordHashB64)

	// Create message handler
	mh := &MessageHandler{
		ownerSpace: "test-owner",
	}

	// Build request
	req := AuthenticateRequest{
		DeviceID:            "test-device-001",
		DeviceType:          "android",
		AppVersion:          "1.0.0",
		EncryptedCredential: encryptedCred,
		PasswordHash:        passwordHashB64,
		Nonce:               nonce,
		BackupKey:           base64.StdEncoding.EncodeToString(key),
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	msg := &IncomingMessage{
		ID:      "test-msg-001",
		Type:    MessageTypeVaultOp,
		Subject: "OwnerSpace.test-owner.forVault.app.authenticate",
		Payload: reqBytes,
	}

	// Call handler
	response, err := mh.handleAuthenticate(msg)
	if err != nil {
		t.Fatalf("Handler returned error: %v", err)
	}

	// Parse response
	var resp AuthenticateResponse
	if err := json.Unmarshal(response.Payload, &resp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	// Verify success
	if !resp.Success {
		t.Errorf("Expected success=true, got false. Message: %s", resp.Message)
	}

	if resp.UserGUID != "user-guid-456" {
		t.Errorf("Expected user_guid='user-guid-456', got '%s'", resp.UserGUID)
	}

	if resp.DeviceID != "test-device-001" {
		t.Errorf("Expected device_id='test-device-001', got '%s'", resp.DeviceID)
	}

	t.Logf("Authentication successful! UserGUID: %s", resp.UserGUID)
}

func TestAuthenticateHandler_WrongPassword(t *testing.T) {
	// Create test encryption key
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}

	// Correct password hash stored in credential
	correctPasswordHash := make([]byte, 32)
	copy(correctPasswordHash, []byte("CorrectPassword"))
	correctPasswordHashB64 := base64.StdEncoding.EncodeToString(correctPasswordHash)

	// Wrong password hash provided by attacker
	wrongPasswordHash := make([]byte, 32)
	copy(wrongPasswordHash, []byte("WrongPassword!!!"))
	wrongPasswordHashB64 := base64.StdEncoding.EncodeToString(wrongPasswordHash)

	// Create credential with correct password
	encryptedCred, nonce := createTestCredential(t, key, "user-123", correctPasswordHashB64)

	mh := &MessageHandler{
		ownerSpace: "test-owner",
	}

	// Request with WRONG password
	req := AuthenticateRequest{
		DeviceID:            "attacker-device",
		DeviceType:          "android",
		AppVersion:          "1.0.0",
		EncryptedCredential: encryptedCred,
		PasswordHash:        wrongPasswordHashB64,
		Nonce:               nonce,
		BackupKey:           base64.StdEncoding.EncodeToString(key),
	}

	reqBytes, _ := json.Marshal(req)

	msg := &IncomingMessage{
		ID:      "test-msg-002",
		Type:    MessageTypeVaultOp,
		Payload: reqBytes,
	}

	response, err := mh.handleAuthenticate(msg)
	if err != nil {
		t.Fatalf("Handler returned error: %v", err)
	}

	var resp AuthenticateResponse
	json.Unmarshal(response.Payload, &resp)

	// Should fail due to wrong password
	if resp.Success {
		t.Error("Expected authentication to FAIL with wrong password, but it succeeded!")
	}

	if resp.Message != "Password verification failed" {
		t.Errorf("Expected 'Password verification failed', got: %s", resp.Message)
	}

	if resp.UserGUID != "" {
		t.Error("Expected no user_guid to be returned for failed auth")
	}

	t.Logf("Correctly rejected wrong password. Message: %s", resp.Message)
}

func TestAuthenticateHandler_InvalidKey(t *testing.T) {
	// Create test encryption key
	correctKey := make([]byte, 32)
	for i := range correctKey {
		correctKey[i] = byte(i + 1)
	}

	// Wrong key
	wrongKey := make([]byte, 32)
	for i := range wrongKey {
		wrongKey[i] = byte(i + 100)
	}

	passwordHash := base64.StdEncoding.EncodeToString([]byte("password"))
	encryptedCred, nonce := createTestCredential(t, correctKey, "user-123", passwordHash)

	mh := &MessageHandler{
		ownerSpace: "test-owner",
	}

	// Request with WRONG key
	req := AuthenticateRequest{
		DeviceID:            "test-device",
		DeviceType:          "ios",
		AppVersion:          "1.0.0",
		EncryptedCredential: encryptedCred,
		PasswordHash:        passwordHash,
		Nonce:               nonce,
		BackupKey:           base64.StdEncoding.EncodeToString(wrongKey),
	}

	reqBytes, _ := json.Marshal(req)

	msg := &IncomingMessage{
		ID:      "test-msg-003",
		Type:    MessageTypeVaultOp,
		Payload: reqBytes,
	}

	response, err := mh.handleAuthenticate(msg)
	if err != nil {
		t.Fatalf("Handler returned error: %v", err)
	}

	var resp AuthenticateResponse
	json.Unmarshal(response.Payload, &resp)

	if resp.Success {
		t.Error("Expected authentication to FAIL with wrong key")
	}

	if resp.Message != "Failed to decrypt credential - invalid key or corrupted backup" {
		t.Errorf("Expected decryption failure message, got: %s", resp.Message)
	}

	t.Logf("Correctly rejected wrong key. Message: %s", resp.Message)
}

func TestAuthenticateHandler_MissingFields(t *testing.T) {
	mh := &MessageHandler{
		ownerSpace: "test-owner",
	}

	testCases := []struct {
		name          string
		request       AuthenticateRequest
		expectedError string
	}{
		{
			name:          "missing device_id",
			request:       AuthenticateRequest{EncryptedCredential: "x", PasswordHash: "x", Nonce: "x", BackupKey: "x"},
			expectedError: "device_id is required",
		},
		{
			name:          "missing encrypted_credential",
			request:       AuthenticateRequest{DeviceID: "x", PasswordHash: "x", Nonce: "x", BackupKey: "x"},
			expectedError: "encrypted_credential is required",
		},
		{
			name:          "missing auth fields",
			request:       AuthenticateRequest{DeviceID: "x", EncryptedCredential: "x"},
			expectedError: "Either UTK fields (key_id, encrypted_password_hash) or restore fields (backup_key, password_hash) required",
		},
		{
			name:          "restore missing nonce",
			request:       AuthenticateRequest{DeviceID: "x", EncryptedCredential: "x", PasswordHash: "x", BackupKey: "x"},
			expectedError: "nonce is required for restore",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reqBytes, _ := json.Marshal(tc.request)

			msg := &IncomingMessage{
				ID:      "test-msg",
				Type:    MessageTypeVaultOp,
				Payload: reqBytes,
			}

			response, err := mh.handleAuthenticate(msg)
			if err != nil {
				t.Fatalf("Handler returned error: %v", err)
			}

			var resp AuthenticateResponse
			json.Unmarshal(response.Payload, &resp)

			if resp.Success {
				t.Errorf("Expected failure for %s", tc.name)
			}

			if resp.Message != tc.expectedError {
				t.Errorf("Expected '%s', got '%s'", tc.expectedError, resp.Message)
			}
		})
	}
}
