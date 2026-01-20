package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/mesmerverse/vettid-dev/enclave/vault-manager/storage"
)

// setupCredentialSecretHandler creates a test CredentialSecretHandler with initialized storage
func setupCredentialSecretHandler(t *testing.T) (*CredentialSecretHandler, *EventHandler, func()) {
	t.Helper()

	// Create DEK
	dek := make([]byte, 32)
	rand.Read(dek)

	// Create storage
	store, err := storage.NewSQLiteStorage("test-owner", dek)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}

	// Create encrypted storage wrapper
	encStorage := &EncryptedStorage{
		sqlite:     store,
		ownerSpace: "test-owner",
	}

	// Create vault state
	vaultState := NewVaultState()

	// Create bootstrap handler
	bootstrapHandler := NewBootstrapHandler("test-owner", vaultState)

	// Create event handler
	eventHandler := NewEventHandler("test-owner", encStorage, nil)

	// Create credential secret handler
	handler := NewCredentialSecretHandler("test-owner", encStorage, vaultState, bootstrapHandler, eventHandler)

	cleanup := func() {
		store.Close()
	}

	return handler, eventHandler, cleanup
}

func TestCredentialSecretHandler_HandleAdd_Success(t *testing.T) {
	handler, _, cleanup := setupCredentialSecretHandler(t)
	defer cleanup()

	// Create test data
	encryptedValue := make([]byte, 64)
	rand.Read(encryptedValue)
	ephemeralKey := make([]byte, 33)
	rand.Read(ephemeralKey)
	nonce := make([]byte, 24)
	rand.Read(nonce)

	req := CredentialSecretAddRequest{
		Name:               "My Bitcoin Wallet",
		Category:           "SEED_PHRASE",
		Description:        "Primary wallet seed phrase",
		EncryptedValue:     base64.StdEncoding.EncodeToString(encryptedValue),
		EphemeralPublicKey: base64.StdEncoding.EncodeToString(ephemeralKey),
		Nonce:              base64.StdEncoding.EncodeToString(nonce),
	}
	reqBytes, _ := json.Marshal(req)

	msg := &IncomingMessage{
		ID:      "test-msg-1",
		Payload: reqBytes,
	}

	resp, err := handler.HandleAdd(msg)
	if err != nil {
		t.Fatalf("HandleAdd returned error: %v", err)
	}

	if resp.Type == MessageTypeError {
		t.Fatalf("Expected success, got error: %s", resp.Error)
	}

	var addResp CredentialSecretAddResponse
	if err := json.Unmarshal(resp.Payload, &addResp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if addResp.ID == "" {
		t.Error("Expected ID to be returned")
	}

	if addResp.CreatedAt == "" {
		t.Error("Expected created_at to be returned")
	}
}

func TestCredentialSecretHandler_HandleAdd_ValidationErrors(t *testing.T) {
	handler, _, cleanup := setupCredentialSecretHandler(t)
	defer cleanup()

	tests := []struct {
		name        string
		req         CredentialSecretAddRequest
		expectedErr string
	}{
		{
			name:        "missing name",
			req:         CredentialSecretAddRequest{Category: "SEED_PHRASE", EncryptedValue: "dGVzdA==", EphemeralPublicKey: "dGVzdA==", Nonce: "dGVzdA=="},
			expectedErr: "name is required",
		},
		{
			name:        "missing category",
			req:         CredentialSecretAddRequest{Name: "Test", EncryptedValue: "dGVzdA==", EphemeralPublicKey: "dGVzdA==", Nonce: "dGVzdA=="},
			expectedErr: "category is required",
		},
		{
			name:        "missing encrypted_value",
			req:         CredentialSecretAddRequest{Name: "Test", Category: "SEED_PHRASE", EphemeralPublicKey: "dGVzdA==", Nonce: "dGVzdA=="},
			expectedErr: "encrypted_value is required",
		},
		{
			name:        "missing ephemeral_public_key",
			req:         CredentialSecretAddRequest{Name: "Test", Category: "SEED_PHRASE", EncryptedValue: "dGVzdA==", Nonce: "dGVzdA=="},
			expectedErr: "ephemeral_public_key is required",
		},
		{
			name:        "missing nonce",
			req:         CredentialSecretAddRequest{Name: "Test", Category: "SEED_PHRASE", EncryptedValue: "dGVzdA==", EphemeralPublicKey: "dGVzdA=="},
			expectedErr: "nonce is required",
		},
		{
			name:        "invalid category",
			req:         CredentialSecretAddRequest{Name: "Test", Category: "INVALID", EncryptedValue: "dGVzdA==", EphemeralPublicKey: "dGVzdA==", Nonce: "dGVzdA=="},
			expectedErr: "invalid category",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reqBytes, _ := json.Marshal(tc.req)
			msg := &IncomingMessage{ID: "test-msg", Payload: reqBytes}

			resp, _ := handler.HandleAdd(msg)

			if resp.Type != MessageTypeError {
				t.Errorf("Expected error response, got %s", resp.Type)
			}

			if resp.Error == "" {
				t.Error("Expected error message")
			}
		})
	}
}

func TestCredentialSecretHandler_HandleAdd_AllCategories(t *testing.T) {
	handler, _, cleanup := setupCredentialSecretHandler(t)
	defer cleanup()

	categories := []string{
		"SEED_PHRASE",
		"PRIVATE_KEY",
		"SIGNING_KEY",
		"MASTER_PASSWORD",
		"OTHER",
	}

	for _, cat := range categories {
		t.Run(cat, func(t *testing.T) {
			encryptedValue := make([]byte, 64)
			rand.Read(encryptedValue)
			ephemeralKey := make([]byte, 33)
			rand.Read(ephemeralKey)
			nonce := make([]byte, 24)
			rand.Read(nonce)

			req := CredentialSecretAddRequest{
				Name:               "Test " + cat,
				Category:           cat,
				EncryptedValue:     base64.StdEncoding.EncodeToString(encryptedValue),
				EphemeralPublicKey: base64.StdEncoding.EncodeToString(ephemeralKey),
				Nonce:              base64.StdEncoding.EncodeToString(nonce),
			}
			reqBytes, _ := json.Marshal(req)
			msg := &IncomingMessage{ID: "test-msg-" + cat, Payload: reqBytes}

			resp, _ := handler.HandleAdd(msg)

			if resp.Type == MessageTypeError {
				t.Errorf("Expected success for category %s, got error: %s", cat, resp.Error)
			}
		})
	}
}

func TestCredentialSecretHandler_HandleList_Empty(t *testing.T) {
	handler, _, cleanup := setupCredentialSecretHandler(t)
	defer cleanup()

	msg := &IncomingMessage{ID: "test-list", Payload: []byte("{}")}

	resp, err := handler.HandleList(msg)
	if err != nil {
		t.Fatalf("HandleList returned error: %v", err)
	}

	if resp.Type == MessageTypeError {
		t.Fatalf("Expected success, got error: %s", resp.Error)
	}

	var listResp CredentialSecretListResponse
	if err := json.Unmarshal(resp.Payload, &listResp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if len(listResp.Secrets) != 0 {
		t.Errorf("Expected 0 secrets, got %d", len(listResp.Secrets))
	}
}

func TestCredentialSecretHandler_HandleList_WithSecrets(t *testing.T) {
	handler, _, cleanup := setupCredentialSecretHandler(t)
	defer cleanup()

	// Add some secrets first
	for i := 0; i < 3; i++ {
		encryptedValue := make([]byte, 64)
		rand.Read(encryptedValue)
		ephemeralKey := make([]byte, 33)
		rand.Read(ephemeralKey)
		nonce := make([]byte, 24)
		rand.Read(nonce)

		req := CredentialSecretAddRequest{
			Name:               "Secret " + string(rune('A'+i)),
			Category:           "SEED_PHRASE",
			Description:        "Test secret",
			EncryptedValue:     base64.StdEncoding.EncodeToString(encryptedValue),
			EphemeralPublicKey: base64.StdEncoding.EncodeToString(ephemeralKey),
			Nonce:              base64.StdEncoding.EncodeToString(nonce),
		}
		reqBytes, _ := json.Marshal(req)
		msg := &IncomingMessage{ID: "add-msg", Payload: reqBytes}
		handler.HandleAdd(msg)
	}

	// List secrets
	msg := &IncomingMessage{ID: "test-list", Payload: []byte("{}")}
	resp, _ := handler.HandleList(msg)

	var listResp CredentialSecretListResponse
	if err := json.Unmarshal(resp.Payload, &listResp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if len(listResp.Secrets) != 3 {
		t.Errorf("Expected 3 secrets, got %d", len(listResp.Secrets))
	}

	// Verify metadata is returned but not encrypted values
	for _, secret := range listResp.Secrets {
		if secret.ID == "" {
			t.Error("Expected ID in metadata")
		}
		if secret.Name == "" {
			t.Error("Expected name in metadata")
		}
		if secret.Category == "" {
			t.Error("Expected category in metadata")
		}
		if secret.CreatedAt == "" {
			t.Error("Expected created_at in metadata")
		}
	}
}

func TestCredentialSecretHandler_HandleGet_RequiresPassword(t *testing.T) {
	handler, _, cleanup := setupCredentialSecretHandler(t)
	defer cleanup()

	// Add a secret
	encryptedValue := make([]byte, 64)
	rand.Read(encryptedValue)
	ephemeralKey := make([]byte, 33)
	rand.Read(ephemeralKey)
	nonce := make([]byte, 24)
	rand.Read(nonce)

	addReq := CredentialSecretAddRequest{
		Name:               "Test Secret",
		Category:           "SEED_PHRASE",
		EncryptedValue:     base64.StdEncoding.EncodeToString(encryptedValue),
		EphemeralPublicKey: base64.StdEncoding.EncodeToString(ephemeralKey),
		Nonce:              base64.StdEncoding.EncodeToString(nonce),
	}
	addBytes, _ := json.Marshal(addReq)
	addMsg := &IncomingMessage{ID: "add-msg", Payload: addBytes}
	addResp, _ := handler.HandleAdd(addMsg)

	var added CredentialSecretAddResponse
	json.Unmarshal(addResp.Payload, &added)

	// Try to get without valid password - should fail
	getReq := CredentialSecretGetRequest{
		ID:                    added.ID,
		EncryptedPasswordHash: "invalid",
		KeyID:                 "invalid-key",
	}
	getBytes, _ := json.Marshal(getReq)
	getMsg := &IncomingMessage{ID: "get-msg", Payload: getBytes}

	resp, _ := handler.HandleGet(getMsg)

	if resp.Type != MessageTypeError {
		t.Error("Expected error when password verification fails")
	}

	if resp.Error == "" {
		t.Error("Expected error message")
	}
}

func TestCredentialSecretHandler_HandleGet_MissingFields(t *testing.T) {
	handler, _, cleanup := setupCredentialSecretHandler(t)
	defer cleanup()

	tests := []struct {
		name string
		req  CredentialSecretGetRequest
	}{
		{
			name: "missing id",
			req:  CredentialSecretGetRequest{EncryptedPasswordHash: "test", KeyID: "key"},
		},
		{
			name: "missing password",
			req:  CredentialSecretGetRequest{ID: "test-id", KeyID: "key"},
		},
		{
			name: "missing key_id",
			req:  CredentialSecretGetRequest{ID: "test-id", EncryptedPasswordHash: "test"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reqBytes, _ := json.Marshal(tc.req)
			msg := &IncomingMessage{ID: "test-msg", Payload: reqBytes}

			resp, _ := handler.HandleGet(msg)

			if resp.Type != MessageTypeError {
				t.Errorf("Expected error for %s", tc.name)
			}
		})
	}
}

func TestCredentialSecretHandler_HandleDelete_RequiresPassword(t *testing.T) {
	handler, _, cleanup := setupCredentialSecretHandler(t)
	defer cleanup()

	// Add a secret
	encryptedValue := make([]byte, 64)
	rand.Read(encryptedValue)
	ephemeralKey := make([]byte, 33)
	rand.Read(ephemeralKey)
	nonce := make([]byte, 24)
	rand.Read(nonce)

	addReq := CredentialSecretAddRequest{
		Name:               "Test Secret",
		Category:           "SEED_PHRASE",
		EncryptedValue:     base64.StdEncoding.EncodeToString(encryptedValue),
		EphemeralPublicKey: base64.StdEncoding.EncodeToString(ephemeralKey),
		Nonce:              base64.StdEncoding.EncodeToString(nonce),
	}
	addBytes, _ := json.Marshal(addReq)
	addMsg := &IncomingMessage{ID: "add-msg", Payload: addBytes}
	addResp, _ := handler.HandleAdd(addMsg)

	var added CredentialSecretAddResponse
	json.Unmarshal(addResp.Payload, &added)

	// Try to delete without valid password
	delReq := CredentialSecretDeleteRequest{
		ID:                    added.ID,
		EncryptedPasswordHash: "invalid",
		KeyID:                 "invalid-key",
	}
	delBytes, _ := json.Marshal(delReq)
	delMsg := &IncomingMessage{ID: "del-msg", Payload: delBytes}

	resp, _ := handler.HandleDelete(delMsg)

	if resp.Type != MessageTypeError {
		t.Error("Expected error when password verification fails")
	}

	// Verify secret still exists
	listMsg := &IncomingMessage{ID: "list-msg", Payload: []byte("{}")}
	listResp, _ := handler.HandleList(listMsg)

	var listRes CredentialSecretListResponse
	json.Unmarshal(listResp.Payload, &listRes)

	if len(listRes.Secrets) != 1 {
		t.Error("Secret should still exist after failed delete")
	}
}

func TestCredentialSecretHandler_HandleDelete_MissingFields(t *testing.T) {
	handler, _, cleanup := setupCredentialSecretHandler(t)
	defer cleanup()

	tests := []struct {
		name string
		req  CredentialSecretDeleteRequest
	}{
		{
			name: "missing id",
			req:  CredentialSecretDeleteRequest{EncryptedPasswordHash: "test", KeyID: "key"},
		},
		{
			name: "missing password",
			req:  CredentialSecretDeleteRequest{ID: "test-id", KeyID: "key"},
		},
		{
			name: "missing key_id",
			req:  CredentialSecretDeleteRequest{ID: "test-id", EncryptedPasswordHash: "test"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reqBytes, _ := json.Marshal(tc.req)
			msg := &IncomingMessage{ID: "test-msg", Payload: reqBytes}

			resp, _ := handler.HandleDelete(msg)

			if resp.Type != MessageTypeError {
				t.Errorf("Expected error for %s", tc.name)
			}
		})
	}
}

func TestCredentialSecretHandler_HandleDelete_InvalidID(t *testing.T) {
	handler, _, cleanup := setupCredentialSecretHandler(t)
	defer cleanup()

	delReq := CredentialSecretDeleteRequest{
		ID:                    "non-existent-id",
		EncryptedPasswordHash: "test",
		KeyID:                 "key",
	}
	delBytes, _ := json.Marshal(delReq)
	delMsg := &IncomingMessage{ID: "del-msg", Payload: delBytes}

	resp, _ := handler.HandleDelete(delMsg)

	// Should fail either due to password verification or secret not found
	if resp.Type != MessageTypeError {
		t.Error("Expected error for non-existent secret")
	}
}

func TestCredentialSecretHandler_AuditLogging(t *testing.T) {
	handler, eventHandler, cleanup := setupCredentialSecretHandler(t)
	defer cleanup()

	// Add a secret
	encryptedValue := make([]byte, 64)
	rand.Read(encryptedValue)
	ephemeralKey := make([]byte, 33)
	rand.Read(ephemeralKey)
	nonce := make([]byte, 24)
	rand.Read(nonce)

	addReq := CredentialSecretAddRequest{
		Name:               "Test Secret",
		Category:           "SEED_PHRASE",
		EncryptedValue:     base64.StdEncoding.EncodeToString(encryptedValue),
		EphemeralPublicKey: base64.StdEncoding.EncodeToString(ephemeralKey),
		Nonce:              base64.StdEncoding.EncodeToString(nonce),
	}
	addBytes, _ := json.Marshal(addReq)
	addMsg := &IncomingMessage{ID: "add-msg", Payload: addBytes}
	addResp, _ := handler.HandleAdd(addMsg)

	var added CredentialSecretAddResponse
	json.Unmarshal(addResp.Payload, &added)

	// Try to get with invalid password - should log security event
	getReq := CredentialSecretGetRequest{
		ID:                    added.ID,
		EncryptedPasswordHash: "invalid",
		KeyID:                 "invalid-key",
	}
	getBytes, _ := json.Marshal(getReq)
	getMsg := &IncomingMessage{ID: "get-msg", Payload: getBytes}
	handler.HandleGet(getMsg)

	// Query audit log for security events
	ctx := context.Background()
	auditReq := &AuditQueryRequest{
		EventTypes: []EventType{EventTypeAuthAttemptFailed},
		Limit:      10,
	}

	auditResp, err := eventHandler.QueryAudit(ctx, auditReq)
	if err != nil {
		t.Fatalf("Failed to query audit log: %v", err)
	}

	// Should have at least one failed auth event
	if auditResp.Total == 0 {
		t.Error("Expected security event to be logged for failed password attempt")
	}
}

func TestIsValidSecretCategory(t *testing.T) {
	validCategories := []string{
		"SEED_PHRASE",
		"PRIVATE_KEY",
		"SIGNING_KEY",
		"MASTER_PASSWORD",
		"OTHER",
	}

	for _, cat := range validCategories {
		if !isValidSecretCategory(cat) {
			t.Errorf("Expected %s to be valid", cat)
		}
	}

	invalidCategories := []string{
		"INVALID",
		"seed_phrase", // lowercase
		"SEED",
		"",
	}

	for _, cat := range invalidCategories {
		if isValidSecretCategory(cat) {
			t.Errorf("Expected %s to be invalid", cat)
		}
	}
}
