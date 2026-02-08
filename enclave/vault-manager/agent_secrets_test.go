package main

import (
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/vettid/vettid-dev/enclave/vault-manager/storage"
)

// setupAgentSecretsHandler creates a test AgentSecretsHandler with initialized storage.
func setupAgentSecretsHandler(t *testing.T) (*AgentSecretsHandler, func()) {
	t.Helper()

	dek := make([]byte, 32)
	rand.Read(dek)

	store, err := storage.NewSQLiteStorage("test-owner", dek)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}

	encStorage := &EncryptedStorage{
		sqlite:     store,
		ownerSpace: "test-owner",
	}

	eventHandler := NewEventHandler("test-owner", encStorage, nil)
	handler := NewAgentSecretsHandler("test-owner", encStorage, eventHandler)

	cleanup := func() {
		store.Close()
	}

	return handler, cleanup
}

func TestAgentSecrets_ShareAndGet(t *testing.T) {
	handler, cleanup := setupAgentSecretsHandler(t)
	defer cleanup()

	// Share a secret
	reqPayload, _ := json.Marshal(ShareSecretRequest{
		Name:           "Test API Key",
		Category:       "api_keys",
		Description:    "OpenAI API key for testing",
		Tags:           []string{"openai", "testing"},
		Value:          "sk-test-12345",
		AllowedActions: []string{"retrieve"},
	})

	msg := &IncomingMessage{
		RequestID: "test-1",
		Payload:   reqPayload,
	}

	resp, err := handler.HandleShareSecret(msg)
	if err != nil {
		t.Fatalf("HandleShareSecret failed: %v", err)
	}

	var shareResp ShareSecretResponse
	json.Unmarshal(resp.Payload, &shareResp)

	if !shareResp.Success {
		t.Fatal("Expected success=true")
	}
	if shareResp.SecretID == "" {
		t.Fatal("Expected non-empty secret_id")
	}

	// Get the secret back
	secret, err := handler.GetSecret(shareResp.SecretID)
	if err != nil {
		t.Fatalf("GetSecret failed: %v", err)
	}

	if secret.Name != "Test API Key" {
		t.Errorf("Expected name 'Test API Key', got '%s'", secret.Name)
	}
	if secret.Category != "api_keys" {
		t.Errorf("Expected category 'api_keys', got '%s'", secret.Category)
	}
	if secret.Value != "sk-test-12345" {
		t.Errorf("Expected value 'sk-test-12345', got '%s'", secret.Value)
	}
	if len(secret.AllowedActions) != 1 || secret.AllowedActions[0] != "retrieve" {
		t.Errorf("Expected allowed_actions=['retrieve'], got %v", secret.AllowedActions)
	}
}

func TestAgentSecrets_ShareWithCustomID(t *testing.T) {
	handler, cleanup := setupAgentSecretsHandler(t)
	defer cleanup()

	reqPayload, _ := json.Marshal(ShareSecretRequest{
		SecretID:       "my-custom-id",
		Name:           "My Secret",
		Category:       "api_keys",
		Value:          "secret-value",
		AllowedActions: []string{"retrieve", "use"},
	})

	msg := &IncomingMessage{
		RequestID: "test-2",
		Payload:   reqPayload,
	}

	resp, _ := handler.HandleShareSecret(msg)

	var shareResp ShareSecretResponse
	json.Unmarshal(resp.Payload, &shareResp)

	if shareResp.SecretID != "my-custom-id" {
		t.Errorf("Expected secret_id 'my-custom-id', got '%s'", shareResp.SecretID)
	}
}

func TestAgentSecrets_UpdateSecret(t *testing.T) {
	handler, cleanup := setupAgentSecretsHandler(t)
	defer cleanup()

	// Create a secret first
	createPayload, _ := json.Marshal(ShareSecretRequest{
		SecretID:       "update-test",
		Name:           "Original Name",
		Category:       "api_keys",
		Value:          "original-value",
		AllowedActions: []string{"retrieve"},
	})
	handler.HandleShareSecret(&IncomingMessage{RequestID: "create", Payload: createPayload})

	// Update it
	updatePayload, _ := json.Marshal(UpdateSharedSecretRequest{
		SecretID: "update-test",
		Name:     "Updated Name",
		Value:    "new-value",
	})

	resp, err := handler.HandleUpdateSharedSecret(&IncomingMessage{RequestID: "update", Payload: updatePayload})
	if err != nil {
		t.Fatalf("HandleUpdateSharedSecret failed: %v", err)
	}

	var updateResp map[string]interface{}
	json.Unmarshal(resp.Payload, &updateResp)
	if updateResp["success"] != true {
		t.Fatal("Expected success=true")
	}

	// Verify update
	secret, _ := handler.GetSecret("update-test")
	if secret.Name != "Updated Name" {
		t.Errorf("Expected name 'Updated Name', got '%s'", secret.Name)
	}
	if secret.Value != "new-value" {
		t.Errorf("Expected value 'new-value', got '%s'", secret.Value)
	}
	// Category should remain unchanged
	if secret.Category != "api_keys" {
		t.Errorf("Expected category 'api_keys', got '%s'", secret.Category)
	}
}

func TestAgentSecrets_RevokeSecret(t *testing.T) {
	handler, cleanup := setupAgentSecretsHandler(t)
	defer cleanup()

	// Create a secret
	createPayload, _ := json.Marshal(ShareSecretRequest{
		SecretID:       "revoke-test",
		Name:           "To Be Revoked",
		Category:       "ssh_keys",
		Value:          "private-key-data",
		AllowedActions: []string{"use"},
	})
	handler.HandleShareSecret(&IncomingMessage{RequestID: "create", Payload: createPayload})

	// Revoke it
	revokePayload, _ := json.Marshal(RevokeSharedSecretRequest{
		SecretID: "revoke-test",
	})

	resp, err := handler.HandleRevokeSharedSecret(&IncomingMessage{RequestID: "revoke", Payload: revokePayload})
	if err != nil {
		t.Fatalf("HandleRevokeSharedSecret failed: %v", err)
	}

	var revokeResp map[string]interface{}
	json.Unmarshal(resp.Payload, &revokeResp)
	if revokeResp["success"] != true {
		t.Fatal("Expected success=true")
	}

	// Verify it's gone
	_, err = handler.GetSecret("revoke-test")
	if err == nil {
		t.Fatal("Expected error getting revoked secret")
	}
}

func TestAgentSecrets_ListSecrets(t *testing.T) {
	handler, cleanup := setupAgentSecretsHandler(t)
	defer cleanup()

	// Create multiple secrets
	secrets := []ShareSecretRequest{
		{SecretID: "s1", Name: "API Key 1", Category: "api_keys", Value: "v1", AllowedActions: []string{"retrieve"}},
		{SecretID: "s2", Name: "API Key 2", Category: "api_keys", Value: "v2", AllowedActions: []string{"retrieve"}},
		{SecretID: "s3", Name: "SSH Key 1", Category: "ssh_keys", Value: "v3", AllowedActions: []string{"use"}},
	}

	for _, s := range secrets {
		payload, _ := json.Marshal(s)
		handler.HandleShareSecret(&IncomingMessage{RequestID: "create", Payload: payload})
	}

	// List all
	listPayload, _ := json.Marshal(ListSharedSecretsRequest{})
	resp, _ := handler.HandleListSharedSecrets(&IncomingMessage{RequestID: "list", Payload: listPayload})

	var listResp ListSharedSecretsResponse
	json.Unmarshal(resp.Payload, &listResp)

	if len(listResp.Secrets) != 3 {
		t.Errorf("Expected 3 secrets, got %d", len(listResp.Secrets))
	}

	// List filtered by category
	filterPayload, _ := json.Marshal(ListSharedSecretsRequest{Category: "ssh_keys"})
	resp, _ = handler.HandleListSharedSecrets(&IncomingMessage{RequestID: "list-filter", Payload: filterPayload})

	json.Unmarshal(resp.Payload, &listResp)
	if len(listResp.Secrets) != 1 {
		t.Errorf("Expected 1 ssh_keys secret, got %d", len(listResp.Secrets))
	}
	if listResp.Secrets[0].SecretID != "s3" {
		t.Errorf("Expected secret_id 's3', got '%s'", listResp.Secrets[0].SecretID)
	}
}

func TestAgentSecrets_BuildCatalog(t *testing.T) {
	handler, cleanup := setupAgentSecretsHandler(t)
	defer cleanup()

	// Create secrets
	secrets := []ShareSecretRequest{
		{SecretID: "c1", Name: "API Key", Category: "api_keys", Value: "v1", AllowedActions: []string{"retrieve"}},
		{SecretID: "c2", Name: "SSH Key", Category: "ssh_keys", Value: "v2", AllowedActions: []string{"use"}},
		{SecretID: "c3", Name: "DB Pass", Category: "database", Value: "v3", AllowedActions: []string{"retrieve", "use"}},
	}
	for _, s := range secrets {
		payload, _ := json.Marshal(s)
		handler.HandleShareSecret(&IncomingMessage{RequestID: "create", Payload: payload})
	}

	// Build full catalog (empty scope = all)
	catalog := handler.BuildCatalog([]string{})
	if len(catalog.Entries) != 3 {
		t.Errorf("Expected 3 catalog entries, got %d", len(catalog.Entries))
	}

	// Build scoped catalog
	catalog = handler.BuildCatalog([]string{"api_keys", "database"})
	if len(catalog.Entries) != 2 {
		t.Errorf("Expected 2 catalog entries for scoped query, got %d", len(catalog.Entries))
	}

	// Verify catalog entries don't include values
	for _, entry := range catalog.Entries {
		// AgentSecretCatalogEntry has no Value field, so this is structural
		if entry.SecretID == "" || entry.Name == "" || entry.Category == "" {
			t.Errorf("Catalog entry missing required fields: %+v", entry)
		}
	}
}

func TestAgentSecrets_ValidationErrors(t *testing.T) {
	handler, cleanup := setupAgentSecretsHandler(t)
	defer cleanup()

	// Missing name
	payload, _ := json.Marshal(ShareSecretRequest{
		Category:       "api_keys",
		Value:          "v1",
		AllowedActions: []string{"retrieve"},
	})
	resp, _ := handler.HandleShareSecret(&IncomingMessage{RequestID: "test", Payload: payload})
	var errResp map[string]interface{}
	json.Unmarshal(resp.Payload, &errResp)
	if errResp["success"] != false {
		t.Error("Expected success=false for missing name")
	}

	// Invalid action
	payload, _ = json.Marshal(ShareSecretRequest{
		Name:           "Test",
		Category:       "api_keys",
		Value:          "v1",
		AllowedActions: []string{"invalid"},
	})
	resp, _ = handler.HandleShareSecret(&IncomingMessage{RequestID: "test", Payload: payload})
	json.Unmarshal(resp.Payload, &errResp)
	if errResp["success"] != false {
		t.Error("Expected success=false for invalid action")
	}
}

func TestAgentSecrets_InScope(t *testing.T) {
	if !InScope("api_keys", []string{}) {
		t.Error("Empty scope should match all")
	}
	if !InScope("api_keys", []string{"api_keys", "ssh_keys"}) {
		t.Error("api_keys should be in scope")
	}
	if InScope("database", []string{"api_keys", "ssh_keys"}) {
		t.Error("database should not be in scope")
	}
}

func TestAgentSecrets_HasAction(t *testing.T) {
	if !HasAction("retrieve", []string{"retrieve", "use"}) {
		t.Error("retrieve should be found")
	}
	if HasAction("delete", []string{"retrieve", "use"}) {
		t.Error("delete should not be found")
	}
}

func TestAgentSecrets_CatalogVersion(t *testing.T) {
	handler, cleanup := setupAgentSecretsHandler(t)
	defer cleanup()

	v0 := handler.getCatalogVersion()
	if v0 != 0 {
		t.Errorf("Expected initial version 0, got %d", v0)
	}

	// Share a secret to increment version
	payload, _ := json.Marshal(ShareSecretRequest{
		SecretID:       "ver-test",
		Name:           "Test",
		Category:       "api_keys",
		Value:          "v1",
		AllowedActions: []string{"retrieve"},
	})
	handler.HandleShareSecret(&IncomingMessage{RequestID: "create", Payload: payload})

	v1 := handler.getCatalogVersion()
	if v1 != 1 {
		t.Errorf("Expected version 1 after share, got %d", v1)
	}

	// Revoke to increment again
	revokePayload, _ := json.Marshal(RevokeSharedSecretRequest{SecretID: "ver-test"})
	handler.HandleRevokeSharedSecret(&IncomingMessage{RequestID: "revoke", Payload: revokePayload})

	v2 := handler.getCatalogVersion()
	if v2 != 2 {
		t.Errorf("Expected version 2 after revoke, got %d", v2)
	}
}
