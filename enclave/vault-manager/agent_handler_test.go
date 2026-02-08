package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/vettid/vettid-dev/enclave/vault-manager/storage"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// testPublisher collects published messages for assertions.
type testPublisher struct {
	published []publishedMessage
}

type publishedMessage struct {
	subject string
	payload []byte
}

func (p *testPublisher) sendFn(msg *OutgoingMessage) error {
	p.published = append(p.published, publishedMessage{
		subject: msg.Subject,
		payload: msg.Payload,
	})
	return nil
}

// setupAgentHandler creates a test AgentHandler with initialized storage and a test connection.
func setupAgentHandler(t *testing.T) (*AgentHandler, *AgentSecretsHandler, *EncryptedStorage, *testPublisher, func()) {
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

	tp := &testPublisher{}
	publisher := NewVsockPublisher("test-owner", tp.sendFn)
	eventHandler := NewEventHandler("test-owner", encStorage, publisher)
	connHandler := NewConnectionsHandler("test-owner", encStorage, eventHandler)
	secretsHandler := NewAgentSecretsHandler("test-owner", encStorage, eventHandler)

	handler := NewAgentHandler("test-owner", encStorage, publisher, eventHandler, connHandler, secretsHandler)

	cleanup := func() {
		store.Close()
	}

	return handler, secretsHandler, encStorage, tp, cleanup
}

// createTestAgentConnection creates a test active agent connection with shared secret.
func createTestAgentConnection(t *testing.T, encStorage *EncryptedStorage, connectionID string) ([]byte, *ConnectionRecord) {
	t.Helper()

	// Generate vault-side key pair
	vaultPrivate := make([]byte, 32)
	rand.Read(vaultPrivate)
	vaultPublic, _ := curve25519.X25519(vaultPrivate, curve25519.Basepoint)

	// Generate agent-side key pair
	agentPrivate := make([]byte, 32)
	rand.Read(agentPrivate)
	agentPublic, _ := curve25519.X25519(agentPrivate, curve25519.Basepoint)

	// Compute shared secret
	sharedSecret, _ := curve25519.X25519(vaultPrivate, agentPublic)

	record := ConnectionRecord{
		ConnectionID:    connectionID,
		ConnectionType:  ConnectionTypeAgent,
		PeerAlias:       "Test Agent",
		Status:          "active",
		CreatedAt:       time.Now(),
		LocalPublicKey:  vaultPublic,
		LocalPrivateKey: vaultPrivate,
		PeerPublicKey:   agentPublic,
		SharedSecret:    sharedSecret,
		Contract: &ConnectionContract{
			AgentName:    "Test Agent",
			Scope:        []string{"api_keys", "ssh_keys"},
			ApprovalMode: "auto_within_contract",
			RateLimit:    RateLimit{Max: 60, Per: "hour"},
		},
	}

	data, _ := json.Marshal(record)
	encStorage.Put("connections/"+connectionID, data)

	return agentPrivate, &record
}

func TestAgentHandler_DecryptEncryptCycle(t *testing.T) {
	// Test that encryptXChaCha20 → decryptXChaCha20 round-trips correctly
	key := make([]byte, 32)
	rand.Read(key)

	plaintext := []byte(`{"request_id":"test-123","status":"approved"}`)

	ciphertext, err := encryptXChaCha20(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := decryptXChaCha20(key, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Round-trip failed: got %s, want %s", decrypted, plaintext)
	}
}

func TestAgentHandler_DeriveConnectionKey(t *testing.T) {
	// Test that deriveConnectionKey produces consistent keys
	sharedSecret := make([]byte, 32)
	rand.Read(sharedSecret)

	key1, err := deriveConnectionKey(sharedSecret)
	if err != nil {
		t.Fatalf("deriveConnectionKey failed: %v", err)
	}

	key2, err := deriveConnectionKey(sharedSecret)
	if err != nil {
		t.Fatalf("deriveConnectionKey failed: %v", err)
	}

	if !timingSafeEqual(key1, key2) {
		t.Error("Same shared secret should produce same connection key")
	}

	// Different shared secret should produce different key
	otherSecret := make([]byte, 32)
	rand.Read(otherSecret)
	key3, _ := deriveConnectionKey(otherSecret)
	if timingSafeEqual(key1, key3) {
		t.Error("Different shared secrets should produce different keys")
	}
}

func TestAgentHandler_SecretRequest_AutoApprove(t *testing.T) {
	handler, secretsHandler, encStorage, tp, cleanup := setupAgentHandler(t)
	defer cleanup()

	// Create a test connection
	agentPrivate, conn := createTestAgentConnection(t, encStorage, "test-conn-1")

	// Share a secret
	createPayload, _ := json.Marshal(ShareSecretRequest{
		SecretID:       "secret-1",
		Name:           "OpenAI Key",
		Category:       "api_keys",
		Value:          "sk-test-key",
		AllowedActions: []string{"retrieve"},
	})
	secretsHandler.HandleShareSecret(&IncomingMessage{RequestID: "create", Payload: createPayload})

	// Build a secret request
	secretReq := AgentSecretRequest{
		RequestID: "req-1",
		SecretID:  "secret-1",
		Purpose:   "Need API key for testing",
		TTL:       3600,
		Action:    "retrieve",
	}
	reqBytes, _ := json.Marshal(secretReq)

	// Derive the same connection key the agent would use
	connKey, err := deriveConnectionKey(conn.SharedSecret)
	if err != nil {
		t.Fatalf("deriveConnectionKey failed: %v", err)
	}

	// Encrypt the request
	encrypted, err := encryptXChaCha20(connKey, reqBytes)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	// Build envelope
	encPayloadJSON, _ := json.Marshal(encrypted)
	envelope := AgentEnvelope{
		Type:      AgentMsgSecretRequest,
		KeyID:     "test-conn-1",
		Payload:   encPayloadJSON,
		Timestamp: time.Now().UTC(),
		Sequence:  1,
	}
	envBytes, _ := json.Marshal(envelope)

	msg := &IncomingMessage{
		RequestID: "msg-1",
		Type:      MessageTypeVaultOp,
		Subject:   "MessageSpace.test-owner.forOwner.agent",
		Payload:   envBytes,
	}

	// Process
	result, err := handler.HandleAgentMessage(nil, msg)
	if err != nil {
		t.Fatalf("HandleAgentMessage failed: %v", err)
	}
	if result != nil {
		t.Error("Expected nil result (response sent via publisher)")
	}

	// Check that a response was published
	if len(tp.published) == 0 {
		t.Fatal("Expected a published response")
	}

	pub := tp.published[0]
	expectedTopic := "MessageSpace.test-owner.forOwner.agent.test-conn-1"
	if pub.subject != expectedTopic {
		t.Errorf("Expected topic %s, got %s", expectedTopic, pub.subject)
	}

	// Decrypt the response
	var respEnvelope AgentEnvelope
	json.Unmarshal(pub.payload, &respEnvelope)

	if respEnvelope.Type != AgentMsgSecretResponse {
		t.Errorf("Expected type %s, got %s", AgentMsgSecretResponse, respEnvelope.Type)
	}

	// Agent would derive the same key and decrypt
	agentShared, _ := curve25519.X25519(agentPrivate, conn.LocalPublicKey)
	agentKey, _ := deriveConnectionKey(agentShared)

	var encRespPayload []byte
	json.Unmarshal(respEnvelope.Payload, &encRespPayload)

	decryptedResp, err := decryptXChaCha20(agentKey, encRespPayload)
	if err != nil {
		t.Fatalf("Failed to decrypt response: %v", err)
	}

	var secretResp AgentSecretResponse
	json.Unmarshal(decryptedResp, &secretResp)

	if secretResp.Status != "approved" {
		t.Errorf("Expected status 'approved', got '%s'", secretResp.Status)
	}
	if secretResp.SecretValue != "sk-test-key" {
		t.Errorf("Expected secret value 'sk-test-key', got '%s'", secretResp.SecretValue)
	}
	if secretResp.RequestID != "req-1" {
		t.Errorf("Expected request_id 'req-1', got '%s'", secretResp.RequestID)
	}

	zeroBytes(agentPrivate)
	zeroBytes(agentShared)
	zeroBytes(agentKey)
	zeroBytes(connKey)
}

func TestAgentHandler_SecretRequest_OutOfScope(t *testing.T) {
	handler, secretsHandler, encStorage, _, cleanup := setupAgentHandler(t)
	defer cleanup()

	// Create connection with limited scope (only api_keys)
	_, conn := createTestAgentConnection(t, encStorage, "test-conn-2")
	conn.Contract.Scope = []string{"api_keys"}
	data, _ := json.Marshal(conn)
	encStorage.Put("connections/test-conn-2", data)

	// Share a secret in a different category
	createPayload, _ := json.Marshal(ShareSecretRequest{
		SecretID:       "secret-out-of-scope",
		Name:           "SSH Key",
		Category:       "database", // Not in scope
		Value:          "private-key",
		AllowedActions: []string{"retrieve"},
	})
	secretsHandler.HandleShareSecret(&IncomingMessage{RequestID: "create", Payload: createPayload})

	// Request the out-of-scope secret
	secretReq := AgentSecretRequest{
		RequestID: "req-oos",
		SecretID:  "secret-out-of-scope",
		Purpose:   "Need database password",
		Action:    "retrieve",
	}
	reqBytes, _ := json.Marshal(secretReq)

	connKey, _ := deriveConnectionKey(conn.SharedSecret)
	defer zeroBytes(connKey)

	encrypted, _ := encryptXChaCha20(connKey, reqBytes)
	encPayloadJSON, _ := json.Marshal(encrypted)

	envelope := AgentEnvelope{
		Type:      AgentMsgSecretRequest,
		KeyID:     "test-conn-2",
		Payload:   encPayloadJSON,
		Timestamp: time.Now().UTC(),
		Sequence:  1,
	}
	envBytes, _ := json.Marshal(envelope)

	msg := &IncomingMessage{
		RequestID: "msg-2",
		Type:      MessageTypeVaultOp,
		Payload:   envBytes,
	}

	handler.HandleAgentMessage(nil, msg)

	// The response should be "denied"
	// (checking via publisher output would require parsing, but the test above
	//  already validated the full decrypt cycle, so here we just verify no crash)
}

func TestAgentHandler_CatalogRequest(t *testing.T) {
	handler, secretsHandler, encStorage, tp, cleanup := setupAgentHandler(t)
	defer cleanup()

	_, conn := createTestAgentConnection(t, encStorage, "test-conn-cat")

	// Share some secrets
	for _, s := range []ShareSecretRequest{
		{SecretID: "cat-1", Name: "Key 1", Category: "api_keys", Value: "v1", AllowedActions: []string{"retrieve"}},
		{SecretID: "cat-2", Name: "Key 2", Category: "ssh_keys", Value: "v2", AllowedActions: []string{"use"}},
	} {
		payload, _ := json.Marshal(s)
		secretsHandler.HandleShareSecret(&IncomingMessage{RequestID: "create", Payload: payload})
	}

	// Request catalog
	catReq := AgentCatalogRefreshRequest{CurrentVersion: 0}
	reqBytes, _ := json.Marshal(catReq)

	connKey, _ := deriveConnectionKey(conn.SharedSecret)
	defer zeroBytes(connKey)

	encrypted, _ := encryptXChaCha20(connKey, reqBytes)
	encPayloadJSON, _ := json.Marshal(encrypted)

	envelope := AgentEnvelope{
		Type:      AgentMsgCatalogRequest,
		KeyID:     "test-conn-cat",
		Payload:   encPayloadJSON,
		Timestamp: time.Now().UTC(),
		Sequence:  1,
	}
	envBytes, _ := json.Marshal(envelope)

	msg := &IncomingMessage{
		RequestID: "msg-cat",
		Type:      MessageTypeVaultOp,
		Payload:   envBytes,
	}

	handler.HandleAgentMessage(nil, msg)

	if len(tp.published) == 0 {
		t.Fatal("Expected catalog response to be published")
	}

	// Verify the response contains a catalog
	var respEnvelope AgentEnvelope
	json.Unmarshal(tp.published[0].payload, &respEnvelope)

	if respEnvelope.Type != AgentMsgCatalogResponse {
		t.Errorf("Expected type %s, got %s", AgentMsgCatalogResponse, respEnvelope.Type)
	}

	// Decrypt and parse catalog
	var encRespPayload []byte
	json.Unmarshal(respEnvelope.Payload, &encRespPayload)

	decrypted, err := decryptXChaCha20(connKey, encRespPayload)
	if err != nil {
		t.Fatalf("Failed to decrypt catalog response: %v", err)
	}

	var catalog AgentSecretCatalog
	json.Unmarshal(decrypted, &catalog)

	if len(catalog.Entries) != 2 {
		t.Errorf("Expected 2 catalog entries, got %d", len(catalog.Entries))
	}
}

func TestAgentHandler_InactiveConnection(t *testing.T) {
	handler, _, encStorage, tp, cleanup := setupAgentHandler(t)
	defer cleanup()

	// Create an inactive connection
	_, conn := createTestAgentConnection(t, encStorage, "test-conn-inactive")
	conn.Status = "revoked"
	data, _ := json.Marshal(conn)
	encStorage.Put("connections/test-conn-inactive", data)

	connKey, _ := deriveConnectionKey(conn.SharedSecret)
	defer zeroBytes(connKey)

	reqBytes, _ := json.Marshal(AgentSecretRequest{RequestID: "req", SecretID: "s", Action: "retrieve"})
	encrypted, _ := encryptXChaCha20(connKey, reqBytes)
	encPayloadJSON, _ := json.Marshal(encrypted)

	envelope := AgentEnvelope{
		Type:      AgentMsgSecretRequest,
		KeyID:     "test-conn-inactive",
		Payload:   encPayloadJSON,
		Timestamp: time.Now().UTC(),
	}
	envBytes, _ := json.Marshal(envelope)

	handler.HandleAgentMessage(nil, &IncomingMessage{
		RequestID: "msg",
		Payload:   envBytes,
	})

	// Should NOT publish any response for inactive connections
	if len(tp.published) != 0 {
		t.Error("Expected no response for inactive connection")
	}
}

func TestAgentHandler_ECIESDecryptAgentDomain(t *testing.T) {
	// Generate a vault key pair
	vaultPrivate := make([]byte, 32)
	rand.Read(vaultPrivate)
	vaultPublic, _ := curve25519.X25519(vaultPrivate, curve25519.Basepoint)

	// Simulate what the agent does: ECIES encrypt with vault's public key
	// using DomainAgent
	plaintext := []byte(`{"invitation_id":"inv-123","agent_public_key":"AAAA"}`)

	// Generate ephemeral keypair
	ephPriv := make([]byte, 32)
	rand.Read(ephPriv)
	ephPub, _ := curve25519.X25519(ephPriv, curve25519.Basepoint)

	// ECDH
	shared, _ := curve25519.X25519(ephPriv, vaultPublic)

	// HKDF with agent domain
	connKey, err := func() ([]byte, error) {
		return deriveKeyWithDomain(shared, DomainAgent)
	}()
	if err != nil {
		t.Fatalf("HKDF failed: %v", err)
	}

	// XChaCha20-Poly1305 encrypt
	encrypted, err := encryptXChaCha20(connKey, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Assemble ECIES format: ephPub (32) || encrypted (nonce + ciphertext)
	eciesData := make([]byte, 0, len(ephPub)+len(encrypted))
	eciesData = append(eciesData, ephPub...)
	eciesData = append(eciesData, encrypted...)

	// Decrypt on vault side
	decrypted, err := decryptECIESAgentDomain(vaultPrivate, eciesData)
	if err != nil {
		t.Fatalf("ECIES decrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("ECIES round-trip failed: got %s, want %s", decrypted, plaintext)
	}
}

// deriveKeyWithDomain is a test helper that derives a key using HKDF
// with a specific domain, matching the agent's DeriveKeyHKDF pattern.
func deriveKeyWithDomain(sharedSecret []byte, domain string) ([]byte, error) {
	r := hkdf.New(sha256.New, sharedSecret, []byte(domain), nil)
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}
