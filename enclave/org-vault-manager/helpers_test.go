package main

// Test helpers shared by *_test.go files.
// _test.go files are only compiled when running tests, never in the production binary.

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"
)

// testPublisher captures all messages sent via sendFn for assertions.
type testPublisher struct {
	sent []*OutgoingMessage
}

func (p *testPublisher) sendFn(msg *OutgoingMessage) error {
	p.sent = append(p.sent, msg)
	return nil
}

// setupTestVault creates an isolated MessageHandler + storage + publisher
// for unit tests.
func setupTestVault(t *testing.T) (*MessageHandler, *EncryptedStorage, *testPublisher, func()) {
	t.Helper()

	storage, err := NewEncryptedStorage("test-org-vault")
	if err != nil {
		t.Fatalf("storage: %v", err)
	}

	tp := &testPublisher{}
	mh := NewMessageHandler("test-org-vault", storage, tp.sendFn)

	cleanup := func() {
		storage.SecureErase()
	}
	return mh, storage, tp, cleanup
}

// mustStoreCredential stores a test credential with the given access policy.
func mustStoreCredential(t *testing.T, store *CredentialStore, id string, policy AccessPolicy) {
	t.Helper()
	cred := &StoredCredential{
		CredentialID:   id,
		CredentialType: "database",
		Label:          "test cred",
		AccessPolicy:   policy,
		CreatedAt:      time.Now(),
		RotatedAt:      time.Now(),
	}
	secret, _ := json.Marshal(DatabaseCredential{
		Host:     "test-host",
		Port:     5432,
		Database: "testdb",
		Username: "testuser",
		Password: "testpass",
		SSLMode:  "require",
	})
	if err := store.StoreCredential(cred, secret); err != nil {
		t.Fatalf("store credential: %v", err)
	}
}

// mustCreateOperator creates an active operator connection directly in storage,
// skipping the invite/connect handshake. Useful for tests that need an operator
// to exist but don't care about the key exchange flow.
func mustCreateOperator(t *testing.T, cm *ConnectionManager, email, role string) (*OperatorConnection, []byte) {
	t.Helper()

	// Generate a real X25519 keypair so DeriveConnectionKey works
	curve := ecdh.X25519()
	vaultPriv, _ := curve.GenerateKey(rand.Reader)
	operatorPriv, _ := curve.GenerateKey(rand.Reader)

	connID := generateID()
	op := &OperatorConnection{
		ConnectionID:    connID,
		OperatorEmail:   email,
		OperatorRole:    role,
		Status:          "active",
		LocalPrivateKey: vaultPriv.Bytes(),
		LocalPublicKey:  vaultPriv.PublicKey().Bytes(),
		PeerPublicKey:   operatorPriv.PublicKey().Bytes(),
		ConnectedAt:     time.Now(),
		LastActiveAt:    time.Now(),
	}
	if err := cm.storage.PutJSON(KeyOperatorPrefix+connID, op); err != nil {
		t.Fatalf("put operator: %v", err)
	}
	if err := cm.storage.AddToIndex(KeyOperatorIndex, connID); err != nil {
		t.Fatalf("index operator: %v", err)
	}

	// Compute the shared secret + connection key the same way DeriveConnectionKey does
	sharedSecret, _ := operatorPriv.ECDH(vaultPriv.PublicKey())
	connKey, _ := deriveConnectionKey(sharedSecret)

	return op, connKey
}
