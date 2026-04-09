package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCredentialStore_StoreAndRetrieveSecret(t *testing.T) {
	mh, _, _, cleanup := setupTestVault(t)
	defer cleanup()

	mustStoreCredential(t, mh.credentialStore, "test-cred", AccessPolicy{
		AllowedRoles: []string{"*"},
	})

	secret, err := mh.credentialStore.GetCredentialSecret("test-cred")
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}

	var dbCred DatabaseCredential
	if err := json.Unmarshal(secret, &dbCred); err != nil {
		t.Fatalf("unmarshal secret: %v", err)
	}

	if dbCred.Host != "test-host" || dbCred.Username != "testuser" || dbCred.Password != "testpass" {
		t.Errorf("secret values not preserved: %+v", dbCred)
	}
}

func TestCredentialStore_ListReturnsMetadataOnly(t *testing.T) {
	mh, _, _, cleanup := setupTestVault(t)
	defer cleanup()

	mustStoreCredential(t, mh.credentialStore, "cred-1", AccessPolicy{})
	mustStoreCredential(t, mh.credentialStore, "cred-2", AccessPolicy{})

	creds, err := mh.credentialStore.ListCredentials()
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	if len(creds) != 2 {
		t.Errorf("expected 2 credentials, got %d", len(creds))
	}

	// Marshal the list and verify no plaintext secret values appear
	listJSON, _ := json.Marshal(creds)
	if strings.Contains(string(listJSON), "testpass") {
		t.Error("ListCredentials leaked secret value 'testpass'")
	}
}

func TestCredentialStore_DeleteRemovesIndex(t *testing.T) {
	mh, _, _, cleanup := setupTestVault(t)
	defer cleanup()

	mustStoreCredential(t, mh.credentialStore, "ephemeral", AccessPolicy{})

	if err := mh.credentialStore.DeleteCredential("ephemeral"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// Should no longer appear in list
	creds, _ := mh.credentialStore.ListCredentials()
	for _, c := range creds {
		if c.CredentialID == "ephemeral" {
			t.Error("deleted credential still in list")
		}
	}

	// Direct GetCredentialMetadata should fail
	if _, err := mh.credentialStore.GetCredentialMetadata("ephemeral"); err == nil {
		t.Error("expected GetCredentialMetadata to fail for deleted credential")
	}
}

func TestCredentialStore_RotateUpdatesTimestamp(t *testing.T) {
	mh, _, _, cleanup := setupTestVault(t)
	defer cleanup()

	mustStoreCredential(t, mh.credentialStore, "rotate-test", AccessPolicy{})

	original, err := mh.credentialStore.GetCredentialMetadata("rotate-test")
	if err != nil {
		t.Fatalf("get original: %v", err)
	}
	originalRotated := original.RotatedAt

	// Sleep enough for timestamp resolution to differ
	newSecret, _ := json.Marshal(DatabaseCredential{
		Host: "new-host", Port: 5432, Database: "newdb",
		Username: "newuser", Password: "newpass", SSLMode: "require",
	})

	if err := mh.credentialStore.RotateCredential("rotate-test", newSecret); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	updated, err := mh.credentialStore.GetCredentialMetadata("rotate-test")
	if err != nil {
		t.Fatalf("get updated: %v", err)
	}

	if !updated.RotatedAt.After(originalRotated) && !updated.RotatedAt.Equal(originalRotated) {
		t.Errorf("RotatedAt not updated: %v vs %v", updated.RotatedAt, originalRotated)
	}

	// Verify the new secret is what we get back
	secret, _ := mh.credentialStore.GetCredentialSecret("rotate-test")
	var dbCred DatabaseCredential
	json.Unmarshal(secret, &dbCred)
	if dbCred.Host != "new-host" {
		t.Errorf("rotated secret not retrievable: got %s", dbCred.Host)
	}
}
