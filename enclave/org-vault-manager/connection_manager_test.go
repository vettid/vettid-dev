package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"testing"
)

func TestConnectionManager_InviteGeneratesKeypair(t *testing.T) {
	mh, _, _, cleanup := setupTestVault(t)
	defer cleanup()

	req, _ := json.Marshal(map[string]string{
		"operator_email": "alice@healthcorp.dev",
		"operator_role":  "billing",
	})
	msg := &IncomingMessage{
		Type:    MessageTypeVaultOp,
		Subject: "OrgSpace.test-org-vault.connection.invite",
		Payload: req,
	}

	resp, err := mh.connectionMgr.HandleInvite(msg)
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response")
	}

	var result struct {
		Success      bool   `json:"success"`
		ConnectionID string `json:"connection_id"`
		PublicKey    []byte `json:"public_key"`
	}
	if err := json.Unmarshal(resp.Payload, &result); err != nil {
		t.Fatalf("parse response: %v", err)
	}

	if !result.Success {
		t.Error("invite should succeed")
	}
	if result.ConnectionID == "" {
		t.Error("connection_id should be set")
	}
	if len(result.PublicKey) != 32 {
		t.Errorf("expected 32-byte X25519 public key, got %d bytes", len(result.PublicKey))
	}
}

func TestConnectionManager_ConnectECDH(t *testing.T) {
	mh, _, _, cleanup := setupTestVault(t)
	defer cleanup()

	// Step 1: Vault generates its keypair via invite
	inviteReq, _ := json.Marshal(map[string]string{
		"operator_email": "bob@healthcorp.dev",
		"operator_role":  "physician",
	})
	inviteResp, _ := mh.connectionMgr.HandleInvite(&IncomingMessage{
		Type: MessageTypeVaultOp, Payload: inviteReq,
	})

	var inviteResult struct {
		ConnectionID string `json:"connection_id"`
		PublicKey    []byte `json:"public_key"`
	}
	json.Unmarshal(inviteResp.Payload, &inviteResult)

	// Step 2: Operator generates its keypair and connects
	curve := ecdh.X25519()
	operatorPriv, _ := curve.GenerateKey(rand.Reader)
	operatorPubKey := operatorPriv.PublicKey().Bytes()

	connectReq, _ := json.Marshal(map[string]interface{}{
		"connection_id":   inviteResult.ConnectionID,
		"peer_public_key": operatorPubKey,
	})
	connectResp, err := mh.connectionMgr.HandleConnect(&IncomingMessage{
		Type: MessageTypeVaultOp, Payload: connectReq,
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}

	var connectResult struct {
		Success bool   `json:"success"`
		Status  string `json:"status"`
	}
	json.Unmarshal(connectResp.Payload, &connectResult)
	if !connectResult.Success {
		t.Error("connect should succeed")
	}
	if connectResult.Status != "active" {
		t.Errorf("expected status 'active', got %q", connectResult.Status)
	}

	// Step 3: Verify both sides derive the same connection_key
	conn, err := mh.connectionMgr.GetConnection(inviteResult.ConnectionID)
	if err != nil {
		t.Fatalf("get connection: %v", err)
	}
	vaultKey, err := mh.connectionMgr.DeriveConnectionKey(conn)
	if err != nil {
		t.Fatalf("derive vault key: %v", err)
	}

	// Operator computes its side
	vaultPubKey, _ := curve.NewPublicKey(inviteResult.PublicKey)
	operatorShared, _ := operatorPriv.ECDH(vaultPubKey)
	operatorKey, _ := deriveConnectionKey(operatorShared)

	if !bytes.Equal(vaultKey, operatorKey) {
		t.Error("vault and operator should derive the same connection key from ECDH")
	}
}

func TestConnectionManager_RevokeChangesStatus(t *testing.T) {
	mh, _, _, cleanup := setupTestVault(t)
	defer cleanup()

	op, _ := mustCreateOperator(t, mh.connectionMgr, "carol@healthcorp.dev", "admin")

	revokeReq, _ := json.Marshal(map[string]string{
		"connection_id": op.ConnectionID,
		"reason":        "test revocation",
	})
	resp, err := mh.connectionMgr.HandleRevoke(&IncomingMessage{
		Type: MessageTypeVaultOp, Payload: revokeReq,
	})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}

	var result struct {
		Success bool   `json:"success"`
		Status  string `json:"status"`
	}
	json.Unmarshal(resp.Payload, &result)
	if !result.Success || result.Status != "revoked" {
		t.Errorf("expected revoked, got %+v", result)
	}

	// Verify status persisted
	updated, _ := mh.connectionMgr.GetConnection(op.ConnectionID)
	if updated.Status != "revoked" {
		t.Errorf("status not persisted: %s", updated.Status)
	}
}

func TestConnectionManager_DeriveConnectionKeyMatchesHelper(t *testing.T) {
	mh, _, _, cleanup := setupTestVault(t)
	defer cleanup()

	_, expectedKey := mustCreateOperator(t, mh.connectionMgr, "alice@healthcorp.dev", "billing")

	// Read the connection back from storage and derive
	ops, _ := mh.connectionMgr.ListConnections()
	if len(ops) == 0 {
		t.Fatal("no operators")
	}
	conn, _ := mh.connectionMgr.GetConnection(ops[0].ConnectionID)
	derivedKey, err := mh.connectionMgr.DeriveConnectionKey(conn)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}

	if !bytes.Equal(expectedKey, derivedKey) {
		t.Error("DeriveConnectionKey doesn't match the helper's expected key")
	}
}
