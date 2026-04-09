package main

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestAuditHandler_EmitEventLocalStorage(t *testing.T) {
	mh, storage, _, cleanup := setupTestVault(t)
	defer cleanup()

	eventID := mh.auditHandler.EmitEvent(&OrgAuditEvent{
		OperatorEmail: "alice@healthcorp.dev",
		Action:        "credential_proxy_query",
		ResourceID:    "MRN-12345",
		Outcome:       "success",
	})

	if eventID == "" {
		t.Error("expected event ID")
	}

	// Verify event is in local storage
	var stored OrgAuditEvent
	if err := storage.GetJSON(KeyAuditPrefix+eventID, &stored); err != nil {
		t.Fatalf("event not in storage: %v", err)
	}
	if stored.OperatorEmail != "alice@healthcorp.dev" {
		t.Errorf("operator email mismatch: %s", stored.OperatorEmail)
	}
	if stored.OrgVaultID != "test-org-vault" {
		t.Errorf("org_vault_id should be auto-set: %s", stored.OrgVaultID)
	}
	if stored.Timestamp == 0 {
		t.Error("timestamp should be auto-set")
	}
}

func TestAuditHandler_EmitEventForwardedToParent(t *testing.T) {
	mh, _, tp, cleanup := setupTestVault(t)
	defer cleanup()

	mh.auditHandler.EmitEvent(&OrgAuditEvent{
		OperatorEmail: "bob@healthcorp.dev",
		Action:        "credential_proxy_query",
		Outcome:       "success",
	})

	// Look for an audit_event message in the publisher
	var auditMsg *OutgoingMessage
	for _, m := range tp.sent {
		if m.Type == MessageTypeAuditEvent {
			auditMsg = m
			break
		}
	}
	if auditMsg == nil {
		t.Fatal("expected audit_event message to be sent to parent")
	}

	var event OrgAuditEvent
	if err := json.Unmarshal(auditMsg.Payload, &event); err != nil {
		t.Fatalf("parse audit event: %v", err)
	}
	if event.OperatorEmail != "bob@healthcorp.dev" {
		t.Errorf("operator email mismatch: %s", event.OperatorEmail)
	}
}

func TestAuditHandler_QueryHashIsSHA256(t *testing.T) {
	query := "SELECT * FROM patients WHERE mrn = $1"
	hash := HashQuery(query)

	// SHA-256 hex is 64 characters
	if len(hash) != 64 {
		t.Errorf("expected 64 hex chars, got %d", len(hash))
	}
	// All characters must be valid hex
	if _, err := hex.DecodeString(hash); err != nil {
		t.Errorf("hash is not valid hex: %v", err)
	}
	// Should be deterministic
	if HashQuery(query) != hash {
		t.Error("hash should be deterministic")
	}
	// Should not contain the original query
	if strings.Contains(hash, "patients") {
		t.Error("hash should not contain plaintext query")
	}
}

func TestAuditHandler_QueryFilterByOperator(t *testing.T) {
	mh, _, _, cleanup := setupTestVault(t)
	defer cleanup()

	mh.auditHandler.EmitEvent(&OrgAuditEvent{OperatorEmail: "alice@healthcorp.dev", Action: "query", Outcome: "success"})
	mh.auditHandler.EmitEvent(&OrgAuditEvent{OperatorEmail: "bob@healthcorp.dev", Action: "query", Outcome: "success"})
	mh.auditHandler.EmitEvent(&OrgAuditEvent{OperatorEmail: "alice@healthcorp.dev", Action: "query", Outcome: "denied_policy"})

	queryReq, _ := json.Marshal(map[string]interface{}{
		"operator_email": "alice@healthcorp.dev",
	})
	resp, _ := mh.auditHandler.HandleQuery(&IncomingMessage{
		Type: MessageTypeVaultOp, Payload: queryReq,
	})

	var result struct {
		Success bool             `json:"success"`
		Events  []OrgAuditEvent  `json:"events"`
		Count   int              `json:"count"`
	}
	json.Unmarshal(resp.Payload, &result)

	if result.Count != 2 {
		t.Errorf("expected 2 alice events, got %d", result.Count)
	}
	for _, e := range result.Events {
		if e.OperatorEmail != "alice@healthcorp.dev" {
			t.Errorf("query returned non-alice event: %s", e.OperatorEmail)
		}
	}
}
