package main

import (
	"encoding/json"
	"testing"
)

func TestAuditTransfer_FilterByResourceID(t *testing.T) {
	mh, _, _, cleanup := setupTestVault(t)
	defer cleanup()

	// Create some audit events for different resources
	mh.auditHandler.EmitEvent(&OrgAuditEvent{OperatorEmail: "alice@healthcorp.dev", Action: "credential_proxy_query", ResourceID: "MRN-12345", Outcome: "success"})
	mh.auditHandler.EmitEvent(&OrgAuditEvent{OperatorEmail: "bob@healthcorp.dev", Action: "credential_proxy_query", ResourceID: "MRN-99999", Outcome: "success"})
	mh.auditHandler.EmitEvent(&OrgAuditEvent{OperatorEmail: "alice@healthcorp.dev", Action: "credential_proxy_query", ResourceID: "MRN-12345", Outcome: "success"})
	mh.auditHandler.EmitEvent(&OrgAuditEvent{OperatorEmail: "carol@healthcorp.dev", Action: "credential_proxy_query", ResourceID: "MRN-12345", Outcome: "denied_policy"})

	req, _ := json.Marshal(AuditTransferRequest{ResourceID: "MRN-12345"})
	resp, err := mh.auditTransfer.HandleTransfer(&IncomingMessage{
		Type: MessageTypeVaultOp, Payload: req,
	})
	if err != nil {
		t.Fatalf("transfer: %v", err)
	}

	var result AuditTransferResponse
	if err := json.Unmarshal(resp.Payload, &result); err != nil {
		t.Fatalf("parse: %v", err)
	}

	if !result.Success {
		t.Error("transfer should succeed")
	}
	if result.Count != 3 {
		t.Errorf("expected 3 events for MRN-12345, got %d", result.Count)
	}
	for _, e := range result.Events {
		if e.ResourceID != "MRN-12345" {
			t.Errorf("got event for wrong resource: %s", e.ResourceID)
		}
	}
}

func TestAuditTransfer_RespectsMaxEvents(t *testing.T) {
	mh, _, _, cleanup := setupTestVault(t)
	defer cleanup()

	for i := 0; i < 10; i++ {
		mh.auditHandler.EmitEvent(&OrgAuditEvent{
			OperatorEmail: "alice@healthcorp.dev",
			Action:        "credential_proxy_query",
			ResourceID:    "MRN-99999",
			Outcome:       "success",
		})
	}

	req, _ := json.Marshal(AuditTransferRequest{ResourceID: "MRN-99999", MaxEvents: 3})
	resp, _ := mh.auditTransfer.HandleTransfer(&IncomingMessage{
		Type: MessageTypeVaultOp, Payload: req,
	})

	var result AuditTransferResponse
	json.Unmarshal(resp.Payload, &result)
	if result.Count != 3 {
		t.Errorf("expected max 3 events, got %d", result.Count)
	}
}

func TestAuditTransfer_NewestFirst(t *testing.T) {
	mh, _, _, cleanup := setupTestVault(t)
	defer cleanup()

	mh.auditHandler.EmitEvent(&OrgAuditEvent{
		Timestamp: 1000, OperatorEmail: "first", Action: "q", ResourceID: "MRN-X", Outcome: "success",
	})
	mh.auditHandler.EmitEvent(&OrgAuditEvent{
		Timestamp: 2000, OperatorEmail: "second", Action: "q", ResourceID: "MRN-X", Outcome: "success",
	})
	mh.auditHandler.EmitEvent(&OrgAuditEvent{
		Timestamp: 3000, OperatorEmail: "third", Action: "q", ResourceID: "MRN-X", Outcome: "success",
	})

	req, _ := json.Marshal(AuditTransferRequest{ResourceID: "MRN-X"})
	resp, _ := mh.auditTransfer.HandleTransfer(&IncomingMessage{
		Type: MessageTypeVaultOp, Payload: req,
	})

	var result AuditTransferResponse
	json.Unmarshal(resp.Payload, &result)

	if len(result.Events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(result.Events))
	}
	// Newest first
	if result.Events[0].OperatorEmail != "third" {
		t.Errorf("expected first event to be 'third', got %s", result.Events[0].OperatorEmail)
	}
	if result.Events[2].OperatorEmail != "first" {
		t.Errorf("expected last event to be 'first', got %s", result.Events[2].OperatorEmail)
	}
}

func TestAuditTransfer_EmptyForUnknownResource(t *testing.T) {
	mh, _, _, cleanup := setupTestVault(t)
	defer cleanup()

	mh.auditHandler.EmitEvent(&OrgAuditEvent{
		OperatorEmail: "alice@healthcorp.dev", Action: "q",
		ResourceID: "MRN-12345", Outcome: "success",
	})

	req, _ := json.Marshal(AuditTransferRequest{ResourceID: "MRN-NOT-FOUND"})
	resp, _ := mh.auditTransfer.HandleTransfer(&IncomingMessage{
		Type: MessageTypeVaultOp, Payload: req,
	})

	var result AuditTransferResponse
	json.Unmarshal(resp.Payload, &result)
	if result.Count != 0 {
		t.Errorf("expected 0 events for unknown resource, got %d", result.Count)
	}
}

func TestAuditTransfer_RejectsEmptyResourceID(t *testing.T) {
	mh, _, _, cleanup := setupTestVault(t)
	defer cleanup()

	req, _ := json.Marshal(AuditTransferRequest{})
	resp, _ := mh.auditTransfer.HandleTransfer(&IncomingMessage{
		Type: MessageTypeVaultOp, Payload: req,
	})

	var result map[string]interface{}
	json.Unmarshal(resp.Payload, &result)
	if result["success"] == true {
		t.Error("expected failure for empty resource_id")
	}
}
