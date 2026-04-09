package main

import (
	"context"
	"encoding/json"
	"testing"
)

// Tests for the access policy enforcement layer of credential_proxy.
// We don't test the actual HTTP proxy execution here (would need a mock DB bridge);
// instead we focus on the policy + audit guarantees that matter for security.

func TestCredentialProxy_DeniedRoleNotAllowed(t *testing.T) {
	mh, _, tp, cleanup := setupTestVault(t)
	defer cleanup()

	// Credential allows only "admin" role
	mustStoreCredential(t, mh.credentialStore, "restricted-cred", AccessPolicy{
		AllowedRoles:   []string{"admin"},
		RequirePurpose: false,
	})

	// Operator has "billing" role — should be denied
	op, _ := mustCreateOperator(t, mh.connectionMgr, "alice@healthcorp.dev", "billing")

	req := ProxyQueryRequest{
		CredentialID: "restricted-cred",
		Query:        "SELECT 1",
		ResourceID:   "MRN-12345",
		Purpose:      "billing_inquiry",
	}
	reqBytes, _ := json.Marshal(req)
	msg := &IncomingMessage{Type: MessageTypeVaultOp, Payload: reqBytes}

	resp, _ := mh.credentialProxy.HandleProxy(context.Background(), msg, op)

	var result map[string]interface{}
	json.Unmarshal(resp.Payload, &result)
	if result["success"] == true {
		t.Error("expected denied due to role mismatch")
	}

	// Verify a denied audit event was emitted
	foundDenied := false
	for _, m := range tp.sent {
		if m.Type != MessageTypeAuditEvent {
			continue
		}
		var event OrgAuditEvent
		json.Unmarshal(m.Payload, &event)
		if event.Outcome == "denied_policy" {
			foundDenied = true
			if event.OperatorEmail != "alice@healthcorp.dev" {
				t.Errorf("denied event should be attributed to alice, got %s", event.OperatorEmail)
			}
		}
	}
	if !foundDenied {
		t.Error("expected denied_policy audit event")
	}
}

func TestCredentialProxy_DeniedPurposeRequired(t *testing.T) {
	mh, _, _, cleanup := setupTestVault(t)
	defer cleanup()

	mustStoreCredential(t, mh.credentialStore, "needs-purpose", AccessPolicy{
		AllowedRoles:   []string{"*"},
		RequirePurpose: true,
	})
	op, _ := mustCreateOperator(t, mh.connectionMgr, "alice@healthcorp.dev", "billing")

	// Request with no purpose
	reqBytes, _ := json.Marshal(ProxyQueryRequest{
		CredentialID: "needs-purpose",
		Query:        "SELECT 1",
		ResourceID:   "MRN-99999",
		// Purpose intentionally omitted
	})
	resp, _ := mh.credentialProxy.HandleProxy(context.Background(), &IncomingMessage{
		Type: MessageTypeVaultOp, Payload: reqBytes,
	}, op)

	var result map[string]interface{}
	json.Unmarshal(resp.Payload, &result)
	if result["success"] == true {
		t.Error("expected denied due to missing purpose")
	}
}

func TestCredentialProxy_RoleWildcard(t *testing.T) {
	mh, _, _, cleanup := setupTestVault(t)
	defer cleanup()

	// Wildcard allows any role — should pass policy checks
	// Note: query execution will fail (no DB bridge in tests), but policy passes.
	mustStoreCredential(t, mh.credentialStore, "open-cred", AccessPolicy{
		AllowedRoles: []string{"*"},
	})
	op, _ := mustCreateOperator(t, mh.connectionMgr, "alice@healthcorp.dev", "billing")

	// We're not testing the HTTP proxy here, just verifying the policy passes.
	// The proxy will attempt to send an HTTP request, time out, and emit an "error" audit event.
	// What we care about is that policy didn't deny it before reaching the proxy.
	policy, _ := mh.credentialStore.GetCredentialMetadata("open-cred")
	allowed := mh.credentialProxy.checkAccessPolicy(policy.AccessPolicy, op, &ProxyQueryRequest{
		CredentialID: "open-cred",
		Query:        "SELECT 1",
		Purpose:      "billing_inquiry",
		ResourceID:   "MRN-12345",
	})
	if !allowed {
		t.Error("wildcard role should allow any operator")
	}
}

func TestCredentialProxy_DeniedRateLimit(t *testing.T) {
	mh, _, _, cleanup := setupTestVault(t)
	defer cleanup()

	mustStoreCredential(t, mh.credentialStore, "rate-limited", AccessPolicy{
		AllowedRoles: []string{"*"},
		MaxQueryRate: 2, // Only 2 per hour
	})
	op, _ := mustCreateOperator(t, mh.connectionMgr, "alice@healthcorp.dev", "billing")

	policy, _ := mh.credentialStore.GetCredentialMetadata("rate-limited")

	// First two should pass
	if !mh.credentialProxy.checkRateLimit(policy.AccessPolicy, op) {
		t.Error("first call should pass rate limit")
	}
	if !mh.credentialProxy.checkRateLimit(policy.AccessPolicy, op) {
		t.Error("second call should pass rate limit")
	}
	// Third should fail
	if mh.credentialProxy.checkRateLimit(policy.AccessPolicy, op) {
		t.Error("third call should fail rate limit")
	}
}

func TestCredentialProxy_RateLimitDisabled(t *testing.T) {
	mh, _, _, cleanup := setupTestVault(t)
	defer cleanup()

	op, _ := mustCreateOperator(t, mh.connectionMgr, "alice@healthcorp.dev", "billing")

	// MaxQueryRate=0 should disable the limit
	policy := AccessPolicy{MaxQueryRate: 0}
	for i := 0; i < 100; i++ {
		if !mh.credentialProxy.checkRateLimit(policy, op) {
			t.Errorf("call %d should pass when rate limit is disabled", i)
		}
	}
}

func TestCredentialProxy_AccessPolicyRoleListNoMatch(t *testing.T) {
	mh, _, _, cleanup := setupTestVault(t)
	defer cleanup()

	op, _ := mustCreateOperator(t, mh.connectionMgr, "mallory@healthcorp.dev", "contractor")
	policy := AccessPolicy{
		AllowedRoles:   []string{"billing", "physician", "admin"},
		RequirePurpose: false,
	}

	allowed := mh.credentialProxy.checkAccessPolicy(policy, op, &ProxyQueryRequest{
		CredentialID: "any",
		Query:        "SELECT 1",
		Purpose:      "test",
	})
	if allowed {
		t.Error("contractor role should not match billing/physician/admin")
	}
}

func TestCredentialProxy_AuditAttribution(t *testing.T) {
	mh, _, tp, cleanup := setupTestVault(t)
	defer cleanup()

	mustStoreCredential(t, mh.credentialStore, "test-attribution", AccessPolicy{
		AllowedRoles:   []string{"admin"},
		RequirePurpose: true,
	})
	// Operator with wrong role — will be denied, but audit event must include their identity
	op, _ := mustCreateOperator(t, mh.connectionMgr, "alice@healthcorp.dev", "billing")

	reqBytes, _ := json.Marshal(ProxyQueryRequest{
		CredentialID: "test-attribution",
		Query:        "SELECT 1",
		Purpose:      "billing_inquiry",
		ResourceID:   "MRN-12345",
	})
	mh.credentialProxy.HandleProxy(context.Background(), &IncomingMessage{
		Type: MessageTypeVaultOp, Payload: reqBytes,
	}, op)

	// Find the audit event
	var event *OrgAuditEvent
	for _, m := range tp.sent {
		if m.Type == MessageTypeAuditEvent {
			var e OrgAuditEvent
			json.Unmarshal(m.Payload, &e)
			event = &e
			break
		}
	}
	if event == nil {
		t.Fatal("no audit event emitted")
	}

	// The "money shot" — even on denial, the audit event must contain the operator
	// and the resource they tried to access
	if event.OperatorEmail != "alice@healthcorp.dev" {
		t.Errorf("operator email mismatch: %s", event.OperatorEmail)
	}
	if event.OperatorRole != "billing" {
		t.Errorf("operator role mismatch: %s", event.OperatorRole)
	}
	if event.ResourceID != "MRN-12345" {
		t.Errorf("resource_id mismatch: %s", event.ResourceID)
	}
	if event.Purpose != "billing_inquiry" {
		t.Errorf("purpose mismatch: %s", event.Purpose)
	}
	if event.ConnectionID != op.ConnectionID {
		t.Errorf("connection_id mismatch")
	}
}
