package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/vettid/vettid-dev/enclave/vault-manager/storage"
)

// setupLeashHandler returns a LeashHandler wired to an in-process
// SQLite storage. Mirrors setupAgentHandler in agent_handler_test.go.
func setupLeashHandler(t *testing.T) (*LeashHandler, *EncryptedStorage, func()) {
	t.Helper()

	dek := make([]byte, 32)
	rand.Read(dek)

	store, err := storage.NewSQLiteStorage("test-owner", dek)
	if err != nil {
		t.Fatalf("storage: %v", err)
	}
	encStorage := &EncryptedStorage{
		sqlite:     store,
		ownerSpace: "test-owner",
	}
	handler := NewLeashHandler("test-owner", encStorage, nil, nil)
	cleanup := func() { store.Close() }
	return handler, encStorage, cleanup
}

// seedAgentConnection writes a minimal ConnectionRecord so
// HandleGrantAttest's "agent connection exists + active" preconditions
// pass.
func seedAgentConnection(t *testing.T, encStorage *EncryptedStorage, connID string) {
	t.Helper()
	rec := ConnectionRecord{
		ConnectionID:   connID,
		ConnectionType: ConnectionTypeAgent,
		Status:         "active",
		PeerAlias:      "Test Agent",
	}
	data, _ := json.Marshal(rec)
	encStorage.Put("connections/"+connID, data)
}

// freshAgentEd25519 produces a random Ed25519 keypair encoded as the
// handler expects: base64url-encoded pubkey + raw private key.
func freshAgentEd25519(t *testing.T) (privKey ed25519.PrivateKey, pubB64 string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return priv, base64.RawURLEncoding.EncodeToString(pub)
}

// invokeAttest issues a leash through the handler and returns the
// parsed response. Caller asserts on shape.
func invokeAttest(t *testing.T, h *LeashHandler, req GrantAttestRequest) (*OutgoingMessage, *GrantAttestResponse, map[string]interface{}) {
	t.Helper()
	body, _ := json.Marshal(req)
	msg := &IncomingMessage{
		Type:    MessageTypeVaultOp,
		Payload: body,
	}
	out, err := h.HandleGrantAttest(context.Background(), msg)
	if err != nil {
		t.Fatalf("HandleGrantAttest: %v", err)
	}
	if out == nil {
		t.Fatalf("HandleGrantAttest returned nil")
	}
	var resp GrantAttestResponse
	if err := json.Unmarshal(out.Payload, &resp); err != nil {
		t.Fatalf("response unmarshal: %v (payload=%s)", err, string(out.Payload))
	}
	// Also surface as a generic map so error responses (no leash field)
	// can be asserted on by tests that expect failure.
	var generic map[string]interface{}
	_ = json.Unmarshal(out.Payload, &generic)
	return out, &resp, generic
}

// splitJWT returns the three compact-form segments.
func splitJWT(t *testing.T, token string) (headerB64, claimsB64, sigB64 string) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3-segment JWT, got %d segments: %q", len(parts), token)
	}
	return parts[0], parts[1], parts[2]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestLeash_AttestRoundTrip_VerifiesUnderAttestKey(t *testing.T) {
	h, encStorage, cleanup := setupLeashHandler(t)
	defer cleanup()

	connID := "agent-conn-roundtrip"
	seedAgentConnection(t, encStorage, connID)
	_, agentPubB64 := freshAgentEd25519(t)

	_, resp, _ := invokeAttest(t, h, GrantAttestRequest{
		ConnectionID: connID,
		AgentPubkey:  agentPubB64,
		Scope:        []string{"profile.email:read", "credential.sign:cred-7a9f"},
		DurationSecs: 3600,
	})

	if resp.Leash == "" {
		t.Fatalf("empty leash in response")
	}
	if !strings.HasPrefix(resp.JTI, "leash-") {
		t.Errorf("jti should be leash-prefixed: %q", resp.JTI)
	}
	if resp.ExpiresAt <= resp.IssuedAt {
		t.Errorf("expires_at (%d) must be after issued_at (%d)", resp.ExpiresAt, resp.IssuedAt)
	}

	// Verify the JWT signature using the attest pubkey the handler exposes.
	kid, attestPub, err := h.AttestationPublicKey()
	if err != nil {
		t.Fatalf("AttestationPublicKey: %v", err)
	}
	if kid != resp.Kid {
		t.Errorf("kid mismatch: response=%q handler=%q", resp.Kid, kid)
	}
	if len(attestPub) != ed25519.PublicKeySize {
		t.Fatalf("unexpected pubkey length: %d", len(attestPub))
	}

	hb64, cb64, sb64 := splitJWT(t, resp.Leash)
	sig, err := base64.RawURLEncoding.DecodeString(sb64)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	signingInput := hb64 + "." + cb64
	if !ed25519.Verify(attestPub, []byte(signingInput), sig) {
		t.Errorf("ed25519.Verify failed — leash signature does not validate under attest pubkey")
	}
}

func TestLeash_HeaderShape_LocksAlgAndTyp(t *testing.T) {
	h, encStorage, cleanup := setupLeashHandler(t)
	defer cleanup()

	connID := "agent-conn-header"
	seedAgentConnection(t, encStorage, connID)
	_, agentPubB64 := freshAgentEd25519(t)

	_, resp, _ := invokeAttest(t, h, GrantAttestRequest{
		ConnectionID: connID,
		AgentPubkey:  agentPubB64,
		Scope:        []string{"profile.email:read"},
	})

	hb64, _, _ := splitJWT(t, resp.Leash)
	hbytes, err := base64.RawURLEncoding.DecodeString(hb64)
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var header map[string]string
	if err := json.Unmarshal(hbytes, &header); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	if header["alg"] != "EdDSA" {
		t.Errorf("alg must be EdDSA, got %q", header["alg"])
	}
	if header["typ"] != "leash+jwt" {
		t.Errorf("typ must be leash+jwt, got %q", header["typ"])
	}
	if !strings.HasPrefix(header["kid"], "leash-attest-") {
		t.Errorf("kid must start with leash-attest-, got %q", header["kid"])
	}
}

func TestLeash_ClaimsShape_MatchesSpec(t *testing.T) {
	h, encStorage, cleanup := setupLeashHandler(t)
	defer cleanup()

	connID := "agent-conn-claims"
	seedAgentConnection(t, encStorage, connID)
	_, agentPubB64 := freshAgentEd25519(t)

	scope := []string{"profile.email:read", "credential.sign:cred-7a9f"}
	_, resp, _ := invokeAttest(t, h, GrantAttestRequest{
		ConnectionID: connID,
		AgentPubkey:  agentPubB64,
		Scope:        scope,
		DurationSecs: 1800,
	})

	_, cb64, _ := splitJWT(t, resp.Leash)
	cbytes, err := base64.RawURLEncoding.DecodeString(cb64)
	if err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(cbytes, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}

	expectClaim(t, claims, "iss", "did:vettid:test-owner")
	expectClaim(t, claims, "sub", "agent:"+connID)
	expectClaim(t, claims, "jti", resp.JTI)
	expectClaim(t, claims, "vettid:v", float64(LeashSchemaVersion)) // json numbers decode as float64
	expectClaim(t, claims, "vettid:agent_pubkey", agentPubB64)
	expectClaim(t, claims, "vettid:audience", nil)

	// Scope round-trip
	gotScope, ok := claims["vettid:scope"].([]interface{})
	if !ok {
		t.Fatalf("vettid:scope is not an array: %T", claims["vettid:scope"])
	}
	if len(gotScope) != len(scope) {
		t.Errorf("scope length mismatch: got %d want %d", len(gotScope), len(scope))
	}
	for i, want := range scope {
		if gotScope[i] != want {
			t.Errorf("scope[%d]: got %v want %q", i, gotScope[i], want)
		}
	}

	// revocation_url shape
	revURL, _ := claims["vettid:revocation_url"].(string)
	if !strings.HasSuffix(revURL, resp.JTI) {
		t.Errorf("revocation_url should end with jti %q, got %q", resp.JTI, revURL)
	}
}

func TestLeash_GrantVersion_IsMonotonicPerAgent(t *testing.T) {
	h, encStorage, cleanup := setupLeashHandler(t)
	defer cleanup()

	connA := "agent-conn-A"
	connB := "agent-conn-B"
	seedAgentConnection(t, encStorage, connA)
	seedAgentConnection(t, encStorage, connB)
	_, pubAB64 := freshAgentEd25519(t)
	_, pubBB64 := freshAgentEd25519(t)

	mintGetVersion := func(conn, pub string) int {
		_, resp, _ := invokeAttest(t, h, GrantAttestRequest{
			ConnectionID: conn, AgentPubkey: pub, Scope: []string{"profile.email:read"},
		})
		_, cb64, _ := splitJWT(t, resp.Leash)
		cbytes, _ := base64.RawURLEncoding.DecodeString(cb64)
		var claims map[string]interface{}
		_ = json.Unmarshal(cbytes, &claims)
		v, _ := claims["vettid:grant_version"].(float64)
		return int(v)
	}

	a1 := mintGetVersion(connA, pubAB64)
	a2 := mintGetVersion(connA, pubAB64)
	b1 := mintGetVersion(connB, pubBB64)
	a3 := mintGetVersion(connA, pubAB64)

	if a1 != 1 || a2 != 2 || a3 != 3 {
		t.Errorf("agent A grant_version sequence: got [%d %d %d], want [1 2 3]", a1, a2, a3)
	}
	if b1 != 1 {
		t.Errorf("agent B grant_version should start at 1 independently, got %d", b1)
	}
}

func TestLeash_AttestKey_PersistsAcrossCalls(t *testing.T) {
	h, encStorage, cleanup := setupLeashHandler(t)
	defer cleanup()

	connID := "agent-conn-persist"
	seedAgentConnection(t, encStorage, connID)
	_, agentPubB64 := freshAgentEd25519(t)

	kid1, pub1, err := h.AttestationPublicKey()
	if err != nil {
		t.Fatalf("first AttestationPublicKey: %v", err)
	}

	// Issue a leash, then re-read the key. Must be identical — we
	// don't want a key rotation per call.
	_, _, _ = invokeAttest(t, h, GrantAttestRequest{
		ConnectionID: connID, AgentPubkey: agentPubB64, Scope: []string{"profile.email:read"},
	})

	kid2, pub2, err := h.AttestationPublicKey()
	if err != nil {
		t.Fatalf("second AttestationPublicKey: %v", err)
	}
	if kid1 != kid2 {
		t.Errorf("kid changed across calls: %q → %q", kid1, kid2)
	}
	if string(pub1) != string(pub2) {
		t.Errorf("pubkey changed across calls — attestation key must be stable")
	}
}

func TestLeash_IssuedRecord_StoredForRevocationLookup(t *testing.T) {
	h, encStorage, cleanup := setupLeashHandler(t)
	defer cleanup()

	connID := "agent-conn-record"
	seedAgentConnection(t, encStorage, connID)
	_, agentPubB64 := freshAgentEd25519(t)

	_, resp, _ := invokeAttest(t, h, GrantAttestRequest{
		ConnectionID: connID,
		AgentPubkey:  agentPubB64,
		Scope:        []string{"profile.email:read"},
		DurationSecs: 600,
	})

	rec, ok, err := h.IssuedRecord(resp.JTI)
	if err != nil {
		t.Fatalf("IssuedRecord error: %v", err)
	}
	if !ok || rec == nil {
		t.Fatalf("issuance record not found for jti %q", resp.JTI)
	}
	if rec.JTI != resp.JTI {
		t.Errorf("jti mismatch: rec=%q resp=%q", rec.JTI, resp.JTI)
	}
	if rec.Revoked {
		t.Errorf("newly-issued leash should not be marked revoked")
	}
	if rec.ConnectionID != connID {
		t.Errorf("connection_id mismatch: rec=%q want=%q", rec.ConnectionID, connID)
	}
	if rec.ExpiresAt != resp.ExpiresAt {
		t.Errorf("expires_at mismatch: rec=%d resp=%d", rec.ExpiresAt, resp.ExpiresAt)
	}
}

func TestLeash_Reject_MissingConnection(t *testing.T) {
	h, _, cleanup := setupLeashHandler(t)
	defer cleanup()

	_, agentPubB64 := freshAgentEd25519(t)
	_, _, generic := invokeAttest(t, h, GrantAttestRequest{
		ConnectionID: "does-not-exist",
		AgentPubkey:  agentPubB64,
		Scope:        []string{"profile.email:read"},
	})
	expectError(t, generic, "connection not found")
}

func TestLeash_Reject_EmptyScope(t *testing.T) {
	h, encStorage, cleanup := setupLeashHandler(t)
	defer cleanup()
	seedAgentConnection(t, encStorage, "agent-conn-emptyscope")
	_, agentPubB64 := freshAgentEd25519(t)

	_, _, generic := invokeAttest(t, h, GrantAttestRequest{
		ConnectionID: "agent-conn-emptyscope",
		AgentPubkey:  agentPubB64,
		Scope:        []string{},
	})
	expectError(t, generic, "scope token")
}

func TestLeash_Reject_UnscopedWildcard(t *testing.T) {
	h, encStorage, cleanup := setupLeashHandler(t)
	defer cleanup()
	seedAgentConnection(t, encStorage, "agent-conn-wildcard")
	_, agentPubB64 := freshAgentEd25519(t)

	_, _, generic := invokeAttest(t, h, GrantAttestRequest{
		ConnectionID: "agent-conn-wildcard",
		AgentPubkey:  agentPubB64,
		Scope:        []string{"*:*"},
	})
	expectError(t, generic, "unscoped")
}

func TestLeash_Reject_BadAgentPubkey(t *testing.T) {
	h, encStorage, cleanup := setupLeashHandler(t)
	defer cleanup()
	seedAgentConnection(t, encStorage, "agent-conn-badpub")

	_, _, generic := invokeAttest(t, h, GrantAttestRequest{
		ConnectionID: "agent-conn-badpub",
		AgentPubkey:  "not-base64url!",
		Scope:        []string{"profile.email:read"},
	})
	expectError(t, generic, "agent_pubkey")
}

func TestLeash_Reject_NonAgentConnection(t *testing.T) {
	h, encStorage, cleanup := setupLeashHandler(t)
	defer cleanup()

	// Seed a peer (not agent) connection.
	rec := ConnectionRecord{
		ConnectionID:   "peer-conn-1",
		ConnectionType: "peer",
		Status:         "active",
		PeerAlias:      "Some Peer",
	}
	data, _ := json.Marshal(rec)
	encStorage.Put("connections/peer-conn-1", data)
	_, agentPubB64 := freshAgentEd25519(t)

	_, _, generic := invokeAttest(t, h, GrantAttestRequest{
		ConnectionID: "peer-conn-1",
		AgentPubkey:  agentPubB64,
		Scope:        []string{"profile.email:read"},
	})
	expectError(t, generic, "not an agent")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func expectClaim(t *testing.T, claims map[string]interface{}, key string, want interface{}) {
	t.Helper()
	got, ok := claims[key]
	if !ok {
		t.Errorf("claim %q missing", key)
		return
	}
	if got != want {
		t.Errorf("claim %q: got %v want %v", key, got, want)
	}
}

func expectError(t *testing.T, generic map[string]interface{}, substring string) {
	t.Helper()
	if success, _ := generic["success"].(bool); success {
		t.Errorf("expected error containing %q, got success=true: %v", substring, generic)
		return
	}
	errStr, _ := generic["error"].(string)
	if !strings.Contains(errStr, substring) {
		t.Errorf("expected error to contain %q, got %q", substring, errStr)
	}
}
