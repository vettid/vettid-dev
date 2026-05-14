package main

// Regression tests for the routing-ownership revocation fence
// (split-brain fix, D2 2026-05-14).
//
// When the parent's RoutingManager loses a user's routing claim it
// sends a revoke_ownership message. receiveMessages applies it via
// MarkOwnershipRevoked — bypassing HandleMessage so it lands even
// while the main loop is blocked mid-request. Once set, the flag
// must (a) make HandleMessage refuse new ops and (b) make
// flushVaultStateToS3 refuse to persist, so the orphaned OLD
// subprocess can't clobber the new owner's vault_state.enc.

import (
	"context"
	"testing"
)

func TestIsRevokeOwnership(t *testing.T) {
	mh := &MessageHandler{}
	cases := []struct {
		name string
		typ  MessageType
		want bool
	}{
		{"revoke_ownership matches", MessageTypeRevokeOwnership, true},
		{"vault_op does not match", MessageTypeVaultOp, false},
		{"sealer_response does not match", MessageTypeSealerResponse, false},
		{"empty type does not match", MessageType(""), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := mh.IsRevokeOwnership(&IncomingMessage{Type: tc.typ}); got != tc.want {
				t.Errorf("IsRevokeOwnership(%q) = %v, want %v", tc.typ, got, tc.want)
			}
		})
	}
}

func TestMarkOwnershipRevoked_FlipsFlag(t *testing.T) {
	mh := &MessageHandler{ownerSpace: "user-1", vaultState: &VaultState{}}

	if mh.isOwnershipRevoked() {
		t.Fatal("ownershipRevoked should start false")
	}
	mh.MarkOwnershipRevoked()
	if !mh.isOwnershipRevoked() {
		t.Fatal("ownershipRevoked should be true after MarkOwnershipRevoked")
	}
	// Idempotent — a second revoke (e.g. a duplicate message) must not
	// panic or clear the flag.
	mh.MarkOwnershipRevoked()
	if !mh.isOwnershipRevoked() {
		t.Fatal("ownershipRevoked should stay true after a second MarkOwnershipRevoked")
	}
}

func TestMarkOwnershipRevoked_NilStateIsSafe(t *testing.T) {
	mh := &MessageHandler{ownerSpace: "user-1"} // vaultState nil
	mh.MarkOwnershipRevoked()                   // must not panic
	if mh.isOwnershipRevoked() {
		t.Error("isOwnershipRevoked should be false when vaultState is nil")
	}
}

func TestHandleMessage_RefusesWhenRevoked(t *testing.T) {
	mh := &MessageHandler{ownerSpace: "user-1", vaultState: &VaultState{}}
	mh.MarkOwnershipRevoked()

	// Once revoked the handler must refuse the op outright — not just
	// decline to persist. Serving would mutate in-memory state that
	// can never be safely flushed. The app retries and lands on the
	// new owner.
	resp, err := mh.HandleMessage(context.Background(), &IncomingMessage{
		Type:      MessageTypeVaultOp,
		RequestID: "req-1",
		Subject:   "OwnerSpace.user-1.forVault.profile.get",
	})
	if err != nil {
		t.Fatalf("expected a graceful error response, not a Go error: %v", err)
	}
	if resp == nil || resp.Type != MessageTypeError {
		t.Fatalf("expected an error-typed response when revoked, got %+v", resp)
	}
	if resp.RequestID != "req-1" {
		t.Errorf("error response should echo the request id, got %q", resp.RequestID)
	}
}
