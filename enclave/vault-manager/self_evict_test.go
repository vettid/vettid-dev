package main

// Regression tests for D3 self-eviction (split-brain self-heal).
//
// When a conditional-PUT of vault_state.enc is rejected because our
// IfMatch ETag went stale (another writer won the race), the D3
// branch in flushVaultStateToS3 sets selfEvictRequested instead of
// latching ownershipRevoked. The main loop polls IsSelfEvictRequested
// and exits the subprocess so the next op spawns a fresh one that
// cold-reloads the winning state. Until the loop gets there,
// HandleMessage must refuse further ops with the same retry error
// the revoke path uses.

import (
	"context"
	"testing"
)

func TestIsSelfEvictRequested_DefaultsFalse(t *testing.T) {
	mh := &MessageHandler{ownerSpace: "user-1", vaultState: &VaultState{}}
	if mh.IsSelfEvictRequested() {
		t.Fatal("selfEvictRequested should start false")
	}
}

func TestIsSelfEvictRequested_NilStateIsSafe(t *testing.T) {
	mh := &MessageHandler{ownerSpace: "user-1"} // vaultState nil
	if mh.IsSelfEvictRequested() {
		t.Error("IsSelfEvictRequested should be false when vaultState is nil")
	}
}

func TestHandleMessage_RefusesWhenSelfEvictPending(t *testing.T) {
	mh := &MessageHandler{ownerSpace: "user-1", vaultState: &VaultState{}}
	// Simulate the D3 branch having tripped.
	mh.vaultState.mu.Lock()
	mh.vaultState.selfEvictRequested = true
	mh.vaultState.mu.Unlock()

	resp, err := mh.HandleMessage(context.Background(), &IncomingMessage{
		Type:      MessageTypeVaultOp,
		RequestID: "req-1",
		Subject:   "OwnerSpace.user-1.forVault.profile.get",
	})
	if err != nil {
		t.Fatalf("expected a graceful error response, not a Go error: %v", err)
	}
	if resp == nil || resp.Type != MessageTypeError {
		t.Fatalf("expected an error-typed response when self-evict pending, got %+v", resp)
	}
	if resp.RequestID != "req-1" {
		t.Errorf("error response should echo the request id, got %q", resp.RequestID)
	}
}

// selfEvictRequested and ownershipRevoked are independent fences: the
// D3 path must NOT latch ownershipRevoked (that flag assumes the
// supervisor kills the subprocess right after, which a self-detected
// conflict has no one to do).
func TestSelfEvict_DoesNotLatchOwnershipRevoked(t *testing.T) {
	mh := &MessageHandler{ownerSpace: "user-1", vaultState: &VaultState{}}
	mh.vaultState.mu.Lock()
	mh.vaultState.selfEvictRequested = true
	mh.vaultState.mu.Unlock()

	if mh.isOwnershipRevoked() {
		t.Error("D3 self-eviction must not set ownershipRevoked")
	}
	if !mh.IsSelfEvictRequested() {
		t.Error("selfEvictRequested should be observable once set")
	}
}
