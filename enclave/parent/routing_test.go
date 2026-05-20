package main

import (
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

// TestRecordOwnershipLocked_RefreshesInPlace guards the 2026-05-20
// double-subscription bug: a reclaim that REPLACED an existing
// r.owned[guid] entry orphaned that entry's live NATS subscription
// (it was never Unsubscribed, just dropped), and subscribeUser then
// added a second — every vault op was delivered twice.
//
// recordOwnershipLocked must refresh an existing entry IN PLACE
// (same *ownedUser pointer, so its .subscription survives) and only
// allocate a fresh entry when the user is genuinely unowned.
func TestRecordOwnershipLocked_RefreshesInPlace(t *testing.T) {
	r := &RoutingManager{owned: make(map[string]*ownedUser)}
	const guid = "11111111-2222-3333-4444-555555555555"

	// Fresh claim — a new entry is allocated.
	r.mu.Lock()
	r.recordOwnershipLocked(guid, 5, time.Now().Add(time.Minute))
	r.mu.Unlock()

	first := r.owned[guid]
	if first == nil {
		t.Fatal("first claim did not record an ownership entry")
	}
	if first.revision != 5 {
		t.Fatalf("revision: got %d, want 5", first.revision)
	}

	// Stand in for the subscription subscribeUser would attach.
	sentinel := &nats.Subscription{}
	first.subscription = sentinel

	// Reclaim (e.g. ReclaimUsersFromPCR0 running again on a deploy.sh
	// Phase 4.6 retry). The entry must NOT be replaced.
	r.mu.Lock()
	r.recordOwnershipLocked(guid, 9, time.Now().Add(2*time.Minute))
	r.mu.Unlock()

	second := r.owned[guid]
	if second != first {
		t.Fatal("reclaim replaced the ownership entry — the live subscription would be orphaned and subscribeUser would add a second (double delivery)")
	}
	if second.subscription != sentinel {
		t.Fatal("reclaim dropped the entry's subscription pointer")
	}
	if second.revision != 9 {
		t.Fatalf("reclaim did not refresh the revision: got %d, want 9", second.revision)
	}
}
