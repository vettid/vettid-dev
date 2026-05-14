package main

// Regression tests for the routing ownership-release callback wiring
// (split-brain fix, D1 2026-05-14).
//
// releaseLocally is the single funnel for all three ways this instance
// can lose a routing claim (intentional handoff, watcher-observed
// steal, heartbeat CAS-fail) plus the reconcile stale-drop. The parent
// hooks its onRelease callback here to evict the now-orphaned
// vault-manager subprocess. Two invariants matter:
//
//  1. onRelease fires when we genuinely held the entry.
//  2. onRelease does NOT fire on a no-op release (entry already gone),
//     so a double release — e.g. a heartbeat CAS-fail immediately
//     followed by a watcher event for the same user — evicts once,
//     not twice.

import (
	"testing"
	"time"
)

// waitForRelease drains up to `want` callback signals from ch within a
// short window. Returns how many actually arrived. onRelease runs on a
// goroutine, so the test must synchronize rather than assume the call
// is complete when releaseLocally returns.
func waitForRelease(t *testing.T, ch <-chan string, want int) int {
	t.Helper()
	got := 0
	deadline := time.After(500 * time.Millisecond)
	for got < want {
		select {
		case <-ch:
			got++
		case <-deadline:
			return got
		}
	}
	// Give any spurious extra callback a moment to show up so the
	// "fires exactly once" assertions are meaningful.
	select {
	case <-ch:
		got++
	case <-time.After(50 * time.Millisecond):
	}
	return got
}

func TestReleaseLocally_FiresOnReleaseWhenOwned(t *testing.T) {
	const guid = "user-abc"
	fired := make(chan string, 4)
	r := &RoutingManager{
		owned:     map[string]*ownedUser{guid: {}}, // subscription nil — no NATS needed
		onRelease: func(g string) { fired <- g },
	}

	r.releaseLocally(guid)

	if n := waitForRelease(t, fired, 1); n != 1 {
		t.Fatalf("expected onRelease to fire exactly once for an owned user, got %d", n)
	}
	if _, stillOwned := r.owned[guid]; stillOwned {
		t.Errorf("releaseLocally should have removed the entry from owned")
	}
}

func TestReleaseLocally_DoesNotFireWhenNotOwned(t *testing.T) {
	fired := make(chan string, 4)
	r := &RoutingManager{
		owned:     map[string]*ownedUser{},
		onRelease: func(g string) { fired <- g },
	}

	// Releasing a user we never owned must be a silent no-op — no
	// callback, so the supervisor isn't told to evict a subprocess
	// that doesn't exist / belongs to nobody.
	r.releaseLocally("user-never-owned")

	if n := waitForRelease(t, fired, 1); n != 0 {
		t.Fatalf("expected onRelease NOT to fire for an unowned user, got %d", n)
	}
}

func TestReleaseLocally_DoubleReleaseFiresOnce(t *testing.T) {
	const guid = "user-xyz"
	fired := make(chan string, 4)
	r := &RoutingManager{
		owned:     map[string]*ownedUser{guid: {}},
		onRelease: func(g string) { fired <- g },
	}

	// First release: genuine transition — fires.
	r.releaseLocally(guid)
	// Second release for the same user: entry is already gone, so this
	// is the heartbeat-CAS-fail-then-watcher-event sequence. Must NOT
	// fire a second eviction.
	r.releaseLocally(guid)

	if n := waitForRelease(t, fired, 2); n != 1 {
		t.Fatalf("double release of the same user should fire onRelease exactly once, got %d", n)
	}
}

func TestReleaseLocally_NilCallbackIsSafe(t *testing.T) {
	const guid = "user-nocb"
	r := &RoutingManager{
		owned: map[string]*ownedUser{guid: {}},
		// onRelease intentionally nil — SetOnRelease may not have been
		// called (e.g. in tests, or a future caller). Must not panic.
	}
	r.releaseLocally(guid) // must not panic
	if _, stillOwned := r.owned[guid]; stillOwned {
		t.Errorf("releaseLocally should still remove the entry with a nil callback")
	}
}
