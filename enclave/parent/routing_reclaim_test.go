package main

// Regression tests for the input-validation paths of
// ReclaimUsersFromPCR0. The full happy path requires a live NATS
// KeyValue store; that's exercised end-to-end by deploy.sh Phase 4.6
// against a real fleet. The cases below pin the safety checks that
// run before any KV access — they would have caught a "reclaim from
// self" bug at unit time.

import (
	"strings"
	"testing"
)

func TestReclaimUsersFromPCR0_RejectsEmpty(t *testing.T) {
	r := &RoutingManager{pcr0: "abc123..."}
	got, err := r.ReclaimUsersFromPCR0("")
	if err == nil {
		t.Fatal("expected error on empty oldPCR0")
	}
	if got != 0 {
		t.Errorf("expected claimed=0 on rejected input, got %d", got)
	}
	if !strings.Contains(err.Error(), "non-empty") {
		t.Errorf("error should describe the empty-input problem: %v", err)
	}
}

func TestReclaimUsersFromPCR0_RejectsSelfReclaim(t *testing.T) {
	// Critical safety: if NEW's own PCR0 is passed (operator typo,
	// stale config, etc.) we'd CAS-update every routing entry to
	// ourselves with a new lease, masking real ownership state.
	// Refuse explicitly.
	const ourPCR = "abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc1"
	r := &RoutingManager{pcr0: ourPCR}
	got, err := r.ReclaimUsersFromPCR0(ourPCR)
	if err == nil {
		t.Fatal("expected error on self-reclaim")
	}
	if got != 0 {
		t.Errorf("expected claimed=0 on rejected input, got %d", got)
	}
	if !strings.Contains(err.Error(), "self") {
		t.Errorf("error should call out the self-reclaim problem: %v", err)
	}
}
