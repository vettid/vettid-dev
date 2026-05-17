package main

import (
	"fmt"
	"testing"
	"time"
)

func TestAgentRateLimiter_BurstThenDeny(t *testing.T) {
	l := newAgentRateLimiter()
	key := "conn-A"
	// Burst should drain to zero in exactly `agentRateBurst` calls.
	for i := 0; i < agentRateBurst; i++ {
		if !l.Allow(key) {
			t.Fatalf("Allow returned false within burst at i=%d", i)
		}
	}
	// One more should be refused.
	if l.Allow(key) {
		t.Errorf("Allow returned true after exhausting burst")
	}
}

func TestAgentRateLimiter_Refills(t *testing.T) {
	l := newAgentRateLimiter()
	key := "conn-A"
	for i := 0; i < agentRateBurst; i++ {
		if !l.Allow(key) {
			t.Fatalf("Allow returned false within burst at i=%d", i)
		}
	}
	// Manually rewind the bucket's lastRefill so refill math credits us
	// without sleeping a real second in the test.
	l.mu.Lock()
	l.buckets[key].lastRefill = time.Now().Add(-2 * time.Second)
	l.mu.Unlock()
	if !l.Allow(key) {
		t.Errorf("Allow returned false after 2s refill window")
	}
}

func TestAgentRateLimiter_PerKeyIsolation(t *testing.T) {
	l := newAgentRateLimiter()
	for i := 0; i < agentRateBurst; i++ {
		if !l.Allow("conn-A") {
			t.Fatalf("Allow A returned false at i=%d", i)
		}
	}
	// A is now drained, B should still be allowed.
	if !l.Allow("conn-B") {
		t.Errorf("Allow B refused even though only A was drained")
	}
}

func TestAgentRateLimiter_EmptyKeyRejected(t *testing.T) {
	l := newAgentRateLimiter()
	if l.Allow("") {
		t.Errorf("Allow accepted empty key")
	}
}

func TestAgentRateLimiter_CapHeld(t *testing.T) {
	l := newAgentRateLimiter()
	// Fill to cap then keep pushing novel keys. The map must never
	// exceed maxItems regardless of how many keys we throw at it.
	for i := 0; i < agentRateMaxBuckets*2; i++ {
		l.Allow(fmt.Sprintf("conn-%d", i))
	}
	if got := l.size(); got > agentRateMaxBuckets {
		t.Errorf("bucket map grew past cap: got %d > %d", got, agentRateMaxBuckets)
	}
}

func TestAgentRateLimiter_IdleEvictPreferred(t *testing.T) {
	l := newAgentRateLimiter()
	// Fill to cap, then mark one bucket as idle.
	for i := 0; i < agentRateMaxBuckets; i++ {
		l.Allow(fmt.Sprintf("conn-%d", i))
	}
	l.mu.Lock()
	l.buckets["conn-0"].lastSeen = time.Now().Add(-2 * agentRateIdleEvictTTL)
	l.mu.Unlock()

	// A novel key should be admitted, and the idle bucket should be
	// the one that got reclaimed (not a younger, active one).
	if !l.Allow("conn-fresh") {
		t.Errorf("Allow refused novel key after idle slot freed")
	}
	l.mu.Lock()
	_, conn0Survived := l.buckets["conn-0"]
	_, freshExists := l.buckets["conn-fresh"]
	l.mu.Unlock()
	if conn0Survived {
		t.Errorf("idle bucket conn-0 should have been evicted")
	}
	if !freshExists {
		t.Errorf("conn-fresh should have been admitted")
	}
}

func TestAgentRateLimiter_LRUFallbackWhenAllBusy(t *testing.T) {
	// If no buckets are idle, a novel key still gets in by evicting
	// the oldest-seen entry. This is the design — otherwise 512
	// attacker-controlled connection IDs would permanently lock out
	// new ones.
	l := newAgentRateLimiter()
	for i := 0; i < agentRateMaxBuckets; i++ {
		l.Allow(fmt.Sprintf("conn-%d", i))
	}
	if !l.Allow("conn-fresh") {
		t.Errorf("Allow refused novel key when LRU fallback should have admitted it")
	}
	if l.size() > agentRateMaxBuckets {
		t.Errorf("size %d exceeds cap %d after LRU fallback", l.size(), agentRateMaxBuckets)
	}
}

func TestAgentRateLimiter_ForgetClearsBucket(t *testing.T) {
	l := newAgentRateLimiter()
	if !l.Allow("conn-X") {
		t.Fatal("Allow refused first request")
	}
	if l.size() != 1 {
		t.Fatalf("expected 1 bucket, got %d", l.size())
	}
	l.Forget("conn-X")
	if l.size() != 0 {
		t.Fatalf("Forget did not drop bucket, size=%d", l.size())
	}
}
