package main

import (
	"sync"
	"time"
)

// SECURITY (#32): per-connection token-bucket rate limit on the agent
// message handler.
//
// Why: HandleAgentMessage does non-trivial work per message — connection
// lookup, ECDH-derived key derivation, AEAD decrypt, JSON parse, and in
// the common case a storage round-trip. A peer that holds valid
// connection credentials but spins a tight loop can saturate the
// vault's CPU and message-channel queue. The contract-level RateLimit
// (e.g. 60/hour for secret retrievals) defends the *user-visible* cost
// of data leaks, but doesn't stop the cheaper "ping the inbox" flood.
//
// Why not just count: a token bucket gives small bursts (legitimate
// flows like initial agent handshake or batch catalog enumeration
// frequently send a handful of messages in quick succession) while
// holding the long-run rate to something a human-driven workflow can
// sustain.
//
// Capacity: 512 buckets total — mirrors pendingApprovalsMaxTotal so a
// hostile peer can't blow up the bucket table itself. Buckets are
// evicted oldest-first when the cap is hit.

const (
	agentRateBurst        = 60
	agentRateTokensPerSec = 1.0
	agentRateMaxBuckets   = 512
	agentRateIdleEvictTTL = 5 * time.Minute
)

type tokenBucket struct {
	tokens     float64
	lastRefill time.Time
	lastSeen   time.Time
}

type agentRateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*tokenBucket
	burst    float64
	refill   float64 // tokens per second
	maxItems int
	idleTTL  time.Duration
}

func newAgentRateLimiter() *agentRateLimiter {
	return &agentRateLimiter{
		buckets:  make(map[string]*tokenBucket),
		burst:    float64(agentRateBurst),
		refill:   agentRateTokensPerSec,
		maxItems: agentRateMaxBuckets,
		idleTTL:  agentRateIdleEvictTTL,
	}
}

// Allow checks whether a request from `key` (the connection_id) may
// proceed and atomically debits one token. Returns false when the
// bucket is empty OR when the table is full and `key` is novel.
func (l *agentRateLimiter) Allow(key string) bool {
	if key == "" {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	b, ok := l.buckets[key]
	if !ok {
		// Try to evict idle entries before allocating a new bucket.
		if len(l.buckets) >= l.maxItems {
			l.evictLocked(now)
		}
		// Still full → refuse novel keys. Existing buckets keep working.
		if len(l.buckets) >= l.maxItems {
			return false
		}
		b = &tokenBucket{
			tokens:     l.burst,
			lastRefill: now,
			lastSeen:   now,
		}
		l.buckets[key] = b
	}

	// Refill: add tokens proportional to elapsed time, capped at burst.
	elapsed := now.Sub(b.lastRefill).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * l.refill
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.lastRefill = now
	}
	b.lastSeen = now

	if b.tokens < 1 {
		return false
	}
	b.tokens -= 1
	return true
}

// evictLocked removes idle buckets so a fresh key can allocate. Caller
// holds the mutex. Two passes:
//   1. Drop any bucket that has been idle longer than `idleTTL`.
//   2. If still over cap, drop the single oldest-seen bucket.
func (l *agentRateLimiter) evictLocked(now time.Time) {
	cutoff := now.Add(-l.idleTTL)
	for k, b := range l.buckets {
		if b.lastSeen.Before(cutoff) {
			delete(l.buckets, k)
		}
	}
	if len(l.buckets) < l.maxItems {
		return
	}
	// Drop the single oldest entry — preserves recently-active flows.
	var oldestKey string
	var oldestSeen time.Time
	for k, b := range l.buckets {
		if oldestKey == "" || b.lastSeen.Before(oldestSeen) {
			oldestKey = k
			oldestSeen = b.lastSeen
		}
	}
	if oldestKey != "" {
		delete(l.buckets, oldestKey)
	}
}

// Forget drops the bucket for a connection — call this when a
// connection is revoked so the table doesn't carry dead entries.
func (l *agentRateLimiter) Forget(key string) {
	if key == "" {
		return
	}
	l.mu.Lock()
	delete(l.buckets, key)
	l.mu.Unlock()
}

// size returns the current number of tracked buckets. Test-only.
func (l *agentRateLimiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
