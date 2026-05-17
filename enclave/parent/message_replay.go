package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// SECURITY: Replay protection constants
const (
	// Maximum age of messages (reject messages older than this)
	maxMessageAgeSeconds = 300 // 5 minutes

	// Maximum future-clock-skew tolerance for inbound messages.
	// Higher than the backend-to-enclave control-command skew
	// (10s — see control_verification.go) because messages here
	// can originate from mobile clients whose NTP discipline is
	// less reliable than EC2's. Tighten further if mobile-side
	// clock drift turns out to be a non-issue in production.
	maxMessageFutureSkewSeconds = 30

	// Time window for duplicate detection
	replayCacheRetentionSeconds = 600 // 10 minutes (2x message age for safety)

	// Maximum entries in replay cache (prevent memory exhaustion)
	maxReplayCacheSize = 50000

	// Cleanup interval
	replayCacheCleanupInterval = 60 * time.Second

	// SECURITY (authZ-H4): persist the replay cache to local disk so a
	// parent restart inside the message-freshness window doesn't reset
	// the dedup state. On the same EC2 host across an in-place restart
	// this prevents an attacker from replaying a captured-but-fresh
	// message while we were briefly down. Across an ASG refresh the
	// new host starts empty (no shared disk), but the timestamp gate
	// is still the primary defence.
	replayCachePersistInterval = 30 * time.Second
	replayCachePathDefault     = "/var/lib/vettid/replay-cache.json"
	replayCachePathEnvVar      = "VETTID_REPLAY_CACHE_PATH"
)

// replayEntry stores a message hash with its first-seen time
type replayEntry struct {
	hash     [32]byte
	firstSeen time.Time
}

// MessageReplayCache prevents replay attacks by tracking seen messages
// SECURITY: Thread-safe cache with automatic expiration and size limits
type MessageReplayCache struct {
	entries     map[[32]byte]time.Time
	mu          sync.RWMutex
	lastCleanup time.Time
}

// NewMessageReplayCache creates a new message replay cache. Loads any
// previously-persisted entries from disk so dedup state survives an
// in-place parent restart. SECURITY (authZ-H4).
func NewMessageReplayCache() *MessageReplayCache {
	rc := &MessageReplayCache{
		entries:     make(map[[32]byte]time.Time),
		lastCleanup: time.Now(),
	}
	rc.loadFromDisk()
	go rc.persistLoop()
	return rc
}

func replayCachePath() string {
	if p := os.Getenv(replayCachePathEnvVar); p != "" {
		return p
	}
	return replayCachePathDefault
}

// persistedEntry is the on-disk shape — we serialize the hex hash + the
// first-seen unix-nanos so reload preserves the original retention
// window.
type persistedEntry struct {
	Hash      string `json:"h"`
	FirstSeen int64  `json:"t"`
}

func (rc *MessageReplayCache) loadFromDisk() {
	path := replayCachePath()
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warn().Err(err).Str("path", path).Msg("Replay cache load failed; starting empty")
		}
		return
	}
	var entries []persistedEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		log.Warn().Err(err).Str("path", path).Msg("Replay cache parse failed; starting empty")
		return
	}
	cutoff := time.Now().Add(-time.Duration(replayCacheRetentionSeconds) * time.Second)
	loaded := 0
	for _, e := range entries {
		ts := time.Unix(0, e.FirstSeen)
		if ts.Before(cutoff) {
			continue
		}
		raw, err := hex.DecodeString(e.Hash)
		if err != nil || len(raw) != 32 {
			continue
		}
		var hash [32]byte
		copy(hash[:], raw)
		rc.entries[hash] = ts
		loaded++
	}
	log.Info().Int("loaded", loaded).Int("on_disk", len(entries)).Msg("Replay cache restored from disk")
}

func (rc *MessageReplayCache) persistLoop() {
	ticker := time.NewTicker(replayCachePersistInterval)
	defer ticker.Stop()
	for range ticker.C {
		if err := rc.persistToDisk(); err != nil {
			log.Warn().Err(err).Msg("Replay cache persist failed")
		}
	}
}

func (rc *MessageReplayCache) persistToDisk() error {
	rc.mu.RLock()
	entries := make([]persistedEntry, 0, len(rc.entries))
	for hash, ts := range rc.entries {
		entries = append(entries, persistedEntry{
			Hash:      hex.EncodeToString(hash[:]),
			FirstSeen: ts.UnixNano(),
		})
	}
	rc.mu.RUnlock()

	data, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	path := replayCachePath()
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil && !os.IsExist(err) {
			return err
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// computeMessageHash generates a unique hash for a message
// SECURITY: Hash includes subject + data to ensure uniqueness
func computeMessageHash(subject string, data []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(subject))
	h.Write([]byte(":")) // Separator to prevent collision attacks
	h.Write(data)
	var hash [32]byte
	copy(hash[:], h.Sum(nil))
	return hash
}

// CheckAndAdd checks if a message is a replay, returning true if allowed (not a replay)
// SECURITY: Atomically checks and inserts to prevent race conditions
func (rc *MessageReplayCache) CheckAndAdd(subject string, data []byte) (bool, string) {
	hash := computeMessageHash(subject, data)

	rc.mu.Lock()
	defer rc.mu.Unlock()

	// Periodic cleanup
	now := time.Now()
	if now.Sub(rc.lastCleanup) > replayCacheCleanupInterval {
		rc.cleanupLocked()
		rc.lastCleanup = now
	}

	// Check if message already seen
	if firstSeen, exists := rc.entries[hash]; exists {
		hashStr := hex.EncodeToString(hash[:8]) // Short hash for logging
		age := now.Sub(firstSeen)
		log.Warn().
			Str("subject", subject).
			Str("hash", hashStr).
			Dur("age_since_first", age).
			Msg("SECURITY: Replay attack detected - duplicate message")
		return false, "replay detected: message already processed"
	}

	// Check cache size
	if len(rc.entries) >= maxReplayCacheSize {
		rc.cleanupLocked()
		// If TTL cleanup didn't free space, drop the oldest 20% so
		// new traffic can flow. SECURITY (#33/#85): after this we
		// have to fail-closed if the cache is STILL full — the
		// previous behaviour was to "log and allow", which under
		// sustained pressure meant replay protection silently
		// degraded to zero for the duration of the overflow.
		if len(rc.entries) >= maxReplayCacheSize {
			log.Warn().
				Int("cache_size", len(rc.entries)).
				Msg("SECURITY: Replay cache full — forcing aggressive cleanup")
			rc.aggressiveCleanupLocked()
		}
		if len(rc.entries) >= maxReplayCacheSize {
			// Genuinely cannot make room — every entry is fresh.
			// This indicates a DoS, not normal traffic. Reject
			// rather than letting a captured replay slip past.
			log.Error().
				Int("cache_size", len(rc.entries)).
				Msg("SECURITY: Replay cache exhausted — failing closed")
			return false, "replay cache exhausted (server under load)"
		}
	}

	// Add to cache
	rc.entries[hash] = now
	return true, ""
}

// cleanupLocked removes expired entries (must be called with lock held)
func (rc *MessageReplayCache) cleanupLocked() {
	cutoff := time.Now().Add(-time.Duration(replayCacheRetentionSeconds) * time.Second)
	removed := 0
	for hash, ts := range rc.entries {
		if ts.Before(cutoff) {
			delete(rc.entries, hash)
			removed++
		}
	}
	if removed > 0 {
		log.Debug().
			Int("removed", removed).
			Int("remaining", len(rc.entries)).
			Msg("Replay cache cleanup completed")
	}
}

// aggressiveCleanupLocked removes the oldest 20% of entries (must be called with lock held).
//
// SECURITY (#85): the prior implementation re-scanned the full map
// to find the single oldest entry, then repeated K=N/5 times. That's
// O(N²) — with N=50000 (the configured cap) and K=10000 that's
// 500 million map iterations per cleanup. Under a deliberate flood
// the cleanup itself becomes the DoS amplifier. Now we collect
// (hash, ts) pairs once, sort by ts, drop the K oldest in one pass:
// O(N) collect + O(N log N) sort + O(K) delete. With N=50000 that's
// ~700K operations instead of 500M.
func (rc *MessageReplayCache) aggressiveCleanupLocked() {
	targetRemoval := len(rc.entries) / 5
	if targetRemoval == 0 {
		return
	}

	type entry struct {
		hash [32]byte
		ts   time.Time
	}
	all := make([]entry, 0, len(rc.entries))
	for h, ts := range rc.entries {
		all = append(all, entry{hash: h, ts: ts})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ts.Before(all[j].ts) })

	for i := 0; i < targetRemoval; i++ {
		delete(rc.entries, all[i].hash)
	}

	log.Warn().
		Int("removed", targetRemoval).
		Int("remaining", len(rc.entries)).
		Msg("SECURITY: Aggressive replay cache cleanup completed")
}

// Size returns the current cache size
func (rc *MessageReplayCache) Size() int {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return len(rc.entries)
}

// messagePayload represents the expected structure of NATS message payloads
// SECURITY: Used for timestamp validation
type messagePayload struct {
	Timestamp    int64  `json:"timestamp,omitempty"`     // Unix timestamp in seconds
	TimestampMs  int64  `json:"timestamp_ms,omitempty"`  // Unix timestamp in milliseconds
	RequestID    string `json:"request_id,omitempty"`    // Request ID for correlation
	MessageID    string `json:"message_id,omitempty"`    // Explicit message ID
	Nonce        string `json:"nonce,omitempty"`         // Message nonce
}

// ValidateMessageTimestamp checks if the message payload contains a valid timestamp
// Returns true if message is fresh (or has no timestamp), false if expired
// SECURITY: Prevents replay of old captured messages
func ValidateMessageTimestamp(data []byte) (bool, string) {
	var payload messagePayload
	if err := json.Unmarshal(data, &payload); err != nil {
		// Not JSON or doesn't have timestamp fields - allow (fail open for compatibility)
		return true, ""
	}

	// SECURITY (#75): messages with NO timestamp at all bypass the
	// freshness gate today — an attacker who strips the timestamp
	// field from a captured message can replay it indefinitely.
	// Warn-and-allow surfaces the legacy callers in logs so the
	// audit can flip this to fail-closed (set
	// VETTID_REQUIRE_MESSAGE_TIMESTAMP=true) once the inventory is
	// clean. Enforce mode rejects; non-enforce mode logs + allows.
	hasTimestamp := payload.Timestamp > 0 || payload.TimestampMs > 0
	if !hasTimestamp {
		if requireMessageTimestamp() {
			log.Warn().Msg("SECURITY: message has no timestamp — rejecting (strict mode)")
			return false, "message missing required timestamp"
		}
		log.Warn().Msg("SECURITY: message has no timestamp — allowing (compat mode; set VETTID_REQUIRE_MESSAGE_TIMESTAMP=true to enforce)")
	}

	now := time.Now().Unix()

	// Check Unix timestamp (seconds)
	if payload.Timestamp > 0 {
		age := now - payload.Timestamp
		if age < 0 {
			// Message from the future - allow small mobile-tolerant skew
			if age < -maxMessageFutureSkewSeconds {
				log.Warn().
					Int64("timestamp", payload.Timestamp).
					Int64("age_seconds", age).
					Msg("SECURITY: Message timestamp in the future")
				return false, "message timestamp in the future"
			}
		} else if age > maxMessageAgeSeconds {
			log.Warn().
				Int64("timestamp", payload.Timestamp).
				Int64("age_seconds", age).
				Msg("SECURITY: Message timestamp expired")
			return false, "message timestamp expired"
		}
	}

	// Check millisecond timestamp
	if payload.TimestampMs > 0 {
		ageMs := (now * 1000) - payload.TimestampMs
		ageSec := ageMs / 1000
		if ageSec < 0 {
			// Message from the future - allow small mobile-tolerant skew
			if ageSec < -maxMessageFutureSkewSeconds {
				log.Warn().
					Int64("timestamp_ms", payload.TimestampMs).
					Int64("age_seconds", ageSec).
					Msg("SECURITY: Message timestamp_ms in the future")
				return false, "message timestamp in the future"
			}
		} else if ageSec > maxMessageAgeSeconds {
			log.Warn().
				Int64("timestamp_ms", payload.TimestampMs).
				Int64("age_seconds", ageSec).
				Msg("SECURITY: Message timestamp_ms expired")
			return false, "message timestamp expired"
		}
	}

	return true, ""
}

// requireMessageTimestamp reports whether ValidateMessageTimestamp
// should fail-closed when an inbound message has no Timestamp /
// TimestampMs at all. See #75 — kept opt-in (env-gated) until the
// audit of legacy callers is complete.
func requireMessageTimestamp() bool {
	return os.Getenv("VETTID_REQUIRE_MESSAGE_TIMESTAMP") == "true"
}

// Global message replay cache
var globalMessageReplayCache = NewMessageReplayCache()

// CheckMessageReplay validates a NATS message for replay attacks
// Returns (allowed, errorMessage)
// SECURITY: Combines timestamp validation with duplicate detection
func CheckMessageReplay(subject string, data []byte) (bool, string) {
	// First, check timestamp (if present)
	if valid, reason := ValidateMessageTimestamp(data); !valid {
		return false, reason
	}

	// Then, check for duplicate message
	return globalMessageReplayCache.CheckAndAdd(subject, data)
}
