package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// SECURITY: Control command verification
// All control commands must be Ed25519 signed to prevent unauthorized execution
// even if NATS credentials are compromised

const (
	// Maximum age of control commands (must match TypeScript COMMAND_TTL_MS)
	maxControlCommandAge = 5 * time.Minute

	// Clock skew allowance (1 minute into the future)
	maxClockSkew = 1 * time.Minute

	// Idempotency cache retention (2x command age for safety)
	commandIdCacheRetention = 10 * time.Minute

	// Maximum command IDs in cache (prevent memory exhaustion)
	maxCommandIdCacheSize = 10000

	// Cleanup interval
	commandIdCleanupInterval = 60 * time.Second
)

// ControlTarget represents the target of a control command
type ControlTarget struct {
	Type string `json:"type"` // "global", "enclave", or "user"
	ID   string `json:"id,omitempty"`
}

// SignedControlCommand represents a signed control command from the backend
type SignedControlCommand struct {
	CommandID string            `json:"command_id"`
	Command   string            `json:"command"`
	Target    ControlTarget     `json:"target"`
	Params    map[string]any    `json:"params"`
	IssuedAt  string            `json:"issued_at"`
	IssuedBy  string            `json:"issued_by"`
	ExpiresAt string            `json:"expires_at"`
	Signature string            `json:"signature"`
}

// commandIdEntry stores a command ID with its first-seen time
type commandIdEntry struct {
	issuedAt time.Time
}

// CommandIdempotencyCache prevents replay of control commands by tracking command IDs
// SECURITY: Thread-safe cache with automatic expiration
type CommandIdempotencyCache struct {
	entries     map[string]commandIdEntry
	mu          sync.RWMutex
	lastCleanup time.Time
}

// NewCommandIdempotencyCache creates a new command idempotency cache
func NewCommandIdempotencyCache() *CommandIdempotencyCache {
	return &CommandIdempotencyCache{
		entries:     make(map[string]commandIdEntry),
		lastCleanup: time.Now(),
	}
}

// CheckAndAdd checks if a command ID has been seen, returns true if new (allowed)
// SECURITY: Atomically checks and inserts to prevent race conditions
func (c *CommandIdempotencyCache) CheckAndAdd(commandID string, issuedAt time.Time) (bool, string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Periodic cleanup
	now := time.Now()
	if now.Sub(c.lastCleanup) > commandIdCleanupInterval {
		c.cleanupLocked()
		c.lastCleanup = now
	}

	// Check if command ID already seen
	if _, exists := c.entries[commandID]; exists {
		log.Warn().
			Str("command_id", commandID).
			Msg("SECURITY: Control command replay detected - duplicate command_id")
		return false, "command already executed"
	}

	// Check cache size
	if len(c.entries) >= maxCommandIdCacheSize {
		c.cleanupLocked()
		if len(c.entries) >= maxCommandIdCacheSize {
			log.Warn().
				Int("cache_size", len(c.entries)).
				Msg("SECURITY: Command ID cache full - forcing cleanup")
			c.aggressiveCleanupLocked()
		}
	}

	// Add to cache
	c.entries[commandID] = commandIdEntry{issuedAt: issuedAt}
	return true, ""
}

// cleanupLocked removes expired entries (must be called with lock held)
func (c *CommandIdempotencyCache) cleanupLocked() {
	cutoff := time.Now().Add(-commandIdCacheRetention)
	removed := 0
	for id, entry := range c.entries {
		if entry.issuedAt.Before(cutoff) {
			delete(c.entries, id)
			removed++
		}
	}
	if removed > 0 {
		log.Debug().
			Int("removed", removed).
			Int("remaining", len(c.entries)).
			Msg("Command ID cache cleanup completed")
	}
}

// aggressiveCleanupLocked removes the oldest 20% of entries
func (c *CommandIdempotencyCache) aggressiveCleanupLocked() {
	targetRemoval := len(c.entries) / 5
	if targetRemoval == 0 {
		return
	}

	// Find and remove oldest entries
	removed := 0
	for removed < targetRemoval {
		var oldestID string
		var oldest time.Time = time.Now()
		for id, entry := range c.entries {
			if entry.issuedAt.Before(oldest) {
				oldest = entry.issuedAt
				oldestID = id
			}
		}
		if oldestID != "" {
			delete(c.entries, oldestID)
			removed++
		}
	}

	log.Warn().
		Int("removed", removed).
		Int("remaining", len(c.entries)).
		Msg("SECURITY: Aggressive command ID cache cleanup completed")
}

// Global instances
var (
	commandIdCache        = NewCommandIdempotencyCache()
	controlSigningPublicKey ed25519.PublicKey
	controlSigningKeyLoaded bool
	controlSigningKeyMu     sync.RWMutex
)

// getControlSigningPublicKey returns the Ed25519 public key for verifying control commands
// SECURITY: Public key is loaded from environment or Secrets Manager
func getControlSigningPublicKey() (ed25519.PublicKey, error) {
	controlSigningKeyMu.RLock()
	if controlSigningKeyLoaded {
		defer controlSigningKeyMu.RUnlock()
		return controlSigningPublicKey, nil
	}
	controlSigningKeyMu.RUnlock()

	controlSigningKeyMu.Lock()
	defer controlSigningKeyMu.Unlock()

	// Double-check after acquiring write lock
	if controlSigningKeyLoaded {
		return controlSigningPublicKey, nil
	}

	// Try environment variable first
	publicKeyB64 := os.Getenv("CONTROL_SIGNING_PUBLIC_KEY")
	if publicKeyB64 == "" {
		// In development mode, allow unsigned commands
		if os.Getenv("PARENT_DEV_MODE") == "true" {
			log.Warn().Msg("SECURITY: Control signing public key not configured (dev mode)")
			return nil, nil
		}
		return nil, fmt.Errorf("CONTROL_SIGNING_PUBLIC_KEY environment variable not set")
	}

	// Decode the DER-encoded public key
	// The TypeScript code exports as SPKI DER format
	publicKeyDER, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	// Parse SPKI DER format
	// SPKI for Ed25519 is: SEQUENCE { SEQUENCE { OID ed25519 }, BIT STRING { public key } }
	// The raw public key is the last 32 bytes
	if len(publicKeyDER) < 32 {
		return nil, fmt.Errorf("invalid public key format: too short")
	}

	// Ed25519 SPKI is typically 44 bytes: 12 byte header + 32 byte key
	// We extract the last 32 bytes
	controlSigningPublicKey = ed25519.PublicKey(publicKeyDER[len(publicKeyDER)-32:])
	controlSigningKeyLoaded = true

	log.Info().Msg("Control signing public key loaded")
	return controlSigningPublicKey, nil
}

// createSigningPayload creates the canonical JSON payload for signature verification
// SECURITY: Must match the TypeScript createSigningPayload function exactly
func createSigningPayload(cmd *SignedControlCommand) ([]byte, error) {
	// Create the same structure as TypeScript
	payload := map[string]any{
		"command_id": cmd.CommandID,
		"command":    cmd.Command,
		"target":     cmd.Target,
		"params":     cmd.Params,
		"issued_at":  cmd.IssuedAt,
		"issued_by":  cmd.IssuedBy,
		"expires_at": cmd.ExpiresAt,
	}
	return json.Marshal(payload)
}

// VerifyControlCommand verifies a signed control command
// SECURITY: Checks signature, expiration, and idempotency
// Returns (valid, error message)
func VerifyControlCommand(data []byte) (*SignedControlCommand, bool, string) {
	// Parse the command
	var cmd SignedControlCommand
	if err := json.Unmarshal(data, &cmd); err != nil {
		return nil, false, fmt.Sprintf("failed to parse control command: %v", err)
	}

	// Check if command has required fields
	if cmd.CommandID == "" || cmd.Command == "" || cmd.Signature == "" {
		return &cmd, false, "missing required fields (command_id, command, or signature)"
	}

	// Parse timestamps
	expiresAt, err := time.Parse(time.RFC3339, cmd.ExpiresAt)
	if err != nil {
		return &cmd, false, fmt.Sprintf("invalid expires_at format: %v", err)
	}

	issuedAt, err := time.Parse(time.RFC3339, cmd.IssuedAt)
	if err != nil {
		return &cmd, false, fmt.Sprintf("invalid issued_at format: %v", err)
	}

	now := time.Now()

	// 1. Check expiration
	if expiresAt.Before(now) {
		log.Warn().
			Str("command_id", cmd.CommandID).
			Str("command", cmd.Command).
			Time("expires_at", expiresAt).
			Msg("SECURITY: Control command has expired")
		return &cmd, false, "control command has expired"
	}

	// 2. Check freshness (must be issued within last 5 minutes)
	age := now.Sub(issuedAt)
	if age > maxControlCommandAge {
		log.Warn().
			Str("command_id", cmd.CommandID).
			Str("command", cmd.Command).
			Dur("age", age).
			Msg("SECURITY: Control command is too old")
		return &cmd, false, "control command is too old"
	}

	// Allow some clock skew into the future
	if age < -maxClockSkew {
		log.Warn().
			Str("command_id", cmd.CommandID).
			Str("command", cmd.Command).
			Time("issued_at", issuedAt).
			Msg("SECURITY: Control command issued in the future")
		return &cmd, false, "control command issued in the future"
	}

	// 3. Verify signature
	publicKey, err := getControlSigningPublicKey()
	if err != nil {
		log.Error().Err(err).Msg("SECURITY: Failed to get control signing public key")
		return &cmd, false, "failed to get signing public key"
	}

	// In dev mode without a key, allow unsigned commands
	if publicKey == nil {
		log.Warn().
			Str("command_id", cmd.CommandID).
			Str("command", cmd.Command).
			Msg("SECURITY: Allowing unsigned control command (dev mode)")
	} else {
		// Decode signature
		signature, err := base64.StdEncoding.DecodeString(cmd.Signature)
		if err != nil {
			return &cmd, false, fmt.Sprintf("failed to decode signature: %v", err)
		}

		// Create canonical payload for verification
		payload, err := createSigningPayload(&cmd)
		if err != nil {
			return &cmd, false, fmt.Sprintf("failed to create signing payload: %v", err)
		}

		// Verify signature
		if !ed25519.Verify(publicKey, payload, signature) {
			log.Warn().
				Str("command_id", cmd.CommandID).
				Str("command", cmd.Command).
				Str("issued_by", cmd.IssuedBy).
				Msg("SECURITY: Invalid control command signature")
			return &cmd, false, "invalid control command signature"
		}
	}

	// 4. Check idempotency (prevent replay of same command)
	if allowed, reason := commandIdCache.CheckAndAdd(cmd.CommandID, issuedAt); !allowed {
		return &cmd, false, reason
	}

	log.Info().
		Str("command_id", cmd.CommandID).
		Str("command", cmd.Command).
		Str("target_type", cmd.Target.Type).
		Str("target_id", cmd.Target.ID).
		Str("issued_by", cmd.IssuedBy).
		Msg("Control command verified successfully")

	return &cmd, true, ""
}

// IsControlSubject checks if a NATS subject is a Control.* subject
func IsControlSubject(subject string) bool {
	return len(subject) >= 8 && subject[:8] == "Control."
}
