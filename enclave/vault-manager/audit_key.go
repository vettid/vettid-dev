package main

// Audit-key derivation + binding.
//
// The vault audit log (both surfaces — global SQLite events table and
// per-connection AuditLog rows) is tamper-evident: each entry includes
// a hash of itself + the prior entry, and is signed by a per-user
// audit key. Anyone with the user's identity public key can verify
// every chain from the binding signature down.
//
// Why derive a dedicated audit key instead of signing with identity?
// Identity-key use is intentionally gated by a per-event password
// prompt (vote.cast, connection.authenticate, critical-secret use) —
// that prompt is the user's only signal that something cryptographic
// just happened with their personal key. Wiring every audit row
// through that gate would either kill performance or force us to
// TTL-cache the identity key in vault memory (an attack surface we
// removed deliberately, see feedback-audit-log-mirroring.md).
//
// The audit key threads the needle: HKDF-derived from identity at
// PIN-unlock, held in vault memory for the session (wiped only when
// identity is wiped), used for all audit writes without prompting.
// The one-time `audit.binding` event the vault emits proves the
// audit key is bound to the identity key. Compromising the audit key
// lets an attacker forge *new* audit entries (caught by missing
// prev_hash continuity) but cannot recover the identity key or
// back-date history.

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"io"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/hkdf"
)

const (
	// HKDF info string. Version suffix lets us rotate the derivation
	// path in the future without forcing every audit row to be
	// re-signed — old chains stay verifiable against the old audit
	// pub key, new chains chain forward under a new derivation.
	auditKeyHKDFInfo = "vettid-audit-key-v1"

	// Binding signature domain. Identity key signs this string ||
	// audit_pub once per derivation so any third party can verify
	// the audit key is bound to the user.
	auditBindingDomain = "vettid-audit-binding-v1"
)

// deriveAuditKey runs HKDF-SHA256 over the identity private key to
// produce a 32-byte Ed25519 seed, then expands the seed into a full
// keypair. Pure function — same identity_priv always produces the
// same audit_priv, so chain verification across sessions Just Works.
//
// The 32-byte HKDF output is used as the Ed25519 seed (NewKeyFromSeed),
// not as the raw 64-byte secret expansion — that's the Ed25519
// standard derivation path and the only one for which a public key
// can be derived deterministically.
func deriveAuditKey(identityPriv []byte) (priv ed25519.PrivateKey, pub ed25519.PublicKey, err error) {
	if len(identityPriv) == 0 {
		return nil, nil, ed25519Err("identity private key empty")
	}
	// HKDF: extract step uses no salt (we already have a high-entropy
	// IKM via the identity key); expand step uses the versioned info
	// string. 32 bytes out → Ed25519 seed.
	r := hkdf.New(sha256.New, identityPriv, nil, []byte(auditKeyHKDFInfo))
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(r, seed); err != nil {
		return nil, nil, err
	}
	priv = ed25519.NewKeyFromSeed(seed)
	pub = priv.Public().(ed25519.PublicKey)
	return priv, pub, nil
}

// computeAuditBindingSignature signs the canonical binding payload
// with the user's identity key. Used by the verifier on the client
// side to confirm audit_pub is bound to identity_pub — without it,
// an attacker who recovered audit_priv could publish forged entries
// under a forged audit_pub.
func computeAuditBindingSignature(identityPriv ed25519.PrivateKey, auditPub ed25519.PublicKey) []byte {
	msg := append([]byte(auditBindingDomain), auditPub...)
	return ed25519.Sign(identityPriv, msg)
}

// loadAuditKey runs HKDF derivation against the identity key currently
// loaded in vault state and caches the result. Returns the cached key
// if one is already present (idempotent across calls within a session).
// Caller must hold (or be the sole owner of) the vault-state lock or
// guarantee single-threaded access; the function locks internally.
func (mh *MessageHandler) loadAuditKey() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	if mh.vaultState == nil {
		return nil, nil, ed25519Err("vault state unavailable")
	}
	mh.vaultState.mu.Lock()
	defer mh.vaultState.mu.Unlock()
	if len(mh.vaultState.auditPrivateKey) > 0 && len(mh.vaultState.auditPublicKey) > 0 {
		// Return defensive copies — callers should not modify the cache.
		priv := append(ed25519.PrivateKey(nil), mh.vaultState.auditPrivateKey...)
		pub := append(ed25519.PublicKey(nil), mh.vaultState.auditPublicKey...)
		return priv, pub, nil
	}
	if len(mh.vaultState.identityPrivateKey) == 0 {
		return nil, nil, ed25519Err("identity key not loaded — PIN unlock required")
	}
	priv, pub, err := deriveAuditKey(mh.vaultState.identityPrivateKey)
	if err != nil {
		return nil, nil, err
	}
	mh.vaultState.auditPrivateKey = append([]byte(nil), priv...)
	mh.vaultState.auditPublicKey = append([]byte(nil), pub...)
	mh.vaultState.auditBindingSignature = computeAuditBindingSignature(
		ed25519.PrivateKey(mh.vaultState.identityPrivateKey),
		pub,
	)
	return priv, pub, nil
}

// clearAuditKey wipes the cached audit key. Called from PIN-lock
// alongside identity key wipe.
func (mh *MessageHandler) clearAuditKey() {
	if mh.vaultState == nil {
		return
	}
	mh.vaultState.mu.Lock()
	defer mh.vaultState.mu.Unlock()
	zeroBytes(mh.vaultState.auditPrivateKey)
	mh.vaultState.auditPrivateKey = nil
	zeroBytes(mh.vaultState.auditPublicKey)
	mh.vaultState.auditPublicKey = nil
	zeroBytes(mh.vaultState.auditBindingSignature)
	mh.vaultState.auditBindingSignature = nil
	mh.vaultState.auditBindingEmitted = false
}

// ensureBindingEmitted writes a single audit.binding event on the
// first audit-signing operation per session. The event carries the
// audit_pub and an identity-key signature over it so any consumer
// of the audit log can verify the chain back to the user's identity
// without trusting the vault. Idempotent.
func (mh *MessageHandler) ensureBindingEmitted(ctx context.Context) {
	if mh.vaultState == nil || mh.eventHandler == nil {
		return
	}
	mh.vaultState.mu.RLock()
	already := mh.vaultState.auditBindingEmitted
	auditPub := append([]byte(nil), mh.vaultState.auditPublicKey...)
	bindingSig := append([]byte(nil), mh.vaultState.auditBindingSignature...)
	mh.vaultState.mu.RUnlock()
	if already || len(auditPub) == 0 || len(bindingSig) == 0 {
		return
	}
	// Mark before write so a concurrent caller doesn't re-emit on
	// failure. If the LogEvent fails, the next verify attempt by the
	// client will return "binding not yet present" and we re-derive
	// on next unlock — better than a noisy retry loop.
	mh.vaultState.mu.Lock()
	mh.vaultState.auditBindingEmitted = true
	mh.vaultState.mu.Unlock()

	meta := map[string]string{
		"audit_pub":   base64.StdEncoding.EncodeToString(auditPub),
		"binding_sig": base64.StdEncoding.EncodeToString(bindingSig),
		"domain":      auditBindingDomain,
	}
	if err := mh.eventHandler.LogEvent(ctx, &Event{
		EventType:  EventTypeAuditBinding,
		SourceType: "system",
		Title:      "Audit key bound to identity",
		Metadata:   meta,
	}); err != nil {
		log.Warn().Err(err).Msg("audit binding event emit failed")
	}
}

// ed25519Err wraps a plain string error so callers get a sentinel
// type without pulling fmt into this file.
type auditKeyError string

func (e auditKeyError) Error() string { return string(e) }
func ed25519Err(s string) error       { return auditKeyError(s) }
