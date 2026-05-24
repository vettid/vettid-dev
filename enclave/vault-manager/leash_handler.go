package main

// leash_handler.go — issues LEASH tokens (scoped, time-bound delegation
// JWTs) for agent connections. See docs/LEASH-TOKEN-FORMAT.md for the
// wire format spec.
//
// Sprint 1 scope: lazy attestation-key generation + grant.attest op.
// Pubkey publishing (Sprint 2), revocation lookup (Sprint 2), and the
// validator service (Sprint 3) are separate workstreams that consume
// outputs from this file.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// LeashSchemaVersion is the value emitted in the `vettid:v` claim.
// Bump when the claim shape changes in a verifier-visible way.
const LeashSchemaVersion = 1

// leashAttestKeyStorageKey is where the per-user Ed25519 attestation
// key is persisted. Kept separate from any other vault key namespace
// so a rotation here has no cross-effects on internal signing.
const leashAttestKeyStorageKey = "leash/attest_key"

// leashGrantVersionStorageKey is the prefix for per-(user,agent)
// monotonic grant counters. The `vettid:grant_version` claim is what
// blocks rollback to an earlier, broader leash.
const leashGrantVersionStorageKeyPrefix = "leash/grant_versions/"

// leashIssuedRecordStorageKeyPrefix is the prefix for the per-jti
// issuance record. Used by Sprint 2's revocation lookup endpoint.
const leashIssuedRecordStorageKeyPrefix = "leash/issued/"

// defaultLeashDurationSecs caps unspecified duration requests. One hour
// is the longest "live demo" attention span and short enough that an
// agent compromise has bounded blast radius.
const defaultLeashDurationSecs int64 = 3600

// maxLeashDurationSecs ceils any requested duration. 24h matches the
// AgentSession ceiling; a leash should never outlive the session that
// authorized it.
const maxLeashDurationSecs int64 = 24 * 3600

// minScopeTokens is the minimum number of scope entries a request must
// carry. Zero scopes = unscoped = explicitly rejected per the spec
// "verifiers SHOULD reject" guidance — we reject at issuance too so a
// misconfigured agent never ends up holding an unscoped JWT.
const minScopeTokens = 1

// LeashAttestKey is the persisted form of the user's attestation
// keypair. Private half stays inside the vault; public half is what
// Sprint 2's Lambda will publish.
type LeashAttestKey struct {
	Kid       string `json:"kid"`        // "leash-attest-{user_guid}-v{generation}"
	Algorithm string `json:"alg"`        // always "EdDSA" in v1
	Private   []byte `json:"private"`    // 64-byte ed25519 private key
	Public    []byte `json:"public"`     // 32-byte ed25519 public key
	CreatedAt int64  `json:"created_at"` // unix seconds
	// RotatedAt is set on the *previous* generation when a new key is
	// generated. Currently unused (no rotation in Sprint 1) but reserved
	// so the schema doesn't change when rotation lands.
	RotatedAt int64 `json:"rotated_at,omitempty"`
}

// LeashIssuedRecord tracks one issued LEASH for revocation lookup.
// Sprint 1 writes these; Sprint 2's revocation Lambda reads them.
type LeashIssuedRecord struct {
	JTI          string   `json:"jti"`
	Subject      string   `json:"subject"`       // "agent:{conn_id}"
	ConnectionID string   `json:"connection_id"` // raw connection_id for backreferencing
	Scope        []string `json:"scope"`
	IssuedAt     int64    `json:"issued_at"`
	ExpiresAt    int64    `json:"expires_at"`
	Revoked      bool     `json:"revoked"`
	RevokedAt    int64    `json:"revoked_at,omitempty"`
	Reason       string   `json:"reason,omitempty"`
}

// GrantAttestRequest is the payload of a `leash.attest` op.
//
// Sprint 1 takes `agent_pubkey` from the caller (the agent CLI in
// Sprint 4 will generate its own Ed25519 keypair and supply the public
// half here). This keeps the leash handler independent of however
// agent pairing happens to handle keys today — and lets the demo
// validator-side tests run without standing up a full pairing flow.
type GrantAttestRequest struct {
	ConnectionID string   `json:"connection_id"`            // agent connection to delegate to
	AgentPubkey  string   `json:"agent_pubkey"`             // base64url Ed25519 pubkey, 32 bytes
	Scope        []string `json:"scope"`                    // scope tokens
	DurationSecs int64    `json:"duration_secs,omitempty"`  // default defaultLeashDurationSecs
}

// GrantAttestResponse is what the vault returns after issuing a LEASH.
type GrantAttestResponse struct {
	Leash      string `json:"leash"`       // compact JWT
	JTI        string `json:"jti"`
	Kid        string `json:"kid"`
	IssuedAt   int64  `json:"issued_at"`
	ExpiresAt  int64  `json:"expires_at"`
}

// RevokeRequest is the payload of a `leash.revoke` op.
type RevokeRequest struct {
	JTI    string `json:"jti"`              // jti of the leash to revoke
	Reason string `json:"reason,omitempty"` // optional human-readable reason
}

// RevokeResponse is what the vault returns after marking a LEASH revoked.
type RevokeResponse struct {
	JTI       string `json:"jti"`
	Revoked   bool   `json:"revoked"`
	RevokedAt int64  `json:"revoked_at"`
	Reason    string `json:"reason,omitempty"`
}

// LeashHandler owns the user's attestation key + issued-leash records.
type LeashHandler struct {
	ownerSpace  string
	storage     *EncryptedStorage
	vaultState  *VaultState
	sealerProxy *SealerProxy // bridge to parent for DDB publishes (nil in unit tests)

	// keyMu protects ensureAttestationKey's read/generate/write race.
	// Multiple concurrent grant.attest calls on a cold cache would
	// otherwise generate competing keys.
	keyMu sync.Mutex
}

// NewLeashHandler constructs a handler bound to one user's vault.
// sealerProxy is the bridge to the parent process for publishing the
// attest pubkey + issuance records to DynamoDB; pass nil in unit tests
// (publishes are skipped silently, all crypto + local storage still work).
func NewLeashHandler(ownerSpace string, storage *EncryptedStorage, vaultState *VaultState, sealerProxy *SealerProxy) *LeashHandler {
	return &LeashHandler{
		ownerSpace:  ownerSpace,
		storage:     storage,
		vaultState:  vaultState,
		sealerProxy: sealerProxy,
	}
}

// HandleGrantAttest issues a LEASH JWT for the requested agent + scope.
// Validates inputs, increments the (user, agent) grant version, persists
// the issuance record, signs the JWT, and returns it.
//
// This op MUST be phone-required at the device-handler tier — issuing
// a leash is "give my AI agent power on my behalf" and the user has to
// see it. Capability gating is at the device-handler layer; this handler
// trusts that the gate already approved.
func (h *LeashHandler) HandleGrantAttest(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req GrantAttestRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleGrantAttest"); err != nil {
		return h.errorResponse(msg.GetID(), "invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}
	if len(req.Scope) < minScopeTokens {
		return h.errorResponse(msg.GetID(), "at least one scope token is required")
	}
	for _, s := range req.Scope {
		if s == "" {
			return h.errorResponse(msg.GetID(), "empty scope token rejected")
		}
		if s == "*:*" {
			// The spec says verifiers SHOULD reject; reject at the mint
			// too so a misconfigured agent never holds an unscoped JWT.
			return h.errorResponse(msg.GetID(), "unscoped leash (*:*) refused at issuance")
		}
	}

	agentPubkey, err := base64.RawURLEncoding.DecodeString(req.AgentPubkey)
	if err != nil || len(agentPubkey) != ed25519.PublicKeySize {
		return h.errorResponse(msg.GetID(), "agent_pubkey must be base64url-encoded 32-byte Ed25519 key")
	}

	// Validate the connection exists and is an agent. Reading it here
	// also surfaces "connection revoked / never existed" before we mint
	// crypto that can't be used.
	connData, err := h.storage.Get("connections/" + req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "connection not found")
	}
	var conn ConnectionRecord
	if err := json.Unmarshal(connData, &conn); err != nil {
		return h.errorResponse(msg.GetID(), "connection record unreadable")
	}
	if !conn.IsAgent() {
		return h.errorResponse(msg.GetID(), "connection is not an agent")
	}
	if conn.Status == "revoked" || conn.Status == "expired" {
		return h.errorResponse(msg.GetID(), fmt.Sprintf("connection is %s", conn.Status))
	}

	// Clamp duration.
	durationSecs := req.DurationSecs
	if durationSecs <= 0 {
		durationSecs = defaultLeashDurationSecs
	}
	if durationSecs > maxLeashDurationSecs {
		durationSecs = maxLeashDurationSecs
	}

	// Lazy-load/generate the attestation key.
	attestKey, err := h.ensureAttestationKey()
	if err != nil {
		log.Error().Err(err).Str("owner_space", h.ownerSpace).Msg("Failed to ensure leash attestation key")
		return h.errorResponse(msg.GetID(), "attestation key unavailable")
	}

	// Increment the (user, agent) grant version. Stored under a
	// per-agent key so each agent has its own monotonic series; a new
	// leash to agent A doesn't affect the version space for agent B.
	grantVersion, err := h.nextGrantVersion(req.ConnectionID)
	if err != nil {
		log.Error().Err(err).Str("connection_id", req.ConnectionID).Msg("Failed to increment grant version")
		return h.errorResponse(msg.GetID(), "grant version unavailable")
	}

	// Profile version is informational in v1 — read what's current, use
	// it. If the read fails we substitute zero rather than failing the
	// whole mint.
	profileVersion := h.currentProfileVersion()

	now := time.Now()
	issuedAt := now.Unix()
	expiresAt := issuedAt + durationSecs
	jti := "leash-" + uuid.New().String()

	claims := buildLeashClaims(
		h.ownerSpace,
		req.ConnectionID,
		req.Scope,
		grantVersion,
		profileVersion,
		agentPubkey,
		jti,
		issuedAt,
		expiresAt,
	)

	token, err := signLeashJWT(attestKey, claims)
	if err != nil {
		log.Error().Err(err).Msg("Failed to sign LEASH JWT")
		return h.errorResponse(msg.GetID(), "leash signing failed")
	}

	// Persist the issuance record locally so revocation lookups via
	// the vault have something to read.
	issued := &LeashIssuedRecord{
		JTI:          jti,
		Subject:      "agent:" + req.ConnectionID,
		ConnectionID: req.ConnectionID,
		Scope:        req.Scope,
		IssuedAt:     issuedAt,
		ExpiresAt:    expiresAt,
		Revoked:      false,
	}
	issuedBytes, err := json.Marshal(issued)
	if err == nil {
		_ = h.storage.Put(leashIssuedRecordStorageKeyPrefix+jti, issuedBytes)
	}

	// Also mirror to the public LeashIssued DynamoDB table so the
	// revocation-status Lambda can answer. Failure to publish here
	// would leave a leash that verifiers will treat as 404 (i.e.
	// revoked) — fail the mint rather than ship a leash that won't
	// verify. Skip when sealerProxy is nil (unit-test path).
	if h.sealerProxy != nil {
		publicRow := map[string]interface{}{
			"jti":             jti,
			"subject":         "agent:" + req.ConnectionID,
			"scope":           req.Scope,
			"issued_at":       issuedAt,
			"expires_at":      expiresAt,
			"expires_at_ttl":  expiresAt,
			"revoked":         false,
			"iss":             "did:vettid:" + h.ownerSpace,
			"grant_version":   grantVersion,
			"profile_version": profileVersion,
		}
		pubBytes, perr := json.Marshal(publicRow)
		if perr != nil {
			log.Error().Err(perr).Str("jti", jti).Msg("marshal public leash issued row")
			return h.errorResponse(msg.GetID(), "leash publish encoding failed")
		}
		if perr := h.sealerProxy.PublishLeashIssued(pubBytes); perr != nil {
			log.Error().Err(perr).Str("jti", jti).Msg("publish leash issued to DDB")
			return h.errorResponse(msg.GetID(), "leash publish failed")
		}
	}

	log.Info().
		Str("owner_space", h.ownerSpace).
		Str("connection_id", req.ConnectionID).
		Str("jti", jti).
		Int("grant_version", grantVersion).
		Int64("duration_secs", durationSecs).
		Int("scope_count", len(req.Scope)).
		Msg("LEASH issued")

	resp := GrantAttestResponse{
		Leash:     token,
		JTI:       jti,
		Kid:       attestKey.Kid,
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
	}
	respBytes, _ := json.Marshal(resp)
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleRevoke marks a previously-issued LEASH as revoked. Authorization
// is implicit: the per-user issuance record only exists in the minting
// vault, so a caller can only revoke leashes they personally minted.
// The DDB row is re-published with `revoked=true` so public verifiers
// see the new state on their next status check.
//
// This op MUST be phone-required at the device-handler tier for the
// same reason HandleGrantAttest is — revoking is an owner-level decision
// about an outstanding delegation.
//
// Idempotent: revoking an already-revoked leash returns the existing
// record without writing again.
func (h *LeashHandler) HandleRevoke(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req RevokeRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleRevoke"); err != nil {
		return h.errorResponse(msg.GetID(), "invalid request format")
	}
	if req.JTI == "" {
		return h.errorResponse(msg.GetID(), "jti is required")
	}

	rec, ok, err := h.IssuedRecord(req.JTI)
	if err != nil {
		log.Error().Err(err).Str("jti", req.JTI).Msg("Failed to read leash issuance record")
		return h.errorResponse(msg.GetID(), "issuance record unreadable")
	}
	if !ok {
		return h.errorResponse(msg.GetID(), "jti not found in this vault")
	}

	if rec.Revoked {
		resp := RevokeResponse{JTI: rec.JTI, Revoked: true, RevokedAt: rec.RevokedAt, Reason: rec.Reason}
		respBytes, _ := json.Marshal(resp)
		return &OutgoingMessage{
			RequestID: msg.GetID(),
			Type:      MessageTypeResponse,
			Payload:   respBytes,
		}, nil
	}

	now := time.Now().Unix()
	rec.Revoked = true
	rec.RevokedAt = now
	rec.Reason = req.Reason

	recBytes, err := json.Marshal(rec)
	if err != nil {
		log.Error().Err(err).Str("jti", req.JTI).Msg("marshal revoked record")
		return h.errorResponse(msg.GetID(), "record encoding failed")
	}
	if err := h.storage.Put(leashIssuedRecordStorageKeyPrefix+req.JTI, recBytes); err != nil {
		log.Error().Err(err).Str("jti", req.JTI).Msg("persist revoked record")
		return h.errorResponse(msg.GetID(), "persist failed")
	}

	if h.sealerProxy != nil {
		publicRow := map[string]interface{}{
			"jti":            rec.JTI,
			"subject":        rec.Subject,
			"scope":          rec.Scope,
			"issued_at":      rec.IssuedAt,
			"expires_at":     rec.ExpiresAt,
			"expires_at_ttl": rec.ExpiresAt,
			"iss":            "did:vettid:" + h.ownerSpace,
			"revoked":        true,
			"revoked_at":     now,
		}
		if req.Reason != "" {
			publicRow["reason"] = req.Reason
		}
		pubBytes, perr := json.Marshal(publicRow)
		if perr != nil {
			log.Error().Err(perr).Str("jti", req.JTI).Msg("marshal public revoked leash row")
			return h.errorResponse(msg.GetID(), "leash revoke encoding failed")
		}
		if perr := h.sealerProxy.PublishLeashIssued(pubBytes); perr != nil {
			log.Error().Err(perr).Str("jti", req.JTI).Msg("publish revoked leash to DDB")
			return h.errorResponse(msg.GetID(), "leash revoke publish failed")
		}
	}

	log.Info().
		Str("owner_space", h.ownerSpace).
		Str("jti", req.JTI).
		Str("reason", req.Reason).
		Msg("LEASH revoked")

	resp := RevokeResponse{JTI: rec.JTI, Revoked: true, RevokedAt: now, Reason: req.Reason}
	respBytes, _ := json.Marshal(resp)
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// AttestationPublicKey returns the public half of the user's leash
// attestation key, generating it lazily if needed. Sprint 2's pubkey
// Lambda calls this through a new bridge to publish the key.
func (h *LeashHandler) AttestationPublicKey() (kid string, pubkey []byte, err error) {
	key, err := h.ensureAttestationKey()
	if err != nil {
		return "", nil, err
	}
	// Copy so callers can't mutate the cached slice.
	out := make([]byte, len(key.Public))
	copy(out, key.Public)
	return key.Kid, out, nil
}

// IssuedRecord fetches the issuance record for one jti. Sprint 2's
// revocation Lambda calls this to answer the public status endpoint.
// Returns nil + ErrNotFound-like behavior via a returned ok=false.
func (h *LeashHandler) IssuedRecord(jti string) (*LeashIssuedRecord, bool, error) {
	if jti == "" {
		return nil, false, fmt.Errorf("empty jti")
	}
	data, err := h.storage.Get(leashIssuedRecordStorageKeyPrefix + jti)
	if err != nil {
		// Storage Get returns an error for "not found" — Sprint 2 will
		// treat this case as 404 from the public endpoint.
		return nil, false, nil
	}
	var rec LeashIssuedRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, true, fmt.Errorf("issued record unreadable: %w", err)
	}
	return &rec, true, nil
}

// ensureAttestationKey loads the persisted key, or generates and stores
// a new one on first use. Thread-safe via keyMu.
func (h *LeashHandler) ensureAttestationKey() (*LeashAttestKey, error) {
	h.keyMu.Lock()
	defer h.keyMu.Unlock()

	if data, err := h.storage.Get(leashAttestKeyStorageKey); err == nil {
		var key LeashAttestKey
		if err := json.Unmarshal(data, &key); err == nil {
			if len(key.Private) == ed25519.PrivateKeySize && len(key.Public) == ed25519.PublicKeySize {
				return &key, nil
			}
			log.Warn().Str("owner_space", h.ownerSpace).Msg("Persisted leash attest key is malformed — regenerating")
		} else {
			log.Warn().Err(err).Str("owner_space", h.ownerSpace).Msg("Persisted leash attest key unreadable — regenerating")
		}
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ed25519 key generation: %w", err)
	}
	key := &LeashAttestKey{
		Kid:       fmt.Sprintf("leash-attest-%s-v1", h.ownerSpace),
		Algorithm: "EdDSA",
		Private:   []byte(priv),
		Public:    []byte(pub),
		CreatedAt: time.Now().Unix(),
	}
	out, err := json.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("marshal leash attest key: %w", err)
	}
	if err := h.storage.Put(leashAttestKeyStorageKey, out); err != nil {
		return nil, fmt.Errorf("persist leash attest key: %w", err)
	}

	// Publish the public half to DynamoDB so external verifiers can
	// fetch it. Failure here means the vault has a usable key but the
	// public verifier can't resolve it — surface as a hard error so
	// the caller can retry or fall back. (Without this, leashes would
	// be unverifiable until next mint attempt — confusing for testers.)
	if h.sealerProxy != nil {
		pubPayload := map[string]interface{}{
			"user_guid":  h.ownerSpace,
			"kid":        key.Kid,
			"alg":        key.Algorithm,
			"pubkey":     base64.RawURLEncoding.EncodeToString(key.Public),
			"created_at": key.CreatedAt,
		}
		pubBytes, err := json.Marshal(pubPayload)
		if err != nil {
			return nil, fmt.Errorf("marshal leash attest key publish payload: %w", err)
		}
		if err := h.sealerProxy.PublishLeashAttestKey(pubBytes); err != nil {
			return nil, fmt.Errorf("publish leash attest key: %w", err)
		}
	}

	log.Info().
		Str("owner_space", h.ownerSpace).
		Str("kid", key.Kid).
		Msg("Generated LEASH attestation key")
	return key, nil
}

// nextGrantVersion increments the per-(user, agent) monotonic counter
// and returns the new value. Sprint 1 doesn't enforce uniqueness across
// concurrent mints — read-modify-write is intended to be serialized by
// the message handler's procMu.
func (h *LeashHandler) nextGrantVersion(connectionID string) (int, error) {
	key := leashGrantVersionStorageKeyPrefix + connectionID
	current := 0
	if data, err := h.storage.Get(key); err == nil {
		var v struct {
			Version int `json:"version"`
		}
		if json.Unmarshal(data, &v) == nil {
			current = v.Version
		}
	}
	current++
	out, err := json.Marshal(struct {
		Version int `json:"version"`
	}{Version: current})
	if err != nil {
		return 0, err
	}
	if err := h.storage.Put(key, out); err != nil {
		return 0, err
	}
	return current, nil
}

// currentProfileVersion returns the user's published-profile version,
// or 0 on read failure. Informational in v1.
func (h *LeashHandler) currentProfileVersion() int {
	data, err := h.storage.Get("profile/_published")
	if err != nil {
		return 0
	}
	var p struct {
		Version int `json:"version"`
	}
	if json.Unmarshal(data, &p) != nil {
		return 0
	}
	return p.Version
}

func (h *LeashHandler) errorResponse(id string, message string) (*OutgoingMessage, error) {
	resp := map[string]interface{}{
		"success": false,
		"error":   message,
	}
	respBytes, _ := json.Marshal(resp)
	return &OutgoingMessage{
		RequestID: id,
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// ---------------------------------------------------------------------------
// JWT encoding (compact form, EdDSA only)
// ---------------------------------------------------------------------------
//
// We hand-roll the JWT encoder to eliminate the entire algorithm-
// confusion surface: there's no `alg` parameter to spoof, no parse path
// for `alg: none`, no possibility of a verifier-side library accidentally
// accepting an HS256 token signed with the EdDSA public key. The cost is
// ~30 lines.

// buildLeashClaims assembles the claims map per LEASH-TOKEN-FORMAT.md §Claims.
// Returns a map so JSON ordering is deterministic-via-sorted-keys when we
// marshal (encoding/json sorts map keys).
func buildLeashClaims(
	ownerSpace string,
	connectionID string,
	scope []string,
	grantVersion int,
	profileVersion int,
	agentPubkey []byte,
	jti string,
	issuedAt int64,
	expiresAt int64,
) map[string]interface{} {
	revocationURL := fmt.Sprintf("https://api.vettid.dev/v1/public/leash/status/%s", jti)
	return map[string]interface{}{
		"iss":                      "did:vettid:" + ownerSpace,
		"sub":                      "agent:" + connectionID,
		"iat":                      issuedAt,
		"nbf":                      issuedAt,
		"exp":                      expiresAt,
		"jti":                      jti,
		"vettid:v":                 LeashSchemaVersion,
		"vettid:scope":             scope,
		"vettid:grant_version":     grantVersion,
		"vettid:profile_version":   profileVersion,
		"vettid:agent_pubkey":      base64.RawURLEncoding.EncodeToString(agentPubkey),
		"vettid:revocation_url":    revocationURL,
		"vettid:audience":          nil,
	}
}

// signLeashJWT produces the compact-form JWT with the locked header
// shape (alg=EdDSA, typ=leash+jwt, kid=<key.Kid>) and an EdDSA sig.
func signLeashJWT(key *LeashAttestKey, claims map[string]interface{}) (string, error) {
	header := map[string]string{
		"alg": "EdDSA",
		"typ": "leash+jwt",
		"kid": key.Kid,
	}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}

	signingInput := base64.RawURLEncoding.EncodeToString(headerBytes) +
		"." +
		base64.RawURLEncoding.EncodeToString(claimsBytes)

	sig := ed25519.Sign(ed25519.PrivateKey(key.Private), []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
