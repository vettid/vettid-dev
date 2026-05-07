package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/curve25519"
)

// ConnectionsHandler handles connection credential management.
// This enables vault-to-vault communication.
type ConnectionsHandler struct {
	ownerSpace   string
	storage      *EncryptedStorage
	eventHandler *EventHandler
	natsProxy    *NATSProxy
	sealerProxy  *SealerProxy
	publisher    *VsockPublisher
	vaultState   *VaultState
	// Per-connection audit trail. Optional — when nil, audit
	// writes are skipped. Populated post-construction via
	// SetAuditLog so we don't have to touch every call site.
	auditLog     *AuditLog

	// Per-connection mutex map. Two paths can mutate the same
	// connection record concurrently — local respond from the app
	// and peer signals arriving on NATS — so the parallel-review
	// handshake serializes every read-modify-write through these
	// locks. Lazily populated; entries are intentionally never
	// removed (they're cheap and the connection lifetime is short).
	connMutexes sync.Map // map[string]*sync.Mutex (key = connection_id)
}

// NewConnectionsHandler creates a new connections handler
func NewConnectionsHandler(ownerSpace string, storage *EncryptedStorage, eventHandler *EventHandler, natsProxy *NATSProxy, publisher *VsockPublisher, vaultState *VaultState) *ConnectionsHandler {
	return &ConnectionsHandler{
		ownerSpace:   ownerSpace,
		storage:      storage,
		eventHandler: eventHandler,
		natsProxy:    natsProxy,
		publisher:    publisher,
		vaultState:   vaultState,
	}
}

// SetAuditLog plumbs the per-connection audit trail in after the
// MessageHandler has created its AuditLog. Allows audit writes for
// connection-lifecycle events (activated, revoked, rotated) so the
// per-connection history view shows them alongside messages and
// calls. Idempotent — safe to call again on reload.
func (h *ConnectionsHandler) SetAuditLog(auditLog *AuditLog) {
	h.auditLog = auditLog
}

// connectionLock returns the per-connection mutex, creating one on
// first use. Use this around every read-modify-write of a
// ConnectionRecord — see plans/parallel-review-handshake.md §10 risk
// #1 for the race we're guarding against.
func (h *ConnectionsHandler) connectionLock(connectionID string) *sync.Mutex {
	if m, ok := h.connMutexes.Load(connectionID); ok {
		return m.(*sync.Mutex)
	}
	m, _ := h.connMutexes.LoadOrStore(connectionID, &sync.Mutex{})
	return m.(*sync.Mutex)
}

// withConnectionRecord loads a record, runs `mutate` under the
// per-connection lock, and persists the result if mutate returned true.
// `mutate` returns (changed bool, err error). The helper is the only
// place ConnectionRecord writes should happen on the parallel-review
// path. Loads with no record return ErrKeyNotFound.
func (h *ConnectionsHandler) withConnectionRecord(connectionID string, mutate func(*ConnectionRecord) (bool, error)) (*ConnectionRecord, error) {
	lock := h.connectionLock(connectionID)
	lock.Lock()
	defer lock.Unlock()

	storageKey := "connections/" + connectionID
	data, err := h.storage.Get(storageKey)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, ErrKeyNotFound
	}
	var record ConnectionRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("decode connection record: %w", err)
	}

	changed, err := mutate(&record)
	if err != nil {
		return &record, err
	}
	if !changed {
		return &record, nil
	}

	newData, err := json.Marshal(&record)
	if err != nil {
		return &record, fmt.Errorf("encode connection record: %w", err)
	}
	if err := h.storage.Put(storageKey, newData); err != nil {
		return &record, fmt.Errorf("persist connection record: %w", err)
	}
	return &record, nil
}

// recordTerminal returns true when the record is in a final state and
// should reject further decision changes. Replay attacks of stale
// signals also bounce off this guard (plan §10 risk #2).
func recordTerminal(status string) bool {
	switch status {
	case ConnStatusActive, ConnStatusDeclinedByUs, ConnStatusDeclinedByPeer, ConnStatusExpired, ConnStatusRevoked:
		return true
	}
	return false
}

// applyDecision sets either LocalDecision or PeerDecision on the record
// while enforcing the no-flip rule (once a side commits, it stays
// committed). Returns true if the field actually changed.
func applyDecision(field *string, decision string) (bool, error) {
	if decision != DecisionAccept && decision != DecisionReject {
		return false, fmt.Errorf("invalid decision: %s", decision)
	}
	if *field == decision {
		return false, nil // idempotent
	}
	if *field != "" {
		// Decision already recorded as the opposite — refuse to flip.
		return false, fmt.Errorf("decision already recorded as %s, cannot change to %s", *field, decision)
	}
	*field = decision
	return true, nil
}

// computeStatus is the single source of truth for record.Status given
// the two decisions. Run after every applyDecision under the lock.
func computeStatus(record *ConnectionRecord) {
	if recordTerminal(record.Status) {
		return // already final, don't reverse
	}
	switch {
	case record.LocalDecision == DecisionReject:
		record.Status = ConnStatusDeclinedByUs
	case record.PeerDecision == DecisionReject:
		record.Status = ConnStatusDeclinedByPeer
	case record.LocalDecision == DecisionAccept && record.PeerDecision == DecisionAccept:
		record.Status = ConnStatusActive
	case record.LocalDecision == DecisionAccept:
		record.Status = ConnStatusOurAcceptPending
	case record.PeerDecision == DecisionAccept:
		record.Status = ConnStatusPeerAcceptPending
	default:
		// Neither side has decided. Leave as-is unless caller set it
		// explicitly (e.g. invited or peer_reviewing).
	}
}

// tryActivate is the convergence point. Called from both the local
// respond path AND the peer-signal arrival path. Atomic, idempotent,
// and emits connection.activated exactly once per record-lifetime
// thanks to the ActivatedAt guard.
//
// Returns the post-mutation record and a flag indicating whether the
// record was newly activated by this call.
func (h *ConnectionsHandler) tryActivate(ctx context.Context, connectionID string) (*ConnectionRecord, bool, error) {
	var newlyActivated bool
	record, err := h.withConnectionRecord(connectionID, func(r *ConnectionRecord) (bool, error) {
		// ActivatedAt is the canonical "we already emitted" guard.
		// computeStatus may have flipped Status to Active before
		// this call (which is fine — the work to do is just emit).
		if !r.ActivatedAt.IsZero() {
			return false, nil
		}
		if r.LocalDecision != DecisionAccept || r.PeerDecision != DecisionAccept {
			return false, nil // not ready
		}
		r.Status = ConnStatusActive
		r.ActivatedAt = time.Now().UTC()
		// Clear the invitation-window expiry — at this point the
		// invitation has fully resolved, the peer key is exchanged,
		// and the record is a long-lived connection. Leaving the
		// 10-minute invite expiry on it caused active connections
		// to look expired the next time the user logged in (the
		// list-side migration check flagged any active record past
		// ExpiresAt as expired).
		r.ExpiresAt = time.Time{}
		newlyActivated = true
		return true, nil
	})
	if err != nil {
		return nil, false, err
	}
	if newlyActivated && h.publisher != nil && record != nil {
		// 1) Notify the peer so they too can flip to active. The peer
		// runs its own tryActivate when this signal arrives — if it
		// converged at the same instant, that side already activated
		// and the signal is a no-op.
		if record.PeerOwnerSpace != "" {
			if !isValidOwnerSpace(record.PeerOwnerSpace) {
				log.Error().Str("peer_owner_space", record.PeerOwnerSpace).Msg("SECURITY: refusing to publish to malformed peer owner space")
			} else {
				signal := map[string]interface{}{
					"signal":        "peer-accepted",
					"connection_id": connectionID,
				}
				payload, _ := json.Marshal(signal)
				subject := fmt.Sprintf("MessageSpace.%s.forOwner.connection.signal", record.PeerOwnerSpace)
				if err := h.publisher.PublishRaw(subject, payload); err != nil {
					log.Warn().Err(err).Str("connection_id", connectionID).Msg("Failed to publish peer-accepted signal during activation")
				}
			}
		}
		// 2) Notify our own app.
		notif := map[string]interface{}{
			"type":          "connection.activated",
			"connection_id": connectionID,
			"peer_guid":     record.PeerGUID,
			"peer_alias":    record.PeerAlias,
		}
		notifBytes, _ := json.Marshal(notif)
		if err := h.publisher.PublishToApp(ctx, "connection.activated", notifBytes); err != nil {
			log.Warn().Err(err).Msg("Failed to publish connection.activated to app")
		}
		if h.eventHandler != nil {
			h.eventHandler.LogConnectionEvent(ctx, EventTypeConnectionCreated, connectionID, record.PeerGUID, "Connection established")
		}
		// Seed the per-connection share policy with the default
		// (published-profile fields allowed; everything else
		// default-deny). Idempotent — safe if both sides activate
		// on the same instant.
		SeedDefaultSharePolicy(h.storage, connectionID)
		// Per-connection audit trail entry so the connection-detail
		// history view has a "Connection established" row at the
		// origin of the timeline. The feed gets it via the event
		// above; that's a separate stream.
		if h.auditLog != nil {
			h.auditLog.Append(AuditEntry{
				ConnectionID: connectionID,
				PeerGUID:     record.PeerGUID,
				EventType:    AuditTypeConnectionAccepted,
				Direction:    AuditDirectionInternal,
				Title:        "Connection established",
				CreatedAt:    record.ActivatedAt.Unix(),
			})
		}
	}
	return record, newlyActivated, nil
}

// SetSealerProxy sets the sealer proxy for account seed loading
func (h *ConnectionsHandler) SetSealerProxy(sp *SealerProxy) {
	h.sealerProxy = sp
}

// CapabilitiesOrDefault returns the connection's capabilities, falling
// back to peer defaults for pre-feature records that have no stored
// capability block. The system connection always returns its read-only
// set regardless of what's persisted.
func (c *ConnectionRecord) CapabilitiesOrDefault() ConnectionCapabilities {
	if c.ConnectionType == ConnectionTypeSystem {
		return SystemCapabilities()
	}
	if c.Capabilities != nil {
		return *c.Capabilities
	}
	return DefaultPeerCapabilities()
}

// publishConnectionSignal sends a tiny routing-only signal to the peer's
// MessageSpace. Hard rule: NO PII rides on this subject — only the
// connection_id and (for response-ready) a review_nonce. See
// plans/parallel-review-handshake.md §3.2.
func (h *ConnectionsHandler) publishConnectionSignal(peerOwnerSpace, signalType, connectionID, reviewNonce string) error {
	if h.publisher == nil {
		return fmt.Errorf("publisher not available")
	}
	if peerOwnerSpace == "" {
		return fmt.Errorf("peer_owner_space is empty — cannot route signal")
	}
	body := map[string]interface{}{
		"signal":        signalType,
		"connection_id": connectionID,
		// peer_owner_space identifies WHO is sending so the receiver
		// can verify it matches the connection record's stored peer
		// owner space (defense against forged signals from anyone
		// who knows just the connection_id). See verifyPeerSignalOrigin.
		"peer_owner_space": h.ownerSpace,
	}
	if reviewNonce != "" {
		body["review_nonce"] = reviewNonce
	}
	if !isValidOwnerSpace(peerOwnerSpace) {
		return fmt.Errorf("invalid peer owner space")
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	subject := fmt.Sprintf("MessageSpace.%s.forOwner.connection.signal", peerOwnerSpace)
	return h.publisher.PublishRaw(subject, payload)
}

// publishConnectionSignalWithExtras is publishConnectionSignal but with
// caller-supplied additional fields. Used to inline the response-invite
// payload directly into the response-ready signal so the receiving
// vault skips the JetStream broker fetch (sealerProxy.ResolveResponseInvite)
// — that's the dominant cost in the parallel-review handshake on a cold
// JetStream consumer.
func (h *ConnectionsHandler) publishConnectionSignalWithExtras(
	peerOwnerSpace, signalType, connectionID, reviewNonce string,
	extras map[string]interface{},
) error {
	if h.publisher == nil {
		return fmt.Errorf("publisher not available")
	}
	body := map[string]interface{}{
		"signal":        signalType,
		"connection_id": connectionID,
		// See publishConnectionSignal — peer_owner_space is the
		// origin identity the receiver verifies against its stored
		// PeerOwnerSpace. extras must not clobber it.
		"peer_owner_space": h.ownerSpace,
	}
	if reviewNonce != "" {
		body["review_nonce"] = reviewNonce
	}
	for k, v := range extras {
		// Don't let extras clobber the routing fields.
		if k == "signal" || k == "connection_id" || k == "review_nonce" || k == "peer_owner_space" {
			continue
		}
		body[k] = v
	}
	if !isValidOwnerSpace(peerOwnerSpace) {
		return fmt.Errorf("invalid peer owner space")
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	subject := fmt.Sprintf("MessageSpace.%s.forOwner.connection.signal", peerOwnerSpace)
	return h.publisher.PublishRaw(subject, payload)
}

// publishResponseInvite writes B's response invite into the broker
// keyed by A's connection_id. Subject: `invite.response.<conn_id>`.
// Overwrites on each call (re-resolves replace prior content).
func (h *ConnectionsHandler) publishResponseInvite(connectionID string, payload map[string]interface{}) error {
	if h.publisher == nil {
		return fmt.Errorf("publisher not available")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	subject := fmt.Sprintf("invite.response.%s", connectionID)
	return h.publisher.PublishRaw(subject, body)
}

// generateReviewNonce returns a hex-encoded 16-byte nonce used to
// de-dup peer-side review notifications when the scanner re-resolves
// the same code.
func generateReviewNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fall back to time-based if crypto/rand fails (extremely unlikely)
		return fmt.Sprintf("ts-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// EnsureSystemConnection creates the per-vault VettID system connection
// on first call and is a noop afterwards. Idempotent — safe to run on
// every vault init. The system connection is read-only: it has no
// peer_guid, no keys, no message-space topic, and
// CapabilitiesOrDefault() reports read-only messaging only.
//
// Also sweeps the orphan record under the legacy "system/vettid" key
// (which broke app-side nav routing) if present — one-shot migration.
func (h *ConnectionsHandler) EnsureSystemConnection(ctx context.Context) error {
	h.cleanupLegacySystemConnection()

	key := "connections/" + SystemConnectionID
	if data, err := h.storage.Get(key); err == nil && len(data) > 0 {
		return nil // already provisioned
	}

	caps := SystemCapabilities()
	record := ConnectionRecord{
		ConnectionID:   SystemConnectionID,
		ConnectionType: ConnectionTypeSystem,
		PeerAlias:      "VettID",
		Status:         "active",
		CreatedAt:      time.Now(),
		Capabilities:   &caps,
	}
	data, err := json.Marshal(&record)
	if err != nil {
		return fmt.Errorf("marshal system connection: %w", err)
	}
	if err := h.storage.Put(key, data); err != nil {
		return fmt.Errorf("store system connection: %w", err)
	}
	h.addToConnectionIndex(SystemConnectionID)
	log.Info().Str("owner_space", h.ownerSpace).Msg("VettID system connection provisioned")
	return nil
}

// cleanupLegacySystemConnection removes the orphaned record and index
// entry produced by the v3 enclave, which used a "/" in the ID. Runs
// every time EnsureSystemConnection is called; cheap no-op on vaults
// that never had the old ID.
func (h *ConnectionsHandler) cleanupLegacySystemConnection() {
	legacyKey := "connections/" + legacySystemConnectionID
	if _, err := h.storage.Get(legacyKey); err == nil {
		if err := h.storage.Delete(legacyKey); err != nil {
			log.Warn().Err(err).Msg("failed to delete legacy system connection record")
		} else {
			log.Info().Msg("removed legacy system connection record (system/vettid)")
		}
	}
	// Strip the legacy id from the connection index if present.
	indexData, err := h.storage.Get("connections/_index")
	if err != nil {
		return
	}
	var ids []string
	if json.Unmarshal(indexData, &ids) != nil {
		return
	}
	filtered := make([]string, 0, len(ids))
	changed := false
	for _, id := range ids {
		if id == legacySystemConnectionID {
			changed = true
			continue
		}
		filtered = append(filtered, id)
	}
	if !changed {
		return
	}
	if newIndexData, err := json.Marshal(filtered); err == nil {
		_ = h.storage.Put("connections/_index", newIndexData)
	}
}

// --- Storage types ---

// Connection type constants
const (
	ConnectionTypePeer   = "peer"   // Human-to-human connection (default)
	ConnectionTypeAgent  = "agent"  // AI agent connection via Agent Connector
	ConnectionTypeDevice = "device" // Desktop device connection via session
	ConnectionTypeSystem = "system" // VettID service itself (single per vault, capped capabilities)
)

// SystemConnectionID is the reserved connection_id for the per-vault
// VettID system connection. All service-originated events (guides,
// migration prompts, vote notifications, security alerts) append to
// its audit trail.
//
// Must be a single path segment (no "/") — it travels through app-side
// nav routes like connections/{connectionId} and Android's NavController
// treats "/" as a path boundary.
const SystemConnectionID = "system-vettid"

// legacySystemConnectionID is the first-shipped ID for the system
// connection; it contained a "/" which broke nav routing. Vaults
// provisioned under PCR0 v3 have an orphan record at this key —
// EnsureSystemConnection cleans it up on next call.
const legacySystemConnectionID = "system/vettid"

// ConnectionCapabilities declares which user-visible features a
// connection supports. Peer connections default to all true; agents
// get a configured subset; the VettID system connection is read-only.
type ConnectionCapabilities struct {
	MessagingRead  bool `json:"messaging_read"`
	MessagingWrite bool `json:"messaging_write"`
	VoiceCall      bool `json:"voice_call"`
	VideoCall      bool `json:"video_call"`
	BTCTransfer    bool `json:"btc_transfer"`
}

// DefaultPeerCapabilities returns the capability set a freshly-created
// peer connection starts with — everything on.
func DefaultPeerCapabilities() ConnectionCapabilities {
	return ConnectionCapabilities{
		MessagingRead:  true,
		MessagingWrite: true,
		VoiceCall:      true,
		VideoCall:      true,
		BTCTransfer:    true,
	}
}

// SystemCapabilities returns the read-only capability set for the
// VettID system connection.
func SystemCapabilities() ConnectionCapabilities {
	return ConnectionCapabilities{MessagingRead: true}
}

// ConnectionRecord represents a stored connection
// Connection statuses for the parallel-review handshake.
//
//	invited            — A created the connection invite, no response yet.
//	peer_reviewing     — both sides are reviewing each other's profiles.
//	our_accept_pending — our side accepted, waiting on the peer.
//	peer_accept_pending — peer accepted, our side still reviewing.
//	active             — both sides accepted; connection live.
//	declined_by_us     — terminal: this vault declined.
//	declined_by_peer   — terminal: the peer declined.
//	expired            — terminal: invitation TTL elapsed before both accepted.
//	revoked            — terminal: a previously-active connection was revoked.
const (
	ConnStatusInvited            = "invited"
	ConnStatusPeerReviewing      = "peer_reviewing"
	ConnStatusOurAcceptPending   = "our_accept_pending"
	ConnStatusPeerAcceptPending  = "peer_accept_pending"
	ConnStatusActive             = "active"
	ConnStatusDeclinedByUs       = "declined_by_us"
	ConnStatusDeclinedByPeer     = "declined_by_peer"
	ConnStatusExpired            = "expired"
	ConnStatusRevoked            = "revoked"
)

// Decision values for ConnectionRecord.LocalDecision / PeerDecision.
const (
	DecisionAccept = "accept"
	DecisionReject = "reject"
)

type ConnectionRecord struct {
	ConnectionID      string    `json:"connection_id"`
	ConnectionType    string    `json:"connection_type,omitempty"` // "peer" (default) or "agent"
	PeerAlias         string    `json:"peer_alias"`
	PeerGUID          string    `json:"peer_guid,omitempty"`
	CredentialsType   string    `json:"credentials_type"` // "outbound" or "inbound"
	Credentials       string    `json:"credentials,omitempty"`
	MessageSpaceTopic string    `json:"message_space_topic"`
	Status            string    `json:"status"` // see ConnStatus* constants
	CreatedAt         time.Time `json:"created_at"`
	ExpiresAt         time.Time `json:"expires_at,omitempty"`
	// InviteCode is the 8-char code published to the INVITATIONS
	// broker stream as the subject suffix `invite.<code>`. Persisted
	// here so RepublishOutstandingInvites can rebuild the broker
	// payload on profile changes (otherwise the scanner sees a stale
	// catalog snapshot from create-invite time).
	InviteCode        string    `json:"invite_code,omitempty"`

	// Parallel-review handshake (plans/parallel-review-handshake.md):
	// each vault tracks BOTH local and peer decisions independently.
	// Convergence to "active" is gated on both being "accept" via
	// the idempotent tryActivate() helper. ActivatedAt fires the
	// app-side connection.activated event exactly once per record.
	LocalDecision string    `json:"local_decision,omitempty"` // "" | accept | reject
	PeerDecision  string    `json:"peer_decision,omitempty"`  // "" | accept | reject
	ReviewNonce   string    `json:"review_nonce,omitempty"`   // last accepted from peer; de-dup
	ActivatedAt   time.Time `json:"activated_at,omitempty"`   // zero == not yet emitted

	// Presence: per-connection override of the user-wide
	// presence_share_default. nil = follow default, true/false = explicit.
	// See plans/luminous-unifying-manatee.md §15.
	PresenceShareOverride *bool `json:"presence_share_override,omitempty"`
	LastRotatedAt     time.Time `json:"last_rotated_at,omitempty"`
	KeyExchangeAt     time.Time `json:"key_exchange_at,omitempty"`
	KeyRotationCount  int       `json:"key_rotation_count"`
	// Peer routing (for sending notifications back)
	PeerOwnerSpace   string `json:"peer_owner_space,omitempty"`
	PeerMessageSpace string `json:"peer_message_space,omitempty"`

	// E2E encryption fields
	LocalPublicKey  []byte `json:"local_public_key,omitempty"`
	LocalPrivateKey []byte `json:"local_private_key,omitempty"`
	PeerPublicKey   []byte `json:"peer_public_key,omitempty"`
	SharedSecret    []byte `json:"shared_secret,omitempty"`

	// Activity tracking
	LastActiveAt  *time.Time `json:"last_active_at,omitempty"`
	ActivityCount int        `json:"activity_count"`

	// Organization features
	Tags       []string `json:"tags,omitempty"`
	IsFavorite bool     `json:"is_favorite"`
	IsArchived bool     `json:"is_archived"`

	// Credential tracking
	CredentialsExpireAt *time.Time `json:"credentials_expire_at,omitempty"`

	// Peer profile sync
	PeerProfileVersion int `json:"peer_profile_version"`

	// Peer verifications and capabilities
	PeerVerifications []string          `json:"peer_verifications,omitempty"`
	PeerCapabilities  map[string]string `json:"peer_capabilities,omitempty"`

	// Capabilities declares which user-visible features this connection
	// supports from the owner's side. Zero value (all false) means the
	// record predates this field and should be treated as a standard
	// peer with every capability available — see
	// ConnectionRecord.CapabilitiesOrDefault().
	Capabilities *ConnectionCapabilities `json:"capabilities,omitempty"`

	// Agent-specific fields (only set when ConnectionType == "agent")
	AgentMetadata *AgentMetadata      `json:"agent_metadata,omitempty"`
	Contract      *ConnectionContract `json:"contract,omitempty"`

	// Device-specific fields (only set when ConnectionType == "device")
	DeviceMetadata    *DeviceMetadata    `json:"device_metadata,omitempty"`
	DeviceSession     *DeviceSession     `json:"device_session,omitempty"`
	DevicePendingAuth *DevicePendingAuth `json:"device_pending_auth,omitempty"`
}

// DeviceMetadata holds registration details for a desktop device connection.
// Collected by the desktop client during stage-2 pairing and shown to the
// user before they approve. See vettid-dev/docs/DESKTOP-CONNECTION-FLOW.md.
type DeviceMetadata struct {
	DeviceName         string `json:"device_name,omitempty"`         // User-assigned label, set at authorize time
	Hostname           string `json:"hostname,omitempty"`
	Platform           string `json:"platform,omitempty"`            // linux-x86_64, darwin-arm64, windows-x86_64, ...
	OSName             string `json:"os_name,omitempty"`             // Fedora, macOS, Windows, ...
	OSVersion          string `json:"os_version,omitempty"`          // 43, 14.4, 11, ...
	AppVersion         string `json:"app_version,omitempty"`
	BinaryFingerprint  string `json:"binary_fingerprint,omitempty"`  // SHA-256 of desktop binary (full)
	MachineFingerprint string `json:"machine_fingerprint,omitempty"` // HMAC-SHA256 over stable machine attrs
	ClientIP           string `json:"client_ip,omitempty"`           // IP observed by vault at pairing time
	FirstSeenAt        int64  `json:"first_seen_at,omitempty"`       // unix seconds
}

// DevicePendingAuth tracks a stage-2 pairing request awaiting user approval.
// Created when the desktop publishes device.request-session and cleared when
// the app publishes device.authorize-session. See DESKTOP-CONNECTION-FLOW.md.
type DevicePendingAuth struct {
	ApprovalToken  string `json:"approval_token"`   // hex, 32 bytes — set by desktop, verified by app via QR
	DevicePubKey   []byte `json:"device_pubkey"`    // desktop's stage-2 ephemeral X25519 pubkey (32 bytes)
	RequestedAt    int64  `json:"requested_at"`     // unix seconds
	ExpiresAt      int64  `json:"expires_at"`       // unix seconds — stage-2 window (e.g. 10 min)
}

// DeviceSession tracks the time-limited session for an authorized device.
// The session_key is never stored — it's derived fresh from the (vault ephemeral,
// device ephemeral) X25519 shared secret, with both sides doing HKDF over
// "vettid-device-session-v1" + session_id. On expiry, both sides wipe the key.
type DeviceSession struct {
	SessionID        string `json:"session_id"`          // uuid
	Status           string `json:"status"`              // "active" | "expired" | "revoked"
	CreatedAt        int64  `json:"created_at"`          // unix seconds
	ExpiresAt        int64  `json:"expires_at"`          // unix seconds — authored duration from CreatedAt
	LastActiveAt     int64  `json:"last_active_at"`      // unix seconds
	DurationSeconds  int64  `json:"duration_seconds"`    // user-approved duration (≤ 24h)
	KeyRotationCount int    `json:"key_rotation_count"`  // incremented on each extend
	SessionKeyID     string `json:"session_key_id"`      // opaque handle so the vault can match the device's current key
}

// AgentMetadata holds registration details for an AI agent connection.
// Collected by the Agent Connector during registration and sent to the vault.
type AgentMetadata struct {
	AgentType          string `json:"agent_type"`           // coding_assistant, data_pipeline, etc.
	BinaryFingerprint  string `json:"binary_fingerprint"`   // SHA-256 of connector binary
	MachineFingerprint string `json:"machine_fingerprint"`  // HMAC-SHA256 of machine attributes
	IPAddress          string `json:"ip_address"`
	Hostname           string `json:"hostname"`
	Platform           string `json:"platform"`             // linux/amd64, darwin/arm64, etc.
}

// ConnectionContract defines the permissions and limits for an agent connection.
// Set by the vault owner when approving an agent connection request.
type ConnectionContract struct {
	AgentName    string    `json:"agent_name"`              // Owner-defined name for this agent
	Scope        []string  `json:"scope"`                   // api_keys, ssh_keys, etc.
	ApprovalMode string    `json:"approval_mode"`           // always_ask, auto_within_contract, auto_all
	RateLimit    RateLimit `json:"rate_limit"`
}

// RateLimit defines request frequency limits for an agent connection.
type RateLimit struct {
	Max int    `json:"max"` // e.g. 60
	Per string `json:"per"` // "hour", "minute"
}

// GetConnectionType returns the effective connection type, defaulting to "peer"
// for connections created before the type field was added.
func (r *ConnectionRecord) GetConnectionType() string {
	if r.ConnectionType == "" {
		return ConnectionTypePeer
	}
	return r.ConnectionType
}

// IsAgent returns true if this is an agent connection.
func (r *ConnectionRecord) IsAgent() bool {
	return r.GetConnectionType() == ConnectionTypeAgent
}

// IsDevice returns true if this is a desktop device connection.
func (r *ConnectionRecord) IsDevice() bool {
	return r.GetConnectionType() == ConnectionTypeDevice
}

// --- Request/Response types ---

// CreateInviteRequest is the payload for connection.create-invite.
// Supports all connection types: peer, agent, and device.
type CreateInviteRequest struct {
	ConnectionID     string `json:"connection_id,omitempty"`
	PeerGUID         string `json:"peer_guid,omitempty"`
	Label            string `json:"label"`
	ConnectionType   string `json:"connection_type,omitempty"` // "peer" (default), "agent", or "device"
	ExpiresInHours   int    `json:"expires_in_hours"`
	ExpiresInMinutes int    `json:"expires_in_minutes"`
}

// CreateInviteResponse is the response for connection.create-invite
type CreateInviteResponse struct {
	ConnectionID      string            `json:"connection_id"`
	OwnerSpace        string            `json:"owner_space"`
	Credentials       string            `json:"credentials,omitempty"`
	InviteCode        string            `json:"invite_code,omitempty"`
	MessageSpaceTopic string            `json:"message_space_topic"`
	ExpiresAt         string            `json:"expires_at"`
	E2EPublicKey      string            `json:"e2e_public_key"`
	Label             string            `json:"label"`
	InviterProfile    map[string]string `json:"inviter_profile,omitempty"`
}

// StoreCredentialsRequest is the payload for connection.store-credentials.
// Used by all connection types: peer, agent, and device.
type StoreCredentialsRequest struct {
	ConnectionID       string                 `json:"connection_id"`
	PeerAlias          string                 `json:"peer_alias"`
	Label              string                 `json:"label"`
	PeerGUID           string                 `json:"peer_guid"`
	Credentials        string                 `json:"credentials"`
	NATSCredentials    string                 `json:"nats_credentials"`
	MessageSpaceTopic  string                 `json:"message_space_topic"`
	PeerMessageSpaceID string                 `json:"peer_message_space_id"`
	PeerOwnerSpaceID   string                 `json:"peer_owner_space_id"`
	PeerE2EPublicKey   string                 `json:"peer_e2e_public_key"`
	E2EPublicKey       string                 `json:"e2e_public_key"`          // Hex-encoded X25519 public key (used by agent/device)
	ConnectionType     string                 `json:"connection_type,omitempty"` // "peer" (default), "agent", or "device"
	PeerProfile        map[string]interface{} `json:"peer_profile,omitempty"`

	// InviteCode is the 12-char invite code the caller received via
	// the out-of-band channel (QR / push / share-link). The vault
	// rejects this request unless the code matches an InviteCode
	// previously stamped on a local outbound connection record by
	// HandleCreateInvite. Without this binding, anyone who can
	// publish to forOwner.connection.store-credentials could forge
	// a Status="active" record (audit finding A3).
	InviteCode string `json:"invite_code,omitempty"`
}

// StoreCredentialsResponse is the response for connection.store-credentials
type StoreCredentialsResponse struct {
	Success      bool   `json:"success"`
	ConnectionID string `json:"connection_id"`
	E2EPublicKey string `json:"e2e_public_key"`
}

// InitiateConnectionRequest is the payload for connection.initiate
// Used when User B (invitee) initiates connection with User A (inviter)
type InitiateConnectionRequest struct {
	InvitationID         string            `json:"invitation_id"`
	RequesterProfile     map[string]string `json:"requester_profile"`               // B's profile to share with A
	RequesterCapabilities map[string]string `json:"requester_capabilities,omitempty"` // B's capabilities
	RequesterNATSCreds   string            `json:"requester_nats_credentials"`       // Reciprocal creds for A
	RequesterE2EPublicKey string           `json:"requester_e2e_public_key"`
}

// InitiateConnectionResponse is the response for connection.initiate
type InitiateConnectionResponse struct {
	ConnectionID        string            `json:"connection_id"`
	InviterProfile      map[string]string `json:"inviter_profile"`       // A's profile
	InviterCapabilities map[string]string `json:"inviter_capabilities,omitempty"`
	InviterE2EPublicKey string            `json:"inviter_e2e_public_key"`
	PeerVerifications   []string          `json:"peer_verifications"`    // A's verification status
	Status              string            `json:"status"`                // "pending_their_review"
}

// RevokeConnectionRequest is the payload for connection.revoke
type RevokeConnectionRequest struct {
	ConnectionID string `json:"connection_id"`
}

// RespondConnectionRequest is the payload for connection.respond
// Used for bidirectional consent - both parties must accept
type RespondConnectionRequest struct {
	ConnectionID    string `json:"connection_id"`
	Response        string `json:"response"` // "accept" or "reject"
	RejectionReason string `json:"rejection_reason,omitempty"`
}

// RespondConnectionResponse is the response for connection.respond
type RespondConnectionResponse struct {
	Success      bool   `json:"success"`
	ConnectionID string `json:"connection_id"`
	Status       string `json:"status"` // New connection status after response
	Message      string `json:"message,omitempty"`
}

// ListConnectionsRequest is the payload for connection.list
type ListConnectionsRequest struct {
	ConnectionType string   `json:"connection_type,omitempty"` // "peer", "agent", or "" for all
	Status         string   `json:"status,omitempty"`
	Tags           []string `json:"tags,omitempty"`
	IsFavorite     *bool    `json:"is_favorite,omitempty"`
	IsArchived     *bool    `json:"is_archived,omitempty"`
	Search         string   `json:"search,omitempty"`
	SortBy         string   `json:"sort_by,omitempty"` // "recent_activity", "alphabetical", "created_at"
	SortOrder      string   `json:"sort_order,omitempty"` // "asc", "desc"
	Limit          int      `json:"limit,omitempty"`
	Offset         int      `json:"offset,omitempty"`
}

// ConnectionInfo represents connection info in list response
type ConnectionInfo struct {
	ConnectionID     string `json:"connection_id"`
	ConnectionType   string `json:"connection_type"` // "peer" or "agent"
	PeerAlias        string `json:"peer_alias"`
	PeerGUID         string `json:"peer_guid,omitempty"`
	Status           string `json:"status"`
	CreatedAt        string `json:"created_at"`
	LastRotatedAt    string `json:"last_rotated_at,omitempty"`
	CredentialsType  string `json:"credentials_type"`
	E2EReady         bool   `json:"e2e_ready"`
	KeyExchangeAt    string `json:"key_exchange_at,omitempty"`
	KeyRotationCount int    `json:"key_rotation_count,omitempty"`

	// Cached peer profile (loaded from vault storage)
	PeerProfile json.RawMessage `json:"peer_profile,omitempty"`

	// Enhanced fields
	LastActiveAt        string   `json:"last_active_at,omitempty"`
	ActivityCount       int      `json:"activity_count,omitempty"`
	Tags                []string `json:"tags,omitempty"`
	IsFavorite          bool     `json:"is_favorite,omitempty"`
	IsArchived          bool     `json:"is_archived,omitempty"`
	NeedsAttention      bool     `json:"needs_attention,omitempty"`
	CredentialsExpireAt string   `json:"credentials_expire_at,omitempty"`
	PeerProfileVersion  int      `json:"peer_profile_version,omitempty"`
	PeerVerifications   []string `json:"peer_verifications,omitempty"`

	// Message preview (for connection card display)
	LastMessagePreview   string `json:"last_message_preview,omitempty"`
	LastMessageAt        string `json:"last_message_at,omitempty"`
	LastMessageDirection string `json:"last_message_direction,omitempty"` // "incoming" | "outgoing"
	UnreadCount          int    `json:"unread_count"`

	// Last activity — merges messages and calls so the card icon can
	// reflect whatever the user did most recently, not just the last
	// message. The app picks a glyph from Type + Subtype + Direction +
	// Outcome. MissedCallCount is the number of unanswered incoming
	// calls in the record so the Voice action button can show a badge.
	LastActivityType      string `json:"last_activity_type,omitempty"`      // "message" | "call"
	LastActivityAt        string `json:"last_activity_at,omitempty"`        // RFC3339
	LastActivityDirection string `json:"last_activity_direction,omitempty"` // "incoming" | "outgoing"
	LastActivitySubtype   string `json:"last_activity_subtype,omitempty"`   // for calls: "voice" | "video"
	LastActivityOutcome   string `json:"last_activity_outcome,omitempty"`   // for calls: "completed" | "missed" | "rejected"
	MissedCallCount       int    `json:"missed_call_count,omitempty"`

	// Agent-specific fields (only present for agent connections)
	AgentMetadata *AgentMetadata      `json:"agent_metadata,omitempty"`
	Contract      *ConnectionContract `json:"contract,omitempty"`

	// Per-connection presence override. nil = follow user-wide
	// default; true/false = explicit override. Surfaced on the
	// connection-detail screen so the user can override their global
	// presence setting for a specific peer.
	PresenceShareOverride *bool `json:"presence_share_override,omitempty"`
}

// ListConnectionsResponse is the response for connection.list
type ListConnectionsResponse struct {
	Connections []ConnectionInfo `json:"connections"`
}

// GetConnectionRequest is the payload for connection.get
type GetConnectionRequest struct {
	ConnectionID string `json:"connection_id"`
}

// ConnectionUpdateRequest is the payload for connection.update
type ConnectionUpdateRequest struct {
	ConnectionID string   `json:"connection_id"`
	Tags         []string `json:"tags,omitempty"`
	IsFavorite   *bool    `json:"is_favorite,omitempty"`
	IsArchived   *bool    `json:"is_archived,omitempty"`
	PeerAlias    string   `json:"peer_alias,omitempty"`
}

// ConnectionUpdateResponse is the response for connection.update
type ConnectionUpdateResponse struct {
	Success      bool   `json:"success"`
	ConnectionID string `json:"connection_id"`
}

// GetCapabilitiesRequest is the payload for connection.get-capabilities
type GetCapabilitiesRequest struct {
	ConnectionID string `json:"connection_id"`
}

// GetCapabilitiesResponse is the response for connection.get-capabilities
type GetCapabilitiesResponse struct {
	ConnectionID string            `json:"connection_id"`
	Capabilities map[string]string `json:"capabilities"`
}

// ActivitySummaryRequest is the payload for connection.activity-summary
type ActivitySummaryRequest struct {
	ConnectionID string `json:"connection_id"`
}

// ActivitySummaryResponse is the response for connection.activity-summary
type ActivitySummaryResponse struct {
	ConnectionID     string `json:"connection_id"`
	TotalMessages    int    `json:"total_messages"`
	MessagesSent     int    `json:"messages_sent"`
	MessagesReceived int    `json:"messages_received"`
	TotalCalls       int    `json:"total_calls"`
	LastActivityAt   string `json:"last_activity_at,omitempty"`
	LastActivityType string `json:"last_activity_type,omitempty"`
}

// CreateAgentInviteRequest is the payload for connection.agent.create-invite
type CreateAgentInviteRequest struct {
	Label string `json:"label"` // Optional name for this agent slot
}

// CreateAgentInviteResponse returns data the app needs to call POST /vault/agent/shortlink
type CreateAgentInviteResponse struct {
	ConnectionID   string `json:"connection_id"`
	InvitationID   string `json:"invitation_id"`
	InviteToken    string `json:"invite_token"`     // 32 bytes, base64url
	OwnerGUID      string `json:"owner_guid"`
	VaultPublicKey string `json:"vault_public_key"` // Hex X25519 public key
	ExpiresAt      string `json:"expires_at"`
}

// CreateDeviceInviteRequest is the payload for device.create-invite.
// The user invokes this from the app when they want to pair a new desktop.
type CreateDeviceInviteRequest struct {
	Label string `json:"label,omitempty"` // Optional placeholder; final name is set at authorize time
}

// CreateDeviceInviteResponse returns the short code the user types into the
// desktop client. See vettid-dev/docs/DESKTOP-CONNECTION-FLOW.md §Stage 1.
type CreateDeviceInviteResponse struct {
	ConnectionID string `json:"connection_id"`
	InviteCode   string `json:"invite_code"`   // 8-char ambiguity-safe code
	NATSEndpoint string `json:"nats_endpoint"` // so the app can show it to the user if needed
	ExpiresAt    string `json:"expires_at"`    // ISO 8601 — 2 min from now
}

// --- Handler methods ---

// HandleCreateInvite handles connection.create-invite messages
func (h *ConnectionsHandler) HandleCreateInvite(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req CreateInviteRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleCreateInvite"); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	// Generate connection_id if not provided
	connectionID := req.ConnectionID
	if connectionID == "" {
		idBytes := make([]byte, 16)
		rand.Read(idBytes)
		connectionID = fmt.Sprintf("conn-%x", idBytes)
	}

	// Support expires_in_minutes (preferred) or expires_in_hours (legacy)
	var expiresAt time.Time
	if req.ExpiresInMinutes > 0 {
		expiresAt = time.Now().Add(time.Duration(req.ExpiresInMinutes) * time.Minute)
	} else if req.ExpiresInHours > 0 {
		expiresAt = time.Now().Add(time.Duration(req.ExpiresInHours) * time.Hour)
	} else {
		expiresAt = time.Now().Add(24 * 30 * time.Hour) // Default 30 days
	}

	// Generate X25519 key pair for E2E encryption
	localPrivate := make([]byte, 32)
	rand.Read(localPrivate)

	// Derive public key from private key using X25519 scalar multiplication
	localPublic, err := curve25519.X25519(localPrivate, curve25519.Basepoint)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to derive public key")
	}

	// Store the outbound connection record.
	//
	// Status starts as "pending": the peer hasn't resolved the
	// invitation yet, so no session exists to message/call over.
	// Previously this was "active" from the start, which made the
	// Android card render as a blank "Connected" entry (no peer
	// profile, but not marked pending either) and left the record
	// stuck forever when the peer never joined. HandleActivation
	// (line ~861) flips this to "active" when the peer accepts.
	// Parallel-review handshake: peer connections start at "invited"
	// (was "pending"). Status flips through peer_reviewing → *_pending
	// → active as the resolve + decisions land. Agent / device flows
	// keep their own status semantics; we only own peer here.
	initialStatus := "pending"
	if req.ConnectionType == "" || req.ConnectionType == "peer" {
		initialStatus = ConnStatusInvited
	}
	record := ConnectionRecord{
		ConnectionID:      connectionID,
		ConnectionType:    req.ConnectionType, // "peer", "agent", or "device" (empty defaults to peer)
		PeerAlias:         req.Label,
		PeerGUID:          req.PeerGUID,
		CredentialsType:   "outbound",
		MessageSpaceTopic: fmt.Sprintf("MessageSpace.%s.forOwner.>", h.ownerSpace),
		Status:            initialStatus,
		CreatedAt:         time.Now(),
		ExpiresAt:         expiresAt,
		LocalPublicKey:    localPublic,
		LocalPrivateKey:   localPrivate,
	}

	data, err := json.Marshal(record)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to marshal connection")
	}

	storageKey := "connections/" + connectionID
	if err := h.storage.Put(storageKey, data); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to store connection")
	}

	// Add to index
	h.addToConnectionIndex(connectionID)

	// Log connection created event for audit
	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(context.Background(), EventTypeConnectionCreated, connectionID, req.PeerGUID, "Connection invite created")
	}

	log.Info().Str("connection_id", connectionID).Msg("Connection invite created")

	// Generate scoped NATS credentials for the invitation
	// These allow the peer to connect and read this vault's published profile
	invitationCreds := ""
	if h.natsProxy != nil {
		creds, err := h.generateInvitationCredentials(expiresAt)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to generate invitation NATS credentials (non-fatal)")
		} else {
			invitationCreds = creds
		}
	}

	// Load inviter's profile for the response
	inviterProfile := h.loadInviterProfile()

	// Always use profile name when available, overriding generic/GUID-based labels
	if firstName, ok := inviterProfile["_system_first_name"]; ok && firstName != "" {
		profileLabel := firstName
		if lastName, ok := inviterProfile["_system_last_name"]; ok && lastName != "" {
			profileLabel += " " + lastName
		}
		profileLabel = strings.TrimSpace(profileLabel)
		if profileLabel != "" {
			req.Label = profileLabel
		}
	}

	// Publish invitation to NATS broker stream so QR code only needs a short code.
	// The scanner fetches the full invitation data from the stream using guest credentials.
	inviteCode := ""
	if h.publisher != nil && invitationCreds != "" {
		inviteCode = generateInviteCode()

		// Extract JWT and seed from .creds format for compact storage
		jwt, seed := extractCredsComponents(invitationCreds)

		// Include inviter's published profile so scanner sees it immediately
		inviterProfile := h.loadPublishedProfileForPeer()

		brokerPayload := map[string]interface{}{
			"type":            "vettid_connection",
			"kind":            "connection", // see plans/parallel-review-handshake.md §3.1
			"connection_id":   connectionID,
			"jwt":             jwt,
			"seed":            seed,
			"owner_space":     h.ownerSpace,
			"message_space":   record.MessageSpaceTopic,
			"expires_at":      expiresAt.Format(time.RFC3339),
			"label":           req.Label,
			"inviter_profile": inviterProfile,
			// E2E pubkey rides in the broker payload (capability-gated
			// by the invite code) so B can derive the shared secret at
			// resolve-time before any review screen renders. The
			// existing JWT/seed already grant the holder reach to A's
			// MessageSpace, so embedding A's pubkey here is no weaker.
			"e2e_public_key": fmt.Sprintf("%x", localPublic),
		}
		payloadBytes, _ := json.Marshal(brokerPayload)

		subject := fmt.Sprintf("invite.%s", inviteCode)
		if err := h.publisher.PublishRaw(subject, payloadBytes); err != nil {
			log.Warn().Err(err).Str("subject", subject).Msg("Failed to publish invitation to broker (falling back to inline creds)")
			inviteCode = "" // Fall back to inline credentials
		} else {
			log.Info().Str("invite_code", inviteCode).Str("connection_id", connectionID).Msg("Invitation published to broker stream")
			// Persist code + creds on the connection record so
			// RepublishOutstandingInvites can rebuild the broker
			// payload after later metadata mutations. Best-effort.
			record.Credentials = invitationCreds
			record.InviteCode = inviteCode
			if updated, err := json.Marshal(record); err == nil {
				_ = h.storage.Put(storageKey, updated)
			}
		}
	}

	resp := CreateInviteResponse{
		ConnectionID:      connectionID,
		OwnerSpace:        h.ownerSpace,
		Credentials:       invitationCreds,
		InviteCode:        inviteCode,
		MessageSpaceTopic: record.MessageSpaceTopic,
		ExpiresAt:         expiresAt.Format(time.RFC3339),
		E2EPublicKey:      fmt.Sprintf("%x", localPublic),
		Label:             req.Label,
		InviterProfile:    inviterProfile,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleResolveInvite handles connection.resolve-invite messages.
//
// In the parallel-review handshake (plans/parallel-review-handshake.md)
// this handler does the heavy lifting on B's side:
//   1. Fetch A's connection invite from the broker.
//   2. Generate B's X25519 keypair, derive the shared secret with A's pubkey.
//   3. Persist B's inbound connection record at status `peer_reviewing`.
//   4. Publish B's response invite (`invite.response.<conn_id>`) carrying
//      B's profile + pubkey + message_space.
//   5. Push a tiny `signal=response-ready` ping to A's MessageSpace
//      (no PII, just `{conn_id, review_nonce}`).
//   6. Return inviter profile + connection_id to B's app so the preview
//      screen renders without a second round-trip.
//
// Re-resolves of the same code are idempotent: existing local record is
// kept (and its keypair preserved), a fresh review_nonce is minted, the
// response invite is overwritten, the signal is re-pushed.
func (h *ConnectionsHandler) HandleResolveInvite(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		InviteCode string `json:"invite_code"`
	}
	if err := unmarshalRequest(msg.Payload, &req, "HandleResolveInvite"); err != nil || req.InviteCode == "" {
		return h.errorResponse(msg.GetID(), "invite_code is required")
	}

	if h.sealerProxy == nil {
		return h.errorResponse(msg.GetID(), "sealer proxy not available")
	}

	log.Info().Str("invite_code", req.InviteCode).Msg("Resolving invitation from broker")

	inviteData, err := h.sealerProxy.ResolveInvite(req.InviteCode)
	if err != nil {
		log.Warn().Err(err).Str("invite_code", req.InviteCode).Msg("Failed to resolve invitation")
		return h.errorResponse(msg.GetID(), fmt.Sprintf("invitation not found or expired: %v", err))
	}

	// Parse the broker payload to pull out the fields the parallel-review
	// flow needs. The shape is set by HandleCreateInvite on A's side.
	var brokerPayload struct {
		ConnectionID    string                 `json:"connection_id"`
		JWT             string                 `json:"jwt"`
		Seed            string                 `json:"seed"`
		OwnerSpace      string                 `json:"owner_space"`
		MessageSpace    string                 `json:"message_space"`
		ExpiresAt       string                 `json:"expires_at"`
		Label           string                 `json:"label"`
		InviterProfile  map[string]interface{} `json:"inviter_profile"`
		E2EPublicKey    string                 `json:"e2e_public_key"`
	}
	if err := json.Unmarshal(inviteData, &brokerPayload); err != nil {
		log.Warn().Err(err).Msg("Failed to parse broker invitation payload")
		return h.errorResponse(msg.GetID(), "invitation payload malformed")
	}
	if brokerPayload.ConnectionID == "" || brokerPayload.OwnerSpace == "" || brokerPayload.E2EPublicKey == "" {
		return h.errorResponse(msg.GetID(), "invitation payload missing required fields")
	}
	if brokerPayload.OwnerSpace == h.ownerSpace {
		return h.errorResponse(msg.GetID(), "cannot resolve your own invitation")
	}

	// SECURITY (authZ-H1): the broker stores invitation payloads under
	// the inviter's account, but anyone with broker write would be able
	// to forge a payload pointing at a different OwnerSpace. Verify
	// that the embedded JWT (a) is signature-valid, (b) names a user
	// whose seed we hold, and (c) carries publish/subscribe permissions
	// scoped to the OwnerSpace claimed in the payload. Any mismatch
	// means the payload was tampered with.
	if err := verifyBrokerInviteJWT(brokerPayload.JWT, brokerPayload.Seed, brokerPayload.OwnerSpace); err != nil {
		log.Warn().Err(err).Str("invite_code", req.InviteCode).Str("owner_space", brokerPayload.OwnerSpace).Msg("Broker invite JWT verification failed")
		return h.errorResponse(msg.GetID(), "invitation rejected: signature verification failed")
	}

	peerPubKey, err := decodeHexKey(brokerPayload.E2EPublicKey)
	if err != nil {
		return h.errorResponse(msg.GetID(), fmt.Sprintf("invalid inviter pubkey: %v", err))
	}
	expiresAt, _ := time.Parse(time.RFC3339, brokerPayload.ExpiresAt)

	// Look up an existing record (re-resolve case). On first resolve we
	// create the record from scratch with a fresh keypair.
	storageKey := "connections/" + brokerPayload.ConnectionID
	var record ConnectionRecord
	existing, _ := h.storage.Get(storageKey)
	if len(existing) > 0 {
		_ = json.Unmarshal(existing, &record)
		if recordTerminal(record.Status) {
			return h.errorResponse(msg.GetID(), "this connection is already terminal")
		}
	}

	// Generate B's keypair only if we don't already have one for this
	// connection_id (so re-resolves don't churn keys).
	if len(record.LocalPrivateKey) == 0 {
		localPrivate := make([]byte, 32)
		if _, err := rand.Read(localPrivate); err != nil {
			return h.errorResponse(msg.GetID(), "Failed to generate keys")
		}
		localPublic, err := curve25519.X25519(localPrivate, curve25519.Basepoint)
		if err != nil {
			return h.errorResponse(msg.GetID(), "Failed to derive public key")
		}
		record.LocalPrivateKey = localPrivate
		record.LocalPublicKey = localPublic
	}

	// Derive shared secret. Idempotent — same inputs → same output.
	sharedSecret, err := curve25519.X25519(record.LocalPrivateKey, peerPubKey)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to derive shared secret")
	}

	// Build a peer-alias from the inviter profile (first + last name).
	peerAlias := brokerPayload.Label
	if firstName, ok := brokerPayload.InviterProfile["_system_first_name"].(string); ok && firstName != "" {
		alias := firstName
		if lastName, ok := brokerPayload.InviterProfile["_system_last_name"].(string); ok && lastName != "" {
			alias += " " + lastName
		}
		peerAlias = strings.TrimSpace(alias)
	}

	// Fill / refresh the record. Preserve the original ConnectionID,
	// CreatedAt, and any decisions already recorded.
	record.ConnectionID = brokerPayload.ConnectionID
	record.ConnectionType = "peer"
	record.CredentialsType = "inbound"
	record.PeerOwnerSpace = brokerPayload.OwnerSpace
	record.PeerMessageSpace = brokerPayload.MessageSpace
	record.PeerGUID = brokerPayload.OwnerSpace
	record.PeerAlias = peerAlias
	record.PeerPublicKey = peerPubKey
	record.SharedSecret = sharedSecret
	record.KeyExchangeAt = time.Now()
	record.MessageSpaceTopic = fmt.Sprintf("MessageSpace.%s.forOwner.>", h.ownerSpace)
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now()
	}
	if !expiresAt.IsZero() {
		record.ExpiresAt = expiresAt
	}
	if record.Status == "" || record.Status == "pending" || record.Status == ConnStatusInvited {
		record.Status = ConnStatusPeerReviewing
	}
	record.ReviewNonce = generateReviewNonce()

	newData, err := json.Marshal(record)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to marshal connection record")
	}
	if err := h.storage.Put(storageKey, newData); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to store connection record")
	}
	h.addToConnectionIndex(brokerPayload.ConnectionID)

	// Publish B's response invite to the broker so A can pull B's
	// profile + pubkey on demand. Hard rule: profile + pubkey only
	// flow through the broker (capability-gated). The peer push that
	// follows is a tiny routing-only signal.
	myProfile := h.loadPublishedProfileForPeer()
	myAlias := ""
	if firstName, ok := myProfile["_system_first_name"].(string); ok && firstName != "" {
		myAlias = firstName
		if lastName, ok := myProfile["_system_last_name"].(string); ok && lastName != "" {
			myAlias += " " + lastName
		}
		myAlias = strings.TrimSpace(myAlias)
	}
	responsePayload := map[string]interface{}{
		"type":           "vettid_connection",
		"kind":           "response",
		"connection_id":  brokerPayload.ConnectionID,
		"owner_space":    h.ownerSpace,
		"message_space":  record.MessageSpaceTopic,
		"expires_at":     brokerPayload.ExpiresAt,
		"label":          myAlias,
		"profile":        myProfile,
		"e2e_public_key": fmt.Sprintf("%x", record.LocalPublicKey),
		"review_nonce":   record.ReviewNonce,
	}
	if err := h.publishResponseInvite(brokerPayload.ConnectionID, responsePayload); err != nil {
		log.Warn().Err(err).Str("connection_id", brokerPayload.ConnectionID).Msg("Failed to publish response invite (continuing)")
	}

	// Cache A's profile to the per-connection peer-profile key so B's
	// connection.list returns it. Without this, B's preview/detail
	// screens for this connection render blank.
	if profileBytes, marshalErr := json.Marshal(brokerPayload.InviterProfile); marshalErr == nil && len(brokerPayload.InviterProfile) > 0 {
		if err := h.storage.Put("connections/"+brokerPayload.ConnectionID+"/_peer_profile", profileBytes); err != nil {
			log.Warn().Err(err).Str("connection_id", brokerPayload.ConnectionID).Msg("Failed to cache inviter profile")
		}
	}

	// Push response-ready signal to A with the response-invite payload
	// inlined. The broker write above stays as a fallback (older
	// inviter vaults that don't read inline data still pull from
	// the broker), but the inline path skips the JetStream round-trip
	// and is the difference between a ~1s and a ~10s convergence on a
	// cold consumer. See plans/parallel-review-handshake.md §3.1.
	signalExtras := map[string]interface{}{
		"owner_space":    h.ownerSpace,
		"message_space":  record.MessageSpaceTopic,
		"label":          myAlias,
		"profile":        myProfile,
		"e2e_public_key": fmt.Sprintf("%x", record.LocalPublicKey),
		"expires_at":     brokerPayload.ExpiresAt,
	}
	if err := h.publishConnectionSignalWithExtras(brokerPayload.OwnerSpace, "response-ready", brokerPayload.ConnectionID, record.ReviewNonce, signalExtras); err != nil {
		log.Warn().Err(err).Str("connection_id", brokerPayload.ConnectionID).Msg("Failed to push response-ready signal")
	}

	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(context.Background(), EventTypeConnectionCreated, brokerPayload.ConnectionID, brokerPayload.OwnerSpace, "Reviewing peer's connection invite")
	}

	// Emit forApp.connection.peer-reviewing so the local app can render
	// the preview screen with A's profile (the same path A's app will
	// use to render its review screen with B's profile).
	if h.publisher != nil {
		notif := map[string]interface{}{
			"type":          "connection.peer-reviewing",
			"connection_id": brokerPayload.ConnectionID,
			"peer_guid":     brokerPayload.OwnerSpace,
			"peer_alias":    peerAlias,
			"peer_profile":  brokerPayload.InviterProfile,
			"status":        record.Status,
		}
		notifBytes, _ := json.Marshal(notif)
		_ = h.publisher.PublishToApp(context.Background(), "connection.peer-reviewing", notifBytes)
	}

	// Return the original broker payload to the app so the existing
	// scanner preview continues to render without further round-trips.
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   inviteData,
	}, nil
}

// HandleConnectionSignal routes incoming peer signals (response-ready,
// peer-accepted, peer-rejected) on the parallel-review handshake.
// Hard rule: signals carry only routing tokens (conn_id + nonce) — no
// PII flows on this channel. See plans/parallel-review-handshake.md §3.2.
func (h *ConnectionsHandler) HandleConnectionSignal(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	// The signal struct stays narrow for routing; inline payload fields
	// (used by response-ready to skip the broker fetch) are pulled out
	// of the raw payload by the receiving handler.
	var signal struct {
		Signal       string `json:"signal"`
		ConnectionID string `json:"connection_id"`
		ReviewNonce  string `json:"review_nonce,omitempty"`
	}
	if err := unmarshalRequest(msg.Payload, &signal, "HandleConnectionSignal"); err != nil {
		return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}, nil
	}
	if signal.ConnectionID == "" || signal.Signal == "" {
		return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}, nil
	}

	switch signal.Signal {
	case "response-ready":
		return h.handleResponseReady(ctx, msg, signal.ConnectionID, signal.ReviewNonce)
	case "peer-accepted":
		return h.handlePeerAccepted(ctx, msg, signal.ConnectionID)
	case "peer-rejected":
		return h.handlePeerRejected(ctx, msg, signal.ConnectionID)
	default:
		log.Debug().Str("signal", signal.Signal).Msg("Unknown connection signal — dropping")
		return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}, nil
	}
}

// readInlineResponseInvite extracts the response-invite fields the
// scanner inlines into the response-ready signal. Returns nil if the
// payload doesn't carry inline data (older scanner builds, or the
// scanner couldn't include the profile for any reason).
func readInlineResponseInvite(payload []byte, connectionID string) *responseInvite {
	var raw map[string]json.RawMessage
	if json.Unmarshal(payload, &raw) != nil {
		return nil
	}
	var inline struct {
		OwnerSpace   string                 `json:"owner_space"`
		MessageSpace string                 `json:"message_space"`
		Label        string                 `json:"label"`
		Profile      map[string]interface{} `json:"profile"`
		E2EPublicKey string                 `json:"e2e_public_key"`
		ExpiresAt    string                 `json:"expires_at"`
		ReviewNonce  string                 `json:"review_nonce"`
	}
	// Decode fields one at a time so a malformed sub-field doesn't
	// drop the whole payload.
	if data, ok := raw["owner_space"]; ok {
		_ = json.Unmarshal(data, &inline.OwnerSpace)
	}
	if data, ok := raw["message_space"]; ok {
		_ = json.Unmarshal(data, &inline.MessageSpace)
	}
	if data, ok := raw["label"]; ok {
		_ = json.Unmarshal(data, &inline.Label)
	}
	if data, ok := raw["profile"]; ok {
		_ = json.Unmarshal(data, &inline.Profile)
	}
	if data, ok := raw["e2e_public_key"]; ok {
		_ = json.Unmarshal(data, &inline.E2EPublicKey)
	}
	if data, ok := raw["expires_at"]; ok {
		_ = json.Unmarshal(data, &inline.ExpiresAt)
	}
	if data, ok := raw["review_nonce"]; ok {
		_ = json.Unmarshal(data, &inline.ReviewNonce)
	}
	if inline.OwnerSpace == "" || inline.E2EPublicKey == "" {
		return nil
	}
	return &responseInvite{
		ConnectionID: connectionID,
		OwnerSpace:   inline.OwnerSpace,
		MessageSpace: inline.MessageSpace,
		Label:        inline.Label,
		Profile:      inline.Profile,
		E2EPublicKey: inline.E2EPublicKey,
		ReviewNonce:  inline.ReviewNonce,
	}
}

// responseInvite is the unified shape consumed by handleResponseReady,
// regardless of whether it came from the inline signal payload or the
// JetStream broker fetch fallback.
type responseInvite struct {
	ConnectionID string
	OwnerSpace   string
	MessageSpace string
	Label        string
	Profile      map[string]interface{}
	E2EPublicKey string
	ReviewNonce  string
}

// handleResponseReady is A's vault reacting to B's "response-ready"
// ping: pull the response invite from the broker, fill in B's profile +
// pubkey, derive shared secret, set status peer_reviewing, emit
// forApp.connection.peer-reviewing so A's review screen lights up.
//
// De-dup: identical (connection_id, review_nonce) combos are no-ops.
// Drop signals for terminal records (replay guard, plan §10 risk #2).
func (h *ConnectionsHandler) handleResponseReady(ctx context.Context, msg *IncomingMessage, connectionID, reviewNonce string) (*OutgoingMessage, error) {
	storageKey := "connections/" + connectionID
	existing, _ := h.storage.Get(storageKey)
	if len(existing) == 0 {
		// We don't have a record for this connection_id at all. Either
		// it was already revoked/expired (and the storage cleaned up),
		// or this is a stray signal we have no business processing.
		log.Debug().Str("connection_id", connectionID).Msg("response-ready for unknown connection — dropping")
		return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}, nil
	}
	var prior ConnectionRecord
	if err := json.Unmarshal(existing, &prior); err != nil {
		log.Warn().Err(err).Msg("Failed to parse connection record for response-ready")
		return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}, nil
	}
	if recordTerminal(prior.Status) {
		log.Debug().Str("connection_id", connectionID).Str("status", prior.Status).Msg("response-ready dropped — record terminal")
		return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}, nil
	}
	if prior.ReviewNonce == reviewNonce && prior.ReviewNonce != "" && len(prior.PeerPublicKey) > 0 {
		// Duplicate signal — we already pulled this response invite.
		log.Debug().Str("connection_id", connectionID).Msg("response-ready duplicate (nonce match) — no-op")
		return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}, nil
	}

	// Prefer the inline payload from the response-ready signal — saves
	// the JetStream round-trip the broker fetch costs on a cold
	// consumer. Fall back to the broker only if the scanner's signal
	// didn't carry the fields.
	response := readInlineResponseInvite(msg.Payload, connectionID)
	if response == nil {
		if h.sealerProxy == nil {
			return h.errorResponse(msg.GetID(), "sealer proxy not available")
		}
		respData, err := h.sealerProxy.ResolveResponseInvite(connectionID)
		if err != nil {
			log.Warn().Err(err).Str("connection_id", connectionID).Msg("Failed to fetch response invite")
			return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}, nil
		}
		var raw struct {
			ConnectionID string                 `json:"connection_id"`
			OwnerSpace   string                 `json:"owner_space"`
			MessageSpace string                 `json:"message_space"`
			Label        string                 `json:"label"`
			Profile      map[string]interface{} `json:"profile"`
			E2EPublicKey string                 `json:"e2e_public_key"`
			ReviewNonce  string                 `json:"review_nonce"`
		}
		if err := json.Unmarshal(respData, &raw); err != nil {
			log.Warn().Err(err).Msg("Failed to parse response invite payload")
			return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}, nil
		}
		response = &responseInvite{
			ConnectionID: raw.ConnectionID,
			OwnerSpace:   raw.OwnerSpace,
			MessageSpace: raw.MessageSpace,
			Label:        raw.Label,
			Profile:      raw.Profile,
			E2EPublicKey: raw.E2EPublicKey,
			ReviewNonce:  raw.ReviewNonce,
		}
	}
	if response.ConnectionID != connectionID || response.OwnerSpace == "" || response.E2EPublicKey == "" {
		log.Warn().Str("connection_id", connectionID).Msg("Response invite payload missing required fields — dropping")
		return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}, nil
	}
	peerPubKey, err := decodeHexKey(response.E2EPublicKey)
	if err != nil {
		log.Warn().Err(err).Msg("Invalid responder pubkey — dropping")
		return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}, nil
	}

	// Fold the pulled data into the record under the per-connection lock.
	record, err := h.withConnectionRecord(connectionID, func(r *ConnectionRecord) (bool, error) {
		if recordTerminal(r.Status) {
			return false, nil
		}
		// Decline-flip protection — once the peer's decision is
		// recorded as accept/reject, response-ready can't undo it.
		// This guards against profile churn flipping our state.
		r.PeerOwnerSpace = response.OwnerSpace
		r.PeerMessageSpace = response.MessageSpace
		r.PeerGUID = response.OwnerSpace
		r.PeerAlias = response.Label
		r.PeerPublicKey = peerPubKey
		// SECURITY (crypto-H1): only flip status when we actually
		// computed a shared secret. A nil SharedSecret with status
		// peer_reviewing → active misleads the UI into thinking
		// messaging works when it can't.
		if len(r.LocalPrivateKey) > 0 {
			ss, err := curve25519.X25519(r.LocalPrivateKey, peerPubKey)
			if err != nil {
				log.Error().Err(err).Str("connection_id", connectionID).Msg("ECDH derive failed for response-ready")
				return false, fmt.Errorf("derive shared secret: %w", err)
			}
			r.SharedSecret = ss
			r.KeyExchangeAt = time.Now()
		}
		r.ReviewNonce = response.ReviewNonce
		// Only set peer_reviewing if neither side has decided yet.
		if r.LocalDecision == "" && r.PeerDecision == "" {
			r.Status = ConnStatusPeerReviewing
		} else {
			computeStatus(r)
		}
		return true, nil
	})
	if err != nil {
		log.Warn().Err(err).Str("connection_id", connectionID).Msg("Failed to apply response-ready under lock")
		return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}, nil
	}

	// Persist the peer's published profile to the per-connection
	// cache key so connection.list returns it. Without this, the
	// app's peer-profile view renders blank — the parallel-review
	// handshake landed but the cache write was missing.
	if profileBytes, marshalErr := json.Marshal(response.Profile); marshalErr == nil && len(response.Profile) > 0 {
		if err := h.storage.Put("connections/"+connectionID+"/_peer_profile", profileBytes); err != nil {
			log.Warn().Err(err).Str("connection_id", connectionID).Msg("Failed to cache peer profile")
		}
	}

	// Emit forApp.connection.peer-reviewing so A's review screen lights up.
	if h.publisher != nil && record != nil {
		notif := map[string]interface{}{
			"type":          "connection.peer-reviewing",
			"connection_id": connectionID,
			"peer_guid":     record.PeerGUID,
			"peer_alias":    record.PeerAlias,
			"peer_profile":  response.Profile,
			"status":        record.Status,
		}
		notifBytes, _ := json.Marshal(notif)
		_ = h.publisher.PublishToApp(ctx, "connection.peer-reviewing", notifBytes)
	}
	return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}, nil
}

// handlePeerAccepted records that the peer hit Accept on their side.
// Sets PeerDecision and runs tryActivate. Idempotent.
//
// SECURITY (A4): the audit found that this handler was flipping
// PeerDecision based purely on signal-arrival, with no proof the
// signal originated from the peer of record. Anyone who could
// publish to MessageSpace.<us>.forOwner.connection.signal could
// flip a connection's PeerDecision and trip tryActivate.
//
// Defense layer: require the signal payload carry `peer_owner_space`
// matching the connection record's stored `PeerOwnerSpace`. The
// attacker now needs both the connection_id AND the peer's owner
// space ID. (A stronger HMAC-over-SharedSecret authentication is
// the longer-term plan; this is the immediate harden.)
func (h *ConnectionsHandler) handlePeerAccepted(ctx context.Context, msg *IncomingMessage, connectionID string) (*OutgoingMessage, error) {
	if !h.verifyPeerSignalOrigin(msg, connectionID) {
		log.Warn().Str("connection_id", connectionID).Msg("peer-accepted signal rejected — peer_owner_space mismatch")
		return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true,"rejected":"origin_unverified"}`)}, nil
	}
	var changed bool
	_, err := h.withConnectionRecord(connectionID, func(r *ConnectionRecord) (bool, error) {
		if recordTerminal(r.Status) {
			return false, nil
		}
		c, err := applyDecision(&r.PeerDecision, DecisionAccept)
		if err != nil || !c {
			return false, err
		}
		computeStatus(r)
		changed = true
		return true, nil
	})
	if err != nil {
		log.Warn().Err(err).Str("connection_id", connectionID).Msg("peer-accepted apply failed")
	}
	if changed {
		if _, _, aerr := h.tryActivate(ctx, connectionID); aerr != nil {
			log.Warn().Err(aerr).Str("connection_id", connectionID).Msg("tryActivate after peer-accepted failed")
		}
	}
	return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}, nil
}

// verifyPeerSignalOrigin returns true when the inbound signal claims
// a peer_owner_space matching the connection record's stored
// PeerOwnerSpace. Returns false on any mismatch, missing field, or
// connection lookup failure — caller should ack-and-drop without
// mutating state.
//
// This is one half of the peer-signal trust boundary. The other
// half (which would tighten further) is an HMAC keyed by the
// connection's SharedSecret over the signal contents — not yet wired
// because both sender + receiver need to agree.
func (h *ConnectionsHandler) verifyPeerSignalOrigin(msg *IncomingMessage, connectionID string) bool {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(msg.Payload, &probe); err != nil {
		return false
	}
	var claimedPeerOwner string
	if raw, ok := probe["peer_owner_space"]; ok {
		_ = json.Unmarshal(raw, &claimedPeerOwner)
	}
	if claimedPeerOwner == "" {
		return false
	}
	data, err := h.storage.Get("connections/" + connectionID)
	if err != nil || len(data) == 0 {
		return false
	}
	var rec ConnectionRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return false
	}
	if rec.PeerOwnerSpace == "" {
		// Record predates peer-owner-space binding (only possible on
		// legacy records). Strict mode: reject. The user can re-issue
		// the invite to bind the peer's owner space.
		return false
	}
	return rec.PeerOwnerSpace == claimedPeerOwner
}

// handlePeerRejected records that the peer declined. Marks the record
// terminal as declined_by_peer, zeroes shared key material, emits
// forApp.connection.rejected. Idempotent.
//
// SECURITY (A4): destructive op — same origin check as peer-accepted.
// Refuse to mutate state when the signal's peer_owner_space doesn't
// match the connection record's stored PeerOwnerSpace.
func (h *ConnectionsHandler) handlePeerRejected(ctx context.Context, msg *IncomingMessage, connectionID string) (*OutgoingMessage, error) {
	if !h.verifyPeerSignalOrigin(msg, connectionID) {
		log.Warn().Str("connection_id", connectionID).Msg("peer-rejected signal rejected — peer_owner_space mismatch")
		return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true,"rejected":"origin_unverified"}`)}, nil
	}
	var fired bool
	record, err := h.withConnectionRecord(connectionID, func(r *ConnectionRecord) (bool, error) {
		if r.Status == ConnStatusDeclinedByPeer {
			return false, nil // idempotent
		}
		if recordTerminal(r.Status) {
			return false, nil
		}
		_, _ = applyDecision(&r.PeerDecision, DecisionReject)
		r.Status = ConnStatusDeclinedByPeer
		// Zero shared key material — connection won't be used.
		zeroBytes(r.SharedSecret)
		r.SharedSecret = nil
		zeroBytes(r.LocalPrivateKey)
		r.LocalPrivateKey = nil
		fired = true
		return true, nil
	})
	if err != nil {
		log.Warn().Err(err).Str("connection_id", connectionID).Msg("peer-rejected apply failed")
	}
	if fired && h.publisher != nil && record != nil {
		notif := map[string]interface{}{
			"type":          "connection.rejected",
			"connection_id": connectionID,
			"peer_guid":     record.PeerGUID,
		}
		notifBytes, _ := json.Marshal(notif)
		_ = h.publisher.PublishToApp(ctx, "connection.rejected", notifBytes)
	}
	return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}, nil
}

// HandlePeerKeyExchange handles incoming key exchange replies from peers.
// When A's vault processes B's acceptance, it sends A's public key back to B.
// This handler on B's vault stores A's public key and computes the shared secret.
func (h *ConnectionsHandler) HandlePeerKeyExchange(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var keyExchange struct {
		ConnectionID string `json:"connection_id"`
		PeerGUID     string `json:"peer_guid"`
		E2EPublicKey string `json:"e2e_public_key"`
	}

	if err := unmarshalRequest(msg.Payload, &keyExchange, "HandlePeerKeyExchange"); err != nil {
		log.Warn().Err(err).Msg("Failed to parse key exchange message")
		return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}, nil
	}

	if keyExchange.ConnectionID == "" || keyExchange.E2EPublicKey == "" {
		log.Warn().Msg("Key exchange missing connection_id or e2e_public_key")
		return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}, nil
	}

	log.Info().Str("connection_id", keyExchange.ConnectionID).Msg("Received key exchange from peer")

	// Load our connection record
	storageKey := "connections/" + keyExchange.ConnectionID
	connData, err := h.storage.Get(storageKey)
	if err != nil {
		log.Warn().Str("connection_id", keyExchange.ConnectionID).Msg("Connection not found for key exchange")
		return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}, nil
	}

	var record ConnectionRecord
	if err := json.Unmarshal(connData, &record); err != nil {
		log.Warn().Err(err).Msg("Failed to read connection for key exchange")
		return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}, nil
	}

	// Store peer's public key and compute shared secret
	peerPublicKey, err := decodeHexKey(keyExchange.E2EPublicKey)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to decode peer public key in key exchange")
		return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}, nil
	}

	record.PeerPublicKey = peerPublicKey
	// SECURITY (crypto-H1): without a successful ECDH the connection
	// can't carry messages. Refuse to persist the half-state — the peer
	// will retry the key-exchange and we'll reconverge on the next ping.
	if len(record.LocalPrivateKey) > 0 {
		sharedSecret, err := curve25519.X25519(record.LocalPrivateKey, peerPublicKey)
		if err != nil {
			log.Error().Err(err).Str("connection_id", keyExchange.ConnectionID).Msg("ECDH derive failed (B side)")
			return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":false,"error":"derive_shared_secret"}`)}, nil
		}
		record.SharedSecret = sharedSecret
		record.KeyExchangeAt = time.Now()
		log.Info().Str("connection_id", keyExchange.ConnectionID).Msg("Computed shared secret (B side)")
	}

	// Save updated record
	newData, _ := json.Marshal(record)
	if err := h.storage.Put(storageKey, newData); err != nil {
		log.Error().Err(err).Msg("Failed to store connection after key exchange")
	}

	// Notify app that key exchange is complete
	if h.publisher != nil {
		notif := map[string]interface{}{
			"type":          "connection.key-exchanged",
			"connection_id": keyExchange.ConnectionID,
			"peer_guid":     keyExchange.PeerGUID,
		}
		notifBytes, _ := json.Marshal(notif)
		h.publisher.PublishToApp(ctx, "connection.key-exchanged", notifBytes)
	}

	return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}, nil
}

// HandlePeerConnectionActivated handles activation notifications from peers.
// When A reviews and accepts, A's vault publishes this to B's MessageSpace.
func (h *ConnectionsHandler) HandlePeerConnectionActivated(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var activation struct {
		ConnectionID string `json:"connection_id"`
		PeerGUID     string `json:"peer_guid"`
	}

	if err := unmarshalRequest(msg.Payload, &activation, "HandlePeerConnectionActivated"); err != nil || activation.ConnectionID == "" {
		return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}, nil
	}

	log.Info().Str("connection_id", activation.ConnectionID).Msg("Peer activated connection")

	storageKey := "connections/" + activation.ConnectionID
	connData, err := h.storage.Get(storageKey)
	if err != nil {
		return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}, nil
	}

	var record ConnectionRecord
	if err := json.Unmarshal(connData, &record); err != nil {
		return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}, nil
	}

	record.Status = "active"
	// Stamp ActivatedAt and clear ExpiresAt on every path that
	// promotes a record to active. Without ActivatedAt the
	// connection.list self-heal can't distinguish a real active
	// record from a stale "active without peer key" outbound
	// invitation. Without clearing ExpiresAt the active record
	// inherits the 10-minute invite expiry and gets wrongly
	// demoted to "expired" the next time the user logs in.
	if record.ActivatedAt.IsZero() {
		record.ActivatedAt = time.Now().UTC()
	}
	record.ExpiresAt = time.Time{}
	newData, _ := json.Marshal(record)
	h.storage.Put(storageKey, newData)

	if h.publisher != nil {
		notif := map[string]interface{}{
			"type":          "connection.activated",
			"connection_id": activation.ConnectionID,
			"peer_guid":     activation.PeerGUID,
			"peer_alias":    record.PeerAlias,
		}
		notifBytes, _ := json.Marshal(notif)
		h.publisher.PublishToApp(ctx, "connection.activated", notifBytes)
	}

	return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}, nil
}

// HandlePeerConnectionRejected handles rejection notifications from peers.
func (h *ConnectionsHandler) HandlePeerConnectionRejected(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var rejection struct {
		ConnectionID string `json:"connection_id"`
		PeerGUID     string `json:"peer_guid"`
	}

	if err := unmarshalRequest(msg.Payload, &rejection, "HandlePeerConnectionRejected"); err != nil || rejection.ConnectionID == "" {
		return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}, nil
	}

	log.Info().Str("connection_id", rejection.ConnectionID).Msg("Peer rejected connection")

	storageKey := "connections/" + rejection.ConnectionID
	connData, err := h.storage.Get(storageKey)
	if err != nil {
		return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}, nil
	}

	var record ConnectionRecord
	if err := json.Unmarshal(connData, &record); err != nil {
		return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}, nil
	}

	record.Status = "rejected"
	zeroBytes(record.SharedSecret)
	record.SharedSecret = nil
	zeroBytes(record.LocalPrivateKey)
	record.LocalPrivateKey = nil
	newData, _ := json.Marshal(record)
	h.storage.Put(storageKey, newData)

	if h.publisher != nil {
		notif := map[string]interface{}{
			"type":          "connection.rejected",
			"connection_id": rejection.ConnectionID,
			"peer_guid":     rejection.PeerGUID,
		}
		notifBytes, _ := json.Marshal(notif)
		h.publisher.PublishToApp(ctx, "connection.rejected", notifBytes)
	}

	return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":true}`)}, nil
}

// HandleCreateAgentInvite handles connection.agent.create-invite messages.
// Creates a connection + invitation for an AI agent connector and returns
// the details the app needs to call POST /vault/agent/shortlink.
func (h *ConnectionsHandler) HandleCreateAgentInvite(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req CreateAgentInviteRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleCreateAgentInvite"); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	label := req.Label
	if label == "" {
		label = "Agent"
	}

	// Generate connection ID
	idBytes := make([]byte, 16)
	rand.Read(idBytes)
	connectionID := fmt.Sprintf("conn-%x", idBytes)

	// Agent invitations expire in 24 hours (shorter than peer's 30 days)
	expiresAt := time.Now().Add(24 * time.Hour)

	// Generate X25519 key pair for E2E encryption
	localPrivate := make([]byte, 32)
	rand.Read(localPrivate)

	localPublic, err := curve25519.X25519(localPrivate, curve25519.Basepoint)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to derive public key")
	}

	// Generate invite token (32 bytes, base64url-encoded)
	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	inviteToken := base64.RawURLEncoding.EncodeToString(tokenBytes)

	// Store the outbound agent connection record
	record := ConnectionRecord{
		ConnectionID:      connectionID,
		ConnectionType:    ConnectionTypeAgent,
		PeerAlias:         label,
		CredentialsType:   "outbound",
		MessageSpaceTopic: fmt.Sprintf("MessageSpace.%s.forOwner.>", h.ownerSpace),
		Status:            "invited",
		CreatedAt:         time.Now(),
		ExpiresAt:         expiresAt,
		LocalPublicKey:    localPublic,
		LocalPrivateKey:   localPrivate,
	}

	data, err := json.Marshal(record)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to marshal connection")
	}

	storageKey := "connections/" + connectionID
	if err := h.storage.Put(storageKey, data); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to store connection")
	}

	h.addToConnectionIndex(connectionID)

	// Create invitation record
	invitationID, err := h.createAgentInvitation(connectionID, label, inviteToken, expiresAt)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to create invitation")
	}

	// Log connection created event for audit
	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(context.Background(), EventTypeConnectionCreated, connectionID, "", "Agent invitation created")
	}

	log.Info().
		Str("connection_id", connectionID).
		Str("invitation_id", invitationID).
		Msg("Agent invitation created")

	resp := CreateAgentInviteResponse{
		ConnectionID:   connectionID,
		InvitationID:   invitationID,
		InviteToken:    inviteToken,
		OwnerGUID:      h.ownerSpace,
		VaultPublicKey: fmt.Sprintf("%x", localPublic),
		ExpiresAt:      expiresAt.Format(time.RFC3339),
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// createAgentInvitation creates an invitation record for an agent connection.
func (h *ConnectionsHandler) createAgentInvitation(connectionID, label, inviteToken string, expiresAt time.Time) (string, error) {
	idBytes := make([]byte, 16)
	rand.Read(idBytes)
	invitationID := fmt.Sprintf("inv-%x", idBytes)

	record := InvitationRecord{
		InvitationID:   invitationID,
		ConnectionID:   connectionID,
		Status:         "pending",
		DeliveryMethod: "shortlink",
		Label:          label,
		InviteToken:    inviteToken,
		CreatedAt:      time.Now(),
		ExpiresAt:      expiresAt,
	}

	data, err := json.Marshal(record)
	if err != nil {
		return "", fmt.Errorf("failed to marshal invitation: %w", err)
	}

	if err := h.storage.Put("invitations/"+invitationID, data); err != nil {
		return "", fmt.Errorf("failed to store invitation: %w", err)
	}

	// Add to invitation index
	var index []string
	indexData, err := h.storage.Get("invitations/_index")
	if err == nil {
		json.Unmarshal(indexData, &index)
	}

	for _, id := range index {
		if id == invitationID {
			return invitationID, nil
		}
	}

	index = append(index, invitationID)
	newIndexData, _ := json.Marshal(index)
	h.storage.Put("invitations/_index", newIndexData)

	log.Info().
		Str("invitation_id", invitationID).
		Str("connection_id", connectionID).
		Msg("Agent invitation record created")

	return invitationID, nil
}

// HandleStoreCredentials handles connection.store-credentials messages
func (h *ConnectionsHandler) HandleStoreCredentials(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req StoreCredentialsRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleStoreCredentials"); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	// Normalize alternate field names from Android client
	if req.PeerAlias == "" && req.Label != "" {
		req.PeerAlias = req.Label
	}
	if req.Credentials == "" && req.NATSCredentials != "" {
		req.Credentials = req.NATSCredentials
	}
	if req.MessageSpaceTopic == "" && req.PeerMessageSpaceID != "" {
		req.MessageSpaceTopic = req.PeerMessageSpaceID
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}
	// Credentials are optional in Phase 1 (no scoped NATS JWTs yet)
	if req.MessageSpaceTopic == "" {
		return h.errorResponse(msg.GetID(), "message_space_topic is required")
	}

	// SECURITY (A3): require the caller to prove possession of the
	// invite_code we previously issued. Without this, anyone who can
	// publish to forOwner.connection.store-credentials could forge a
	// Status="active" record by guessing or replaying a connection_id.
	//
	// Look up the existing outbound record (created by
	// HandleCreateInvite) and require: (1) the record exists, (2) it
	// is an outbound invite we issued, (3) the wire-supplied
	// invite_code matches the stored one.
	storageKey := "connections/" + req.ConnectionID
	existing, _ := h.storage.Get(storageKey)
	if len(existing) == 0 {
		log.Warn().
			Str("connection_id", req.ConnectionID).
			Str("peer_guid", req.PeerGUID).
			Msg("store-credentials refused — no local record for this connection_id")
		return h.errorResponse(msg.GetID(), "no matching invitation for this connection_id")
	}
	var existingRec ConnectionRecord
	if err := json.Unmarshal(existing, &existingRec); err != nil {
		return h.errorResponse(msg.GetID(), "stored connection record corrupted")
	}
	if existingRec.CredentialsType != "outbound" {
		log.Warn().
			Str("connection_id", req.ConnectionID).
			Str("creds_type", existingRec.CredentialsType).
			Msg("store-credentials refused — record is not an outbound invite")
		return h.errorResponse(msg.GetID(), "connection is not in an invitable state")
	}
	if existingRec.InviteCode == "" {
		// Existing record predates invite-code binding. Refuse rather
		// than silently accept — the user can re-issue a fresh invite.
		log.Warn().
			Str("connection_id", req.ConnectionID).
			Msg("store-credentials refused — existing record has no invite_code (re-issue invite)")
		return h.errorResponse(msg.GetID(), "invitation not bound to a code; re-issue it")
	}
	if req.InviteCode == "" || req.InviteCode != existingRec.InviteCode {
		log.Warn().
			Str("connection_id", req.ConnectionID).
			Bool("code_supplied", req.InviteCode != "").
			Msg("store-credentials refused — invite_code mismatch")
		return h.errorResponse(msg.GetID(), "invite_code mismatch")
	}
	if recordTerminal(existingRec.Status) {
		return h.errorResponse(msg.GetID(), "invitation has expired or been revoked")
	}

	// Generate our X25519 key pair
	localPrivate := make([]byte, 32)
	rand.Read(localPrivate)

	// Derive public key from private key using X25519 scalar multiplication
	localPublic, err := curve25519.X25519(localPrivate, curve25519.Basepoint)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to derive public key")
	}

	// Determine connection type (default: peer)
	connType := ConnectionTypePeer
	if req.ConnectionType == ConnectionTypeAgent {
		connType = ConnectionTypeAgent
	} else if req.ConnectionType == ConnectionTypeDevice {
		connType = ConnectionTypeDevice
	}

	// Store the inbound connection record
	record := ConnectionRecord{
		ConnectionID:      req.ConnectionID,
		ConnectionType:    connType,
		PeerAlias:         req.PeerAlias,
		PeerGUID:          req.PeerGUID,
		CredentialsType:   "inbound",
		Credentials:       req.Credentials,
		MessageSpaceTopic: req.MessageSpaceTopic,
		PeerOwnerSpace:    req.PeerOwnerSpaceID,
		Status:            "active", // Scanner already consented by accepting the invitation
		CreatedAt:         time.Now(),
		LocalPublicKey:    localPublic,
		LocalPrivateKey:   localPrivate,
	}

	// Agent connections get a default contract
	if connType == ConnectionTypeAgent {
		record.Contract = &ConnectionContract{
			AgentName:    req.PeerAlias,
			Scope:        []string{},
			ApprovalMode: "always_ask",
			RateLimit:    RateLimit{Max: 60, Per: "hour"},
		}
		// Extract agent metadata from peer_profile
		if req.PeerProfile != nil {
			record.AgentMetadata = &AgentMetadata{
				AgentType:          getStringField(req.PeerProfile, "agent_type"),
				Hostname:           getStringField(req.PeerProfile, "hostname"),
				Platform:           getStringField(req.PeerProfile, "platform"),
				BinaryFingerprint:  getStringField(req.PeerProfile, "binary_fingerprint"),
				MachineFingerprint: getStringField(req.PeerProfile, "machine_fingerprint"),
				IPAddress:          getStringField(req.PeerProfile, "ip_address"),
			}
		}
	}

	// Device connections get a default session config
	if connType == ConnectionTypeDevice {
		if req.PeerProfile != nil {
			record.AgentMetadata = &AgentMetadata{
				Hostname:           getStringField(req.PeerProfile, "hostname"),
				Platform:           getStringField(req.PeerProfile, "platform"),
				BinaryFingerprint:  getStringField(req.PeerProfile, "binary_fingerprint"),
				MachineFingerprint: getStringField(req.PeerProfile, "machine_fingerprint"),
			}
		}
	}

	// If e2e_public_key was provided (agent/device pattern), store it directly.
	// SECURITY (crypto-H1): we used to swallow ECDH failures here and
	// keep the record without a SharedSecret, which let downstream
	// state flips claim "active" with no working session. Reject the
	// store-credentials request instead so the caller knows to retry.
	e2eKeyHex := req.E2EPublicKey
	if e2eKeyHex == "" {
		e2eKeyHex = req.PeerE2EPublicKey
	}
	if e2eKeyHex != "" {
		peerPubBytes, decodeErr := hex.DecodeString(e2eKeyHex)
		if decodeErr != nil || len(peerPubBytes) != 32 {
			return h.errorResponse(msg.GetID(), "Invalid peer e2e public key")
		}
		record.PeerPublicKey = peerPubBytes
		sharedSecret, sharedErr := curve25519.X25519(localPrivate, peerPubBytes)
		if sharedErr != nil {
			log.Error().Err(sharedErr).Str("connection_id", record.ConnectionID).Msg("ECDH derive failed (store-credentials)")
			return h.errorResponse(msg.GetID(), "Failed to derive shared secret")
		}
		record.SharedSecret = sharedSecret
		record.KeyExchangeAt = time.Now()
	}

	data, err := json.Marshal(record)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to marshal connection")
	}

	if err := h.storage.Put(storageKey, data); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to store connection")
	}

	h.addToConnectionIndex(req.ConnectionID)

	// Cache the peer's profile (from the scanner's profile fetch) for the app
	if len(req.PeerProfile) > 0 {
		profileBytes, _ := json.Marshal(req.PeerProfile)
		if err := h.storage.Put("connections/"+req.ConnectionID+"/_peer_profile", profileBytes); err != nil {
			log.Warn().Err(err).Msg("Failed to cache peer profile on inbound connection")
		}
	}

	// Log connection event for audit (storing credentials means we accepted — audit only, no feed prompt needed)
	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(context.Background(), EventTypeConnectionCreated, req.ConnectionID, req.PeerGUID, "Connection initiated")
	}

	log.Info().Str("connection_id", req.ConnectionID).Msg("Connection credentials stored")

	// Notify the inviter's vault that we accepted the connection.
	// Include our full published profile (with photo) so the inviter can review it.
	// Published via parent (backend account) so the parent's MessageSpace subscription receives it.
	if h.publisher != nil && req.PeerOwnerSpaceID != "" && isValidOwnerSpace(req.PeerOwnerSpaceID) {
		fullProfile := h.loadPublishedProfileForPeer()
		notification := map[string]interface{}{
			"connection_id":  req.ConnectionID,
			"peer_guid":      h.ownerSpace,
			"e2e_public_key": fmt.Sprintf("%x", localPublic),
			"owner_space":    h.ownerSpace,
			"message_space":  fmt.Sprintf("MessageSpace.%s.forOwner.>", h.ownerSpace),
			"peer_profile":   fullProfile,
		}

		notifBytes, _ := json.Marshal(notification)
		subject := fmt.Sprintf("MessageSpace.%s.forOwner.connection.accepted", req.PeerOwnerSpaceID)
		if err := h.publisher.PublishRaw(subject, notifBytes); err != nil {
			log.Warn().Err(err).Str("subject", subject).Msg("Failed to notify peer of acceptance (non-fatal)")
		} else {
			log.Info().
				Str("connection_id", req.ConnectionID).
				Str("peer_owner_space", req.PeerOwnerSpaceID).
				Msg("Published acceptance notification to peer's vault")
		}
	}

	resp := map[string]interface{}{
		"success":       true,
		"connection_id": req.ConnectionID,
		"e2e_public_key": fmt.Sprintf("%x", localPublic),
		"label":         record.PeerAlias,
		"peer_guid":     record.PeerGUID,
		"status":        record.Status,
		"direction":     record.CredentialsType,
		"created_at":    record.CreatedAt.Format(time.RFC3339),
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleInitiate handles connection.initiate messages
// This is used when User B (invitee) initiates a connection with User A (inviter)
// Part of the bidirectional consent flow
func (h *ConnectionsHandler) HandleInitiate(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req InitiateConnectionRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleInitiate"); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.InvitationID == "" {
		return h.errorResponse(msg.GetID(), "invitation_id is required")
	}
	if req.RequesterE2EPublicKey == "" {
		return h.errorResponse(msg.GetID(), "requester_e2e_public_key is required")
	}

	// Find the connection associated with this invitation
	// Invitations are linked to connections via the connection_id stored in the invitation
	invitationData, err := h.storage.Get("invitations/" + req.InvitationID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Invitation not found")
	}

	var invitation struct {
		ConnectionID string `json:"connection_id"`
		Status       string `json:"status"`
		ExpiresAt    string `json:"expires_at"`
	}
	if err := json.Unmarshal(invitationData, &invitation); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to read invitation")
	}

	if invitation.Status != "pending" {
		return h.errorResponse(msg.GetID(), "Invitation is no longer valid")
	}

	// Load the connection record
	connectionID := invitation.ConnectionID
	storageKey := "connections/" + connectionID
	connData, err := h.storage.Get(storageKey)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}

	var record ConnectionRecord
	if err := json.Unmarshal(connData, &record); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to read connection")
	}

	// Store requester's info in the connection record
	record.PeerCapabilities = req.RequesterCapabilities

	// Decode peer's E2E public key and compute shared secret
	peerPublicKey, err := decodeHexKey(req.RequesterE2EPublicKey)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Invalid requester public key format")
	}
	record.PeerPublicKey = peerPublicKey

	// SECURITY (crypto-H1): require a successful ECDH before flipping
	// status to "pending_our_review". Otherwise we ack a request that
	// the peer can never message us back on.
	if len(record.LocalPrivateKey) > 0 && len(peerPublicKey) > 0 {
		sharedSecret, sharedErr := curve25519.X25519(record.LocalPrivateKey, peerPublicKey)
		if sharedErr != nil {
			log.Error().Err(sharedErr).Str("connection_id", record.ConnectionID).Msg("ECDH derive failed (peer-key-exchange)")
			return h.errorResponse(msg.GetID(), "Failed to derive shared secret")
		}
		record.SharedSecret = sharedSecret
		record.KeyExchangeAt = time.Now()
	}
	record.Status = "pending_our_review" // Inviter (A) needs to review invitee (B)

	// Save updated connection record
	newData, err := json.Marshal(record)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to update connection")
	}
	if err := h.storage.Put(storageKey, newData); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to store connection update")
	}

	// Log the initiation event
	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(context.Background(), EventTypeConnectionInitiated, connectionID, "", "Connection initiated by peer")
	}

	// Load the inviter's profile to return to the requester
	inviterProfile := make(map[string]string)
	profileIndexData, err := h.storage.Get("profile/_index")
	if err == nil {
		var fieldNames []string
		if json.Unmarshal(profileIndexData, &fieldNames) == nil {
			for _, field := range fieldNames {
				fieldData, err := h.storage.Get("profile/" + field)
				if err == nil {
					var entry struct {
						Value string `json:"value"`
					}
					if json.Unmarshal(fieldData, &entry) == nil {
						inviterProfile[field] = entry.Value
					}
				}
			}
		}
	}

	// Build peer verifications array from profile
	peerVerifications := []string{}
	if _, ok := inviterProfile["email_verified"]; ok {
		if inviterProfile["email_verified"] == "true" {
			peerVerifications = append(peerVerifications, "email")
		}
	}
	if _, ok := inviterProfile["identity_verified"]; ok {
		if inviterProfile["identity_verified"] == "true" {
			peerVerifications = append(peerVerifications, "identity")
		}
	}

	log.Info().
		Str("connection_id", connectionID).
		Str("invitation_id", req.InvitationID).
		Msg("Connection initiated")

	resp := InitiateConnectionResponse{
		ConnectionID:        connectionID,
		InviterProfile:      inviterProfile,
		InviterCapabilities: record.PeerCapabilities,
		InviterE2EPublicKey: fmt.Sprintf("%x", record.LocalPublicKey),
		PeerVerifications:   peerVerifications,
		Status:              "pending_their_review", // B needs to review A
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// decodeHexKey decodes a hex-encoded key string
func decodeHexKey(hexKey string) ([]byte, error) {
	// Remove any leading 0x prefix if present
	if len(hexKey) >= 2 && hexKey[:2] == "0x" {
		hexKey = hexKey[2:]
	}

	decoded := make([]byte, len(hexKey)/2)
	for i := 0; i < len(decoded); i++ {
		var b byte
		_, err := fmt.Sscanf(hexKey[i*2:i*2+2], "%02x", &b)
		if err != nil {
			return nil, fmt.Errorf("invalid hex at position %d: %w", i*2, err)
		}
		decoded[i] = b
	}
	return decoded, nil
}

// HandleRespond handles connection.respond messages on the parallel-
// review handshake. Sets LocalDecision (accept|reject), pushes the
// matching peer signal, and runs tryActivate. Idempotent — repeat
// taps converge to the same state.
func (h *ConnectionsHandler) HandleRespond(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req RespondConnectionRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleRespond"); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}
	if req.Response != "accept" && req.Response != "reject" {
		return h.errorResponse(msg.GetID(), "response must be 'accept' or 'reject'")
	}

	decision := DecisionAccept
	if req.Response == "reject" {
		decision = DecisionReject
	}

	// Apply the decision under the per-connection lock. The mutator
	// enforces the no-flip rule (once a decision is recorded, it's
	// final) and computes the resulting status.
	var declined bool
	record, err := h.withConnectionRecord(req.ConnectionID, func(r *ConnectionRecord) (bool, error) {
		if recordTerminal(r.Status) {
			// Idempotent for the case where we got the same accept
			// twice and already activated.
			if r.Status == ConnStatusActive && decision == DecisionAccept && r.LocalDecision == DecisionAccept {
				return false, nil
			}
			return false, fmt.Errorf("connection is %s, cannot respond", r.Status)
		}
		c, err := applyDecision(&r.LocalDecision, decision)
		if err != nil || !c {
			return false, err
		}
		if decision == DecisionReject {
			r.Status = ConnStatusDeclinedByUs
			zeroBytes(r.SharedSecret)
			r.SharedSecret = nil
			zeroBytes(r.LocalPrivateKey)
			r.LocalPrivateKey = nil
			declined = true
		} else {
			computeStatus(r)
		}
		return true, nil
	})
	if err != nil {
		return h.errorResponse(msg.GetID(), err.Error())
	}
	if record == nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}

	// Push the matching peer signal. NonCancellable upstream — we set
	// LocalDecision before publishing, so even if the push fails the
	// state is consistent and a future re-respond is a no-op.
	if record.PeerOwnerSpace != "" {
		signalType := "peer-accepted"
		if decision == DecisionReject {
			signalType = "peer-rejected"
		}
		if err := h.publishConnectionSignal(record.PeerOwnerSpace, signalType, req.ConnectionID, ""); err != nil {
			log.Warn().Err(err).Str("connection_id", req.ConnectionID).Msg("Failed to push respond signal to peer")
		}
	}

	// Reject side: log, notify own app, return.
	if declined {
		if h.eventHandler != nil {
			h.eventHandler.LogConnectionEvent(context.Background(), EventTypeConnectionRejected, req.ConnectionID, record.PeerGUID, req.RejectionReason)
		}
		if h.publisher != nil {
			notif := map[string]interface{}{
				"type":          "connection.rejected",
				"connection_id": req.ConnectionID,
				"peer_guid":     record.PeerGUID,
			}
			notifBytes, _ := json.Marshal(notif)
			_ = h.publisher.PublishToApp(context.Background(), "connection.rejected", notifBytes)
		}
	} else {
		// Accept side: try to activate. Will be a no-op if peer
		// hasn't accepted yet — the converging accept signal from the
		// peer will trigger activation when it lands.
		if _, _, aerr := h.tryActivate(context.Background(), req.ConnectionID); aerr != nil {
			log.Warn().Err(aerr).Str("connection_id", req.ConnectionID).Msg("tryActivate after local respond failed")
		}
	}

	// Re-load to return current status (post-tryActivate).
	final, _ := h.withConnectionRecord(req.ConnectionID, func(r *ConnectionRecord) (bool, error) { return false, nil })
	status := record.Status
	if final != nil {
		status = final.Status
	}
	message := "Decision recorded"
	switch status {
	case ConnStatusActive:
		message = "Connection established"
	case ConnStatusDeclinedByUs, ConnStatusDeclinedByPeer:
		message = "Connection declined"
	case ConnStatusOurAcceptPending:
		message = "Waiting for peer to accept"
	case ConnStatusPeerAcceptPending:
		message = "Peer is reviewing your acceptance"
	}

	log.Info().
		Str("connection_id", req.ConnectionID).
		Str("decision", decision).
		Str("status", status).
		Msg("Connection respond processed")

	resp := RespondConnectionResponse{
		Success:      true,
		ConnectionID: req.ConnectionID,
		Status:       status,
		Message:      message,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandlePeerConnectionNotification handles incoming connection acceptance notifications
// from peers. When User B accepts an invitation, they publish a notification to User A's
// MessageSpace.{ownerSpace}.forOwner.connection.accepted topic. This handler updates
// User A's outbound connection record with User B's details.
func (h *ConnectionsHandler) HandlePeerConnectionNotification(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var notification struct {
		ConnectionID string                 `json:"connection_id"`
		PeerGUID     string                 `json:"peer_guid"`
		PeerProfile  map[string]interface{} `json:"peer_profile"`
		E2EPublicKey string                 `json:"e2e_public_key"`
		OwnerSpace   string                 `json:"owner_space"`
		MessageSpace string                 `json:"message_space"`
	}

	if err := unmarshalRequest(msg.Payload, &notification, "HandlePeerConnectionNotification"); err != nil {
		log.Warn().Err(err).Msg("Failed to parse peer connection notification")
		return &OutgoingMessage{
			Type:    MessageTypeResponse,
			Payload: json.RawMessage(`{"ack":true}`),
		}, nil
	}

	if notification.ConnectionID == "" {
		log.Warn().Msg("Peer connection notification missing connection_id")
		return &OutgoingMessage{
			Type:    MessageTypeResponse,
			Payload: json.RawMessage(`{"ack":true}`),
		}, nil
	}

	log.Info().
		Str("connection_id", notification.ConnectionID).
		Str("peer_guid", notification.PeerGUID).
		Msg("Received peer connection acceptance notification")

	// Load the outbound connection record
	storageKey := "connections/" + notification.ConnectionID
	connData, err := h.storage.Get(storageKey)
	if err != nil {
		log.Warn().Str("connection_id", notification.ConnectionID).Msg("Connection not found for peer notification")
		return &OutgoingMessage{
			Type:    MessageTypeResponse,
			Payload: json.RawMessage(`{"ack":true}`),
		}, nil
	}

	var record ConnectionRecord
	if err := json.Unmarshal(connData, &record); err != nil {
		log.Warn().Err(err).Msg("Failed to read connection for peer notification")
		return &OutgoingMessage{
			Type:    MessageTypeResponse,
			Payload: json.RawMessage(`{"ack":true}`),
		}, nil
	}

	// Update the connection with peer's details
	if notification.PeerGUID != "" {
		record.PeerGUID = notification.PeerGUID
	}
	if notification.OwnerSpace != "" {
		record.PeerOwnerSpace = notification.OwnerSpace
	}
	if notification.MessageSpace != "" {
		record.PeerMessageSpace = notification.MessageSpace
	}

	// Build display name from peer profile
	if notification.PeerProfile != nil {
		firstName, _ := notification.PeerProfile["_system_first_name"].(string)
		lastName, _ := notification.PeerProfile["_system_last_name"].(string)
		displayName := strings.TrimSpace(firstName + " " + lastName)
		if displayName != "" {
			record.PeerAlias = displayName
		}

		// Cache the peer's full profile in vault storage for the app
		profileBytes, _ := json.Marshal(notification.PeerProfile)
		if err := h.storage.Put("connections/"+notification.ConnectionID+"/_peer_profile", profileBytes); err != nil {
			log.Warn().Err(err).Msg("Failed to cache peer profile")
		}
	}

	// Store peer's E2E public key and compute shared secret.
	// SECURITY (crypto-H1): if the key is malformed or ECDH fails, the
	// notification is dropped — refuse to flip status to "pending"
	// without a working session, so the inviter retries instead of
	// reviewing a profile they can't message.
	if notification.E2EPublicKey != "" {
		peerPublicKey, decodeErr := decodeHexKey(notification.E2EPublicKey)
		if decodeErr != nil {
			log.Warn().Err(decodeErr).Str("connection_id", notification.ConnectionID).Msg("Invalid peer e2e key in accepted notification")
			return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":false,"error":"invalid_peer_e2e_key"}`)}, nil
		}
		record.PeerPublicKey = peerPublicKey
		if len(record.LocalPrivateKey) > 0 {
			sharedSecret, sharedErr := curve25519.X25519(record.LocalPrivateKey, peerPublicKey)
			if sharedErr != nil {
				log.Error().Err(sharedErr).Str("connection_id", notification.ConnectionID).Msg("ECDH derive failed (A side)")
				return &OutgoingMessage{Type: MessageTypeResponse, Payload: json.RawMessage(`{"ack":false,"error":"derive_shared_secret"}`)}, nil
			}
			record.SharedSecret = sharedSecret
			record.KeyExchangeAt = time.Now()
			log.Info().Str("connection_id", notification.ConnectionID).Msg("Computed shared secret (A side)")
		}
	}

	// Set status to pending — inviter needs to review peer's profile
	record.Status = "pending"

	// Save updated connection record
	newData, err := json.Marshal(record)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal updated connection")
		return &OutgoingMessage{
			Type:    MessageTypeResponse,
			Payload: json.RawMessage(`{"ack":true}`),
		}, nil
	}
	if err := h.storage.Put(storageKey, newData); err != nil {
		log.Error().Err(err).Msg("Failed to store updated connection")
		return &OutgoingMessage{
			Type:    MessageTypeResponse,
			Payload: json.RawMessage(`{"ack":true}`),
		}, nil
	}

	// Log the acceptance event — include peer name so feed shows who wants to connect
	if h.eventHandler != nil {
		title := fmt.Sprintf("%s wants to connect", record.PeerAlias)
		if record.PeerAlias == "" {
			title = "New connection request"
		}
		h.eventHandler.LogConnectionEvent(ctx, EventTypeConnectionAccepted, notification.ConnectionID, notification.PeerGUID, title)
	}

	log.Info().
		Str("connection_id", notification.ConnectionID).
		Str("peer_guid", notification.PeerGUID).
		Str("peer_alias", record.PeerAlias).
		Msg("Connection updated with peer details, status set to pending")

	// Send key exchange reply to peer's vault with our public key
	// This allows B to compute the same shared secret
	if h.publisher != nil && notification.OwnerSpace != "" && isValidOwnerSpace(notification.OwnerSpace) && len(record.LocalPublicKey) > 0 {
		keyExchangeReply := map[string]interface{}{
			"connection_id":  notification.ConnectionID,
			"peer_guid":      h.ownerSpace,
			"e2e_public_key": fmt.Sprintf("%x", record.LocalPublicKey),
		}
		replyBytes, _ := json.Marshal(keyExchangeReply)
		subject := fmt.Sprintf("MessageSpace.%s.forOwner.connection.key-exchange", notification.OwnerSpace)
		if err := h.publisher.PublishRaw(subject, replyBytes); err != nil {
			log.Warn().Err(err).Str("subject", subject).Msg("Failed to send key exchange reply")
		} else {
			log.Info().Str("connection_id", notification.ConnectionID).Msg("Published key exchange reply to peer")
		}
	}

	// Notify the owner's app that a peer accepted — show review UI
	if h.publisher != nil {
		appNotification := map[string]interface{}{
			"type":          "connection.peer-accepted",
			"connection_id": notification.ConnectionID,
			"peer_guid":     notification.PeerGUID,
			"peer_alias":    record.PeerAlias,
			"peer_profile":  notification.PeerProfile,
			"status":        "pending",
		}
		notifBytes, _ := json.Marshal(appNotification)
		if err := h.publisher.PublishToApp(ctx, "connection.peer-accepted", notifBytes); err != nil {
			log.Warn().Err(err).Msg("Failed to notify app of peer acceptance")
		}
	}

	return &OutgoingMessage{
		Type:    MessageTypeResponse,
		Payload: json.RawMessage(`{"ack":true}`),
	}, nil
}

// HandleRevoke handles connection.revoke messages
func (h *ConnectionsHandler) HandleRevoke(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req RevokeConnectionRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleRevoke"); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	storageKey := "connections/" + req.ConnectionID
	data, err := h.storage.Get(storageKey)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}

	var record ConnectionRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to read connection")
	}

	// SECURITY: Zero key material before storing revoked connection
	zeroBytes(record.SharedSecret)
	record.SharedSecret = nil
	zeroBytes(record.LocalPrivateKey)
	record.LocalPrivateKey = nil
	record.Status = "revoked"

	newData, _ := json.Marshal(record)
	if err := h.storage.Put(storageKey, newData); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to revoke connection")
	}

	// Log connection revoked event for audit and feed
	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(context.Background(), EventTypeConnectionRevoked, req.ConnectionID, record.PeerGUID, "Connection revoked")
	}

	log.Info().Str("connection_id", req.ConnectionID).Msg("Connection revoked")

	resp := map[string]interface{}{
		"success":       true,
		"connection_id": req.ConnectionID,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleList handles connection.list messages
func (h *ConnectionsHandler) HandleList(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req ListConnectionsRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleList"); err != nil {
		// Allow empty payload for list all
		req = ListConnectionsRequest{}
	}

	// Lazy-provision the VettID system connection. The Initialize hook
	// in messages.go runs before PIN unlock, when storage isn't ready
	// yet — so the initial EnsureSystemConnection call is a silent
	// no-op. Running it here, right before the app reads the list,
	// guarantees storage is ready (list is only reachable post-unlock)
	// and keeps the call idempotent.
	if err := h.EnsureSystemConnection(context.Background()); err != nil {
		log.Warn().Err(err).Msg("lazy provision of system connection failed — list may be missing VettID card")
	}

	// Get connection index. Silent-empty on error previously hid
	// legitimate problems (decrypt failure, storage not ready); log
	// enough to tell the difference from "genuinely no connections."
	indexData, err := h.storage.Get("connections/_index")
	var connectionIDs []string
	if err != nil {
		log.Warn().Err(err).Str("owner_space", h.ownerSpace).Msg("connection.list: index read failed — returning empty")
	} else if len(indexData) == 0 {
		log.Info().Str("owner_space", h.ownerSpace).Msg("connection.list: index empty — no connections provisioned yet")
	} else if err := json.Unmarshal(indexData, &connectionIDs); err != nil {
		log.Warn().Err(err).Str("owner_space", h.ownerSpace).Int("bytes", len(indexData)).Msg("connection.list: index unmarshal failed")
	}

	connections := make([]ConnectionInfo, 0)
	for _, connID := range connectionIDs {
		data, err := h.storage.Get("connections/" + connID)
		if err != nil {
			continue
		}

		var record ConnectionRecord
		if json.Unmarshal(data, &record) != nil {
			continue
		}

		// Self-heal records mistakenly written to "expired" by the
		// pre-fix list-side check. Criteria: both sides accepted
		// AND peer key is on the record. Either of those alone
		// could be ambiguous, but together they only describe a
		// connection that fully completed key exchange and mutual
		// accept — there's no scenario where "expired" is the
		// correct status for such a record. ActivatedAt is NOT
		// required because legacy paths (HandlePeerConnectionActivated,
		// agent activation) didn't stamp it; relying on it would
		// leave those records stranded.
		if record.Status == ConnStatusExpired &&
			record.LocalDecision == DecisionAccept &&
			record.PeerDecision == DecisionAccept &&
			len(record.PeerPublicKey) > 0 {
			record.Status = ConnStatusActive
			record.ExpiresAt = time.Time{}
			if record.ActivatedAt.IsZero() {
				record.ActivatedAt = time.Now().UTC()
			}
			if updated, mErr := json.Marshal(&record); mErr == nil {
				_ = h.storage.Put("connections/"+record.ConnectionID, updated)
				log.Info().
					Str("connection_id", record.ConnectionID).
					Msg("connection.list: self-healed mistakenly-expired record back to active")
			}
		}

		// Transition stale outbound invitations to "expired" when
		// expires_at has lapsed AND the peer never got far enough
		// for key exchange. Once a PeerPublicKey is present the
		// invitation has already been resolved by the peer.
		//
		// IMPORTANT: never flip a fully-activated record to expired
		// here. ExpiresAt on the record is the INVITATION expiry,
		// inherited at activation time and not cleared on success
		// (the invitation broker payload's expiry doesn't apply to
		// the long-lived connection). A successfully-activated
		// connection that's been around longer than the invitation
		// window would otherwise get retroactively expired the next
		// time the user opens the app — the bug behind "logged in
		// and both connections show expired".
		//
		// Cases covered:
		//   - status="pending" with no peer key: peer never opened
		//     the invitation link/code in time. Sweep to expired.
		// Legacy "active without peer key" records are now defended
		// at activation time (see tryActivate: ExpiresAt cleared).
		expired := !record.ExpiresAt.IsZero() && record.ExpiresAt.Before(time.Now())
		unaccepted := len(record.PeerPublicKey) == 0
		if expired && unaccepted && record.Status == "pending" {
			record.Status = "expired"
			if updated, mErr := json.Marshal(&record); mErr == nil {
				if pErr := h.storage.Put("connections/"+record.ConnectionID, updated); pErr != nil {
					log.Warn().Err(pErr).
						Str("connection_id", record.ConnectionID).
						Msg("connection.list: failed to persist → expired transition")
				}
			}
		}

		// Filter by connection type if specified
		if req.ConnectionType != "" && record.GetConnectionType() != req.ConnectionType {
			continue
		}

		// Filter by status if specified
		if req.Status != "" && record.Status != req.Status {
			continue
		}

		// Filter by tags if specified
		if len(req.Tags) > 0 {
			hasTag := false
			for _, reqTag := range req.Tags {
				for _, recTag := range record.Tags {
					if reqTag == recTag {
						hasTag = true
						break
					}
				}
				if hasTag {
					break
				}
			}
			if !hasTag {
				continue
			}
		}

		// Filter by favorite if specified
		if req.IsFavorite != nil && record.IsFavorite != *req.IsFavorite {
			continue
		}

		// Filter by archived if specified
		if req.IsArchived != nil && record.IsArchived != *req.IsArchived {
			continue
		}

		// Filter by search term (case-insensitive substring match on alias or agent name)
		if req.Search != "" {
			searchLower := strings.ToLower(req.Search)
			matchAlias := strings.Contains(strings.ToLower(record.PeerAlias), searchLower)
			matchAgent := record.Contract != nil && strings.Contains(strings.ToLower(record.Contract.AgentName), searchLower)
			if !matchAlias && !matchAgent {
				continue
			}
		}

		// Compute needs_attention flag
		needsAttention := h.computeNeedsAttention(&record)

		info := ConnectionInfo{
			ConnectionID:          record.ConnectionID,
			ConnectionType:        record.GetConnectionType(),
			PeerAlias:             record.PeerAlias,
			PeerGUID:              record.PeerGUID,
			Status:                record.Status,
			CreatedAt:             record.CreatedAt.Format(time.RFC3339),
			CredentialsType:       record.CredentialsType,
			E2EReady:              len(record.SharedSecret) > 0,
			KeyRotationCount:      record.KeyRotationCount,
			ActivityCount:         record.ActivityCount,
			Tags:                  record.Tags,
			IsFavorite:            record.IsFavorite,
			IsArchived:            record.IsArchived,
			NeedsAttention:        needsAttention,
			PeerProfileVersion:    record.PeerProfileVersion,
			PeerVerifications:     record.PeerVerifications,
			AgentMetadata:         record.AgentMetadata,
			Contract:              record.Contract,
			PresenceShareOverride: record.PresenceShareOverride,
		}

		if !record.LastRotatedAt.IsZero() {
			info.LastRotatedAt = record.LastRotatedAt.Format(time.RFC3339)
		}
		if !record.KeyExchangeAt.IsZero() {
			info.KeyExchangeAt = record.KeyExchangeAt.Format(time.RFC3339)
		}
		if record.LastActiveAt != nil {
			info.LastActiveAt = record.LastActiveAt.Format(time.RFC3339)
		}
		if record.CredentialsExpireAt != nil {
			info.CredentialsExpireAt = record.CredentialsExpireAt.Format(time.RFC3339)
		}

		// Load cached peer profile if available
		profileData, err := h.storage.Get("connections/" + connID + "/_peer_profile")
		if err == nil && len(profileData) > 0 {
			info.PeerProfile = json.RawMessage(profileData)
		}

		// Load message preview and unread count for this connection
		activity := h.getLastActivity(connID)
		info.LastMessagePreview = activity.MessagePreview
		info.LastMessageAt = activity.MessageAt
		info.LastMessageDirection = activity.MessageDirection
		info.UnreadCount = activity.UnreadCount
		info.LastActivityType = activity.Type
		info.LastActivityAt = activity.At
		info.LastActivityDirection = activity.Direction
		info.LastActivitySubtype = activity.Subtype
		info.LastActivityOutcome = activity.Outcome
		info.MissedCallCount = activity.MissedCallCount

		connections = append(connections, info)
	}

	// Sort connections
	h.sortConnections(connections, req.SortBy, req.SortOrder)

	// Apply pagination
	total := len(connections)
	if req.Offset > 0 && req.Offset < len(connections) {
		connections = connections[req.Offset:]
	} else if req.Offset >= len(connections) {
		connections = []ConnectionInfo{}
	}
	if req.Limit > 0 && req.Limit < len(connections) {
		connections = connections[:req.Limit]
	}

	resp := struct {
		Connections []ConnectionInfo `json:"connections"`
		Total       int              `json:"total"`
		Offset      int              `json:"offset"`
		Limit       int              `json:"limit"`
	}{
		Connections: connections,
		Total:       total,
		Offset:      req.Offset,
		Limit:       req.Limit,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// computeNeedsAttention determines if a connection requires user attention
func (h *ConnectionsHandler) computeNeedsAttention(record *ConnectionRecord) bool {
	// Pending invitations need attention
	if record.Status == "pending" {
		return true
	}

	// Expiring credentials within 7 days need attention
	if record.CredentialsExpireAt != nil {
		sevenDays := time.Now().Add(7 * 24 * time.Hour)
		if record.CredentialsExpireAt.Before(sevenDays) {
			return true
		}
	}

	// Expired connections need attention
	if !record.ExpiresAt.IsZero() && record.ExpiresAt.Before(time.Now()) {
		return true
	}

	return false
}

// sortConnections sorts the connection list based on sort parameters
func (h *ConnectionsHandler) sortConnections(connections []ConnectionInfo, sortBy, sortOrder string) {
	if sortBy == "" {
		sortBy = "created_at"
	}
	if sortOrder == "" {
		sortOrder = "desc"
	}

	// Sort using sort.Slice
	switch sortBy {
	case "alphabetical":
		if sortOrder == "asc" {
			for i := 0; i < len(connections)-1; i++ {
				for j := i + 1; j < len(connections); j++ {
					if strings.ToLower(connections[i].PeerAlias) > strings.ToLower(connections[j].PeerAlias) {
						connections[i], connections[j] = connections[j], connections[i]
					}
				}
			}
		} else {
			for i := 0; i < len(connections)-1; i++ {
				for j := i + 1; j < len(connections); j++ {
					if strings.ToLower(connections[i].PeerAlias) < strings.ToLower(connections[j].PeerAlias) {
						connections[i], connections[j] = connections[j], connections[i]
					}
				}
			}
		}
	case "recent_activity":
		if sortOrder == "asc" {
			for i := 0; i < len(connections)-1; i++ {
				for j := i + 1; j < len(connections); j++ {
					if connections[i].LastActiveAt > connections[j].LastActiveAt {
						connections[i], connections[j] = connections[j], connections[i]
					}
				}
			}
		} else {
			for i := 0; i < len(connections)-1; i++ {
				for j := i + 1; j < len(connections); j++ {
					if connections[i].LastActiveAt < connections[j].LastActiveAt {
						connections[i], connections[j] = connections[j], connections[i]
					}
				}
			}
		}
	default: // created_at
		if sortOrder == "asc" {
			for i := 0; i < len(connections)-1; i++ {
				for j := i + 1; j < len(connections); j++ {
					if connections[i].CreatedAt > connections[j].CreatedAt {
						connections[i], connections[j] = connections[j], connections[i]
					}
				}
			}
		} else {
			for i := 0; i < len(connections)-1; i++ {
				for j := i + 1; j < len(connections); j++ {
					if connections[i].CreatedAt < connections[j].CreatedAt {
						connections[i], connections[j] = connections[j], connections[i]
					}
				}
			}
		}
	}
}

// HandleGet handles connection.get messages
func (h *ConnectionsHandler) HandleGet(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req GetConnectionRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleGet"); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	data, err := h.storage.Get("connections/" + req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}

	var record ConnectionRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to read connection")
	}

	// Compute needs_attention flag
	needsAttention := h.computeNeedsAttention(&record)

	info := ConnectionInfo{
		ConnectionID:       record.ConnectionID,
		ConnectionType:     record.GetConnectionType(),
		PeerAlias:          record.PeerAlias,
		PeerGUID:           record.PeerGUID,
		Status:             record.Status,
		CreatedAt:          record.CreatedAt.Format(time.RFC3339),
		CredentialsType:    record.CredentialsType,
		E2EReady:           len(record.SharedSecret) > 0,
		KeyRotationCount:   record.KeyRotationCount,
		ActivityCount:      record.ActivityCount,
		Tags:               record.Tags,
		IsFavorite:         record.IsFavorite,
		IsArchived:         record.IsArchived,
		NeedsAttention:     needsAttention,
		PeerProfileVersion: record.PeerProfileVersion,
		PeerVerifications:  record.PeerVerifications,
		AgentMetadata:      record.AgentMetadata,
		Contract:           record.Contract,
	}

	if !record.LastRotatedAt.IsZero() {
		info.LastRotatedAt = record.LastRotatedAt.Format(time.RFC3339)
	}
	if !record.KeyExchangeAt.IsZero() {
		info.KeyExchangeAt = record.KeyExchangeAt.Format(time.RFC3339)
	}
	if record.LastActiveAt != nil {
		info.LastActiveAt = record.LastActiveAt.Format(time.RFC3339)
	}
	if record.CredentialsExpireAt != nil {
		info.CredentialsExpireAt = record.CredentialsExpireAt.Format(time.RFC3339)
	}

	respBytes, _ := json.Marshal(info)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleUpdate handles connection.update messages
func (h *ConnectionsHandler) HandleUpdate(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req ConnectionUpdateRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleUpdate"); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	storageKey := "connections/" + req.ConnectionID
	data, err := h.storage.Get(storageKey)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}

	var record ConnectionRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to read connection")
	}

	// Update fields if provided
	if req.Tags != nil {
		record.Tags = req.Tags
	}
	if req.IsFavorite != nil {
		record.IsFavorite = *req.IsFavorite
	}
	if req.IsArchived != nil {
		record.IsArchived = *req.IsArchived
	}
	if req.PeerAlias != "" {
		record.PeerAlias = req.PeerAlias
	}

	// Save updated record
	newData, err := json.Marshal(record)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to marshal connection")
	}

	if err := h.storage.Put(storageKey, newData); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to update connection")
	}

	log.Info().Str("connection_id", req.ConnectionID).Msg("Connection updated")

	resp := ConnectionUpdateResponse{
		Success:      true,
		ConnectionID: req.ConnectionID,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleRotate handles connection.rotate messages
// Generates a new X25519 keypair for an active connection
func (h *ConnectionsHandler) HandleRotate(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		ConnectionID string `json:"connection_id"`
	}
	if err := unmarshalRequest(msg.Payload, &req, "HandleRotate"); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	storageKey := "connections/" + req.ConnectionID
	data, err := h.storage.Get(storageKey)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}

	var record ConnectionRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to read connection")
	}

	if record.Status != "active" {
		return h.errorResponse(msg.GetID(), fmt.Sprintf("Cannot rotate keys for connection with status: %s", record.Status))
	}

	// Generate new X25519 keypair
	localPrivate := make([]byte, 32)
	rand.Read(localPrivate)

	localPublic, err := curve25519.X25519(localPrivate, curve25519.Basepoint)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to derive public key")
	}

	// Update connection record
	record.LocalPrivateKey = localPrivate
	record.LocalPublicKey = localPublic
	record.SharedSecret = nil // Clear shared secret until peer exchanges new key
	record.LastRotatedAt = time.Now()
	record.KeyRotationCount++

	newData, err := json.Marshal(record)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to marshal connection")
	}

	if err := h.storage.Put(storageKey, newData); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to update connection")
	}

	// Log rotation event
	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(context.Background(), EventTypeConnectionRotated, req.ConnectionID, record.PeerGUID, "Keys rotated")
	}

	log.Info().Str("connection_id", req.ConnectionID).Int("rotation_count", record.KeyRotationCount).Msg("Connection keys rotated")

	resp := map[string]interface{}{
		"connection_id":      record.ConnectionID,
		"peer_guid":          record.PeerGUID,
		"label":              record.PeerAlias,
		"status":             record.Status,
		"direction":          record.CredentialsType,
		"created_at":         record.CreatedAt.Format(time.RFC3339),
		"last_rotated_at":    record.LastRotatedAt.Format(time.RFC3339),
		"key_rotation_count": record.KeyRotationCount,
		"e2e_public_key":     fmt.Sprintf("%x", localPublic),
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleGetCredentials handles connection.get-credentials messages
// Returns NATS credentials for communicating with a peer
func (h *ConnectionsHandler) HandleGetCredentials(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		ConnectionID string `json:"connection_id"`
	}
	if err := unmarshalRequest(msg.Payload, &req, "HandleGetCredentials"); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	data, err := h.storage.Get("connections/" + req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}

	var record ConnectionRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to read connection")
	}

	resp := map[string]interface{}{
		"connection_id":        record.ConnectionID,
		"nats_credentials":     record.Credentials,
		"peer_message_space_id": record.MessageSpaceTopic,
	}
	if record.CredentialsExpireAt != nil {
		resp["expires_at"] = record.CredentialsExpireAt.Format(time.RFC3339)
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleGetCapabilities handles connection.get-capabilities messages
func (h *ConnectionsHandler) HandleGetCapabilities(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req GetCapabilitiesRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleGetCapabilities"); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	data, err := h.storage.Get("connections/" + req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}

	var record ConnectionRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to read connection")
	}

	capabilities := record.PeerCapabilities
	if capabilities == nil {
		capabilities = make(map[string]string)
	}

	resp := GetCapabilitiesResponse{
		ConnectionID: req.ConnectionID,
		Capabilities: capabilities,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleActivitySummary handles connection.activity-summary messages
func (h *ConnectionsHandler) HandleActivitySummary(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req ActivitySummaryRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleActivitySummary"); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	data, err := h.storage.Get("connections/" + req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}

	var record ConnectionRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to read connection")
	}

	// Load activity summary from separate storage
	// Activity is stored at connections/{connection_id}/activity
	activityKey := "connections/" + req.ConnectionID + "/activity"
	var summary ActivitySummaryResponse
	summary.ConnectionID = req.ConnectionID

	activityData, err := h.storage.Get(activityKey)
	if err == nil {
		json.Unmarshal(activityData, &summary)
	}

	// Always use the total activity count from the connection record
	summary.TotalMessages = summary.MessagesSent + summary.MessagesReceived

	if record.LastActiveAt != nil {
		summary.LastActivityAt = record.LastActiveAt.Format(time.RFC3339)
	}

	respBytes, _ := json.Marshal(summary)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// UpdateConnectionActivity updates activity tracking for a connection
func (h *ConnectionsHandler) UpdateConnectionActivity(connectionID string, activityType string) error {
	storageKey := "connections/" + connectionID
	data, err := h.storage.Get(storageKey)
	if err != nil {
		return fmt.Errorf("connection not found: %s", connectionID)
	}

	var record ConnectionRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return fmt.Errorf("failed to read connection: %w", err)
	}

	// Update activity tracking
	now := time.Now()
	record.LastActiveAt = &now
	record.ActivityCount++

	// Save updated record
	newData, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal connection: %w", err)
	}

	if err := h.storage.Put(storageKey, newData); err != nil {
		return fmt.Errorf("failed to update connection: %w", err)
	}

	// Update activity summary
	activityKey := "connections/" + connectionID + "/activity"
	var summary ActivitySummaryResponse
	activityData, err := h.storage.Get(activityKey)
	if err == nil {
		json.Unmarshal(activityData, &summary)
	}

	summary.ConnectionID = connectionID
	summary.LastActivityAt = now.Format(time.RFC3339)
	summary.LastActivityType = activityType

	switch activityType {
	case "message_sent":
		summary.MessagesSent++
	case "message_received":
		summary.MessagesReceived++
	case "call":
		summary.TotalCalls++
	}
	summary.TotalMessages = summary.MessagesSent + summary.MessagesReceived

	summaryData, _ := json.Marshal(summary)
	h.storage.Put(activityKey, summaryData)

	return nil
}

// StartExpirySweep launches a background ticker that periodically
// flips stale connection records to ConnStatusExpired. Records are
// considered expired when ExpiresAt is in the past AND status is one
// of the in-flight states (invited, peer_reviewing, *_pending).
// Active and terminal records are untouched. See plan §10 risk #3.
func (h *ConnectionsHandler) StartExpirySweep(ctx context.Context) {
	go func() {
		// Run an immediate first sweep so a vault that wakes up after
		// being offline catches up quickly.
		h.sweepExpiredConnections(ctx)
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				h.sweepExpiredConnections(ctx)
			}
		}
	}()
}

func (h *ConnectionsHandler) sweepExpiredConnections(ctx context.Context) {
	indexData, err := h.storage.Get("connections/_index")
	if err != nil || len(indexData) == 0 {
		return
	}
	var index []string
	if err := json.Unmarshal(indexData, &index); err != nil {
		return
	}
	now := time.Now().UTC()
	// 30s grace window for clock skew across vaults.
	threshold := now.Add(-30 * time.Second)

	for _, connectionID := range index {
		var fired bool
		record, err := h.withConnectionRecord(connectionID, func(r *ConnectionRecord) (bool, error) {
			if recordTerminal(r.Status) || r.Status == "" {
				return false, nil
			}
			if r.ExpiresAt.IsZero() {
				return false, nil
			}
			if r.ExpiresAt.After(threshold) {
				return false, nil // not yet expired
			}
			// Only sweep records still in the in-flight state set.
			switch r.Status {
			case ConnStatusInvited, ConnStatusPeerReviewing, ConnStatusOurAcceptPending, ConnStatusPeerAcceptPending, "pending":
				r.Status = ConnStatusExpired
				zeroBytes(r.SharedSecret)
				r.SharedSecret = nil
				zeroBytes(r.LocalPrivateKey)
				r.LocalPrivateKey = nil
				fired = true
				return true, nil
			default:
				return false, nil
			}
		})
		if err != nil {
			log.Debug().Err(err).Str("connection_id", connectionID).Msg("expiry sweep skipped record")
			continue
		}
		if fired && h.publisher != nil && record != nil {
			notif := map[string]interface{}{
				"type":          "connection.expired",
				"connection_id": connectionID,
				"peer_guid":     record.PeerGUID,
			}
			notifBytes, _ := json.Marshal(notif)
			_ = h.publisher.PublishToApp(ctx, "connection.expired", notifBytes)
		}
	}
}

// Helper methods

func (h *ConnectionsHandler) addToConnectionIndex(connectionID string) {
	var index []string
	indexData, err := h.storage.Get("connections/_index")
	if err == nil {
		json.Unmarshal(indexData, &index)
	}

	// Check if already in index
	for _, id := range index {
		if id == connectionID {
			return
		}
	}

	index = append(index, connectionID)
	newIndexData, _ := json.Marshal(index)
	h.storage.Put("connections/_index", newIndexData)
}

// HandleAcceptAgentConnection processes an agent connection request (registration completion).
//
// The agent sends a ConnectionRequest ECIES-encrypted with the vault's X25519 public key.
// This handler:
//  1. Finds the invitation by ID from the decrypted request
//  2. Validates the invitation (exists, not expired, status "pending")
//  3. Computes X25519 shared secret from vault private key + agent public key
//  4. Updates the connection record with agent metadata, shared secret, and "active" status
//  5. Publishes an approval response to the invitation-specific topic
//
// The envelope.Payload is ECIES-encrypted with the vault's connection public key
// using DomainAgent domain separation.
func (h *ConnectionsHandler) HandleAcceptAgentConnection(ctx context.Context, msg *IncomingMessage, envelope *AgentEnvelope) (*OutgoingMessage, error) {
	// Extract encrypted bytes from envelope payload
	encryptedPayload, err := extractPayloadBytes(envelope.Payload)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to extract agent connection request payload")
		return nil, nil
	}

	// We need to find the invitation first to get the connection record's private key.
	// The key_id in the envelope isn't set for connection requests (agent doesn't know
	// connection ID yet). Instead we try all pending agent invitations.
	invRecord, connRecord, err := h.findPendingAgentInvitationForECIES(encryptedPayload)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to find matching agent invitation")
		return nil, nil
	}

	// ECIES-decrypt with the connection's local private key using agent domain
	plaintext, err := decryptECIESAgentDomain(connRecord.LocalPrivateKey, encryptedPayload)
	if err != nil {
		log.Warn().Err(err).
			Str("connection_id", connRecord.ConnectionID).
			Msg("Failed to decrypt agent connection request")
		return nil, nil
	}
	defer zeroBytes(plaintext)

	// Parse the connection request
	var connReq struct {
		InvitationID   string    `json:"invitation_id"`
		AgentPublicKey []byte    `json:"agent_public_key"`
		Registration   AgentMetadata `json:"registration"`
		Timestamp      time.Time `json:"timestamp"`
	}
	if err := json.Unmarshal(plaintext, &connReq); err != nil {
		log.Warn().Err(err).Msg("Failed to parse agent connection request")
		return nil, nil
	}

	// Verify invitation ID matches
	if connReq.InvitationID != invRecord.InvitationID {
		log.Warn().
			Str("expected", invRecord.InvitationID).
			Str("got", connReq.InvitationID).
			Msg("Agent connection request invitation ID mismatch")
		return nil, nil
	}

	// Validate invitation
	if invRecord.Status != "pending" {
		log.Warn().Str("status", invRecord.Status).Msg("Agent invitation not pending")
		return nil, nil
	}
	if time.Now().After(invRecord.ExpiresAt) {
		log.Warn().Msg("Agent invitation expired")
		return nil, nil
	}

	// Validate agent public key
	if len(connReq.AgentPublicKey) != 32 {
		log.Warn().Int("len", len(connReq.AgentPublicKey)).Msg("Invalid agent public key length")
		return nil, nil
	}

	// Compute X25519 shared secret
	sharedSecret, err := curve25519.X25519(connRecord.LocalPrivateKey, connReq.AgentPublicKey)
	if err != nil {
		log.Error().Err(err).Msg("Failed to compute shared secret")
		return nil, nil
	}

	// Update connection record
	connRecord.PeerPublicKey = connReq.AgentPublicKey
	connRecord.SharedSecret = sharedSecret
	connRecord.Status = "active"
	connRecord.KeyExchangeAt = time.Now()
	// Stamp ActivatedAt + clear invite expiry so connection.list's
	// migration sweep doesn't later flip this agent connection back
	// to "expired" when the original invite window lapses.
	if connRecord.ActivatedAt.IsZero() {
		connRecord.ActivatedAt = time.Now().UTC()
	}
	connRecord.ExpiresAt = time.Time{}
	connRecord.AgentMetadata = &connReq.Registration

	// Set default contract (owner can update later)
	if connRecord.Contract == nil {
		connRecord.Contract = &ConnectionContract{
			AgentName:    connRecord.PeerAlias,
			Scope:        []string{}, // Empty = all categories allowed
			ApprovalMode: "always_ask",
			RateLimit:    RateLimit{Max: 60, Per: "hour"},
		}
	}

	// Save updated connection
	connData, err := json.Marshal(connRecord)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal updated connection")
		return nil, nil
	}
	if err := h.storage.Put("connections/"+connRecord.ConnectionID, connData); err != nil {
		log.Error().Err(err).Msg("Failed to store updated connection")
		return nil, nil
	}

	// Update invitation status
	now := time.Now()
	invRecord.Status = "accepted"
	invRecord.RespondedAt = &now
	invData, _ := json.Marshal(invRecord)
	h.storage.Put("invitations/"+invRecord.InvitationID, invData)

	// Log event
	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(ctx, EventTypeAgentConnectionApproved, connRecord.ConnectionID, "",
			fmt.Sprintf("Agent connection accepted: %s", connRecord.PeerAlias))
	}

	log.Info().
		Str("connection_id", connRecord.ConnectionID).
		Str("invitation_id", invRecord.InvitationID).
		Str("agent_type", connReq.Registration.AgentType).
		Msg("Agent connection accepted")

	// Derive connection key to encrypt the approval response
	connKey, err := deriveConnectionKey(sharedSecret)
	if err != nil {
		log.Error().Err(err).Msg("Failed to derive connection key for approval response")
		return nil, nil
	}
	defer zeroBytes(connKey)

	// Build approval payload
	approval := struct {
		ConnectionID string             `json:"connection_id"`
		KeyID        string             `json:"key_id"`
		Contract     *ConnectionContract `json:"contract"`
	}{
		ConnectionID: connRecord.ConnectionID,
		KeyID:        connRecord.ConnectionID,
		Contract:     connRecord.Contract,
	}
	approvalBytes, _ := json.Marshal(approval)

	// Encrypt with connection key
	encryptedApproval, err := encryptXChaCha20(connKey, approvalBytes)
	if err != nil {
		log.Error().Err(err).Msg("Failed to encrypt approval response")
		return nil, nil
	}
	zeroBytes(approvalBytes)

	// Build response envelope
	encPayloadJSON, _ := json.Marshal(encryptedApproval)
	envBytes, err := json.Marshal(AgentEnvelope{
		Type:      AgentMsgConnectionApproved,
		KeyID:     connRecord.ConnectionID,
		Payload:   encPayloadJSON,
		Timestamp: time.Now().UTC(),
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal approval envelope")
		return nil, nil
	}

	// Publish to invitation-specific topic so the agent can receive it
	responseTopic := fmt.Sprintf("MessageSpace.%s.forOwner.agent.invitation.%s", h.ownerSpace, invRecord.InvitationID)
	log.Debug().Str("topic", responseTopic).Msg("Publishing agent connection approval")

	return &OutgoingMessage{
		ID:      generateMessageID(),
		Type:    MessageTypeNATSPublish,
		Subject: responseTopic,
		Payload: envBytes,
	}, nil
}

// findPendingAgentInvitationForECIES finds the pending agent invitation
// that can successfully decrypt the ECIES payload.
// This is needed because the agent doesn't know the connection ID before registration.
func (h *ConnectionsHandler) findPendingAgentInvitationForECIES(encryptedPayload []byte) (*InvitationRecord, *ConnectionRecord, error) {
	// Get invitation index
	var invIndex []string
	indexData, err := h.storage.Get("invitations/_index")
	if err != nil {
		return nil, nil, fmt.Errorf("no invitations found")
	}
	json.Unmarshal(indexData, &invIndex)

	for _, invID := range invIndex {
		invData, err := h.storage.Get("invitations/" + invID)
		if err != nil {
			continue
		}

		var inv InvitationRecord
		if err := json.Unmarshal(invData, &inv); err != nil {
			continue
		}

		// Only check pending, non-expired invitations
		if inv.Status != "pending" || time.Now().After(inv.ExpiresAt) {
			continue
		}

		// Look up the connection for this invitation
		connData, err := h.storage.Get("connections/" + inv.ConnectionID)
		if err != nil {
			continue
		}

		var conn ConnectionRecord
		if err := json.Unmarshal(connData, &conn); err != nil {
			continue
		}

		// Must be an agent connection with a private key
		if !conn.IsAgent() || len(conn.LocalPrivateKey) == 0 {
			continue
		}

		// Try to decrypt — if it works, this is the right invitation
		_, err = decryptECIESAgentDomain(conn.LocalPrivateKey, encryptedPayload)
		if err == nil {
			return &inv, &conn, nil
		}
	}

	return nil, nil, fmt.Errorf("no matching pending agent invitation found")
}

// HandleCreateDeviceInvite handles device.create-invite messages.
//
// Stage 1 of the device pairing flow (see DESKTOP-CONNECTION-FLOW.md):
//  1. Generate 8-char ambiguity-safe invite code, 2-minute expiry
//  2. Generate scoped NATS credentials bound to a new connection_id
//  3. Publish the full invite payload to the INVITATIONS JetStream subject
//     invite.<code> — the desktop, using its embedded guest account, reads
//     this to obtain the scoped creds
//  4. Create a connection record in "pending_pairing" status
//  5. Return the code + endpoint to the app for display
//
// No ConnectionRecord-held ephemeral keys at this stage. Key exchange happens
// later during stage 2 (device.authorize-session) using fresh ephemeral keys
// so the stage-1 NATS creds, even if leaked, cannot decrypt session data.
func (h *ConnectionsHandler) HandleCreateDeviceInvite(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req CreateDeviceInviteRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleCreateDeviceInvite"); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if h.natsProxy == nil || h.publisher == nil {
		return h.errorResponse(msg.GetID(), "NATS unavailable — cannot create device invite")
	}

	// Generate connection ID
	idBytes := make([]byte, 16)
	rand.Read(idBytes)
	connectionID := fmt.Sprintf("conn-%x", idBytes)

	// 2-minute pairing window
	expiresAt := time.Now().Add(2 * time.Minute)

	// Generate scoped NATS credentials — bound to this connection_id
	accountSeed, err := h.loadAccountSeed()
	if err != nil {
		log.Warn().Err(err).Msg("Failed to load NATS account seed for device invite")
		return h.errorResponse(msg.GetID(), "Failed to generate invitation credentials")
	}
	creds, err := GenerateDeviceCredentials(accountSeed, h.ownerSpace, connectionID, expiresAt)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to generate device credentials")
	}
	jwtStr, seedStr := extractCredsComponents(creds)

	// Generate the 8-char code and publish the invite payload to JetStream
	inviteCode := generateDeviceInviteCode()
	brokerPayload := map[string]interface{}{
		"type":          "vettid_device",
		"connection_id": connectionID,
		"jwt":           jwtStr,
		"seed":          seedStr,
		"owner_space":   h.ownerSpace,
		"message_space": fmt.Sprintf("MessageSpace.%s.forApp.device.%s.>", h.ownerSpace, connectionID),
		"expires_at":    expiresAt.Format(time.RFC3339),
		"label":         req.Label,
	}
	payloadBytes, _ := json.Marshal(brokerPayload)
	subject := fmt.Sprintf("invite.%s", inviteCode)
	if err := h.publisher.PublishRaw(subject, payloadBytes); err != nil {
		log.Error().Err(err).Str("subject", subject).Msg("Failed to publish device invite to broker")
		return h.errorResponse(msg.GetID(), "Failed to publish invitation")
	}

	// Store the outbound device connection record
	record := ConnectionRecord{
		ConnectionID:      connectionID,
		ConnectionType:    ConnectionTypeDevice,
		PeerAlias:         req.Label, // user may have hinted a name; final set at authorize
		CredentialsType:   "outbound",
		MessageSpaceTopic: fmt.Sprintf("MessageSpace.%s.forOwner.device.%s.>", h.ownerSpace, connectionID),
		Status:            "pending_pairing",
		CreatedAt:         time.Now(),
		ExpiresAt:         expiresAt,
	}
	data, err := json.Marshal(record)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to marshal connection")
	}
	if err := h.storage.Put("connections/"+connectionID, data); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to store connection")
	}
	h.addToConnectionIndex(connectionID)

	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(context.Background(), EventTypeDeviceConnectionRequest, connectionID, "", "Device pairing invite created")
	}

	natsEndpoint := ""
	if h.natsProxy != nil {
		natsEndpoint = h.natsProxy.GetNATSEndpoint()
	}

	log.Info().
		Str("connection_id", connectionID).
		Str("invite_code", inviteCode).
		Msg("Device invite created and published to broker")

	resp := CreateDeviceInviteResponse{
		ConnectionID: connectionID,
		InviteCode:   inviteCode,
		NATSEndpoint: natsEndpoint,
		ExpiresAt:    expiresAt.Format(time.RFC3339),
	}
	respBytes, _ := json.Marshal(resp)
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// loadAccountSeed returns the NATS account seed, loading from storage /
// sealer proxy if it isn't cached yet. Mirrors generateInvitationCredentials.
func (h *ConnectionsHandler) loadAccountSeed() (string, error) {
	if h.natsProxy == nil {
		return "", fmt.Errorf("NATS proxy not available")
	}
	if !h.natsProxy.HasAccountSeed() {
		if h.storage != nil {
			if seedData, err := h.storage.Get("nats_account_seed"); err == nil && len(seedData) > 0 {
				h.natsProxy.SetAccountSeed(string(seedData))
			}
		}
	}
	if !h.natsProxy.HasAccountSeed() {
		if h.sealerProxy == nil {
			return "", fmt.Errorf("sealer proxy not available")
		}
		seed, err := h.sealerProxy.LoadAccountSeed()
		if err != nil {
			return "", fmt.Errorf("load account seed: %w", err)
		}
		h.natsProxy.SetAccountSeed(seed)
		if h.storage != nil {
			_ = h.storage.Put("nats_account_seed", []byte(seed))
		}
	}
	seed := h.natsProxy.GetAccountSeed()
	if seed == "" {
		return "", fmt.Errorf("account seed empty after load")
	}
	return seed, nil
}

// HandleListDeviceConnections returns all device connections with session status.
func (h *ConnectionsHandler) HandleListDeviceConnections(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	indexData, err := h.storage.Get("connections/_index")
	var connectionIDs []string
	if err == nil {
		json.Unmarshal(indexData, &connectionIDs)
	}

	type DeviceInfo struct {
		ConnectionID string `json:"connection_id"`
		DeviceName   string `json:"device_name"`
		Hostname     string `json:"hostname,omitempty"`
		Platform     string `json:"platform,omitempty"`
		Status       string `json:"status"`
		SessionID    string `json:"session_id,omitempty"`
		SessionStatus string `json:"session_status,omitempty"`
		SessionExpires int64 `json:"session_expires,omitempty"`
		ConnectedAt  string `json:"connected_at"`
		LastActiveAt string `json:"last_active_at,omitempty"`
	}

	devices := make([]DeviceInfo, 0)
	for _, connID := range connectionIDs {
		data, err := h.storage.Get("connections/" + connID)
		if err != nil {
			continue
		}

		var record ConnectionRecord
		if json.Unmarshal(data, &record) != nil {
			continue
		}

		if !record.IsDevice() {
			continue
		}

		info := DeviceInfo{
			ConnectionID: record.ConnectionID,
			DeviceName:   record.PeerAlias,
			Status:       record.Status,
			ConnectedAt:  record.CreatedAt.Format(time.RFC3339),
		}

		if record.DeviceMetadata != nil {
			info.Hostname = record.DeviceMetadata.Hostname
			info.Platform = record.DeviceMetadata.Platform
		}

		if record.DeviceSession != nil {
			info.SessionID = record.DeviceSession.SessionID
			info.SessionStatus = record.DeviceSession.Status
			info.SessionExpires = record.DeviceSession.ExpiresAt
		}

		if record.LastActiveAt != nil {
			info.LastActiveAt = record.LastActiveAt.Format(time.RFC3339)
		}

		devices = append(devices, info)
	}

	resp := struct {
		Devices []DeviceInfo `json:"devices"`
		Count   int          `json:"count"`
	}{
		Devices: devices,
		Count:   len(devices),
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleRevokeDevice revokes a device connection and its session.
// Can be called from either the app (admin revoke) or the device itself (logout).
// Wipes the session key, marks the connection revoked, and publishes a
// revocation event so the desktop can clear its local state.
func (h *ConnectionsHandler) HandleRevokeDevice(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req DeviceRevokeRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleRevokeDevice"); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	data, err := h.storage.Get("connections/" + req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}

	var record ConnectionRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to read connection")
	}

	if !record.IsDevice() {
		return h.errorResponse(msg.GetID(), "Connection is not a device")
	}

	// Wipe the session key from storage
	if record.DeviceSession != nil && record.DeviceSession.SessionKeyID != "" {
		keyPath := fmt.Sprintf("device_session_keys/%s/%s", record.ConnectionID, record.DeviceSession.SessionKeyID)
		if err := h.storage.Delete(keyPath); err != nil {
			log.Warn().Err(err).Str("path", keyPath).Msg("Failed to delete session key during revoke (non-fatal)")
		}
	}

	// Mark revoked
	record.Status = "revoked"
	if record.DeviceSession != nil {
		record.DeviceSession.Status = "revoked"
	}
	record.DevicePendingAuth = nil

	connData, _ := json.Marshal(record)
	h.storage.Put("connections/"+record.ConnectionID, connData)

	// Notify the desktop so it can clear local state
	if h.publisher != nil {
		revokeNotif := map[string]interface{}{
			"type":          "device.session.revoked",
			"connection_id": record.ConnectionID,
			"reason":        req.Reason,
		}
		notifBytes, _ := json.Marshal(revokeNotif)
		subject := fmt.Sprintf("MessageSpace.%s.forApp.device.%s.revoked", h.ownerSpace, record.ConnectionID)
		if err := h.publisher.PublishRaw(subject, notifBytes); err != nil {
			log.Warn().Err(err).Str("subject", subject).Msg("Failed to publish device revocation (non-fatal)")
		}
	}

	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(ctx, EventTypeDeviceConnectionRevoked, record.ConnectionID, "",
			fmt.Sprintf("Device connection revoked: %s", record.PeerAlias))
	}

	log.Info().
		Str("connection_id", record.ConnectionID).
		Str("reason", req.Reason).
		Msg("Device connection revoked")

	resp := struct {
		Success      bool   `json:"success"`
		ConnectionID string `json:"connection_id"`
	}{
		Success:      true,
		ConnectionID: record.ConnectionID,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// NOTE: HandleExtendDeviceSession is now defined in device_pairing.go with the
// key-rotation semantics described in DESKTOP-CONNECTION-FLOW.md §Stage 4.
// The old phone-heartbeat-based HandleDeviceHeartbeat is removed — sessions are
// bounded by wall-clock expiry only, extended via user QR scan.

// HandleListAgentConnections returns all agent connections with metadata.
func (h *ConnectionsHandler) HandleListAgentConnections(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	indexData, err := h.storage.Get("connections/_index")
	var connectionIDs []string
	if err == nil {
		json.Unmarshal(indexData, &connectionIDs)
	}

	type AgentInfo struct {
		ConnectionID string             `json:"connection_id"`
		AgentName    string             `json:"agent_name"`
		AgentType    string             `json:"agent_type"`
		Status       string             `json:"status"`
		ApprovalMode string             `json:"approval_mode"`
		Scope        []string           `json:"scope"`
		ConnectedAt  string             `json:"connected_at"`
		LastActiveAt string             `json:"last_active_at,omitempty"`
		Hostname     string             `json:"hostname,omitempty"`
		Platform     string             `json:"platform,omitempty"`
	}

	agents := make([]AgentInfo, 0)
	for _, connID := range connectionIDs {
		data, err := h.storage.Get("connections/" + connID)
		if err != nil {
			continue
		}

		var record ConnectionRecord
		if json.Unmarshal(data, &record) != nil {
			continue
		}

		if !record.IsAgent() {
			continue
		}

		info := AgentInfo{
			ConnectionID: record.ConnectionID,
			AgentName:    record.PeerAlias,
			Status:       record.Status,
			ConnectedAt:  record.CreatedAt.UTC().Format(time.RFC3339),
		}

		if record.Contract != nil {
			info.ApprovalMode = record.Contract.ApprovalMode
			info.Scope = record.Contract.Scope
		}

		if record.AgentMetadata != nil {
			info.AgentType = record.AgentMetadata.AgentType
			info.Hostname = record.AgentMetadata.Hostname
			info.Platform = record.AgentMetadata.Platform
		}

		if record.LastActiveAt != nil {
			info.LastActiveAt = record.LastActiveAt.UTC().Format(time.RFC3339)
		}

		agents = append(agents, info)
	}

	resp := map[string]interface{}{
		"success": true,
		"agents":  agents,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleRevokeAgent revokes an agent connection and clears its shared secret.
func (h *ConnectionsHandler) HandleRevokeAgent(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		ConnectionID string `json:"connection_id"`
	}
	if err := unmarshalRequest(msg.Payload, &req, "HandleRevokeAgent"); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	storageKey := "connections/" + req.ConnectionID
	data, err := h.storage.Get(storageKey)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}

	var record ConnectionRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to read connection")
	}

	if !record.IsAgent() {
		return h.errorResponse(msg.GetID(), "Not an agent connection")
	}

	// SECURITY: Zero shared secret before saving
	zeroBytes(record.SharedSecret)
	record.SharedSecret = nil
	record.Status = "revoked"

	newData, _ := json.Marshal(record)
	if err := h.storage.Put(storageKey, newData); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to revoke agent")
	}

	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(ctx, EventTypeConnectionRevoked, req.ConnectionID, "",
			fmt.Sprintf("Agent connection revoked: %s", record.PeerAlias))
	}

	log.Info().Str("connection_id", req.ConnectionID).Str("agent", record.PeerAlias).Msg("Agent connection revoked")

	resp := map[string]interface{}{
		"success":       true,
		"connection_id": req.ConnectionID,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleUpdateAgentContract updates an agent connection's contract (scope, approval mode, rate limit).
func (h *ConnectionsHandler) HandleUpdateAgentContract(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		ConnectionID string    `json:"connection_id"`
		Scope        []string  `json:"scope,omitempty"`
		ApprovalMode string    `json:"approval_mode,omitempty"`
		RateLimit    *RateLimit `json:"rate_limit,omitempty"`
	}
	if err := unmarshalRequest(msg.Payload, &req, "HandleUpdateAgentContract"); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	storageKey := "connections/" + req.ConnectionID
	data, err := h.storage.Get(storageKey)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}

	var record ConnectionRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to read connection")
	}

	if !record.IsAgent() {
		return h.errorResponse(msg.GetID(), "Not an agent connection")
	}

	if record.Contract == nil {
		record.Contract = &ConnectionContract{
			AgentName:    record.PeerAlias,
			ApprovalMode: "always_ask",
			RateLimit:    RateLimit{Max: 60, Per: "hour"},
		}
	}

	// Apply updates
	if req.Scope != nil {
		record.Contract.Scope = req.Scope
	}
	if req.ApprovalMode != "" {
		// Validate approval mode
		switch req.ApprovalMode {
		case "always_ask", "auto_within_contract", "auto_all":
			record.Contract.ApprovalMode = req.ApprovalMode
		default:
			return h.errorResponse(msg.GetID(), "Invalid approval_mode")
		}
	}
	if req.RateLimit != nil {
		record.Contract.RateLimit = *req.RateLimit
	}

	newData, _ := json.Marshal(record)
	if err := h.storage.Put(storageKey, newData); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to update contract")
	}

	log.Info().
		Str("connection_id", req.ConnectionID).
		Str("approval_mode", record.Contract.ApprovalMode).
		Msg("Agent contract updated")

	resp := map[string]interface{}{
		"success":       true,
		"connection_id": req.ConnectionID,
		"contract":      record.Contract,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// loadInviterProfile reads the vault owner's profile for inclusion in invite responses.
func (h *ConnectionsHandler) loadInviterProfile() map[string]string {
	profile := make(map[string]string)

	systemFields := []string{"_system_first_name", "_system_last_name", "_system_email"}
	for _, field := range systemFields {
		data, err := h.storage.Get("profile/" + field)
		if err != nil {
			continue
		}
		var entry struct {
			Value string `json:"value"`
		}
		if json.Unmarshal(data, &entry) == nil && entry.Value != "" {
			profile[field] = entry.Value
		}
	}

	return profile
}

// loadPublishedProfileForPeer loads the full published profile for sending to
// a connection peer. Uses the shared BuildPublishedProfile function to ensure
// consistency with profile.get-published and profile.publish.
func (h *ConnectionsHandler) loadPublishedProfileForPeer() map[string]interface{} {
	profile := BuildPublishedProfile(h.ownerSpace, h.storage, h.vaultState)
	return PublishedProfileToMap(profile)
}

// RepublishOutstandingInvites walks every pending outbound invitation
// the user has open and re-publishes its broker payload (subject
// invite.<code>) with a fresh `inviter_profile` snapshot. INVITATIONS
// stream uses last-message-per-subject retention so re-publishing
// overwrites the previous payload — a scanner who hasn't resolved yet
// will see the latest catalogs/wallets.
//
// Best-effort: a per-invite failure logs but does not abort the walk.
// Skips connections that have already moved past the pre-resolve
// window (active, declined, expired, revoked, etc.).
func RepublishOutstandingInvites(ownerSpace string, storage *EncryptedStorage, publisher *VsockPublisher, vaultState *VaultState) {
	if storage == nil || publisher == nil {
		return
	}
	indexData, err := storage.Get("connections/_index")
	if err != nil || len(indexData) == 0 {
		return
	}
	var ids []string
	if err := json.Unmarshal(indexData, &ids); err != nil {
		return
	}

	profile := BuildPublishedProfile(ownerSpace, storage, vaultState)
	inviterProfile := PublishedProfileToMap(profile)

	for _, id := range ids {
		data, err := storage.Get("connections/" + id)
		if err != nil {
			continue
		}
		var rec ConnectionRecord
		if json.Unmarshal(data, &rec) != nil {
			continue
		}
		if rec.CredentialsType != "outbound" {
			continue
		}
		if rec.InviteCode == "" {
			continue
		}
		// Only refresh while the invite is still pre-resolution.
		switch rec.Status {
		case ConnStatusInvited, ConnStatusPeerReviewing,
			ConnStatusOurAcceptPending, ConnStatusPeerAcceptPending,
			"pending", "pending_their_review":
			// proceed
		default:
			continue
		}

		jwt, seed := extractCredsComponents(rec.Credentials)
		if jwt == "" || seed == "" {
			continue
		}

		brokerPayload := map[string]interface{}{
			"type":            "vettid_connection",
			"kind":            "connection",
			"connection_id":   rec.ConnectionID,
			"jwt":             jwt,
			"seed":            seed,
			"owner_space":     ownerSpace,
			"message_space":   rec.MessageSpaceTopic,
			"expires_at":      rec.ExpiresAt.Format(time.RFC3339),
			"label":           rec.PeerAlias,
			"inviter_profile": inviterProfile,
			"e2e_public_key":  fmt.Sprintf("%x", rec.LocalPublicKey),
		}
		payloadBytes, err := json.Marshal(brokerPayload)
		if err != nil {
			continue
		}
		subject := fmt.Sprintf("invite.%s", rec.InviteCode)
		if err := publisher.PublishRaw(subject, payloadBytes); err != nil {
			log.Warn().Err(err).Str("invite_code", rec.InviteCode).Msg("RepublishOutstandingInvites: per-invite republish failed")
		}
	}
}

// lastActivityInfo aggregates the bits HandleList needs to paint a
// connection card's last-activity icon + badges.
type lastActivityInfo struct {
	// Message fields (still surfaced separately for the preview text).
	MessagePreview   string
	MessageAt        string // RFC3339
	MessageDirection string // "incoming" | "outgoing"
	UnreadCount      int    // unread incoming messages

	// Activity fields — whichever of (latest message, latest call) is
	// most recent wins Type + At + Direction; the call-only fields
	// (Subtype, Outcome) populate when Type == "call".
	Type      string // "message" | "call"
	At        string // RFC3339
	Direction string // "incoming" | "outgoing"
	Subtype   string // "voice" | "video"
	Outcome   string // "completed" | "missed" | "rejected"

	MissedCallCount int
}

// getLastActivity walks the connection's message index and the global
// call index to compute the latest-activity summary. Missed incoming
// calls also contribute a count for the Voice action button's badge.
func (h *ConnectionsHandler) getLastActivity(connectionID string) lastActivityInfo {
	out := lastActivityInfo{}

	// --- Messages ---
	var latestMessageTime time.Time
	if indexData, err := h.storage.Get(fmt.Sprintf("messages/%s/_index", connectionID)); err == nil {
		var messageIDs []string
		if json.Unmarshal(indexData, &messageIDs) == nil {
			for _, msgID := range messageIDs {
				data, err := h.storage.Get(fmt.Sprintf("messages/%s/%s", connectionID, msgID))
				if err != nil {
					continue
				}
				var rec MessageRecord
				if json.Unmarshal(data, &rec) != nil {
					continue
				}
				if rec.CreatedAt.After(latestMessageTime) {
					latestMessageTime = rec.CreatedAt
					if rec.Direction == MessageDirectionIncoming {
						out.MessagePreview = "Received a message"
						out.MessageDirection = "incoming"
					} else {
						out.MessagePreview = "You sent a message"
						out.MessageDirection = "outgoing"
					}
				}
				if rec.Direction == MessageDirectionIncoming && rec.Status != MessageStatusRead {
					out.UnreadCount++
				}
			}
		}
	}
	if !latestMessageTime.IsZero() {
		if len(out.MessagePreview) > 100 {
			out.MessagePreview = out.MessagePreview[:100] + "..."
		}
		out.MessageAt = latestMessageTime.Format(time.RFC3339)
	}

	// --- Calls ---
	var latestCallTime time.Time
	var latestCall *CallRecord
	if indexData, err := h.storage.Get("calls/_index"); err == nil {
		var callIDs []string
		if json.Unmarshal(indexData, &callIDs) == nil {
			for _, callID := range callIDs {
				data, err := h.storage.Get("calls/" + callID)
				if err != nil {
					continue
				}
				var rec CallRecord
				if json.Unmarshal(data, &rec) != nil {
					continue
				}
				if rec.ConnectionID != connectionID {
					continue
				}
				if rec.Direction == "incoming" && rec.Status == "missed" && rec.SeenAt == 0 {
					out.MissedCallCount++
				}
				started := time.Unix(rec.StartedAt, 0)
				if started.After(latestCallTime) {
					latestCallTime = started
					r := rec
					latestCall = &r
				}
			}
		}
	}

	// --- Choose winner for Activity* fields ---
	messageWins := !latestMessageTime.IsZero() && latestMessageTime.After(latestCallTime)
	if messageWins {
		out.Type = "message"
		out.At = out.MessageAt
		out.Direction = out.MessageDirection
	} else if latestCall != nil {
		out.Type = "call"
		out.At = latestCallTime.Format(time.RFC3339)
		out.Direction = latestCall.Direction
		out.Subtype = latestCall.CallType
		switch latestCall.Status {
		case "answered":
			out.Outcome = "completed"
		case "missed":
			out.Outcome = "missed"
		case "cancelled":
			// Caller hung up before the peer answered. Distinct
			// from "missed" (which is the peer side's view of the
			// same event) so the outgoing side's card can say
			// "Call cancelled" instead of "Missed call."
			out.Outcome = "cancelled"
		case "rejected", "blocked":
			out.Outcome = "rejected"
		}
	}

	return out
}

// generateInvitationCredentials creates scoped NATS credentials for an invitation.
// Loads the account seed from vault storage first (fast path), falling back to
// sealer proxy (DynamoDB via parent) for initial fetch, then caches in vault storage.
func (h *ConnectionsHandler) generateInvitationCredentials(expiresAt time.Time) (string, error) {
	if h.natsProxy == nil {
		return "", fmt.Errorf("NATS proxy not available")
	}

	// Fast path: already cached in memory
	if !h.natsProxy.HasAccountSeed() {
		// Try loading from vault's own encrypted storage first
		if h.storage != nil {
			seedData, err := h.storage.Get("nats_account_seed")
			if err == nil && len(seedData) > 0 {
				log.Info().Str("owner_space", h.ownerSpace).Msg("Loaded NATS account seed from vault storage")
				h.natsProxy.SetAccountSeed(string(seedData))
			}
		}
	}

	// Fallback: fetch via sealer proxy (parent → DynamoDB → KMS) and cache in vault storage
	if !h.natsProxy.HasAccountSeed() {
		if h.sealerProxy == nil {
			return "", fmt.Errorf("sealer proxy not available for account seed loading")
		}

		log.Info().Str("owner_space", h.ownerSpace).Msg("Loading NATS account seed via sealer proxy")
		seed, err := h.sealerProxy.LoadAccountSeed()
		if err != nil {
			return "", fmt.Errorf("failed to load account seed: %w", err)
		}
		h.natsProxy.SetAccountSeed(seed)

		// Cache in vault storage so future loads don't need DynamoDB
		if h.storage != nil {
			if storeErr := h.storage.Put("nats_account_seed", []byte(seed)); storeErr != nil {
				log.Warn().Err(storeErr).Msg("Failed to cache account seed in vault storage (non-fatal)")
			} else {
				log.Info().Str("owner_space", h.ownerSpace).Msg("Cached NATS account seed in vault storage")
			}
		}
	}

	accountSeed := h.natsProxy.GetAccountSeed()
	if accountSeed == "" {
		return "", fmt.Errorf("account seed not available after loading")
	}

	return GenerateInvitationCredentials(accountSeed, h.ownerSpace, expiresAt)
}

func (h *ConnectionsHandler) errorResponse(id string, message string) (*OutgoingMessage, error) {
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

// getStringField safely extracts a string value from a map.
func getStringField(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
