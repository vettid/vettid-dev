package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/vettid/vettid-dev/enclave/vault-manager/storage"
)

// ----------------------------------------------------------------------
// Event taxonomy
// ----------------------------------------------------------------------

const (
	AuditTypeMessageSent     = "message.sent"
	AuditTypeMessageReceived = "message.received"

	AuditTypeCallVoiceStarted   = "call.voice.started"
	AuditTypeCallVoiceCompleted = "call.voice.completed"
	AuditTypeCallVoiceMissed    = "call.voice.missed"
	AuditTypeCallVideoStarted   = "call.video.started"
	AuditTypeCallVideoCompleted = "call.video.completed"
	AuditTypeCallVideoMissed    = "call.video.missed"
	AuditTypeCallRejected       = "call.rejected"

	AuditTypeTransferBtcSent     = "transfer.btc.sent"
	AuditTypeTransferBtcReceived = "transfer.btc.received"

	AuditTypeConnectionCreated  = "connection.created"
	AuditTypeConnectionAccepted = "connection.accepted"
	AuditTypeConnectionRevoked  = "connection.revoked"
	AuditTypeConnectionRotated  = "connection.rotated"

	AuditTypeSecurityKeyRotated = "security.key.rotated"
	AuditTypeSecurityAlert      = "security.alert"

	AuditTypeAgentActionExecuted = "agent.action.executed"
	AuditTypeAgentSecretAccessed = "agent.secret.accessed"

	// Location lifecycle (peer-connection scoped). Direction encodes
	// who initiated the action:
	//   outbound: owner did it (sent the request, toggled sharing on/off, sent one-shot)
	//   inbound:  peer did it (asked us, started sharing with us, stopped, etc.)
	//
	// Continuous-share start/stop and one-shot location-update share the
	// same `location.share.started` event on the receiver side because
	// the receiver can't distinguish them locally — the cache write
	// path fires either way. UX consequence: a one-shot reads as
	// "started sharing" with no follow-up "stopped" entry until the
	// cache row ages out or the peer explicitly stops.
	AuditTypeLocationRequest      = "location.request"
	AuditTypeLocationShareStarted = "location.share.started"
	AuditTypeLocationShareStopped = "location.share.stopped"

	// Shared-action invocations (action_invoker.go). These land on the
	// connection that drove the invocation — both sides see the trail.
	AuditTypeActionInvocationSigOK     = "action.invocation.sig_ok"
	AuditTypeActionInvocationSigFailed = "action.invocation.sig_failed"
	AuditTypeActionInvoked             = "action.invoked"
	AuditTypeActionApproved            = "action.approved"
	AuditTypeActionDenied              = "action.denied"
	AuditTypeActionExpired             = "action.expired"
	AuditTypeActionFailed              = "action.failed"

	// Reference-based data sharing (see plans/data-request-grants.md
	// Phase 1). One entry per lifecycle transition + one per fetch.
	// Fetches accumulate quickly on a renewable grant; if audit log
	// volume becomes a problem, add a daily rollup.
	AuditTypeDataRequestSent     = "data.request.sent"
	AuditTypeDataRequestReceived = "data.request.received"
	AuditTypeDataGranted         = "data.granted"
	AuditTypeDataGrantDenied     = "data.grant.denied"
	AuditTypeDataFetched         = "data.fetched"
	AuditTypeDataFetchDenied     = "data.fetch.denied"
	AuditTypeDataRevoked         = "data.revoked"
	AuditTypeDataExpired         = "data.expired"

	// Critical-secret use-on-my-behalf (plans/data-request-grants.md
	// Phase 6). Direction:
	//   outbound: peer asked us / we performed for peer (depending on
	//             which side of the connection logged it)
	AuditTypeCriticalSecretUseRequested = "critical_secret.use.requested"
	AuditTypeCriticalSecretUsed         = "critical_secret.used"
	AuditTypeCriticalSecretUseDenied    = "critical_secret.use.denied"

	// Identity-key usage. Every site that consumes the user's Ed25519
	// identity private key for signing emits this — votes, shared-
	// action invocations + results, service-contract signatures,
	// connection.authenticate challenges. Audit metadata carries
	// "purpose" so the user can see WHY their key was used, not just
	// THAT it was. Direction is internal (the act is by the user's
	// vault on the user's behalf); ConnectionID is populated when the
	// signing was for a specific peer relationship.
	AuditTypeIdentityKeyUsed = "identity_key.used"

	// connection.authenticate (2026-05-12) — challenge/response proof
	// that a peer holds the credential bound to their identity key.
	// Eventually load-bearing for service-vault auth flows; today it
	// surfaces in the audit trail as a record that authentication was
	// requested + completed.
	AuditTypeConnectionAuthenticated     = "connection.authenticated"
	AuditTypeConnectionAuthenticateRequested = "connection.authenticate.requested"
	AuditTypeConnectionAuthenticateFailed = "connection.authenticate.failed"

	// System connection events — originate from the VettID service
	// itself (not a peer) and all land on the reserved system
	// connection. See plans/luminous-unifying-manatee.md.
	AuditTypeSystemGuidePublished     = "system.guide.published"
	AuditTypeSystemMigrationRequired  = "system.migration.required"
	AuditTypeSystemMigrationFinalized = "system.migration.finalized"
	AuditTypeSystemVoteProposed       = "system.vote.proposed"
	AuditTypeSystemVoteTallied        = "system.vote.tallied"
	AuditTypeSystemSecurityAlert      = "system.security.alert"
	AuditTypeSystemAnnouncement       = "system.announcement"
)

// AppendSystem records a service-originated event on the reserved
// VettID system connection. Convenience wrapper that fills in the
// connection_id and direction so write sites stay short. Reads
// SystemConnectionID from connections.go.
func (a *AuditLog) AppendSystem(entry AuditEntry) {
	if entry.ConnectionID == "" {
		entry.ConnectionID = SystemConnectionID
	}
	if entry.Direction == "" {
		entry.Direction = AuditDirectionInbound
	}
	a.Append(entry)
}

// AuditDirectionOutbound / Inbound identify which side initiated the
// entry from the owner's point of view.
const (
	AuditDirectionOutbound = "outbound"
	AuditDirectionInbound  = "inbound"
	AuditDirectionInternal = "internal"
)

// auditBodyMaxLen mirrors the feed-event preview cap so audit bodies
// don't hold whole message bodies — short preview, follow refs for the
// rest. See docs/CONNECTION-AUDIT-TRAIL-PLAN.md open question resolution.
const auditBodyMaxLen = 120

// ----------------------------------------------------------------------
// AuditEntry
// ----------------------------------------------------------------------

// AuditEntry is the per-interaction record stored under a connection.
// Serializes to JSON for the storage payload blob, and again to JSON for
// the list/search RPC response.
type AuditEntry struct {
	EntryID      string            `json:"entry_id"`
	ConnectionID string            `json:"connection_id"`
	PeerGUID     string            `json:"peer_guid,omitempty"`
	EventType    string            `json:"event_type"`
	Direction    string            `json:"direction,omitempty"`
	Title        string            `json:"title"`
	Body         string            `json:"body,omitempty"`
	CreatedAt    int64             `json:"created_at"`
	Refs         map[string]string `json:"refs,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`

	// Per-connection hash chain + signature. Each entry's hash
	// includes the previous entry's hash for this connection, so any
	// row insertion/deletion/reorder breaks the chain. Sig is
	// produced by the audit_priv derived from identity (see audit_key.go).
	// Empty for legacy rows / rows written pre-PIN-unlock.
	PreviousHash string `json:"previous_hash,omitempty"`
	EntryHash    string `json:"entry_hash,omitempty"`
	EntrySig     string `json:"entry_sig,omitempty"`
}

// ----------------------------------------------------------------------
// AuditLog helper
// ----------------------------------------------------------------------

// AuditLog is the vault-manager's thin wrapper around the storage
// package. Handlers call Append(...) inline with the operation that
// produced the event.
type AuditLog struct {
	storage *EncryptedStorage
}

// NewAuditLog returns an AuditLog bound to the vault's encrypted
// storage. nil-safe: if storage isn't initialized yet, Append logs and
// returns without erroring so write points stay fire-and-forget.
func NewAuditLog(s *EncryptedStorage) *AuditLog {
	return &AuditLog{storage: s}
}

// Append stores an audit entry. Fills in EntryID / CreatedAt if the
// caller left them blank, clamps the body, and logs-on-error so the
// primary operation never fails because of the audit log.
func (a *AuditLog) Append(entry AuditEntry) {
	if a == nil || a.storage == nil || a.storage.SQLite() == nil {
		log.Debug().Msg("audit log unavailable — skipping append")
		return
	}
	if entry.ConnectionID == "" {
		log.Warn().Str("event_type", entry.EventType).Msg("audit append missing connection_id — dropping")
		return
	}
	if entry.EntryID == "" {
		entry.EntryID = newAuditEntryID()
	}
	if entry.CreatedAt == 0 {
		entry.CreatedAt = time.Now().Unix()
	}
	entry.Body = clampBody(entry.Body)

	payload, err := json.Marshal(entry)
	if err != nil {
		log.Warn().Err(err).Str("entry_id", entry.EntryID).Msg("audit marshal failed — dropping")
		return
	}

	rec := storage.AuditEntryRecord{
		EntryID:      entry.EntryID,
		ConnectionID: entry.ConnectionID,
		PeerGUID:     entry.PeerGUID,
		EventType:    entry.EventType,
		Direction:    entry.Direction,
		Title:        entry.Title,
		Body:         entry.Body,
		CreatedAt:    entry.CreatedAt,
		Payload:      payload,
	}
	if err := a.storage.SQLite().AppendAuditEntry(rec); err != nil {
		log.Warn().Err(err).
			Str("entry_id", entry.EntryID).
			Str("event_type", entry.EventType).
			Msg("audit append failed — continuing")
	}
}

// List returns a page of entries for a connection. Thin wrapper over
// the storage-layer query with the payload decoded to AuditEntry.
func (a *AuditLog) List(opts storage.AuditListOptions) ([]AuditEntry, *storage.AuditCursor, error) {
	if a == nil || a.storage == nil || a.storage.SQLite() == nil {
		return nil, nil, fmt.Errorf("audit log unavailable")
	}
	result, err := a.storage.SQLite().ListAuditEntries(opts)
	if err != nil {
		return nil, nil, err
	}
	return decodeAuditEntries(result.Entries), result.NextCursor, nil
}

// Search runs an FTS5 MATCH query (see storage.SearchAuditEntries).
func (a *AuditLog) Search(opts storage.AuditSearchOptions) ([]AuditEntry, *storage.AuditCursor, error) {
	if a == nil || a.storage == nil || a.storage.SQLite() == nil {
		return nil, nil, fmt.Errorf("audit log unavailable")
	}
	result, err := a.storage.SQLite().SearchAuditEntries(opts)
	if err != nil {
		return nil, nil, err
	}
	return decodeAuditEntries(result.Entries), result.NextCursor, nil
}

// Count reports the number of audit entries recorded for a connection.
func (a *AuditLog) Count(connectionID string) (int, error) {
	if a == nil || a.storage == nil || a.storage.SQLite() == nil {
		return 0, nil
	}
	return a.storage.SQLite().AuditEntryCount(connectionID)
}

// ----------------------------------------------------------------------
// helpers
// ----------------------------------------------------------------------

func decodeAuditEntries(rows []storage.AuditEntryRecord) []AuditEntry {
	out := make([]AuditEntry, 0, len(rows))
	for _, r := range rows {
		var e AuditEntry
		if err := json.Unmarshal(r.Payload, &e); err != nil {
			// Fall back to the indexed columns so a malformed payload
			// doesn't make the entry disappear from the UI.
			e = AuditEntry{
				EntryID:      r.EntryID,
				ConnectionID: r.ConnectionID,
				PeerGUID:     r.PeerGUID,
				EventType:    r.EventType,
				Direction:    r.Direction,
				Title:        r.Title,
				Body:         r.Body,
				CreatedAt:    r.CreatedAt,
			}
		}
		// Chain fields live on the storage row, not the embedded payload
		// — copy them out so the JSON response carries the chain anchors
		// the client uses to verify integrity.
		e.PreviousHash = r.PreviousHash
		e.EntryHash = r.EntryHash
		e.EntrySig = r.EntrySig
		out = append(out, e)
	}
	return out
}

// newAuditEntryID produces a ULID-ish, time-sortable, collision-free id
// without adding a new dependency. Format: <unix_nanos>-<hex16>.
// Lexicographic sort is identical to chronological sort — which is what
// the (created_at DESC, entry_id DESC) index relies on for tie-breaks.
func newAuditEntryID() string {
	var rnd [8]byte
	_, _ = rand.Read(rnd[:])
	return fmt.Sprintf("%020d-%s", time.Now().UnixNano(), hex.EncodeToString(rnd[:]))
}

func clampBody(s string) string {
	if len(s) <= auditBodyMaxLen {
		return s
	}
	clamped := s[:auditBodyMaxLen]
	// Trim trailing partial UTF-8 byte sequence so we don't produce
	// invalid strings; cheap: strip trailing non-ASCII continuation bytes.
	for len(clamped) > 0 && (clamped[len(clamped)-1]&0xC0) == 0x80 {
		clamped = clamped[:len(clamped)-1]
	}
	return strings.TrimRight(clamped, " ") + "…"
}
