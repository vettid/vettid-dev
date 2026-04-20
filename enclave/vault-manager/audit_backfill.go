package main

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/vettid/vettid-dev/enclave/vault-manager/storage"
)

// AuditBackfiller reconstructs an audit trail for connections that
// existed before the audit feature shipped. Runs lazily on the first
// connection.audit.list / .search for a given connection, marks the
// connection as backfilled via a sentinel key, then stays out of the
// way on subsequent reads.
//
// Input sources (best-effort, skip what isn't available):
//   - messages/<connection_id>/<id> — message sent/received records
//   - events table — global feed with call / transfer / lifecycle events
//   - connections/<id> ConnectionRecord — lifecycle timestamps
type AuditBackfiller struct {
	ownerSpace string
	storage    *EncryptedStorage
	auditLog   *AuditLog
}

func NewAuditBackfiller(ownerSpace string, s *EncryptedStorage, a *AuditLog) *AuditBackfiller {
	return &AuditBackfiller{
		ownerSpace: ownerSpace,
		storage:    s,
		auditLog:   a,
	}
}

const auditBackfillMarkerPrefix = "connections/"
const auditBackfillMarkerSuffix = "/audit/_backfilled"

func backfillMarkerKey(connectionID string) string {
	return auditBackfillMarkerPrefix + connectionID + auditBackfillMarkerSuffix
}

// EnsureBackfilled runs the one-shot reconstruction the first time it's
// invoked for a connection. Subsequent calls are a single storage.Get
// check.
func (b *AuditBackfiller) EnsureBackfilled(connectionID string) error {
	if b == nil || b.storage == nil {
		return nil
	}
	marker := backfillMarkerKey(connectionID)
	if data, err := b.storage.Get(marker); err == nil && len(data) > 0 {
		return nil // already backfilled
	}

	log.Info().Str("connection_id", connectionID).Msg("audit backfill starting")
	start := time.Now()

	peerGuid := b.loadPeerGUID(connectionID)
	wrote := 0
	wrote += b.backfillLifecycle(connectionID, peerGuid)
	wrote += b.backfillMessages(connectionID, peerGuid)
	wrote += b.backfillFromFeed(connectionID, peerGuid)

	// Set marker even if we wrote nothing — an empty connection is a
	// valid state and we don't want to rerun on every read.
	if err := b.storage.Put(marker, []byte("1")); err != nil {
		log.Warn().Err(err).Str("connection_id", connectionID).
			Msg("audit backfill: failed to write marker (will retry next read)")
	}

	log.Info().
		Str("connection_id", connectionID).
		Int("entries", wrote).
		Dur("elapsed", time.Since(start)).
		Msg("audit backfill complete")
	return nil
}

// ----------------------------------------------------------------------
// Source: connection lifecycle timestamps
// ----------------------------------------------------------------------

func (b *AuditBackfiller) backfillLifecycle(connectionID, peerGuid string) int {
	data, err := b.storage.Get("connections/" + connectionID)
	if err != nil || len(data) == 0 {
		return 0
	}
	var rec ConnectionRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return 0
	}

	wrote := 0
	if !rec.CreatedAt.IsZero() {
		b.append(AuditEntry{
			ConnectionID: connectionID,
			PeerGUID:     peerGuid,
			EventType:    AuditTypeConnectionCreated,
			Direction:    AuditDirectionInternal,
			Title:        "Connection created",
			CreatedAt:    rec.CreatedAt.Unix(),
		})
		wrote++
	}
	if !rec.KeyExchangeAt.IsZero() {
		b.append(AuditEntry{
			ConnectionID: connectionID,
			PeerGUID:     peerGuid,
			EventType:    AuditTypeConnectionAccepted,
			Direction:    AuditDirectionInternal,
			Title:        "Connection activated",
			Body:         "End-to-end encryption established",
			CreatedAt:    rec.KeyExchangeAt.Unix(),
		})
		wrote++
	}
	if !rec.LastRotatedAt.IsZero() {
		b.append(AuditEntry{
			ConnectionID: connectionID,
			PeerGUID:     peerGuid,
			EventType:    AuditTypeConnectionRotated,
			Direction:    AuditDirectionInternal,
			Title:        "Connection keys rotated",
			CreatedAt:    rec.LastRotatedAt.Unix(),
		})
		wrote++
	}
	if rec.Status == "revoked" {
		b.append(AuditEntry{
			ConnectionID: connectionID,
			PeerGUID:     peerGuid,
			EventType:    AuditTypeConnectionRevoked,
			Direction:    AuditDirectionInternal,
			Title:        "Connection revoked",
			CreatedAt:    rec.CreatedAt.Unix(), // lifecycle timestamp unavailable; use create as placeholder
		})
		wrote++
	}
	return wrote
}

// ----------------------------------------------------------------------
// Source: stored messages
// ----------------------------------------------------------------------

// storedMessage is the minimum shape we rely on for backfill. The real
// MessageHandler schema carries more fields — we only need id / sender
// / preview / timestamp.
type storedMessage struct {
	MessageID   string `json:"message_id"`
	SenderGUID  string `json:"sender_guid"`
	Content     string `json:"content,omitempty"`
	Preview     string `json:"preview,omitempty"`
	SentAt      string `json:"sent_at,omitempty"`
	SentAtUnix  int64  `json:"sent_at_unix,omitempty"`
	ContentType string `json:"content_type,omitempty"`
}

func (b *AuditBackfiller) backfillMessages(connectionID, peerGuid string) int {
	// Messages live under messages/<connection_id>/_index → []message_id.
	idxBytes, err := b.storage.Get("messages/" + connectionID + "/_index")
	if err != nil || len(idxBytes) == 0 {
		return 0
	}
	var ids []string
	if err := json.Unmarshal(idxBytes, &ids); err != nil {
		return 0
	}

	wrote := 0
	for _, id := range ids {
		blob, err := b.storage.Get("messages/" + connectionID + "/" + id)
		if err != nil || len(blob) == 0 {
			continue
		}
		var m storedMessage
		if err := json.Unmarshal(blob, &m); err != nil {
			continue
		}

		direction := AuditDirectionInbound
		evtType := AuditTypeMessageReceived
		title := "Received a message"
		if m.SenderGUID == b.ownerSpace {
			direction = AuditDirectionOutbound
			evtType = AuditTypeMessageSent
			title = "Sent a message"
		}

		body := strings.TrimSpace(m.Preview)
		if body == "" {
			body = strings.TrimSpace(m.Content)
		}

		createdAt := m.SentAtUnix
		if createdAt == 0 && m.SentAt != "" {
			if t, err := time.Parse(time.RFC3339, m.SentAt); err == nil {
				createdAt = t.Unix()
			}
		}
		if createdAt == 0 {
			continue // no usable timestamp
		}

		b.append(AuditEntry{
			ConnectionID: connectionID,
			PeerGUID:     peerGuid,
			EventType:    evtType,
			Direction:    direction,
			Title:        title,
			Body:         body,
			CreatedAt:    createdAt,
			Refs: map[string]string{
				"message_id": id,
			},
		})
		wrote++
	}
	return wrote
}

// ----------------------------------------------------------------------
// Source: global feed events already in SQLite
// ----------------------------------------------------------------------

// backfillFromFeed scans the events table for entries that reference
// this connection and projects them onto the audit schema. Covers
// historical calls + transfers + security alerts for existing
// connections without requiring the event handlers themselves to be
// updated in lockstep.
func (b *AuditBackfiller) backfillFromFeed(connectionID, peerGuid string) int {
	sqlite := b.storage.SQLite()
	if sqlite == nil {
		return 0
	}
	events, err := sqlite.GetEventsSince(0, 5000, true)
	if err != nil {
		log.Warn().Err(err).Msg("audit backfill: feed scan failed")
		return 0
	}

	wrote := 0
	for _, ev := range events {
		if !feedEventBelongsToConnection(ev.SourceID, connectionID, peerGuid, ev.Payload) {
			continue
		}
		entry := projectFeedRecord(connectionID, peerGuid, ev)
		if entry == nil {
			continue
		}
		b.append(*entry)
		wrote++
	}
	return wrote
}

// feedEventBelongsToConnection matches the app-side logic: source id is
// either the connection id or the peer guid, or the payload blob
// mentions either (covers events whose own metadata carries the id).
func feedEventBelongsToConnection(sourceID, connectionID, peerGuid string, payload []byte) bool {
	if sourceID == connectionID {
		return true
	}
	if peerGuid != "" && sourceID == peerGuid {
		return true
	}
	s := string(payload)
	if strings.Contains(s, "\""+connectionID+"\"") {
		return true
	}
	if peerGuid != "" && strings.Contains(s, "\""+peerGuid+"\"") {
		return true
	}
	return false
}

// projectFeedRecord maps a stored feed event to an AuditEntry. Returns
// nil for event types we don't represent in the per-connection trail.
func projectFeedRecord(connectionID, peerGuid string, ev storage.EventRecord) *AuditEntry {
	var (
		evtType string
		refs    map[string]string
	)
	switch {
	case ev.EventType == "call.missed":
		evtType = AuditTypeCallVoiceMissed
	case ev.EventType == "call.completed":
		evtType = AuditTypeCallVoiceCompleted
	case strings.HasPrefix(ev.EventType, "call."):
		evtType = AuditTypeCallVoiceStarted
	case strings.HasPrefix(ev.EventType, "transfer.btc."):
		evtType = ev.EventType
	case ev.EventType == "security.alert":
		evtType = AuditTypeSecurityAlert
	case strings.HasPrefix(ev.EventType, "connection."):
		// Lifecycle covered by the connection record scan; skip here.
		return nil
	default:
		return nil
	}

	// Pull the human-readable title + body out of the encrypted payload
	// if it parses as the standard feed shape. Best-effort — we already
	// have a taxonomy fallback if the payload is opaque.
	title, body, meta := parseFeedPayload(ev.Payload)
	if title == "" {
		title = humanizeAuditType(evtType)
	}
	if strings.HasPrefix(evtType, "transfer.btc.") {
		refs = map[string]string{}
		if tx := meta["tx_id"]; tx != "" {
			refs["tx_id"] = tx
		}
	}

	return &AuditEntry{
		EntryID:      "backfill-" + ev.EventID,
		ConnectionID: connectionID,
		PeerGUID:     peerGuid,
		EventType:    evtType,
		Direction:    AuditDirectionInternal,
		Title:        title,
		Body:         body,
		CreatedAt:    ev.CreatedAt,
		Refs:         refs,
	}
}

// parseFeedPayload pulls the user-visible fields out of a feed event's
// JSON blob. Not all events share the same shape — we only care about
// the common { title, message, metadata } fields.
func parseFeedPayload(payload []byte) (title, body string, metadata map[string]string) {
	var shape struct {
		Title    string                 `json:"title"`
		Message  string                 `json:"message"`
		Metadata map[string]interface{} `json:"metadata"`
	}
	if err := json.Unmarshal(payload, &shape); err != nil {
		return "", "", nil
	}
	meta := map[string]string{}
	for k, v := range shape.Metadata {
		if s, ok := v.(string); ok {
			meta[k] = s
		}
	}
	return shape.Title, shape.Message, meta
}

func humanizeAuditType(t string) string {
	return strings.ReplaceAll(t, ".", " · ")
}

// ----------------------------------------------------------------------
// Shared helpers
// ----------------------------------------------------------------------

func (b *AuditBackfiller) loadPeerGUID(connectionID string) string {
	data, err := b.storage.Get("connections/" + connectionID)
	if err != nil || len(data) == 0 {
		return ""
	}
	var rec ConnectionRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return ""
	}
	return rec.PeerGUID
}

func (b *AuditBackfiller) append(entry AuditEntry) {
	b.auditLog.Append(entry)
}
