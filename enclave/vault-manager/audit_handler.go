package main

import (
	"encoding/json"

	"github.com/rs/zerolog/log"
	"github.com/vettid/vettid-dev/enclave/vault-manager/storage"
)

// AuditHandler serves the connection.audit.* RPCs. Read-only — writes
// happen inline in the handlers that produce the underlying events, via
// AuditLog.Append.
type AuditHandler struct {
	ownerSpace string
	auditLog   *AuditLog
	backfill   *AuditBackfiller
}

// NewAuditHandler constructs the handler. A non-nil AuditLog is
// required; the backfiller may be nil until backfill support lands.
func NewAuditHandler(ownerSpace string, auditLog *AuditLog, backfill *AuditBackfiller) *AuditHandler {
	return &AuditHandler{
		ownerSpace: ownerSpace,
		auditLog:   auditLog,
		backfill:   backfill,
	}
}

// ----------------------------------------------------------------------
// Request / response types
// ----------------------------------------------------------------------

type AuditListRequest struct {
	ConnectionID    string   `json:"connection_id"`
	Limit           int      `json:"limit,omitempty"`
	CursorCreatedAt int64    `json:"cursor_created_at,omitempty"`
	CursorEntryID   string   `json:"cursor_entry_id,omitempty"`
	SinceEpoch      int64    `json:"since_epoch,omitempty"`
	EventTypes      []string `json:"event_types,omitempty"`
}

type AuditSearchRequest struct {
	ConnectionID    string   `json:"connection_id"`
	Query           string   `json:"query"`
	Limit           int      `json:"limit,omitempty"`
	CursorCreatedAt int64    `json:"cursor_created_at,omitempty"`
	CursorEntryID   string   `json:"cursor_entry_id,omitempty"`
	EventTypes      []string `json:"event_types,omitempty"`
}

type AuditListResponse struct {
	Entries       []AuditEntry `json:"entries"`
	NextCursor    *AuditCursor `json:"next_cursor,omitempty"`
	TotalEstimate int          `json:"total_estimate"`
}

type AuditCursor struct {
	CreatedAt int64  `json:"created_at"`
	EntryID   string `json:"entry_id"`
}

// ----------------------------------------------------------------------
// Handlers
// ----------------------------------------------------------------------

// HandleList serves connection.audit.list. Newest entries first.
func (h *AuditHandler) HandleList(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req AuditListRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleAuditList"); err != nil {
		return h.errorResponse(msg.GetID(), "invalid request")
	}
	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	// Lazy backfill — first read of a connection's audit synthesizes
	// historical entries from messages + feed + lifecycle so existing
	// connections aren't blank on the first load after the feature
	// ships. Noop on subsequent reads.
	if h.backfill != nil {
		if err := h.backfill.EnsureBackfilled(req.ConnectionID); err != nil {
			log.Warn().Err(err).Str("connection_id", req.ConnectionID).
				Msg("audit backfill failed — continuing with whatever's already indexed")
		}
	}

	entries, cursor, err := h.auditLog.List(storage.AuditListOptions{
		ConnectionID:      req.ConnectionID,
		Limit:             req.Limit,
		CursorCreatedAt:   req.CursorCreatedAt,
		CursorEntryID:     req.CursorEntryID,
		SinceEpoch:        req.SinceEpoch,
		EventTypePrefixes: req.EventTypes,
	})
	if err != nil {
		log.Warn().Err(err).Str("connection_id", req.ConnectionID).Msg("audit list failed")
		return h.errorResponse(msg.GetID(), "failed to list audit entries")
	}

	total, _ := h.auditLog.Count(req.ConnectionID)
	return h.respond(msg.GetID(), entries, cursor, total)
}

// HandleSearch serves connection.audit.search. Empty query degrades to
// a plain list (see storage.SearchAuditEntries).
func (h *AuditHandler) HandleSearch(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req AuditSearchRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleAuditSearch"); err != nil {
		return h.errorResponse(msg.GetID(), "invalid request")
	}
	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	if h.backfill != nil {
		if err := h.backfill.EnsureBackfilled(req.ConnectionID); err != nil {
			log.Warn().Err(err).Str("connection_id", req.ConnectionID).
				Msg("audit backfill failed — continuing with whatever's already indexed")
		}
	}

	entries, cursor, err := h.auditLog.Search(storage.AuditSearchOptions{
		ConnectionID:      req.ConnectionID,
		Query:             req.Query,
		Limit:             req.Limit,
		CursorCreatedAt:   req.CursorCreatedAt,
		CursorEntryID:     req.CursorEntryID,
		EventTypePrefixes: req.EventTypes,
	})
	if err != nil {
		log.Warn().Err(err).Str("connection_id", req.ConnectionID).Msg("audit search failed")
		return h.errorResponse(msg.GetID(), "failed to search audit entries")
	}

	total, _ := h.auditLog.Count(req.ConnectionID)
	return h.respond(msg.GetID(), entries, cursor, total)
}

// ----------------------------------------------------------------------
// helpers
// ----------------------------------------------------------------------

func (h *AuditHandler) respond(requestID string, entries []AuditEntry, cursor *storage.AuditCursor, total int) (*OutgoingMessage, error) {
	resp := AuditListResponse{
		Entries:       entries,
		TotalEstimate: total,
	}
	if cursor != nil {
		resp.NextCursor = &AuditCursor{
			CreatedAt: cursor.CreatedAt,
			EntryID:   cursor.EntryID,
		}
	}

	payload, err := json.Marshal(resp)
	if err != nil {
		return h.errorResponse(requestID, "failed to marshal response")
	}
	return &OutgoingMessage{
		RequestID: requestID,
		Type:      MessageTypeResponse,
		Payload:   payload,
	}, nil
}

func (h *AuditHandler) errorResponse(requestID, msg string) (*OutgoingMessage, error) {
	return &OutgoingMessage{
		RequestID: requestID,
		Type:      MessageTypeError,
		Error:     msg,
	}, nil
}
