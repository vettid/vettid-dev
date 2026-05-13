package main

// Persistent verify-identity state cache. Mirrors the location cache
// pattern (location.go's peerLocationCacheKey) — one storage row per
// connection holds the last verify outcome in both directions so the
// Connection Detail UI can render "Verified 3 minutes ago" / "Not yet
// verified" without round-tripping the peer on every screen entry.
//
// Storage keys:
//   connections/<connID>/_verify_state  →  CachedVerifyState (JSON)
//
// The state survives PIN-lock and re-seal — it's part of vault state
// and re-encrypted on every persist. No TTL: the timestamp is the
// freshness signal, and the UI decides how long counts as "recent."

import (
	"context"
	"encoding/json"
	"time"

	"github.com/rs/zerolog/log"
)

// verifyStateKey is the per-connection storage row for cached verify
// outcomes. Matches the peerLocationCacheKey naming so the storage
// layout stays scannable.
func verifyStateKey(connID string) string {
	return "connections/" + connID + "/_verify_state"
}

// CachedVerifyState carries the last verify-identity outcome for a
// connection in both directions. "Outbound" = we challenged them and
// got a response. "Inbound" = they challenged us and we responded.
// The Detail screen primarily renders the Outbound fields ("when did I
// last verify them?") but both are stored so the same state can power
// per-side audit displays without a second round-trip.
type CachedVerifyState struct {
	// Outbound: we asked the peer to prove their identity.
	LastOutboundAt     string `json:"last_outbound_at,omitempty"`
	LastOutboundOk     bool   `json:"last_outbound_ok"`
	LastOutboundReason string `json:"last_outbound_reason,omitempty"`
	LastOutboundReqID  string `json:"last_outbound_request_id,omitempty"`

	// Inbound: the peer asked us to prove our identity.
	LastInboundAt     string `json:"last_inbound_at,omitempty"`
	LastInboundOk     bool   `json:"last_inbound_ok"`
	LastInboundReason string `json:"last_inbound_reason,omitempty"`
	LastInboundReqID  string `json:"last_inbound_request_id,omitempty"`
}

// recordVerifyOutbound updates the outbound side of the verify-state
// row. Called from HandleIncomingAuthResponse once a peer's verdict has
// been processed (verified, denied_by_user, identity_locked, or any
// failure reason). Best-effort — a write failure logs but never blocks
// the caller's response path.
func (mh *MessageHandler) recordVerifyOutbound(connID, requestID, reason string, ok bool) {
	if connID == "" {
		return
	}
	state := mh.loadVerifyState(connID)
	state.LastOutboundAt = time.Now().UTC().Format(time.RFC3339)
	state.LastOutboundOk = ok
	state.LastOutboundReason = reason
	state.LastOutboundReqID = requestID
	mh.saveVerifyState(connID, state)
}

// recordVerifyInbound updates the inbound side of the verify-state row.
// Called from HandleApproveVerify (ok=true) and HandleDenyVerify (ok=false).
func (mh *MessageHandler) recordVerifyInbound(connID, requestID, reason string, ok bool) {
	if connID == "" {
		return
	}
	state := mh.loadVerifyState(connID)
	state.LastInboundAt = time.Now().UTC().Format(time.RFC3339)
	state.LastInboundOk = ok
	state.LastInboundReason = reason
	state.LastInboundReqID = requestID
	mh.saveVerifyState(connID, state)
}

func (mh *MessageHandler) loadVerifyState(connID string) CachedVerifyState {
	var state CachedVerifyState
	if data, err := mh.storage.Get(verifyStateKey(connID)); err == nil && len(data) > 0 {
		_ = json.Unmarshal(data, &state)
	}
	return state
}

func (mh *MessageHandler) saveVerifyState(connID string, state CachedVerifyState) {
	data, err := json.Marshal(&state)
	if err != nil {
		log.Warn().Err(err).Str("connection_id", connID).Msg("verify state marshal failed")
		return
	}
	if err := mh.storage.Put(verifyStateKey(connID), data); err != nil {
		log.Warn().Err(err).Str("connection_id", connID).Msg("verify state persist failed")
	}
}

// VerifyStateGetRequest fetches the cached verify state for one
// connection. Mirrors LocationPeerGetRequest.
type VerifyStateGetRequest struct {
	ConnectionID string `json:"connection_id"`
}

type VerifyStateGetResponse struct {
	State *CachedVerifyState `json:"state,omitempty"`
}

// HandleVerifyStateGet serves connection-authenticate.get — returns
// the cached state for a single connection. Returns an empty state
// (not an error) when no verify exchanges have happened yet.
func (mh *MessageHandler) HandleVerifyStateGet(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req VerifyStateGetRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleVerifyStateGet"); err != nil {
		return mh.errorResponse(msg.GetID(), "invalid request format")
	}
	if req.ConnectionID == "" {
		return mh.errorResponse(msg.GetID(), "connection_id is required")
	}
	state := mh.loadVerifyState(req.ConnectionID)
	resp := VerifyStateGetResponse{State: &state}
	respBytes, _ := json.Marshal(&resp)
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// VerifyStateListEntry is one connection's worth of cached state in
// the list response. ConnectionID is echoed so the app can map the
// list into its in-memory connection collection.
type VerifyStateListEntry struct {
	ConnectionID string            `json:"connection_id"`
	State        CachedVerifyState `json:"state"`
}

type VerifyStateListResponse struct {
	Entries []VerifyStateListEntry `json:"entries"`
}

// HandleVerifyStateList serves connection-authenticate.list — returns
// cached state for every connection that has one. The connection list
// view uses this to render badges without N round-trips. Reads the
// canonical "connections/_index" array (same as connection.list).
func (mh *MessageHandler) HandleVerifyStateList(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	indexData, err := mh.storage.Get("connections/_index")
	var connIDs []string
	if err == nil && len(indexData) > 0 {
		_ = json.Unmarshal(indexData, &connIDs)
	}
	out := make([]VerifyStateListEntry, 0, len(connIDs))
	for _, connID := range connIDs {
		data, err := mh.storage.Get(verifyStateKey(connID))
		if err != nil || len(data) == 0 {
			continue
		}
		var state CachedVerifyState
		if err := json.Unmarshal(data, &state); err != nil {
			continue
		}
		out = append(out, VerifyStateListEntry{
			ConnectionID: connID,
			State:        state,
		})
	}
	respBytes, _ := json.Marshal(&VerifyStateListResponse{Entries: out})
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}
