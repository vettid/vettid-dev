package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// Handler authorization state. The enclave's handler catalog declares
// what's POSSIBLE (immutable, attested). This file owns what the user
// has CHOSEN: which non-required handlers are enabled, which shareable
// handlers appear in their published profile, and which are exposed to
// each connection.
//
// Storage keys:
//   handlers/_state                       -> HandlerState (global toggles)
//   handlers/_per_connection/<conn_id>    -> ConnectionHandlerGrants
//
// All dispatch — owner-originated and peer-originated — passes through
// gateOperation(). System-category handlers bypass; everything else is
// fail-closed.

const (
	handlerStateKey               = "handlers/_state"
	handlerConnectionGrantsPrefix = "handlers/_per_connection/"
	handlerStateVersion           = 1
)

// Error codes returned by the gate. Stable wire identifiers — the app's
// OwnerSpaceClient maps these to UI strings.
const (
	HandlerErrDisabled         = "handler_disabled"
	HandlerErrRequired         = "handler_required"
	HandlerErrNotShareable     = "handler_not_shareable"
	HandlerErrNotSharedToPeer  = "handler_not_shared_with_peer"
	HandlerErrUnknown          = "handler_unknown"
)

// HandlerStateEntry is the per-handler user toggle pair.
type HandlerStateEntry struct {
	Enabled       bool `json:"enabled"`
	ShareGlobally bool `json:"share_globally"`
}

// HandlerState is the persisted user-wide handler toggle map.
type HandlerState struct {
	Version   int                          `json:"version"`
	Entries   map[string]HandlerStateEntry `json:"entries"`
	UpdatedAt int64                        `json:"updated_at"`
}

// ConnectionHandlerGrants is the persisted per-connection grant set.
// Granted narrows from HandlerState.ShareGlobally — you cannot grant a
// peer access to a handler you haven't globally shared.
type ConnectionHandlerGrants struct {
	ConnectionID string          `json:"connection_id"`
	Granted      map[string]bool `json:"granted"`
	UpdatedAt    int64           `json:"updated_at"`
}

// defaultHandlerState materialises the user's initial toggle map from
// the catalog. Required → enabled. Default → enabled. Optional → off.
// Shareable handlers default to share_globally=true so existing
// behaviour (all capabilities announced) is preserved; the user can
// narrow per-handler from the settings screen.
func defaultHandlerState() HandlerState {
	state := HandlerState{
		Version:   handlerStateVersion,
		Entries:   make(map[string]HandlerStateEntry),
		UpdatedAt: time.Now().Unix(),
	}
	for _, entry := range HandlerCatalog() {
		se := HandlerStateEntry{}
		switch {
		case entry.Required:
			se.Enabled = true
		case entry.Category == HandlerCategoryDefault:
			se.Enabled = true
		case entry.Category == HandlerCategorySystem:
			se.Enabled = true
		default: // optional
			se.Enabled = false
		}
		if entry.Shareable && se.Enabled {
			se.ShareGlobally = true
		}
		state.Entries[entry.ID] = se
	}
	return state
}

// loadHandlerAuthState reads handlers/_state from storage, materialising
// defaults if absent. Must be called after storage is unlocked (post-PIN).
// Caller holds handlerAuthMu for write.
func (mh *MessageHandler) loadHandlerAuthStateLocked() error {
	if mh.storage == nil {
		return fmt.Errorf("storage not initialized")
	}
	var state HandlerState
	err := mh.storage.GetJSON(handlerStateKey, &state)
	if err == ErrKeyNotFound {
		state = defaultHandlerState()
		if perr := mh.storage.PutJSON(handlerStateKey, &state); perr != nil {
			return fmt.Errorf("persist default handler state: %w", perr)
		}
	} else if err != nil {
		return fmt.Errorf("read handler state: %w", err)
	}
	// Catalog may have added entries since the state was persisted —
	// reconcile so new handlers pick up sensible defaults without
	// requiring a full reset.
	dirty := false
	if state.Entries == nil {
		state.Entries = map[string]HandlerStateEntry{}
		dirty = true
	}
	for _, entry := range HandlerCatalog() {
		if _, ok := state.Entries[entry.ID]; ok {
			continue
		}
		se := HandlerStateEntry{}
		switch {
		case entry.Required, entry.Category == HandlerCategorySystem, entry.Category == HandlerCategoryDefault:
			se.Enabled = true
		}
		if entry.Shareable && se.Enabled {
			se.ShareGlobally = true
		}
		state.Entries[entry.ID] = se
		dirty = true
	}
	if dirty {
		state.UpdatedAt = time.Now().Unix()
		if perr := mh.storage.PutJSON(handlerStateKey, &state); perr != nil {
			log.Warn().Err(perr).Msg("Failed to persist reconciled handler state")
		}
	}
	mh.handlerAuthState = &state
	mh.handlerAuthGrants = make(map[string]*ConnectionHandlerGrants)
	return nil
}

// refreshHandlerAuth reloads the cache from storage. Safe to call from
// any goroutine; takes the write lock.
func (mh *MessageHandler) refreshHandlerAuth() error {
	mh.handlerAuthMu.Lock()
	defer mh.handlerAuthMu.Unlock()
	return mh.loadHandlerAuthStateLocked()
}

// gateOperation enforces the handler-authorization contract.
//
//   source        = "owner" for forVault.* from the user's app, "peer" for
//                   incoming subjects from another vault.
//   connectionID  = "" for owner; the resolved connection_id for peers
//                   (use NotificationsHandler.FindConnectionByPeerGUID).
//
// Returns nil when the operation is authorized. Returns an error
// response (already shaped for the wire) when it must be rejected.
// Unknown roots return nil so the existing default branch in the
// dispatcher can produce its own "unknown operation" error.
func (mh *MessageHandler) gateOperation(operation, source, connectionID, msgID string) *OutgoingMessage {
	entry, ok := handlerCatalogLookup(operation)
	if !ok {
		return nil
	}
	if entry.Category == HandlerCategorySystem {
		return nil
	}

	mh.handlerAuthMu.RLock()
	state := mh.handlerAuthState
	mh.handlerAuthMu.RUnlock()
	if state == nil {
		// Fail closed. Any non-system op before the cache is hydrated is
		// rejected — system ops already returned above.
		resp, _ := mh.errorResponse(msgID, fmt.Sprintf("%s: vault state not initialized", HandlerErrDisabled))
		return resp
	}

	se, hasState := state.Entries[operation]
	if !hasState {
		// New catalog entry that the persisted state hasn't yet absorbed.
		// Fall back to the catalog's category default.
		se.Enabled = entry.Category == HandlerCategoryDefault || entry.Required
	}
	if !se.Enabled {
		resp, _ := mh.errorResponse(msgID, fmt.Sprintf("%s: %s is turned off in your vault", HandlerErrDisabled, entry.Name))
		return resp
	}

	if source == "peer" {
		if !entry.Shareable {
			resp, _ := mh.errorResponse(msgID, fmt.Sprintf("%s: %s cannot be invoked by peers", HandlerErrNotShareable, entry.ID))
			return resp
		}
		if !mh.isHandlerGrantedToConnection(operation, connectionID) {
			resp, _ := mh.errorResponse(msgID, fmt.Sprintf("%s: %s not exposed to this connection", HandlerErrNotSharedToPeer, entry.ID))
			return resp
		}
	}
	return nil
}

// handlerCatalogLookup returns the catalog entry for a dispatch root.
// Built fresh each call — the catalog is small (<50 entries) and gates
// run on a hot path; benchmark before caching across calls.
func handlerCatalogLookup(id string) (HandlerCatalogEntry, bool) {
	for _, e := range HandlerCatalog() {
		if e.ID == id {
			return e, true
		}
	}
	return HandlerCatalogEntry{}, false
}

// setHandlerEnabled flips the user's per-handler enable state. Required
// handlers cannot be disabled; the gate would still let them through but
// rejecting up-front gives the app a clean error path.
func (mh *MessageHandler) setHandlerEnabled(id string, enabled bool) error {
	entry, ok := handlerCatalogLookup(id)
	if !ok {
		return fmt.Errorf("%s: %s", HandlerErrUnknown, id)
	}
	if entry.Required && !enabled {
		return fmt.Errorf("%s: %s cannot be disabled", HandlerErrRequired, entry.Name)
	}

	mh.handlerAuthMu.Lock()
	defer mh.handlerAuthMu.Unlock()
	if mh.handlerAuthState == nil {
		if err := mh.loadHandlerAuthStateLocked(); err != nil {
			return err
		}
	}
	se := mh.handlerAuthState.Entries[id]
	se.Enabled = enabled
	if !enabled {
		// Disabling forces share_globally off — you can't share what's
		// off. Re-enabling does NOT auto-restore share_globally; the
		// user re-opts-in explicitly.
		se.ShareGlobally = false
	}
	mh.handlerAuthState.Entries[id] = se
	mh.handlerAuthState.UpdatedAt = time.Now().Unix()
	return mh.storage.PutJSON(handlerStateKey, mh.handlerAuthState)
}

// setHandlerShareGlobal flips the user's "show this handler in my public
// profile" toggle. Only meaningful for catalog entries with Shareable=true.
func (mh *MessageHandler) setHandlerShareGlobal(id string, share bool) error {
	entry, ok := handlerCatalogLookup(id)
	if !ok {
		return fmt.Errorf("%s: %s", HandlerErrUnknown, id)
	}
	if !entry.Shareable && share {
		return fmt.Errorf("%s: %s is not shareable", HandlerErrNotShareable, entry.Name)
	}

	mh.handlerAuthMu.Lock()
	defer mh.handlerAuthMu.Unlock()
	if mh.handlerAuthState == nil {
		if err := mh.loadHandlerAuthStateLocked(); err != nil {
			return err
		}
	}
	se := mh.handlerAuthState.Entries[id]
	if !se.Enabled && share {
		return fmt.Errorf("%s: %s is disabled — enable it before sharing", HandlerErrDisabled, entry.Name)
	}
	se.ShareGlobally = share
	mh.handlerAuthState.Entries[id] = se
	mh.handlerAuthState.UpdatedAt = time.Now().Unix()
	return mh.storage.PutJSON(handlerStateKey, mh.handlerAuthState)
}

// snapshotHandlerState returns a copy of the current state for read-only
// callers (handlers.list, handlers.get-state, profile_builder).
func (mh *MessageHandler) snapshotHandlerState() HandlerState {
	mh.handlerAuthMu.RLock()
	defer mh.handlerAuthMu.RUnlock()
	if mh.handlerAuthState == nil {
		return defaultHandlerState()
	}
	out := HandlerState{
		Version:   mh.handlerAuthState.Version,
		Entries:   make(map[string]HandlerStateEntry, len(mh.handlerAuthState.Entries)),
		UpdatedAt: mh.handlerAuthState.UpdatedAt,
	}
	for k, v := range mh.handlerAuthState.Entries {
		out.Entries[k] = v
	}
	return out
}

// connectionGrantsKey returns the storage key for a connection's grant blob.
func connectionGrantsKey(connectionID string) string {
	return handlerConnectionGrantsPrefix + connectionID
}

// getConnectionGrants returns the cached grants for a connection,
// loading from storage if necessary. If neither cache nor storage have
// the blob, the function seeds defaults from the user's current
// share_globally set (so a freshly-activated connection sees every
// handler the owner publishes globally). Caller holds no lock.
func (mh *MessageHandler) getConnectionGrants(connectionID string) (*ConnectionHandlerGrants, error) {
	if connectionID == "" {
		return nil, fmt.Errorf("missing connection_id")
	}

	mh.handlerAuthMu.RLock()
	if mh.handlerAuthGrants != nil {
		if cached, ok := mh.handlerAuthGrants[connectionID]; ok {
			mh.handlerAuthMu.RUnlock()
			return cached, nil
		}
	}
	mh.handlerAuthMu.RUnlock()

	// Slow path — load from storage.
	mh.handlerAuthMu.Lock()
	defer mh.handlerAuthMu.Unlock()
	if mh.handlerAuthGrants == nil {
		mh.handlerAuthGrants = make(map[string]*ConnectionHandlerGrants)
	}
	if cached, ok := mh.handlerAuthGrants[connectionID]; ok {
		return cached, nil
	}

	var grants ConnectionHandlerGrants
	err := mh.storage.GetJSON(connectionGrantsKey(connectionID), &grants)
	if err == ErrKeyNotFound {
		// Seed defaults from current globally-shared set.
		grants = ConnectionHandlerGrants{
			ConnectionID: connectionID,
			Granted:      make(map[string]bool),
			UpdatedAt:    time.Now().Unix(),
		}
		if mh.handlerAuthState != nil {
			for _, entry := range HandlerCatalog() {
				if !entry.Shareable {
					continue
				}
				se := mh.handlerAuthState.Entries[entry.ID]
				if se.Enabled && se.ShareGlobally {
					grants.Granted[entry.ID] = true
				}
			}
		}
		if perr := mh.storage.PutJSON(connectionGrantsKey(connectionID), &grants); perr != nil {
			log.Warn().Err(perr).Str("connection_id", connectionID).Msg("Failed to persist seeded handler grants")
		}
	} else if err != nil {
		return nil, fmt.Errorf("read connection grants: %w", err)
	}
	mh.handlerAuthGrants[connectionID] = &grants
	return &grants, nil
}

// setConnectionGrants writes the per-connection grant blob. Validates
// that every granted ID is currently in the user's globally-shared set —
// you cannot grant per-connection what you haven't globally shared.
func (mh *MessageHandler) setConnectionGrants(connectionID string, granted map[string]bool) error {
	if connectionID == "" {
		return fmt.Errorf("missing connection_id")
	}

	mh.handlerAuthMu.Lock()
	defer mh.handlerAuthMu.Unlock()
	if mh.handlerAuthState == nil {
		if err := mh.loadHandlerAuthStateLocked(); err != nil {
			return err
		}
	}
	for id, on := range granted {
		entry, ok := handlerCatalogLookup(id)
		if !ok {
			return fmt.Errorf("%s: %s", HandlerErrUnknown, id)
		}
		if !on {
			continue
		}
		if !entry.Shareable {
			return fmt.Errorf("%s: %s", HandlerErrNotShareable, id)
		}
		se := mh.handlerAuthState.Entries[id]
		if !se.Enabled || !se.ShareGlobally {
			return fmt.Errorf("%s: %s is not in your globally-shared set", HandlerErrDisabled, id)
		}
	}

	grants := &ConnectionHandlerGrants{
		ConnectionID: connectionID,
		Granted:      make(map[string]bool, len(granted)),
		UpdatedAt:    time.Now().Unix(),
	}
	for k, v := range granted {
		if v {
			grants.Granted[k] = true
		}
	}
	if err := mh.storage.PutJSON(connectionGrantsKey(connectionID), grants); err != nil {
		return err
	}
	if mh.handlerAuthGrants == nil {
		mh.handlerAuthGrants = make(map[string]*ConnectionHandlerGrants)
	}
	mh.handlerAuthGrants[connectionID] = grants

	// Phase 2: also write through to the SharePolicy so the unified
	// gate sees the same decision as the legacy Handlers dialog.
	policyItems := make(map[string]SharePolicyItem, len(granted))
	for id, on := range granted {
		policyItems[sharePolicyKey(SharePolicyKindHandler, id)] = SharePolicyItem{
			Allowed: on,
			Tier:    "on_demand",
		}
	}
	if err := MergePolicyItems(mh.storage, connectionID, policyItems); err != nil {
		log.Warn().Err(err).Str("connection_id", connectionID).Msg("setConnectionGrants: SharePolicy mirror failed (non-fatal)")
	}
	return nil
}

// seedConnectionGrants is called from connections.go when a new
// connection activates. Seeds the grant blob from the current
// globally-shared set so the peer immediately has access to every
// shareable handler the user publishes globally.
func (mh *MessageHandler) seedConnectionGrants(connectionID string) error {
	if connectionID == "" {
		return nil
	}
	// Fast path: check if it already exists. If so, leave it alone —
	// re-seeding would clobber any narrowing the user has already done.
	mh.handlerAuthMu.RLock()
	if mh.handlerAuthGrants != nil {
		if _, ok := mh.handlerAuthGrants[connectionID]; ok {
			mh.handlerAuthMu.RUnlock()
			return nil
		}
	}
	mh.handlerAuthMu.RUnlock()
	if mh.storage != nil {
		var existing ConnectionHandlerGrants
		if err := mh.storage.GetJSON(connectionGrantsKey(connectionID), &existing); err == nil {
			return nil // already seeded
		}
	}
	_, err := mh.getConnectionGrants(connectionID)
	return err
}

// clearConnectionGrants is called from connections.go when a connection
// is revoked. Removes both cache and storage so a future re-pair starts
// from the current global defaults.
func (mh *MessageHandler) clearConnectionGrants(connectionID string) {
	if connectionID == "" {
		return
	}
	mh.handlerAuthMu.Lock()
	defer mh.handlerAuthMu.Unlock()
	if mh.handlerAuthGrants != nil {
		delete(mh.handlerAuthGrants, connectionID)
	}
	if mh.storage != nil {
		_ = mh.storage.Delete(connectionGrantsKey(connectionID))
	}
}

// isHandlerGrantedToConnection answers the per-connection gate question.
// Phase 2 of the sharing-and-contracts plan makes SharePolicy the
// authoritative store; the legacy ConnectionHandlerGrants blob is the
// read-through fallback for connections that haven't been re-seeded yet.
// Errors fail closed.
func (mh *MessageHandler) isHandlerGrantedToConnection(handlerID, connectionID string) bool {
	if connectionID == "" {
		// No connection context — peer message arrived but we couldn't
		// resolve which connection it came from. Reject.
		return false
	}
	if policy := loadSharePolicy(mh.storage, connectionID); policy != nil {
		key := sharePolicyKey(SharePolicyKindHandler, handlerID)
		if item, ok := policy.Items[key]; ok {
			// Explicit per-connection decision wins. Honour expiry.
			if item.ExpiresAt > 0 && item.ExpiresAt < time.Now().Unix() {
				return false
			}
			return item.Allowed
		}
		// No explicit policy item: fall back to the user's global
		// share-state. A handler the user has marked share_globally
		// remains granted to every active connection unless the user
		// explicitly toggles it off for this peer in the editor.
		mh.handlerAuthMu.RLock()
		state := mh.handlerAuthState
		mh.handlerAuthMu.RUnlock()
		if state != nil {
			se := state.Entries[handlerID]
			if se.Enabled && se.ShareGlobally {
				return true
			}
		}
		return false
	}
	grants, err := mh.getConnectionGrants(connectionID)
	if err != nil || grants == nil {
		log.Warn().Err(err).
			Str("handler_id", handlerID).
			Str("connection_id", connectionID).
			Msg("Failed to load connection grants — failing closed")
		return false
	}
	return grants.Granted[handlerID]
}

// handlersStateResponseEntry is the merged catalog + state shape returned
// by handlers.list and handlers.get-state.
type handlersStateResponseEntry struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Description   string   `json:"description,omitempty"`
	Operations    []string `json:"operations,omitempty"`
	Category      string   `json:"category"`
	Required      bool     `json:"required"`
	Shareable     bool     `json:"shareable"`
	Enabled       bool     `json:"enabled"`
	ShareGlobally bool     `json:"share_globally"`
}

// buildHandlersStateResponse merges the catalog with the user's state
// and returns the slice for handlers.list / handlers.get-state. Only
// surfaced (user-visible) entries are included.
func (mh *MessageHandler) buildHandlersStateResponse() []handlersStateResponseEntry {
	state := mh.snapshotHandlerState()
	out := make([]handlersStateResponseEntry, 0)
	for _, entry := range HandlerCatalog() {
		if !entry.Surfaced {
			continue
		}
		se := state.Entries[entry.ID]
		out = append(out, handlersStateResponseEntry{
			ID:            entry.ID,
			Name:          entry.Name,
			Description:   entry.Description,
			Operations:    entry.Operations,
			Category:      entry.Category,
			Required:      entry.Required,
			Shareable:     entry.Shareable,
			Enabled:       se.Enabled,
			ShareGlobally: se.ShareGlobally,
		})
	}
	return out
}

// gatePeerSubject is the gate entry-point for peer-originated subjects.
// Extracts the sender GUID from the payload (best-effort, multiple
// schemas), resolves the connection, and runs gateOperation. Returns
// nil when authorized; an error response otherwise. If the operation
// isn't peer-gated, returns nil.
func (mh *MessageHandler) gatePeerSubject(operation string, payload []byte, msgID string) *OutgoingMessage {
	handlerID := peerHandlerForIncomingSubject(operation)
	if handlerID == "" {
		return nil
	}
	senderGUID := extractSenderGUID(payload)
	connID := ""
	if senderGUID != "" && mh.notificationsHandler != nil {
		connID = mh.notificationsHandler.FindConnectionByPeerGUID(senderGUID)
	}
	return mh.gateOperation(handlerID, "peer", connID, msgID)
}

// isValidOwnerSpace returns true when the value is shaped like a
// UUID-style owner-space identifier and contains no characters that
// could escape a NATS subject when interpolated.
//
// SECURITY (injection-#1): peer-controlled OwnerSpace fields land in
// fmt.Sprintf("MessageSpace.%s.forOwner.*", peer). NATS subject tokens
// are dot-delimited; a peer that smuggles a `.` or `>` in their owner
// space would publish to a subject the receiver never authorized.
// Constrain to lowercase hex + hyphens (the shape uuid.New() emits).
//
// We don't strictly require canonical 36-char UUID — agents and
// devices use shorter GUID variants — but we reject anything outside
// [a-zA-Z0-9-_], non-empty, and length-bounded.
func isValidOwnerSpace(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_':
		default:
			return false
		}
	}
	return true
}

// extractSenderGUID looks for a sender identifier in a peer payload.
// Tries the field names used by the various payload schemas. Returns
// "" if none are present.
//
// SECURITY (A4/H2): `owner_space` is intentionally excluded from the
// candidate list. The audit found that including it let a peer pick
// a wrong connection_id by setting `owner_space` to another peer's
// GUID — `FindConnectionByPeerGUID` would resolve to the wrong
// record and the gate would consult the wrong connection's policy.
// The remaining keys are sender-shaped fields the schemas reserve
// for the actual sender. Even these are still attacker-controlled
// at this layer; the gate that follows is one of several defense
// layers (the tighter authentication is the per-message MAC + the
// authenticated-subject derivation, both being added separately).
func extractSenderGUID(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(payload, &probe); err != nil {
		return ""
	}
	for _, key := range []string{"sender_guid", "reader_guid", "from_user_guid", "from_owner_space", "fromOwnerSpace", "sender"} {
		if raw, ok := probe[key]; ok {
			var s string
			if err := json.Unmarshal(raw, &s); err == nil && s != "" {
				return s
			}
		}
	}
	return ""
}

// peerHandlerForIncomingSubject maps the operation token of an incoming
// peer subject to the catalog handler ID that gates it. Returns "" if
// the subject is not peer-gated (e.g. a system internal).
func peerHandlerForIncomingSubject(operation string) string {
	switch operation {
	case "new-message", "read-receipt":
		return "message"
	case "location-update", "location-stop", "location-request-ping":
		return "location"
	case "btc-address-request", "btc-payment-request", "btc-payment-receipt", "btc-address-response":
		return "wallet"
	case "profile-update":
		return "profile"
	case "revoked":
		return "connection"
	}
	if strings.HasPrefix(operation, "presence.") {
		return "presence"
	}
	// Reference-based data-sharing peer ops (plans/data-request-grants.md).
	// Gated under the "grant" handler — the user can toggle data
	// sharing per-connection without affecting messaging / calls / etc.
	if operation == "data.request" || strings.HasPrefix(operation, "data.grant.") {
		return "grant"
	}
	// Critical-secret use-on-my-behalf (plans/data-request-grants.md
	// Phase 6) is its own handler so users can disable "let peers ask
	// me to sign / decrypt" independently of normal data sharing.
	if strings.HasPrefix(operation, "critical_secret.") {
		return "critical-secret-use"
	}
	// connection.authenticate is gated by the connection handler — if
	// you've severed a connection you don't want to be challenged or
	// to be able to challenge.
	if strings.HasPrefix(operation, "connection.authenticate.") {
		return "connection"
	}
	return ""
}

// parseHandlerToggleRequest extracts {handler_id, enabled} or
// {handler_id, share_globally} from the request payload.
func parseHandlerToggleRequest(payload []byte) (handlerID string, value bool, valueKey string, err error) {
	var req map[string]json.RawMessage
	if err = json.Unmarshal(payload, &req); err != nil {
		return "", false, "", fmt.Errorf("invalid handler toggle payload: %w", err)
	}
	if raw, ok := req["handler_id"]; ok {
		if err = json.Unmarshal(raw, &handlerID); err != nil {
			return "", false, "", fmt.Errorf("handler_id must be string")
		}
	}
	if handlerID == "" {
		return "", false, "", fmt.Errorf("missing handler_id")
	}
	for _, k := range []string{"enabled", "share_globally"} {
		if raw, ok := req[k]; ok {
			if err = json.Unmarshal(raw, &value); err != nil {
				return "", false, "", fmt.Errorf("%s must be boolean", k)
			}
			valueKey = k
			return handlerID, value, valueKey, nil
		}
	}
	return "", false, "", fmt.Errorf("missing enabled or share_globally")
}
