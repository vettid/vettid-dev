package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// PresenceHandler runs the user's opt-in presence broadcast loop and
// handles incoming presence heartbeats from peer vaults. See
// plans/luminous-unifying-manatee.md §15 for the full design.
//
// Phase 1 is two-state: "online" when the vault is running and the
// user's effective broadcast flag is true for that connection; absence
// otherwise. The observer infers offline from heartbeat absence — the
// lack of a signal is not itself an informational channel.
type PresenceHandler struct {
	ownerSpace  string
	storage     *EncryptedStorage
	publisher   *VsockPublisher
	connections *ConnectionsHandler

	// Background heartbeat control
	tickerMu sync.Mutex
	ticker   *time.Ticker
	done     chan struct{}
}

const (
	presenceSettingsKey = "settings/presence"
	presenceInterval    = 30 * time.Second
)

// PresenceSettings holds the user-wide presence-share default plus
// any future user-level presence preferences.
type PresenceSettings struct {
	// ShareDefault is the default value for presence broadcasting.
	// Per-connection overrides on ConnectionRecord take precedence.
	ShareDefault bool `json:"share_default"`
}

// PresenceHeartbeat is the wire payload for a single "I'm online"
// signal. Peer vault republishes it to the observer's app.
type PresenceHeartbeat struct {
	ConnectionID string `json:"connection_id"`
	Status       string `json:"status"` // "online"
	At           int64  `json:"at"`     // unix seconds
}

// NewPresenceHandler wires up storage + publisher + connections
// access. Call StartHeartbeat after the vault has unlocked so the
// loop can see real connection records.
func NewPresenceHandler(ownerSpace string, storage *EncryptedStorage, publisher *VsockPublisher, connections *ConnectionsHandler) *PresenceHandler {
	return &PresenceHandler{
		ownerSpace:  ownerSpace,
		storage:     storage,
		publisher:   publisher,
		connections: connections,
	}
}

// GetSettings returns the current user-wide presence settings. Lazily
// initializes with defaults (opt-in = false) on first read.
func (h *PresenceHandler) GetSettings() PresenceSettings {
	var settings PresenceSettings
	if err := h.storage.GetJSON(presenceSettingsKey, &settings); err != nil {
		// Missing / unreadable → defaults (share_default=false).
		return PresenceSettings{ShareDefault: false}
	}
	return settings
}

// SaveSettings persists the user-wide presence settings.
func (h *PresenceHandler) SaveSettings(settings PresenceSettings) error {
	return h.storage.PutJSON(presenceSettingsKey, &settings)
}

// effectiveShare resolves the broadcast decision for a single
// connection: per-connection override wins over the user default.
func (h *PresenceHandler) effectiveShare(record *ConnectionRecord, defaults PresenceSettings) bool {
	if record.PresenceShareOverride != nil {
		return *record.PresenceShareOverride
	}
	return defaults.ShareDefault
}

// HandleSettingsGet returns the user-wide presence settings.
func (h *PresenceHandler) HandleSettingsGet(msg *IncomingMessage) (*OutgoingMessage, error) {
	settings := h.GetSettings()
	data, err := json.Marshal(settings)
	if err != nil {
		return h.errorResponse(msg.GetID(), "failed to serialize settings")
	}
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   data,
	}, nil
}

// HandleSetDefault updates the user-wide presence share default.
// Payload: {"share_default": bool}
func (h *PresenceHandler) HandleSetDefault(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		ShareDefault bool `json:"share_default"`
	}
	if err := unmarshalRequest(msg.Payload, &req, "HandleSetDefault"); err != nil {
		return h.errorResponse(msg.GetID(), "invalid request format")
	}
	settings := h.GetSettings()
	settings.ShareDefault = req.ShareDefault
	if err := h.SaveSettings(settings); err != nil {
		return h.errorResponse(msg.GetID(), "failed to save settings")
	}
	log.Info().Bool("share_default", req.ShareDefault).Msg("Presence share default updated")
	return okResponse(msg.GetID())
}

// HandleSetOverride updates the per-connection presence override.
// Payload: {"connection_id": "...", "override": true|false|null}
// Passing null (omitting the field, or sending explicit JSON null)
// clears the override so the connection follows the user default.
func (h *PresenceHandler) HandleSetOverride(msg *IncomingMessage) (*OutgoingMessage, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(msg.Payload, &raw); err != nil {
		return h.errorResponse(msg.GetID(), "invalid request format")
	}
	connIDRaw, ok := raw["connection_id"]
	if !ok {
		return h.errorResponse(msg.GetID(), "connection_id required")
	}
	var connID string
	if err := json.Unmarshal(connIDRaw, &connID); err != nil || connID == "" {
		return h.errorResponse(msg.GetID(), "connection_id must be a non-empty string")
	}

	// Explicit null (or missing) clears the override.
	var overridePtr *bool
	if rawOverride, hasOverride := raw["override"]; hasOverride && string(rawOverride) != "null" {
		var b bool
		if err := json.Unmarshal(rawOverride, &b); err != nil {
			return h.errorResponse(msg.GetID(), "override must be boolean or null")
		}
		overridePtr = &b
	}

	storageKey := "connections/" + connID
	data, err := h.storage.Get(storageKey)
	if err != nil {
		return h.errorResponse(msg.GetID(), "connection not found")
	}
	var record ConnectionRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return h.errorResponse(msg.GetID(), "corrupt connection record")
	}
	record.PresenceShareOverride = overridePtr
	newData, err := json.Marshal(&record)
	if err != nil {
		return h.errorResponse(msg.GetID(), "failed to serialize connection")
	}
	if err := h.storage.Put(storageKey, newData); err != nil {
		return h.errorResponse(msg.GetID(), "failed to persist connection")
	}
	log.Info().Str("connection_id", connID).Interface("override", overridePtr).Msg("Presence override updated")
	return okResponse(msg.GetID())
}

// StartHeartbeat kicks off the background loop that broadcasts the
// online signal to every peer whose effective share setting is true.
// Idempotent — calling twice reuses the existing ticker.
func (h *PresenceHandler) StartHeartbeat(ctx context.Context) {
	h.tickerMu.Lock()
	defer h.tickerMu.Unlock()
	if h.ticker != nil {
		return
	}
	h.ticker = time.NewTicker(presenceInterval)
	h.done = make(chan struct{})
	go h.heartbeatLoop(ctx)
	log.Info().Dur("interval", presenceInterval).Msg("Presence heartbeat started")
}

// StopHeartbeat halts the background loop. Safe to call even if
// StartHeartbeat was never called.
func (h *PresenceHandler) StopHeartbeat() {
	h.tickerMu.Lock()
	defer h.tickerMu.Unlock()
	if h.ticker == nil {
		return
	}
	h.ticker.Stop()
	close(h.done)
	h.ticker = nil
	h.done = nil
}

func (h *PresenceHandler) heartbeatLoop(ctx context.Context) {
	// Fire once immediately so the observer doesn't wait up to
	// 30 seconds for the first signal after we come online.
	h.broadcast(ctx)
	for {
		select {
		case <-h.ticker.C:
			h.broadcast(ctx)
		case <-h.done:
			return
		case <-ctx.Done():
			return
		}
	}
}

// broadcast iterates the connection index once and publishes an
// "online" heartbeat to every peer for whom the user has opted in.
func (h *PresenceHandler) broadcast(ctx context.Context) {
	if h.connections == nil || h.publisher == nil {
		return
	}
	indexData, err := h.storage.Get("connections/_index")
	if err != nil || len(indexData) == 0 {
		return
	}
	var ids []string
	if err := json.Unmarshal(indexData, &ids); err != nil {
		return
	}
	defaults := h.GetSettings()
	now := time.Now().Unix()

	for _, id := range ids {
		data, err := h.storage.Get("connections/" + id)
		if err != nil {
			continue
		}
		var record ConnectionRecord
		if json.Unmarshal(data, &record) != nil {
			continue
		}
		if record.Status != "active" || record.PeerGUID == "" {
			continue
		}
		if !h.effectiveShare(&record, defaults) {
			continue
		}
		hb := PresenceHeartbeat{
			ConnectionID: record.ConnectionID,
			Status:       "online",
			At:           now,
		}
		payload, err := json.Marshal(&hb)
		if err != nil {
			continue
		}
		if err := h.publisher.PublishToVault(ctx, record.PeerGUID, "presence.heartbeat", payload); err != nil {
			log.Debug().Err(err).Str("connection_id", record.ConnectionID).Msg("Presence heartbeat publish failed")
		}
	}
}

// HandleIncomingPeerHeartbeat is called from the message router when
// a peer vault sends us their "I'm online" signal. We re-emit it to
// our app so the UI can render the ring around the peer's avatar.
func (h *PresenceHandler) HandleIncomingPeerHeartbeat(ctx context.Context, payload []byte) error {
	var hb PresenceHeartbeat
	if err := json.Unmarshal(payload, &hb); err != nil {
		return fmt.Errorf("invalid presence heartbeat: %w", err)
	}
	if hb.ConnectionID == "" {
		return fmt.Errorf("presence heartbeat missing connection_id")
	}
	if hb.Status == "" {
		hb.Status = "online"
	}
	if hb.At == 0 {
		hb.At = time.Now().Unix()
	}
	out, err := json.Marshal(&hb)
	if err != nil {
		return fmt.Errorf("re-serialize presence heartbeat: %w", err)
	}
	return h.publisher.PublishToApp(ctx, "presence.heartbeat", out)
}

func (h *PresenceHandler) errorResponse(requestID string, message string) (*OutgoingMessage, error) {
	errBytes, _ := json.Marshal(map[string]string{"error": message})
	return &OutgoingMessage{
		RequestID: requestID,
		Type:      MessageTypeError,
		Payload:   errBytes,
	}, nil
}

func okResponse(requestID string) (*OutgoingMessage, error) {
	return &OutgoingMessage{
		RequestID: requestID,
		Type:      MessageTypeResponse,
		Payload:   json.RawMessage(`{"success":true}`),
	}, nil
}

// handlePresenceOperation routes forVault.presence.* operations to
// the presence handler.
func (mh *MessageHandler) handlePresenceOperation(ctx context.Context, msg *IncomingMessage, opParts []string) (*OutgoingMessage, error) {
	if len(opParts) < 1 {
		return mh.errorResponse(msg.GetID(), "missing presence operation")
	}
	h := mh.presenceHandler
	if h == nil {
		return mh.errorResponse(msg.GetID(), "presence handler not initialized")
	}
	switch opParts[0] {
	case "get":
		return h.HandleSettingsGet(msg)
	case "set-default":
		resp, err := h.HandleSetDefault(msg)
		if err != nil {
			return resp, err
		}
		mh.persistVaultStateToS3()
		return resp, nil
	case "set-override":
		resp, err := h.HandleSetOverride(msg)
		if err != nil {
			return resp, err
		}
		mh.persistVaultStateToS3()
		return resp, nil
	default:
		return mh.errorResponse(msg.GetID(), fmt.Sprintf("unknown presence operation: %s", opParts[0]))
	}
}
