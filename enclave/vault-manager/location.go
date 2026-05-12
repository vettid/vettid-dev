package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"
)

// LocationHandler handles location-related operations in the enclave.
// Location data is stored encrypted in the vault's storage.
type LocationHandler struct {
	ownerSpace string
	storage    *EncryptedStorage
	publisher  *VsockPublisher
	auditLog   *AuditLog
}

// NewLocationHandler creates a new location handler
func NewLocationHandler(ownerSpace string, storage *EncryptedStorage, publisher *VsockPublisher) *LocationHandler {
	return &LocationHandler{
		ownerSpace: ownerSpace,
		storage:    storage,
		publisher:  publisher,
	}
}

// SetAuditLog wires the per-connection audit trail so location
// lifecycle events (request, share-started, share-stopped) show up
// in Interaction History. nil-safe — the Append callers below check
// h.auditLog before writing.
func (h *LocationHandler) SetAuditLog(a *AuditLog) { h.auditLog = a }

// --- Storage keys ---

const (
	locationSettingsKey     = "location/_settings"
	locationIndexKey        = "location/_index"
	locationPrefix          = "location/"
	locationSharingIndexKey = "location/_sharing_index"
	locationLatestKey       = "location/_latest"
)

// peerLocationCacheKey returns the storage key for the latest peer
// location cached against a given local connection. Mirrors the
// `connections/<id>/_peer_profile` pattern used by HandleIncomingProfileUpdate.
func peerLocationCacheKey(connID string) string {
	return "connections/" + connID + "/_peer_location"
}

// autoFulfillLocationKey returns the storage key for the per-connection
// auto-fulfill flag. When the JSON value is {"enabled":true} the
// receiver-side HandleIncomingLocationRequest skips the forApp prompt
// and silently invokes send-once. Default off — incoming requests
// always prompt unless the user has explicitly opted in for this peer.
func autoFulfillLocationKey(connID string) string {
	return "connections/" + connID + "/_auto_fulfill_location_requests"
}

// autoFulfillLastFireKey records the Unix-epoch second of the most
// recent auto-fulfilled location-request for this connection. Used by
// the rate-limit guard: a malicious peer with auto-fulfill enabled
// could otherwise spam `location.request` and harvest unlimited
// samples. We cap auto-fires to one per autoFulfillCooldown so the
// privacy ceiling is bounded regardless of ping cadence; over-limit
// requests fall through to the prompt path so the user can still
// respond manually.
func autoFulfillLastFireKey(connID string) string {
	return "connections/" + connID + "/_auto_fulfill_last_at"
}

const autoFulfillCooldown = 60 * time.Second

// peerLocationStaleAfter is how long a cached peer location stays
// valid before HandlePeerGet treats it as expired. The pin indicator
// on the connection card and the "View location" action label
// disappear after this window — anything older isn't a useful
// "current location" answer. Peer broadcasts that re-arrive update
// the cache UpdatedAt and restart the clock.
const peerLocationStaleAfter = 6 * time.Hour

// CachedPeerLocation is the JSON blob stored at peerLocationCacheKey.
// One per connection; overwritten on every received location-update.
// `FirstReceivedAt` is set on the initial write and never overwritten —
// it's the transition marker the start-sharing notification (V3)
// uses to decide whether this is the first observation of the share.
type CachedPeerLocation struct {
	Latitude        float64  `json:"latitude"`
	Longitude       float64  `json:"longitude"`
	Accuracy        *float32 `json:"accuracy,omitempty"`
	Timestamp       int64    `json:"timestamp"`
	UpdatedAt       string   `json:"updated_at"`
	FirstReceivedAt string   `json:"first_received_at"`
}

// --- Data types ---

// LocationSettings holds user preferences for location tracking
type LocationSettings struct {
	Enabled                 bool `json:"enabled"`
	RetentionDays           int  `json:"retention_days"`
	CompactionThresholdDays int  `json:"compaction_threshold_days"`
}

// LocationPoint represents a single location capture
type LocationPoint struct {
	ID        string   `json:"id"`
	Latitude  float64  `json:"latitude"`
	Longitude float64  `json:"longitude"`
	Accuracy  *float32 `json:"accuracy,omitempty"`
	Altitude  *float64 `json:"altitude,omitempty"`
	Speed     *float32 `json:"speed,omitempty"`
	Timestamp int64    `json:"timestamp"` // epoch seconds
	Source    string   `json:"source"`    // "gps", "network", "passive"
	IsSummary bool     `json:"is_summary"`
}

// --- Request types ---

type LocationAddRequest struct {
	Latitude  float64  `json:"latitude"`
	Longitude float64  `json:"longitude"`
	Accuracy  *float32 `json:"accuracy,omitempty"`
	Altitude  *float64 `json:"altitude,omitempty"`
	Speed     *float32 `json:"speed,omitempty"`
	Timestamp int64    `json:"timestamp"`
	Source    string   `json:"source"`
}

type LocationListRequest struct {
	StartTime int64 `json:"start_time,omitempty"`
	EndTime   int64 `json:"end_time,omitempty"`
	Limit     int   `json:"limit,omitempty"`
}

type LocationDeleteRequest struct {
	ID string `json:"id"`
}

// --- Sharing request/response types ---

type LocationSharingToggleRequest struct {
	ConnectionID string `json:"connection_id"`
	Enabled      bool   `json:"enabled"`
}

type LocationSharingListResponse struct {
	SharedWith []string `json:"shared_with"`
}

// LocationPeerGetRequest reads the cached peer-shared location for a
// single local connection. The connection_id is the LOCAL id (the one
// the owner's vault assigned), not the peer's.
type LocationPeerGetRequest struct {
	ConnectionID string `json:"connection_id"`
}

// LocationPeerGetResponse carries the cached peer location, or
// Shared=false if no cache row exists. Callers should treat absence
// as "peer is not sharing right now" — V5 stop-sharing deletes the
// row, and an unobserved peer never had one.
type LocationPeerGetResponse struct {
	Shared   bool                `json:"shared"`
	Location *CachedPeerLocation `json:"location,omitempty"`
}

// LocationRequestRequest is the app-side payload for the
// `location.request` op: ask a connected peer to send their current
// location once. Maps to a `location-request-ping` peer broadcast.
type LocationRequestRequest struct {
	ConnectionID string `json:"connection_id"`
}

// LocationRequestPing is the peer-broadcast payload for a one-shot
// request. Receiver forwards to its app as
// `connection.peer-location-requested`; the receiver's user decides
// whether to fulfill (typically via `location.send-once`).
type LocationRequestPing struct {
	EventID        string `json:"event_id,omitempty"`
	FromOwnerSpace string `json:"from_owner_space"`
	RequestedAt    string `json:"requested_at"`
}

// LocationAutoFulfillRequest is the app-side payload for setting the
// per-connection auto-fulfill flag.
type LocationAutoFulfillRequest struct {
	ConnectionID string `json:"connection_id"`
	Enabled      bool   `json:"enabled"`
}

// LocationAutoFulfillResponse is what `location.sharing.get-auto-fulfill`
// returns. Separate get/set ops keep the optimistic-toggle pattern
// the Android side already uses for other per-connection toggles.
type LocationAutoFulfillResponse struct {
	ConnectionID string `json:"connection_id"`
	Enabled      bool   `json:"enabled"`
}

// LocationSendOnceRequest is the app-side payload for the
// `location.send-once` op: push the cached latest location point to a
// single peer WITHOUT adding the peer to the sharing index. Used by
// the receiver to satisfy a `location.request` ping without enabling
// continuous sharing.
type LocationSendOnceRequest struct {
	ConnectionID string `json:"connection_id"`
}

// LocationStopBroadcast is sent by a vault to a single peer when the
// owner toggles sharing off for that peer's connection. The peer
// clears its cached peer-location row for the resolved connection
// (see HandleIncomingLocationStop) and emits a one-shot system-card
// notification so the receiver UI can take down "View Location"
// without waiting for a poll. Single-typed peer subject — sender
// marshals, receiver unmarshals into the same struct.
type LocationStopBroadcast struct {
	EventID        string `json:"event_id,omitempty"`
	FromOwnerSpace string `json:"from_owner_space"`
	StoppedAt      string `json:"stopped_at"`
}

// IncomingLocationUpdate is received from a peer vault.
//
// `ConnectionID` is the SENDER'S local connection id. Each vault
// assigns its own connection id, so this value is meaningless to
// the receiver and is kept only for backwards-compat logging.
// `FromOwnerSpace` is the field the receiver actually uses to
// resolve the local connection record via
// FindConnectionByPeerGUID — same pattern as
// ProfileUpdateNotification. Older senders that predate this
// field will produce updates with FromOwnerSpace="" which the
// receiver handles by skipping the cache write (V2) and the
// transition notification (V3); the legacy forward-to-app path
// still fires.
type IncomingLocationUpdate struct {
	EventID        string   `json:"event_id,omitempty"`
	ConnectionID   string   `json:"connection_id"`
	FromOwnerSpace string   `json:"from_owner_space,omitempty"`
	Latitude       float64  `json:"latitude"`
	Longitude      float64  `json:"longitude"`
	Accuracy       *float32 `json:"accuracy,omitempty"`
	// Timestamp is the GPS sample epoch (when the location was
	// measured on the sender's device). The JSON tag is
	// `captured_at` rather than `timestamp` to avoid colliding with
	// the parent's replay-prevention layer, which reads any
	// top-level `timestamp` field as the message send time and
	// drops messages older than 5 minutes. A cached point from
	// earlier in the day would always trip that check. The send
	// time travels in `UpdatedAt` (RFC3339 string, which the
	// replay layer ignores). Older senders that still emitted
	// `timestamp` were silently rejected at the parent boundary
	// (production incident 2026-05-11).
	Timestamp int64  `json:"captured_at"`
	UpdatedAt string `json:"updated_at"`
}

// --- Response types ---

type LocationListResponse struct {
	Points []LocationPoint `json:"points"`
	Total  int             `json:"total"`
}

type LocationStatsResponse struct {
	TotalRecords    int   `json:"total_records"`
	OldestTimestamp int64 `json:"oldest_timestamp,omitempty"`
	NewestTimestamp int64 `json:"newest_timestamp,omitempty"`
}

// --- Handler methods ---

// HandleAdd stores a new location point and runs maintenance
func (h *LocationHandler) HandleAdd(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req LocationAddRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleAdd"); err != nil {
		return h.errorResponse(msg.GetID(), "invalid request format")
	}

	if req.Timestamp == 0 {
		req.Timestamp = time.Now().Unix()
	}

	// Use timestamp as ID for natural ordering
	id := strconv.FormatInt(req.Timestamp, 10)

	point := LocationPoint{
		ID:        id,
		Latitude:  req.Latitude,
		Longitude: req.Longitude,
		Accuracy:  req.Accuracy,
		Altitude:  req.Altitude,
		Speed:     req.Speed,
		Timestamp: req.Timestamp,
		Source:    req.Source,
	}

	data, err := json.Marshal(point)
	if err != nil {
		return h.errorResponse(msg.GetID(), "failed to marshal location point")
	}

	storageKey := locationPrefix + id
	if err := h.storage.Put(storageKey, data); err != nil {
		log.Error().Err(err).Str("id", id).Msg("Failed to store location point")
		return h.errorResponse(msg.GetID(), "failed to store location point")
	}

	if err := h.storage.AddToIndex(locationIndexKey, id); err != nil {
		log.Error().Err(err).Str("id", id).Msg("Failed to add to location index")
		// Point is stored but index may be inconsistent - log but don't fail
	}

	log.Info().Str("id", id).Float64("lat", req.Latitude).Float64("lon", req.Longitude).Msg("Location point added")

	// Run maintenance opportunistically (non-blocking errors)
	h.runMaintenance()

	// Cache the latest point for sharing
	if err := h.storage.Put(locationLatestKey, data); err != nil {
		log.Warn().Err(err).Msg("Failed to cache latest location point")
	}

	// Push to shared connections (non-blocking)
	h.pushToSharedConnections(context.Background(), point)

	resp := map[string]interface{}{
		"success": true,
		"id":      id,
	}
	respBytes, _ := json.Marshal(resp)
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleList returns location points filtered by time range
func (h *LocationHandler) HandleList(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req LocationListRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleList"); err != nil {
		req = LocationListRequest{} // Use defaults
	}

	ids, err := h.storage.GetIndex(locationIndexKey)
	if err != nil {
		return h.errorResponse(msg.GetID(), "failed to read location index")
	}

	// Sort IDs (timestamps) in descending order (newest first)
	sort.Sort(sort.Reverse(sort.StringSlice(ids)))

	var points []LocationPoint
	for _, id := range ids {
		storageKey := locationPrefix + id
		data, err := h.storage.Get(storageKey)
		if err != nil {
			continue // Skip missing entries
		}

		var point LocationPoint
		if err := json.Unmarshal(data, &point); err != nil {
			continue
		}

		// Apply time filters
		if req.StartTime > 0 && point.Timestamp < req.StartTime {
			continue
		}
		if req.EndTime > 0 && point.Timestamp > req.EndTime {
			continue
		}

		points = append(points, point)

		if req.Limit > 0 && len(points) >= req.Limit {
			break
		}
	}

	resp := LocationListResponse{
		Points: points,
		Total:  len(points),
	}
	respBytes, _ := json.Marshal(resp)
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleDelete removes a specific location point by ID
func (h *LocationHandler) HandleDelete(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req LocationDeleteRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleDelete"); err != nil {
		return h.errorResponse(msg.GetID(), "invalid request format")
	}

	if req.ID == "" {
		return h.errorResponse(msg.GetID(), "id is required")
	}

	storageKey := locationPrefix + req.ID
	if err := h.storage.Delete(storageKey); err != nil {
		return h.errorResponse(msg.GetID(), "failed to delete location point")
	}

	if err := h.storage.RemoveFromIndex(locationIndexKey, req.ID); err != nil {
		log.Error().Err(err).Str("id", req.ID).Msg("Failed to remove from location index")
	}

	log.Info().Str("id", req.ID).Msg("Location point deleted")

	resp := map[string]interface{}{
		"success": true,
		"id":      req.ID,
	}
	respBytes, _ := json.Marshal(resp)
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleDeleteAll removes all location data and index
func (h *LocationHandler) HandleDeleteAll(msg *IncomingMessage) (*OutgoingMessage, error) {
	ids, err := h.storage.GetIndex(locationIndexKey)
	if err != nil {
		return h.errorResponse(msg.GetID(), "failed to read location index")
	}

	deletedCount := 0
	for _, id := range ids {
		storageKey := locationPrefix + id
		if err := h.storage.Delete(storageKey); err != nil {
			log.Error().Err(err).Str("id", id).Msg("Failed to delete location point during delete-all")
			continue
		}
		deletedCount++
	}

	// Clear the index
	emptyIndex, _ := json.Marshal([]string{})
	if err := h.storage.Put(locationIndexKey, emptyIndex); err != nil {
		log.Error().Err(err).Msg("Failed to clear location index")
	}

	log.Info().Int("deleted", deletedCount).Msg("All location data deleted")

	resp := map[string]interface{}{
		"success":       true,
		"deleted_count": deletedCount,
	}
	respBytes, _ := json.Marshal(resp)
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleSettingsGet returns current location settings
func (h *LocationHandler) HandleSettingsGet(msg *IncomingMessage) (*OutgoingMessage, error) {
	settings := h.getSettings()

	respBytes, _ := json.Marshal(settings)
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleSettingsUpdate updates location settings
func (h *LocationHandler) HandleSettingsUpdate(msg *IncomingMessage) (*OutgoingMessage, error) {
	var settings LocationSettings
	if err := unmarshalRequest(msg.Payload, &settings, "HandleSettingsUpdate"); err != nil {
		return h.errorResponse(msg.GetID(), "invalid settings format")
	}

	// Validate retention days
	if settings.RetentionDays < 1 {
		settings.RetentionDays = 30
	}
	if settings.CompactionThresholdDays < 1 {
		settings.CompactionThresholdDays = 7
	}

	if err := h.storage.PutJSON(locationSettingsKey, &settings); err != nil {
		return h.errorResponse(msg.GetID(), "failed to save settings")
	}

	log.Info().
		Bool("enabled", settings.Enabled).
		Int("retention_days", settings.RetentionDays).
		Int("compaction_days", settings.CompactionThresholdDays).
		Msg("Location settings updated")

	resp := map[string]interface{}{
		"success": true,
	}
	respBytes, _ := json.Marshal(resp)
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleStats returns statistics about stored location data
func (h *LocationHandler) HandleStats(msg *IncomingMessage) (*OutgoingMessage, error) {
	ids, err := h.storage.GetIndex(locationIndexKey)
	if err != nil {
		return h.errorResponse(msg.GetID(), "failed to read location index")
	}

	stats := LocationStatsResponse{
		TotalRecords: len(ids),
	}

	if len(ids) > 0 {
		// IDs are timestamps, so we can find oldest/newest from the index
		sort.Strings(ids)
		if oldest, err := strconv.ParseInt(ids[0], 10, 64); err == nil {
			stats.OldestTimestamp = oldest
		}
		if newest, err := strconv.ParseInt(ids[len(ids)-1], 10, 64); err == nil {
			stats.NewestTimestamp = newest
		}
	}

	respBytes, _ := json.Marshal(stats)
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// --- Internal helpers ---

func (h *LocationHandler) getSettings() LocationSettings {
	var settings LocationSettings
	if err := h.storage.GetJSON(locationSettingsKey, &settings); err != nil {
		// Return defaults
		return LocationSettings{
			Enabled:                 false,
			RetentionDays:           30,
			CompactionThresholdDays: 7,
		}
	}
	return settings
}

// runMaintenance performs auto-purge and compaction based on settings
func (h *LocationHandler) runMaintenance() {
	settings := h.getSettings()
	now := time.Now().Unix()

	ids, err := h.storage.GetIndex(locationIndexKey)
	if err != nil || len(ids) == 0 {
		return
	}

	// Auto-purge: remove records older than retention_days
	retentionCutoff := now - int64(settings.RetentionDays*86400)
	var purgedIDs []string

	for _, id := range ids {
		ts, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			continue
		}
		if ts < retentionCutoff {
			storageKey := locationPrefix + id
			if err := h.storage.Delete(storageKey); err == nil {
				purgedIDs = append(purgedIDs, id)
			}
		}
	}

	for _, id := range purgedIDs {
		_ = h.storage.RemoveFromIndex(locationIndexKey, id)
	}

	if len(purgedIDs) > 0 {
		log.Info().Int("purged", len(purgedIDs)).Msg("Location auto-purge completed")
	}

	// Compaction: summarize old records into daily centroids
	compactionCutoff := now - int64(settings.CompactionThresholdDays*86400)
	h.compactOldRecords(compactionCutoff)
}

// compactOldRecords replaces individual points older than cutoff with daily centroid summaries
func (h *LocationHandler) compactOldRecords(cutoffTimestamp int64) {
	ids, err := h.storage.GetIndex(locationIndexKey)
	if err != nil {
		return
	}

	// Group points by day (UTC)
	dayGroups := make(map[string][]LocationPoint)
	var summaryIDs []string // already-compacted records to skip

	for _, id := range ids {
		ts, err := strconv.ParseInt(id, 10, 64)
		if err != nil || ts >= cutoffTimestamp {
			continue
		}

		storageKey := locationPrefix + id
		data, err := h.storage.Get(storageKey)
		if err != nil {
			continue
		}

		var point LocationPoint
		if err := json.Unmarshal(data, &point); err != nil {
			continue
		}

		// Skip already-compacted summaries
		if point.IsSummary {
			summaryIDs = append(summaryIDs, id)
			continue
		}

		dayKey := time.Unix(point.Timestamp, 0).UTC().Format("2006-01-02")
		dayGroups[dayKey] = append(dayGroups[dayKey], point)
	}

	compacted := 0
	for dayKey, points := range dayGroups {
		if len(points) <= 1 {
			continue // Nothing to compact
		}

		// Compute centroid
		var sumLat, sumLon float64
		var minTS int64 = math.MaxInt64
		for _, p := range points {
			sumLat += p.Latitude
			sumLon += p.Longitude
			if p.Timestamp < minTS {
				minTS = p.Timestamp
			}
		}

		summary := LocationPoint{
			ID:        fmt.Sprintf("summary_%s", dayKey),
			Latitude:  sumLat / float64(len(points)),
			Longitude: sumLon / float64(len(points)),
			Timestamp: minTS,
			Source:    "compacted",
			IsSummary: true,
		}

		// Store summary
		data, _ := json.Marshal(summary)
		storageKey := locationPrefix + summary.ID
		if err := h.storage.Put(storageKey, data); err != nil {
			continue
		}
		_ = h.storage.AddToIndex(locationIndexKey, summary.ID)

		// Remove original points
		for _, p := range points {
			_ = h.storage.Delete(locationPrefix + p.ID)
			_ = h.storage.RemoveFromIndex(locationIndexKey, p.ID)
		}
		compacted += len(points)
	}

	if compacted > 0 {
		log.Info().Int("compacted", compacted).Msg("Location compaction completed")
	}
}

// --- Sharing handler methods ---

// HandleSharingToggle enables or disables location sharing for a connection
func (h *LocationHandler) HandleSharingToggle(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req LocationSharingToggleRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleSharingToggle"); err != nil {
		return h.errorResponse(msg.GetID(), "invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	// Load current sharing index
	sharedWith := h.getSharingIndex()

	wasAlreadyShared := false
	if req.Enabled {
		// Add connection if not already present
		found := false
		for _, id := range sharedWith {
			if id == req.ConnectionID {
				found = true
				break
			}
		}
		wasAlreadyShared = found
		if !found {
			sharedWith = append(sharedWith, req.ConnectionID)
		}
	} else {
		// Remove connection
		var updated []string
		wasShared := false
		for _, id := range sharedWith {
			if id == req.ConnectionID {
				wasShared = true
				continue
			}
			updated = append(updated, id)
		}
		sharedWith = updated
		// V5: tell the peer right away so it can clear its cache and
		// drop the "View Location" affordance. Only fire if the
		// connection was actually in the sharing index — toggling
		// off something that was never on shouldn't generate noise.
		if wasShared {
			h.pushStopToSharedConnection(context.Background(), req.ConnectionID)
		}
	}

	// Audit entry — show up in Interaction History as "Started/Stopped
	// sharing location". On toggle-ON, the inline push below routes
	// through sendLocationOnceInternal which writes its own
	// "Started sharing location" audit row, so skip here to avoid
	// duplicate entries. Toggle-OFF still audits here (the stop
	// broadcast path doesn't write audit rows).
	if h.auditLog != nil && !req.Enabled {
		h.auditLog.Append(AuditEntry{
			ConnectionID: req.ConnectionID,
			EventType:    AuditTypeLocationShareStopped,
			Direction:    AuditDirectionOutbound,
			Title:        "Stopped sharing location",
		})
	}

	// Persist
	if err := h.storage.PutJSON(locationSharingIndexKey, &sharedWith); err != nil {
		return h.errorResponse(msg.GetID(), "failed to save sharing index")
	}

	// Toggle-ON: immediately push the latest cached location point to
	// the peer so their cache populates AND the share-started
	// notification fires right away. Without this, the start-sharing
	// notification only fires when the LocationCollectionWorker's
	// next periodic push lands — which could be ~15 minutes after
	// the toggle. Skip on toggle-OFF (the stop broadcast handles it)
	// and skip the no-op toggle-ON case (avoids spam if the user
	// flips an already-on toggle).
	if req.Enabled && !wasAlreadyShared {
		if err := h.sendLocationOnceInternal(req.ConnectionID, "Started sharing location"); err != nil {
			// Non-fatal: the toggle still landed; the worker's next
			// push will be the share-started trigger. Common reason
			// for failure: no cached location point yet (user just
			// enrolled, hasn't moved).
			log.Info().Err(err).Str("connection_id", req.ConnectionID).Msg("Could not immediately push location on toggle-on; will wait for next collector tick")
		}
	}

	log.Info().
		Str("connection_id", req.ConnectionID).
		Bool("enabled", req.Enabled).
		Int("total_shared", len(sharedWith)).
		Msg("Location sharing toggled")

	resp := map[string]interface{}{
		"success":     true,
		"shared_with": sharedWith,
	}
	respBytes, _ := json.Marshal(resp)
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleSharingList returns the list of connection IDs that sharing is enabled for
func (h *LocationHandler) HandleSharingList(msg *IncomingMessage) (*OutgoingMessage, error) {
	sharedWith := h.getSharingIndex()

	resp := LocationSharingListResponse{
		SharedWith: sharedWith,
	}
	respBytes, _ := json.Marshal(resp)
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleSharingPush manually pushes the latest location to all shared connections
func (h *LocationHandler) HandleSharingPush(msg *IncomingMessage) (*OutgoingMessage, error) {
	// Load latest cached point
	data, err := h.storage.Get(locationLatestKey)
	if err != nil {
		return h.errorResponse(msg.GetID(), "no location data available to push")
	}

	var point LocationPoint
	if err := json.Unmarshal(data, &point); err != nil {
		return h.errorResponse(msg.GetID(), "failed to read latest location")
	}

	successCount, failCount := h.pushToSharedConnections(context.Background(), point)

	resp := map[string]interface{}{
		"success":       true,
		"pushed_count":  successCount,
		"failed_count":  failCount,
	}
	respBytes, _ := json.Marshal(resp)
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleRequest publishes a one-shot location-request ping to a
// single connected peer. The peer's vault forwards the ping to its
// app, which can then call `location.send-once` to fulfill the
// request without enabling continuous sharing.
func (h *LocationHandler) HandleRequest(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req LocationRequestRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleRequest"); err != nil {
		return h.errorResponse(msg.GetID(), "invalid request format")
	}
	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	connData, err := h.storage.Get("connections/" + req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "connection not found")
	}
	var conn ConnectionRecord
	if err := json.Unmarshal(connData, &conn); err != nil {
		return h.errorResponse(msg.GetID(), "failed to parse connection record")
	}
	if conn.Status != "active" || conn.PeerGUID == "" {
		return h.errorResponse(msg.GetID(), "connection is not active")
	}

	now := time.Now().UTC().Format(time.RFC3339)
	eventID := fmt.Sprintf("loc-req:%s:%d", h.ownerSpace, time.Now().UnixNano())
	ping := LocationRequestPing{
		EventID:        eventID,
		FromOwnerSpace: h.ownerSpace,
		RequestedAt:    now,
	}
	payload, _ := json.Marshal(ping)
	if err := encryptAndPublishToPeer(
		context.Background(), h.storage, h.publisher, h.ownerSpace,
		req.ConnectionID, "location-request-ping", eventID, payload, time.Now().Unix(),
	); err != nil {
		log.Warn().Err(err).Str("connection_id", req.ConnectionID).Msg("Failed to publish location-request-ping")
		return h.errorResponse(msg.GetID(), "failed to send location request")
	}

	// Audit: "Asked for location" (outbound on this peer's connection)
	if h.auditLog != nil {
		h.auditLog.Append(AuditEntry{
			ConnectionID: req.ConnectionID,
			PeerGUID:     conn.PeerGUID,
			EventType:    AuditTypeLocationRequest,
			Direction:    AuditDirectionOutbound,
			Title:        "Asked for location",
		})
	}

	resp := map[string]interface{}{
		"success":      true,
		"connection_id": req.ConnectionID,
		"requested_at": now,
	}
	respBytes, _ := json.Marshal(resp)
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleSendOnce pushes the latest cached location point to a single
// peer without modifying the sharing index. Companion to HandleRequest:
// the receiver of a `location-request-ping` calls this to fulfill the
// request once without enabling continuous sharing.
func (h *LocationHandler) HandleSendOnce(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req LocationSendOnceRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleSendOnce"); err != nil {
		return h.errorResponse(msg.GetID(), "invalid request format")
	}
	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	if err := h.sendLocationOnceInternal(req.ConnectionID, "Sent location"); err != nil {
		return h.errorResponse(msg.GetID(), err.Error())
	}

	resp := map[string]interface{}{
		"success":      true,
		"connection_id": req.ConnectionID,
	}
	respBytes, _ := json.Marshal(resp)
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// sendLocationOnceInternal pushes the latest cached point to one peer
// and writes the audit entry. Shared by HandleSendOnce (user-approved)
// and HandleIncomingLocationRequest's auto-fulfill branch — auditTitle
// distinguishes the two on the trail so the user can tell which path
// fired (e.g., "Sent location" vs "Auto-sent location on request").
func (h *LocationHandler) sendLocationOnceInternal(connID, auditTitle string) error {
	connData, err := h.storage.Get("connections/" + connID)
	if err != nil {
		return fmt.Errorf("connection not found")
	}
	var conn ConnectionRecord
	if err := json.Unmarshal(connData, &conn); err != nil {
		return fmt.Errorf("failed to parse connection record")
	}
	if conn.Status != "active" || conn.PeerGUID == "" {
		return fmt.Errorf("connection is not active")
	}

	latestData, err := h.storage.Get(locationLatestKey)
	if err != nil || len(latestData) == 0 {
		return fmt.Errorf("no location data available to send")
	}
	var point LocationPoint
	if err := json.Unmarshal(latestData, &point); err != nil {
		return fmt.Errorf("failed to read latest location")
	}

	settings := h.getSettings()
	lat, lon := applyPrecision(point.Latitude, point.Longitude, settings)
	now := time.Now().UTC()
	eventID := fmt.Sprintf("loc-once:%s:%d", h.ownerSpace, time.Now().UnixNano())
	update := IncomingLocationUpdate{
		EventID:        eventID,
		ConnectionID:   connID,
		FromOwnerSpace: h.ownerSpace,
		Latitude:       lat,
		Longitude:      lon,
		Accuracy:       point.Accuracy,
		Timestamp:      point.Timestamp,
		UpdatedAt:      now.Format(time.RFC3339),
	}
	updateData, _ := json.Marshal(update)
	if err := encryptAndPublishToPeer(
		context.Background(), h.storage, h.publisher, h.ownerSpace,
		connID, "location-update", eventID, updateData, now.Unix(),
	); err != nil {
		log.Warn().Err(err).Str("connection_id", connID).Msg("Failed to send one-shot location")
		return fmt.Errorf("failed to send location")
	}

	if h.auditLog != nil {
		h.auditLog.Append(AuditEntry{
			ConnectionID: connID,
			PeerGUID:     conn.PeerGUID,
			EventType:    AuditTypeLocationShareStarted,
			Direction:    AuditDirectionOutbound,
			Title:        auditTitle,
		})
	}
	return nil
}

// HandleSetAutoFulfill flips the per-connection auto-fulfill flag.
// When enabled, incoming location-request pings on this connection
// are silently fulfilled by the vault (send-once internally) without
// surfacing a prompt to the user.
func (h *LocationHandler) HandleSetAutoFulfill(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req LocationAutoFulfillRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleSetAutoFulfill"); err != nil {
		return h.errorResponse(msg.GetID(), "invalid request format")
	}
	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	data, _ := json.Marshal(map[string]bool{"enabled": req.Enabled})
	if err := h.storage.Put(autoFulfillLocationKey(req.ConnectionID), data); err != nil {
		return h.errorResponse(msg.GetID(), "failed to persist auto-fulfill setting")
	}

	log.Info().Str("connection_id", req.ConnectionID).Bool("enabled", req.Enabled).Msg("Auto-fulfill location toggled")

	resp := map[string]interface{}{
		"success":       true,
		"connection_id": req.ConnectionID,
		"enabled":       req.Enabled,
	}
	respBytes, _ := json.Marshal(resp)
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleGetAutoFulfill reads the per-connection auto-fulfill flag.
// Returns enabled=false when the key isn't set (default off).
func (h *LocationHandler) HandleGetAutoFulfill(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req LocationAutoFulfillRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleGetAutoFulfill"); err != nil {
		return h.errorResponse(msg.GetID(), "invalid request format")
	}
	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	resp := LocationAutoFulfillResponse{
		ConnectionID: req.ConnectionID,
		Enabled:      h.isAutoFulfillEnabled(req.ConnectionID),
	}
	respBytes, _ := json.Marshal(resp)
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// isAutoFulfillEnabled returns the stored boolean for this connection,
// defaulting to false when the key is missing or malformed.
func (h *LocationHandler) isAutoFulfillEnabled(connID string) bool {
	raw, err := h.storage.Get(autoFulfillLocationKey(connID))
	if err != nil || len(raw) == 0 {
		return false
	}
	var v struct {
		Enabled bool `json:"enabled"`
	}
	if json.Unmarshal(raw, &v) != nil {
		return false
	}
	return v.Enabled
}

// autoFulfillRateLimitOK returns true when enough time has passed
// since the last auto-fulfilled fire on this connection to send
// another one. The fixed-window approach is good enough at the
// expected scale — we're not trying to defend against high-frequency
// attackers, just bounded against a peer who tries to harvest
// continuous location by spamming requests.
func (h *LocationHandler) autoFulfillRateLimitOK(connID string) bool {
	raw, err := h.storage.Get(autoFulfillLastFireKey(connID))
	if err != nil || len(raw) == 0 {
		return true
	}
	last, perr := strconv.ParseInt(string(raw), 10, 64)
	if perr != nil {
		return true
	}
	return time.Since(time.Unix(last, 0)) >= autoFulfillCooldown
}

// recordAutoFulfillFire stamps the current epoch second so the next
// invocation's rate-limit check sees it.
func (h *LocationHandler) recordAutoFulfillFire(connID string) {
	now := strconv.FormatInt(time.Now().Unix(), 10)
	if err := h.storage.Put(autoFulfillLastFireKey(connID), []byte(now)); err != nil {
		log.Warn().Err(err).Str("connection_id", connID).Msg("Failed to record auto-fulfill timestamp")
	}
}

// HandleIncomingLocationRequest processes a one-shot location-request
// ping from a peer vault. Forwards to the receiver app as
// `connection.peer-location-requested` so the UI can prompt the user
// to fulfill (via `location.send-once`) or ignore.
func (h *LocationHandler) HandleIncomingLocationRequest(ctx context.Context, data []byte) error {
	// Encrypted-envelope wire format (2026-05-12+). Decrypt first; the
	// inner payload is the original LocationRequestPing JSON.
	dec, err := decryptIncomingPeerEnvelope(h.storage, data)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to decrypt incoming location-request-ping envelope")
		return err
	}
	var ping LocationRequestPing
	if err := json.Unmarshal(dec.InnerPayload, &ping); err != nil {
		return err
	}
	if ping.FromOwnerSpace == "" {
		ping.FromOwnerSpace = dec.FromOwnerSpace
	}

	eventID := ping.EventID
	if eventID == "" {
		eventID = fmt.Sprintf("location-request:%s:%s", ping.FromOwnerSpace, ping.RequestedAt)
	}
	if alreadyProcessed, err := h.storage.IsEventProcessed(eventID); err == nil && alreadyProcessed {
		log.Info().Str("from_owner_space", ping.FromOwnerSpace).Msg("Duplicate location-request detected - ignoring replay")
		return nil
	}
	if err := h.storage.MarkEventProcessed(eventID, "location_request"); err != nil {
		log.Warn().Err(err).Msg("Failed to mark location-request as processed")
	}

	if ping.FromOwnerSpace == "" {
		log.Debug().Msg("location-request-ping missing from_owner_space — dropping")
		return nil
	}
	connID := h.findConnectionByPeerGUID(ping.FromOwnerSpace)
	if connID == "" {
		log.Debug().Str("from_owner_space", ping.FromOwnerSpace).Msg("location-request-ping for unknown peer — skipping")
		return nil
	}

	requestedAt := ping.RequestedAt
	if requestedAt == "" {
		requestedAt = time.Now().UTC().Format(time.RFC3339)
	}

	// Audit the inbound request unconditionally — the user wants the
	// trail to show "X asked for your location" whether or not the
	// vault auto-fulfilled it.
	if h.auditLog != nil {
		h.auditLog.Append(AuditEntry{
			ConnectionID: connID,
			PeerGUID:     ping.FromOwnerSpace,
			EventType:    AuditTypeLocationRequest,
			Direction:    AuditDirectionInbound,
			Title:        "Asked for your location",
		})
	}

	// Auto-fulfill branch: when the user has pre-approved this peer,
	// silently send the latest location instead of prompting. Rate
	// limit guards against a peer spamming requests and harvesting
	// unlimited samples — over-cap requests fall through to the
	// prompt path so the user sees them and can investigate.
	if h.isAutoFulfillEnabled(connID) {
		if !h.autoFulfillRateLimitOK(connID) {
			log.Warn().Str("connection_id", connID).Msg("Auto-fulfill rate-limited; falling back to prompt for this request")
		} else if err := h.sendLocationOnceInternal(connID, "Auto-sent location on request"); err != nil {
			log.Warn().Err(err).Str("connection_id", connID).Msg("Auto-fulfill failed; falling back to prompt")
			// Fall through to the prompt path so the user can still
			// respond manually if auto-send fails for any reason.
		} else {
			h.recordAutoFulfillFire(connID)
			log.Info().Str("connection_id", connID).Msg("Auto-fulfilled location request without prompting")
			return nil
		}
	}

	payload, _ := json.Marshal(map[string]string{
		"connection_id":    connID,
		"from_owner_space": ping.FromOwnerSpace,
		"requested_at":     requestedAt,
	})
	if err := h.publisher.PublishToApp(ctx, "connection.peer-location-requested", payload); err != nil {
		log.Warn().Err(err).Str("connection_id", connID).Msg("Failed to forward location-request-ping to app")
	}
	return nil
}

// HandleIncomingLocationStop processes a stop-sharing notice from a
// peer vault. Clears the cached peer-location row for the resolved
// connection (V2 cache key) and emits the V5
// `connection.peer-location-share-stopped` notification to the app
// so the UI can drop the "View Location" affordance immediately.
// Legacy senders (no FromOwnerSpace) are ignored — there's no way
// to resolve the local connection without it.
func (h *LocationHandler) HandleIncomingLocationStop(ctx context.Context, data []byte) error {
	dec, err := decryptIncomingPeerEnvelope(h.storage, data)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to decrypt incoming location-stop envelope")
		return err
	}
	var stop LocationStopBroadcast
	if err := json.Unmarshal(dec.InnerPayload, &stop); err != nil {
		return err
	}
	if stop.FromOwnerSpace == "" {
		stop.FromOwnerSpace = dec.FromOwnerSpace
	}

	eventID := stop.EventID
	if eventID == "" {
		eventID = fmt.Sprintf("location-stop:%s:%s", stop.FromOwnerSpace, stop.StoppedAt)
	}
	if alreadyProcessed, err := h.storage.IsEventProcessed(eventID); err == nil && alreadyProcessed {
		log.Info().Str("from_owner_space", stop.FromOwnerSpace).Msg("Duplicate location-stop detected - ignoring replay")
		return nil
	}
	if err := h.storage.MarkEventProcessed(eventID, "location_stop"); err != nil {
		log.Warn().Err(err).Msg("Failed to mark location-stop as processed")
	}

	if stop.FromOwnerSpace == "" {
		log.Debug().Msg("location-stop missing from_owner_space — cannot resolve connection, dropping")
		return nil
	}

	connID := h.findConnectionByPeerGUID(stop.FromOwnerSpace)
	if connID == "" {
		log.Debug().Str("from_owner_space", stop.FromOwnerSpace).Msg("location-stop for unknown peer — skipping")
		return nil
	}

	key := peerLocationCacheKey(connID)
	hadCache := false
	if existing, err := h.storage.Get(key); err == nil && len(existing) > 0 {
		hadCache = true
	}
	if hadCache {
		if err := h.storage.Delete(key); err != nil {
			log.Warn().Err(err).Str("connection_id", connID).Msg("Failed to clear cached peer location on stop")
		}
	}
	log.Info().
		Str("connection_id", connID).
		Str("from_owner_space", stop.FromOwnerSpace).
		Bool("had_cache", hadCache).
		Msg("Processed peer location-stop")

	// Always emit the app notification, even if cache was absent:
	// the receiver-side UI may have been showing a stale "shared"
	// indicator derived from elsewhere, and the system-card row is
	// part of the activity feed regardless of cache state.
	stoppedAt := stop.StoppedAt
	if stoppedAt == "" {
		stoppedAt = time.Now().UTC().Format(time.RFC3339)
	}
	h.emitPeerLocationShareStopped(ctx, connID, stop.FromOwnerSpace, stoppedAt)

	// Audit: peer stopped sharing (inbound).
	if h.auditLog != nil {
		h.auditLog.Append(AuditEntry{
			ConnectionID: connID,
			PeerGUID:     stop.FromOwnerSpace,
			EventType:    AuditTypeLocationShareStopped,
			Direction:    AuditDirectionInbound,
			Title:        "Stopped sharing location",
		})
	}
	return nil
}

// emitPeerLocationShareStopped publishes a one-shot notification to
// the owner's app announcing that a peer just stopped sharing their
// location. Mirrors emitPeerLocationShareStarted (V3).
func (h *LocationHandler) emitPeerLocationShareStopped(ctx context.Context, connID, fromOwnerSpace, stoppedAt string) {
	payload, err := json.Marshal(map[string]string{
		"connection_id":    connID,
		"from_owner_space": fromOwnerSpace,
		"stopped_at":       stoppedAt,
	})
	if err != nil {
		return
	}
	if err := h.publisher.PublishToApp(ctx, "connection.peer-location-share-stopped", payload); err != nil {
		log.Warn().Err(err).Str("connection_id", connID).Msg("Failed to publish peer-location-share-stopped notification")
	}
}

// pushStopToSharedConnection sends a single location-stop broadcast
// to the peer for the given connection id. Used by HandleSharingToggle
// when sharing is being turned off; the explicit signal lets the peer
// clear its cache and update its UI without waiting for a poll.
// Non-fatal on failure — the sender's sharing-index update is the
// canonical state; the peer will eventually time out its cache.
func (h *LocationHandler) pushStopToSharedConnection(ctx context.Context, connID string) {
	now := time.Now().UTC()
	eventID := fmt.Sprintf("loc-stop:%s:%d", h.ownerSpace, time.Now().UnixNano())
	stop := LocationStopBroadcast{
		EventID:        eventID,
		FromOwnerSpace: h.ownerSpace,
		StoppedAt:      now.Format(time.RFC3339),
	}
	payload, _ := json.Marshal(stop)
	if err := encryptAndPublishToPeer(
		ctx, h.storage, h.publisher, h.ownerSpace,
		connID, "location-stop", eventID, payload, now.Unix(),
	); err != nil {
		log.Warn().Err(err).Str("connection_id", connID).Msg("Failed to push location-stop to peer")
	}
}

// HandlePeerGet returns the cached peer location for a single
// connection. This is what powers the "View Location" action on the
// Connection Detail screen — the cache is written on every received
// location-update (see HandleIncomingLocationUpdate) and removed by
// V5 stop-sharing, so reading it is the cheapest way to ask "is this
// peer currently sharing?".
func (h *LocationHandler) HandlePeerGet(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req LocationPeerGetRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandlePeerGet"); err != nil {
		return h.errorResponse(msg.GetID(), "invalid request format")
	}
	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	key := peerLocationCacheKey(req.ConnectionID)
	data, err := h.storage.Get(key)
	if err != nil || len(data) == 0 {
		respBytes, _ := json.Marshal(LocationPeerGetResponse{Shared: false})
		return &OutgoingMessage{
			RequestID: msg.GetID(),
			Type:      MessageTypeResponse,
			Payload:   respBytes,
		}, nil
	}

	var cached CachedPeerLocation
	if err := json.Unmarshal(data, &cached); err != nil {
		log.Warn().Err(err).Str("connection_id", req.ConnectionID).Msg("Failed to decode cached peer location")
		return h.errorResponse(msg.GetID(), "failed to decode cached peer location")
	}

	// Stale-cache cleanup: peer broadcasts populate UpdatedAt on every
	// receive, so anything older than peerLocationStaleAfter means the
	// peer hasn't pushed in 6h+ (uninstalled, sharing toggled off
	// without a stop broadcast, network drop). Return shared:false so
	// the connection-card pin and "View location" affordance fall
	// back to the request flow rather than showing a stale point as
	// if it were current. Delete the row lazily so the next fresh
	// broadcast counts as a new share-started transition.
	if cached.UpdatedAt != "" {
		if updated, perr := time.Parse(time.RFC3339, cached.UpdatedAt); perr == nil {
			if time.Since(updated) > peerLocationStaleAfter {
				log.Info().
					Str("connection_id", req.ConnectionID).
					Str("updated_at", cached.UpdatedAt).
					Msg("Peer location cache stale — deleting and returning shared:false")
				if delErr := h.storage.Delete(key); delErr != nil {
					log.Warn().Err(delErr).Str("connection_id", req.ConnectionID).Msg("Failed to delete stale peer-location row (continuing)")
				}
				respBytes, _ := json.Marshal(LocationPeerGetResponse{Shared: false})
				return &OutgoingMessage{
					RequestID: msg.GetID(),
					Type:      MessageTypeResponse,
					Payload:   respBytes,
				}, nil
			}
		}
	}

	respBytes, _ := json.Marshal(LocationPeerGetResponse{
		Shared:   true,
		Location: &cached,
	})
	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleIncomingLocationUpdate processes a location update from a peer vault.
// The update is ephemeral — it is NOT stored, only forwarded to the app.
func (h *LocationHandler) HandleIncomingLocationUpdate(ctx context.Context, data []byte) error {
	dec, err := decryptIncomingPeerEnvelope(h.storage, data)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to decrypt incoming location-update envelope")
		return err
	}
	var update IncomingLocationUpdate
	if err := json.Unmarshal(dec.InnerPayload, &update); err != nil {
		return err
	}
	if update.FromOwnerSpace == "" {
		update.FromOwnerSpace = dec.FromOwnerSpace
	}

	// SECURITY: Replay attack prevention
	eventID := update.EventID
	if eventID == "" {
		eventID = fmt.Sprintf("location:%s:%d", update.ConnectionID, update.Timestamp)
	}
	if alreadyProcessed, err := h.storage.IsEventProcessed(eventID); err == nil && alreadyProcessed {
		log.Info().
			Str("connection_id", update.ConnectionID).
			Msg("Duplicate location update detected - ignoring replay")
		return nil
	}

	log.Debug().
		Str("connection_id", update.ConnectionID).
		Float64("lat", update.Latitude).
		Float64("lon", update.Longitude).
		Msg("Received location update from peer")

	// SECURITY: Mark event as processed to prevent replay
	if err := h.storage.MarkEventProcessed(eventID, "location_update"); err != nil {
		log.Warn().Err(err).Str("connection_id", update.ConnectionID).Msg("Failed to mark location update as processed")
	}

	// V2 (2026-05-11): cache the latest point under the LOCAL connection
	// id so Connection Detail can render it without subscribing to live
	// broadcasts. The sender's `update.ConnectionID` is useless — each
	// vault assigns its own connection id — so resolve via
	// FromOwnerSpace → local connID. Legacy senders (no FromOwnerSpace)
	// skip the cache write; the legacy forward-to-app branch below
	// still fires so existing clients aren't regressed.
	//
	// V3 transition detection lands in the same write: if the cache
	// key didn't previously exist, FirstReceivedAt is stamped and the
	// "started sharing" notification fires (see emitPeerLocationShareStarted).
	if update.FromOwnerSpace != "" {
		if connID := h.findConnectionByPeerGUID(update.FromOwnerSpace); connID != "" {
			h.cachePeerLocationAndMaybeNotify(ctx, connID, update)
		} else {
			log.Debug().
				Str("from_owner_space", update.FromOwnerSpace).
				Msg("Peer location update for unknown peer — skipping cache (not a connected peer)")
		}
	}

	// Forward to app (ephemeral — kept for legacy subscribers that
	// want push-driven live updates; the cache above is the durable
	// source of truth for "what was the last shared location".)
	// Send the decrypted IncomingLocationUpdate JSON, not the envelope
	// bytes — the app has no shared secret to unwrap them.
	if err := h.publisher.PublishToApp(ctx, "location-update", dec.InnerPayload); err != nil {
		log.Warn().Err(err).Msg("Failed to notify app of location update")
	}

	return nil
}

// findConnectionByPeerGUID walks the connection index and returns the
// local connection id whose `PeerGUID` matches the argument. Returns
// "" if no match. Inlined here rather than imported from
// NotificationsHandler to keep LocationHandler self-contained — the
// lookup is a pure storage read.
func (h *LocationHandler) findConnectionByPeerGUID(peerGUID string) string {
	indexData, err := h.storage.Get("connections/_index")
	if err != nil {
		return ""
	}
	var connectionIDs []string
	if json.Unmarshal(indexData, &connectionIDs) != nil {
		return ""
	}
	for _, connID := range connectionIDs {
		data, err := h.storage.Get("connections/" + connID)
		if err != nil {
			continue
		}
		var conn ConnectionRecord
		if json.Unmarshal(data, &conn) != nil {
			continue
		}
		if conn.PeerGUID == peerGUID {
			return connID
		}
	}
	return ""
}

// cachePeerLocationAndMaybeNotify writes the latest peer location to
// connections/<connID>/_peer_location. On the first write for this
// connection (key absent, or last entry was explicitly cleared by
// V5 stop-sharing), it stamps FirstReceivedAt and emits the V3
// "started sharing" system-card notification to the app.
func (h *LocationHandler) cachePeerLocationAndMaybeNotify(ctx context.Context, connID string, update IncomingLocationUpdate) {
	key := peerLocationCacheKey(connID)
	now := update.UpdatedAt
	if now == "" {
		now = time.Now().UTC().Format(time.RFC3339)
	}

	// Try to read existing cache to decide transition.
	existed := false
	firstReceivedAt := now
	if existing, err := h.storage.Get(key); err == nil && len(existing) > 0 {
		var prev CachedPeerLocation
		if json.Unmarshal(existing, &prev) == nil && prev.FirstReceivedAt != "" {
			existed = true
			firstReceivedAt = prev.FirstReceivedAt
		}
	}

	cache := CachedPeerLocation{
		Latitude:        update.Latitude,
		Longitude:       update.Longitude,
		Accuracy:        update.Accuracy,
		Timestamp:       update.Timestamp,
		UpdatedAt:       now,
		FirstReceivedAt: firstReceivedAt,
	}
	cacheBytes, err := json.Marshal(cache)
	if err != nil {
		log.Warn().Err(err).Str("connection_id", connID).Msg("Failed to marshal cached peer location")
		return
	}
	if err := h.storage.Put(key, cacheBytes); err != nil {
		log.Warn().Err(err).Str("connection_id", connID).Msg("Failed to cache peer location")
		return
	}
	log.Info().
		Str("connection_id", connID).
		Str("from_owner_space", update.FromOwnerSpace).
		Bool("first_share_observation", !existed).
		Msg("Cached peer location")

	// V3: on transition (first observation, or first after a V5 stop),
	// emit the system-card notification. Idempotent absence of the
	// cache key is the trigger.
	if !existed {
		h.emitPeerLocationShareStarted(ctx, connID, update.FromOwnerSpace, now)
		// Audit: peer started sharing with us (or sent a one-shot —
		// indistinguishable on the receiver side). Same transition
		// gate as the system-card notification so the audit trail
		// and the activity feed agree.
		if h.auditLog != nil {
			h.auditLog.Append(AuditEntry{
				ConnectionID: connID,
				PeerGUID:     update.FromOwnerSpace,
				EventType:    AuditTypeLocationShareStarted,
				Direction:    AuditDirectionInbound,
				Title:        "Shared their location",
			})
		}
	}
}

// emitPeerLocationShareStarted publishes a one-shot notification to
// the owner's app announcing that a peer just started sharing their
// location. Used for the system-card activity-feed row + UI badge
// refresh. Non-fatal on failure — the cache write already landed.
func (h *LocationHandler) emitPeerLocationShareStarted(ctx context.Context, connID, fromOwnerSpace, startedAt string) {
	payload, err := json.Marshal(map[string]string{
		"connection_id":    connID,
		"from_owner_space": fromOwnerSpace,
		"started_at":       startedAt,
	})
	if err != nil {
		return
	}
	if err := h.publisher.PublishToApp(ctx, "connection.peer-location-share-started", payload); err != nil {
		log.Warn().Err(err).Str("connection_id", connID).Msg("Failed to publish peer-location-share-started notification")
	}
}

// --- Sharing internal helpers ---

// getSharingIndex loads the list of connection IDs that sharing is enabled for
func (h *LocationHandler) getSharingIndex() []string {
	var sharedWith []string
	if err := h.storage.GetJSON(locationSharingIndexKey, &sharedWith); err != nil {
		return []string{}
	}
	return sharedWith
}

// pushToSharedConnections iterates the sharing index and publishes the latest
// location point to each peer vault. Returns success and failure counts.
func (h *LocationHandler) pushToSharedConnections(ctx context.Context, point LocationPoint) (int, int) {
	sharedWith := h.getSharingIndex()
	if len(sharedWith) == 0 {
		return 0, 0
	}

	// Load settings for precision
	settings := h.getSettings()
	lat, lon := applyPrecision(point.Latitude, point.Longitude, settings)

	now := time.Now().UTC()
	successCount := 0
	failCount := 0

	for _, connID := range sharedWith {
		// Load connection record to get peer GUID
		connData, err := h.storage.Get("connections/" + connID)
		if err != nil {
			log.Warn().Err(err).Str("connection_id", connID).Msg("Failed to load connection for location push")
			failCount++
			continue
		}

		var conn ConnectionRecord
		if err := json.Unmarshal(connData, &conn); err != nil {
			log.Warn().Err(err).Str("connection_id", connID).Msg("Failed to parse connection for location push")
			failCount++
			continue
		}

		// Only push to active connections with valid peer GUID
		if conn.Status != "active" || conn.PeerGUID == "" {
			continue
		}

		eventID := fmt.Sprintf("loc:%s:%d", h.ownerSpace, point.Timestamp)
		update := IncomingLocationUpdate{
			EventID:        eventID,
			ConnectionID:   connID,
			FromOwnerSpace: h.ownerSpace, // V1 (2026-05-11): receiver resolves via this
			Latitude:       lat,
			Longitude:      lon,
			Accuracy:       point.Accuracy,
			Timestamp:      point.Timestamp,
			UpdatedAt:      now.Format(time.RFC3339),
		}
		updateData, _ := json.Marshal(update)

		if err := encryptAndPublishToPeer(
			ctx, h.storage, h.publisher, h.ownerSpace,
			connID, "location-update", eventID, updateData, now.Unix(),
		); err != nil {
			log.Warn().Err(err).Str("connection_id", connID).Msg("Failed to push location to peer")
			failCount++
		} else {
			successCount++
		}
	}

	if successCount > 0 || failCount > 0 {
		log.Info().
			Int("success", successCount).
			Int("failed", failCount).
			Msg("Location push to shared connections complete")
	}

	return successCount, failCount
}

// applyPrecision reduces coordinate precision based on settings.
// Returns coordinates rounded to the appropriate number of decimal places.
func applyPrecision(lat, lon float64, settings LocationSettings) (float64, float64) {
	// Default: no rounding (full precision)
	// Settings don't currently have a precision field, but the Android app
	// sends coordinates at the user's chosen precision level already.
	// This is a defense-in-depth measure in case raw coords are cached.
	return lat, lon
}

func (h *LocationHandler) errorResponse(id string, message string) (*OutgoingMessage, error) {
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
