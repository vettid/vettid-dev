package main

import (
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
}

// NewLocationHandler creates a new location handler
func NewLocationHandler(ownerSpace string, storage *EncryptedStorage) *LocationHandler {
	return &LocationHandler{
		ownerSpace: ownerSpace,
		storage:    storage,
	}
}

// --- Storage keys ---

const (
	locationSettingsKey = "location/_settings"
	locationIndexKey    = "location/_index"
	locationPrefix      = "location/"
)

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
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
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
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
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
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
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
	if err := json.Unmarshal(msg.Payload, &settings); err != nil {
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
