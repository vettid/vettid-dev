package main

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// ServiceDataHandler handles on-demand data access from services.
// Key principles:
// - Services do NOT cache user profiles (on-demand access only)
// - All requests enforced against accepted contract
// - Rate limiting per connection
// - Sandboxed storage per service
type ServiceDataHandler struct {
	ownerSpace        string
	storage           *EncryptedStorage
	eventHandler      *EventHandler
	connectionHandler *ServiceConnectionHandler
	contractsHandler  *ServiceContractsHandler
	profileHandler    *ProfileHandler

	// Rate limiters per connection (in-memory, reset hourly)
	rateLimiters   map[string]*RateLimiter
	rateLimitersMu sync.Mutex
}

// RateLimiter implements token bucket rate limiting per connection
type RateLimiter struct {
	ConnectionID   string
	MaxPerHour     int
	TokensRemaining int
	WindowStart    time.Time
}

// NewServiceDataHandler creates a new service data handler
func NewServiceDataHandler(
	ownerSpace string,
	storage *EncryptedStorage,
	eventHandler *EventHandler,
	connectionHandler *ServiceConnectionHandler,
	contractsHandler *ServiceContractsHandler,
	profileHandler *ProfileHandler,
) *ServiceDataHandler {
	return &ServiceDataHandler{
		ownerSpace:        ownerSpace,
		storage:           storage,
		eventHandler:      eventHandler,
		connectionHandler: connectionHandler,
		contractsHandler:  contractsHandler,
		profileHandler:    profileHandler,
		rateLimiters:      make(map[string]*RateLimiter),
	}
}

// --- Data Models ---

// ServiceStorageRecord represents data stored by a service in user's sandbox
type ServiceStorageRecord struct {
	Key             string     `json:"key"`
	ConnectionID    string     `json:"connection_id"`
	Category        string     `json:"category"`
	VisibilityLevel string     `json:"visibility_level"` // "hidden", "metadata", "viewable"
	EncryptedValue  []byte     `json:"encrypted_value"`
	Label           string     `json:"label,omitempty"`
	Description     string     `json:"description,omitempty"`
	DataType        string     `json:"data_type,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
}

// --- Request/Response Types ---

// ServiceDataGetRequest is sent by services to request profile fields
type ServiceDataGetRequest struct {
	ConnectionID string   `json:"connection_id"`
	Fields       []string `json:"fields"`
	Purpose      string   `json:"purpose,omitempty"` // Why service needs this data
}

// ServiceDataGetResponse is returned to services
type ServiceDataGetResponse struct {
	Fields      map[string]string `json:"fields"`       // field -> encrypted value
	Denied      []string          `json:"denied,omitempty"` // Fields denied by contract
	RequireConsent []string       `json:"require_consent,omitempty"` // Fields needing explicit approval
}

// ServiceDataStoreRequest is sent by services to store data in user's sandbox
type ServiceDataStoreRequest struct {
	ConnectionID    string     `json:"connection_id"`
	Key             string     `json:"key"`
	Category        string     `json:"category"`
	VisibilityLevel string     `json:"visibility_level"` // "hidden", "metadata", "viewable"
	EncryptedValue  []byte     `json:"encrypted_value"`
	Label           string     `json:"label,omitempty"`
	Description     string     `json:"description,omitempty"`
	DataType        string     `json:"data_type,omitempty"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
}

// ServiceDataStoreResponse is returned after storing data
type ServiceDataStoreResponse struct {
	Success bool   `json:"success"`
	Key     string `json:"key"`
	Message string `json:"message,omitempty"`
}

// ServiceDataListRequest is for listing service-stored data (user-facing)
type ServiceDataListRequest struct {
	ConnectionID string `json:"connection_id"`
	Category     string `json:"category,omitempty"` // Filter by category
	Limit        int    `json:"limit,omitempty"`
	Offset       int    `json:"offset,omitempty"`
}

// ServiceDataListItem represents a data item for listing
type ServiceDataListItem struct {
	Key             string    `json:"key"`
	Category        string    `json:"category"`
	VisibilityLevel string    `json:"visibility_level"`
	Label           string    `json:"label,omitempty"`
	Description     string    `json:"description,omitempty"`
	DataType        string    `json:"data_type,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	// Value only included if visibility is "viewable"
	Value []byte `json:"value,omitempty"`
}

// ServiceDataListResponse is returned for list requests
type ServiceDataListResponse struct {
	Items   []ServiceDataListItem `json:"items"`
	Total   int                   `json:"total"`
	HasMore bool                  `json:"has_more"`
}

// ServiceDataDeleteRequest is for deleting service data (user-facing)
type ServiceDataDeleteRequest struct {
	ConnectionID string   `json:"connection_id"`
	Keys         []string `json:"keys,omitempty"`    // Specific keys to delete
	DeleteAll    bool     `json:"delete_all"`        // Delete all data from this service
}

// ServiceDataDeleteResponse is returned after deletion
type ServiceDataDeleteResponse struct {
	Success      bool `json:"success"`
	ItemsDeleted int  `json:"items_deleted"`
}

// ServiceDataSummaryRequest is for getting storage summary (user-facing)
type ServiceDataSummaryRequest struct {
	ConnectionID string `json:"connection_id"`
}

// ServiceDataSummary shows storage usage for a service
type ServiceDataSummary struct {
	ConnectionID   string         `json:"connection_id"`
	TotalItems     int            `json:"total_items"`
	TotalSizeBytes int64          `json:"total_size_bytes"`
	Categories     map[string]int `json:"categories"` // Category -> item count
	OldestItem     *time.Time     `json:"oldest_item,omitempty"`
	NewestItem     *time.Time     `json:"newest_item,omitempty"`
}

// ServiceDataExportRequest is for exporting all service data (user-facing)
type ServiceDataExportRequest struct {
	ConnectionID string `json:"connection_id"`
	Format       string `json:"format"` // "json"
}

// ServiceDataExportResponse contains exported data
type ServiceDataExportResponse struct {
	Data       []byte `json:"data"`
	Format     string `json:"format"`
	ItemCount  int    `json:"item_count"`
	ExportedAt string `json:"exported_at"`
}

// --- Handler Methods ---

func (h *ServiceDataHandler) errorResponse(requestID, message string) (*OutgoingMessage, error) {
	resp := map[string]interface{}{
		"success": false,
		"error":   message,
	}
	respBytes, _ := json.Marshal(resp)
	return &OutgoingMessage{
		RequestID: requestID,
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleGet handles incoming data requests from services
// Enforces contract and rate limiting
func (h *ServiceDataHandler) HandleGet(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req ServiceDataGetRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}
	if len(req.Fields) == 0 {
		return h.errorResponse(msg.GetID(), "fields are required")
	}

	// Get connection and verify active
	conn, err := h.connectionHandler.GetConnection(req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}
	if conn.Status != "active" {
		return h.errorResponse(msg.GetID(), "Connection is not active")
	}

	// Check rate limit
	if err := h.checkRateLimit(req.ConnectionID, conn.ServiceProfile.CurrentContract.MaxRequestsPerHour); err != nil {
		// Log rate limit exceeded
		if h.eventHandler != nil {
			h.eventHandler.LogConnectionEvent(
				context.Background(),
				EventTypeServiceRateLimitExceeded,
				req.ConnectionID,
				conn.ServiceGUID,
				"Rate limit exceeded for data request",
			)
		}
		return h.errorResponse(msg.GetID(), "Rate limit exceeded")
	}

	// Enforce contract
	allowed, denied, err := h.contractsHandler.EnforceContract(req.ConnectionID, req.Fields, "read")
	if err != nil {
		return h.errorResponse(msg.GetID(), "Contract enforcement failed")
	}

	// Check for consent fields
	var requireConsent []string
	for _, field := range req.Fields {
		for _, cf := range conn.ServiceProfile.CurrentContract.ConsentFields {
			if cf == field && containsString(denied, field) {
				requireConsent = append(requireConsent, field)
			}
		}
	}

	// Get allowed fields from profile
	fields := make(map[string]string)
	allowedFields := make([]string, 0)
	for _, field := range req.Fields {
		if !containsString(denied, field) && !containsString(requireConsent, field) {
			allowedFields = append(allowedFields, field)
		}
	}

	for _, field := range allowedFields {
		data, err := h.storage.Get("profile/" + field)
		if err != nil {
			continue
		}

		var entry ProfileEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			continue
		}
		fields[field] = entry.Value
	}

	// Update last active time
	h.connectionHandler.UpdateLastActive(req.ConnectionID)

	// Log data access
	if h.eventHandler != nil && len(fields) > 0 {
		h.eventHandler.LogConnectionEvent(
			context.Background(),
			EventTypeServiceDataProvided,
			req.ConnectionID,
			conn.ServiceGUID,
			"Provided "+string(rune(len(fields)))+" profile field(s)",
		)
	}

	if !allowed && len(denied) > 0 {
		// Log denied access
		if h.eventHandler != nil {
			h.eventHandler.LogConnectionEvent(
				context.Background(),
				EventTypeServiceDataDenied,
				req.ConnectionID,
				conn.ServiceGUID,
				"Denied access to "+string(rune(len(denied)))+" field(s)",
			)
		}
	}

	log.Info().
		Str("connection_id", req.ConnectionID).
		Int("fields_provided", len(fields)).
		Int("fields_denied", len(denied)).
		Msg("Service data request processed")

	resp := ServiceDataGetResponse{
		Fields:         fields,
		Denied:         denied,
		RequireConsent: requireConsent,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleStore handles data storage requests from services
// Stores data in service's sandbox in user's vault
func (h *ServiceDataHandler) HandleStore(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req ServiceDataStoreRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}
	if req.Key == "" {
		return h.errorResponse(msg.GetID(), "key is required")
	}

	// Get connection and verify active
	conn, err := h.connectionHandler.GetConnection(req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}
	if conn.Status != "active" {
		return h.errorResponse(msg.GetID(), "Connection is not active")
	}

	// Check if service has storage permission
	if !conn.ServiceProfile.CurrentContract.CanStoreData {
		return h.errorResponse(msg.GetID(), "Service does not have storage permission")
	}

	// Check category is allowed
	if req.Category != "" && len(conn.ServiceProfile.CurrentContract.StorageCategories) > 0 {
		allowed := false
		for _, cat := range conn.ServiceProfile.CurrentContract.StorageCategories {
			if cat == req.Category {
				allowed = true
				break
			}
		}
		if !allowed {
			return h.errorResponse(msg.GetID(), "Category not allowed by contract")
		}
	}

	// Validate visibility level
	if req.VisibilityLevel == "" {
		req.VisibilityLevel = "hidden"
	}
	if req.VisibilityLevel != "hidden" && req.VisibilityLevel != "metadata" && req.VisibilityLevel != "viewable" {
		return h.errorResponse(msg.GetID(), "Invalid visibility_level")
	}

	// Check storage quota
	summary, _ := h.getStorageSummary(req.ConnectionID)
	maxStorage := int64(conn.ServiceProfile.CurrentContract.MaxStorageMB * 1024 * 1024)
	if maxStorage > 0 && summary.TotalSizeBytes+int64(len(req.EncryptedValue)) > maxStorage {
		return h.errorResponse(msg.GetID(), "Storage quota exceeded")
	}

	now := time.Now()
	record := ServiceStorageRecord{
		Key:             req.Key,
		ConnectionID:    req.ConnectionID,
		Category:        req.Category,
		VisibilityLevel: req.VisibilityLevel,
		EncryptedValue:  req.EncryptedValue,
		Label:           req.Label,
		Description:     req.Description,
		DataType:        req.DataType,
		CreatedAt:       now,
		UpdatedAt:       now,
		ExpiresAt:       req.ExpiresAt,
	}

	data, _ := json.Marshal(record)
	storageKey := "service-data/" + req.ConnectionID + "/" + req.Key
	if err := h.storage.Put(storageKey, data); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to store data")
	}

	// Update index
	h.addToDataIndex(req.ConnectionID, req.Key)

	// Update last active
	h.connectionHandler.UpdateLastActive(req.ConnectionID)

	// Log event
	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(
			context.Background(),
			EventTypeServiceDataStored,
			req.ConnectionID,
			conn.ServiceGUID,
			"Stored data: "+req.Label,
		)
	}

	log.Info().
		Str("connection_id", req.ConnectionID).
		Str("key", req.Key).
		Str("category", req.Category).
		Msg("Service data stored")

	resp := ServiceDataStoreResponse{
		Success: true,
		Key:     req.Key,
		Message: "Data stored successfully",
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleList handles listing service-stored data (user-facing)
func (h *ServiceDataHandler) HandleList(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req ServiceDataListRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	if req.Limit <= 0 {
		req.Limit = 50
	}
	if req.Limit > 100 {
		req.Limit = 100
	}

	// Load data index
	indexData, err := h.storage.Get("service-data/" + req.ConnectionID + "/_index")
	var keys []string
	if err == nil {
		json.Unmarshal(indexData, &keys)
	}

	var items []ServiceDataListItem
	for _, key := range keys {
		data, err := h.storage.Get("service-data/" + req.ConnectionID + "/" + key)
		if err != nil {
			continue
		}

		var record ServiceStorageRecord
		if err := json.Unmarshal(data, &record); err != nil {
			continue
		}

		// Apply category filter
		if req.Category != "" && record.Category != req.Category {
			continue
		}

		item := ServiceDataListItem{
			Key:             record.Key,
			Category:        record.Category,
			VisibilityLevel: record.VisibilityLevel,
			Label:           record.Label,
			Description:     record.Description,
			DataType:        record.DataType,
			CreatedAt:       record.CreatedAt,
			UpdatedAt:       record.UpdatedAt,
		}

		// Only include value if viewable
		if record.VisibilityLevel == "viewable" {
			item.Value = record.EncryptedValue
		}

		items = append(items, item)
	}

	// Apply pagination
	total := len(items)
	start := req.Offset
	if start > total {
		start = total
	}
	end := start + req.Limit
	if end > total {
		end = total
	}

	paginatedItems := items[start:end]
	if paginatedItems == nil {
		paginatedItems = []ServiceDataListItem{}
	}

	resp := ServiceDataListResponse{
		Items:   paginatedItems,
		Total:   total,
		HasMore: end < total,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleDelete handles deleting service data (user-facing)
func (h *ServiceDataHandler) HandleDelete(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req ServiceDataDeleteRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	var keysToDelete []string

	if req.DeleteAll {
		// Get all keys from index
		indexData, err := h.storage.Get("service-data/" + req.ConnectionID + "/_index")
		if err == nil {
			json.Unmarshal(indexData, &keysToDelete)
		}
	} else {
		keysToDelete = req.Keys
	}

	deletedCount := 0
	for _, key := range keysToDelete {
		storageKey := "service-data/" + req.ConnectionID + "/" + key
		if err := h.storage.Delete(storageKey); err == nil {
			deletedCount++
		}
	}

	// Update index
	if req.DeleteAll {
		h.storage.Delete("service-data/" + req.ConnectionID + "/_index")
	} else {
		h.removeFromDataIndex(req.ConnectionID, keysToDelete)
	}

	// Log event
	if h.eventHandler != nil {
		conn, _ := h.connectionHandler.GetConnection(req.ConnectionID)
		serviceGUID := ""
		if conn != nil {
			serviceGUID = conn.ServiceGUID
		}
		h.eventHandler.LogConnectionEvent(
			context.Background(),
			EventTypeServiceDataDeleted,
			req.ConnectionID,
			serviceGUID,
			"Deleted service data",
		)
	}

	log.Info().
		Str("connection_id", req.ConnectionID).
		Int("deleted_count", deletedCount).
		Msg("Service data deleted")

	resp := ServiceDataDeleteResponse{
		Success:      true,
		ItemsDeleted: deletedCount,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleSummary handles getting storage summary (user-facing)
func (h *ServiceDataHandler) HandleSummary(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req ServiceDataSummaryRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	summary, err := h.getStorageSummary(req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to get storage summary")
	}

	respBytes, _ := json.Marshal(summary)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleExport handles exporting all service data (user-facing)
func (h *ServiceDataHandler) HandleExport(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req ServiceDataExportRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	// Load all data
	indexData, err := h.storage.Get("service-data/" + req.ConnectionID + "/_index")
	var keys []string
	if err == nil {
		json.Unmarshal(indexData, &keys)
	}

	var records []ServiceStorageRecord
	for _, key := range keys {
		data, err := h.storage.Get("service-data/" + req.ConnectionID + "/" + key)
		if err != nil {
			continue
		}

		var record ServiceStorageRecord
		if err := json.Unmarshal(data, &record); err != nil {
			continue
		}

		records = append(records, record)
	}

	// Export as JSON
	exportData, _ := json.MarshalIndent(map[string]interface{}{
		"connection_id": req.ConnectionID,
		"exported_at":   time.Now().Format(time.RFC3339),
		"item_count":    len(records),
		"data":          records,
	}, "", "  ")

	resp := ServiceDataExportResponse{
		Data:       exportData,
		Format:     "json",
		ItemCount:  len(records),
		ExportedAt: time.Now().Format(time.RFC3339),
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// --- Helper Methods ---

// checkRateLimit checks and updates rate limit for a connection
func (h *ServiceDataHandler) checkRateLimit(connectionID string, maxPerHour int) error {
	if maxPerHour <= 0 {
		return nil // No rate limit configured
	}

	h.rateLimitersMu.Lock()
	defer h.rateLimitersMu.Unlock()

	now := time.Now()

	rl, exists := h.rateLimiters[connectionID]
	if !exists {
		// Create new rate limiter
		h.rateLimiters[connectionID] = &RateLimiter{
			ConnectionID:    connectionID,
			MaxPerHour:      maxPerHour,
			TokensRemaining: maxPerHour - 1, // Consume one token
			WindowStart:     now,
		}
		return nil
	}

	// Check if window has expired (reset after 1 hour)
	if now.Sub(rl.WindowStart) > time.Hour {
		rl.TokensRemaining = maxPerHour - 1
		rl.WindowStart = now
		return nil
	}

	// Check if tokens available
	if rl.TokensRemaining <= 0 {
		return &RateLimitError{
			ConnectionID: connectionID,
			Limit:        maxPerHour,
			ResetAt:      rl.WindowStart.Add(time.Hour),
		}
	}

	// Consume token
	rl.TokensRemaining--
	return nil
}

// RateLimitError represents a rate limit exceeded error
type RateLimitError struct {
	ConnectionID string
	Limit        int
	ResetAt      time.Time
}

func (e *RateLimitError) Error() string {
	return "rate limit exceeded"
}

// getStorageSummary calculates storage summary for a connection
func (h *ServiceDataHandler) getStorageSummary(connectionID string) (*ServiceDataSummary, error) {
	summary := &ServiceDataSummary{
		ConnectionID: connectionID,
		Categories:   make(map[string]int),
	}

	indexData, err := h.storage.Get("service-data/" + connectionID + "/_index")
	var keys []string
	if err == nil {
		json.Unmarshal(indexData, &keys)
	}

	for _, key := range keys {
		data, err := h.storage.Get("service-data/" + connectionID + "/" + key)
		if err != nil {
			continue
		}

		var record ServiceStorageRecord
		if err := json.Unmarshal(data, &record); err != nil {
			continue
		}

		summary.TotalItems++
		summary.TotalSizeBytes += int64(len(record.EncryptedValue))
		summary.Categories[record.Category]++

		if summary.OldestItem == nil || record.CreatedAt.Before(*summary.OldestItem) {
			summary.OldestItem = &record.CreatedAt
		}
		if summary.NewestItem == nil || record.CreatedAt.After(*summary.NewestItem) {
			summary.NewestItem = &record.UpdatedAt
		}
	}

	return summary, nil
}

// addToDataIndex adds a key to the connection's data index
func (h *ServiceDataHandler) addToDataIndex(connectionID, key string) {
	indexKey := "service-data/" + connectionID + "/_index"
	indexData, _ := h.storage.Get(indexKey)

	var keys []string
	if indexData != nil {
		json.Unmarshal(indexData, &keys)
	}

	// Add if not present
	for _, k := range keys {
		if k == key {
			return
		}
	}
	keys = append(keys, key)

	newIndexData, _ := json.Marshal(keys)
	h.storage.Put(indexKey, newIndexData)
}

// removeFromDataIndex removes keys from the connection's data index
func (h *ServiceDataHandler) removeFromDataIndex(connectionID string, keysToRemove []string) {
	indexKey := "service-data/" + connectionID + "/_index"
	indexData, _ := h.storage.Get(indexKey)

	var keys []string
	if indexData != nil {
		json.Unmarshal(indexData, &keys)
	}

	// Filter out removed keys
	removeSet := make(map[string]bool)
	for _, k := range keysToRemove {
		removeSet[k] = true
	}

	var newKeys []string
	for _, k := range keys {
		if !removeSet[k] {
			newKeys = append(newKeys, k)
		}
	}

	newIndexData, _ := json.Marshal(newKeys)
	h.storage.Put(indexKey, newIndexData)
}
