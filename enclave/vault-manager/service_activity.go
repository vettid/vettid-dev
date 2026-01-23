package main

import (
	"encoding/json"
	"time"

	"github.com/rs/zerolog/log"
)

// ServiceActivityHandler handles activity logging and transparency for service connections.
// Phase 7: Activity & Transparency
type ServiceActivityHandler struct {
	ownerSpace        string
	storage           *EncryptedStorage
	eventHandler      *EventHandler
	connectionHandler *ServiceConnectionHandler
}

// NewServiceActivityHandler creates a new service activity handler
func NewServiceActivityHandler(
	ownerSpace string,
	storage *EncryptedStorage,
	eventHandler *EventHandler,
	connectionHandler *ServiceConnectionHandler,
) *ServiceActivityHandler {
	return &ServiceActivityHandler{
		ownerSpace:        ownerSpace,
		storage:           storage,
		eventHandler:      eventHandler,
		connectionHandler: connectionHandler,
	}
}

// --- Data Models ---

// ServiceActivity represents a logged activity for a service connection
type ServiceActivity struct {
	ActivityID    string            `json:"activity_id"`
	ConnectionID  string            `json:"connection_id"`
	ServiceGUID   string            `json:"service_guid"`
	ServiceName   string            `json:"service_name"`
	ActivityType  string            `json:"activity_type"` // "data_request", "data_store", "auth", "consent", "payment", "notification", "call"
	Description   string            `json:"description"`
	Fields        []string          `json:"fields,omitempty"`       // Fields accessed
	Amount        *Money            `json:"amount,omitempty"`       // For payment activities
	Status        string            `json:"status"`                 // "approved", "denied", "pending", "completed", "failed"
	RequestID     string            `json:"request_id,omitempty"`   // Related request ID
	Metadata      map[string]string `json:"metadata,omitempty"`
	Timestamp     time.Time         `json:"timestamp"`
	DurationMs    int64             `json:"duration_ms,omitempty"` // How long the operation took
}

// ActivitySummary provides aggregated statistics for a connection
type ActivitySummary struct {
	ConnectionID         string            `json:"connection_id"`
	ServiceGUID          string            `json:"service_guid"`
	ServiceName          string            `json:"service_name"`
	TotalActivities      int               `json:"total_activities"`
	ActivitiesByType     map[string]int    `json:"activities_by_type"`
	ActivitiesByStatus   map[string]int    `json:"activities_by_status"`
	FirstActivityAt      *time.Time        `json:"first_activity_at,omitempty"`
	LastActivityAt       *time.Time        `json:"last_activity_at,omitempty"`
	FieldAccessCounts    map[string]int    `json:"field_access_counts"`   // How many times each field was accessed
	TotalDataRequests    int               `json:"total_data_requests"`
	ApprovedDataRequests int               `json:"approved_data_requests"`
	DeniedDataRequests   int               `json:"denied_data_requests"`
	TotalPaymentAmount   int64             `json:"total_payment_amount"`
	PaymentCurrency      string            `json:"payment_currency,omitempty"`
	Period               string            `json:"period"` // "all_time", "30_days", "7_days", "24_hours"
}

// DataSummary provides storage usage summary for a service
type DataSummary struct {
	ConnectionID    string          `json:"connection_id"`
	ServiceGUID     string          `json:"service_guid"`
	TotalItems      int             `json:"total_items"`
	TotalSizeBytes  int64           `json:"total_size_bytes"`
	StorageLimitMB  int             `json:"storage_limit_mb"`
	UsagePercent    float64         `json:"usage_percent"`
	ItemsByCategory map[string]int  `json:"items_by_category"`
	OldestItemAt    *time.Time      `json:"oldest_item_at,omitempty"`
	NewestItemAt    *time.Time      `json:"newest_item_at,omitempty"`
}

// DataExport contains all data stored by a service for export
type DataExport struct {
	ConnectionID  string           `json:"connection_id"`
	ServiceGUID   string           `json:"service_guid"`
	ServiceName   string           `json:"service_name"`
	ExportedAt    time.Time        `json:"exported_at"`
	ItemCount     int              `json:"item_count"`
	TotalSizeBytes int64           `json:"total_size_bytes"`
	Items         []DataExportItem `json:"items"`
}

// DataExportItem is a single item in the export
type DataExportItem struct {
	ItemID    string          `json:"item_id"`
	Category  string          `json:"category"`
	Key       string          `json:"key"`
	Data      json.RawMessage `json:"data"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
	SizeBytes int64           `json:"size_bytes"`
}

// --- Request/Response Types ---

// ListActivityRequest is the payload for service.activity.list
type ListActivityRequest struct {
	ConnectionID string   `json:"connection_id"`
	ActivityType string   `json:"activity_type,omitempty"` // Filter by type
	Status       string   `json:"status,omitempty"`        // Filter by status
	Since        *int64   `json:"since,omitempty"`         // Unix timestamp
	Until        *int64   `json:"until,omitempty"`         // Unix timestamp
	Limit        int      `json:"limit,omitempty"`
	Offset       int      `json:"offset,omitempty"`
}

// ListActivityResponse contains activity list
type ListActivityResponse struct {
	Activities []ServiceActivity `json:"activities"`
	Total      int               `json:"total"`
	HasMore    bool              `json:"has_more"`
}

// GetActivitySummaryRequest is the payload for service.activity.summary
type GetActivitySummaryRequest struct {
	ConnectionID string `json:"connection_id"`
	Period       string `json:"period,omitempty"` // "all_time", "30_days", "7_days", "24_hours"
}

// GetDataSummaryRequest is the payload for service.data.summary
type GetDataSummaryRequest struct {
	ConnectionID string `json:"connection_id"`
}

// ExportDataRequest is the payload for service.data.export
type ExportDataRequest struct {
	ConnectionID string `json:"connection_id"`
	Format       string `json:"format,omitempty"` // "json" (default)
}

// --- Handler Methods ---

func (h *ServiceActivityHandler) errorResponse(requestID, message string) (*OutgoingMessage, error) {
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

// HandleActivityList handles service.activity.list
func (h *ServiceActivityHandler) HandleActivityList(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req ListActivityRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	// Verify connection exists
	_, err := h.connectionHandler.GetConnection(req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}

	if req.Limit <= 0 {
		req.Limit = 50
	}
	if req.Limit > 100 {
		req.Limit = 100
	}

	// Load activity index for this connection
	indexKey := "service-activity/" + req.ConnectionID + "/_index"
	indexData, _ := h.storage.Get(indexKey)
	var activityIDs []string
	if indexData != nil {
		json.Unmarshal(indexData, &activityIDs)
	}

	var activities []ServiceActivity
	for _, actID := range activityIDs {
		data, err := h.storage.Get("service-activity/" + req.ConnectionID + "/" + actID)
		if err != nil {
			continue
		}

		var activity ServiceActivity
		if err := json.Unmarshal(data, &activity); err != nil {
			continue
		}

		// Apply filters
		if req.ActivityType != "" && activity.ActivityType != req.ActivityType {
			continue
		}
		if req.Status != "" && activity.Status != req.Status {
			continue
		}
		if req.Since != nil && activity.Timestamp.Unix() < *req.Since {
			continue
		}
		if req.Until != nil && activity.Timestamp.Unix() > *req.Until {
			continue
		}

		activities = append(activities, activity)
	}

	// Apply pagination
	total := len(activities)
	start := req.Offset
	if start > total {
		start = total
	}
	end := start + req.Limit
	if end > total {
		end = total
	}

	paginatedActivities := activities[start:end]
	if paginatedActivities == nil {
		paginatedActivities = []ServiceActivity{}
	}

	resp := ListActivityResponse{
		Activities: paginatedActivities,
		Total:      total,
		HasMore:    end < total,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleActivitySummary handles service.activity.summary
func (h *ServiceActivityHandler) HandleActivitySummary(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req GetActivitySummaryRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	conn, err := h.connectionHandler.GetConnection(req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}

	period := req.Period
	if period == "" {
		period = "all_time"
	}

	// Calculate time cutoff
	var cutoff time.Time
	switch period {
	case "24_hours":
		cutoff = time.Now().Add(-24 * time.Hour)
	case "7_days":
		cutoff = time.Now().Add(-7 * 24 * time.Hour)
	case "30_days":
		cutoff = time.Now().Add(-30 * 24 * time.Hour)
	default:
		cutoff = time.Time{} // No cutoff for all_time
	}

	// Load and aggregate activities
	indexKey := "service-activity/" + req.ConnectionID + "/_index"
	indexData, _ := h.storage.Get(indexKey)
	var activityIDs []string
	if indexData != nil {
		json.Unmarshal(indexData, &activityIDs)
	}

	summary := ActivitySummary{
		ConnectionID:       req.ConnectionID,
		ServiceGUID:        conn.ServiceGUID,
		ServiceName:        conn.ServiceProfile.ServiceName,
		ActivitiesByType:   make(map[string]int),
		ActivitiesByStatus: make(map[string]int),
		FieldAccessCounts:  make(map[string]int),
		Period:             period,
	}

	var firstActivity, lastActivity *time.Time

	for _, actID := range activityIDs {
		data, err := h.storage.Get("service-activity/" + req.ConnectionID + "/" + actID)
		if err != nil {
			continue
		}

		var activity ServiceActivity
		if err := json.Unmarshal(data, &activity); err != nil {
			continue
		}

		// Apply time filter
		if !cutoff.IsZero() && activity.Timestamp.Before(cutoff) {
			continue
		}

		summary.TotalActivities++
		summary.ActivitiesByType[activity.ActivityType]++
		summary.ActivitiesByStatus[activity.Status]++

		// Track data requests
		if activity.ActivityType == "data_request" {
			summary.TotalDataRequests++
			if activity.Status == "approved" {
				summary.ApprovedDataRequests++
			} else if activity.Status == "denied" {
				summary.DeniedDataRequests++
			}
		}

		// Track field access
		for _, field := range activity.Fields {
			summary.FieldAccessCounts[field]++
		}

		// Track payment totals
		if activity.ActivityType == "payment" && activity.Amount != nil && activity.Status == "approved" {
			summary.TotalPaymentAmount += activity.Amount.Amount
			if summary.PaymentCurrency == "" {
				summary.PaymentCurrency = activity.Amount.Currency
			}
		}

		// Track first/last activity
		if firstActivity == nil || activity.Timestamp.Before(*firstActivity) {
			t := activity.Timestamp
			firstActivity = &t
		}
		if lastActivity == nil || activity.Timestamp.After(*lastActivity) {
			t := activity.Timestamp
			lastActivity = &t
		}
	}

	summary.FirstActivityAt = firstActivity
	summary.LastActivityAt = lastActivity

	respBytes, _ := json.Marshal(summary)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleDataSummary handles service.data.summary
func (h *ServiceActivityHandler) HandleDataSummary(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req GetDataSummaryRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	conn, err := h.connectionHandler.GetConnection(req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}

	// Load data index for this connection
	indexKey := "service-data/" + req.ConnectionID + "/_index"
	indexData, _ := h.storage.Get(indexKey)
	var itemIDs []string
	if indexData != nil {
		json.Unmarshal(indexData, &itemIDs)
	}

	summary := DataSummary{
		ConnectionID:    req.ConnectionID,
		ServiceGUID:     conn.ServiceGUID,
		StorageLimitMB:  conn.ServiceProfile.CurrentContract.MaxStorageMB,
		ItemsByCategory: make(map[string]int),
	}

	var oldestItem, newestItem *time.Time

	for _, itemID := range itemIDs {
		data, err := h.storage.Get("service-data/" + req.ConnectionID + "/" + itemID)
		if err != nil {
			continue
		}

		var item struct {
			Category  string    `json:"category"`
			CreatedAt time.Time `json:"created_at"`
			UpdatedAt time.Time `json:"updated_at"`
		}
		if err := json.Unmarshal(data, &item); err != nil {
			continue
		}

		summary.TotalItems++
		summary.TotalSizeBytes += int64(len(data))
		summary.ItemsByCategory[item.Category]++

		if oldestItem == nil || item.CreatedAt.Before(*oldestItem) {
			oldestItem = &item.CreatedAt
		}
		if newestItem == nil || item.UpdatedAt.After(*newestItem) {
			newestItem = &item.UpdatedAt
		}
	}

	summary.OldestItemAt = oldestItem
	summary.NewestItemAt = newestItem

	if summary.StorageLimitMB > 0 {
		limitBytes := float64(summary.StorageLimitMB * 1024 * 1024)
		summary.UsagePercent = (float64(summary.TotalSizeBytes) / limitBytes) * 100
	}

	respBytes, _ := json.Marshal(summary)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleDataExport handles service.data.export
func (h *ServiceActivityHandler) HandleDataExport(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req ExportDataRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	conn, err := h.connectionHandler.GetConnection(req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}

	// Load data index for this connection
	indexKey := "service-data/" + req.ConnectionID + "/_index"
	indexData, _ := h.storage.Get(indexKey)
	var itemIDs []string
	if indexData != nil {
		json.Unmarshal(indexData, &itemIDs)
	}

	export := DataExport{
		ConnectionID: req.ConnectionID,
		ServiceGUID:  conn.ServiceGUID,
		ServiceName:  conn.ServiceProfile.ServiceName,
		ExportedAt:   time.Now(),
		Items:        []DataExportItem{},
	}

	for _, itemID := range itemIDs {
		data, err := h.storage.Get("service-data/" + req.ConnectionID + "/" + itemID)
		if err != nil {
			continue
		}

		var item struct {
			ItemID    string          `json:"item_id"`
			Category  string          `json:"category"`
			Key       string          `json:"key"`
			Data      json.RawMessage `json:"data"`
			CreatedAt time.Time       `json:"created_at"`
			UpdatedAt time.Time       `json:"updated_at"`
		}
		if err := json.Unmarshal(data, &item); err != nil {
			continue
		}

		exportItem := DataExportItem{
			ItemID:    item.ItemID,
			Category:  item.Category,
			Key:       item.Key,
			Data:      item.Data,
			CreatedAt: item.CreatedAt,
			UpdatedAt: item.UpdatedAt,
			SizeBytes: int64(len(data)),
		}

		export.Items = append(export.Items, exportItem)
		export.TotalSizeBytes += exportItem.SizeBytes
	}

	export.ItemCount = len(export.Items)

	log.Info().
		Str("connection_id", req.ConnectionID).
		Int("items", export.ItemCount).
		Int64("bytes", export.TotalSizeBytes).
		Msg("Service data exported")

	respBytes, _ := json.Marshal(export)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// --- Activity Logging Methods ---

// LogActivity records an activity for a service connection
func (h *ServiceActivityHandler) LogActivity(activity *ServiceActivity) error {
	if activity.ActivityID == "" {
		activity.ActivityID = generateUUID()
	}
	if activity.Timestamp.IsZero() {
		activity.Timestamp = time.Now()
	}

	// Store activity
	storageKey := "service-activity/" + activity.ConnectionID + "/" + activity.ActivityID
	data, err := json.Marshal(activity)
	if err != nil {
		return err
	}
	if err := h.storage.Put(storageKey, data); err != nil {
		return err
	}

	// Update index (prepend for most-recent-first ordering)
	indexKey := "service-activity/" + activity.ConnectionID + "/_index"
	indexData, _ := h.storage.Get(indexKey)
	var activityIDs []string
	if indexData != nil {
		json.Unmarshal(indexData, &activityIDs)
	}

	activityIDs = append([]string{activity.ActivityID}, activityIDs...)

	// Limit index size (keep last 1000 activities per connection)
	if len(activityIDs) > 1000 {
		activityIDs = activityIDs[:1000]
	}

	newIndexData, _ := json.Marshal(activityIDs)
	return h.storage.Put(indexKey, newIndexData)
}

// LogDataRequest logs a data request activity
func (h *ServiceActivityHandler) LogDataRequest(connectionID, serviceGUID, serviceName string, fields []string, status string) {
	activity := &ServiceActivity{
		ConnectionID: connectionID,
		ServiceGUID:  serviceGUID,
		ServiceName:  serviceName,
		ActivityType: "data_request",
		Description:  "Data request for fields",
		Fields:       fields,
		Status:       status,
	}
	if err := h.LogActivity(activity); err != nil {
		log.Warn().Err(err).Str("connection_id", connectionID).Msg("Failed to log data request activity")
	}
}

// LogAuthRequest logs an auth request activity
func (h *ServiceActivityHandler) LogAuthRequest(connectionID, serviceGUID, serviceName, requestID, status string) {
	activity := &ServiceActivity{
		ConnectionID: connectionID,
		ServiceGUID:  serviceGUID,
		ServiceName:  serviceName,
		ActivityType: "auth",
		Description:  "Authentication request",
		RequestID:    requestID,
		Status:       status,
	}
	if err := h.LogActivity(activity); err != nil {
		log.Warn().Err(err).Str("connection_id", connectionID).Msg("Failed to log auth activity")
	}
}

// LogPaymentRequest logs a payment request activity
func (h *ServiceActivityHandler) LogPaymentRequest(connectionID, serviceGUID, serviceName, requestID string, amount *Money, status string) {
	activity := &ServiceActivity{
		ConnectionID: connectionID,
		ServiceGUID:  serviceGUID,
		ServiceName:  serviceName,
		ActivityType: "payment",
		Description:  "Payment request",
		RequestID:    requestID,
		Amount:       amount,
		Status:       status,
	}
	if err := h.LogActivity(activity); err != nil {
		log.Warn().Err(err).Str("connection_id", connectionID).Msg("Failed to log payment activity")
	}
}

// LogNotification logs a notification activity
func (h *ServiceActivityHandler) LogNotification(connectionID, serviceGUID, serviceName, title string) {
	activity := &ServiceActivity{
		ConnectionID: connectionID,
		ServiceGUID:  serviceGUID,
		ServiceName:  serviceName,
		ActivityType: "notification",
		Description:  title,
		Status:       "completed",
	}
	if err := h.LogActivity(activity); err != nil {
		log.Warn().Err(err).Str("connection_id", connectionID).Msg("Failed to log notification activity")
	}
}

// LogCall logs a call activity
func (h *ServiceActivityHandler) LogCall(connectionID, serviceGUID, serviceName, callID, callType, status string) {
	activity := &ServiceActivity{
		ConnectionID: connectionID,
		ServiceGUID:  serviceGUID,
		ServiceName:  serviceName,
		ActivityType: "call",
		Description:  callType + " call",
		RequestID:    callID,
		Status:       status,
		Metadata: map[string]string{
			"call_type": callType,
		},
	}
	if err := h.LogActivity(activity); err != nil {
		log.Warn().Err(err).Str("connection_id", connectionID).Msg("Failed to log call activity")
	}
}
