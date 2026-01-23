package main

import (
	"encoding/json"
	"time"

	"github.com/rs/zerolog/log"
)

// ServiceNotificationsHandler handles per-service notification settings and trust indicators.
// Phase 8: Notifications & Trust
type ServiceNotificationsHandler struct {
	ownerSpace        string
	storage           *EncryptedStorage
	eventHandler      *EventHandler
	connectionHandler *ServiceConnectionHandler
}

// NewServiceNotificationsHandler creates a new service notifications handler
func NewServiceNotificationsHandler(
	ownerSpace string,
	storage *EncryptedStorage,
	eventHandler *EventHandler,
	connectionHandler *ServiceConnectionHandler,
) *ServiceNotificationsHandler {
	return &ServiceNotificationsHandler{
		ownerSpace:        ownerSpace,
		storage:           storage,
		eventHandler:      eventHandler,
		connectionHandler: connectionHandler,
	}
}

// --- Data Models ---

// ServiceNotificationSettings stores per-service notification preferences
type ServiceNotificationSettings struct {
	ConnectionID         string    `json:"connection_id"`
	ServiceGUID          string    `json:"service_guid"`
	Level                string    `json:"level"`                   // "all", "important", "muted"
	AllowDataRequests    bool      `json:"allow_data_requests"`     // Show data request notifications
	AllowAuthRequests    bool      `json:"allow_auth_requests"`     // Show auth request notifications
	AllowPaymentRequests bool      `json:"allow_payment_requests"`  // Show payment request notifications
	AllowMessages        bool      `json:"allow_messages"`          // Show message notifications
	AllowCalls           bool      `json:"allow_calls"`             // Show call notifications
	BypassQuietHours     bool      `json:"bypass_quiet_hours"`      // Allow notifications during quiet hours
	CustomSound          string    `json:"custom_sound,omitempty"`  // Custom notification sound
	UpdatedAt            time.Time `json:"updated_at"`
}

// TrustIndicators provides trust scoring for a service connection
type TrustIndicators struct {
	ConnectionID          string    `json:"connection_id"`
	ServiceGUID           string    `json:"service_guid"`
	ServiceName           string    `json:"service_name"`

	// Overall trust score (0-100)
	TrustScore            int       `json:"trust_score"`
	TrustLevel            string    `json:"trust_level"` // "high", "medium", "low", "unknown"

	// Component scores
	OrganizationVerified  bool      `json:"organization_verified"`
	VerificationType      string    `json:"verification_type,omitempty"` // "business", "nonprofit", "government"
	VerifiedAt            *time.Time `json:"verified_at,omitempty"`

	// Connection history
	ConnectionAge         int       `json:"connection_age_days"`
	TotalInteractions     int       `json:"total_interactions"`
	LastInteractionAt     *time.Time `json:"last_interaction_at,omitempty"`

	// Behavior tracking
	RateLimitViolations   int       `json:"rate_limit_violations"`
	ContractViolations    int       `json:"contract_violations"`
	DeniedRequests        int       `json:"denied_requests"`
	ApprovedRequests      int       `json:"approved_requests"`

	// Flags
	HasPendingContract    bool      `json:"has_pending_contract"`
	IsInactive            bool      `json:"is_inactive"` // No activity in 30+ days
	HasIssues             bool      `json:"has_issues"`
	Issues                []string  `json:"issues,omitempty"`

	CalculatedAt          time.Time `json:"calculated_at"`
}

// ViolationRecord tracks a rate limit or contract violation
type ViolationRecord struct {
	ViolationID   string    `json:"violation_id"`
	ConnectionID  string    `json:"connection_id"`
	ServiceGUID   string    `json:"service_guid"`
	ViolationType string    `json:"violation_type"` // "rate_limit", "contract", "unauthorized"
	Description   string    `json:"description"`
	Severity      string    `json:"severity"` // "low", "medium", "high"
	OccurredAt    time.Time `json:"occurred_at"`
	Acknowledged  bool      `json:"acknowledged"`
}

// --- Request/Response Types ---

// GetNotificationSettingsRequest is the payload for service.notifications.get
type GetNotificationSettingsRequest struct {
	ConnectionID string `json:"connection_id"`
}

// UpdateNotificationSettingsRequest is the payload for service.notifications.update
type UpdateNotificationSettingsRequest struct {
	ConnectionID         string  `json:"connection_id"`
	Level                *string `json:"level,omitempty"`
	AllowDataRequests    *bool   `json:"allow_data_requests,omitempty"`
	AllowAuthRequests    *bool   `json:"allow_auth_requests,omitempty"`
	AllowPaymentRequests *bool   `json:"allow_payment_requests,omitempty"`
	AllowMessages        *bool   `json:"allow_messages,omitempty"`
	AllowCalls           *bool   `json:"allow_calls,omitempty"`
	BypassQuietHours     *bool   `json:"bypass_quiet_hours,omitempty"`
	CustomSound          *string `json:"custom_sound,omitempty"`
}

// GetTrustIndicatorsRequest is the payload for service.trust.get
type GetTrustIndicatorsRequest struct {
	ConnectionID string `json:"connection_id"`
}

// ListViolationsRequest is the payload for service.violations.list
type ListViolationsRequest struct {
	ConnectionID    string `json:"connection_id,omitempty"` // Filter by connection
	ViolationType   string `json:"violation_type,omitempty"`
	IncludeAcknowledged bool `json:"include_acknowledged,omitempty"`
	Limit           int    `json:"limit,omitempty"`
	Offset          int    `json:"offset,omitempty"`
}

// ListViolationsResponse contains violation list
type ListViolationsResponse struct {
	Violations []ViolationRecord `json:"violations"`
	Total      int               `json:"total"`
	HasMore    bool              `json:"has_more"`
}

// AcknowledgeViolationRequest is the payload for service.violations.acknowledge
type AcknowledgeViolationRequest struct {
	ViolationID string `json:"violation_id"`
}

// --- Handler Methods ---

func (h *ServiceNotificationsHandler) errorResponse(requestID, message string) (*OutgoingMessage, error) {
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

// HandleGetNotificationSettings handles service.notifications.get
func (h *ServiceNotificationsHandler) HandleGetNotificationSettings(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req GetNotificationSettingsRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	// Verify connection exists
	conn, err := h.connectionHandler.GetConnection(req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}

	// Load settings
	storageKey := "service-notifications/" + req.ConnectionID
	data, err := h.storage.Get(storageKey)

	var settings ServiceNotificationSettings
	if err != nil {
		// Return default settings if not configured
		settings = ServiceNotificationSettings{
			ConnectionID:         req.ConnectionID,
			ServiceGUID:          conn.ServiceGUID,
			Level:                "all",
			AllowDataRequests:    true,
			AllowAuthRequests:    true,
			AllowPaymentRequests: true,
			AllowMessages:        true,
			AllowCalls:           true,
			BypassQuietHours:     false,
			UpdatedAt:            time.Now(),
		}
	} else {
		if err := json.Unmarshal(data, &settings); err != nil {
			return h.errorResponse(msg.GetID(), "Failed to read settings")
		}
	}

	// Apply muted state from connection
	if conn.IsMuted {
		settings.Level = "muted"
	}

	respBytes, _ := json.Marshal(settings)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleUpdateNotificationSettings handles service.notifications.update
func (h *ServiceNotificationsHandler) HandleUpdateNotificationSettings(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req UpdateNotificationSettingsRequest
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

	// Load existing settings or create default
	storageKey := "service-notifications/" + req.ConnectionID
	data, _ := h.storage.Get(storageKey)

	var settings ServiceNotificationSettings
	if data != nil {
		json.Unmarshal(data, &settings)
	} else {
		settings = ServiceNotificationSettings{
			ConnectionID:         req.ConnectionID,
			ServiceGUID:          conn.ServiceGUID,
			Level:                "all",
			AllowDataRequests:    true,
			AllowAuthRequests:    true,
			AllowPaymentRequests: true,
			AllowMessages:        true,
			AllowCalls:           true,
			BypassQuietHours:     false,
		}
	}

	// Apply updates
	if req.Level != nil {
		if *req.Level != "all" && *req.Level != "important" && *req.Level != "muted" {
			return h.errorResponse(msg.GetID(), "Invalid level: must be 'all', 'important', or 'muted'")
		}
		settings.Level = *req.Level
	}
	if req.AllowDataRequests != nil {
		settings.AllowDataRequests = *req.AllowDataRequests
	}
	if req.AllowAuthRequests != nil {
		settings.AllowAuthRequests = *req.AllowAuthRequests
	}
	if req.AllowPaymentRequests != nil {
		settings.AllowPaymentRequests = *req.AllowPaymentRequests
	}
	if req.AllowMessages != nil {
		settings.AllowMessages = *req.AllowMessages
	}
	if req.AllowCalls != nil {
		settings.AllowCalls = *req.AllowCalls
	}
	if req.BypassQuietHours != nil {
		settings.BypassQuietHours = *req.BypassQuietHours
	}
	if req.CustomSound != nil {
		settings.CustomSound = *req.CustomSound
	}

	settings.UpdatedAt = time.Now()

	// Save settings
	newData, _ := json.Marshal(settings)
	if err := h.storage.Put(storageKey, newData); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to save settings")
	}

	log.Info().
		Str("connection_id", req.ConnectionID).
		Str("level", settings.Level).
		Msg("Notification settings updated")

	resp := map[string]interface{}{
		"success":  true,
		"settings": settings,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleGetTrustIndicators handles service.trust.get
func (h *ServiceNotificationsHandler) HandleGetTrustIndicators(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req GetTrustIndicatorsRequest
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

	indicators := h.calculateTrustIndicators(conn)
	respBytes, _ := json.Marshal(indicators)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// calculateTrustIndicators computes trust score and indicators for a connection
func (h *ServiceNotificationsHandler) calculateTrustIndicators(conn *ServiceConnectionRecord) *TrustIndicators {
	now := time.Now()

	indicators := &TrustIndicators{
		ConnectionID:         conn.ConnectionID,
		ServiceGUID:          conn.ServiceGUID,
		ServiceName:          conn.ServiceProfile.ServiceName,
		OrganizationVerified: conn.ServiceProfile.Organization.Verified,
		VerificationType:     conn.ServiceProfile.Organization.VerificationType,
		TotalInteractions:    conn.ActivityCount,
		HasPendingContract:   conn.PendingContractVersion != nil,
		CalculatedAt:         now,
	}

	// Parse verified at timestamp
	if conn.ServiceProfile.Organization.VerifiedAt != "" {
		if t, err := time.Parse(time.RFC3339, conn.ServiceProfile.Organization.VerifiedAt); err == nil {
			indicators.VerifiedAt = &t
		}
	}

	// Calculate connection age
	indicators.ConnectionAge = int(now.Sub(conn.CreatedAt).Hours() / 24)

	// Set last interaction
	indicators.LastInteractionAt = conn.LastActiveAt

	// Check for inactivity
	if conn.LastActiveAt != nil {
		daysSinceActive := int(now.Sub(*conn.LastActiveAt).Hours() / 24)
		indicators.IsInactive = daysSinceActive > 30
	} else {
		indicators.IsInactive = indicators.ConnectionAge > 30
	}

	// Load violation counts
	violationData, _ := h.storage.Get("service-violations/" + conn.ConnectionID + "/_counts")
	if violationData != nil {
		var counts struct {
			RateLimitViolations int `json:"rate_limit"`
			ContractViolations  int `json:"contract"`
		}
		if json.Unmarshal(violationData, &counts) == nil {
			indicators.RateLimitViolations = counts.RateLimitViolations
			indicators.ContractViolations = counts.ContractViolations
		}
	}

	// Load request stats from activity summary
	activityData, _ := h.storage.Get("service-activity/" + conn.ConnectionID + "/_stats")
	if activityData != nil {
		var stats struct {
			Approved int `json:"approved"`
			Denied   int `json:"denied"`
		}
		if json.Unmarshal(activityData, &stats) == nil {
			indicators.ApprovedRequests = stats.Approved
			indicators.DeniedRequests = stats.Denied
		}
	}

	// Calculate trust score (0-100)
	score := 50 // Base score

	// Organization verification (+20)
	if indicators.OrganizationVerified {
		score += 20
		if indicators.VerificationType == "government" {
			score += 5
		}
	}

	// Connection age (+15 max)
	if indicators.ConnectionAge >= 365 {
		score += 15
	} else if indicators.ConnectionAge >= 90 {
		score += 10
	} else if indicators.ConnectionAge >= 30 {
		score += 5
	}

	// Interaction history (+10)
	if indicators.TotalInteractions > 100 {
		score += 10
	} else if indicators.TotalInteractions > 10 {
		score += 5
	}

	// Violations (-20 max)
	violationPenalty := (indicators.RateLimitViolations * 2) + (indicators.ContractViolations * 5)
	if violationPenalty > 20 {
		violationPenalty = 20
	}
	score -= violationPenalty

	// Denied requests penalty
	if indicators.ApprovedRequests+indicators.DeniedRequests > 0 {
		denialRate := float64(indicators.DeniedRequests) / float64(indicators.ApprovedRequests+indicators.DeniedRequests)
		if denialRate > 0.5 {
			score -= 10
		} else if denialRate > 0.2 {
			score -= 5
		}
	}

	// Pending contract (-5)
	if indicators.HasPendingContract {
		score -= 5
	}

	// Inactivity (-5)
	if indicators.IsInactive {
		score -= 5
	}

	// Clamp score
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	indicators.TrustScore = score

	// Determine trust level
	switch {
	case score >= 80:
		indicators.TrustLevel = "high"
	case score >= 50:
		indicators.TrustLevel = "medium"
	case score >= 20:
		indicators.TrustLevel = "low"
	default:
		indicators.TrustLevel = "unknown"
	}

	// Compile issues
	var issues []string
	if indicators.RateLimitViolations > 0 {
		issues = append(issues, "Rate limit violations detected")
	}
	if indicators.ContractViolations > 0 {
		issues = append(issues, "Contract violations detected")
	}
	if indicators.HasPendingContract {
		issues = append(issues, "Contract update pending review")
	}
	if indicators.IsInactive {
		issues = append(issues, "No recent activity")
	}
	if !indicators.OrganizationVerified {
		issues = append(issues, "Organization not verified")
	}

	indicators.Issues = issues
	indicators.HasIssues = len(issues) > 0

	return indicators
}

// HandleListViolations handles service.violations.list
func (h *ServiceNotificationsHandler) HandleListViolations(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req ListViolationsRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		req = ListViolationsRequest{Limit: 50}
	}

	if req.Limit <= 0 {
		req.Limit = 50
	}
	if req.Limit > 100 {
		req.Limit = 100
	}

	// Load violation index
	var indexKey string
	if req.ConnectionID != "" {
		indexKey = "service-violations/" + req.ConnectionID + "/_index"
	} else {
		indexKey = "service-violations/_global_index"
	}

	indexData, _ := h.storage.Get(indexKey)
	var violationIDs []string
	if indexData != nil {
		json.Unmarshal(indexData, &violationIDs)
	}

	var violations []ViolationRecord
	for _, vID := range violationIDs {
		var key string
		if req.ConnectionID != "" {
			key = "service-violations/" + req.ConnectionID + "/" + vID
		} else {
			// Need to find which connection this violation belongs to
			// For simplicity, skip global listing for now
			continue
		}

		data, err := h.storage.Get(key)
		if err != nil {
			continue
		}

		var violation ViolationRecord
		if err := json.Unmarshal(data, &violation); err != nil {
			continue
		}

		// Apply filters
		if req.ViolationType != "" && violation.ViolationType != req.ViolationType {
			continue
		}
		if !req.IncludeAcknowledged && violation.Acknowledged {
			continue
		}

		violations = append(violations, violation)
	}

	// Apply pagination
	total := len(violations)
	start := req.Offset
	if start > total {
		start = total
	}
	end := start + req.Limit
	if end > total {
		end = total
	}

	paginatedViolations := violations[start:end]
	if paginatedViolations == nil {
		paginatedViolations = []ViolationRecord{}
	}

	resp := ListViolationsResponse{
		Violations: paginatedViolations,
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

// HandleAcknowledgeViolation handles service.violations.acknowledge
func (h *ServiceNotificationsHandler) HandleAcknowledgeViolation(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req AcknowledgeViolationRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ViolationID == "" {
		return h.errorResponse(msg.GetID(), "violation_id is required")
	}

	// Find and update violation
	// Note: This requires knowing which connection the violation belongs to
	// For now, we'll search through all connections
	indexData, _ := h.storage.Get("service-connections/_index")
	var connectionIDs []string
	if indexData != nil {
		json.Unmarshal(indexData, &connectionIDs)
	}

	for _, connID := range connectionIDs {
		key := "service-violations/" + connID + "/" + req.ViolationID
		data, err := h.storage.Get(key)
		if err != nil {
			continue
		}

		var violation ViolationRecord
		if err := json.Unmarshal(data, &violation); err != nil {
			continue
		}

		// Found it - acknowledge
		violation.Acknowledged = true
		newData, _ := json.Marshal(violation)
		h.storage.Put(key, newData)

		log.Info().
			Str("violation_id", req.ViolationID).
			Str("connection_id", connID).
			Msg("Violation acknowledged")

		resp := map[string]interface{}{
			"success":      true,
			"violation_id": req.ViolationID,
			"acknowledged": true,
		}
		respBytes, _ := json.Marshal(resp)

		return &OutgoingMessage{
			RequestID: msg.GetID(),
			Type:      MessageTypeResponse,
			Payload:   respBytes,
		}, nil
	}

	return h.errorResponse(msg.GetID(), "Violation not found")
}

// --- Violation Recording ---

// RecordViolation logs a violation for a connection
func (h *ServiceNotificationsHandler) RecordViolation(connectionID, serviceGUID, violationType, description, severity string) error {
	violation := ViolationRecord{
		ViolationID:   generateUUID(),
		ConnectionID:  connectionID,
		ServiceGUID:   serviceGUID,
		ViolationType: violationType,
		Description:   description,
		Severity:      severity,
		OccurredAt:    time.Now(),
		Acknowledged:  false,
	}

	// Store violation
	key := "service-violations/" + connectionID + "/" + violation.ViolationID
	data, err := json.Marshal(violation)
	if err != nil {
		return err
	}
	if err := h.storage.Put(key, data); err != nil {
		return err
	}

	// Update index
	indexKey := "service-violations/" + connectionID + "/_index"
	indexData, _ := h.storage.Get(indexKey)
	var violationIDs []string
	if indexData != nil {
		json.Unmarshal(indexData, &violationIDs)
	}
	violationIDs = append([]string{violation.ViolationID}, violationIDs...)
	newIndexData, _ := json.Marshal(violationIDs)
	h.storage.Put(indexKey, newIndexData)

	// Update counts
	countsKey := "service-violations/" + connectionID + "/_counts"
	countsData, _ := h.storage.Get(countsKey)
	var counts struct {
		RateLimitViolations int `json:"rate_limit"`
		ContractViolations  int `json:"contract"`
	}
	if countsData != nil {
		json.Unmarshal(countsData, &counts)
	}
	switch violationType {
	case "rate_limit":
		counts.RateLimitViolations++
	case "contract":
		counts.ContractViolations++
	}
	newCountsData, _ := json.Marshal(counts)
	h.storage.Put(countsKey, newCountsData)

	log.Warn().
		Str("connection_id", connectionID).
		Str("type", violationType).
		Str("severity", severity).
		Msg("Violation recorded")

	return nil
}

// ShouldSendNotification checks if a notification should be sent based on settings
func (h *ServiceNotificationsHandler) ShouldSendNotification(connectionID, notificationType string) bool {
	conn, err := h.connectionHandler.GetConnection(connectionID)
	if err != nil {
		return true // Default to allow if can't check
	}

	// Check if connection is muted
	if conn.IsMuted {
		return false
	}

	// Load settings
	storageKey := "service-notifications/" + connectionID
	data, err := h.storage.Get(storageKey)
	if err != nil {
		return true // Default to allow if no settings
	}

	var settings ServiceNotificationSettings
	if err := json.Unmarshal(data, &settings); err != nil {
		return true
	}

	// Check level
	if settings.Level == "muted" {
		return false
	}

	// Check specific notification type
	switch notificationType {
	case "data_request":
		return settings.AllowDataRequests
	case "auth_request":
		return settings.AllowAuthRequests
	case "payment_request":
		return settings.AllowPaymentRequests
	case "message":
		return settings.AllowMessages
	case "call":
		return settings.AllowCalls
	default:
		return true
	}
}
