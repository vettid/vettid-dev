package main

import (
	"encoding/json"
	"time"

	"github.com/rs/zerolog/log"
)

// ServiceOfflineHandler handles offline action queueing and sync for service connections.
// Phase 9: Offline Support
//
// When the app is offline, actions that would normally be sent to services are queued.
// When connectivity is restored, queued actions are synced with exponential backoff.
type ServiceOfflineHandler struct {
	ownerSpace        string
	storage           *EncryptedStorage
	eventHandler      *EventHandler
	connectionHandler *ServiceConnectionHandler
}

// NewServiceOfflineHandler creates a new service offline handler
func NewServiceOfflineHandler(
	ownerSpace string,
	storage *EncryptedStorage,
	eventHandler *EventHandler,
	connectionHandler *ServiceConnectionHandler,
) *ServiceOfflineHandler {
	return &ServiceOfflineHandler{
		ownerSpace:        ownerSpace,
		storage:           storage,
		eventHandler:      eventHandler,
		connectionHandler: connectionHandler,
	}
}

// --- Data Models ---

// OfflineServiceAction represents a queued action to be synced when online
type OfflineServiceAction struct {
	ActionID     string            `json:"action_id"`
	ConnectionID string            `json:"connection_id"`
	ServiceGUID  string            `json:"service_guid"`
	ActionType   string            `json:"action_type"` // "request_response", "revoke", "contract_accept", "contract_reject", "data_delete"
	Payload      json.RawMessage   `json:"payload"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	SyncStatus   string            `json:"sync_status"` // "pending", "syncing", "synced", "failed"
	SyncedAt     *time.Time        `json:"synced_at,omitempty"`
	RetryCount   int               `json:"retry_count"`
	NextRetryAt  *time.Time        `json:"next_retry_at,omitempty"`
	Error        string            `json:"error,omitempty"`
	ExpiresAt    *time.Time        `json:"expires_at,omitempty"` // Some actions may expire
}

// OfflineSyncStatus provides overall sync status
type OfflineSyncStatus struct {
	PendingCount   int        `json:"pending_count"`
	SyncingCount   int        `json:"syncing_count"`
	FailedCount    int        `json:"failed_count"`
	LastSyncAt     *time.Time `json:"last_sync_at,omitempty"`
	NextSyncAt     *time.Time `json:"next_sync_at,omitempty"`
	IsOnline       bool       `json:"is_online"`
	SyncInProgress bool       `json:"sync_in_progress"`
}

// --- Request/Response Types ---

// ListOfflineActionsRequest is the payload for service.offline.list
type ListOfflineActionsRequest struct {
	ConnectionID string   `json:"connection_id,omitempty"` // Filter by connection
	Status       []string `json:"status,omitempty"`        // Filter by status
	ActionType   string   `json:"action_type,omitempty"`   // Filter by type
	Limit        int      `json:"limit,omitempty"`
	Offset       int      `json:"offset,omitempty"`
}

// ListOfflineActionsResponse contains offline actions list
type ListOfflineActionsResponse struct {
	Actions []OfflineServiceAction `json:"actions"`
	Total   int                    `json:"total"`
	HasMore bool                   `json:"has_more"`
	Status  OfflineSyncStatus      `json:"status"`
}

// TriggerSyncRequest is the payload for service.offline.sync
type TriggerSyncRequest struct {
	ConnectionID string `json:"connection_id,omitempty"` // Sync specific connection only
	ForceRetry   bool   `json:"force_retry,omitempty"`   // Retry failed actions immediately
}

// TriggerSyncResponse is the response for sync trigger
type TriggerSyncResponse struct {
	Success      bool   `json:"success"`
	Message      string `json:"message,omitempty"`
	ActionsSynced int   `json:"actions_synced"`
	ActionsFailed int   `json:"actions_failed"`
	ActionsRemaining int `json:"actions_remaining"`
}

// ClearOfflineActionsRequest is the payload for service.offline.clear
type ClearOfflineActionsRequest struct {
	ConnectionID string   `json:"connection_id,omitempty"` // Clear for specific connection
	Status       []string `json:"status,omitempty"`        // Clear only specific statuses
	ClearAll     bool     `json:"clear_all,omitempty"`     // Clear all (requires confirmation)
}

// RetryActionRequest is the payload for service.offline.retry
type RetryActionRequest struct {
	ActionID string `json:"action_id"`
}

// CancelActionRequest is the payload for service.offline.cancel
type CancelActionRequest struct {
	ActionID string `json:"action_id"`
}

// --- Handler Methods ---

func (h *ServiceOfflineHandler) errorResponse(requestID, message string) (*OutgoingMessage, error) {
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

// HandleListOfflineActions handles service.offline.list
func (h *ServiceOfflineHandler) HandleListOfflineActions(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req ListOfflineActionsRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		req = ListOfflineActionsRequest{Limit: 50}
	}

	if req.Limit <= 0 {
		req.Limit = 50
	}
	if req.Limit > 100 {
		req.Limit = 100
	}

	// Load all offline actions
	actions, err := h.loadAllActions(req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to load offline actions")
	}

	// Apply filters
	var filteredActions []OfflineServiceAction
	for _, action := range actions {
		// Filter by status
		if len(req.Status) > 0 {
			matched := false
			for _, s := range req.Status {
				if action.SyncStatus == s {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}

		// Filter by action type
		if req.ActionType != "" && action.ActionType != req.ActionType {
			continue
		}

		filteredActions = append(filteredActions, action)
	}

	// Apply pagination
	total := len(filteredActions)
	start := req.Offset
	if start > total {
		start = total
	}
	end := start + req.Limit
	if end > total {
		end = total
	}

	paginatedActions := filteredActions[start:end]
	if paginatedActions == nil {
		paginatedActions = []OfflineServiceAction{}
	}

	// Get sync status
	status := h.getSyncStatus(actions)

	resp := ListOfflineActionsResponse{
		Actions: paginatedActions,
		Total:   total,
		HasMore: end < total,
		Status:  status,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleTriggerSync handles service.offline.sync
func (h *ServiceOfflineHandler) HandleTriggerSync(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req TriggerSyncRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		req = TriggerSyncRequest{}
	}

	// Load pending actions
	actions, err := h.loadAllActions(req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to load offline actions")
	}

	synced := 0
	failed := 0
	remaining := 0

	now := time.Now()

	for i := range actions {
		action := &actions[i]

		// Skip already synced
		if action.SyncStatus == "synced" {
			continue
		}

		// Check if action has expired
		if action.ExpiresAt != nil && now.After(*action.ExpiresAt) {
			action.SyncStatus = "failed"
			action.Error = "Action expired"
			h.saveAction(action)
			failed++
			continue
		}

		// Check if we should retry
		if action.SyncStatus == "failed" && !req.ForceRetry {
			if action.NextRetryAt != nil && now.Before(*action.NextRetryAt) {
				remaining++
				continue
			}
		}

		// Attempt sync
		action.SyncStatus = "syncing"
		h.saveAction(action)

		syncErr := h.syncAction(action)
		if syncErr != nil {
			action.SyncStatus = "failed"
			action.Error = syncErr.Error()
			action.RetryCount++

			// Calculate next retry with exponential backoff
			backoff := calculateBackoff(action.RetryCount)
			nextRetry := now.Add(backoff)
			action.NextRetryAt = &nextRetry

			h.saveAction(action)
			failed++

			log.Warn().
				Str("action_id", action.ActionID).
				Int("retry_count", action.RetryCount).
				Err(syncErr).
				Msg("Offline action sync failed")
		} else {
			action.SyncStatus = "synced"
			action.SyncedAt = &now
			action.Error = ""
			h.saveAction(action)
			synced++

			log.Info().
				Str("action_id", action.ActionID).
				Str("action_type", action.ActionType).
				Msg("Offline action synced")
		}
	}

	// Update last sync time
	h.updateLastSyncTime(now)

	resp := TriggerSyncResponse{
		Success:          true,
		Message:          "Sync completed",
		ActionsSynced:    synced,
		ActionsFailed:    failed,
		ActionsRemaining: remaining,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleClearOfflineActions handles service.offline.clear
func (h *ServiceOfflineHandler) HandleClearOfflineActions(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req ClearOfflineActionsRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	// Load all actions
	actions, err := h.loadAllActions(req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to load offline actions")
	}

	cleared := 0

	for _, action := range actions {
		shouldClear := false

		if req.ClearAll {
			shouldClear = true
		} else if len(req.Status) > 0 {
			for _, s := range req.Status {
				if action.SyncStatus == s {
					shouldClear = true
					break
				}
			}
		} else {
			// Default: only clear synced actions
			shouldClear = action.SyncStatus == "synced"
		}

		if shouldClear {
			h.deleteAction(action.ActionID, action.ConnectionID)
			cleared++
		}
	}

	log.Info().
		Int("cleared", cleared).
		Msg("Offline actions cleared")

	resp := map[string]interface{}{
		"success": true,
		"cleared": cleared,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleRetryAction handles service.offline.retry
func (h *ServiceOfflineHandler) HandleRetryAction(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req RetryActionRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ActionID == "" {
		return h.errorResponse(msg.GetID(), "action_id is required")
	}

	// Find and retry the action
	action, err := h.findAction(req.ActionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Action not found")
	}

	if action.SyncStatus == "synced" {
		return h.errorResponse(msg.GetID(), "Action already synced")
	}

	// Reset retry state and attempt sync
	now := time.Now()
	action.SyncStatus = "syncing"
	action.NextRetryAt = nil
	h.saveAction(action)

	syncErr := h.syncAction(action)
	if syncErr != nil {
		action.SyncStatus = "failed"
		action.Error = syncErr.Error()
		action.RetryCount++

		backoff := calculateBackoff(action.RetryCount)
		nextRetry := now.Add(backoff)
		action.NextRetryAt = &nextRetry

		h.saveAction(action)

		return h.errorResponse(msg.GetID(), "Sync failed: "+syncErr.Error())
	}

	action.SyncStatus = "synced"
	action.SyncedAt = &now
	action.Error = ""
	h.saveAction(action)

	resp := map[string]interface{}{
		"success":   true,
		"action_id": req.ActionID,
		"status":    "synced",
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleCancelAction handles service.offline.cancel
func (h *ServiceOfflineHandler) HandleCancelAction(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req CancelActionRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ActionID == "" {
		return h.errorResponse(msg.GetID(), "action_id is required")
	}

	// Find the action
	action, err := h.findAction(req.ActionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Action not found")
	}

	if action.SyncStatus == "synced" {
		return h.errorResponse(msg.GetID(), "Cannot cancel synced action")
	}

	// Delete the action
	h.deleteAction(action.ActionID, action.ConnectionID)

	log.Info().
		Str("action_id", req.ActionID).
		Msg("Offline action cancelled")

	resp := map[string]interface{}{
		"success":   true,
		"action_id": req.ActionID,
		"cancelled": true,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleGetSyncStatus handles service.offline.status
func (h *ServiceOfflineHandler) HandleGetSyncStatus(msg *IncomingMessage) (*OutgoingMessage, error) {
	actions, _ := h.loadAllActions("")
	status := h.getSyncStatus(actions)

	respBytes, _ := json.Marshal(status)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// --- Action Queueing ---

// QueueAction adds an action to the offline queue
func (h *ServiceOfflineHandler) QueueAction(connectionID, serviceGUID, actionType string, payload json.RawMessage, expiresIn *time.Duration) (*OfflineServiceAction, error) {
	now := time.Now()

	action := &OfflineServiceAction{
		ActionID:     generateUUID(),
		ConnectionID: connectionID,
		ServiceGUID:  serviceGUID,
		ActionType:   actionType,
		Payload:      payload,
		CreatedAt:    now,
		SyncStatus:   "pending",
		RetryCount:   0,
	}

	if expiresIn != nil {
		expires := now.Add(*expiresIn)
		action.ExpiresAt = &expires
	}

	if err := h.saveAction(action); err != nil {
		return nil, err
	}

	// Add to index
	h.addToActionIndex(action.ActionID, connectionID)

	log.Info().
		Str("action_id", action.ActionID).
		Str("connection_id", connectionID).
		Str("action_type", actionType).
		Msg("Action queued for offline sync")

	return action, nil
}

// --- Helper Methods ---

func (h *ServiceOfflineHandler) loadAllActions(connectionID string) ([]OfflineServiceAction, error) {
	var actions []OfflineServiceAction

	if connectionID != "" {
		// Load for specific connection
		indexKey := "service-offline/" + connectionID + "/_index"
		indexData, _ := h.storage.Get(indexKey)
		var actionIDs []string
		if indexData != nil {
			json.Unmarshal(indexData, &actionIDs)
		}

		for _, actionID := range actionIDs {
			data, err := h.storage.Get("service-offline/" + connectionID + "/" + actionID)
			if err != nil {
				continue
			}

			var action OfflineServiceAction
			if err := json.Unmarshal(data, &action); err != nil {
				continue
			}
			actions = append(actions, action)
		}
	} else {
		// Load all connections' actions
		connIndexData, _ := h.storage.Get("service-connections/_index")
		var connectionIDs []string
		if connIndexData != nil {
			json.Unmarshal(connIndexData, &connectionIDs)
		}

		for _, connID := range connectionIDs {
			connActions, _ := h.loadAllActions(connID)
			actions = append(actions, connActions...)
		}
	}

	return actions, nil
}

func (h *ServiceOfflineHandler) findAction(actionID string) (*OfflineServiceAction, error) {
	// Search through all connections
	connIndexData, _ := h.storage.Get("service-connections/_index")
	var connectionIDs []string
	if connIndexData != nil {
		json.Unmarshal(connIndexData, &connectionIDs)
	}

	for _, connID := range connectionIDs {
		data, err := h.storage.Get("service-offline/" + connID + "/" + actionID)
		if err == nil {
			var action OfflineServiceAction
			if err := json.Unmarshal(data, &action); err == nil {
				return &action, nil
			}
		}
	}

	return nil, errNotFound
}

func (h *ServiceOfflineHandler) saveAction(action *OfflineServiceAction) error {
	key := "service-offline/" + action.ConnectionID + "/" + action.ActionID
	data, err := json.Marshal(action)
	if err != nil {
		return err
	}
	return h.storage.Put(key, data)
}

func (h *ServiceOfflineHandler) deleteAction(actionID, connectionID string) error {
	key := "service-offline/" + connectionID + "/" + actionID
	h.storage.Delete(key)

	// Remove from index
	h.removeFromActionIndex(actionID, connectionID)
	return nil
}

func (h *ServiceOfflineHandler) addToActionIndex(actionID, connectionID string) {
	indexKey := "service-offline/" + connectionID + "/_index"
	indexData, _ := h.storage.Get(indexKey)
	var actionIDs []string
	if indexData != nil {
		json.Unmarshal(indexData, &actionIDs)
	}

	actionIDs = append([]string{actionID}, actionIDs...)
	newIndexData, _ := json.Marshal(actionIDs)
	h.storage.Put(indexKey, newIndexData)
}

func (h *ServiceOfflineHandler) removeFromActionIndex(actionID, connectionID string) {
	indexKey := "service-offline/" + connectionID + "/_index"
	indexData, _ := h.storage.Get(indexKey)
	var actionIDs []string
	if indexData != nil {
		json.Unmarshal(indexData, &actionIDs)
	}

	var newIDs []string
	for _, id := range actionIDs {
		if id != actionID {
			newIDs = append(newIDs, id)
		}
	}

	newIndexData, _ := json.Marshal(newIDs)
	h.storage.Put(indexKey, newIndexData)
}

func (h *ServiceOfflineHandler) getSyncStatus(actions []OfflineServiceAction) OfflineSyncStatus {
	status := OfflineSyncStatus{
		IsOnline: true, // Assume online unless told otherwise
	}

	for _, action := range actions {
		switch action.SyncStatus {
		case "pending":
			status.PendingCount++
		case "syncing":
			status.SyncingCount++
			status.SyncInProgress = true
		case "failed":
			status.FailedCount++
		}
	}

	// Load last sync time
	lastSyncData, _ := h.storage.Get("service-offline/_last_sync")
	if lastSyncData != nil {
		var lastSync time.Time
		if json.Unmarshal(lastSyncData, &lastSync) == nil {
			status.LastSyncAt = &lastSync
		}
	}

	return status
}

func (h *ServiceOfflineHandler) updateLastSyncTime(t time.Time) {
	data, _ := json.Marshal(t)
	h.storage.Put("service-offline/_last_sync", data)
}

func (h *ServiceOfflineHandler) syncAction(action *OfflineServiceAction) error {
	// In a real implementation, this would send the action to the service via NATS
	// For now, we simulate success
	// The actual sync would be handled by the messaging infrastructure

	log.Debug().
		Str("action_id", action.ActionID).
		Str("action_type", action.ActionType).
		Msg("Syncing offline action (simulated)")

	// TODO: Implement actual NATS message sending based on action type
	// switch action.ActionType {
	// case "request_response":
	//     // Send response to service's callback topic
	// case "revoke":
	//     // Send revocation notice to service
	// case "contract_accept":
	//     // Send contract acceptance
	// case "contract_reject":
	//     // Send contract rejection
	// }

	return nil // Success for now
}

// calculateBackoff returns the backoff duration for exponential backoff
func calculateBackoff(retryCount int) time.Duration {
	// Base: 1 minute, max: 1 hour
	base := time.Minute
	max := time.Hour

	backoff := base * time.Duration(1<<uint(retryCount))
	if backoff > max {
		backoff = max
	}

	return backoff
}

// errNotFound is returned when an item is not found
var errNotFound = &notFoundError{}

type notFoundError struct{}

func (e *notFoundError) Error() string {
	return "not found"
}
