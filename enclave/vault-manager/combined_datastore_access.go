package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
)

// DatastoreAccessController enforces permissions for combined datastores.
// Every read/write/delete operation is validated against the participant's permissions.
type DatastoreAccessController struct {
	ownerSpace        string
	storage           *EncryptedStorage
	eventHandler      *EventHandler
	datastoreHandler  *CombinedDatastoreHandler
	publisher         *VsockPublisher
}

// NewDatastoreAccessController creates a new access controller
func NewDatastoreAccessController(
	ownerSpace string,
	storage *EncryptedStorage,
	eventHandler *EventHandler,
	datastoreHandler *CombinedDatastoreHandler,
	publisher *VsockPublisher,
) *DatastoreAccessController {
	return &DatastoreAccessController{
		ownerSpace:       ownerSpace,
		storage:          storage,
		eventHandler:     eventHandler,
		datastoreHandler: datastoreHandler,
		publisher:        publisher,
	}
}

// --- Request/Response Types ---

// DatastoreReadRequest is the payload for datastore.read
type DatastoreReadRequest struct {
	DatastoreID string   `json:"datastore_id"`
	ServiceID   string   `json:"service_id"` // Requesting service
	Fields      []string `json:"fields,omitempty"` // Specific fields, empty = all allowed
}

// DatastoreReadResponse is the response for datastore.read
type DatastoreReadResponse struct {
	Success   bool                   `json:"success"`
	Data      map[string]interface{} `json:"data"`
	Version   int64                  `json:"version"`
	UpdatedAt time.Time              `json:"updated_at"`
	UpdatedBy string                 `json:"updated_by"`
	Message   string                 `json:"message,omitempty"`
}

// DatastoreWriteRequest is the payload for datastore.write
type DatastoreWriteRequest struct {
	DatastoreID     string                 `json:"datastore_id"`
	ServiceID       string                 `json:"service_id"` // Writing service
	Data            map[string]interface{} `json:"data"`
	ExpectedVersion int64                  `json:"expected_version,omitempty"` // Optimistic locking
}

// DatastoreWriteResponse is the response for datastore.write
type DatastoreWriteResponse struct {
	Success    bool      `json:"success"`
	Version    int64     `json:"version"`
	UpdatedAt  time.Time `json:"updated_at"`
	Conflict   bool      `json:"conflict,omitempty"`
	Message    string    `json:"message,omitempty"`
}

// DatastoreDeleteRequest is the payload for datastore.delete (delete fields)
type DatastoreDeleteRequest struct {
	DatastoreID     string   `json:"datastore_id"`
	ServiceID       string   `json:"service_id"`
	Fields          []string `json:"fields"` // Fields to delete
	ExpectedVersion int64    `json:"expected_version,omitempty"`
}

// DatastoreDeleteResponse is the response for datastore.delete
type DatastoreDeleteResponse struct {
	Success   bool      `json:"success"`
	Version   int64     `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
	Message   string    `json:"message,omitempty"`
}

// DatastoreSubscribeRequest is the payload for datastore.subscribe
type DatastoreSubscribeRequest struct {
	DatastoreID string   `json:"datastore_id"`
	ServiceID   string   `json:"service_id"`
	Fields      []string `json:"fields,omitempty"` // Specific fields to watch, empty = all allowed
}

// DatastoreSubscribeResponse is the response for datastore.subscribe
type DatastoreSubscribeResponse struct {
	Success        bool   `json:"success"`
	SubscriptionID string `json:"subscription_id"`
	Message        string `json:"message,omitempty"`
}

// DatastoreUnsubscribeRequest is the payload for datastore.unsubscribe
type DatastoreUnsubscribeRequest struct {
	DatastoreID    string `json:"datastore_id"`
	ServiceID      string `json:"service_id"`
	SubscriptionID string `json:"subscription_id"`
}

// DatastoreUnsubscribeResponse is the response for datastore.unsubscribe
type DatastoreUnsubscribeResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// DatastoreSubscription tracks an active subscription
type DatastoreSubscription struct {
	SubscriptionID string    `json:"subscription_id"`
	DatastoreID    string    `json:"datastore_id"`
	ServiceID      string    `json:"service_id"`
	Fields         []string  `json:"fields,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

// Storage key for subscriptions
const KeySubscriptionPrefix = "datastore-subscriptions/"
const KeySubscriptionIndex = "datastore-subscriptions-index"

// --- Permission Checking ---

// CanRead checks if a service can read a specific field
func (c *DatastoreAccessController) CanRead(datastore *CombinedDatastore, serviceID string, field string) bool {
	participant := c.getParticipant(datastore, serviceID)
	if participant == nil {
		return false
	}
	if participant.Status != "active" {
		return false
	}
	if !participant.Permissions.Read {
		return false
	}
	// If specific fields are defined, check field access
	if len(participant.Permissions.Fields) > 0 {
		return contains(participant.Permissions.Fields, field)
	}
	return true
}

// CanWrite checks if a service can write to a specific field
func (c *DatastoreAccessController) CanWrite(datastore *CombinedDatastore, serviceID string, field string) bool {
	participant := c.getParticipant(datastore, serviceID)
	if participant == nil {
		return false
	}
	if participant.Status != "active" {
		return false
	}
	if !participant.Permissions.Write {
		return false
	}
	// If specific fields are defined, check field access
	if len(participant.Permissions.Fields) > 0 {
		return contains(participant.Permissions.Fields, field)
	}
	return true
}

// CanDelete checks if a service can delete a specific field
func (c *DatastoreAccessController) CanDelete(datastore *CombinedDatastore, serviceID string, field string) bool {
	participant := c.getParticipant(datastore, serviceID)
	if participant == nil {
		return false
	}
	if participant.Status != "active" {
		return false
	}
	if !participant.Permissions.Delete {
		return false
	}
	// If specific fields are defined, check field access
	if len(participant.Permissions.Fields) > 0 {
		return contains(participant.Permissions.Fields, field)
	}
	return true
}

// getParticipant finds a participant by service ID
func (c *DatastoreAccessController) getParticipant(datastore *CombinedDatastore, serviceID string) *DatastoreParticipant {
	for i := range datastore.Participants {
		if datastore.Participants[i].ServiceID == serviceID {
			return &datastore.Participants[i]
		}
	}
	return nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// --- Handlers ---

// HandleRead handles datastore.read operations
func (c *DatastoreAccessController) HandleRead(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req DatastoreReadRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return c.errorResponse(msg.GetID(), "invalid request payload")
	}

	// Get datastore
	datastore, err := c.datastoreHandler.getDatastore(req.DatastoreID)
	if err != nil {
		return c.errorResponse(msg.GetID(), "datastore not found")
	}

	if datastore.Status != "active" {
		return c.errorResponse(msg.GetID(), "datastore is not active")
	}

	// Get stored data
	data, err := c.datastoreHandler.getDatastoreData(req.DatastoreID)
	if err != nil {
		return c.errorResponse(msg.GetID(), "failed to read datastore data")
	}

	// Filter data by permission
	result := make(map[string]interface{})
	fieldsToRead := req.Fields
	if len(fieldsToRead) == 0 {
		// Read all fields the service has access to
		for field := range data.Data {
			fieldsToRead = append(fieldsToRead, field)
		}
	}

	deniedFields := []string{}
	for _, field := range fieldsToRead {
		if c.CanRead(datastore, req.ServiceID, field) {
			if val, ok := data.Data[field]; ok {
				result[field] = val
			}
		} else {
			deniedFields = append(deniedFields, field)
		}
	}

	// Log access
	c.logAccess(datastore, req.ServiceID, "read", fieldsToRead, len(deniedFields) > 0)

	if len(deniedFields) > 0 {
		log.Warn().
			Str("datastore_id", req.DatastoreID).
			Str("service_id", req.ServiceID).
			Strs("denied_fields", deniedFields).
			Msg("Service denied access to some fields")
	}

	return c.successResponse(msg.GetID(), DatastoreReadResponse{
		Success:   true,
		Data:      result,
		Version:   data.Version,
		UpdatedAt: data.UpdatedAt,
		UpdatedBy: data.UpdatedBy,
	})
}

// HandleWrite handles datastore.write operations with optimistic locking
func (c *DatastoreAccessController) HandleWrite(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req DatastoreWriteRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return c.errorResponse(msg.GetID(), "invalid request payload")
	}

	// Get datastore
	datastore, err := c.datastoreHandler.getDatastore(req.DatastoreID)
	if err != nil {
		return c.errorResponse(msg.GetID(), "datastore not found")
	}

	if datastore.Status != "active" {
		return c.errorResponse(msg.GetID(), "datastore is not active")
	}

	// Get current data
	data, err := c.datastoreHandler.getDatastoreData(req.DatastoreID)
	if err != nil {
		// Initialize if not exists
		data = &DatastoreData{
			DatastoreID: req.DatastoreID,
			Data:        make(map[string]interface{}),
			Version:     0,
		}
	}

	// Check optimistic locking
	if req.ExpectedVersion > 0 && data.Version != req.ExpectedVersion {
		return c.successResponse(msg.GetID(), DatastoreWriteResponse{
			Success:  false,
			Version:  data.Version,
			Conflict: true,
			Message:  fmt.Sprintf("version conflict: expected %d, current %d", req.ExpectedVersion, data.Version),
		})
	}

	// Check write permissions for each field
	deniedFields := []string{}
	allowedData := make(map[string]interface{})
	for field, value := range req.Data {
		if c.CanWrite(datastore, req.ServiceID, field) {
			allowedData[field] = value
		} else {
			deniedFields = append(deniedFields, field)
		}
	}

	if len(deniedFields) > 0 {
		return c.errorResponse(msg.GetID(), fmt.Sprintf("write denied for fields: %v", deniedFields))
	}

	// Capture old values for audit
	oldValues := make(map[string]interface{})
	for field := range allowedData {
		if oldVal, ok := data.Data[field]; ok {
			oldValues[field] = oldVal
		}
	}

	// Apply changes
	for field, value := range allowedData {
		data.Data[field] = value
	}
	data.Version++
	data.UpdatedAt = time.Now()
	data.UpdatedBy = req.ServiceID

	// Store updated data
	if err := c.datastoreHandler.storeDatastoreData(data); err != nil {
		return c.errorResponse(msg.GetID(), "failed to store data")
	}

	// Log access
	fields := make([]string, 0, len(allowedData))
	for f := range allowedData {
		fields = append(fields, f)
	}
	c.logAccess(datastore, req.ServiceID, "write", fields, false)

	// Notify subscribers
	c.notifySubscribers(datastore, req.ServiceID, "write", fields, data)

	log.Info().
		Str("datastore_id", req.DatastoreID).
		Str("service_id", req.ServiceID).
		Int64("version", data.Version).
		Int("fields_written", len(allowedData)).
		Msg("Datastore write successful")

	return c.successResponse(msg.GetID(), DatastoreWriteResponse{
		Success:   true,
		Version:   data.Version,
		UpdatedAt: data.UpdatedAt,
	})
}

// HandleDelete handles datastore.delete operations (delete specific fields)
func (c *DatastoreAccessController) HandleDelete(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req DatastoreDeleteRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return c.errorResponse(msg.GetID(), "invalid request payload")
	}

	// Get datastore
	datastore, err := c.datastoreHandler.getDatastore(req.DatastoreID)
	if err != nil {
		return c.errorResponse(msg.GetID(), "datastore not found")
	}

	if datastore.Status != "active" {
		return c.errorResponse(msg.GetID(), "datastore is not active")
	}

	// Get current data
	data, err := c.datastoreHandler.getDatastoreData(req.DatastoreID)
	if err != nil {
		return c.errorResponse(msg.GetID(), "datastore data not found")
	}

	// Check optimistic locking
	if req.ExpectedVersion > 0 && data.Version != req.ExpectedVersion {
		return c.errorResponse(msg.GetID(), fmt.Sprintf("version conflict: expected %d, current %d", req.ExpectedVersion, data.Version))
	}

	// Check delete permissions for each field
	deniedFields := []string{}
	allowedFields := []string{}
	for _, field := range req.Fields {
		if c.CanDelete(datastore, req.ServiceID, field) {
			allowedFields = append(allowedFields, field)
		} else {
			deniedFields = append(deniedFields, field)
		}
	}

	if len(deniedFields) > 0 {
		return c.errorResponse(msg.GetID(), fmt.Sprintf("delete denied for fields: %v", deniedFields))
	}

	// Delete fields
	for _, field := range allowedFields {
		delete(data.Data, field)
	}
	data.Version++
	data.UpdatedAt = time.Now()
	data.UpdatedBy = req.ServiceID

	// Store updated data
	if err := c.datastoreHandler.storeDatastoreData(data); err != nil {
		return c.errorResponse(msg.GetID(), "failed to store data")
	}

	// Log access
	c.logAccess(datastore, req.ServiceID, "delete", allowedFields, false)

	// Notify subscribers
	c.notifySubscribers(datastore, req.ServiceID, "delete", allowedFields, data)

	log.Info().
		Str("datastore_id", req.DatastoreID).
		Str("service_id", req.ServiceID).
		Int64("version", data.Version).
		Strs("fields_deleted", allowedFields).
		Msg("Datastore delete successful")

	return c.successResponse(msg.GetID(), DatastoreDeleteResponse{
		Success:   true,
		Version:   data.Version,
		UpdatedAt: data.UpdatedAt,
	})
}

// HandleSubscribe handles datastore.subscribe for real-time updates
func (c *DatastoreAccessController) HandleSubscribe(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req DatastoreSubscribeRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return c.errorResponse(msg.GetID(), "invalid request payload")
	}

	// Get datastore
	datastore, err := c.datastoreHandler.getDatastore(req.DatastoreID)
	if err != nil {
		return c.errorResponse(msg.GetID(), "datastore not found")
	}

	// Verify participant has read access
	participant := c.getParticipant(datastore, req.ServiceID)
	if participant == nil || participant.Status != "active" || !participant.Permissions.Read {
		return c.errorResponse(msg.GetID(), "service does not have read access")
	}

	// Create subscription
	subscription := &DatastoreSubscription{
		SubscriptionID: generateSubscriptionID(),
		DatastoreID:    req.DatastoreID,
		ServiceID:      req.ServiceID,
		Fields:         req.Fields,
		CreatedAt:      time.Now(),
	}

	// Store subscription
	subKey := KeySubscriptionPrefix + subscription.SubscriptionID
	if err := c.storage.PutJSON(subKey, subscription); err != nil {
		return c.errorResponse(msg.GetID(), "failed to create subscription")
	}
	c.storage.AddToIndex(KeySubscriptionIndex, subscription.SubscriptionID)

	log.Info().
		Str("subscription_id", subscription.SubscriptionID).
		Str("datastore_id", req.DatastoreID).
		Str("service_id", req.ServiceID).
		Msg("Subscription created")

	return c.successResponse(msg.GetID(), DatastoreSubscribeResponse{
		Success:        true,
		SubscriptionID: subscription.SubscriptionID,
		Message:        "Subscribed to datastore updates",
	})
}

// HandleUnsubscribe handles datastore.unsubscribe
func (c *DatastoreAccessController) HandleUnsubscribe(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req DatastoreUnsubscribeRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return c.errorResponse(msg.GetID(), "invalid request payload")
	}

	// Delete subscription
	subKey := KeySubscriptionPrefix + req.SubscriptionID
	if err := c.storage.Delete(subKey); err != nil {
		return c.errorResponse(msg.GetID(), "subscription not found")
	}
	c.storage.RemoveFromIndex(KeySubscriptionIndex, req.SubscriptionID)

	log.Info().
		Str("subscription_id", req.SubscriptionID).
		Msg("Subscription removed")

	return c.successResponse(msg.GetID(), DatastoreUnsubscribeResponse{
		Success: true,
		Message: "Unsubscribed from datastore updates",
	})
}

// --- Helper Methods ---

// notifySubscribers sends updates to all subscribed services
func (c *DatastoreAccessController) notifySubscribers(datastore *CombinedDatastore, updaterServiceID string, operation string, fields []string, data *DatastoreData) {
	// Get all subscriptions
	subIDs, err := c.storage.GetIndex(KeySubscriptionIndex)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to get subscription index")
		return
	}

	for _, subID := range subIDs {
		var sub DatastoreSubscription
		subKey := KeySubscriptionPrefix + subID
		if err := c.storage.GetJSON(subKey, &sub); err != nil {
			continue
		}

		// Only notify for this datastore
		if sub.DatastoreID != datastore.ID {
			continue
		}

		// Don't notify the updater
		if sub.ServiceID == updaterServiceID {
			continue
		}

		// Check if any subscribed fields were affected
		if len(sub.Fields) > 0 {
			hasMatch := false
			for _, subField := range sub.Fields {
				for _, changedField := range fields {
					if subField == changedField {
						hasMatch = true
						break
					}
				}
				if hasMatch {
					break
				}
			}
			if !hasMatch {
				continue
			}
		}

		// Build notification with only fields the subscriber can see
		visibleData := make(map[string]interface{})
		for _, field := range fields {
			if c.CanRead(datastore, sub.ServiceID, field) {
				if val, ok := data.Data[field]; ok {
					visibleData[field] = val
				}
			}
		}

		// Send notification
		notification := map[string]interface{}{
			"type":          "datastore_update",
			"datastore_id":  datastore.ID,
			"operation":     operation,
			"updated_by":    updaterServiceID,
			"version":       data.Version,
			"updated_at":    data.UpdatedAt,
			"changed_fields": fields,
			"data":          visibleData,
		}

		payload, _ := json.Marshal(notification)
		subject := fmt.Sprintf("ServiceSpace.%s.fromVault.%s.datastore.update", sub.ServiceID, c.ownerSpace)
		c.publisher.PublishRaw(subject, payload)
	}
}

// logAccess logs a datastore access event
func (c *DatastoreAccessController) logAccess(datastore *CombinedDatastore, serviceID, operation string, fields []string, denied bool) {
	// Get service name
	serviceName := serviceID
	for _, p := range datastore.Participants {
		if p.ServiceID == serviceID {
			serviceName = p.ServiceName
			break
		}
	}

	result := "success"
	if denied {
		result = "partial_denied"
	}

	metadata := map[string]string{
		"datastore_id":   datastore.ID,
		"datastore_name": datastore.Name,
		"operation":      operation,
		"result":         result,
	}

	c.eventHandler.LogServiceEvent(
		nil,
		EventType("datastore."+operation),
		datastore.ID,
		serviceID,
		serviceName,
		operation,
		metadata,
	)
}

func generateSubscriptionID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return "SUB-" + hex.EncodeToString(b)
}

func (c *DatastoreAccessController) errorResponse(requestID, message string) (*OutgoingMessage, error) {
	return &OutgoingMessage{
		RequestID: requestID,
		Type:      MessageTypeResponse,
		Payload:   mustMarshalJSON(map[string]interface{}{"success": false, "error": message}),
	}, nil
}

func (c *DatastoreAccessController) successResponse(requestID string, payload interface{}) (*OutgoingMessage, error) {
	return &OutgoingMessage{
		RequestID: requestID,
		Type:      MessageTypeResponse,
		Payload:   mustMarshalJSON(payload),
	}, nil
}
