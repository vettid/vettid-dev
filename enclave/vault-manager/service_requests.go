package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/rs/zerolog/log"
)

// ServiceRequestsHandler handles incoming requests from services.
// Services can request authentication, data consent, and payments.
// All requests appear in the user's feed and require explicit approval.
type ServiceRequestsHandler struct {
	ownerSpace        string
	storage           *EncryptedStorage
	eventHandler      *EventHandler
	connectionHandler *ServiceConnectionHandler
	contractsHandler  *ServiceContractsHandler
}

// NewServiceRequestsHandler creates a new service requests handler
func NewServiceRequestsHandler(
	ownerSpace string,
	storage *EncryptedStorage,
	eventHandler *EventHandler,
	connectionHandler *ServiceConnectionHandler,
	contractsHandler *ServiceContractsHandler,
) *ServiceRequestsHandler {
	return &ServiceRequestsHandler{
		ownerSpace:        ownerSpace,
		storage:           storage,
		eventHandler:      eventHandler,
		connectionHandler: connectionHandler,
		contractsHandler:  contractsHandler,
	}
}

// --- Data Models ---

// ServiceRequest represents a request from a service requiring user action
type ServiceRequest struct {
	RequestID       string     `json:"request_id"`
	ConnectionID    string     `json:"connection_id"`
	ServiceGUID     string     `json:"service_guid"`
	ServiceName     string     `json:"service_name"`
	RequestType     string     `json:"request_type"` // "auth", "consent", "payment"
	RequestedFields []string   `json:"requested_fields,omitempty"`
	RequestedAction string     `json:"requested_action,omitempty"`
	Purpose         string     `json:"purpose,omitempty"`
	Amount          *Money     `json:"amount,omitempty"` // For payment requests
	Status          string     `json:"status"`           // "pending", "approved", "denied", "expired"
	RequestedAt     time.Time  `json:"requested_at"`
	ExpiresAt       time.Time  `json:"expires_at"`
	RespondedAt     *time.Time `json:"responded_at,omitempty"`
	ResponseData    []byte     `json:"response_data,omitempty"` // Encrypted response
}

// Money represents a monetary amount
type Money struct {
	Amount   int64  `json:"amount"`   // In smallest unit (cents, satoshi, etc.)
	Currency string `json:"currency"` // ISO 4217 code
}

// --- Request/Response Types ---

// AuthRequestPayload is sent by services to request user authentication
type AuthRequestPayload struct {
	ConnectionID    string    `json:"connection_id"`
	Challenge       string    `json:"challenge"`        // Random challenge for signature
	Purpose         string    `json:"purpose"`          // Why auth is needed
	ExpiresIn       int       `json:"expires_in"`       // Seconds until expiration
	CallbackSubject string    `json:"callback_subject"` // NATS subject for response
}

// AuthRequestResponse is returned to the service
type AuthRequestResponse struct {
	RequestID string    `json:"request_id"`
	Status    string    `json:"status"` // "pending"
	ExpiresAt time.Time `json:"expires_at"`
}

// ConsentRequestPayload is sent by services to request consent for fields
type ConsentRequestPayload struct {
	ConnectionID    string   `json:"connection_id"`
	Fields          []string `json:"fields"`           // Fields needing consent
	Purpose         string   `json:"purpose"`          // Why fields are needed
	OneTime         bool     `json:"one_time"`         // Consent for single use
	ExpiresIn       int      `json:"expires_in"`       // Seconds until expiration
	CallbackSubject string   `json:"callback_subject"` // NATS subject for response
}

// ConsentRequestResponse is returned to the service
type ConsentRequestResponse struct {
	RequestID string    `json:"request_id"`
	Status    string    `json:"status"` // "pending"
	ExpiresAt time.Time `json:"expires_at"`
}

// PaymentRequestPayload is sent by services to request payment
type PaymentRequestPayload struct {
	ConnectionID    string `json:"connection_id"`
	Amount          Money  `json:"amount"`
	Description     string `json:"description"`
	Reference       string `json:"reference,omitempty"` // Service's reference ID
	ExpiresIn       int    `json:"expires_in"`          // Seconds until expiration
	CallbackSubject string `json:"callback_subject"`    // NATS subject for response
}

// PaymentRequestResponse is returned to the service
type PaymentRequestResponse struct {
	RequestID string    `json:"request_id"`
	Status    string    `json:"status"` // "pending"
	ExpiresAt time.Time `json:"expires_at"`
}

// RespondToRequestPayload is sent by user to respond to a request
type RespondToRequestPayload struct {
	RequestID      string   `json:"request_id"`
	Response       string   `json:"response"` // "approve" or "deny"
	SelectedFields []string `json:"selected_fields,omitempty"` // For consent: which fields to share
	DenyReason     string   `json:"deny_reason,omitempty"`
}

// RespondToRequestResponse is returned after responding
type RespondToRequestResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// ListRequestsPayload is for listing service requests
type ListRequestsPayload struct {
	ConnectionID string   `json:"connection_id,omitempty"` // Filter by connection
	Status       []string `json:"status,omitempty"`        // Filter by status
	RequestType  string   `json:"request_type,omitempty"`  // Filter by type
	Limit        int      `json:"limit,omitempty"`
	Offset       int      `json:"offset,omitempty"`
}

// ListRequestsResponse contains list of requests
type ListRequestsResponse struct {
	Requests []ServiceRequest `json:"requests"`
	Total    int              `json:"total"`
	HasMore  bool             `json:"has_more"`
}

// --- Handler Methods ---

func (h *ServiceRequestsHandler) errorResponse(requestID, message string) (*OutgoingMessage, error) {
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

// HandleAuthRequest handles incoming auth request from service
func (h *ServiceRequestsHandler) HandleAuthRequest(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req AuthRequestPayload
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}
	if req.Challenge == "" {
		return h.errorResponse(msg.GetID(), "challenge is required")
	}

	// Get connection and verify active
	conn, err := h.connectionHandler.GetConnection(req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}
	if conn.Status != "active" {
		return h.errorResponse(msg.GetID(), "Connection is not active")
	}

	// Check if service has auth permission
	if !conn.ServiceProfile.CurrentContract.CanRequestAuth {
		return h.errorResponse(msg.GetID(), "Service does not have auth permission")
	}

	// Calculate expiration
	expiresIn := req.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 300 // Default 5 minutes
	}
	if expiresIn > 3600 {
		expiresIn = 3600 // Max 1 hour
	}

	now := time.Now()
	requestID := generateRequestID()

	request := ServiceRequest{
		RequestID:       requestID,
		ConnectionID:    req.ConnectionID,
		ServiceGUID:     conn.ServiceGUID,
		ServiceName:     conn.ServiceProfile.ServiceName,
		RequestType:     "auth",
		RequestedAction: req.Challenge,
		Purpose:         req.Purpose,
		Status:          "pending",
		RequestedAt:     now,
		ExpiresAt:       now.Add(time.Duration(expiresIn) * time.Second),
	}

	// Store request
	requestData, _ := json.Marshal(request)
	if err := h.storage.Put("service-requests/"+requestID, requestData); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to store request")
	}

	// Add to index
	h.addToRequestIndex(requestID, req.ConnectionID)

	// Log event and notify user
	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(
			context.Background(),
			EventTypeServiceAuthRequested,
			req.ConnectionID,
			conn.ServiceGUID,
			conn.ServiceProfile.ServiceName+" requests authentication",
		)
	}

	log.Info().
		Str("request_id", requestID).
		Str("connection_id", req.ConnectionID).
		Str("service", conn.ServiceProfile.ServiceName).
		Msg("Auth request created")

	resp := AuthRequestResponse{
		RequestID: requestID,
		Status:    "pending",
		ExpiresAt: request.ExpiresAt,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleConsentRequest handles incoming consent request from service
func (h *ServiceRequestsHandler) HandleConsentRequest(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req ConsentRequestPayload
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

	// Verify fields are consent fields in contract
	contract := conn.ServiceProfile.CurrentContract
	validFields := make([]string, 0)
	for _, field := range req.Fields {
		for _, cf := range contract.ConsentFields {
			if cf == field {
				validFields = append(validFields, field)
				break
			}
		}
	}

	if len(validFields) == 0 {
		return h.errorResponse(msg.GetID(), "No valid consent fields requested")
	}

	// Calculate expiration
	expiresIn := req.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 300 // Default 5 minutes
	}
	if expiresIn > 3600 {
		expiresIn = 3600 // Max 1 hour
	}

	now := time.Now()
	requestID := generateRequestID()

	request := ServiceRequest{
		RequestID:       requestID,
		ConnectionID:    req.ConnectionID,
		ServiceGUID:     conn.ServiceGUID,
		ServiceName:     conn.ServiceProfile.ServiceName,
		RequestType:     "consent",
		RequestedFields: validFields,
		Purpose:         req.Purpose,
		Status:          "pending",
		RequestedAt:     now,
		ExpiresAt:       now.Add(time.Duration(expiresIn) * time.Second),
	}

	// Store request
	requestData, _ := json.Marshal(request)
	if err := h.storage.Put("service-requests/"+requestID, requestData); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to store request")
	}

	// Add to index
	h.addToRequestIndex(requestID, req.ConnectionID)

	// Log event and notify user
	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(
			context.Background(),
			EventTypeServiceConsentRequested,
			req.ConnectionID,
			conn.ServiceGUID,
			conn.ServiceProfile.ServiceName+" requests consent for data",
		)
	}

	log.Info().
		Str("request_id", requestID).
		Str("connection_id", req.ConnectionID).
		Int("fields_count", len(validFields)).
		Msg("Consent request created")

	resp := ConsentRequestResponse{
		RequestID: requestID,
		Status:    "pending",
		ExpiresAt: request.ExpiresAt,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandlePaymentRequest handles incoming payment request from service
func (h *ServiceRequestsHandler) HandlePaymentRequest(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req PaymentRequestPayload
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}
	if req.Amount.Amount <= 0 {
		return h.errorResponse(msg.GetID(), "amount must be positive")
	}
	if req.Amount.Currency == "" {
		return h.errorResponse(msg.GetID(), "currency is required")
	}

	// Get connection and verify active
	conn, err := h.connectionHandler.GetConnection(req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}
	if conn.Status != "active" {
		return h.errorResponse(msg.GetID(), "Connection is not active")
	}

	// Check if service has payment permission
	if !conn.ServiceProfile.CurrentContract.CanRequestPayment {
		return h.errorResponse(msg.GetID(), "Service does not have payment permission")
	}

	// Calculate expiration
	expiresIn := req.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 900 // Default 15 minutes
	}
	if expiresIn > 86400 {
		expiresIn = 86400 // Max 24 hours
	}

	now := time.Now()
	requestID := generateRequestID()

	request := ServiceRequest{
		RequestID:       requestID,
		ConnectionID:    req.ConnectionID,
		ServiceGUID:     conn.ServiceGUID,
		ServiceName:     conn.ServiceProfile.ServiceName,
		RequestType:     "payment",
		RequestedAction: req.Description,
		Purpose:         req.Reference,
		Amount:          &req.Amount,
		Status:          "pending",
		RequestedAt:     now,
		ExpiresAt:       now.Add(time.Duration(expiresIn) * time.Second),
	}

	// Store request
	requestData, _ := json.Marshal(request)
	if err := h.storage.Put("service-requests/"+requestID, requestData); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to store request")
	}

	// Add to index
	h.addToRequestIndex(requestID, req.ConnectionID)

	// Log event and notify user
	if h.eventHandler != nil {
		h.eventHandler.LogConnectionEvent(
			context.Background(),
			EventTypeServicePaymentRequested,
			req.ConnectionID,
			conn.ServiceGUID,
			conn.ServiceProfile.ServiceName+" requests payment",
		)
	}

	log.Info().
		Str("request_id", requestID).
		Str("connection_id", req.ConnectionID).
		Int64("amount", req.Amount.Amount).
		Str("currency", req.Amount.Currency).
		Msg("Payment request created")

	resp := PaymentRequestResponse{
		RequestID: requestID,
		Status:    "pending",
		ExpiresAt: request.ExpiresAt,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleRespond handles user response to a request
func (h *ServiceRequestsHandler) HandleRespond(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req RespondToRequestPayload
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.RequestID == "" {
		return h.errorResponse(msg.GetID(), "request_id is required")
	}
	if req.Response != "approve" && req.Response != "deny" {
		return h.errorResponse(msg.GetID(), "response must be 'approve' or 'deny'")
	}

	// Load request
	requestData, err := h.storage.Get("service-requests/" + req.RequestID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Request not found")
	}

	var request ServiceRequest
	if err := json.Unmarshal(requestData, &request); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to read request")
	}

	// Check if already responded
	if request.Status != "pending" {
		return h.errorResponse(msg.GetID(), "Request already responded to")
	}

	// Check if expired
	if time.Now().After(request.ExpiresAt) {
		request.Status = "expired"
		updatedData, _ := json.Marshal(request)
		h.storage.Put("service-requests/"+req.RequestID, updatedData)
		return h.errorResponse(msg.GetID(), "Request has expired")
	}

	now := time.Now()
	request.RespondedAt = &now

	if req.Response == "approve" {
		request.Status = "approved"

		// For consent requests, store which fields were approved
		if request.RequestType == "consent" && len(req.SelectedFields) > 0 {
			responseData := map[string]interface{}{
				"approved_fields": req.SelectedFields,
			}
			request.ResponseData, _ = json.Marshal(responseData)
		}

		// Log approval event
		if h.eventHandler != nil {
			h.eventHandler.LogConnectionEvent(
				context.Background(),
				EventTypeServiceRequestApproved,
				request.ConnectionID,
				request.ServiceGUID,
				"Approved "+request.RequestType+" request from "+request.ServiceName,
			)
		}
	} else {
		request.Status = "denied"

		// Log denial event
		if h.eventHandler != nil {
			h.eventHandler.LogConnectionEvent(
				context.Background(),
				EventTypeServiceRequestDenied,
				request.ConnectionID,
				request.ServiceGUID,
				"Denied "+request.RequestType+" request from "+request.ServiceName,
			)
		}
	}

	// Update request
	updatedData, _ := json.Marshal(request)
	if err := h.storage.Put("service-requests/"+req.RequestID, updatedData); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to update request")
	}

	// Update connection last active
	h.connectionHandler.UpdateLastActive(request.ConnectionID)

	log.Info().
		Str("request_id", req.RequestID).
		Str("response", req.Response).
		Str("request_type", request.RequestType).
		Msg("Request responded")

	resp := RespondToRequestResponse{
		Success: true,
		Message: "Request " + req.Response + "d",
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleList handles listing service requests
func (h *ServiceRequestsHandler) HandleList(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req ListRequestsPayload
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		req = ListRequestsPayload{Limit: 50}
	}

	if req.Limit <= 0 {
		req.Limit = 50
	}
	if req.Limit > 100 {
		req.Limit = 100
	}

	// Load request index
	var allRequestIDs []string
	if req.ConnectionID != "" {
		// Load connection-specific index
		indexData, err := h.storage.Get("service-requests/_index/" + req.ConnectionID)
		if err == nil {
			json.Unmarshal(indexData, &allRequestIDs)
		}
	} else {
		// Load global index
		indexData, err := h.storage.Get("service-requests/_index")
		if err == nil {
			json.Unmarshal(indexData, &allRequestIDs)
		}
	}

	var requests []ServiceRequest
	for _, requestID := range allRequestIDs {
		data, err := h.storage.Get("service-requests/" + requestID)
		if err != nil {
			continue
		}

		var request ServiceRequest
		if err := json.Unmarshal(data, &request); err != nil {
			continue
		}

		// Apply filters
		if len(req.Status) > 0 {
			matched := false
			for _, s := range req.Status {
				if request.Status == s {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}

		if req.RequestType != "" && request.RequestType != req.RequestType {
			continue
		}

		// Check and update expired requests
		if request.Status == "pending" && time.Now().After(request.ExpiresAt) {
			request.Status = "expired"
			updatedData, _ := json.Marshal(request)
			h.storage.Put("service-requests/"+requestID, updatedData)
		}

		requests = append(requests, request)
	}

	// Apply pagination
	total := len(requests)
	start := req.Offset
	if start > total {
		start = total
	}
	end := start + req.Limit
	if end > total {
		end = total
	}

	paginatedRequests := requests[start:end]
	if paginatedRequests == nil {
		paginatedRequests = []ServiceRequest{}
	}

	resp := ListRequestsResponse{
		Requests: paginatedRequests,
		Total:    total,
		HasMore:  end < total,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// --- Helper Methods ---

// addToRequestIndex adds a request ID to indices
func (h *ServiceRequestsHandler) addToRequestIndex(requestID, connectionID string) {
	// Add to global index
	globalIndexKey := "service-requests/_index"
	globalIndexData, _ := h.storage.Get(globalIndexKey)
	var globalIDs []string
	if globalIndexData != nil {
		json.Unmarshal(globalIndexData, &globalIDs)
	}
	globalIDs = append([]string{requestID}, globalIDs...) // Prepend (most recent first)
	newGlobalData, _ := json.Marshal(globalIDs)
	h.storage.Put(globalIndexKey, newGlobalData)

	// Add to connection-specific index
	connIndexKey := "service-requests/_index/" + connectionID
	connIndexData, _ := h.storage.Get(connIndexKey)
	var connIDs []string
	if connIndexData != nil {
		json.Unmarshal(connIndexData, &connIDs)
	}
	connIDs = append([]string{requestID}, connIDs...) // Prepend
	newConnData, _ := json.Marshal(connIDs)
	h.storage.Put(connIndexKey, newConnData)
}

// generateRequestID generates a unique request ID
func generateRequestID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return "req_" + hex.EncodeToString(b)
}
