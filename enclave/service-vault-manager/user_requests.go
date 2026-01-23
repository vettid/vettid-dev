package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
)

// UserRequestsHandler handles sending requests to users and processing responses.
// Services use this to request on-demand data, authentication, consent, and payments.
type UserRequestsHandler struct {
	ownerSpace          string
	storage             *EncryptedStorage
	sendFn              func(msg *OutgoingMessage) error
	connectionsHandler  *UserConnectionsHandler
	contractManager     *ContractManager
}

// NewUserRequestsHandler creates a new user requests handler
func NewUserRequestsHandler(
	ownerSpace string,
	storage *EncryptedStorage,
	sendFn func(msg *OutgoingMessage) error,
	connectionsHandler *UserConnectionsHandler,
	contractManager *ContractManager,
) *UserRequestsHandler {
	return &UserRequestsHandler{
		ownerSpace:         ownerSpace,
		storage:            storage,
		sendFn:             sendFn,
		connectionsHandler: connectionsHandler,
		contractManager:    contractManager,
	}
}

// --- Request Types ---

// DataRequestPayload is the payload for user.request.data
type DataRequestPayload struct {
	ConnectionID string   `json:"connection_id"`
	Fields       []string `json:"fields"`
	Purpose      string   `json:"purpose"`
	ExpiresIn    int      `json:"expires_in,omitempty"` // Seconds until expiry (default: 3600)
}

// DataRequestResponse is the response for user.request.data
type DataRequestResponse struct {
	Success   bool   `json:"success"`
	RequestID string `json:"request_id"`
	Message   string `json:"message,omitempty"`
}

// AuthRequestPayload is the payload for user.request.auth
type AuthRequestPayload struct {
	ConnectionID string `json:"connection_id"`
	Challenge    string `json:"challenge"`       // Challenge for the user to sign
	Purpose      string `json:"purpose"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
}

// AuthRequestResponse is the response for user.request.auth
type AuthRequestResponse struct {
	Success   bool   `json:"success"`
	RequestID string `json:"request_id"`
	Message   string `json:"message,omitempty"`
}

// ConsentRequestPayload is the payload for user.request.consent
type ConsentRequestPayload struct {
	ConnectionID string   `json:"connection_id"`
	Fields       []string `json:"fields"`        // Consent fields to request
	Purpose      string   `json:"purpose"`
	ExpiresIn    int      `json:"expires_in,omitempty"`
}

// ConsentRequestResponse is the response for user.request.consent
type ConsentRequestResponse struct {
	Success   bool   `json:"success"`
	RequestID string `json:"request_id"`
	Message   string `json:"message,omitempty"`
}

// PaymentRequestPayload is the payload for user.request.payment
type PaymentRequestPayload struct {
	ConnectionID string        `json:"connection_id"`
	Amount       PaymentAmount `json:"amount"`
	Description  string        `json:"description"`
	Reference    string        `json:"reference,omitempty"`
	ExpiresIn    int           `json:"expires_in,omitempty"`
}

// PaymentRequestResponse is the response for user.request.payment
type PaymentRequestResponse struct {
	Success   bool   `json:"success"`
	RequestID string `json:"request_id"`
	Message   string `json:"message,omitempty"`
}

// ListRequestsPayload is the payload for user.request.list
type ListRequestsPayload struct {
	ConnectionID string `json:"connection_id,omitempty"`
	Status       string `json:"status,omitempty"`
	Type         string `json:"type,omitempty"`
	Limit        int    `json:"limit,omitempty"`
	Offset       int    `json:"offset,omitempty"`
}

// ListRequestsResponse is the response for user.request.list
type ListRequestsResponse struct {
	Requests []OutboundRequestInfo `json:"requests"`
	Total    int                   `json:"total"`
}

// OutboundRequestInfo is the public view of an outbound request
type OutboundRequestInfo struct {
	RequestID    string         `json:"request_id"`
	ConnectionID string         `json:"connection_id"`
	UserGUID     string         `json:"user_guid"`
	RequestType  string         `json:"request_type"`
	Fields       []string       `json:"fields,omitempty"`
	Purpose      string         `json:"purpose,omitempty"`
	Amount       *PaymentAmount `json:"amount,omitempty"`
	Status       string         `json:"status"`
	CreatedAt    time.Time      `json:"created_at"`
	ExpiresAt    time.Time      `json:"expires_at"`
	RespondedAt  *time.Time     `json:"responded_at,omitempty"`
}

// GetRequestPayload is the payload for user.request.get
type GetRequestPayload struct {
	RequestID string `json:"request_id"`
}

// GetRequestResponse is the response for user.request.get
type GetRequestResponse struct {
	Request      OutboundRequestInfo `json:"request"`
	ResponseData json.RawMessage     `json:"response_data,omitempty"` // Only if approved
}

// UserResponsePayload is what we receive when a user responds to our request
type UserResponsePayload struct {
	RequestID    string          `json:"request_id"`
	Status       string          `json:"status"` // "approved", "denied"
	ResponseData json.RawMessage `json:"response_data,omitempty"`
	Reason       string          `json:"reason,omitempty"` // For denials
}

// --- Handlers ---

// HandleRequestData sends a data request to a connected user
func (h *UserRequestsHandler) HandleRequestData(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req DataRequestPayload
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "invalid request payload")
	}

	// Get connection
	conn, err := h.connectionsHandler.GetConnection(req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "connection not found")
	}
	if conn.Status != "active" {
		return h.errorResponse(msg.GetID(), "connection is not active")
	}

	// Validate fields against contract
	contract, err := h.contractManager.GetCurrentContract()
	if err != nil || contract == nil {
		return h.errorResponse(msg.GetID(), "no active contract")
	}
	if err := h.contractManager.ValidateFieldsForRequest(req.Fields, contract); err != nil {
		return h.errorResponse(msg.GetID(), err.Error())
	}

	// Set default expiry
	if req.ExpiresIn <= 0 {
		req.ExpiresIn = 3600 // 1 hour default
	}

	// Create outbound request
	request := &OutboundRequest{
		RequestID:    generateID(),
		ConnectionID: req.ConnectionID,
		UserGUID:     conn.UserGUID,
		RequestType:  "data",
		Fields:       req.Fields,
		Purpose:      req.Purpose,
		Status:       "pending",
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(time.Duration(req.ExpiresIn) * time.Second),
	}

	// Store request
	if err := h.storeRequest(request); err != nil {
		return h.errorResponse(msg.GetID(), "failed to store request")
	}

	// Send to user's vault
	if err := h.sendToUser(conn.UserGUID, "request.data", request); err != nil {
		return h.errorResponse(msg.GetID(), "failed to send request to user")
	}

	log.Info().
		Str("request_id", request.RequestID).
		Str("user_guid", conn.UserGUID).
		Strs("fields", req.Fields).
		Msg("Data request sent to user")

	return h.successResponse(msg.GetID(), DataRequestResponse{
		Success:   true,
		RequestID: request.RequestID,
		Message:   "Request sent to user",
	})
}

// HandleRequestAuth sends an authentication request to a connected user
func (h *UserRequestsHandler) HandleRequestAuth(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req AuthRequestPayload
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "invalid request payload")
	}

	// Get connection
	conn, err := h.connectionsHandler.GetConnection(req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "connection not found")
	}
	if conn.Status != "active" {
		return h.errorResponse(msg.GetID(), "connection is not active")
	}

	// Check contract allows auth requests
	contract, err := h.contractManager.GetCurrentContract()
	if err != nil || contract == nil {
		return h.errorResponse(msg.GetID(), "no active contract")
	}
	if !contract.CanRequestAuth {
		return h.errorResponse(msg.GetID(), "contract does not allow auth requests")
	}

	// Set default expiry
	if req.ExpiresIn <= 0 {
		req.ExpiresIn = 300 // 5 minutes for auth
	}

	// Create outbound request
	request := &OutboundRequest{
		RequestID:    generateID(),
		ConnectionID: req.ConnectionID,
		UserGUID:     conn.UserGUID,
		RequestType:  "auth",
		Purpose:      req.Purpose,
		Status:       "pending",
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(time.Duration(req.ExpiresIn) * time.Second),
	}

	// Store request
	if err := h.storeRequest(request); err != nil {
		return h.errorResponse(msg.GetID(), "failed to store request")
	}

	// Send to user's vault with challenge
	payload := map[string]interface{}{
		"request_id": request.RequestID,
		"challenge":  req.Challenge,
		"purpose":    req.Purpose,
		"expires_at": request.ExpiresAt,
	}
	if err := h.sendToUserPayload(conn.UserGUID, "request.auth", payload); err != nil {
		return h.errorResponse(msg.GetID(), "failed to send request to user")
	}

	log.Info().
		Str("request_id", request.RequestID).
		Str("user_guid", conn.UserGUID).
		Msg("Auth request sent to user")

	return h.successResponse(msg.GetID(), AuthRequestResponse{
		Success:   true,
		RequestID: request.RequestID,
		Message:   "Auth request sent to user",
	})
}

// HandleRequestConsent sends a consent request for specific fields
func (h *UserRequestsHandler) HandleRequestConsent(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req ConsentRequestPayload
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "invalid request payload")
	}

	// Get connection
	conn, err := h.connectionsHandler.GetConnection(req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "connection not found")
	}
	if conn.Status != "active" {
		return h.errorResponse(msg.GetID(), "connection is not active")
	}

	// Validate consent fields against contract
	contract, err := h.contractManager.GetCurrentContract()
	if err != nil || contract == nil {
		return h.errorResponse(msg.GetID(), "no active contract")
	}

	// Check that requested fields are in consent_fields
	for _, field := range req.Fields {
		found := false
		for _, cf := range contract.ConsentFields {
			if cf == field {
				found = true
				break
			}
		}
		if !found {
			return h.errorResponse(msg.GetID(), fmt.Sprintf("field %s is not a consent field in contract", field))
		}
	}

	// Set default expiry
	if req.ExpiresIn <= 0 {
		req.ExpiresIn = 86400 // 24 hours for consent
	}

	// Create outbound request
	request := &OutboundRequest{
		RequestID:    generateID(),
		ConnectionID: req.ConnectionID,
		UserGUID:     conn.UserGUID,
		RequestType:  "consent",
		Fields:       req.Fields,
		Purpose:      req.Purpose,
		Status:       "pending",
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(time.Duration(req.ExpiresIn) * time.Second),
	}

	// Store request
	if err := h.storeRequest(request); err != nil {
		return h.errorResponse(msg.GetID(), "failed to store request")
	}

	// Send to user's vault
	if err := h.sendToUser(conn.UserGUID, "request.consent", request); err != nil {
		return h.errorResponse(msg.GetID(), "failed to send request to user")
	}

	log.Info().
		Str("request_id", request.RequestID).
		Str("user_guid", conn.UserGUID).
		Strs("fields", req.Fields).
		Msg("Consent request sent to user")

	return h.successResponse(msg.GetID(), ConsentRequestResponse{
		Success:   true,
		RequestID: request.RequestID,
		Message:   "Consent request sent to user",
	})
}

// HandleRequestPayment sends a payment request to a connected user
func (h *UserRequestsHandler) HandleRequestPayment(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req PaymentRequestPayload
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "invalid request payload")
	}

	// Get connection
	conn, err := h.connectionsHandler.GetConnection(req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "connection not found")
	}
	if conn.Status != "active" {
		return h.errorResponse(msg.GetID(), "connection is not active")
	}

	// Check contract allows payment requests
	contract, err := h.contractManager.GetCurrentContract()
	if err != nil || contract == nil {
		return h.errorResponse(msg.GetID(), "no active contract")
	}
	if !contract.CanRequestPayment {
		return h.errorResponse(msg.GetID(), "contract does not allow payment requests")
	}

	// Set default expiry
	if req.ExpiresIn <= 0 {
		req.ExpiresIn = 3600 // 1 hour for payment
	}

	// Create outbound request
	request := &OutboundRequest{
		RequestID:    generateID(),
		ConnectionID: req.ConnectionID,
		UserGUID:     conn.UserGUID,
		RequestType:  "payment",
		Purpose:      req.Description,
		Amount:       &req.Amount,
		Status:       "pending",
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(time.Duration(req.ExpiresIn) * time.Second),
	}

	// Store request
	if err := h.storeRequest(request); err != nil {
		return h.errorResponse(msg.GetID(), "failed to store request")
	}

	// Send to user's vault
	payload := map[string]interface{}{
		"request_id":  request.RequestID,
		"amount":      req.Amount,
		"description": req.Description,
		"reference":   req.Reference,
		"expires_at":  request.ExpiresAt,
	}
	if err := h.sendToUserPayload(conn.UserGUID, "request.payment", payload); err != nil {
		return h.errorResponse(msg.GetID(), "failed to send request to user")
	}

	log.Info().
		Str("request_id", request.RequestID).
		Str("user_guid", conn.UserGUID).
		Str("amount", req.Amount.Amount).
		Str("currency", req.Amount.Currency).
		Msg("Payment request sent to user")

	return h.successResponse(msg.GetID(), PaymentRequestResponse{
		Success:   true,
		RequestID: request.RequestID,
		Message:   "Payment request sent to user",
	})
}

// HandleListRequests lists outbound requests
func (h *UserRequestsHandler) HandleListRequests(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req ListRequestsPayload
	if msg.Payload != nil {
		if err := json.Unmarshal(msg.Payload, &req); err != nil {
			return h.errorResponse(msg.GetID(), "invalid request payload")
		}
	}

	// Set defaults
	if req.Limit <= 0 || req.Limit > 100 {
		req.Limit = 50
	}

	// Get all request IDs
	reqIDs, err := h.storage.GetIndex(KeyRequestIndex)
	if err != nil {
		return h.errorResponse(msg.GetID(), "failed to list requests")
	}

	var requests []OutboundRequestInfo
	for _, reqID := range reqIDs {
		var request OutboundRequest
		reqKey := KeyRequestPrefix + reqID
		if err := h.storage.GetJSON(reqKey, &request); err != nil {
			continue
		}

		// Apply filters
		if req.ConnectionID != "" && request.ConnectionID != req.ConnectionID {
			continue
		}
		if req.Status != "" && request.Status != req.Status {
			continue
		}
		if req.Type != "" && request.RequestType != req.Type {
			continue
		}

		requests = append(requests, OutboundRequestInfo{
			RequestID:    request.RequestID,
			ConnectionID: request.ConnectionID,
			UserGUID:     request.UserGUID,
			RequestType:  request.RequestType,
			Fields:       request.Fields,
			Purpose:      request.Purpose,
			Amount:       request.Amount,
			Status:       request.Status,
			CreatedAt:    request.CreatedAt,
			ExpiresAt:    request.ExpiresAt,
			RespondedAt:  request.RespondedAt,
		})
	}

	// Apply pagination
	total := len(requests)
	start := req.Offset
	end := start + req.Limit
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}
	requests = requests[start:end]

	return h.successResponse(msg.GetID(), ListRequestsResponse{
		Requests: requests,
		Total:    total,
	})
}

// HandleGetRequest retrieves a specific request with its response data
func (h *UserRequestsHandler) HandleGetRequest(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req GetRequestPayload
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "invalid request payload")
	}

	var request OutboundRequest
	reqKey := KeyRequestPrefix + req.RequestID
	if err := h.storage.GetJSON(reqKey, &request); err != nil {
		return h.errorResponse(msg.GetID(), "request not found")
	}

	response := GetRequestResponse{
		Request: OutboundRequestInfo{
			RequestID:    request.RequestID,
			ConnectionID: request.ConnectionID,
			UserGUID:     request.UserGUID,
			RequestType:  request.RequestType,
			Fields:       request.Fields,
			Purpose:      request.Purpose,
			Amount:       request.Amount,
			Status:       request.Status,
			CreatedAt:    request.CreatedAt,
			ExpiresAt:    request.ExpiresAt,
			RespondedAt:  request.RespondedAt,
		},
	}

	// Include response data only if approved
	if request.Status == "approved" && len(request.ResponseData) > 0 {
		response.ResponseData = request.ResponseData
	}

	return h.successResponse(msg.GetID(), response)
}

// HandleUserResponse processes a response from a user's vault
func (h *UserRequestsHandler) HandleUserResponse(msg *IncomingMessage, userGUID string) (*OutgoingMessage, error) {
	var resp UserResponsePayload
	if err := json.Unmarshal(msg.Payload, &resp); err != nil {
		return h.errorResponse(msg.GetID(), "invalid response payload")
	}

	// Get the original request
	var request OutboundRequest
	reqKey := KeyRequestPrefix + resp.RequestID
	if err := h.storage.GetJSON(reqKey, &request); err != nil {
		return h.errorResponse(msg.GetID(), "request not found")
	}

	// Verify the response is from the correct user
	if request.UserGUID != userGUID {
		return h.errorResponse(msg.GetID(), "user mismatch")
	}

	// Verify request is still pending
	if request.Status != "pending" {
		return h.errorResponse(msg.GetID(), "request is no longer pending")
	}

	// Check if expired
	if time.Now().After(request.ExpiresAt) {
		request.Status = "expired"
		h.storage.PutJSON(reqKey, request)
		return h.errorResponse(msg.GetID(), "request has expired")
	}

	// Update request with response
	now := time.Now()
	request.Status = resp.Status
	request.RespondedAt = &now
	if resp.Status == "approved" {
		request.ResponseData = resp.ResponseData
	}

	if err := h.storage.PutJSON(reqKey, request); err != nil {
		return h.errorResponse(msg.GetID(), "failed to store response")
	}

	// Update connection activity
	h.connectionsHandler.UpdateLastActivity(request.ConnectionID)

	log.Info().
		Str("request_id", request.RequestID).
		Str("user_guid", userGUID).
		Str("status", resp.Status).
		Msg("User responded to request")

	return h.successResponse(msg.GetID(), map[string]interface{}{
		"success":    true,
		"request_id": request.RequestID,
		"status":     resp.Status,
	})
}

// --- Helper Methods ---

func (h *UserRequestsHandler) storeRequest(request *OutboundRequest) error {
	reqKey := KeyRequestPrefix + request.RequestID
	if err := h.storage.PutJSON(reqKey, request); err != nil {
		return err
	}
	return h.storage.AddToIndex(KeyRequestIndex, request.RequestID)
}

func (h *UserRequestsHandler) sendToUser(userGUID, operation string, data interface{}) error {
	payload, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return h.sendToUserPayload(userGUID, operation, payload)
}

func (h *UserRequestsHandler) sendToUserPayload(userGUID, operation string, payload interface{}) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	msg := &OutgoingMessage{
		Type:    MessageTypeNATSPublish,
		Subject: fmt.Sprintf("OwnerSpace.%s.fromService.%s.%s", userGUID, h.ownerSpace, operation),
		Payload: data,
	}

	return h.sendFn(msg)
}

func (h *UserRequestsHandler) errorResponse(requestID, message string) (*OutgoingMessage, error) {
	return &OutgoingMessage{
		RequestID: requestID,
		Type:      MessageTypeResponse,
		Payload:   mustMarshal(map[string]interface{}{"success": false, "error": message}),
	}, nil
}

func (h *UserRequestsHandler) successResponse(requestID string, payload interface{}) (*OutgoingMessage, error) {
	return &OutgoingMessage{
		RequestID: requestID,
		Type:      MessageTypeResponse,
		Payload:   mustMarshal(payload),
	}, nil
}
