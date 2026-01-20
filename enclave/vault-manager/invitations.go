package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
)

// InvitationsHandler handles invitation lifecycle management.
// Invitations track the state of connection requests.
type InvitationsHandler struct {
	ownerSpace string
	storage    *EncryptedStorage
}

// NewInvitationsHandler creates a new invitations handler
func NewInvitationsHandler(ownerSpace string, storage *EncryptedStorage) *InvitationsHandler {
	return &InvitationsHandler{
		ownerSpace: ownerSpace,
		storage:    storage,
	}
}

// --- Storage types ---

// InvitationRecord represents a stored invitation
type InvitationRecord struct {
	InvitationID   string     `json:"invitation_id"`
	ConnectionID   string     `json:"connection_id"`
	Status         string     `json:"status"` // "pending", "accepted", "rejected", "expired", "cancelled"
	DeliveryMethod string     `json:"delivery_method,omitempty"` // "qr_code", "link", "sms", "email"
	Label          string     `json:"label,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	ExpiresAt      time.Time  `json:"expires_at"`
	ViewedAt       *time.Time `json:"viewed_at,omitempty"`
	RespondedAt    *time.Time `json:"responded_at,omitempty"`
}

// --- Request/Response types ---

// InvitationListRequest is the payload for invitation.list
type InvitationListRequest struct {
	Status string `json:"status,omitempty"` // Filter by status
	Limit  int    `json:"limit,omitempty"`
	Offset int    `json:"offset,omitempty"`
}

// InvitationInfo represents invitation info in list response
type InvitationInfo struct {
	InvitationID   string `json:"invitation_id"`
	ConnectionID   string `json:"connection_id"`
	Status         string `json:"status"`
	DeliveryMethod string `json:"delivery_method,omitempty"`
	Label          string `json:"label,omitempty"`
	CreatedAt      string `json:"created_at"`
	ExpiresAt      string `json:"expires_at"`
	ViewedAt       string `json:"viewed_at,omitempty"`
	RespondedAt    string `json:"responded_at,omitempty"`
}

// InvitationListResponse is the response for invitation.list
type InvitationListResponse struct {
	Invitations []InvitationInfo `json:"invitations"`
	Total       int              `json:"total"`
}

// InvitationCancelRequest is the payload for invitation.cancel
type InvitationCancelRequest struct {
	InvitationID string `json:"invitation_id"`
}

// InvitationResendRequest is the payload for invitation.resend
type InvitationResendRequest struct {
	InvitationID   string `json:"invitation_id"`
	ExpiresInHours int    `json:"expires_in_hours,omitempty"`
}

// InvitationResendResponse is the response for invitation.resend
type InvitationResendResponse struct {
	Success         bool   `json:"success"`
	NewInvitationID string `json:"new_invitation_id"`
	ExpiresAt       string `json:"expires_at"`
}

// InvitationViewedRequest is the payload for invitation.viewed
type InvitationViewedRequest struct {
	InvitationID string `json:"invitation_id"`
}

// --- Handler methods ---

// HandleList handles invitation.list messages
func (h *InvitationsHandler) HandleList(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req InvitationListRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		// Allow empty payload for list all
		req = InvitationListRequest{}
	}

	// Get invitation index
	indexData, err := h.storage.Get("invitations/_index")
	var invitationIDs []string
	if err == nil {
		json.Unmarshal(indexData, &invitationIDs)
	}

	invitations := make([]InvitationInfo, 0)
	for _, invID := range invitationIDs {
		data, err := h.storage.Get("invitations/" + invID)
		if err != nil {
			continue
		}

		var record InvitationRecord
		if json.Unmarshal(data, &record) != nil {
			continue
		}

		// Check if expired and update status
		if record.Status == "pending" && time.Now().After(record.ExpiresAt) {
			record.Status = "expired"
			// Update in storage
			newData, _ := json.Marshal(record)
			h.storage.Put("invitations/"+invID, newData)
		}

		// Filter by status if specified
		if req.Status != "" && record.Status != req.Status {
			continue
		}

		info := InvitationInfo{
			InvitationID:   record.InvitationID,
			ConnectionID:   record.ConnectionID,
			Status:         record.Status,
			DeliveryMethod: record.DeliveryMethod,
			Label:          record.Label,
			CreatedAt:      record.CreatedAt.Format(time.RFC3339),
			ExpiresAt:      record.ExpiresAt.Format(time.RFC3339),
		}

		if record.ViewedAt != nil {
			info.ViewedAt = record.ViewedAt.Format(time.RFC3339)
		}
		if record.RespondedAt != nil {
			info.RespondedAt = record.RespondedAt.Format(time.RFC3339)
		}

		invitations = append(invitations, info)
	}

	// Apply pagination
	total := len(invitations)
	if req.Offset > 0 && req.Offset < len(invitations) {
		invitations = invitations[req.Offset:]
	} else if req.Offset >= len(invitations) {
		invitations = []InvitationInfo{}
	}
	if req.Limit > 0 && req.Limit < len(invitations) {
		invitations = invitations[:req.Limit]
	}

	resp := InvitationListResponse{
		Invitations: invitations,
		Total:       total,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleCancel handles invitation.cancel messages
func (h *InvitationsHandler) HandleCancel(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req InvitationCancelRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.InvitationID == "" {
		return h.errorResponse(msg.GetID(), "invitation_id is required")
	}

	storageKey := "invitations/" + req.InvitationID
	data, err := h.storage.Get(storageKey)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Invitation not found")
	}

	var record InvitationRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to read invitation")
	}

	if record.Status != "pending" {
		return h.errorResponse(msg.GetID(), "Can only cancel pending invitations")
	}

	// Update invitation status
	record.Status = "cancelled"
	now := time.Now()
	record.RespondedAt = &now

	newData, _ := json.Marshal(record)
	if err := h.storage.Put(storageKey, newData); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to cancel invitation")
	}

	// Update associated connection status if exists
	if record.ConnectionID != "" {
		connData, err := h.storage.Get("connections/" + record.ConnectionID)
		if err == nil {
			var connRecord map[string]interface{}
			if json.Unmarshal(connData, &connRecord) == nil {
				connRecord["status"] = "cancelled"
				newConnData, _ := json.Marshal(connRecord)
				h.storage.Put("connections/"+record.ConnectionID, newConnData)
			}
		}
	}

	log.Info().Str("invitation_id", req.InvitationID).Msg("Invitation cancelled")

	resp := map[string]interface{}{
		"success":       true,
		"invitation_id": req.InvitationID,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleResend handles invitation.resend messages
func (h *InvitationsHandler) HandleResend(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req InvitationResendRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.InvitationID == "" {
		return h.errorResponse(msg.GetID(), "invitation_id is required")
	}

	// Get original invitation
	data, err := h.storage.Get("invitations/" + req.InvitationID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Invitation not found")
	}

	var oldRecord InvitationRecord
	if err := json.Unmarshal(data, &oldRecord); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to read invitation")
	}

	// Mark old invitation as superseded
	oldRecord.Status = "cancelled"
	oldData, _ := json.Marshal(oldRecord)
	h.storage.Put("invitations/"+req.InvitationID, oldData)

	// Create new invitation
	expiresInHours := req.ExpiresInHours
	if expiresInHours <= 0 {
		expiresInHours = 24 * 7 // Default 7 days
	}

	newInvitationID := h.generateInvitationID()
	newRecord := InvitationRecord{
		InvitationID:   newInvitationID,
		ConnectionID:   oldRecord.ConnectionID,
		Status:         "pending",
		DeliveryMethod: oldRecord.DeliveryMethod,
		Label:          oldRecord.Label,
		CreatedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(time.Duration(expiresInHours) * time.Hour),
	}

	newData, err := json.Marshal(newRecord)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to create new invitation")
	}

	if err := h.storage.Put("invitations/"+newInvitationID, newData); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to store new invitation")
	}

	// Add to index
	h.addToInvitationIndex(newInvitationID)

	log.Info().
		Str("old_invitation_id", req.InvitationID).
		Str("new_invitation_id", newInvitationID).
		Msg("Invitation resent")

	resp := InvitationResendResponse{
		Success:         true,
		NewInvitationID: newInvitationID,
		ExpiresAt:       newRecord.ExpiresAt.Format(time.RFC3339),
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleViewed handles invitation.viewed messages
func (h *InvitationsHandler) HandleViewed(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req InvitationViewedRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.InvitationID == "" {
		return h.errorResponse(msg.GetID(), "invitation_id is required")
	}

	storageKey := "invitations/" + req.InvitationID
	data, err := h.storage.Get(storageKey)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Invitation not found")
	}

	var record InvitationRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return h.errorResponse(msg.GetID(), "Failed to read invitation")
	}

	// Only update if not already viewed
	if record.ViewedAt == nil {
		now := time.Now()
		record.ViewedAt = &now

		newData, _ := json.Marshal(record)
		if err := h.storage.Put(storageKey, newData); err != nil {
			return h.errorResponse(msg.GetID(), "Failed to update invitation")
		}

		log.Info().Str("invitation_id", req.InvitationID).Msg("Invitation marked as viewed")
	}

	resp := map[string]interface{}{
		"success":       true,
		"invitation_id": req.InvitationID,
		"viewed_at":     record.ViewedAt.Format(time.RFC3339),
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// CreateInvitation creates a new invitation record (called when connection.create-invite is used)
func (h *InvitationsHandler) CreateInvitation(connectionID string, label string, expiresAt time.Time, deliveryMethod string) (string, error) {
	invitationID := h.generateInvitationID()

	record := InvitationRecord{
		InvitationID:   invitationID,
		ConnectionID:   connectionID,
		Status:         "pending",
		DeliveryMethod: deliveryMethod,
		Label:          label,
		CreatedAt:      time.Now(),
		ExpiresAt:      expiresAt,
	}

	data, err := json.Marshal(record)
	if err != nil {
		return "", fmt.Errorf("failed to marshal invitation: %w", err)
	}

	if err := h.storage.Put("invitations/"+invitationID, data); err != nil {
		return "", fmt.Errorf("failed to store invitation: %w", err)
	}

	h.addToInvitationIndex(invitationID)

	log.Info().
		Str("invitation_id", invitationID).
		Str("connection_id", connectionID).
		Msg("Invitation created")

	return invitationID, nil
}

// MarkInvitationAccepted marks an invitation as accepted
func (h *InvitationsHandler) MarkInvitationAccepted(invitationID string) error {
	storageKey := "invitations/" + invitationID
	data, err := h.storage.Get(storageKey)
	if err != nil {
		return fmt.Errorf("invitation not found: %s", invitationID)
	}

	var record InvitationRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return fmt.Errorf("failed to read invitation: %w", err)
	}

	record.Status = "accepted"
	now := time.Now()
	record.RespondedAt = &now

	newData, _ := json.Marshal(record)
	if err := h.storage.Put(storageKey, newData); err != nil {
		return fmt.Errorf("failed to update invitation: %w", err)
	}

	return nil
}

// --- Helper methods ---

func (h *InvitationsHandler) generateInvitationID() string {
	idBytes := make([]byte, 16)
	rand.Read(idBytes)
	return fmt.Sprintf("inv-%x", idBytes)
}

func (h *InvitationsHandler) addToInvitationIndex(invitationID string) {
	var index []string
	indexData, err := h.storage.Get("invitations/_index")
	if err == nil {
		json.Unmarshal(indexData, &index)
	}

	// Check if already in index
	for _, id := range index {
		if id == invitationID {
			return
		}
	}

	index = append(index, invitationID)
	newIndexData, _ := json.Marshal(index)
	h.storage.Put("invitations/_index", newIndexData)
}

func (h *InvitationsHandler) errorResponse(id string, message string) (*OutgoingMessage, error) {
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
