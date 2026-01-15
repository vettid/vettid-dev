package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
)

// NotificationsHandler handles broadcast notifications to connected peers.
type NotificationsHandler struct {
	ownerSpace string
	storage    *EncryptedStorage
	publisher  *VsockPublisher
}

// NewNotificationsHandler creates a new notifications handler
func NewNotificationsHandler(ownerSpace string, storage *EncryptedStorage, publisher *VsockPublisher) *NotificationsHandler {
	return &NotificationsHandler{
		ownerSpace: ownerSpace,
		storage:    storage,
		publisher:  publisher,
	}
}

// --- Request/Response types ---

// ProfileBroadcastRequest is the payload for profile.broadcast
type ProfileBroadcastRequest struct {
	Fields []string `json:"fields,omitempty"`
}

// ProfileBroadcastResponse is the response for profile.broadcast
type ProfileBroadcastResponse struct {
	Success          bool     `json:"success"`
	ConnectionsCount int      `json:"connections_count"`
	SuccessCount     int      `json:"success_count"`
	FailedConnIDs    []string `json:"failed_connection_ids,omitempty"`
	BroadcastAt      string   `json:"broadcast_at"`
}

// RevokeNotifyRequest is the payload for connection.notify-revoke
type RevokeNotifyRequest struct {
	ConnectionID string `json:"connection_id"`
}

// RevokeNotifyResponse is the response for connection.notify-revoke
type RevokeNotifyResponse struct {
	Success    bool   `json:"success"`
	NotifiedAt string `json:"notified_at,omitempty"`
	Error      string `json:"error,omitempty"`
}

// ProfileUpdateNotification is sent to peers on profile changes
type ProfileUpdateNotification struct {
	Fields    map[string]ProfileFieldValue `json:"fields"`
	UpdatedAt string                       `json:"updated_at"`
}

// ProfileFieldValue represents a field value in the notification
type ProfileFieldValue struct {
	Value     string `json:"value"`
	UpdatedAt string `json:"updated_at"`
}

// RevocationNotification is sent to a peer when connection is revoked
type RevocationNotification struct {
	ConnectionID string `json:"connection_id"`
	RevokedAt    string `json:"revoked_at"`
	Reason       string `json:"reason,omitempty"`
}

// IncomingProfileUpdateNotification is received from peers
type IncomingProfileUpdateNotification struct {
	EventID      string            `json:"event_id,omitempty"` // For replay prevention
	ConnectionID string            `json:"connection_id"`
	Fields       map[string]string `json:"fields"`
	UpdatedAt    string            `json:"updated_at"`
}

// IncomingRevocationNotification is received from peers
type IncomingRevocationNotification struct {
	EventID      string `json:"event_id,omitempty"` // For replay prevention
	ConnectionID string `json:"connection_id"`
	RevokedAt    string `json:"revoked_at"`
	Reason       string `json:"reason,omitempty"`
}

// --- Handler methods ---

// HandleProfileBroadcast broadcasts profile updates to all active connections
func (h *NotificationsHandler) HandleProfileBroadcast(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req ProfileBroadcastRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		// Allow empty payload to broadcast all fields
		req = ProfileBroadcastRequest{}
	}

	// Get profile index to find all fields
	var fieldNames []string
	if len(req.Fields) > 0 {
		fieldNames = req.Fields
	} else {
		indexData, err := h.storage.Get("profile/_index")
		if err == nil {
			json.Unmarshal(indexData, &fieldNames)
		}
	}

	if len(fieldNames) == 0 {
		return h.errorResponse(msg.GetID(), "No profile fields to broadcast")
	}

	// Get profile data
	fields := make(map[string]ProfileFieldValue)
	for _, field := range fieldNames {
		data, err := h.storage.Get("profile/" + field)
		if err != nil {
			continue
		}

		var entry ProfileEntry
		if json.Unmarshal(data, &entry) != nil {
			continue
		}

		fields[field] = ProfileFieldValue{
			Value:     entry.Value,
			UpdatedAt: entry.UpdatedAt.Format(time.RFC3339),
		}
	}

	if len(fields) == 0 {
		return h.errorResponse(msg.GetID(), "No profile fields to broadcast")
	}

	now := time.Now().UTC()
	update := ProfileUpdateNotification{
		Fields:    fields,
		UpdatedAt: now.Format(time.RFC3339),
	}
	updateData, _ := json.Marshal(update)

	// Get all active connections
	indexData, err := h.storage.Get("connections/_index")
	var connectionIDs []string
	if err == nil {
		json.Unmarshal(indexData, &connectionIDs)
	}

	successCount := 0
	var failedIDs []string
	inboundCount := 0

	for _, connID := range connectionIDs {
		data, err := h.storage.Get("connections/" + connID)
		if err != nil {
			continue
		}

		var conn ConnectionRecord
		if json.Unmarshal(data, &conn) != nil {
			continue
		}

		// Only broadcast to active inbound connections
		if conn.Status != "active" || conn.CredentialsType != "inbound" {
			continue
		}

		inboundCount++

		if err := h.publisher.PublishToVault(context.Background(), conn.PeerGUID, "profile-update", updateData); err != nil {
			log.Warn().Err(err).Str("connection_id", connID).Msg("Failed to broadcast profile update")
			failedIDs = append(failedIDs, connID)
		} else {
			successCount++
		}
	}

	log.Info().
		Int("total", inboundCount).
		Int("success", successCount).
		Int("failed", len(failedIDs)).
		Msg("Profile broadcast complete")

	resp := ProfileBroadcastResponse{
		Success:          len(failedIDs) == 0,
		ConnectionsCount: inboundCount,
		SuccessCount:     successCount,
		FailedConnIDs:    failedIDs,
		BroadcastAt:      now.Format(time.RFC3339),
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleRevokeNotify sends a revocation notice to the peer before revoking
func (h *NotificationsHandler) HandleRevokeNotify(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req RevokeNotifyRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	// Get connection
	data, err := h.storage.Get("connections/" + req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}

	var conn ConnectionRecord
	if json.Unmarshal(data, &conn) != nil {
		return h.errorResponse(msg.GetID(), "Invalid connection data")
	}

	now := time.Now().UTC()
	revokedAt := now.Format(time.RFC3339)

	// Send notice if we have peer credentials
	if conn.CredentialsType == "inbound" && conn.Credentials != "" {
		notice := RevocationNotification{
			ConnectionID: req.ConnectionID,
			RevokedAt:    revokedAt,
		}
		noticeData, _ := json.Marshal(notice)

		if err := h.publisher.PublishToVault(context.Background(), conn.PeerGUID, "revoked", noticeData); err != nil {
			log.Warn().Err(err).Str("connection_id", req.ConnectionID).Msg("Failed to send revocation notice")
		} else {
			log.Info().Str("connection_id", req.ConnectionID).Msg("Sent revocation notice to peer")
		}
	}

	// Revoke the connection locally
	conn.Status = "revoked"
	newData, _ := json.Marshal(conn)
	h.storage.Put("connections/"+req.ConnectionID, newData)

	resp := RevokeNotifyResponse{
		Success:    true,
		NotifiedAt: revokedAt,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleIncomingProfileUpdate processes a profile update from a peer vault
func (h *NotificationsHandler) HandleIncomingProfileUpdate(ctx context.Context, data []byte) error {
	var update IncomingProfileUpdateNotification
	if err := json.Unmarshal(data, &update); err != nil {
		return err
	}

	// SECURITY: Replay attack prevention
	// Use event_id if provided, otherwise fall back to connection_id+updated_at
	eventID := update.EventID
	if eventID == "" {
		eventID = fmt.Sprintf("profile:%s:%s", update.ConnectionID, update.UpdatedAt)
	}
	if alreadyProcessed, err := h.storage.IsEventProcessed(eventID); err == nil && alreadyProcessed {
		log.Info().
			Str("connection_id", update.ConnectionID).
			Msg("Duplicate profile update detected - ignoring replay")
		return nil
	}

	log.Debug().
		Str("connection_id", update.ConnectionID).
		Int("fields", len(update.Fields)).
		Msg("Received profile update from peer")

	// SECURITY: Mark event as processed to prevent replay
	if err := h.storage.MarkEventProcessed(eventID, "profile_update"); err != nil {
		log.Warn().Err(err).Str("connection_id", update.ConnectionID).Msg("Failed to mark update as processed")
	}

	// Notify app
	if err := h.publisher.PublishToApp(ctx, "profile-update", data); err != nil {
		log.Warn().Err(err).Msg("Failed to notify app of profile update")
	}

	return nil
}

// HandleIncomingRevocation processes a revocation notice from a peer vault
func (h *NotificationsHandler) HandleIncomingRevocation(ctx context.Context, data []byte) error {
	var revocation IncomingRevocationNotification
	if err := json.Unmarshal(data, &revocation); err != nil {
		return err
	}

	// SECURITY: Replay attack prevention
	// Use event_id if provided, otherwise fall back to connection_id+revoked_at
	eventID := revocation.EventID
	if eventID == "" {
		eventID = fmt.Sprintf("revoke:%s:%s", revocation.ConnectionID, revocation.RevokedAt)
	}
	if alreadyProcessed, err := h.storage.IsEventProcessed(eventID); err == nil && alreadyProcessed {
		log.Info().
			Str("connection_id", revocation.ConnectionID).
			Msg("Duplicate revocation notice detected - ignoring replay")
		return nil
	}

	log.Info().
		Str("connection_id", revocation.ConnectionID).
		Str("revoked_at", revocation.RevokedAt).
		Msg("Received revocation notice from peer")

	// Mark connection as revoked locally
	connData, err := h.storage.Get("connections/" + revocation.ConnectionID)
	if err == nil {
		var conn ConnectionRecord
		if json.Unmarshal(connData, &conn) == nil {
			conn.Status = "revoked"
			newData, _ := json.Marshal(conn)
			h.storage.Put("connections/"+revocation.ConnectionID, newData)
		}
	}

	// SECURITY: Mark event as processed to prevent replay
	if err := h.storage.MarkEventProcessed(eventID, "revocation"); err != nil {
		log.Warn().Err(err).Str("connection_id", revocation.ConnectionID).Msg("Failed to mark revocation as processed")
	}

	// Notify app
	if err := h.publisher.PublishToApp(ctx, "connection-revoked", data); err != nil {
		log.Warn().Err(err).Msg("Failed to notify app of revocation")
	}

	return nil
}

func (h *NotificationsHandler) errorResponse(id string, message string) (*OutgoingMessage, error) {
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
