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

// ProfileUpdateNotification is sent to peers on profile changes.
//
// Legacy format carried only the selected fields via `Fields`. Current
// senders also populate `Profile` with a full PublishedProfileToMap
// snapshot so recipients can REPLACE their cached `_peer_profile` —
// this is how wallets and newly-added fields propagate to peers after
// a connection is already established. Older vaults that only know
// `Fields` still work; they just miss wallets/new-field changes until
// they upgrade.
type ProfileUpdateNotification struct {
	Fields    map[string]ProfileFieldValue `json:"fields"`
	UpdatedAt string                       `json:"updated_at"`
	// Full published-profile snapshot in the same map shape used for
	// `connections/<id>/_peer_profile`. Present on vault 2026-04-19+.
	Profile map[string]interface{} `json:"profile,omitempty"`
	// Sender's ownerSpace. Recipient looks up the connection record by
	// PeerGUID to know which cached _peer_profile to replace (the
	// sender's connection_id is useless — each vault has its own).
	FromOwnerSpace string `json:"from_owner_space,omitempty"`
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
	EventID        string                 `json:"event_id,omitempty"` // For replay prevention
	ConnectionID   string                 `json:"connection_id"`      // Legacy; senders don't set it (the sender's id wouldn't match ours)
	Fields         map[string]string      `json:"fields"`
	Profile        map[string]interface{} `json:"profile,omitempty"`
	FromOwnerSpace string                 `json:"from_owner_space,omitempty"`
	UpdatedAt      string                 `json:"updated_at"`
}

// IncomingRevocationNotification is received from peers
type IncomingRevocationNotification struct {
	EventID      string `json:"event_id,omitempty"` // For replay prevention
	ConnectionID string `json:"connection_id"`
	RevokedAt    string `json:"revoked_at"`
	Reason       string `json:"reason,omitempty"`
}

// --- Handler methods ---

// HandleProfileBroadcast broadcasts the current published profile to all
// active inbound connections. See BroadcastPublishedProfile for the shared
// helper — profile.publish and wallet.set-visibility call it directly so
// peers always get the latest snapshot without requiring an explicit
// broadcast RPC.
func (h *NotificationsHandler) HandleProfileBroadcast(msg *IncomingMessage) (*OutgoingMessage, error) {
	now := time.Now().UTC()
	total, success, failed := BroadcastPublishedProfile(
		context.Background(),
		h.ownerSpace,
		h.storage,
		h.publisher,
		nil, // vaultState optional; BuildPublishedProfile falls back to storage for the identity key
	)

	resp := ProfileBroadcastResponse{
		Success:          len(failed) == 0,
		ConnectionsCount: total,
		SuccessCount:     success,
		FailedConnIDs:    failed,
		BroadcastAt:      now.Format(time.RFC3339),
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// BroadcastPublishedProfile sends the owner's current published profile
// snapshot to every active inbound peer. Called by profile.publish,
// wallet.set-visibility, and the profile.broadcast RPC. Returns
// (totalPeers, successCount, failedConnectionIDs).
func BroadcastPublishedProfile(
	ctx context.Context,
	ownerSpace string,
	storage *EncryptedStorage,
	publisher *VsockPublisher,
	vaultState *VaultState,
) (int, int, []string) {
	if publisher == nil || storage == nil {
		return 0, 0, nil
	}

	profile := BuildPublishedProfile(ownerSpace, storage, vaultState)
	profileMap := PublishedProfileToMap(profile)

	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339)

	// Populate the legacy Fields map so older peer code still gets partial
	// field updates from the same notification.
	legacyFields := make(map[string]ProfileFieldValue, len(profile.Fields))
	for name, field := range profile.Fields {
		legacyFields[name] = ProfileFieldValue{Value: field.Value, UpdatedAt: nowStr}
	}

	update := ProfileUpdateNotification{
		Fields:         legacyFields,
		UpdatedAt:      nowStr,
		Profile:        profileMap,
		FromOwnerSpace: ownerSpace,
	}
	updateData, err := json.Marshal(update)
	if err != nil {
		log.Warn().Err(err).Str("owner_space", ownerSpace).Msg("Failed to marshal profile broadcast")
		return 0, 0, nil
	}

	indexData, err := storage.Get("connections/_index")
	var connectionIDs []string
	if err == nil {
		json.Unmarshal(indexData, &connectionIDs)
	}

	total := 0
	success := 0
	var failed []string
	for _, connID := range connectionIDs {
		data, err := storage.Get("connections/" + connID)
		if err != nil {
			continue
		}
		var conn ConnectionRecord
		if json.Unmarshal(data, &conn) != nil {
			continue
		}
		if conn.Status != "active" || conn.CredentialsType != "inbound" {
			continue
		}
		total++
		if err := publisher.PublishToVault(ctx, conn.PeerGUID, "profile-update", updateData); err != nil {
			log.Warn().Err(err).Str("connection_id", connID).Msg("Failed to broadcast profile update")
			failed = append(failed, connID)
		} else {
			success++
		}
	}

	log.Info().
		Str("owner_space", ownerSpace).
		Int("total", total).
		Int("success", success).
		Int("failed", len(failed)).
		Int("wallet_count", len(profile.Wallets)).
		Int("field_count", len(profile.Fields)).
		Msg("Broadcast published profile to peers")

	return total, success, failed
}

// HandleRevokeNotify sends a revocation notice to the peer before revoking
func (h *NotificationsHandler) HandleRevokeNotify(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req RevokeNotifyRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleRevokeNotify"); err != nil {
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

// HandleIncomingProfileUpdate processes a profile update from a peer vault.
// When the payload carries a full `profile` snapshot (senders on vault
// 2026-04-19+), the cached `connections/<id>/_peer_profile` is replaced so
// the Connection Detail screen and the public-profile preview stay in sync
// with the peer's latest wallets/fields. Legacy payloads (fields-only) are
// still forwarded to the app as before.
func (h *NotificationsHandler) HandleIncomingProfileUpdate(ctx context.Context, data []byte) error {
	var update IncomingProfileUpdateNotification
	if err := json.Unmarshal(data, &update); err != nil {
		return err
	}

	// SECURITY: Replay attack prevention. Use event_id if provided,
	// otherwise fall back to from_owner_space+updated_at (legacy used
	// connection_id but senders never set it).
	eventID := update.EventID
	if eventID == "" {
		peerKey := update.FromOwnerSpace
		if peerKey == "" {
			peerKey = update.ConnectionID
		}
		eventID = fmt.Sprintf("profile:%s:%s", peerKey, update.UpdatedAt)
	}
	if alreadyProcessed, err := h.storage.IsEventProcessed(eventID); err == nil && alreadyProcessed {
		log.Info().
			Str("from_owner_space", update.FromOwnerSpace).
			Msg("Duplicate profile update detected - ignoring replay")
		return nil
	}

	log.Debug().
		Str("from_owner_space", update.FromOwnerSpace).
		Int("fields", len(update.Fields)).
		Bool("has_snapshot", len(update.Profile) > 0).
		Msg("Received profile update from peer")

	// Refresh the cached peer profile when the sender included a full
	// snapshot. Look up the local connection record by PeerGUID — each
	// vault assigns its own connection_id so the sender's is useless.
	if len(update.Profile) > 0 && update.FromOwnerSpace != "" {
		if connID := h.FindConnectionByPeerGUID(update.FromOwnerSpace); connID != "" {
			profileBytes, err := json.Marshal(update.Profile)
			if err == nil {
				if err := h.storage.Put("connections/"+connID+"/_peer_profile", profileBytes); err != nil {
					log.Warn().Err(err).Str("connection_id", connID).Msg("Failed to update cached peer profile")
				} else {
					log.Info().
						Str("connection_id", connID).
						Str("from_owner_space", update.FromOwnerSpace).
						Msg("Cached peer profile refreshed from broadcast")
				}
			}
		} else {
			log.Debug().
				Str("from_owner_space", update.FromOwnerSpace).
				Msg("Profile update from unknown peer — skipping cache refresh")
		}
	}

	// SECURITY: Mark event as processed to prevent replay
	if err := h.storage.MarkEventProcessed(eventID, "profile_update"); err != nil {
		log.Warn().Err(err).Str("from_owner_space", update.FromOwnerSpace).Msg("Failed to mark update as processed")
	}

	// Notify app
	if err := h.publisher.PublishToApp(ctx, "profile-update", data); err != nil {
		log.Warn().Err(err).Msg("Failed to notify app of profile update")
	}

	return nil
}

// FindConnectionByPeerGUID scans the connection index for a record whose
// PeerGUID matches. Returns "" if no match. Exported so other handlers
// (e.g. BTC receive path) can resolve a local connection_id from a
// peer-identified inbound message without duplicating the scan.
func (h *NotificationsHandler) FindConnectionByPeerGUID(peerGUID string) string {
	indexData, err := h.storage.Get("connections/_index")
	if err != nil {
		return ""
	}
	var connectionIDs []string
	if json.Unmarshal(indexData, &connectionIDs) != nil {
		return ""
	}
	for _, connID := range connectionIDs {
		data, err := h.storage.Get("connections/" + connID)
		if err != nil {
			continue
		}
		var conn ConnectionRecord
		if json.Unmarshal(data, &conn) != nil {
			continue
		}
		if conn.PeerGUID == peerGUID {
			return connID
		}
	}
	return ""
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
