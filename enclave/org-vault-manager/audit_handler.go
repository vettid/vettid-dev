package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
)

// AuditHandler manages structured audit events for HIPAA-compliant logging.
// Events are:
// 1. Stored locally in the vault's encrypted storage (compliance retention)
// 2. Sent to the parent via MessageTypeAuditEvent (DynamoDB persistence + NATS streaming)
type AuditHandler struct {
	ownerSpace string
	storage    *EncryptedStorage
	sendFn     func(msg *OutgoingMessage) error
}

// NewAuditHandler creates a new audit handler.
func NewAuditHandler(ownerSpace string, storage *EncryptedStorage, sendFn func(msg *OutgoingMessage) error) *AuditHandler {
	return &AuditHandler{
		ownerSpace: ownerSpace,
		storage:    storage,
		sendFn:     sendFn,
	}
}

// EmitEvent creates and forwards a structured audit event.
// Returns the event ID for reference in responses.
func (ah *AuditHandler) EmitEvent(event *OrgAuditEvent) string {
	if event.EventID == "" {
		event.EventID = generateID()
	}
	if event.Timestamp == 0 {
		event.Timestamp = time.Now().UnixMilli()
	}
	if event.OrgVaultID == "" {
		event.OrgVaultID = ah.ownerSpace
	}

	// Store locally for compliance retention
	if err := ah.storage.PutJSON(KeyAuditPrefix+event.EventID, event); err != nil {
		log.Warn().Err(err).Str("event_id", event.EventID).Msg("Failed to store audit event locally")
	}
	// Best-effort index update (don't fail the operation if index update fails)
	ah.storage.AddToIndex(KeyAuditIndex, event.EventID)

	// Forward to parent for DynamoDB persistence + NATS real-time streaming
	eventBytes, err := json.Marshal(event)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal audit event")
		return event.EventID
	}

	auditMsg := &OutgoingMessage{
		Type:       MessageTypeAuditEvent,
		OwnerSpace: ah.ownerSpace,
		RequestID:  event.EventID,
		Payload:    eventBytes,
	}

	if err := ah.sendFn(auditMsg); err != nil {
		log.Warn().Err(err).Str("event_id", event.EventID).Msg("Failed to forward audit event to parent")
	}

	log.Info().
		Str("event_id", event.EventID).
		Str("action", event.Action).
		Str("operator", event.OperatorEmail).
		Str("outcome", event.Outcome).
		Str("resource", event.ResourceID).
		Str("purpose", event.Purpose).
		Msg("Audit event emitted")

	return event.EventID
}

// HashQuery produces a SHA-256 hash of a query string.
// The actual query is never stored in audit — only the hash for correlation.
func HashQuery(query string) string {
	h := sha256.Sum256([]byte(query))
	return hex.EncodeToString(h[:])
}

// --- Message Handlers ---

// HandleQuery returns audit events matching filter criteria.
func (ah *AuditHandler) HandleQuery(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		Limit         int    `json:"limit"`
		OperatorEmail string `json:"operator_email,omitempty"`
		Action        string `json:"action,omitempty"`
		Since         int64  `json:"since,omitempty"` // Unix milliseconds
	}

	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return errorResponse(msg.GetID(), "invalid request: "+err.Error())
	}

	if req.Limit <= 0 || req.Limit > 100 {
		req.Limit = 50
	}

	ids, err := ah.storage.GetIndex(KeyAuditIndex)
	if err != nil {
		return errorResponse(msg.GetID(), "failed to read audit index: "+err.Error())
	}

	var events []OrgAuditEvent
	// Read in reverse order (newest first)
	for i := len(ids) - 1; i >= 0 && len(events) < req.Limit; i-- {
		var event OrgAuditEvent
		if err := ah.storage.GetJSON(KeyAuditPrefix+ids[i], &event); err != nil {
			continue
		}

		// Apply filters
		if req.Since > 0 && event.Timestamp < req.Since {
			continue
		}
		if req.OperatorEmail != "" && event.OperatorEmail != req.OperatorEmail {
			continue
		}
		if req.Action != "" && event.Action != req.Action {
			continue
		}

		events = append(events, event)
	}

	return successResponse(msg.GetID(), map[string]interface{}{
		"success": true,
		"events":  events,
		"count":   len(events),
	})
}

// HandleExport returns all audit events (for compliance export).
func (ah *AuditHandler) HandleExport(msg *IncomingMessage) (*OutgoingMessage, error) {
	ids, err := ah.storage.GetIndex(KeyAuditIndex)
	if err != nil {
		return errorResponse(msg.GetID(), "failed to read audit index: "+err.Error())
	}

	var events []OrgAuditEvent
	for _, id := range ids {
		var event OrgAuditEvent
		if err := ah.storage.GetJSON(KeyAuditPrefix+id, &event); err != nil {
			continue
		}
		events = append(events, event)
	}

	return successResponse(msg.GetID(), map[string]interface{}{
		"success":      true,
		"events":       events,
		"count":        len(events),
		"org_vault_id": ah.ownerSpace,
		"exported_at":  time.Now().UnixMilli(),
	})
}

// EmitCredentialProxyEvent is a convenience method for the most common audit event type.
func (ah *AuditHandler) EmitCredentialProxyEvent(
	operator *OperatorConnection,
	req *ProxyQueryRequest,
	outcome string,
	durationMs int64,
	rowCount int,
) string {
	return ah.EmitEvent(&OrgAuditEvent{
		OperatorEmail:  operator.OperatorEmail,
		OperatorRole:   operator.OperatorRole,
		ConnectionID:   operator.ConnectionID,
		Action:         "credential_proxy_query",
		CredentialID:   req.CredentialID,
		ResourceType:   req.ResourceType,
		ResourceID:     req.ResourceID,
		Purpose:        req.Purpose,
		Outcome:        outcome,
		DurationMs:     durationMs,
		RowCount:       rowCount,
		QueryHash:      HashQuery(req.Query),
	})
}

// EmitConnectionEvent emits an audit event for connection lifecycle operations.
func (ah *AuditHandler) EmitConnectionEvent(action string, operator *OperatorConnection, outcome string) string {
	email := ""
	role := ""
	connID := ""
	if operator != nil {
		email = operator.OperatorEmail
		role = operator.OperatorRole
		connID = operator.ConnectionID
	}
	return ah.EmitEvent(&OrgAuditEvent{
		OperatorEmail: email,
		OperatorRole:  role,
		ConnectionID:  connID,
		Action:        action,
		Outcome:       outcome,
	})
}

// EmitCredentialEvent emits an audit event for credential management operations.
func (ah *AuditHandler) EmitCredentialEvent(action, credentialID, credentialType, outcome string) string {
	return ah.EmitEvent(&OrgAuditEvent{
		Action:         action,
		CredentialID:   credentialID,
		CredentialType: credentialType,
		Outcome:        outcome,
	})
}

// GetEventCount returns the total number of audit events.
func (ah *AuditHandler) GetEventCount() (int, error) {
	ids, err := ah.storage.GetIndex(KeyAuditIndex)
	if err != nil {
		return 0, fmt.Errorf("failed to read audit index: %w", err)
	}
	return len(ids), nil
}
