package main

import (
	"encoding/json"
	"time"

	"github.com/rs/zerolog/log"
)

// AuditTransferHandler exposes audit events filtered by resource_id.
//
// Use case: data subjects (patients) requesting access history for their own
// records — "who accessed my MRN-12345?"
//
// Operator audit is unconditional (HIPAA compliance — all credential proxy
// operations are logged regardless). This handler exposes a *filtered read*
// path for data subjects to see who accessed records about them.
//
// In production, the recipient (a patient's user vault) would receive these
// events over a service vault connection, encrypted with their connection key.
// In the demo, the demo service queries this directly and renders the events
// in the Patient View panel.
type AuditTransferHandler struct {
	ownerSpace string
	storage    *EncryptedStorage
}

// NewAuditTransferHandler creates a new audit transfer handler.
func NewAuditTransferHandler(ownerSpace string, storage *EncryptedStorage) *AuditTransferHandler {
	return &AuditTransferHandler{
		ownerSpace: ownerSpace,
		storage:    storage,
	}
}

// AuditTransferRequest is the request body for audit.transfer.
type AuditTransferRequest struct {
	ResourceID string `json:"resource_id"`          // e.g., "MRN-12345"
	MaxEvents  int    `json:"max_events,omitempty"` // Default 100, max 500
}

// AuditTransferResponse is the response for audit.transfer.
type AuditTransferResponse struct {
	Success    bool            `json:"success"`
	ResourceID string          `json:"resource_id"`
	Events     []OrgAuditEvent `json:"events"`
	Count      int             `json:"count"`
	OrgVaultID string          `json:"org_vault_id"`
	QueriedAt  int64           `json:"queried_at"`
	Error      string          `json:"error,omitempty"`
}

// HandleTransfer answers a "who accessed my record?" query by filtering
// audit events by resource_id. Returns events newest-first.
func (h *AuditTransferHandler) HandleTransfer(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req AuditTransferRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return errorResponse(msg.GetID(), "invalid request: "+err.Error())
	}
	if req.ResourceID == "" {
		return errorResponse(msg.GetID(), "resource_id is required")
	}
	if req.MaxEvents <= 0 || req.MaxEvents > 500 {
		req.MaxEvents = 100
	}

	ids, err := h.storage.GetIndex(KeyAuditIndex)
	if err != nil {
		return errorResponse(msg.GetID(), "failed to read audit index: "+err.Error())
	}

	// Read newest-first by walking the index in reverse
	matched := make([]OrgAuditEvent, 0)
	for i := len(ids) - 1; i >= 0 && len(matched) < req.MaxEvents; i-- {
		var event OrgAuditEvent
		if err := h.storage.GetJSON(KeyAuditPrefix+ids[i], &event); err != nil {
			continue
		}
		if event.ResourceID == req.ResourceID {
			matched = append(matched, event)
		}
	}

	log.Info().
		Str("resource_id", req.ResourceID).
		Int("matched", len(matched)).
		Msg("Audit transfer query")

	return successResponse(msg.GetID(), AuditTransferResponse{
		Success:    true,
		ResourceID: req.ResourceID,
		Events:     matched,
		Count:      len(matched),
		OrgVaultID: h.ownerSpace,
		QueriedAt:  time.Now().UnixMilli(),
	})
}
