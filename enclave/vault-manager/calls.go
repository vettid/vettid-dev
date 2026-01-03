package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
)

// CallEventType represents the type of call event
type CallEventType string

const (
	CallEventInitiate  CallEventType = "initiate"   // Incoming call request
	CallEventAccept    CallEventType = "accept"     // Call accepted
	CallEventReject    CallEventType = "reject"     // Call rejected by user
	CallEventCancel    CallEventType = "cancel"     // Call cancelled by caller
	CallEventEnd       CallEventType = "end"        // Call ended
	CallEventOffer     CallEventType = "offer"      // WebRTC offer
	CallEventAnswer    CallEventType = "answer"     // WebRTC answer
	CallEventCandidate CallEventType = "candidate"  // ICE candidate
	CallEventBusy      CallEventType = "busy"       // User is busy
	CallEventBlocked   CallEventType = "blocked"    // Caller is blocked
)

// CallEvent represents a call signaling event
type CallEvent struct {
	EventID     string            `json:"event_id"`
	EventType   CallEventType     `json:"event_type"`
	CallerID    string            `json:"caller_id"`              // OwnerSpace of caller
	CalleeID    string            `json:"callee_id"`              // OwnerSpace of callee
	CallID      string            `json:"call_id"`                // Unique call identifier
	Payload     json.RawMessage   `json:"payload,omitempty"`      // WebRTC SDP/ICE data
	Timestamp   int64             `json:"timestamp"`
	Signature   []byte            `json:"signature,omitempty"`    // Caller's signature
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// CallRecord is stored in JetStream for call history
type CallRecord struct {
	CallID       string        `json:"call_id"`
	CallerID     string        `json:"caller_id"`
	CalleeID     string        `json:"callee_id"`
	Direction    string        `json:"direction"` // "incoming" or "outgoing"
	Status       string        `json:"status"`    // "initiated", "answered", "missed", "rejected", "blocked"
	StartedAt    int64         `json:"started_at"`
	AnsweredAt   int64         `json:"answered_at,omitempty"`
	EndedAt      int64         `json:"ended_at,omitempty"`
	DurationSecs int           `json:"duration_secs,omitempty"`
	BlockReason  string        `json:"block_reason,omitempty"`
}

// BlockListEntry represents a blocked caller
type BlockListEntry struct {
	BlockedID   string `json:"blocked_id"`   // OwnerSpace of blocked user
	BlockedAt   int64  `json:"blocked_at"`
	Reason      string `json:"reason,omitempty"`
	ExpiresAt   int64  `json:"expires_at,omitempty"` // 0 = permanent
}

// CallHandler manages call signaling for a vault
type CallHandler struct {
	ownerSpace string
	storage    *EncryptedStorage
	blockList  map[string]*BlockListEntry // In-memory cache
	publisher  CallPublisher              // Interface to publish responses
}

// CallPublisher interface for sending call events
type CallPublisher interface {
	// PublishToApp sends event to owner's app (forApp channel)
	PublishToApp(ctx context.Context, eventType string, payload []byte) error
	// PublishToVault sends event to another vault (forVault channel)
	PublishToVault(ctx context.Context, targetOwnerSpace string, eventType string, payload []byte) error
}

// NewCallHandler creates a new call handler
func NewCallHandler(ownerSpace string, storage *EncryptedStorage, publisher CallPublisher) *CallHandler {
	return &CallHandler{
		ownerSpace: ownerSpace,
		storage:    storage,
		blockList:  make(map[string]*BlockListEntry),
		publisher:  publisher,
	}
}

// LoadBlockList loads the block list from storage
func (ch *CallHandler) LoadBlockList(ctx context.Context) error {
	data, err := ch.storage.Get("blocklist")
	if err != nil {
		// If not found, start with empty list
		log.Debug().Msg("No existing block list found, starting fresh")
		return nil
	}

	var entries []BlockListEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("failed to unmarshal block list: %w", err)
	}

	now := time.Now().Unix()
	for _, entry := range entries {
		// Skip expired blocks
		if entry.ExpiresAt > 0 && entry.ExpiresAt < now {
			continue
		}
		ch.blockList[entry.BlockedID] = &entry
	}

	log.Info().Int("count", len(ch.blockList)).Msg("Loaded block list")
	return nil
}

// SaveBlockList persists the block list to storage
func (ch *CallHandler) SaveBlockList(ctx context.Context) error {
	entries := make([]BlockListEntry, 0, len(ch.blockList))
	for _, entry := range ch.blockList {
		entries = append(entries, *entry)
	}

	data, err := json.Marshal(entries)
	if err != nil {
		return fmt.Errorf("failed to marshal block list: %w", err)
	}

	return ch.storage.Put("blocklist", data)
}

// IsBlocked checks if a caller is blocked
func (ch *CallHandler) IsBlocked(callerID string) (bool, string) {
	entry, exists := ch.blockList[callerID]
	if !exists {
		return false, ""
	}

	// Check if block has expired
	if entry.ExpiresAt > 0 && entry.ExpiresAt < time.Now().Unix() {
		delete(ch.blockList, callerID)
		return false, ""
	}

	return true, entry.Reason
}

// BlockCaller adds a caller to the block list
func (ch *CallHandler) BlockCaller(ctx context.Context, callerID string, reason string, durationSecs int64) error {
	entry := &BlockListEntry{
		BlockedID: callerID,
		BlockedAt: time.Now().Unix(),
		Reason:    reason,
	}
	if durationSecs > 0 {
		entry.ExpiresAt = entry.BlockedAt + durationSecs
	}

	ch.blockList[callerID] = entry

	if err := ch.SaveBlockList(ctx); err != nil {
		return fmt.Errorf("failed to save block list: %w", err)
	}

	log.Info().
		Str("blocked_id", callerID).
		Str("reason", reason).
		Int64("duration_secs", durationSecs).
		Msg("Caller blocked")

	return nil
}

// UnblockCaller removes a caller from the block list
func (ch *CallHandler) UnblockCaller(ctx context.Context, callerID string) error {
	delete(ch.blockList, callerID)

	if err := ch.SaveBlockList(ctx); err != nil {
		return fmt.Errorf("failed to save block list: %w", err)
	}

	log.Info().Str("unblocked_id", callerID).Msg("Caller unblocked")
	return nil
}

// HandleCallEvent processes an incoming call event
func (ch *CallHandler) HandleCallEvent(ctx context.Context, event *CallEvent) error {
	log.Debug().
		Str("event_type", string(event.EventType)).
		Str("call_id", event.CallID).
		Str("caller_id", event.CallerID).
		Msg("Processing call event")

	switch event.EventType {
	case CallEventInitiate:
		return ch.handleCallInitiate(ctx, event)
	case CallEventOffer, CallEventAnswer, CallEventCandidate:
		return ch.handleCallSignaling(ctx, event)
	case CallEventAccept:
		return ch.handleCallAccept(ctx, event)
	case CallEventReject:
		return ch.handleCallReject(ctx, event)
	case CallEventCancel:
		return ch.handleCallCancel(ctx, event)
	case CallEventEnd:
		return ch.handleCallEnd(ctx, event)
	default:
		return fmt.Errorf("unknown call event type: %s", event.EventType)
	}
}

// handleCallInitiate processes an incoming call request
func (ch *CallHandler) handleCallInitiate(ctx context.Context, event *CallEvent) error {
	// 1. Check block list
	if blocked, reason := ch.IsBlocked(event.CallerID); blocked {
		log.Info().
			Str("caller_id", event.CallerID).
			Str("reason", reason).
			Msg("Call blocked")

		// Log blocked call
		record := &CallRecord{
			CallID:      event.CallID,
			CallerID:    event.CallerID,
			CalleeID:    ch.ownerSpace,
			Direction:   "incoming",
			Status:      "blocked",
			StartedAt:   event.Timestamp,
			EndedAt:     time.Now().Unix(),
			BlockReason: reason,
		}
		if err := ch.storeCallRecord(ctx, record); err != nil {
			log.Error().Err(err).Msg("Failed to store blocked call record")
		}

		// Notify caller they are blocked
		blockedEvent := &CallEvent{
			EventID:   generateEventID(),
			EventType: CallEventBlocked,
			CallerID:  ch.ownerSpace,
			CalleeID:  event.CallerID,
			CallID:    event.CallID,
			Timestamp: time.Now().Unix(),
		}
		return ch.publishCallEventToVault(ctx, event.CallerID, blockedEvent)
	}

	// 2. Log incoming call to JetStream
	record := &CallRecord{
		CallID:    event.CallID,
		CallerID:  event.CallerID,
		CalleeID:  ch.ownerSpace,
		Direction: "incoming",
		Status:    "initiated",
		StartedAt: event.Timestamp,
	}
	if err := ch.storeCallRecord(ctx, record); err != nil {
		log.Error().Err(err).Msg("Failed to store call record")
	}

	// 3. Forward to owner's app
	log.Info().
		Str("caller_id", event.CallerID).
		Str("call_id", event.CallID).
		Msg("Forwarding incoming call to app")

	eventData, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal call event: %w", err)
	}

	return ch.publisher.PublishToApp(ctx, "call.incoming", eventData)
}

// handleCallSignaling forwards WebRTC signaling (offer/answer/ICE)
func (ch *CallHandler) handleCallSignaling(ctx context.Context, event *CallEvent) error {
	// Signaling goes through without block list check (call already established)
	// But we still log it for debugging
	log.Debug().
		Str("event_type", string(event.EventType)).
		Str("call_id", event.CallID).
		Msg("Forwarding signaling event")

	eventData, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal signaling event: %w", err)
	}

	return ch.publisher.PublishToApp(ctx, fmt.Sprintf("call.%s", event.EventType), eventData)
}

// handleCallAccept processes call acceptance
func (ch *CallHandler) handleCallAccept(ctx context.Context, event *CallEvent) error {
	// Update call record
	if err := ch.updateCallRecord(ctx, event.CallID, func(r *CallRecord) {
		r.Status = "answered"
		r.AnsweredAt = time.Now().Unix()
	}); err != nil {
		log.Error().Err(err).Msg("Failed to update call record")
	}

	log.Info().Str("call_id", event.CallID).Msg("Call accepted")

	eventData, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal accept event: %w", err)
	}

	return ch.publisher.PublishToApp(ctx, "call.accepted", eventData)
}

// handleCallReject processes call rejection
func (ch *CallHandler) handleCallReject(ctx context.Context, event *CallEvent) error {
	// Update call record
	if err := ch.updateCallRecord(ctx, event.CallID, func(r *CallRecord) {
		r.Status = "rejected"
		r.EndedAt = time.Now().Unix()
	}); err != nil {
		log.Error().Err(err).Msg("Failed to update call record")
	}

	log.Info().Str("call_id", event.CallID).Msg("Call rejected")

	// Notify caller
	rejectEvent := &CallEvent{
		EventID:   generateEventID(),
		EventType: CallEventReject,
		CallerID:  ch.ownerSpace,
		CalleeID:  event.CallerID,
		CallID:    event.CallID,
		Timestamp: time.Now().Unix(),
	}
	return ch.publishCallEventToVault(ctx, event.CallerID, rejectEvent)
}

// handleCallCancel processes call cancellation (caller hung up before answer)
func (ch *CallHandler) handleCallCancel(ctx context.Context, event *CallEvent) error {
	// Update call record
	if err := ch.updateCallRecord(ctx, event.CallID, func(r *CallRecord) {
		r.Status = "missed"
		r.EndedAt = time.Now().Unix()
	}); err != nil {
		log.Error().Err(err).Msg("Failed to update call record")
	}

	log.Info().Str("call_id", event.CallID).Msg("Call cancelled")

	eventData, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal cancel event: %w", err)
	}

	return ch.publisher.PublishToApp(ctx, "call.cancelled", eventData)
}

// handleCallEnd processes call termination
func (ch *CallHandler) handleCallEnd(ctx context.Context, event *CallEvent) error {
	// Update call record with duration
	if err := ch.updateCallRecord(ctx, event.CallID, func(r *CallRecord) {
		r.EndedAt = time.Now().Unix()
		if r.AnsweredAt > 0 {
			r.DurationSecs = int(r.EndedAt - r.AnsweredAt)
		}
	}); err != nil {
		log.Error().Err(err).Msg("Failed to update call record")
	}

	log.Info().Str("call_id", event.CallID).Msg("Call ended")

	eventData, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal end event: %w", err)
	}

	return ch.publisher.PublishToApp(ctx, "call.ended", eventData)
}

// publishCallEventToVault sends a call event to another vault
func (ch *CallHandler) publishCallEventToVault(ctx context.Context, targetOwnerSpace string, event *CallEvent) error {
	eventData, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal call event: %w", err)
	}

	return ch.publisher.PublishToVault(ctx, targetOwnerSpace, fmt.Sprintf("call.%s", event.EventType), eventData)
}

// storeCallRecord stores a call record to JetStream
func (ch *CallHandler) storeCallRecord(ctx context.Context, record *CallRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal call record: %w", err)
	}

	key := fmt.Sprintf("calls/%s", record.CallID)
	return ch.storage.Put(key, data)
}

// updateCallRecord updates an existing call record
func (ch *CallHandler) updateCallRecord(ctx context.Context, callID string, updateFn func(*CallRecord)) error {
	key := fmt.Sprintf("calls/%s", callID)

	data, err := ch.storage.Get(key)
	if err != nil {
		return fmt.Errorf("failed to get call record: %w", err)
	}

	var record CallRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return fmt.Errorf("failed to unmarshal call record: %w", err)
	}

	updateFn(&record)

	newData, err := json.Marshal(&record)
	if err != nil {
		return fmt.Errorf("failed to marshal updated call record: %w", err)
	}

	return ch.storage.Put(key, newData)
}

// GetCallHistory returns recent call records
func (ch *CallHandler) GetCallHistory(ctx context.Context, limit int) ([]*CallRecord, error) {
	// For now, this is a placeholder - in production, use JetStream's
	// consumer with proper filtering and pagination
	// TODO: Implement proper JetStream query
	return nil, nil
}

// Helper functions

func generateEventID() string {
	// TODO: Use crypto/rand for production
	return fmt.Sprintf("evt-%d", time.Now().UnixNano())
}
