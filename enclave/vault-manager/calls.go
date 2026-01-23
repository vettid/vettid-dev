package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"crypto/sha256"
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

// --- App Request/Response types ---

// InitiateCallRequest is sent by the app to start an outgoing call
type InitiateCallRequest struct {
	ConnectionID string            `json:"connection_id"`
	Metadata     map[string]string `json:"metadata,omitempty"` // e.g., call type: audio/video
}

// InitiateCallResponse is returned when a call is initiated
type InitiateCallResponse struct {
	CallID        string `json:"call_id"`
	Status        string `json:"status"`
	LocalKeyPub   string `json:"local_key_pub"`   // X25519 public key for E2EE (base64)
	InitiatedAt   string `json:"initiated_at"`
}

// AcceptCallRequest is sent by the app to accept an incoming call
type AcceptCallRequest struct {
	CallID string `json:"call_id"`
}

// AcceptCallResponse is returned when accepting a call
type AcceptCallResponse struct {
	CallID       string `json:"call_id"`
	Status       string `json:"status"`
	LocalKeyPub  string `json:"local_key_pub"`  // X25519 public key for E2EE (base64)
	SharedSecret string `json:"shared_secret"`  // Derived shared secret (base64) - only if peer key available
	AcceptedAt   string `json:"accepted_at"`
}

// RejectCallRequest is sent by the app to reject an incoming call
type RejectCallRequest struct {
	CallID string `json:"call_id"`
	Reason string `json:"reason,omitempty"`
}

// EndCallRequest is sent by the app to end a call
type EndCallRequest struct {
	CallID string `json:"call_id"`
}

// SendSignalingRequest is sent by the app to send WebRTC signaling data
type SendSignalingRequest struct {
	CallID      string          `json:"call_id"`
	SignalType  string          `json:"signal_type"` // "offer", "answer", "candidate"
	Payload     json.RawMessage `json:"payload"`     // WebRTC SDP or ICE candidate
	PeerKeyPub  string          `json:"peer_key_pub,omitempty"` // Peer's X25519 public key (base64)
}

// SendSignalingResponse is returned after sending signaling
type SendSignalingResponse struct {
	CallID       string `json:"call_id"`
	SignalType   string `json:"signal_type"`
	Sent         bool   `json:"sent"`
	SharedSecret string `json:"shared_secret,omitempty"` // Derived E2EE key if peer_key_pub provided
}

// GetCallHistoryRequest is sent by the app to retrieve call history
type GetCallHistoryRequest struct {
	Limit  int    `json:"limit,omitempty"`  // Default 50
	Before int64  `json:"before,omitempty"` // Unix timestamp for pagination
	Status string `json:"status,omitempty"` // Filter: "all", "missed", "answered"
}

// GetCallHistoryResponse contains call history
type GetCallHistoryResponse struct {
	Calls      []*CallRecord `json:"calls"`
	HasMore    bool          `json:"has_more"`
	OldestTime int64         `json:"oldest_time,omitempty"`
}

// ActiveCall tracks an in-progress call's cryptographic state
type ActiveCall struct {
	CallID        string    `json:"call_id"`
	PeerID        string    `json:"peer_id"`
	Direction     string    `json:"direction"` // "outgoing" or "incoming"
	LocalPrivKey  []byte    `json:"-"`         // X25519 private key (never serialized)
	LocalPubKey   []byte    `json:"local_pub_key"`
	PeerPubKey    []byte    `json:"peer_pub_key,omitempty"`
	SharedSecret  []byte    `json:"-"`         // Derived E2EE key (never serialized)
	Status        string    `json:"status"`
	StartedAt     time.Time `json:"started_at"`
}

// CallHandler manages call signaling for a vault
type CallHandler struct {
	ownerSpace   string
	storage      *EncryptedStorage
	blockList    map[string]*BlockListEntry // In-memory cache
	activeCalls  map[string]*ActiveCall     // In-memory active call state
	publisher    CallPublisher              // Interface to publish responses
	eventHandler *EventHandler              // For audit logging
}

// CallPublisher interface for sending call events
type CallPublisher interface {
	// PublishToApp sends event to owner's app (forApp channel)
	PublishToApp(ctx context.Context, eventType string, payload []byte) error
	// PublishToVault sends event to another vault (forVault channel)
	PublishToVault(ctx context.Context, targetOwnerSpace string, eventType string, payload []byte) error
}

// NewCallHandler creates a new call handler
func NewCallHandler(ownerSpace string, storage *EncryptedStorage, publisher CallPublisher, eventHandler *EventHandler) *CallHandler {
	return &CallHandler{
		ownerSpace:   ownerSpace,
		storage:      storage,
		blockList:    make(map[string]*BlockListEntry),
		activeCalls:  make(map[string]*ActiveCall),
		publisher:    publisher,
		eventHandler: eventHandler,
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

// --- App-initiated call methods ---

// HandleInitiateCall processes a call initiation request from the app
func (ch *CallHandler) HandleInitiateCall(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req InitiateCallRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return ch.errorResponse(msg.GetID(), "invalid request format")
	}

	if req.ConnectionID == "" {
		return ch.errorResponse(msg.GetID(), "connection_id is required")
	}

	// Verify connection exists and get peer info
	connData, err := ch.storage.Get("connections/" + req.ConnectionID)
	if err != nil {
		return ch.errorResponse(msg.GetID(), "connection not found")
	}

	var conn ConnectionRecord
	if err := json.Unmarshal(connData, &conn); err != nil {
		return ch.errorResponse(msg.GetID(), "invalid connection data")
	}

	if conn.Status != "active" {
		return ch.errorResponse(msg.GetID(), "connection is not active")
	}

	// Generate call ID and X25519 keypair for E2EE
	callID := fmt.Sprintf("call-%d", time.Now().UnixNano())
	localPrivKey, localPubKey, err := generateX25519KeyPair()
	if err != nil {
		return ch.errorResponse(msg.GetID(), "failed to generate encryption keys")
	}

	now := time.Now()

	// Store active call state
	activeCall := &ActiveCall{
		CallID:       callID,
		PeerID:       conn.PeerGUID,
		Direction:    "outgoing",
		LocalPrivKey: localPrivKey,
		LocalPubKey:  localPubKey,
		Status:       "initiating",
		StartedAt:    now,
	}
	ch.activeCalls[callID] = activeCall

	// Create call record
	record := &CallRecord{
		CallID:    callID,
		CallerID:  ch.ownerSpace,
		CalleeID:  conn.PeerGUID,
		Direction: "outgoing",
		Status:    "initiated",
		StartedAt: now.Unix(),
	}
	if err := ch.storeCallRecord(ctx, record); err != nil {
		log.Error().Err(err).Msg("Failed to store call record")
	}

	// Send initiate event to peer vault
	initiateEvent := &CallEvent{
		EventID:   generateEventID(),
		EventType: CallEventInitiate,
		CallerID:  ch.ownerSpace,
		CalleeID:  conn.PeerGUID,
		CallID:    callID,
		Timestamp: now.Unix(),
		Metadata:  req.Metadata,
		Payload:   json.RawMessage(fmt.Sprintf(`{"local_key_pub":"%s"}`, base64.StdEncoding.EncodeToString(localPubKey))),
	}

	if err := ch.publishCallEventToVault(ctx, conn.PeerGUID, initiateEvent); err != nil {
		// Clean up on failure
		delete(ch.activeCalls, callID)
		return ch.errorResponse(msg.GetID(), "failed to send call request")
	}

	log.Info().
		Str("call_id", callID).
		Str("peer", conn.PeerGUID).
		Msg("Outgoing call initiated")

	// Log event for audit
	if ch.eventHandler != nil {
		ch.eventHandler.LogCallEvent(ctx, EventTypeCallOutgoing, callID, conn.PeerGUID, "Outgoing call", map[string]string{
			"peer_alias": conn.PeerAlias,
		})
	}

	resp := InitiateCallResponse{
		CallID:      callID,
		Status:      "initiated",
		LocalKeyPub: base64.StdEncoding.EncodeToString(localPubKey),
		InitiatedAt: now.Format(time.RFC3339),
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleAcceptCall processes a call acceptance from the app
func (ch *CallHandler) HandleAcceptCall(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req AcceptCallRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return ch.errorResponse(msg.GetID(), "invalid request format")
	}

	if req.CallID == "" {
		return ch.errorResponse(msg.GetID(), "call_id is required")
	}

	// Get active call state (should have been created when we received the incoming call)
	activeCall, exists := ch.activeCalls[req.CallID]
	if !exists {
		return ch.errorResponse(msg.GetID(), "call not found or already ended")
	}

	// Generate our X25519 keypair if not already done
	if activeCall.LocalPrivKey == nil {
		localPrivKey, localPubKey, err := generateX25519KeyPair()
		if err != nil {
			return ch.errorResponse(msg.GetID(), "failed to generate encryption keys")
		}
		activeCall.LocalPrivKey = localPrivKey
		activeCall.LocalPubKey = localPubKey
	}

	now := time.Now()
	activeCall.Status = "answered"

	// Derive shared secret if we have peer's public key
	var sharedSecretB64 string
	if len(activeCall.PeerPubKey) > 0 {
		sharedSecret, err := deriveSharedSecret(activeCall.LocalPrivKey, activeCall.PeerPubKey, req.CallID)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to derive shared secret")
		} else {
			activeCall.SharedSecret = sharedSecret
			sharedSecretB64 = base64.StdEncoding.EncodeToString(sharedSecret)
		}
	}

	// Update call record
	if err := ch.updateCallRecord(ctx, req.CallID, func(r *CallRecord) {
		r.Status = "answered"
		r.AnsweredAt = now.Unix()
	}); err != nil {
		log.Error().Err(err).Msg("Failed to update call record")
	}

	// Send accept event to peer vault
	acceptEvent := &CallEvent{
		EventID:   generateEventID(),
		EventType: CallEventAccept,
		CallerID:  ch.ownerSpace,
		CalleeID:  activeCall.PeerID,
		CallID:    req.CallID,
		Timestamp: now.Unix(),
		Payload:   json.RawMessage(fmt.Sprintf(`{"local_key_pub":"%s"}`, base64.StdEncoding.EncodeToString(activeCall.LocalPubKey))),
	}

	if err := ch.publishCallEventToVault(ctx, activeCall.PeerID, acceptEvent); err != nil {
		log.Warn().Err(err).Msg("Failed to send accept event to peer")
	}

	log.Info().Str("call_id", req.CallID).Msg("Call accepted")

	resp := AcceptCallResponse{
		CallID:       req.CallID,
		Status:       "answered",
		LocalKeyPub:  base64.StdEncoding.EncodeToString(activeCall.LocalPubKey),
		SharedSecret: sharedSecretB64,
		AcceptedAt:   now.Format(time.RFC3339),
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleRejectCall processes a call rejection from the app
func (ch *CallHandler) HandleRejectCall(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req RejectCallRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return ch.errorResponse(msg.GetID(), "invalid request format")
	}

	if req.CallID == "" {
		return ch.errorResponse(msg.GetID(), "call_id is required")
	}

	activeCall, exists := ch.activeCalls[req.CallID]
	if !exists {
		return ch.errorResponse(msg.GetID(), "call not found or already ended")
	}

	now := time.Now()

	// Update call record
	if err := ch.updateCallRecord(ctx, req.CallID, func(r *CallRecord) {
		r.Status = "rejected"
		r.EndedAt = now.Unix()
	}); err != nil {
		log.Error().Err(err).Msg("Failed to update call record")
	}

	// Send reject event to peer
	rejectEvent := &CallEvent{
		EventID:   generateEventID(),
		EventType: CallEventReject,
		CallerID:  ch.ownerSpace,
		CalleeID:  activeCall.PeerID,
		CallID:    req.CallID,
		Timestamp: now.Unix(),
	}
	ch.publishCallEventToVault(ctx, activeCall.PeerID, rejectEvent)

	// Clean up active call
	delete(ch.activeCalls, req.CallID)

	log.Info().Str("call_id", req.CallID).Msg("Call rejected")

	resp := map[string]interface{}{
		"call_id": req.CallID,
		"status":  "rejected",
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleEndCall processes a call end request from the app
func (ch *CallHandler) HandleEndCall(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req EndCallRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return ch.errorResponse(msg.GetID(), "invalid request format")
	}

	if req.CallID == "" {
		return ch.errorResponse(msg.GetID(), "call_id is required")
	}

	activeCall, exists := ch.activeCalls[req.CallID]
	if !exists {
		// Call may have already ended from the other side
		return ch.successResponse(msg.GetID(), map[string]interface{}{
			"call_id": req.CallID,
			"status":  "ended",
		})
	}

	now := time.Now()

	// Update call record
	if err := ch.updateCallRecord(ctx, req.CallID, func(r *CallRecord) {
		r.EndedAt = now.Unix()
		if r.AnsweredAt > 0 {
			r.DurationSecs = int(r.EndedAt - r.AnsweredAt)
		}
	}); err != nil {
		log.Error().Err(err).Msg("Failed to update call record")
	}

	// Send end event to peer
	endEvent := &CallEvent{
		EventID:   generateEventID(),
		EventType: CallEventEnd,
		CallerID:  ch.ownerSpace,
		CalleeID:  activeCall.PeerID,
		CallID:    req.CallID,
		Timestamp: now.Unix(),
	}
	ch.publishCallEventToVault(ctx, activeCall.PeerID, endEvent)

	// Clean up active call
	delete(ch.activeCalls, req.CallID)

	log.Info().Str("call_id", req.CallID).Msg("Call ended")

	resp := map[string]interface{}{
		"call_id": req.CallID,
		"status":  "ended",
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleSendSignaling processes WebRTC signaling from the app
func (ch *CallHandler) HandleSendSignaling(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req SendSignalingRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return ch.errorResponse(msg.GetID(), "invalid request format")
	}

	if req.CallID == "" {
		return ch.errorResponse(msg.GetID(), "call_id is required")
	}
	if req.SignalType == "" {
		return ch.errorResponse(msg.GetID(), "signal_type is required")
	}

	activeCall, exists := ch.activeCalls[req.CallID]
	if !exists {
		return ch.errorResponse(msg.GetID(), "call not found or already ended")
	}

	// If peer's public key is provided, store it and derive shared secret
	var sharedSecretB64 string
	if req.PeerKeyPub != "" {
		peerPubKey, err := base64.StdEncoding.DecodeString(req.PeerKeyPub)
		if err == nil && len(peerPubKey) == 32 {
			activeCall.PeerPubKey = peerPubKey

			// Derive shared secret
			if activeCall.LocalPrivKey != nil {
				sharedSecret, err := deriveSharedSecret(activeCall.LocalPrivKey, peerPubKey, req.CallID)
				if err == nil {
					activeCall.SharedSecret = sharedSecret
					sharedSecretB64 = base64.StdEncoding.EncodeToString(sharedSecret)
				}
			}
		}
	}

	// Map signal type to CallEventType
	var eventType CallEventType
	switch req.SignalType {
	case "offer":
		eventType = CallEventOffer
	case "answer":
		eventType = CallEventAnswer
	case "candidate":
		eventType = CallEventCandidate
	default:
		return ch.errorResponse(msg.GetID(), "invalid signal_type: must be offer, answer, or candidate")
	}

	// Send signaling to peer
	signalingEvent := &CallEvent{
		EventID:   generateEventID(),
		EventType: eventType,
		CallerID:  ch.ownerSpace,
		CalleeID:  activeCall.PeerID,
		CallID:    req.CallID,
		Payload:   req.Payload,
		Timestamp: time.Now().Unix(),
	}

	sent := true
	if err := ch.publishCallEventToVault(ctx, activeCall.PeerID, signalingEvent); err != nil {
		log.Warn().Err(err).Str("signal_type", req.SignalType).Msg("Failed to send signaling")
		sent = false
	}

	log.Debug().
		Str("call_id", req.CallID).
		Str("signal_type", req.SignalType).
		Bool("sent", sent).
		Msg("Signaling forwarded")

	resp := SendSignalingResponse{
		CallID:       req.CallID,
		SignalType:   req.SignalType,
		Sent:         sent,
		SharedSecret: sharedSecretB64,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleGetCallHistory retrieves call history for the app
func (ch *CallHandler) HandleGetCallHistory(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req GetCallHistoryRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		// Allow empty payload for defaults
		req = GetCallHistoryRequest{}
	}

	limit := req.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}

	// Get call history from storage
	// Note: In a production system, you'd use proper indexing
	calls, hasMore, err := ch.getCallRecords(ctx, limit, req.Before, req.Status)
	if err != nil {
		return ch.errorResponse(msg.GetID(), "failed to retrieve call history")
	}

	var oldestTime int64
	if len(calls) > 0 {
		oldestTime = calls[len(calls)-1].StartedAt
	}

	resp := GetCallHistoryResponse{
		Calls:      calls,
		HasMore:    hasMore,
		OldestTime: oldestTime,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// getCallRecords retrieves call records with filtering using an index
func (ch *CallHandler) getCallRecords(ctx context.Context, limit int, before int64, status string) ([]*CallRecord, bool, error) {
	// Get call index
	var callIDs []string
	indexData, err := ch.storage.Get("calls/_index")
	if err != nil {
		// No calls yet
		return []*CallRecord{}, false, nil
	}
	if err := json.Unmarshal(indexData, &callIDs); err != nil {
		return nil, false, fmt.Errorf("failed to unmarshal call index: %w", err)
	}

	var records []*CallRecord
	for _, callID := range callIDs {
		data, err := ch.storage.Get("calls/" + callID)
		if err != nil {
			continue
		}

		var record CallRecord
		if err := json.Unmarshal(data, &record); err != nil {
			continue
		}

		// Apply filters
		if before > 0 && record.StartedAt >= before {
			continue
		}
		if status != "" && status != "all" {
			if status == "missed" && record.Status != "missed" {
				continue
			}
			if status == "answered" && record.Status != "answered" {
				continue
			}
		}

		records = append(records, &record)
	}

	// Sort by StartedAt descending (most recent first)
	for i := 0; i < len(records)-1; i++ {
		for j := i + 1; j < len(records); j++ {
			if records[j].StartedAt > records[i].StartedAt {
				records[i], records[j] = records[j], records[i]
			}
		}
	}

	hasMore := len(records) > limit
	if hasMore {
		records = records[:limit]
	}

	return records, hasMore, nil
}

// addToCallIndex adds a call ID to the call index
func (ch *CallHandler) addToCallIndex(callID string) {
	var index []string
	indexData, err := ch.storage.Get("calls/_index")
	if err == nil {
		json.Unmarshal(indexData, &index)
	}

	// Check if already in index
	for _, id := range index {
		if id == callID {
			return
		}
	}

	// Add to front (most recent first)
	index = append([]string{callID}, index...)

	// Limit index size (keep last 1000 calls)
	if len(index) > 1000 {
		index = index[:1000]
	}

	indexData, _ = json.Marshal(index)
	ch.storage.Put("calls/_index", indexData)
}

// --- X25519 Key Exchange Helpers ---

// generateX25519KeyPair generates a new X25519 keypair for E2EE
func generateX25519KeyPair() (privateKey, publicKey []byte, err error) {
	privateKey = make([]byte, 32)
	if _, err := rand.Read(privateKey); err != nil {
		return nil, nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Clamp the private key per X25519 spec
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	publicKey, err = curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute public key: %w", err)
	}

	return privateKey, publicKey, nil
}

// deriveSharedSecret performs X25519 key exchange and HKDF to derive a shared secret
func deriveSharedSecret(localPrivKey, peerPubKey []byte, callID string) ([]byte, error) {
	// Perform X25519 key exchange
	sharedPoint, err := curve25519.X25519(localPrivKey, peerPubKey)
	if err != nil {
		return nil, fmt.Errorf("X25519 key exchange failed: %w", err)
	}

	// Use HKDF to derive the final key
	// Salt: call ID for domain separation
	// Info: "vettid-e2ee-call-key" for application binding
	salt := []byte(callID)
	info := []byte("vettid-e2ee-call-key")

	hkdfReader := hkdf.New(sha256.New, sharedPoint, salt, info)

	sharedSecret := make([]byte, 32) // 256-bit key
	if _, err := hkdfReader.Read(sharedSecret); err != nil {
		return nil, fmt.Errorf("HKDF derivation failed: %w", err)
	}

	return sharedSecret, nil
}

// --- Response helpers ---

func (ch *CallHandler) errorResponse(id string, message string) (*OutgoingMessage, error) {
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

func (ch *CallHandler) successResponse(id string, data interface{}) (*OutgoingMessage, error) {
	resp := map[string]interface{}{
		"success": true,
	}
	if data != nil {
		// Merge data into response
		if m, ok := data.(map[string]interface{}); ok {
			for k, v := range m {
				resp[k] = v
			}
		}
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: id,
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleCallEvent processes an incoming call event
func (ch *CallHandler) HandleCallEvent(ctx context.Context, event *CallEvent) error {
	// SECURITY: Replay attack prevention
	// Use EventID if provided, otherwise fall back to call_id+event_type+timestamp
	eventID := event.EventID
	if eventID == "" {
		eventID = fmt.Sprintf("call:%s:%s:%d", event.CallID, event.EventType, event.Timestamp)
	}
	if alreadyProcessed, err := ch.storage.IsEventProcessed(eventID); err == nil && alreadyProcessed {
		log.Info().
			Str("event_id", eventID).
			Str("call_id", event.CallID).
			Msg("Duplicate call event detected - ignoring replay")
		return nil
	}

	// SECURITY: Check event freshness (reject events older than 5 minutes)
	if event.Timestamp > 0 {
		if err := checkEventFreshness(event.Timestamp); err != nil {
			log.Warn().
				Str("call_id", event.CallID).
				Int64("timestamp", event.Timestamp).
				Err(err).
				Msg("Call event failed freshness check - possible replay attack")
			return fmt.Errorf("event failed freshness check: %w", err)
		}
	}

	log.Debug().
		Str("event_type", string(event.EventType)).
		Str("call_id", event.CallID).
		Str("caller_id", event.CallerID).
		Msg("Processing call event")

	var err error
	switch event.EventType {
	case CallEventInitiate:
		err = ch.handleCallInitiate(ctx, event)
	case CallEventOffer, CallEventAnswer, CallEventCandidate:
		err = ch.handleCallSignaling(ctx, event)
	case CallEventAccept:
		err = ch.handleCallAccept(ctx, event)
	case CallEventReject:
		err = ch.handleCallReject(ctx, event)
	case CallEventCancel:
		err = ch.handleCallCancel(ctx, event)
	case CallEventEnd:
		err = ch.handleCallEnd(ctx, event)
	default:
		return fmt.Errorf("unknown call event type: %s", event.EventType)
	}

	if err != nil {
		return err
	}

	// SECURITY: Mark event as processed to prevent replay
	if markErr := ch.storage.MarkEventProcessed(eventID, string(event.EventType)); markErr != nil {
		log.Warn().Err(markErr).Str("event_id", eventID).Msg("Failed to mark call event as processed")
	}

	return nil
}

// checkEventFreshness validates that an event timestamp is recent enough
func checkEventFreshness(eventTimestamp int64) error {
	const maxEventAge int64 = 300 // 5 minutes
	now := time.Now().Unix()
	age := now - eventTimestamp

	if age < 0 {
		return fmt.Errorf("event timestamp is in the future")
	}
	if age > maxEventAge {
		return fmt.Errorf("event is too old: %d seconds (max %d)", age, maxEventAge)
	}
	return nil
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

		// Log blocked call event for audit
		if ch.eventHandler != nil {
			ch.eventHandler.LogCallEvent(ctx, EventTypeCallBlocked, event.CallID, event.CallerID, "Blocked call", map[string]string{
				"reason": reason,
			})
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

	// 2. Create active call state for later accept/reject
	activeCall := &ActiveCall{
		CallID:    event.CallID,
		PeerID:    event.CallerID,
		Direction: "incoming",
		Status:    "ringing",
		StartedAt: time.Unix(event.Timestamp, 0),
	}

	// Extract peer's public key from payload if provided
	if event.Payload != nil {
		var payload struct {
			LocalKeyPub string `json:"local_key_pub"`
		}
		if json.Unmarshal(event.Payload, &payload) == nil && payload.LocalKeyPub != "" {
			if peerPubKey, err := base64.StdEncoding.DecodeString(payload.LocalKeyPub); err == nil {
				activeCall.PeerPubKey = peerPubKey
			}
		}
	}

	ch.activeCalls[event.CallID] = activeCall

	// 3. Log incoming call to storage
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

	// 4. Log incoming call event (will appear in feed with accept/decline action)
	if ch.eventHandler != nil {
		ch.eventHandler.LogCallEvent(ctx, EventTypeCallIncoming, event.CallID, event.CallerID, "Incoming call", nil)
	}

	// 5. Forward to owner's app
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

	// Log missed call event (will appear in feed)
	if ch.eventHandler != nil {
		ch.eventHandler.LogCallEvent(ctx, EventTypeCallMissed, event.CallID, event.CallerID, "Missed call", nil)
	}

	eventData, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal cancel event: %w", err)
	}

	return ch.publisher.PublishToApp(ctx, "call.cancelled", eventData)
}

// handleCallEnd processes call termination
func (ch *CallHandler) handleCallEnd(ctx context.Context, event *CallEvent) error {
	// Update call record with duration
	var durationSecs int
	if err := ch.updateCallRecord(ctx, event.CallID, func(r *CallRecord) {
		r.EndedAt = time.Now().Unix()
		if r.AnsweredAt > 0 {
			r.DurationSecs = int(r.EndedAt - r.AnsweredAt)
			durationSecs = r.DurationSecs
		}
	}); err != nil {
		log.Error().Err(err).Msg("Failed to update call record")
	}

	log.Info().Str("call_id", event.CallID).Msg("Call ended")

	// Log call ended event for audit
	if ch.eventHandler != nil {
		ch.eventHandler.LogCallEvent(ctx, EventTypeCallEnded, event.CallID, event.CallerID, "Call ended", map[string]string{
			"duration_secs": fmt.Sprintf("%d", durationSecs),
		})
	}

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
	if err := ch.storage.Put(key, data); err != nil {
		return err
	}

	// Add to index
	ch.addToCallIndex(record.CallID)

	return nil
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

// --- Service-initiated call methods (DEV-034) ---

// ServiceCallInitiateRequest is the payload for service call initiation
type ServiceCallInitiateRequest struct {
	CallID      string            `json:"call_id"`
	CallType    string            `json:"call_type"`    // "voice" or "video"
	ServiceKey  string            `json:"service_key"`  // Service's X25519 public key (base64)
	DisplayName string            `json:"display_name"` // Name to show on incoming call
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// ServiceCallSignalingRequest is the payload for service WebRTC signaling
type ServiceCallSignalingRequest struct {
	CallID     string          `json:"call_id"`
	SignalType string          `json:"signal_type"` // "offer", "answer", "candidate"
	Payload    json.RawMessage `json:"payload"`     // WebRTC SDP or ICE candidate
	PeerKeyPub string          `json:"peer_key_pub,omitempty"` // Service's X25519 public key
}

// ServiceCallEndRequest is the payload for service ending a call
type ServiceCallEndRequest struct {
	CallID string `json:"call_id"`
	Reason string `json:"reason,omitempty"`
}

// HandleServiceCallInitiate handles an incoming call from a service (DEV-034)
// SECURITY: Connection must be active and have call capability (already verified by router)
func (ch *CallHandler) HandleServiceCallInitiate(ctx context.Context, msg *IncomingMessage, conn *ServiceConnectionRecord) (*OutgoingMessage, error) {
	var req ServiceCallInitiateRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return ch.errorResponse(msg.GetID(), "invalid request format")
	}

	// Generate call ID if not provided
	if req.CallID == "" {
		req.CallID = fmt.Sprintf("svc-call-%d", time.Now().UnixNano())
	}

	// Validate call type
	if req.CallType != "voice" && req.CallType != "video" {
		req.CallType = "voice" // Default to voice
	}

	// Check if this call ID is already active
	if _, exists := ch.activeCalls[req.CallID]; exists {
		return ch.errorResponse(msg.GetID(), "call already in progress")
	}

	now := time.Now()

	// Create active call state
	activeCall := &ActiveCall{
		CallID:    req.CallID,
		PeerID:    conn.ServiceGUID, // Service is the "peer" in this context
		Direction: "incoming",
		Status:    "ringing",
		StartedAt: now,
	}

	// Decode and store service's public key if provided
	if req.ServiceKey != "" {
		if peerPubKey, err := base64.StdEncoding.DecodeString(req.ServiceKey); err == nil && len(peerPubKey) == 32 {
			activeCall.PeerPubKey = peerPubKey
		}
	}

	ch.activeCalls[req.CallID] = activeCall

	// Log call record
	record := &CallRecord{
		CallID:    req.CallID,
		CallerID:  conn.ServiceGUID, // Service is the caller
		CalleeID:  ch.ownerSpace,    // Vault owner is the callee
		Direction: "incoming",
		Status:    "initiated",
		StartedAt: now.Unix(),
	}
	if err := ch.storeCallRecord(ctx, record); err != nil {
		log.Error().Err(err).Msg("Failed to store service call record")
	}

	// Log incoming service call event (will appear in feed with accept/decline action)
	if ch.eventHandler != nil {
		displayName := req.DisplayName
		if displayName == "" {
			displayName = conn.ServiceProfile.ServiceName
		}
		ch.eventHandler.LogCallEvent(ctx, EventTypeCallIncoming, req.CallID, conn.ServiceGUID, "Incoming service call", map[string]string{
			"service_name": conn.ServiceProfile.ServiceName,
			"call_type":    req.CallType,
			"display_name": displayName,
		})
	}

	// Forward to owner's app as incoming call
	callEvent := map[string]interface{}{
		"type":          "service.call.incoming",
		"call_id":       req.CallID,
		"call_type":     req.CallType,
		"service_id":    conn.ServiceGUID,
		"service_name":  conn.ServiceProfile.ServiceName,
		"display_name":  req.DisplayName,
		"service_key":   req.ServiceKey,
		"metadata":      req.Metadata,
		"connection_id": conn.ConnectionID,
		"timestamp":     now.Unix(),
	}
	eventData, _ := json.Marshal(callEvent)

	if err := ch.publisher.PublishToApp(ctx, "service.call.incoming", eventData); err != nil {
		log.Warn().Err(err).Msg("Failed to forward service call to app")
		// Continue - call state is stored
	}

	log.Info().
		Str("call_id", req.CallID).
		Str("service_id", conn.ServiceGUID).
		Str("call_type", req.CallType).
		Msg("Service call initiated")

	// Generate our X25519 keypair for E2EE
	localPrivKey, localPubKey, err := generateX25519KeyPair()
	if err != nil {
		return ch.errorResponse(msg.GetID(), "failed to generate encryption keys")
	}
	activeCall.LocalPrivKey = localPrivKey
	activeCall.LocalPubKey = localPubKey

	resp := map[string]interface{}{
		"success":       true,
		"call_id":       req.CallID,
		"status":        "ringing",
		"vault_key_pub": base64.StdEncoding.EncodeToString(localPubKey),
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleServiceCallSignaling handles WebRTC signaling from a service (DEV-034)
func (ch *CallHandler) HandleServiceCallSignaling(ctx context.Context, msg *IncomingMessage, conn *ServiceConnectionRecord) (*OutgoingMessage, error) {
	var req ServiceCallSignalingRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return ch.errorResponse(msg.GetID(), "invalid request format")
	}

	if req.CallID == "" {
		return ch.errorResponse(msg.GetID(), "call_id is required")
	}
	if req.SignalType == "" {
		return ch.errorResponse(msg.GetID(), "signal_type is required")
	}

	// Validate signal type
	switch req.SignalType {
	case "offer", "answer", "candidate":
		// Valid
	default:
		return ch.errorResponse(msg.GetID(), "invalid signal_type: must be offer, answer, or candidate")
	}

	activeCall, exists := ch.activeCalls[req.CallID]
	if !exists {
		return ch.errorResponse(msg.GetID(), "call not found or already ended")
	}

	// Verify this call is from the same service
	if activeCall.PeerID != conn.ServiceGUID {
		return ch.errorResponse(msg.GetID(), "call belongs to different service")
	}

	// Store peer's public key if provided
	var sharedSecretB64 string
	if req.PeerKeyPub != "" {
		peerPubKey, err := base64.StdEncoding.DecodeString(req.PeerKeyPub)
		if err == nil && len(peerPubKey) == 32 {
			activeCall.PeerPubKey = peerPubKey

			// Derive shared secret if we have our local key
			if activeCall.LocalPrivKey != nil {
				sharedSecret, err := deriveSharedSecret(activeCall.LocalPrivKey, peerPubKey, req.CallID)
				if err == nil {
					activeCall.SharedSecret = sharedSecret
					sharedSecretB64 = base64.StdEncoding.EncodeToString(sharedSecret)
				}
			}
		}
	}

	// Forward signaling to app
	signalingEvent := map[string]interface{}{
		"type":          fmt.Sprintf("service.call.%s", req.SignalType),
		"call_id":       req.CallID,
		"signal_type":   req.SignalType,
		"payload":       req.Payload,
		"service_id":    conn.ServiceGUID,
		"service_key":   req.PeerKeyPub,
		"shared_secret": sharedSecretB64,
		"timestamp":     time.Now().Unix(),
	}
	eventData, _ := json.Marshal(signalingEvent)

	if err := ch.publisher.PublishToApp(ctx, fmt.Sprintf("service.call.%s", req.SignalType), eventData); err != nil {
		log.Warn().Err(err).Str("signal_type", req.SignalType).Msg("Failed to forward signaling to app")
	}

	log.Debug().
		Str("call_id", req.CallID).
		Str("signal_type", req.SignalType).
		Str("service_id", conn.ServiceGUID).
		Msg("Service call signaling forwarded")

	resp := map[string]interface{}{
		"success":       true,
		"call_id":       req.CallID,
		"signal_type":   req.SignalType,
		"shared_secret": sharedSecretB64,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleServiceCallEnd handles call termination from a service (DEV-034)
func (ch *CallHandler) HandleServiceCallEnd(ctx context.Context, msg *IncomingMessage, conn *ServiceConnectionRecord) (*OutgoingMessage, error) {
	var req ServiceCallEndRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return ch.errorResponse(msg.GetID(), "invalid request format")
	}

	if req.CallID == "" {
		return ch.errorResponse(msg.GetID(), "call_id is required")
	}

	activeCall, exists := ch.activeCalls[req.CallID]
	if !exists {
		// Call may have already ended - that's OK
		return ch.successResponse(msg.GetID(), map[string]interface{}{
			"call_id": req.CallID,
			"status":  "ended",
		})
	}

	// Verify this call is from the same service
	if activeCall.PeerID != conn.ServiceGUID {
		return ch.errorResponse(msg.GetID(), "call belongs to different service")
	}

	now := time.Now()

	// Update call record
	if err := ch.updateCallRecord(ctx, req.CallID, func(r *CallRecord) {
		r.EndedAt = now.Unix()
		if r.AnsweredAt > 0 {
			r.DurationSecs = int(r.EndedAt - r.AnsweredAt)
		}
		if r.Status == "initiated" {
			r.Status = "missed" // Service hung up before user answered
		}
	}); err != nil {
		log.Error().Err(err).Msg("Failed to update call record")
	}

	// Clean up active call
	delete(ch.activeCalls, req.CallID)

	// Log call ended event
	if ch.eventHandler != nil {
		ch.eventHandler.LogCallEvent(ctx, EventTypeCallEnded, req.CallID, conn.ServiceGUID, "Service call ended", map[string]string{
			"reason": req.Reason,
		})
	}

	// Notify app
	endEvent := map[string]interface{}{
		"type":       "service.call.ended",
		"call_id":    req.CallID,
		"service_id": conn.ServiceGUID,
		"reason":     req.Reason,
		"timestamp":  now.Unix(),
	}
	eventData, _ := json.Marshal(endEvent)

	if err := ch.publisher.PublishToApp(ctx, "service.call.ended", eventData); err != nil {
		log.Warn().Err(err).Msg("Failed to forward call end to app")
	}

	log.Info().
		Str("call_id", req.CallID).
		Str("service_id", conn.ServiceGUID).
		Str("reason", req.Reason).
		Msg("Service call ended")

	resp := map[string]interface{}{
		"success": true,
		"call_id": req.CallID,
		"status":  "ended",
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// SendServiceCallResponse sends a response back to the service via NATS
// This is used when the user accepts/rejects/ends a service call
func (ch *CallHandler) SendServiceCallResponse(ctx context.Context, callID string, responseType string, payload json.RawMessage) error {
	activeCall, exists := ch.activeCalls[callID]
	if !exists {
		return fmt.Errorf("call not found: %s", callID)
	}

	// Send response to service via MessageSpace
	// The service subscribes to their callback topic for responses
	responseEvent := map[string]interface{}{
		"type":          responseType,
		"call_id":       callID,
		"vault_key_pub": base64.StdEncoding.EncodeToString(activeCall.LocalPubKey),
		"payload":       payload,
		"timestamp":     time.Now().Unix(),
	}
	eventData, _ := json.Marshal(responseEvent)

	// Publish to MessageSpace.{serviceGUID}.forOwner.call.{responseType}
	subject := fmt.Sprintf("MessageSpace.%s.forOwner.call.%s", activeCall.PeerID, responseType)
	msg := &OutgoingMessage{
		ID:      generateMessageID(),
		Type:    MessageTypeNATSPublish,
		Subject: subject,
		Payload: eventData,
	}

	// Use the publisher's sendFn to send via vsock
	if p, ok := ch.publisher.(*VsockPublisher); ok {
		return p.sendFn(msg)
	}

	log.Warn().Str("call_id", callID).Msg("Publisher does not support direct send")
	return nil
}
