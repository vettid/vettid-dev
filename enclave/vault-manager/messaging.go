package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
)

// MessagingHandler handles vault-to-vault messaging operations.
// Messages flow: App -> Vault -> Peer Vault -> Peer App
type MessagingHandler struct {
	ownerSpace string
	storage    *EncryptedStorage
	publisher  *VsockPublisher
}

// NewMessagingHandler creates a new messaging handler
func NewMessagingHandler(ownerSpace string, storage *EncryptedStorage, publisher *VsockPublisher) *MessagingHandler {
	return &MessagingHandler{
		ownerSpace: ownerSpace,
		storage:    storage,
		publisher:  publisher,
	}
}

// --- Storage types ---

// MessageDirection indicates if message is incoming or outgoing
type MessageDirection string

const (
	MessageDirectionIncoming MessageDirection = "incoming"
	MessageDirectionOutgoing MessageDirection = "outgoing"
)

// MessageStatus indicates the delivery status
type MessageStatus string

const (
	MessageStatusSent      MessageStatus = "sent"
	MessageStatusDelivered MessageStatus = "delivered"
	MessageStatusRead      MessageStatus = "read"
	MessageStatusFailed    MessageStatus = "failed"
)

// MessageRecord represents a stored message
type MessageRecord struct {
	MessageID        string           `json:"message_id"`
	ConnectionID     string           `json:"connection_id"`
	PeerGUID         string           `json:"peer_guid,omitempty"`
	Direction        MessageDirection `json:"direction"`
	ContentType      string           `json:"content_type"`
	Status           MessageStatus    `json:"status"`
	EncryptedContent string           `json:"encrypted_content"`
	Nonce            string           `json:"nonce,omitempty"`
	CreatedAt        time.Time        `json:"created_at"`
	DeliveredAt      *time.Time       `json:"delivered_at,omitempty"`
	ReadAt           *time.Time       `json:"read_at,omitempty"`
}

// --- Request/Response types ---

// SendMessageRequest is the payload for message.send
type SendMessageRequest struct {
	ConnectionID     string `json:"connection_id"`
	EncryptedContent string `json:"encrypted_content"`
	Nonce            string `json:"nonce"`
	ContentType      string `json:"content_type"` // "text", "image", "file"
}

// SendMessageResponse is the response for message.send
type SendMessageResponse struct {
	MessageID    string `json:"message_id"`
	ConnectionID string `json:"connection_id"`
	SentAt       string `json:"sent_at"`
	Status       string `json:"status"`
}

// ReadReceiptRequest is the payload for message.read-receipt
type ReadReceiptRequest struct {
	ConnectionID string `json:"connection_id"`
	MessageID    string `json:"message_id"`
}

// ReadReceiptResponse is the response for message.read-receipt
type ReadReceiptResponse struct {
	MessageID string `json:"message_id"`
	ReadAt    string `json:"read_at"`
	Sent      bool   `json:"sent"`
}

// PeerMessage is the structure for messages sent to/from peers
type PeerMessage struct {
	MessageID        string `json:"message_id"`
	SenderGUID       string `json:"sender_guid"`
	ConnectionID     string `json:"connection_id"`
	EncryptedContent string `json:"encrypted_content"`
	Nonce            string `json:"nonce"`
	ContentType      string `json:"content_type"`
	SentAt           string `json:"sent_at"`
}

// PeerReadReceipt is the structure for read receipts
type PeerReadReceipt struct {
	MessageID    string `json:"message_id"`
	ConnectionID string `json:"connection_id"`
	ReadAt       string `json:"read_at"`
}

// --- Handler methods ---

// HandleSend processes message.send from the app
func (h *MessagingHandler) HandleSend(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req SendMessageRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}
	if req.EncryptedContent == "" {
		return h.errorResponse(msg.GetID(), "encrypted_content is required")
	}
	if req.Nonce == "" {
		return h.errorResponse(msg.GetID(), "nonce is required")
	}

	contentType := req.ContentType
	if contentType == "" {
		contentType = "text"
	}

	// Verify connection exists and is active
	connData, err := h.storage.Get("connections/" + req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}

	var conn ConnectionRecord
	if err := json.Unmarshal(connData, &conn); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid connection data")
	}

	if conn.Status != "active" {
		return h.errorResponse(msg.GetID(), "Cannot send to a revoked connection")
	}

	// Generate message ID and timestamp
	messageID := fmt.Sprintf("msg-%d", time.Now().UnixNano())
	now := time.Now().UTC()
	sentAt := now.Format(time.RFC3339)

	// Store message locally
	localMsg := MessageRecord{
		MessageID:        messageID,
		ConnectionID:     req.ConnectionID,
		Direction:        MessageDirectionOutgoing,
		ContentType:      contentType,
		Status:           MessageStatusSent,
		EncryptedContent: req.EncryptedContent,
		Nonce:            req.Nonce,
		CreatedAt:        now,
	}

	msgData, _ := json.Marshal(localMsg)
	storageKey := fmt.Sprintf("messages/%s/%s", req.ConnectionID, messageID)
	if err := h.storage.Put(storageKey, msgData); err != nil {
		log.Warn().Err(err).Msg("Failed to store outgoing message locally")
	}

	// Build message for peer
	peerMsg := PeerMessage{
		MessageID:        messageID,
		SenderGUID:       h.ownerSpace,
		ConnectionID:     req.ConnectionID,
		EncryptedContent: req.EncryptedContent,
		Nonce:            req.Nonce,
		ContentType:      contentType,
		SentAt:           sentAt,
	}

	peerMsgData, _ := json.Marshal(peerMsg)

	// Publish to peer via supervisor
	if err := h.publisher.PublishToVault(context.Background(), conn.PeerGUID, "message", peerMsgData); err != nil {
		// Update local status to failed
		localMsg.Status = MessageStatusFailed
		msgData, _ = json.Marshal(localMsg)
		h.storage.Put(storageKey, msgData)

		return h.errorResponse(msg.GetID(), "Failed to send message to peer")
	}

	log.Info().
		Str("message_id", messageID).
		Str("connection_id", req.ConnectionID).
		Msg("Message sent to peer")

	resp := SendMessageResponse{
		MessageID:    messageID,
		ConnectionID: req.ConnectionID,
		SentAt:       sentAt,
		Status:       "sent",
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleReadReceipt processes message.read-receipt from the app
func (h *MessagingHandler) HandleReadReceipt(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req ReadReceiptRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}
	if req.MessageID == "" {
		return h.errorResponse(msg.GetID(), "message_id is required")
	}

	now := time.Now().UTC()
	readAt := now.Format(time.RFC3339)

	// Mark message as read locally
	storageKey := fmt.Sprintf("messages/%s/%s", req.ConnectionID, req.MessageID)
	msgData, err := h.storage.Get(storageKey)
	if err == nil {
		var record MessageRecord
		if json.Unmarshal(msgData, &record) == nil {
			record.Status = MessageStatusRead
			record.ReadAt = &now
			newData, _ := json.Marshal(record)
			h.storage.Put(storageKey, newData)
		}
	}

	// Get connection for peer info
	connData, err := h.storage.Get("connections/" + req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}

	var conn ConnectionRecord
	if err := json.Unmarshal(connData, &conn); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid connection data")
	}

	// Build read receipt for peer
	receipt := PeerReadReceipt{
		MessageID:    req.MessageID,
		ConnectionID: req.ConnectionID,
		ReadAt:       readAt,
	}
	receiptData, _ := json.Marshal(receipt)

	// Send to peer
	sent := true
	if err := h.publisher.PublishToVault(context.Background(), conn.PeerGUID, "read-receipt", receiptData); err != nil {
		log.Warn().Err(err).Str("message_id", req.MessageID).Msg("Failed to send read receipt to peer")
		sent = false
	}

	resp := ReadReceiptResponse{
		MessageID: req.MessageID,
		ReadAt:    readAt,
		Sent:      sent,
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleIncomingMessage processes a message received from a peer vault
func (h *MessagingHandler) HandleIncomingMessage(ctx context.Context, data []byte) error {
	var peerMsg PeerMessage
	if err := json.Unmarshal(data, &peerMsg); err != nil {
		return fmt.Errorf("invalid message format: %w", err)
	}

	log.Debug().
		Str("message_id", peerMsg.MessageID).
		Str("connection_id", peerMsg.ConnectionID).
		Msg("Received message from peer")

	sentAt, err := time.Parse(time.RFC3339, peerMsg.SentAt)
	if err != nil {
		sentAt = time.Now().UTC()
	}

	now := time.Now()
	record := MessageRecord{
		MessageID:        peerMsg.MessageID,
		ConnectionID:     peerMsg.ConnectionID,
		PeerGUID:         peerMsg.SenderGUID,
		Direction:        MessageDirectionIncoming,
		ContentType:      peerMsg.ContentType,
		Status:           MessageStatusDelivered,
		EncryptedContent: peerMsg.EncryptedContent,
		Nonce:            peerMsg.Nonce,
		CreatedAt:        sentAt,
		DeliveredAt:      &now,
	}

	msgData, _ := json.Marshal(record)
	storageKey := fmt.Sprintf("messages/%s/%s", peerMsg.ConnectionID, peerMsg.MessageID)
	if err := h.storage.Put(storageKey, msgData); err != nil {
		log.Error().Err(err).Str("message_id", peerMsg.MessageID).Msg("Failed to store incoming message")
	}

	// Notify app about new message
	if err := h.publisher.PublishToApp(ctx, "new-message", data); err != nil {
		log.Warn().Err(err).Msg("Failed to notify app of new message")
	}

	return nil
}

// HandleIncomingReadReceipt processes a read receipt from a peer vault
func (h *MessagingHandler) HandleIncomingReadReceipt(ctx context.Context, data []byte) error {
	var receipt PeerReadReceipt
	if err := json.Unmarshal(data, &receipt); err != nil {
		return fmt.Errorf("invalid read receipt format: %w", err)
	}

	log.Debug().
		Str("message_id", receipt.MessageID).
		Str("connection_id", receipt.ConnectionID).
		Msg("Received read receipt from peer")

	// Update local message status
	storageKey := fmt.Sprintf("messages/%s/%s", receipt.ConnectionID, receipt.MessageID)
	msgData, err := h.storage.Get(storageKey)
	if err == nil {
		var record MessageRecord
		if json.Unmarshal(msgData, &record) == nil {
			readAt, _ := time.Parse(time.RFC3339, receipt.ReadAt)
			record.Status = MessageStatusRead
			record.ReadAt = &readAt
			newData, _ := json.Marshal(record)
			h.storage.Put(storageKey, newData)
		}
	}

	// Notify app about read receipt
	if err := h.publisher.PublishToApp(ctx, "read-receipt", data); err != nil {
		log.Warn().Err(err).Msg("Failed to notify app of read receipt")
	}

	return nil
}

func (h *MessagingHandler) errorResponse(id string, message string) (*OutgoingMessage, error) {
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
