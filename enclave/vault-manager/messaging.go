package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/hkdf"
)

// MessagingHandler handles vault-to-vault messaging operations.
// Messages flow: App -> Vault -> Peer Vault -> Peer App
type MessagingHandler struct {
	ownerSpace   string
	storage      *EncryptedStorage
	publisher    *VsockPublisher
	eventHandler *EventHandler
	auditLog     *AuditLog
}

// NewMessagingHandler creates a new messaging handler
func NewMessagingHandler(ownerSpace string, storage *EncryptedStorage, publisher *VsockPublisher, eventHandler *EventHandler) *MessagingHandler {
	return &MessagingHandler{
		ownerSpace:   ownerSpace,
		storage:      storage,
		publisher:    publisher,
		eventHandler: eventHandler,
	}
}

// SetAuditLog wires the per-connection audit log so message send /
// receive events land in the trail. Optional — nil is fine.
func (h *MessagingHandler) SetAuditLog(a *AuditLog) { h.auditLog = a }

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
	Content          string `json:"content,omitempty"`           // Plaintext — vault encrypts
	EncryptedContent string `json:"encrypted_content,omitempty"` // Pre-encrypted (legacy)
	Nonce            string `json:"nonce,omitempty"`
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

// PeerReadReceipt is the structure for read receipts.
//
// ReaderGUID rides on the wire so the receiving vault can resolve
// the connection_id via FindConnectionByPeerGUID and run the
// per-connection handler gate. Without it gatePeerSubject sees an
// empty connectionID and fails closed (HandlerErrNotSharedToPeer),
// which is why early read-receipt rollouts looked like they
// "vanished" peer-side while new-message worked fine.
type PeerReadReceipt struct {
	MessageID    string `json:"message_id"`
	ConnectionID string `json:"connection_id"`
	ReaderGUID   string `json:"reader_guid"`
	ReadAt       string `json:"read_at"`
}

// --- Handler methods ---

// HandleSend processes message.send from the app
func (h *MessagingHandler) HandleSend(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req SendMessageRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleSend"); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}

	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}
	if req.Content == "" && req.EncryptedContent == "" {
		return h.errorResponse(msg.GetID(), "content or encrypted_content is required")
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
		return h.errorResponse(msg.GetID(), fmt.Sprintf("Connection is not active (status: %s)", conn.Status))
	}

	// If app sent transport-encrypted content, decrypt it first
	if req.Content == "" && req.EncryptedContent != "" && req.Nonce != "" {
		if len(conn.SharedSecret) > 0 {
			transportKey, err := deriveTransportKey(conn.SharedSecret)
			if err == nil {
				nonceBytes, err1 := base64.StdEncoding.DecodeString(req.Nonce)
				cipherBytes, err2 := base64.StdEncoding.DecodeString(req.EncryptedContent)
				if err1 == nil && err2 == nil {
					combined := append(nonceBytes, cipherBytes...)
					if plaintext, err := decryptXChaCha20(transportKey, combined); err == nil {
						req.Content = string(plaintext)
						req.EncryptedContent = ""
						req.Nonce = ""
					}
				}
			}
		}
	}

	// If plaintext content provided, encrypt with the connection's shared secret
	if req.Content != "" && req.EncryptedContent == "" {
		if len(conn.SharedSecret) == 0 {
			return h.errorResponse(msg.GetID(), "No encryption keys — key exchange not complete")
		}
		connKey, err := deriveConnectionKey(conn.SharedSecret)
		if err != nil {
			return h.errorResponse(msg.GetID(), "Failed to derive encryption key")
		}
		ciphertext, err := encryptXChaCha20(connKey, []byte(req.Content))
		if err != nil {
			return h.errorResponse(msg.GetID(), "Failed to encrypt message")
		}
		// encryptXChaCha20 returns nonce || ciphertext+tag
		// Split: first 24 bytes are nonce, rest is ciphertext
		req.Nonce = base64.StdEncoding.EncodeToString(ciphertext[:24])
		req.EncryptedContent = base64.StdEncoding.EncodeToString(ciphertext[24:])
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
	h.addToMessageIndex(req.ConnectionID, messageID)

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

	// Wrap the PeerMessage in the encrypted peer envelope so the
	// envelope metadata (sender_guid, connection_id, content_type,
	// sent_at, message_id) is sealed under the connection's shared
	// secret on the NATS hop. The inner EncryptedContent stays
	// encrypted on its own — different rotation semantics, and the
	// receiver still decrypts it via deriveConnectionKey for app
	// display.
	envEventID := fmt.Sprintf("msg:%s", messageID)
	if err := encryptAndPublishToPeer(
		context.Background(), h.storage, h.publisher, h.ownerSpace,
		req.ConnectionID, "message.incoming", envEventID, peerMsgData, now.Unix(),
	); err != nil {
		// Update local status to failed
		localMsg.Status = MessageStatusFailed
		msgData, _ = json.Marshal(localMsg)
		h.storage.Put(storageKey, msgData)

		return h.errorResponse(msg.GetID(), "Failed to send message to peer")
	}

	// Log message sent event for audit and feed
	if h.eventHandler != nil {
		h.eventHandler.LogMessageEvent(context.Background(), EventTypeMessageSent, messageID, req.ConnectionID, conn.PeerAlias, "")
	}

	// Per-connection audit trail: one entry per message the user sends.
	// Body left empty — we don't have the plaintext here (encrypted by
	// the app). The conversation store keeps the content; this entry is
	// a pointer via refs.message_id.
	h.auditLog.Append(AuditEntry{
		ConnectionID: req.ConnectionID,
		PeerGUID:     conn.PeerGUID,
		EventType:    AuditTypeMessageSent,
		Direction:    AuditDirectionOutbound,
		Title:        "Sent a message",
		CreatedAt:    now.Unix(),
		Refs:         map[string]string{"message_id": messageID},
	})

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

// HandleIncomingPeerMessage processes an encrypted message from a peer's vault.
// The peer's vault encrypted the body with the shared secret and wrapped the
// whole PeerMessage in EncryptedPeerEnvelope so the metadata (sender_guid,
// connection_id, content_type, sent_at, message_id) is also sealed on the
// NATS hop. We decrypt the envelope, parse the inner PeerMessage, store the
// (still-encrypted) body locally, decrypt for the app, and notify.
func (h *MessagingHandler) HandleIncomingPeerMessage(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	dec, err := decryptIncomingPeerEnvelope(h.storage, msg.Payload)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to decrypt incoming peer message envelope")
		return h.errorResponse(msg.GetID(), "Invalid peer message envelope")
	}
	var peerMsg PeerMessage
	if err := json.Unmarshal(dec.InnerPayload, &peerMsg); err != nil {
		log.Warn().Err(err).Msg("Failed to parse incoming peer message")
		return h.errorResponse(msg.GetID(), "Invalid peer message format")
	}

	if peerMsg.ConnectionID == "" || peerMsg.MessageID == "" {
		return h.errorResponse(msg.GetID(), "Missing connection_id or message_id")
	}

	// Idempotency gate. The JetStream durable consumer for
	// OwnerSpace.*.forVault.> replays messages from the stream
	// (DeliverAll) — without this check, a peer message that was
	// delivered on the previous enclave gets re-stored here, flipping
	// its status back to "delivered" and inflating the unread count.
	// Short-circuit silently if we've already processed this id.
	storageKey := fmt.Sprintf("messages/%s/%s", peerMsg.ConnectionID, peerMsg.MessageID)
	if existing, err := h.storage.Get(storageKey); err == nil && len(existing) > 0 {
		log.Debug().
			Str("message_id", peerMsg.MessageID).
			Str("connection_id", peerMsg.ConnectionID).
			Msg("Duplicate peer message — already stored, skipping")
		ackPayload, _ := json.Marshal(map[string]interface{}{
			"success": true,
			"status":  "duplicate",
		})
		return &OutgoingMessage{
			RequestID: msg.GetID(),
			Type:      MessageTypeResponse,
			Payload:   ackPayload,
		}, nil
	}

	log.Info().
		Str("message_id", peerMsg.MessageID).
		Str("connection_id", peerMsg.ConnectionID).
		Str("sender", peerMsg.SenderGUID).
		Msg("Received peer message")

	// Verify connection exists
	connData, err := h.storage.Get("connections/" + peerMsg.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found for incoming message")
	}

	var conn ConnectionRecord
	if err := json.Unmarshal(connData, &conn); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid connection data")
	}

	// Store incoming message
	localMsg := MessageRecord{
		MessageID:        peerMsg.MessageID,
		ConnectionID:     peerMsg.ConnectionID,
		Direction:        MessageDirectionIncoming,
		ContentType:      peerMsg.ContentType,
		Status:           MessageStatusDelivered,
		EncryptedContent: peerMsg.EncryptedContent,
		Nonce:            peerMsg.Nonce,
		CreatedAt:        time.Now(),
	}

	msgData, _ := json.Marshal(localMsg)
	if err := h.storage.Put(storageKey, msgData); err != nil {
		log.Warn().Err(err).Msg("Failed to store incoming message")
	}
	h.addToMessageIndex(peerMsg.ConnectionID, peerMsg.MessageID)

	// Decrypt the message content before sending to the app
	var plaintextContent string
	if len(conn.SharedSecret) > 0 && peerMsg.EncryptedContent != "" && peerMsg.Nonce != "" {
		connKey, err := deriveConnectionKey(conn.SharedSecret)
		if err == nil {
			nonceBytes, err1 := base64.StdEncoding.DecodeString(peerMsg.Nonce)
			cipherBytes, err2 := base64.StdEncoding.DecodeString(peerMsg.EncryptedContent)
			if err1 == nil && err2 == nil {
				// Reassemble nonce || ciphertext for decryptXChaCha20
				combined := append(nonceBytes, cipherBytes...)
				plaintext, err := decryptXChaCha20(connKey, combined)
				if err == nil {
					plaintextContent = string(plaintext)
				} else {
					log.Warn().Err(err).Msg("Failed to decrypt incoming peer message")
					plaintextContent = "[Unable to decrypt]"
				}
			}
		}
	}

	// Notify the app with decrypted content
	if h.publisher != nil {
		appNotification := map[string]interface{}{
			"type":          "message.received",
			"message_id":    peerMsg.MessageID,
			"connection_id": peerMsg.ConnectionID,
			"sender_guid":   peerMsg.SenderGUID,
			"content":       plaintextContent,
			"content_type":  peerMsg.ContentType,
			"sent_at":       peerMsg.SentAt,
		}
		notifBytes, _ := json.Marshal(appNotification)
		if err := h.publisher.PublishToApp(ctx, "new-message", notifBytes); err != nil {
			log.Warn().Err(err).Msg("Failed to notify app of incoming message")
		}
	}

	// Log message received event for audit and feed notification
	if h.eventHandler != nil {
		peerAlias := conn.PeerAlias
		if err := h.eventHandler.LogMessageEvent(ctx, EventTypeMessageReceived, peerMsg.MessageID, peerMsg.ConnectionID, peerAlias, "New message"); err != nil {
			log.Error().Err(err).Msg("Failed to log message.received event")
		}
	}

	// Audit trail: receive-side entry, stamped with the decrypted
	// preview body (short). The conversation store has the full text;
	// keep this under the 120-char cap.
	h.auditLog.Append(AuditEntry{
		ConnectionID: peerMsg.ConnectionID,
		PeerGUID:     conn.PeerGUID,
		EventType:    AuditTypeMessageReceived,
		Direction:    AuditDirectionInbound,
		Title:        "Received a message",
		Body:         plaintextContent,
		CreatedAt:    time.Now().Unix(),
		Refs:         map[string]string{"message_id": peerMsg.MessageID},
	})

	resp := map[string]interface{}{
		"success":    true,
		"message_id": peerMsg.MessageID,
		"status":     "delivered",
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// HandleList returns stored messages for a connection, decrypted.
func (h *MessagingHandler) HandleList(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		ConnectionID string `json:"connection_id"`
		Limit        int    `json:"limit,omitempty"`
		Before       string `json:"before,omitempty"` // message_id for pagination
	}
	if err := unmarshalRequest(msg.Payload, &req, "HandleList"); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid request format")
	}
	if req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}
	if req.Limit <= 0 || req.Limit > 100 {
		req.Limit = 50
	}

	// Load connection for decryption key
	connData, err := h.storage.Get("connections/" + req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}
	var conn ConnectionRecord
	json.Unmarshal(connData, &conn)

	var connKey []byte
	if len(conn.SharedSecret) > 0 {
		connKey, _ = deriveConnectionKey(conn.SharedSecret)
	}

	// Load message index for this connection
	indexKey := fmt.Sprintf("messages/%s/_index", req.ConnectionID)
	var messageIDs []string
	indexData, err := h.storage.Get(indexKey)
	if err == nil {
		json.Unmarshal(indexData, &messageIDs)
	}

	type messageItem struct {
		MessageID   string `json:"message_id"`
		Direction   string `json:"direction"`
		Content     string `json:"content"`
		ContentType string `json:"content_type"`
		Status      string `json:"status"`
		SentAt      string `json:"sent_at"`
		SenderGUID  string `json:"sender_guid,omitempty"`
	}

	messages := make([]messageItem, 0)
	for _, msgID := range messageIDs {
		key := fmt.Sprintf("messages/%s/%s", req.ConnectionID, msgID)
		data, err := h.storage.Get(key)
		if err != nil {
			continue
		}
		var record MessageRecord
		if json.Unmarshal(data, &record) != nil {
			continue
		}

		// Decrypt content
		content := ""
		if connKey != nil && record.EncryptedContent != "" && record.Nonce != "" {
			nonceBytes, err1 := base64.StdEncoding.DecodeString(record.Nonce)
			cipherBytes, err2 := base64.StdEncoding.DecodeString(record.EncryptedContent)
			if err1 == nil && err2 == nil {
				combined := append(nonceBytes, cipherBytes...)
				if plaintext, err := decryptXChaCha20(connKey, combined); err == nil {
					content = string(plaintext)
				}
			}
		}

		senderGUID := ""
		if record.Direction == MessageDirectionIncoming {
			senderGUID = record.PeerGUID
		} else {
			senderGUID = h.ownerSpace
		}

		messages = append(messages, messageItem{
			MessageID:   record.MessageID,
			Direction:   string(record.Direction),
			Content:     content,
			ContentType: record.ContentType,
			Status:      string(record.Status),
			SentAt:      record.CreatedAt.Format(time.RFC3339),
			SenderGUID:  senderGUID,
		})
	}

	// Sort by time (newest last)
	sort.Slice(messages, func(i, j int) bool {
		return messages[i].SentAt < messages[j].SentAt
	})

	// Apply limit (return latest N)
	if len(messages) > req.Limit {
		messages = messages[len(messages)-req.Limit:]
	}

	resp := map[string]interface{}{
		"success":       true,
		"connection_id": req.ConnectionID,
		"messages":      messages,
		"total":         len(messages),
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

const domainTransport = "vettid-app-transport-v1"

// deriveTransportKey derives a key for app-vault transport encryption.
// Uses a different HKDF domain than the connection key so they're independent.
func deriveTransportKey(sharedSecret []byte) ([]byte, error) {
	if len(sharedSecret) == 0 {
		return nil, fmt.Errorf("shared secret must not be empty")
	}
	r := hkdf.New(sha256.New, sharedSecret, []byte(domainTransport), nil)
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("HKDF expand: %w", err)
	}
	return key, nil
}

// HandleGetTransportKey returns a derived transport key for app-vault encryption.
// The app uses this to encrypt messages before sending to the vault.
func (h *MessagingHandler) HandleGetTransportKey(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req struct {
		ConnectionID string `json:"connection_id"`
	}
	if err := unmarshalRequest(msg.Payload, &req, "HandleGetTransportKey"); err != nil || req.ConnectionID == "" {
		return h.errorResponse(msg.GetID(), "connection_id is required")
	}

	connData, err := h.storage.Get("connections/" + req.ConnectionID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Connection not found")
	}

	var conn ConnectionRecord
	if err := json.Unmarshal(connData, &conn); err != nil {
		return h.errorResponse(msg.GetID(), "Invalid connection data")
	}

	if len(conn.SharedSecret) == 0 {
		return h.errorResponse(msg.GetID(), "Key exchange not complete")
	}

	transportKey, err := deriveTransportKey(conn.SharedSecret)
	if err != nil {
		return h.errorResponse(msg.GetID(), "Failed to derive transport key")
	}

	resp := map[string]interface{}{
		"success":       true,
		"connection_id": req.ConnectionID,
		"transport_key": base64.StdEncoding.EncodeToString(transportKey),
	}
	respBytes, _ := json.Marshal(resp)

	return &OutgoingMessage{
		RequestID: msg.GetID(),
		Type:      MessageTypeResponse,
		Payload:   respBytes,
	}, nil
}

// addToMessageIndex adds a message ID to the connection's message index.
func (h *MessagingHandler) addToMessageIndex(connectionID, messageID string) {
	indexKey := fmt.Sprintf("messages/%s/_index", connectionID)
	var index []string
	if data, err := h.storage.Get(indexKey); err == nil {
		json.Unmarshal(data, &index)
	}
	index = append(index, messageID)
	if data, err := json.Marshal(index); err == nil {
		h.storage.Put(indexKey, data)
	}
}

// HandleReadReceipt processes message.read-receipt from the app
func (h *MessagingHandler) HandleReadReceipt(msg *IncomingMessage) (*OutgoingMessage, error) {
	var req ReadReceiptRequest
	if err := unmarshalRequest(msg.Payload, &req, "HandleReadReceipt"); err != nil {
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

	// Build read receipt for peer. ReaderGUID is OUR ownerSpace —
	// the peer's gate uses it to resolve the connection record.
	receipt := PeerReadReceipt{
		MessageID:    req.MessageID,
		ConnectionID: req.ConnectionID,
		ReaderGUID:   h.ownerSpace,
		ReadAt:       readAt,
	}
	receiptData, _ := json.Marshal(receipt)

	// Send to peer with retry (read receipts are important for UX)
	eventID := fmt.Sprintf("read-receipt:%s:%s", req.ConnectionID, req.MessageID)
	sent := false
	for attempt := 0; attempt < 3; attempt++ {
		if err := encryptAndPublishToPeer(
			context.Background(), h.storage, h.publisher, h.ownerSpace,
			req.ConnectionID, "read-receipt", eventID, receiptData, time.Now().Unix(),
		); err != nil {
			log.Warn().Err(err).Int("attempt", attempt+1).Str("message_id", req.MessageID).Msg("Read receipt delivery failed, retrying")
			if attempt < 2 {
				time.Sleep(2 * time.Second)
			}
		} else {
			sent = true
			break
		}
	}
	if !sent {
		log.Error().Str("message_id", req.MessageID).Str("peer", conn.PeerGUID).Msg("Read receipt delivery failed after 3 attempts")
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

// HandleIncomingMessage processes a message received from a peer vault.
// Legacy entry point still wired under the forVault.new-message subject;
// kept envelope-aware so a stray broadcast can't bypass the metadata
// encryption added 2026-05-12.
func (h *MessagingHandler) HandleIncomingMessage(ctx context.Context, data []byte) error {
	dec, err := decryptIncomingPeerEnvelope(h.storage, data)
	if err != nil {
		return fmt.Errorf("decrypt envelope: %w", err)
	}
	var peerMsg PeerMessage
	if err := json.Unmarshal(dec.InnerPayload, &peerMsg); err != nil {
		return fmt.Errorf("invalid message format: %w", err)
	}

	// SECURITY: Replay attack prevention - check if message already processed
	eventID := fmt.Sprintf("msg:%s", peerMsg.MessageID)
	if alreadyProcessed, err := h.storage.IsEventProcessed(eventID); err == nil && alreadyProcessed {
		log.Info().
			Str("message_id", peerMsg.MessageID).
			Msg("Duplicate message detected - ignoring replay")
		return nil
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

	// SECURITY: Mark event as processed to prevent replay
	if err := h.storage.MarkEventProcessed(eventID, "incoming_message"); err != nil {
		log.Warn().Err(err).Str("message_id", peerMsg.MessageID).Msg("Failed to mark message as processed")
	}

	// Log message received event for audit and feed
	if h.eventHandler != nil {
		// Look up peer alias from connection record
		peerAlias := ""
		if connData, err := h.storage.Get("connections/" + peerMsg.ConnectionID); err == nil {
			var connRecord struct {
				PeerAlias string `json:"peer_alias"`
			}
			if json.Unmarshal(connData, &connRecord) == nil {
				peerAlias = connRecord.PeerAlias
			}
		}
		log.Info().
			Str("message_id", peerMsg.MessageID).
			Str("connection_id", peerMsg.ConnectionID).
			Str("peer_alias", peerAlias).
			Msg("Creating message.received feed event")
		if err := h.eventHandler.LogMessageEvent(ctx, EventTypeMessageReceived, peerMsg.MessageID, peerMsg.ConnectionID, peerAlias, "New message"); err != nil {
			log.Error().Err(err).Msg("Failed to log message.received event")
		}
	} else {
		log.Warn().Msg("eventHandler is nil — cannot log message.received event")
	}

	// Notify app about new message. The app expects the PeerMessage
	// JSON (decrypted from the envelope) — don't pass the envelope
	// bytes through, the app has no shared secret to unwrap them.
	if err := h.publisher.PublishToApp(ctx, "new-message", dec.InnerPayload); err != nil {
		log.Warn().Err(err).Msg("Failed to notify app of new message")
	}

	return nil
}

// HandleIncomingReadReceipt processes a read receipt from a peer vault
func (h *MessagingHandler) HandleIncomingReadReceipt(ctx context.Context, data []byte) error {
	dec, err := decryptIncomingPeerEnvelope(h.storage, data)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to decrypt incoming read-receipt envelope")
		return err
	}
	var receipt PeerReadReceipt
	if err := json.Unmarshal(dec.InnerPayload, &receipt); err != nil {
		return fmt.Errorf("invalid read receipt format: %w", err)
	}

	// SECURITY: Replay attack prevention - use message_id as receipt identifier
	eventID := fmt.Sprintf("receipt:%s:%s", receipt.ConnectionID, receipt.MessageID)
	if alreadyProcessed, err := h.storage.IsEventProcessed(eventID); err == nil && alreadyProcessed {
		log.Info().
			Str("message_id", receipt.MessageID).
			Msg("Duplicate read receipt detected - ignoring replay")
		return nil
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

	// SECURITY: Mark event as processed to prevent replay
	if err := h.storage.MarkEventProcessed(eventID, "read_receipt"); err != nil {
		log.Warn().Err(err).Str("message_id", receipt.MessageID).Msg("Failed to mark receipt as processed")
	}

	// Notify app about read receipt. Pass the decrypted PeerReadReceipt
	// JSON — the app has no shared secret to unwrap the envelope.
	if err := h.publisher.PublishToApp(ctx, "read-receipt", dec.InnerPayload); err != nil {
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
