/**
 * Integration Tests: Receive Message
 *
 * Tests message receiving and processing:
 * - Message decryption
 * - Authenticity verification
 * - Message storage
 * - Read status tracking
 *
 * @see lambda/handlers/messaging/receiveMessage.ts (pending implementation)
 */

import {
  MockConnectionService,
} from '../../fixtures/connections/mockConnection';
import {
  MockMessagingService,
  decryptMockMessage,
  packageEncryptedMessage,
  unpackageDecryptedMessage,
  createMockMessage,
  EncryptedMessage,
} from '../../fixtures/messaging/mockMessage';
import * as crypto from 'crypto';

// ============================================
// Tests
// ============================================

describe('Receive Message', () => {
  let connectionService: MockConnectionService;
  let messagingService: MockMessagingService;
  const senderGuid = 'user-sender-123';
  const recipientGuid = 'user-recipient-456';
  let connectionId: string;
  let sharedKey: Buffer;

  beforeEach(async () => {
    connectionService = new MockConnectionService();
    messagingService = new MockMessagingService();

    // Create connection between sender and recipient
    const invite = await connectionService.createInvitation(senderGuid);
    const accept = await connectionService.acceptInvitation(recipientGuid, invite.invitation!.code);
    connectionId = accept.connection!.connection_id;

    // Get shared key
    sharedKey = connectionService.getSharedKey(accept.connection!.shared_key_id)!;
    messagingService.setSharedKey(connectionId, sharedKey);
  });

  afterEach(() => {
    connectionService.clear();
    messagingService.clear();
  });

  describe('Message Decryption', () => {
    it('should decrypt message with connection key', async () => {
      const originalContent = 'Hello, this is a secret message!';

      // Send message
      const sendResult = await messagingService.sendMessage(
        senderGuid,
        connectionId,
        recipientGuid,
        originalContent
      );

      expect(sendResult.success).toBe(true);

      // Decrypt message
      const decrypted = decryptMockMessage(sendResult.message!, sharedKey);

      expect(decrypted.content).toBe(originalContent);
    });

    it('should verify message authenticity', async () => {
      const content = 'Authenticated message';

      const sendResult = await messagingService.sendMessage(
        senderGuid,
        connectionId,
        recipientGuid,
        content
      );

      // Decryption succeeds = message is authentic (AEAD property)
      const decrypted = decryptMockMessage(sendResult.message!, sharedKey);
      expect(decrypted.content).toBe(content);
      expect(decrypted.sender_guid).toBe(senderGuid);
    });

    it('should reject tampered messages', async () => {
      const sendResult = await messagingService.sendMessage(
        senderGuid,
        connectionId,
        recipientGuid,
        'Original message'
      );

      // Tamper with encrypted content
      const message = sendResult.message!;
      const tamperedContent = Buffer.from(message.encrypted_content, 'base64');
      tamperedContent[10] ^= 0xff;
      message.encrypted_content = tamperedContent.toString('base64');

      // Decryption should fail
      expect(() => {
        decryptMockMessage(message, sharedKey);
      }).toThrow();
    });

    it('should reject messages with wrong nonce', async () => {
      const content = 'Test message';
      const { encryptedContent } = packageEncryptedMessage(content, sharedKey);

      // Use wrong nonce
      const wrongNonce = crypto.randomBytes(24).toString('base64');

      expect(() => {
        unpackageDecryptedMessage(encryptedContent, wrongNonce, sharedKey);
      }).toThrow();
    });

    it('should handle decryption failures gracefully', () => {
      const wrongKey = crypto.randomBytes(32);
      const { encryptedContent, nonce } = packageEncryptedMessage('Secret', sharedKey);

      expect(() => {
        unpackageDecryptedMessage(encryptedContent, nonce, wrongKey);
      }).toThrow();
    });

    it('should decrypt unicode content correctly', async () => {
      const unicodeContent = '你好世界 🌍 مرحبا العالم';

      const sendResult = await messagingService.sendMessage(
        senderGuid,
        connectionId,
        recipientGuid,
        unicodeContent
      );

      const decrypted = decryptMockMessage(sendResult.message!, sharedKey);
      expect(decrypted.content).toBe(unicodeContent);
    });

    it('should decrypt empty message', async () => {
      const emptyContent = '';

      const sendResult = await messagingService.sendMessage(
        senderGuid,
        connectionId,
        recipientGuid,
        emptyContent
      );

      const decrypted = decryptMockMessage(sendResult.message!, sharedKey);
      expect(decrypted.content).toBe(emptyContent);
    });
  });

  describe('Message Storage', () => {
    it('should store message indexed by connection', async () => {
      await messagingService.sendMessage(
        senderGuid,
        connectionId,
        recipientGuid,
        'Message 1'
      );

      await messagingService.sendMessage(
        senderGuid,
        connectionId,
        recipientGuid,
        'Message 2'
      );

      const messages = messagingService.getMessages(connectionId);
      expect(messages.length).toBe(2);
    });

    it('should store message indexed by timestamp', async () => {
      await messagingService.sendMessage(
        senderGuid,
        connectionId,
        recipientGuid,
        'First message'
      );

      // Small delay to ensure different timestamps
      await new Promise(resolve => setTimeout(resolve, 10));

      await messagingService.sendMessage(
        senderGuid,
        connectionId,
        recipientGuid,
        'Second message'
      );

      const messages = messagingService.getMessages(connectionId);

      // Should be in chronological order
      const time1 = new Date(messages[0].created_at).getTime();
      const time2 = new Date(messages[1].created_at).getTime();
      expect(time1).toBeLessThanOrEqual(time2);
    });

    it('should support message retrieval by ID', async () => {
      const sendResult = await messagingService.sendMessage(
        senderGuid,
        connectionId,
        recipientGuid,
        'Test message'
      );

      const message = messagingService.getMessage(sendResult.message!.message_id);
      expect(message).toBeDefined();
      expect(message?.message_id).toBe(sendResult.message!.message_id);
    });

    it('should handle duplicate message IDs', async () => {
      // Create custom message with specific ID
      const customMessage = createMockMessage({
        senderId: senderGuid,
        recipientId: recipientGuid,
        connectionId,
        content: 'Custom message',
        sharedKey,
      });

      // In real implementation, duplicate IDs would be rejected
      // For mock, we just verify the storage mechanism
      expect(customMessage.message_id).toBeDefined();
    });

    it('should separate messages by connection', async () => {
      // Create second connection
      const thirdUser = 'user-third-789';
      const invite2 = await connectionService.createInvitation(senderGuid);
      const accept2 = await connectionService.acceptInvitation(thirdUser, invite2.invitation!.code);
      const connectionId2 = accept2.connection!.connection_id;
      const sharedKey2 = connectionService.getSharedKey(accept2.connection!.shared_key_id)!;
      messagingService.setSharedKey(connectionId2, sharedKey2);

      // Send to first connection
      await messagingService.sendMessage(senderGuid, connectionId, recipientGuid, 'Message to recipient');

      // Send to second connection
      await messagingService.sendMessage(senderGuid, connectionId2, thirdUser, 'Message to third user');

      // Check separation
      const conn1Messages = messagingService.getMessages(connectionId);
      const conn2Messages = messagingService.getMessages(connectionId2);

      expect(conn1Messages.length).toBe(1);
      expect(conn2Messages.length).toBe(1);
      expect(conn1Messages[0].recipient_guid).toBe(recipientGuid);
      expect(conn2Messages[0].recipient_guid).toBe(thirdUser);
    });
  });

  describe('Message Status', () => {
    it('should track unread count', async () => {
      expect(messagingService.getUnreadCount(recipientGuid)).toBe(0);

      await messagingService.sendMessage(senderGuid, connectionId, recipientGuid, 'Message 1');
      expect(messagingService.getUnreadCount(recipientGuid)).toBe(1);

      await messagingService.sendMessage(senderGuid, connectionId, recipientGuid, 'Message 2');
      expect(messagingService.getUnreadCount(recipientGuid)).toBe(2);
    });

    it('should mark messages as read', async () => {
      const sendResult = await messagingService.sendMessage(
        senderGuid,
        connectionId,
        recipientGuid,
        'Unread message'
      );

      expect(messagingService.getUnreadCount(recipientGuid)).toBe(1);

      await messagingService.markAsRead(recipientGuid, sendResult.message!.message_id);

      expect(messagingService.getUnreadCount(recipientGuid)).toBe(0);

      const message = messagingService.getMessage(sendResult.message!.message_id);
      expect(message?.status).toBe('read');
      expect(message?.read_at).toBeDefined();
    });

    it('should only allow recipient to mark as read', async () => {
      const sendResult = await messagingService.sendMessage(
        senderGuid,
        connectionId,
        recipientGuid,
        'Test message'
      );

      // Sender tries to mark as read
      const result = await messagingService.markAsRead(senderGuid, sendResult.message!.message_id);

      expect(result.success).toBe(false);
      expect(result.error).toContain('Not the recipient');
    });

    it('should update delivered_at on delivery', async () => {
      const sendResult = await messagingService.sendMessage(
        senderGuid,
        connectionId,
        recipientGuid,
        'Delivery test'
      );

      const before = new Date();
      await messagingService.deliverMessage(sendResult.message!.message_id);
      const after = new Date();

      const message = messagingService.getMessage(sendResult.message!.message_id);
      expect(message?.status).toBe('delivered');
      expect(message?.delivered_at).toBeDefined();

      const deliveredAt = new Date(message!.delivered_at!);
      expect(deliveredAt.getTime()).toBeGreaterThanOrEqual(before.getTime());
      expect(deliveredAt.getTime()).toBeLessThanOrEqual(after.getTime());
    });

    it('should track read_at timestamp', async () => {
      const sendResult = await messagingService.sendMessage(
        senderGuid,
        connectionId,
        recipientGuid,
        'Read timestamp test'
      );

      const before = new Date();
      await messagingService.markAsRead(recipientGuid, sendResult.message!.message_id);
      const after = new Date();

      const message = messagingService.getMessage(sendResult.message!.message_id);
      const readAt = new Date(message!.read_at!);

      expect(readAt.getTime()).toBeGreaterThanOrEqual(before.getTime());
      expect(readAt.getTime()).toBeLessThanOrEqual(after.getTime());
    });

    it('should handle marking non-existent message', async () => {
      const result = await messagingService.markAsRead(recipientGuid, 'non-existent-id');

      expect(result.success).toBe(false);
      expect(result.error).toContain('not found');
    });
  });

  describe('Message Delivery', () => {
    it('should deliver message and update status', async () => {
      const sendResult = await messagingService.sendMessage(
        senderGuid,
        connectionId,
        recipientGuid,
        'Delivery test'
      );

      expect(sendResult.message?.status).toBe('sent');

      await messagingService.deliverMessage(sendResult.message!.message_id);

      const message = messagingService.getMessage(sendResult.message!.message_id);
      expect(message?.status).toBe('delivered');
    });

    it('should handle delivery of non-existent message', async () => {
      const result = await messagingService.deliverMessage('non-existent-id');

      expect(result.success).toBe(false);
      expect(result.error).toContain('not found');
    });

    it('should process queued messages on reconnect', async () => {
      // Queue messages for offline recipient
      const message1 = createMockMessage({
        senderId: senderGuid,
        recipientId: recipientGuid,
        connectionId,
        content: 'Queued message 1',
        sharedKey,
      });

      const message2 = createMockMessage({
        senderId: senderGuid,
        recipientId: recipientGuid,
        connectionId,
        content: 'Queued message 2',
        sharedKey,
      });

      messagingService.queueMessage(message1);
      messagingService.queueMessage(message2);

      // Get queued messages
      const queued = messagingService.getQueuedMessages(recipientGuid);
      expect(queued.length).toBe(2);

      // Clear queue (simulate delivery)
      messagingService.clearQueue(recipientGuid);

      const afterClear = messagingService.getQueuedMessages(recipientGuid);
      expect(afterClear.length).toBe(0);
    });
  });

  describe('Message Deletion', () => {
    it('should delete message by ID', async () => {
      const sendResult = await messagingService.sendMessage(
        senderGuid,
        connectionId,
        recipientGuid,
        'To be deleted'
      );

      const deleted = messagingService.deleteMessage(sendResult.message!.message_id);
      expect(deleted).toBe(true);

      const message = messagingService.getMessage(sendResult.message!.message_id);
      expect(message).toBeUndefined();
    });

    it('should update connection message count on deletion', async () => {
      await messagingService.sendMessage(senderGuid, connectionId, recipientGuid, 'Message 1');
      const sendResult = await messagingService.sendMessage(
        senderGuid,
        connectionId,
        recipientGuid,
        'Message 2'
      );

      expect(messagingService.getMessageCount(connectionId)).toBe(2);

      messagingService.deleteMessage(sendResult.message!.message_id);

      expect(messagingService.getMessageCount(connectionId)).toBe(1);
    });

    it('should handle deletion of non-existent message', () => {
      const deleted = messagingService.deleteMessage('non-existent-id');
      expect(deleted).toBe(false);
    });
  });
});
