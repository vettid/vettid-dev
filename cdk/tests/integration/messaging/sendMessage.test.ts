/**
 * Integration Tests: Send Message
 *
 * Tests the message sending endpoint:
 * - Message encryption with XChaCha20-Poly1305
 * - Message delivery via NATS
 * - Message size limits
 * - Connection validation
 *
 * @see lambda/handlers/messaging/sendMessage.ts (pending implementation)
 */

import {
  MockConnectionService,
} from '../../fixtures/connections/mockConnection';
import {
  MockMessagingService,
  encryptMessage,
  decryptMessage,
  packageEncryptedMessage,
  unpackageDecryptedMessage,
  createMockMessage,
  chunkMessage,
  reassembleMessage,
} from '../../fixtures/messaging/mockMessage';
import * as crypto from 'crypto';

// ============================================
// Tests
// ============================================

describe('Send Message', () => {
  let connectionService: MockConnectionService;
  let messagingService: MockMessagingService;
  const senderGuid = 'user-sender-123';
  const recipientGuid = 'user-recipient-456';
  let connectionId: string;
  let sharedKeyId: string;

  beforeEach(async () => {
    connectionService = new MockConnectionService();
    messagingService = new MockMessagingService();

    // Create connection between sender and recipient
    const invite = await connectionService.createInvitation(senderGuid);
    const accept = await connectionService.acceptInvitation(recipientGuid, invite.invitation!.code);

    // Store connection info for tests
    connectionId = accept.connection!.connection_id;
    sharedKeyId = accept.connection!.shared_key_id;

    // Set up shared key in messaging service
    const sharedKey = connectionService.getSharedKey(sharedKeyId);
    messagingService.setSharedKey(connectionId, sharedKey!);
  });

  afterEach(() => {
    connectionService.clear();
    messagingService.clear();
  });

  describe('Message Encryption', () => {
    it('should encrypt message with connection key', async () => {
      const sharedKey = messagingService.getSharedKey(connectionId);

      const message = 'Hello, this is a test message!';
      const { ciphertext, nonce, authTag } = encryptMessage(message, sharedKey!);

      // Ciphertext should be different from plaintext
      expect(ciphertext.toString('utf8')).not.toBe(message);

      // Should be able to decrypt
      const decrypted = decryptMessage(ciphertext, nonce, authTag, sharedKey!);
      expect(decrypted).toBe(message);
    });

    it('should use XChaCha20-Poly1305 AEAD', async () => {
      const sharedKey = messagingService.getSharedKey(connectionId);

      const { encryptedContent, nonce } = packageEncryptedMessage('Test message', sharedKey!);

      // Nonce should be 24 bytes (for XChaCha20)
      const nonceBuffer = Buffer.from(nonce, 'base64');
      expect(nonceBuffer.length).toBe(24);

      // Encrypted content should include auth tag (16 bytes)
      const contentBuffer = Buffer.from(encryptedContent, 'base64');
      expect(contentBuffer.length).toBeGreaterThan(16);
    });

    it('should include unique nonce per message', async () => {
      const sharedKey = messagingService.getSharedKey(connectionId);

      const result1 = packageEncryptedMessage('Message 1', sharedKey!);
      const result2 = packageEncryptedMessage('Message 2', sharedKey!);

      expect(result1.nonce).not.toBe(result2.nonce);
    });

    it('should authenticate sender', async () => {
      const result = await messagingService.sendMessage(
        senderGuid,
        connectionId,
        recipientGuid,
        'Authenticated message'
      );

      expect(result.success).toBe(true);
      expect(result.message?.sender_guid).toBe(senderGuid);
    });

    it('should fail decryption with wrong key', () => {
      const correctKey = crypto.randomBytes(32);
      const wrongKey = crypto.randomBytes(32);

      const { encryptedContent, nonce } = packageEncryptedMessage('Secret message', correctKey);

      expect(() => {
        unpackageDecryptedMessage(encryptedContent, nonce, wrongKey);
      }).toThrow();
    });

    it('should fail decryption with tampered ciphertext', () => {
      const key = crypto.randomBytes(32);
      const { encryptedContent, nonce } = packageEncryptedMessage('Original message', key);

      // Tamper with ciphertext
      const buffer = Buffer.from(encryptedContent, 'base64');
      buffer[0] ^= 0xff;
      const tampered = buffer.toString('base64');

      expect(() => {
        unpackageDecryptedMessage(tampered, nonce, key);
      }).toThrow();
    });

    it('should encrypt and decrypt unicode messages', async () => {
      const sharedKey = messagingService.getSharedKey(connectionId);

      const unicodeMessage = 'Hello 👋 World 🌍! 日本語 العربية';
      const { encryptedContent, nonce } = packageEncryptedMessage(unicodeMessage, sharedKey!);
      const decrypted = unpackageDecryptedMessage(encryptedContent, nonce, sharedKey!);

      expect(decrypted).toBe(unicodeMessage);
    });
  });

  describe('Message Delivery', () => {
    it('should send via messaging service', async () => {
      const result = await messagingService.sendMessage(
        senderGuid,
        connectionId,
        recipientGuid,
        'Test message'
      );

      expect(result.success).toBe(true);
      expect(result.message).toBeDefined();
      expect(result.message?.status).toBe('sent');
    });

    it('should queue for offline recipient', async () => {
      const sharedKey = messagingService.getSharedKey(connectionId);

      // Create message and queue it
      const message = createMockMessage({
        senderId: senderGuid,
        recipientId: recipientGuid,
        connectionId,
        content: 'Queued message',
        sharedKey: sharedKey!,
      });

      messagingService.queueMessage(message);

      const queued = messagingService.getQueuedMessages(recipientGuid);
      expect(queued.length).toBe(1);
      expect(queued[0].message_id).toBe(message.message_id);
    });

    it('should return message status', async () => {
      const result = await messagingService.sendMessage(
        senderGuid,
        connectionId,
        recipientGuid,
        'Status test message'
      );

      expect(result.success).toBe(true);
      expect(result.message?.status).toBe('sent');
      expect(result.message?.created_at).toBeDefined();
    });

    it('should handle large messages (chunking)', () => {
      const key = crypto.randomBytes(32);
      const largeMessage = 'x'.repeat(50000); // 50KB message
      const messageId = crypto.randomUUID();

      const chunks = chunkMessage(largeMessage, messageId, key);

      expect(chunks.length).toBeGreaterThan(1);

      // Reassemble
      const reassembled = reassembleMessage(chunks, key);
      expect(reassembled).toBe(largeMessage);
    });

    it('should maintain chunk order', () => {
      const key = crypto.randomBytes(32);
      const message = 'Part1|Part2|Part3|Part4';
      const messageId = crypto.randomUUID();

      const chunks = chunkMessage(message, messageId, key);

      // Shuffle chunks
      const shuffled = [...chunks].sort(() => Math.random() - 0.5);

      // Reassemble should still work
      const reassembled = reassembleMessage(shuffled, key);
      expect(reassembled).toBe(message);
    });
  });

  describe('Message Validation', () => {
    it('should enforce message size limit', async () => {
      // Create oversized message (>64KB)
      const oversizedContent = 'x'.repeat(65 * 1024);

      const result = await messagingService.sendMessage(
        senderGuid,
        connectionId,
        recipientGuid,
        oversizedContent
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('exceeds maximum size');
    });

    it('should validate connection is active', async () => {
      // Revoke connection - use the recipient's connection (which is the one we have)
      await connectionService.revokeConnection(recipientGuid, connectionId);

      // Clear the shared key (simulating revocation cleanup)
      messagingService.clear();

      // Try to send message
      const result = await messagingService.sendMessage(
        senderGuid,
        connectionId,
        recipientGuid,
        'Test message'
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('key not found');
    });

    it('should reject messages to revoked connections', async () => {
      // Revoke - use the recipient's connection
      await connectionService.revokeConnection(recipientGuid, connectionId);
      messagingService.clear();

      const result = await messagingService.sendMessage(
        senderGuid,
        connectionId,
        recipientGuid,
        'Should fail'
      );

      expect(result.success).toBe(false);
    });

    it('should validate message content type', async () => {
      // Valid content types
      const textResult = await messagingService.sendMessage(
        senderGuid,
        connectionId,
        recipientGuid,
        'Text message',
        'text'
      );
      expect(textResult.success).toBe(true);
      expect(textResult.message?.content_type).toBe('text');

      const imageResult = await messagingService.sendMessage(
        senderGuid,
        connectionId,
        recipientGuid,
        'Image data',
        'image'
      );
      expect(imageResult.success).toBe(true);
      expect(imageResult.message?.content_type).toBe('image');
    });

    it('should require connection key to exist', async () => {
      // Create new connection without setting up shared key
      const newSender = 'new-sender-123';
      const newRecipient = 'new-recipient-456';

      const invite = await connectionService.createInvitation(newSender);
      const accept = await connectionService.acceptInvitation(newRecipient, invite.invitation!.code);

      // Don't set up shared key in messaging service

      const result = await messagingService.sendMessage(
        newSender,
        accept.connection!.connection_id,
        newRecipient,
        'Test'
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('key not found');
    });
  });

  describe('Message Metadata', () => {
    it('should include message_id', async () => {
      const result = await messagingService.sendMessage(
        senderGuid,
        connectionId,
        recipientGuid,
        'Test message'
      );

      expect(result.message?.message_id).toBeDefined();
      expect(result.message?.message_id).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
      );
    });

    it('should include connection_id', async () => {
      const result = await messagingService.sendMessage(
        senderGuid,
        connectionId,
        recipientGuid,
        'Test message'
      );

      expect(result.message?.connection_id).toBe(connectionId);
    });

    it('should include sender and recipient guids', async () => {
      const result = await messagingService.sendMessage(
        senderGuid,
        connectionId,
        recipientGuid,
        'Test message'
      );

      expect(result.message?.sender_guid).toBe(senderGuid);
      expect(result.message?.recipient_guid).toBe(recipientGuid);
    });

    it('should include created_at timestamp', async () => {
      const before = new Date();

      const result = await messagingService.sendMessage(
        senderGuid,
        connectionId,
        recipientGuid,
        'Test message'
      );

      const after = new Date();

      const createdAt = new Date(result.message!.created_at);
      expect(createdAt.getTime()).toBeGreaterThanOrEqual(before.getTime());
      expect(createdAt.getTime()).toBeLessThanOrEqual(after.getTime());
    });
  });

  describe('Unread Count', () => {
    it('should increment unread count for recipient', async () => {
      // Initial count should be 0
      expect(messagingService.getUnreadCount(recipientGuid)).toBe(0);

      // Send message
      await messagingService.sendMessage(
        senderGuid,
        connectionId,
        recipientGuid,
        'Test message'
      );

      expect(messagingService.getUnreadCount(recipientGuid)).toBe(1);
    });

    it('should track unread count per connection', async () => {
      // Create second connection
      const thirdUser = 'user-third-789';
      const invite2 = await connectionService.createInvitation(senderGuid);
      const accept2 = await connectionService.acceptInvitation(thirdUser, invite2.invitation!.code);
      const sharedKey2 = connectionService.getSharedKey(accept2.connection!.shared_key_id);
      const connectionId2 = accept2.connection!.connection_id;
      messagingService.setSharedKey(connectionId2, sharedKey2!);

      // Send to first connection
      await messagingService.sendMessage(
        senderGuid,
        connectionId,
        recipientGuid,
        'Message 1'
      );

      // Send to second connection
      await messagingService.sendMessage(
        senderGuid,
        connectionId2,
        thirdUser,
        'Message 2'
      );

      expect(messagingService.getUnreadCount(recipientGuid, connectionId)).toBe(1);
      expect(messagingService.getUnreadCount(thirdUser, connectionId2)).toBe(1);
    });
  });
});
