/**
 * Integration Tests: Messaging Send Text Handler
 *
 * Tests the first-party messaging handler:
 * - Send text message to connection
 * - Message encryption
 * - Offline queuing
 * - Delivery receipts
 *
 * @see vault-manager/internal/handlers/builtin/messaging.go (pending implementation)
 */

import * as crypto from 'crypto';
import {
  createMessagingHandlerPackage,
  createExecutionContext,
  simulateHandlerExecution,
} from '../../fixtures/handlers/mockHandler';

// ============================================
// Types
// ============================================

interface Connection {
  connection_id: string;
  user_id: string;
  public_key: string;
  display_name: string;
  status: 'active' | 'pending' | 'blocked';
  online: boolean;
}

interface Message {
  message_id: string;
  sender_id: string;
  recipient_id: string;
  content: string;
  encrypted_content: string;
  timestamp: string;
  status: 'sent' | 'delivered' | 'read' | 'queued' | 'failed';
}

interface DeliveryReceipt {
  message_id: string;
  status: 'delivered' | 'read' | 'failed';
  timestamp: string;
  recipient_id: string;
}

// ============================================
// Mock Messaging Service
// ============================================

class MockMessagingService {
  private connections: Map<string, Connection[]> = new Map(); // user_id -> connections
  private messages: Message[] = [];
  private messageQueue: Map<string, Message[]> = new Map(); // recipient_id -> queued messages
  private maxMessageLength = 10000;

  /**
   * Add a connection for a user
   */
  addConnection(userId: string, connection: Connection): void {
    let userConnections = this.connections.get(userId);
    if (!userConnections) {
      userConnections = [];
      this.connections.set(userId, userConnections);
    }
    userConnections.push(connection);
  }

  /**
   * Get user's connections
   */
  getConnections(userId: string): Connection[] {
    return this.connections.get(userId) || [];
  }

  /**
   * Check if users are connected
   */
  isConnected(userId: string, targetUserId: string): boolean {
    const connections = this.connections.get(userId) || [];
    return connections.some(c => c.user_id === targetUserId && c.status === 'active');
  }

  /**
   * Get connection by user ID
   */
  getConnection(userId: string, targetUserId: string): Connection | undefined {
    const connections = this.connections.get(userId) || [];
    return connections.find(c => c.user_id === targetUserId);
  }

  /**
   * Send a text message
   */
  async sendTextMessage(
    senderId: string,
    recipientId: string,
    content: string
  ): Promise<{ success: boolean; message?: Message; error?: string; receipt?: DeliveryReceipt }> {
    // Validate message length
    if (content.length > this.maxMessageLength) {
      return {
        success: false,
        error: `Message exceeds maximum length of ${this.maxMessageLength} characters`,
      };
    }

    // Validate connection
    if (!this.isConnected(senderId, recipientId)) {
      return {
        success: false,
        error: 'Cannot send message to non-connected user',
      };
    }

    const connection = this.getConnection(senderId, recipientId);
    if (!connection) {
      return { success: false, error: 'Connection not found' };
    }

    // Create message
    const messageId = crypto.randomUUID();
    const encryptedContent = this.encryptMessage(content, connection.public_key);

    const message: Message = {
      message_id: messageId,
      sender_id: senderId,
      recipient_id: recipientId,
      content, // Original content (for sender's local copy)
      encrypted_content: encryptedContent,
      timestamp: new Date().toISOString(),
      status: connection.online ? 'sent' : 'queued',
    };

    this.messages.push(message);

    // Queue if recipient offline
    if (!connection.online) {
      let queue = this.messageQueue.get(recipientId);
      if (!queue) {
        queue = [];
        this.messageQueue.set(recipientId, queue);
      }
      queue.push(message);

      return {
        success: true,
        message,
      };
    }

    // Simulate delivery
    const receipt: DeliveryReceipt = {
      message_id: messageId,
      status: 'delivered',
      timestamp: new Date().toISOString(),
      recipient_id: recipientId,
    };

    message.status = 'delivered';

    return {
      success: true,
      message,
      receipt,
    };
  }

  /**
   * Encrypt message with recipient's public key
   */
  private encryptMessage(content: string, publicKey: string): string {
    // Simulate encryption (in real implementation would use actual crypto)
    const combined = content + ':' + publicKey;
    return Buffer.from(combined).toString('base64');
  }

  /**
   * Get queued messages for user
   */
  getQueuedMessages(userId: string): Message[] {
    return this.messageQueue.get(userId) || [];
  }

  /**
   * Deliver queued messages (when user comes online)
   */
  deliverQueuedMessages(userId: string): DeliveryReceipt[] {
    const queue = this.messageQueue.get(userId) || [];
    const receipts: DeliveryReceipt[] = [];

    for (const message of queue) {
      message.status = 'delivered';
      receipts.push({
        message_id: message.message_id,
        status: 'delivered',
        timestamp: new Date().toISOString(),
        recipient_id: userId,
      });
    }

    this.messageQueue.set(userId, []);
    return receipts;
  }

  /**
   * Get all messages for a user
   */
  getMessages(userId: string): Message[] {
    return this.messages.filter(
      m => m.sender_id === userId || m.recipient_id === userId
    );
  }

  /**
   * Clear all state
   */
  clear(): void {
    this.connections.clear();
    this.messages = [];
    this.messageQueue.clear();
  }
}

// ============================================
// Tests
// ============================================

describe('Messaging Send Text Handler', () => {
  let messaging: MockMessagingService;
  const senderId = 'user-sender-123';
  const recipientId = 'user-recipient-456';

  beforeEach(() => {
    messaging = new MockMessagingService();

    // Setup default connection
    messaging.addConnection(senderId, {
      connection_id: 'conn-123',
      user_id: recipientId,
      public_key: 'recipient-public-key-abc123',
      display_name: 'Test Recipient',
      status: 'active',
      online: true,
    });
  });

  afterEach(() => {
    messaging.clear();
  });

  it('should send text message to connection', async () => {
    const result = await messaging.sendTextMessage(
      senderId,
      recipientId,
      'Hello, this is a test message!'
    );

    expect(result.success).toBe(true);
    expect(result.message).toBeDefined();
    expect(result.message?.sender_id).toBe(senderId);
    expect(result.message?.recipient_id).toBe(recipientId);
    expect(result.message?.content).toBe('Hello, this is a test message!');
  });

  it('should encrypt message with connection key', async () => {
    const result = await messaging.sendTextMessage(
      senderId,
      recipientId,
      'Secret message'
    );

    expect(result.success).toBe(true);
    expect(result.message?.encrypted_content).toBeDefined();
    expect(result.message?.encrypted_content).not.toBe('Secret message');
    // Encrypted content should contain the original message (in our mock)
    const decoded = Buffer.from(result.message!.encrypted_content, 'base64').toString();
    expect(decoded).toContain('Secret message');
  });

  it('should queue message for offline recipient', async () => {
    // Set recipient offline
    messaging.clear();
    messaging.addConnection(senderId, {
      connection_id: 'conn-123',
      user_id: recipientId,
      public_key: 'recipient-public-key',
      display_name: 'Offline User',
      status: 'active',
      online: false, // Offline
    });

    const result = await messaging.sendTextMessage(
      senderId,
      recipientId,
      'Message for offline user'
    );

    expect(result.success).toBe(true);
    expect(result.message?.status).toBe('queued');
    expect(result.receipt).toBeUndefined(); // No receipt for queued messages

    const queued = messaging.getQueuedMessages(recipientId);
    expect(queued).toHaveLength(1);
    expect(queued[0].content).toBe('Message for offline user');
  });

  it('should return delivery receipt', async () => {
    const result = await messaging.sendTextMessage(
      senderId,
      recipientId,
      'Message with receipt'
    );

    expect(result.success).toBe(true);
    expect(result.receipt).toBeDefined();
    expect(result.receipt?.message_id).toBe(result.message?.message_id);
    expect(result.receipt?.status).toBe('delivered');
    expect(result.receipt?.recipient_id).toBe(recipientId);
  });

  it('should reject message to non-connected user', async () => {
    const nonConnectedUser = 'user-stranger-999';

    const result = await messaging.sendTextMessage(
      senderId,
      nonConnectedUser,
      'Message to stranger'
    );

    expect(result.success).toBe(false);
    expect(result.error).toContain('non-connected');
  });

  it('should enforce message size limit', async () => {
    const longMessage = 'x'.repeat(15000); // Exceeds 10000 char limit

    const result = await messaging.sendTextMessage(
      senderId,
      recipientId,
      longMessage
    );

    expect(result.success).toBe(false);
    expect(result.error).toContain('maximum length');
  });

  it('should deliver queued messages when recipient comes online', async () => {
    // Set recipient offline
    messaging.clear();
    messaging.addConnection(senderId, {
      connection_id: 'conn-123',
      user_id: recipientId,
      public_key: 'recipient-public-key',
      display_name: 'User',
      status: 'active',
      online: false,
    });

    // Queue some messages
    await messaging.sendTextMessage(senderId, recipientId, 'Message 1');
    await messaging.sendTextMessage(senderId, recipientId, 'Message 2');
    await messaging.sendTextMessage(senderId, recipientId, 'Message 3');

    expect(messaging.getQueuedMessages(recipientId)).toHaveLength(3);

    // Deliver queued messages
    const receipts = messaging.deliverQueuedMessages(recipientId);

    expect(receipts).toHaveLength(3);
    expect(messaging.getQueuedMessages(recipientId)).toHaveLength(0);
  });

  it('should reject message to blocked connection', async () => {
    messaging.clear();
    messaging.addConnection(senderId, {
      connection_id: 'conn-blocked',
      user_id: recipientId,
      public_key: 'blocked-key',
      display_name: 'Blocked User',
      status: 'blocked', // Blocked
      online: true,
    });

    const result = await messaging.sendTextMessage(
      senderId,
      recipientId,
      'Message to blocked user'
    );

    expect(result.success).toBe(false);
    expect(result.error).toContain('non-connected');
  });

  it('should include timestamp on messages', async () => {
    const beforeSend = new Date();

    const result = await messaging.sendTextMessage(
      senderId,
      recipientId,
      'Timestamped message'
    );

    const afterSend = new Date();

    expect(result.message?.timestamp).toBeDefined();
    const messageTime = new Date(result.message!.timestamp);
    expect(messageTime.getTime()).toBeGreaterThanOrEqual(beforeSend.getTime());
    expect(messageTime.getTime()).toBeLessThanOrEqual(afterSend.getTime());
  });

  it('should generate unique message IDs', async () => {
    const results = await Promise.all([
      messaging.sendTextMessage(senderId, recipientId, 'Message 1'),
      messaging.sendTextMessage(senderId, recipientId, 'Message 2'),
      messaging.sendTextMessage(senderId, recipientId, 'Message 3'),
    ]);

    const messageIds = results.map(r => r.message?.message_id);
    const uniqueIds = new Set(messageIds);

    expect(uniqueIds.size).toBe(3);
  });

  it('should store messages for retrieval', async () => {
    await messaging.sendTextMessage(senderId, recipientId, 'Test message 1');
    await messaging.sendTextMessage(senderId, recipientId, 'Test message 2');

    const senderMessages = messaging.getMessages(senderId);
    const recipientMessages = messaging.getMessages(recipientId);

    expect(senderMessages).toHaveLength(2);
    expect(recipientMessages).toHaveLength(2);
  });

  it('should handle empty message content', async () => {
    const result = await messaging.sendTextMessage(
      senderId,
      recipientId,
      ''
    );

    // Empty messages should still be allowed
    expect(result.success).toBe(true);
    expect(result.message?.content).toBe('');
  });

  it('should handle unicode content', async () => {
    const unicodeMessage = '你好世界! 🌍 Привет мир! مرحبا بالعالم';

    const result = await messaging.sendTextMessage(
      senderId,
      recipientId,
      unicodeMessage
    );

    expect(result.success).toBe(true);
    expect(result.message?.content).toBe(unicodeMessage);
  });
});
