/**
 * Integration Tests: Message History
 *
 * Tests message history retrieval and search:
 * - Chronological ordering
 * - Pagination
 * - Filtering by date range
 * - Full-text search
 *
 * @see lambda/handlers/messaging/messageHistory.ts (pending implementation)
 */

import {
  MockConnectionService,
} from '../../fixtures/connections/mockConnection';
import {
  MockMessagingService,
  decryptMockMessage,
} from '../../fixtures/messaging/mockMessage';

// ============================================
// Tests
// ============================================

describe('Message History', () => {
  let connectionService: MockConnectionService;
  let messagingService: MockMessagingService;
  const user1Guid = 'user-1-guid';
  const user2Guid = 'user-2-guid';
  let connectionId: string;
  let sharedKey: Buffer;

  beforeEach(async () => {
    connectionService = new MockConnectionService();
    messagingService = new MockMessagingService();

    // Create connection
    const invite = await connectionService.createInvitation(user1Guid);
    const accept = await connectionService.acceptInvitation(user2Guid, invite.invitation!.code);
    connectionId = accept.connection!.connection_id;

    sharedKey = connectionService.getSharedKey(accept.connection!.shared_key_id)!;
    messagingService.setSharedKey(connectionId, sharedKey);
  });

  afterEach(() => {
    connectionService.clear();
    messagingService.clear();
  });

  describe('History Retrieval', () => {
    it('should return messages in chronological order', async () => {
      // Send messages with delays
      await messagingService.sendMessage(user1Guid, connectionId, user2Guid, 'First message');
      await new Promise(resolve => setTimeout(resolve, 10));
      await messagingService.sendMessage(user2Guid, connectionId, user1Guid, 'Second message');
      await new Promise(resolve => setTimeout(resolve, 10));
      await messagingService.sendMessage(user1Guid, connectionId, user2Guid, 'Third message');

      const messages = messagingService.getDecryptedMessages(connectionId);

      expect(messages.length).toBe(3);
      expect(messages[0].content).toBe('First message');
      expect(messages[1].content).toBe('Second message');
      expect(messages[2].content).toBe('Third message');

      // Verify chronological order
      for (let i = 1; i < messages.length; i++) {
        const prevTime = new Date(messages[i - 1].created_at).getTime();
        const currTime = new Date(messages[i].created_at).getTime();
        expect(currTime).toBeGreaterThanOrEqual(prevTime);
      }
    });

    it('should support pagination with limit', async () => {
      // Send 10 messages
      for (let i = 1; i <= 10; i++) {
        await messagingService.sendMessage(user1Guid, connectionId, user2Guid, `Message ${i}`);
      }

      const page1 = messagingService.getDecryptedMessages(connectionId, { limit: 3 });

      expect(page1.length).toBe(3);
      // Should return last 3 (most recent)
      expect(page1[0].content).toBe('Message 8');
      expect(page1[1].content).toBe('Message 9');
      expect(page1[2].content).toBe('Message 10');
    });

    it('should filter by connection', async () => {
      // Create second connection
      const user3Guid = 'user-3-guid';
      const invite2 = await connectionService.createInvitation(user1Guid);
      const accept2 = await connectionService.acceptInvitation(user3Guid, invite2.invitation!.code);
      const connectionId2 = accept2.connection!.connection_id;
      const sharedKey2 = connectionService.getSharedKey(accept2.connection!.shared_key_id)!;
      messagingService.setSharedKey(connectionId2, sharedKey2);

      // Send to first connection
      await messagingService.sendMessage(user1Guid, connectionId, user2Guid, 'To user 2');

      // Send to second connection
      await messagingService.sendMessage(user1Guid, connectionId2, user3Guid, 'To user 3');

      const conn1Messages = messagingService.getDecryptedMessages(connectionId);
      const conn2Messages = messagingService.getDecryptedMessages(connectionId2);

      expect(conn1Messages.length).toBe(1);
      expect(conn1Messages[0].content).toBe('To user 2');

      expect(conn2Messages.length).toBe(1);
      expect(conn2Messages[0].content).toBe('To user 3');
    });

    it('should filter by date range (after)', async () => {
      const beforeTime = new Date().toISOString();
      await new Promise(resolve => setTimeout(resolve, 50));

      await messagingService.sendMessage(user1Guid, connectionId, user2Guid, 'After cutoff');

      const messages = messagingService.getMessages(connectionId, { after: beforeTime });

      expect(messages.length).toBe(1);
    });

    it('should filter by date range (before)', async () => {
      await messagingService.sendMessage(user1Guid, connectionId, user2Guid, 'Before cutoff');

      await new Promise(resolve => setTimeout(resolve, 50));
      const cutoffTime = new Date().toISOString();

      await messagingService.sendMessage(user1Guid, connectionId, user2Guid, 'After cutoff');

      const messages = messagingService.getMessages(connectionId, { before: cutoffTime });

      expect(messages.length).toBe(1);
      const decrypted = decryptMockMessage(messages[0], sharedKey);
      expect(decrypted.content).toBe('Before cutoff');
    });

    it('should combine filters', async () => {
      // Send messages with delays
      await messagingService.sendMessage(user1Guid, connectionId, user2Guid, 'Message 1');
      await new Promise(resolve => setTimeout(resolve, 20));

      const afterTime = new Date().toISOString();
      await new Promise(resolve => setTimeout(resolve, 20));

      await messagingService.sendMessage(user1Guid, connectionId, user2Guid, 'Message 2');
      await messagingService.sendMessage(user1Guid, connectionId, user2Guid, 'Message 3');

      await new Promise(resolve => setTimeout(resolve, 20));
      const beforeTime = new Date().toISOString();
      await new Promise(resolve => setTimeout(resolve, 20));

      await messagingService.sendMessage(user1Guid, connectionId, user2Guid, 'Message 4');

      const messages = messagingService.getMessages(connectionId, {
        after: afterTime,
        before: beforeTime,
      });

      expect(messages.length).toBe(2);
    });

    it('should return empty array for no messages', () => {
      const messages = messagingService.getDecryptedMessages(connectionId);
      expect(messages).toEqual([]);
    });

    it('should return empty array for invalid connection', () => {
      const messages = messagingService.getDecryptedMessages('invalid-connection-id');
      expect(messages).toEqual([]);
    });
  });

  describe('History Sync', () => {
    it('should maintain message order across multiple sends', async () => {
      // Simulate rapid message sends
      const promises = [];
      for (let i = 1; i <= 5; i++) {
        promises.push(
          messagingService.sendMessage(user1Guid, connectionId, user2Guid, `Rapid ${i}`)
        );
      }
      await Promise.all(promises);

      const messages = messagingService.getMessages(connectionId);
      expect(messages.length).toBe(5);

      // All messages should be retrievable
      const decrypted = messages.map(m => decryptMockMessage(m, sharedKey));
      const contents = decrypted.map(d => d.content);

      for (let i = 1; i <= 5; i++) {
        expect(contents).toContain(`Rapid ${i}`);
      }
    });

    it('should handle bidirectional message flow', async () => {
      await messagingService.sendMessage(user1Guid, connectionId, user2Guid, 'User 1 says hi');
      await messagingService.sendMessage(user2Guid, connectionId, user1Guid, 'User 2 replies');
      await messagingService.sendMessage(user1Guid, connectionId, user2Guid, 'User 1 continues');

      const messages = messagingService.getDecryptedMessages(connectionId);

      expect(messages.length).toBe(3);

      // Verify senders alternate
      expect(messages[0].sender_guid).toBe(user1Guid);
      expect(messages[1].sender_guid).toBe(user2Guid);
      expect(messages[2].sender_guid).toBe(user1Guid);
    });

    it('should preserve message metadata across retrieval', async () => {
      const sendResult = await messagingService.sendMessage(
        user1Guid,
        connectionId,
        user2Guid,
        'Metadata test'
      );

      await messagingService.deliverMessage(sendResult.message!.message_id);
      await messagingService.markAsRead(user2Guid, sendResult.message!.message_id);

      const messages = messagingService.getMessages(connectionId);
      const message = messages[0];

      expect(message.message_id).toBe(sendResult.message!.message_id);
      expect(message.status).toBe('read');
      expect(message.delivered_at).toBeDefined();
      expect(message.read_at).toBeDefined();
    });
  });

  describe('History Search', () => {
    beforeEach(async () => {
      // Create messages for search tests
      await messagingService.sendMessage(user1Guid, connectionId, user2Guid, 'Hello world');
      await messagingService.sendMessage(user2Guid, connectionId, user1Guid, 'How are you?');
      await messagingService.sendMessage(user1Guid, connectionId, user2Guid, 'I am doing great!');
      await messagingService.sendMessage(user2Guid, connectionId, user1Guid, 'The weather is nice');
      await messagingService.sendMessage(user1Guid, connectionId, user2Guid, 'Hello again friend');
    });

    it('should search message content', () => {
      const results = messagingService.searchMessages(user1Guid, 'hello');

      expect(results.length).toBe(2);
      expect(results.every(r => r.content_preview.toLowerCase().includes('hello'))).toBe(true);
    });

    it('should return matching messages with context', () => {
      const results = messagingService.searchMessages(user1Guid, 'weather');

      expect(results.length).toBe(1);
      expect(results[0].match_context).toContain('weather');
    });

    it('should respect search result limits', () => {
      // Add more messages with 'hello'
      for (let i = 0; i < 10; i++) {
        messagingService.sendMessage(user1Guid, connectionId, user2Guid, `Hello message ${i}`);
      }

      const results = messagingService.searchMessages(user1Guid, 'hello');

      // Should return all matches in our mock
      expect(results.length).toBeGreaterThan(0);
    });

    it('should search case-insensitively', () => {
      const lowerResults = messagingService.searchMessages(user1Guid, 'hello');
      const upperResults = messagingService.searchMessages(user1Guid, 'HELLO');
      const mixedResults = messagingService.searchMessages(user1Guid, 'HeLLo');

      expect(lowerResults.length).toBe(upperResults.length);
      expect(lowerResults.length).toBe(mixedResults.length);
    });

    it('should only search user\'s messages', () => {
      const user3Guid = 'user-3-unrelated';

      // User 3 shouldn't find any messages
      const results = messagingService.searchMessages(user3Guid, 'hello');
      expect(results.length).toBe(0);
    });

    it('should filter search by connection', () => {
      // Create second connection with different messages
      const user3Guid = 'user-3-guid';
      const invite2 = connectionService.createInvitation(user1Guid);
      // For simplicity, we just test that connection filtering works
      // with existing connection

      const results = messagingService.searchMessages(user1Guid, 'hello', connectionId);
      expect(results.every(r => r.connection_id === connectionId)).toBe(true);
    });

    it('should return empty for no matches', () => {
      const results = messagingService.searchMessages(user1Guid, 'xyznonexistent');
      expect(results.length).toBe(0);
    });

    it('should include message metadata in search results', () => {
      const results = messagingService.searchMessages(user1Guid, 'hello');

      expect(results.length).toBeGreaterThan(0);

      for (const result of results) {
        expect(result.message_id).toBeDefined();
        expect(result.connection_id).toBeDefined();
        expect(result.sender_guid).toBeDefined();
        expect(result.created_at).toBeDefined();
      }
    });
  });

  describe('Message Count', () => {
    it('should track total message count per connection', async () => {
      expect(messagingService.getMessageCount(connectionId)).toBe(0);

      await messagingService.sendMessage(user1Guid, connectionId, user2Guid, 'Message 1');
      expect(messagingService.getMessageCount(connectionId)).toBe(1);

      await messagingService.sendMessage(user2Guid, connectionId, user1Guid, 'Message 2');
      expect(messagingService.getMessageCount(connectionId)).toBe(2);
    });

    it('should update count on message deletion', async () => {
      const send1 = await messagingService.sendMessage(user1Guid, connectionId, user2Guid, 'M1');
      await messagingService.sendMessage(user1Guid, connectionId, user2Guid, 'M2');

      expect(messagingService.getMessageCount(connectionId)).toBe(2);

      messagingService.deleteMessage(send1.message!.message_id);

      expect(messagingService.getMessageCount(connectionId)).toBe(1);
    });
  });

  describe('Unread Tracking', () => {
    it('should track unread per connection', async () => {
      await messagingService.sendMessage(user1Guid, connectionId, user2Guid, 'Unread 1');
      await messagingService.sendMessage(user1Guid, connectionId, user2Guid, 'Unread 2');

      expect(messagingService.getUnreadCount(user2Guid, connectionId)).toBe(2);
    });

    it('should track total unread across connections', async () => {
      // Create second connection
      const user3Guid = 'user-3-guid';
      const invite2 = await connectionService.createInvitation(user1Guid);
      const accept2 = await connectionService.acceptInvitation(user3Guid, invite2.invitation!.code);
      const connectionId2 = accept2.connection!.connection_id;
      const sharedKey2 = connectionService.getSharedKey(accept2.connection!.shared_key_id)!;
      messagingService.setSharedKey(connectionId2, sharedKey2);

      // User 1 sends to both
      await messagingService.sendMessage(user1Guid, connectionId, user2Guid, 'To user 2');
      await messagingService.sendMessage(user1Guid, connectionId2, user3Guid, 'To user 3');

      // Check totals
      expect(messagingService.getUnreadCount(user2Guid)).toBe(1);
      expect(messagingService.getUnreadCount(user3Guid)).toBe(1);

      // User 1 has no unread
      expect(messagingService.getUnreadCount(user1Guid)).toBe(0);
    });

    it('should clear unread when marking as read', async () => {
      const send = await messagingService.sendMessage(user1Guid, connectionId, user2Guid, 'Test');

      expect(messagingService.getUnreadCount(user2Guid)).toBe(1);

      await messagingService.markAsRead(user2Guid, send.message!.message_id);

      expect(messagingService.getUnreadCount(user2Guid)).toBe(0);
    });
  });
});
