/**
 * E2E Tests: Messaging Flow
 *
 * End-to-end tests for complete messaging scenarios:
 * - Encrypted conversation lifecycle
 * - Message delivery with read receipts
 * - Large message handling with chunking
 * - Search across conversations
 * - Message retention and cleanup
 *
 * @see lambda/handlers/messaging/ (pending implementation)
 */

import {
  MockConnectionService,
} from '../../fixtures/connections/mockConnection';
import {
  MockMessagingService,
  MockProfileService,
  encryptMessage,
  decryptMessage,
  packageEncryptedMessage,
  unpackageDecryptedMessage,
  chunkMessage,
  reassembleMessage,
  decryptMockMessage,
} from '../../fixtures/messaging/mockMessage';
import * as crypto from 'crypto';

// ============================================
// E2E Messaging Flow Tests
// ============================================

describe('Messaging Flow E2E', () => {
  let connectionService: MockConnectionService;
  let messagingService: MockMessagingService;
  let profileService: MockProfileService;

  beforeEach(() => {
    connectionService = new MockConnectionService();
    messagingService = new MockMessagingService();
    profileService = new MockProfileService();
  });

  afterEach(() => {
    connectionService.clear();
    messagingService.clear();
    profileService.clear();
  });

  describe('Complete Conversation Lifecycle', () => {
    it('should handle full conversation: create → exchange → read receipts → search → delete', async () => {
      const alice = 'alice-123';
      const bob = 'bob-456';

      // Step 1: Establish connection
      const invite = await connectionService.createInvitation(alice);
      const accept = await connectionService.acceptInvitation(bob, invite.invitation!.code);
      const connectionId = accept.connection!.connection_id;
      const sharedKey = connectionService.getSharedKey(accept.connection!.shared_key_id)!;
      messagingService.setSharedKey(connectionId, sharedKey);

      // Step 2: Alice initiates conversation
      const msg1 = await messagingService.sendMessage(alice, connectionId, bob, 'Hey Bob!');
      expect(msg1.success).toBe(true);
      expect(msg1.message?.status).toBe('sent');

      // Step 3: Bob receives and reads
      await messagingService.deliverMessage(msg1.message!.message_id);
      await messagingService.markAsRead(bob, msg1.message!.message_id);

      // Verify read receipt
      const updatedMsg1 = messagingService.getMessage(msg1.message!.message_id);
      expect(updatedMsg1?.status).toBe('read');
      expect(updatedMsg1?.read_at).toBeDefined();

      // Step 4: Bob replies
      const msg2 = await messagingService.sendMessage(bob, connectionId, alice, 'Hey Alice!');
      expect(msg2.success).toBe(true);

      // Step 5: Conversation continues
      await messagingService.sendMessage(alice, connectionId, bob, 'How was your weekend?');
      await messagingService.sendMessage(bob, connectionId, alice, 'Great! Went hiking.');
      await messagingService.sendMessage(alice, connectionId, bob, 'Nice! I love hiking too.');

      // Step 6: Search conversation
      const searchResults = messagingService.searchMessages(alice, 'hiking');
      expect(searchResults.length).toBe(2);

      // Step 7: Delete a message
      const messages = messagingService.getMessages(connectionId);
      const initialCount = messages.length;
      messagingService.deleteMessage(messages[0].message_id);

      // Verify deletion
      const remainingMessages = messagingService.getMessages(connectionId);
      expect(remainingMessages.length).toBe(initialCount - 1);
    });

    it('should handle real-time message delivery simulation', async () => {
      const user1 = 'user-1';
      const user2 = 'user-2';

      // Establish connection
      const invite = await connectionService.createInvitation(user1);
      const accept = await connectionService.acceptInvitation(user2, invite.invitation!.code);
      const connectionId = accept.connection!.connection_id;
      const sharedKey = connectionService.getSharedKey(accept.connection!.shared_key_id)!;
      messagingService.setSharedKey(connectionId, sharedKey);

      // Simulate real-time chat with timestamps
      const chatSequence = [
        { sender: user1, content: 'Hello!', delay: 0 },
        { sender: user2, content: 'Hi there!', delay: 100 },
        { sender: user1, content: 'How are you?', delay: 200 },
        { sender: user2, content: 'Good, thanks!', delay: 300 },
        { sender: user1, content: 'Great to hear!', delay: 400 },
      ];

      const sentMessages: any[] = [];

      for (const chat of chatSequence) {
        await new Promise(resolve => setTimeout(resolve, chat.delay));
        const recipient = chat.sender === user1 ? user2 : user1;
        const result = await messagingService.sendMessage(
          chat.sender,
          connectionId,
          recipient,
          chat.content
        );
        sentMessages.push(result.message);

        // Immediate delivery
        await messagingService.deliverMessage(result.message!.message_id);
      }

      // Verify chronological order
      const history = messagingService.getDecryptedMessages(connectionId);
      expect(history.length).toBe(chatSequence.length);

      for (let i = 1; i < history.length; i++) {
        const prevTime = new Date(history[i - 1].created_at).getTime();
        const currTime = new Date(history[i].created_at).getTime();
        expect(currTime).toBeGreaterThanOrEqual(prevTime);
      }
    });

    it('should track unread counts accurately during conversation', async () => {
      const user1 = 'user-1';
      const user2 = 'user-2';

      // Establish connection
      const invite = await connectionService.createInvitation(user1);
      const accept = await connectionService.acceptInvitation(user2, invite.invitation!.code);
      const connectionId = accept.connection!.connection_id;
      const sharedKey = connectionService.getSharedKey(accept.connection!.shared_key_id)!;
      messagingService.setSharedKey(connectionId, sharedKey);

      // Initial state
      expect(messagingService.getUnreadCount(user1)).toBe(0);
      expect(messagingService.getUnreadCount(user2)).toBe(0);

      // User 1 sends 3 messages
      const sent1 = await messagingService.sendMessage(user1, connectionId, user2, 'Message 1');
      const sent2 = await messagingService.sendMessage(user1, connectionId, user2, 'Message 2');
      const sent3 = await messagingService.sendMessage(user1, connectionId, user2, 'Message 3');

      // User 2 has 3 unread
      expect(messagingService.getUnreadCount(user2)).toBe(3);
      expect(messagingService.getUnreadCount(user1)).toBe(0);

      // User 2 reads first message
      await messagingService.markAsRead(user2, sent1.message!.message_id);
      expect(messagingService.getUnreadCount(user2)).toBe(2);

      // User 2 replies (doesn't affect their unread count)
      await messagingService.sendMessage(user2, connectionId, user1, 'Reply 1');
      expect(messagingService.getUnreadCount(user1)).toBe(1);
      expect(messagingService.getUnreadCount(user2)).toBe(2);

      // User 2 reads remaining messages
      await messagingService.markAsRead(user2, sent2.message!.message_id);
      await messagingService.markAsRead(user2, sent3.message!.message_id);
      expect(messagingService.getUnreadCount(user2)).toBe(0);
    });
  });

  describe('Large Message Handling', () => {
    it('should handle large messages with chunking and reassembly', () => {
      const key = crypto.randomBytes(32);
      const largeContent = 'x'.repeat(100000); // 100KB message
      const messageId = crypto.randomUUID();

      // Chunk the message
      const chunks = chunkMessage(largeContent, messageId, key);
      expect(chunks.length).toBeGreaterThan(1);

      // Each chunk should have metadata
      for (let i = 0; i < chunks.length; i++) {
        expect(chunks[i].chunk_index).toBe(i);
        expect(chunks[i].total_chunks).toBe(chunks.length);
        expect(chunks[i].message_id).toBe(messageId);
      }

      // Reassemble in order
      const reassembled = reassembleMessage(chunks, key);
      expect(reassembled).toBe(largeContent);
    });

    it('should handle out-of-order chunk arrival', () => {
      const key = crypto.randomBytes(32);
      const largeContent = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.repeat(1000);
      const messageId = crypto.randomUUID();

      // Chunk and shuffle
      const chunks = chunkMessage(largeContent, messageId, key);
      const shuffled = [...chunks].sort(() => Math.random() - 0.5);

      // Reassembly should handle out-of-order
      const reassembled = reassembleMessage(shuffled, key);
      expect(reassembled).toBe(largeContent);
    });

    it('should detect missing chunks', () => {
      const key = crypto.randomBytes(32);
      const largeContent = 'x'.repeat(50000);
      const messageId = crypto.randomUUID();

      const chunks = chunkMessage(largeContent, messageId, key);

      // Remove a chunk
      const incomplete = chunks.filter((_, i) => i !== 1);

      // Reassembly should detect missing chunk
      expect(() => {
        reassembleMessage(incomplete, key);
      }).toThrow();
    });

    it('should handle binary content in messages', () => {
      const key = crypto.randomBytes(32);

      // Create binary-like content
      const binaryContent = Buffer.from([
        0x00, 0x01, 0xff, 0xfe, 0x89, 0x50, 0x4e, 0x47
      ]).toString('base64');

      const { encryptedContent, nonce } = packageEncryptedMessage(binaryContent, key);
      const decrypted = unpackageDecryptedMessage(encryptedContent, nonce, key);

      expect(decrypted).toBe(binaryContent);
    });
  });

  describe('Multi-Connection Messaging', () => {
    it('should handle messaging across multiple connections simultaneously', async () => {
      const mainUser = 'main-user';
      const contacts = ['contact-1', 'contact-2', 'contact-3'];
      const connections: Map<string, { connectionId: string; sharedKey: Buffer }> = new Map();

      // Establish connections with all contacts
      for (const contact of contacts) {
        const invite = await connectionService.createInvitation(mainUser);
        const accept = await connectionService.acceptInvitation(contact, invite.invitation!.code);
        const connectionId = accept.connection!.connection_id;
        const sharedKey = connectionService.getSharedKey(accept.connection!.shared_key_id)!;
        messagingService.setSharedKey(connectionId, sharedKey);
        connections.set(contact, { connectionId, sharedKey });
      }

      // Send messages to all contacts
      for (const contact of contacts) {
        const conn = connections.get(contact)!;
        await messagingService.sendMessage(
          mainUser,
          conn.connectionId,
          contact,
          `Hello ${contact}!`
        );
      }

      // Verify each connection has correct messages
      for (const contact of contacts) {
        const conn = connections.get(contact)!;
        const messages = messagingService.getDecryptedMessages(conn.connectionId);
        expect(messages.length).toBe(1);
        expect(messages[0].content).toBe(`Hello ${contact}!`);
        expect(messages[0].recipient_guid).toBe(contact);
      }

      // Total message count
      const allMessages = contacts.reduce((acc, contact) => {
        const conn = connections.get(contact)!;
        return acc + messagingService.getMessageCount(conn.connectionId);
      }, 0);
      expect(allMessages).toBe(contacts.length);
    });

    it('should search across all conversations', async () => {
      const mainUser = 'main-user';
      const contacts = ['contact-1', 'contact-2', 'contact-3'];
      const connections: Map<string, { connectionId: string; sharedKey: Buffer }> = new Map();

      // Establish connections
      for (const contact of contacts) {
        const invite = await connectionService.createInvitation(mainUser);
        const accept = await connectionService.acceptInvitation(contact, invite.invitation!.code);
        const connectionId = accept.connection!.connection_id;
        const sharedKey = connectionService.getSharedKey(accept.connection!.shared_key_id)!;
        messagingService.setSharedKey(connectionId, sharedKey);
        connections.set(contact, { connectionId, sharedKey });
      }

      // Send messages with searchable content
      const conn1 = connections.get('contact-1')!;
      await messagingService.sendMessage(mainUser, conn1.connectionId, 'contact-1', 'Meeting tomorrow at 10am');

      const conn2 = connections.get('contact-2')!;
      await messagingService.sendMessage(mainUser, conn2.connectionId, 'contact-2', 'Project meeting notes');

      const conn3 = connections.get('contact-3')!;
      await messagingService.sendMessage(mainUser, conn3.connectionId, 'contact-3', 'Lunch plans');

      // Search for 'meeting' - should find 2 results
      const meetingResults = messagingService.searchMessages(mainUser, 'meeting');
      expect(meetingResults.length).toBe(2);

      // Search for 'lunch' - should find 1 result
      const lunchResults = messagingService.searchMessages(mainUser, 'lunch');
      expect(lunchResults.length).toBe(1);

      // Search in specific connection
      const conn1Results = messagingService.searchMessages(mainUser, 'meeting', conn1.connectionId);
      expect(conn1Results.length).toBe(1);
    });

    it('should isolate message history between connections', async () => {
      const mainUser = 'main-user';
      const contact1 = 'contact-1';
      const contact2 = 'contact-2';

      // Create two connections
      const invite1 = await connectionService.createInvitation(mainUser);
      const accept1 = await connectionService.acceptInvitation(contact1, invite1.invitation!.code);
      const connectionId1 = accept1.connection!.connection_id;
      const sharedKey1 = connectionService.getSharedKey(accept1.connection!.shared_key_id)!;
      messagingService.setSharedKey(connectionId1, sharedKey1);

      const invite2 = await connectionService.createInvitation(mainUser);
      const accept2 = await connectionService.acceptInvitation(contact2, invite2.invitation!.code);
      const connectionId2 = accept2.connection!.connection_id;
      const sharedKey2 = connectionService.getSharedKey(accept2.connection!.shared_key_id)!;
      messagingService.setSharedKey(connectionId2, sharedKey2);

      // Send private messages to each
      await messagingService.sendMessage(mainUser, connectionId1, contact1, 'Secret for contact 1');
      await messagingService.sendMessage(mainUser, connectionId2, contact2, 'Secret for contact 2');

      // Verify isolation - contact 1 cannot see contact 2's messages
      const conn1Messages = messagingService.getDecryptedMessages(connectionId1);
      const conn2Messages = messagingService.getDecryptedMessages(connectionId2);

      expect(conn1Messages.length).toBe(1);
      expect(conn1Messages[0].content).toBe('Secret for contact 1');

      expect(conn2Messages.length).toBe(1);
      expect(conn2Messages[0].content).toBe('Secret for contact 2');

      // Attempting to decrypt conn1 message with conn2 key should fail
      const rawMessage = messagingService.getMessages(connectionId1)[0];
      expect(() => {
        decryptMockMessage(rawMessage, sharedKey2);
      }).toThrow();
    });
  });

  describe('Message Status Workflow', () => {
    it('should progress through all message statuses', async () => {
      const sender = 'sender';
      const recipient = 'recipient';

      // Establish connection
      const invite = await connectionService.createInvitation(sender);
      const accept = await connectionService.acceptInvitation(recipient, invite.invitation!.code);
      const connectionId = accept.connection!.connection_id;
      const sharedKey = connectionService.getSharedKey(accept.connection!.shared_key_id)!;
      messagingService.setSharedKey(connectionId, sharedKey);

      // Send message - status: sent
      const result = await messagingService.sendMessage(
        sender,
        connectionId,
        recipient,
        'Test message'
      );
      expect(result.message?.status).toBe('sent');

      // Deliver message - status: delivered
      await messagingService.deliverMessage(result.message!.message_id);
      let message = messagingService.getMessage(result.message!.message_id);
      expect(message?.status).toBe('delivered');
      expect(message?.delivered_at).toBeDefined();

      // Mark as read - status: read
      await messagingService.markAsRead(recipient, result.message!.message_id);
      message = messagingService.getMessage(result.message!.message_id);
      expect(message?.status).toBe('read');
      expect(message?.read_at).toBeDefined();
    });

    it('should handle batch read receipts', async () => {
      const sender = 'sender';
      const recipient = 'recipient';

      // Establish connection
      const invite = await connectionService.createInvitation(sender);
      const accept = await connectionService.acceptInvitation(recipient, invite.invitation!.code);
      const connectionId = accept.connection!.connection_id;
      const sharedKey = connectionService.getSharedKey(accept.connection!.shared_key_id)!;
      messagingService.setSharedKey(connectionId, sharedKey);

      // Send multiple messages
      const sentMessages: any[] = [];
      for (let i = 0; i < 5; i++) {
        const result = await messagingService.sendMessage(
          sender,
          connectionId,
          recipient,
          `Message ${i}`
        );
        sentMessages.push(result.message);
      }

      // Verify all unread
      expect(messagingService.getUnreadCount(recipient)).toBe(5);

      // Mark all as read
      for (const msg of sentMessages) {
        await messagingService.markAsRead(recipient, msg.message_id);
      }

      // Verify all read
      expect(messagingService.getUnreadCount(recipient)).toBe(0);

      for (const msg of sentMessages) {
        const message = messagingService.getMessage(msg.message_id);
        expect(message?.status).toBe('read');
      }
    });

    it('should only allow recipient to mark as read', async () => {
      const sender = 'sender';
      const recipient = 'recipient';

      // Establish connection
      const invite = await connectionService.createInvitation(sender);
      const accept = await connectionService.acceptInvitation(recipient, invite.invitation!.code);
      const connectionId = accept.connection!.connection_id;
      const sharedKey = connectionService.getSharedKey(accept.connection!.shared_key_id)!;
      messagingService.setSharedKey(connectionId, sharedKey);

      // Send message
      const result = await messagingService.sendMessage(
        sender,
        connectionId,
        recipient,
        'Test'
      );

      // Sender cannot mark as read
      const senderResult = await messagingService.markAsRead(sender, result.message!.message_id);
      expect(senderResult.success).toBe(false);

      // Random user cannot mark as read
      const randomResult = await messagingService.markAsRead('random-user', result.message!.message_id);
      expect(randomResult.success).toBe(false);

      // Recipient can mark as read
      const recipientResult = await messagingService.markAsRead(recipient, result.message!.message_id);
      expect(recipientResult.success).toBe(true);
    });
  });

  describe('Encryption Integrity', () => {
    it('should maintain encryption integrity across conversation', async () => {
      const user1 = 'user-1';
      const user2 = 'user-2';

      // Establish connection
      const invite = await connectionService.createInvitation(user1);
      const accept = await connectionService.acceptInvitation(user2, invite.invitation!.code);
      const connectionId = accept.connection!.connection_id;
      const sharedKey = connectionService.getSharedKey(accept.connection!.shared_key_id)!;
      messagingService.setSharedKey(connectionId, sharedKey);

      // Send messages with various content
      const testMessages = [
        'Simple text',
        '日本語テスト',
        '🎉🎊🎁🎈🎀',
        'Line 1\nLine 2\nLine 3',
        '{"json": "data", "num": 123}',
      ];

      for (const content of testMessages) {
        await messagingService.sendMessage(user1, connectionId, user2, content);
      }

      // Retrieve and verify all messages
      const decrypted = messagingService.getDecryptedMessages(connectionId);
      expect(decrypted.length).toBe(testMessages.length);

      for (let i = 0; i < testMessages.length; i++) {
        expect(decrypted[i].content).toBe(testMessages[i]);
      }

      // Verify raw messages are encrypted
      const raw = messagingService.getMessages(connectionId);
      for (const msg of raw) {
        // Encrypted content should be base64 and not readable
        expect(msg.encrypted_content).toMatch(/^[A-Za-z0-9+/=]+$/);
        expect(msg.encrypted_content).not.toContain('Simple text');
      }
    });

    it('should use unique nonce for each message', async () => {
      const user1 = 'user-1';
      const user2 = 'user-2';

      // Establish connection
      const invite = await connectionService.createInvitation(user1);
      const accept = await connectionService.acceptInvitation(user2, invite.invitation!.code);
      const connectionId = accept.connection!.connection_id;
      const sharedKey = connectionService.getSharedKey(accept.connection!.shared_key_id)!;
      messagingService.setSharedKey(connectionId, sharedKey);

      // Send identical messages
      const sameContent = 'Same content';
      for (let i = 0; i < 10; i++) {
        await messagingService.sendMessage(user1, connectionId, user2, sameContent);
      }

      // Get raw messages
      const raw = messagingService.getMessages(connectionId);

      // All nonces should be unique
      const nonces = raw.map(m => m.nonce);
      const uniqueNonces = new Set(nonces);
      expect(uniqueNonces.size).toBe(raw.length);

      // All encrypted content should be different (due to unique nonces)
      const encryptedContents = raw.map(m => m.encrypted_content);
      const uniqueContent = new Set(encryptedContents);
      expect(uniqueContent.size).toBe(raw.length);
    });

    it('should detect tampering attempts', async () => {
      const user1 = 'user-1';
      const user2 = 'user-2';

      // Establish connection
      const invite = await connectionService.createInvitation(user1);
      const accept = await connectionService.acceptInvitation(user2, invite.invitation!.code);
      const connectionId = accept.connection!.connection_id;
      const sharedKey = connectionService.getSharedKey(accept.connection!.shared_key_id)!;
      messagingService.setSharedKey(connectionId, sharedKey);

      // Send message
      await messagingService.sendMessage(user1, connectionId, user2, 'Original message');

      // Get raw message
      const raw = messagingService.getMessages(connectionId)[0];

      // Attempt to tamper with encrypted content
      const tamperedContent = Buffer.from(raw.encrypted_content, 'base64');
      tamperedContent[5] ^= 0xff;
      const tamperedMessage = {
        ...raw,
        encrypted_content: tamperedContent.toString('base64'),
      };

      // Decryption should fail
      expect(() => {
        decryptMockMessage(tamperedMessage, sharedKey);
      }).toThrow();

      // Attempt to tamper with nonce
      const tamperedNonce = crypto.randomBytes(24).toString('base64');
      const tamperedMessage2 = {
        ...raw,
        nonce: tamperedNonce,
      };

      expect(() => {
        decryptMockMessage(tamperedMessage2, sharedKey);
      }).toThrow();
    });
  });

  describe('Message Queuing and Offline Scenarios', () => {
    it('should queue messages for offline recipients', async () => {
      const onlineUser = 'online';
      const offlineUser = 'offline';

      // Establish connection
      const invite = await connectionService.createInvitation(onlineUser);
      const accept = await connectionService.acceptInvitation(offlineUser, invite.invitation!.code);
      const connectionId = accept.connection!.connection_id;
      const sharedKey = connectionService.getSharedKey(accept.connection!.shared_key_id)!;
      messagingService.setSharedKey(connectionId, sharedKey);

      // Send messages while offline user is... offline
      const messages: any[] = [];
      for (let i = 0; i < 5; i++) {
        const result = await messagingService.sendMessage(
          onlineUser,
          connectionId,
          offlineUser,
          `Queued message ${i}`
        );
        messagingService.queueMessage(result.message!);
        messages.push(result.message);
      }

      // Check queue
      const queued = messagingService.getQueuedMessages(offlineUser);
      expect(queued.length).toBe(5);

      // Offline user comes online - process queue
      for (const msg of queued) {
        await messagingService.deliverMessage(msg.message_id);
      }
      messagingService.clearQueue(offlineUser);

      // Verify delivered
      const delivered = messagingService.getMessages(connectionId);
      for (const msg of delivered) {
        expect(msg.status).toBe('delivered');
      }
    });

    it('should preserve message order in queue', async () => {
      const onlineUser = 'online';
      const offlineUser = 'offline';

      // Establish connection
      const invite = await connectionService.createInvitation(onlineUser);
      const accept = await connectionService.acceptInvitation(offlineUser, invite.invitation!.code);
      const connectionId = accept.connection!.connection_id;
      const sharedKey = connectionService.getSharedKey(accept.connection!.shared_key_id)!;
      messagingService.setSharedKey(connectionId, sharedKey);

      // Queue messages with delays
      for (let i = 0; i < 5; i++) {
        await new Promise(resolve => setTimeout(resolve, 10));
        const result = await messagingService.sendMessage(
          onlineUser,
          connectionId,
          offlineUser,
          `Message ${i}`
        );
        messagingService.queueMessage(result.message!);
      }

      // Get queued messages
      const queued = messagingService.getQueuedMessages(offlineUser);

      // Verify order is preserved
      const decrypted = queued.map(m => decryptMockMessage(m, sharedKey));
      for (let i = 0; i < decrypted.length; i++) {
        expect(decrypted[i].content).toBe(`Message ${i}`);
      }
    });
  });

  describe('Search Functionality', () => {
    it('should search across message content', async () => {
      const user1 = 'user-1';
      const user2 = 'user-2';

      // Establish connection
      const invite = await connectionService.createInvitation(user1);
      const accept = await connectionService.acceptInvitation(user2, invite.invitation!.code);
      const connectionId = accept.connection!.connection_id;
      const sharedKey = connectionService.getSharedKey(accept.connection!.shared_key_id)!;
      messagingService.setSharedKey(connectionId, sharedKey);

      // Send various messages
      await messagingService.sendMessage(user1, connectionId, user2, 'Hello world');
      await messagingService.sendMessage(user2, connectionId, user1, 'Hello there');
      await messagingService.sendMessage(user1, connectionId, user2, 'Goodbye world');
      await messagingService.sendMessage(user2, connectionId, user1, 'See you later');
      await messagingService.sendMessage(user1, connectionId, user2, 'Hello again');

      // Search tests
      const helloResults = messagingService.searchMessages(user1, 'hello');
      expect(helloResults.length).toBe(3);

      const worldResults = messagingService.searchMessages(user1, 'world');
      expect(worldResults.length).toBe(2);

      const seeResults = messagingService.searchMessages(user1, 'see');
      expect(seeResults.length).toBe(1);
    });

    it('should be case-insensitive', async () => {
      const user1 = 'user-1';
      const user2 = 'user-2';

      // Establish connection
      const invite = await connectionService.createInvitation(user1);
      const accept = await connectionService.acceptInvitation(user2, invite.invitation!.code);
      const connectionId = accept.connection!.connection_id;
      const sharedKey = connectionService.getSharedKey(accept.connection!.shared_key_id)!;
      messagingService.setSharedKey(connectionId, sharedKey);

      await messagingService.sendMessage(user1, connectionId, user2, 'HELLO');
      await messagingService.sendMessage(user1, connectionId, user2, 'Hello');
      await messagingService.sendMessage(user1, connectionId, user2, 'hello');
      await messagingService.sendMessage(user1, connectionId, user2, 'HeLLo');

      const results1 = messagingService.searchMessages(user1, 'hello');
      const results2 = messagingService.searchMessages(user1, 'HELLO');
      const results3 = messagingService.searchMessages(user1, 'HeLLo');

      expect(results1.length).toBe(4);
      expect(results2.length).toBe(4);
      expect(results3.length).toBe(4);
    });

    it('should return search results with context', async () => {
      const user1 = 'user-1';
      const user2 = 'user-2';

      // Establish connection
      const invite = await connectionService.createInvitation(user1);
      const accept = await connectionService.acceptInvitation(user2, invite.invitation!.code);
      const connectionId = accept.connection!.connection_id;
      const sharedKey = connectionService.getSharedKey(accept.connection!.shared_key_id)!;
      messagingService.setSharedKey(connectionId, sharedKey);

      await messagingService.sendMessage(
        user1,
        connectionId,
        user2,
        'The quick brown fox jumps over the lazy dog'
      );

      const results = messagingService.searchMessages(user1, 'fox');
      expect(results.length).toBe(1);
      expect(results[0].match_context).toContain('fox');
      expect(results[0].message_id).toBeDefined();
      expect(results[0].connection_id).toBe(connectionId);
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle empty messages', async () => {
      const user1 = 'user-1';
      const user2 = 'user-2';

      const invite = await connectionService.createInvitation(user1);
      const accept = await connectionService.acceptInvitation(user2, invite.invitation!.code);
      const connectionId = accept.connection!.connection_id;
      const sharedKey = connectionService.getSharedKey(accept.connection!.shared_key_id)!;
      messagingService.setSharedKey(connectionId, sharedKey);

      const result = await messagingService.sendMessage(user1, connectionId, user2, '');
      expect(result.success).toBe(true);

      const messages = messagingService.getDecryptedMessages(connectionId);
      expect(messages[0].content).toBe('');
    });

    it('should handle special characters', async () => {
      const user1 = 'user-1';
      const user2 = 'user-2';

      const invite = await connectionService.createInvitation(user1);
      const accept = await connectionService.acceptInvitation(user2, invite.invitation!.code);
      const connectionId = accept.connection!.connection_id;
      const sharedKey = connectionService.getSharedKey(accept.connection!.shared_key_id)!;
      messagingService.setSharedKey(connectionId, sharedKey);

      const specialContent = '!@#$%^&*()_+-=[]{}|;:\'",.<>?/\\`~';
      const result = await messagingService.sendMessage(user1, connectionId, user2, specialContent);
      expect(result.success).toBe(true);

      const messages = messagingService.getDecryptedMessages(connectionId);
      expect(messages[0].content).toBe(specialContent);
    });

    it('should enforce message size limits', async () => {
      const user1 = 'user-1';
      const user2 = 'user-2';

      const invite = await connectionService.createInvitation(user1);
      const accept = await connectionService.acceptInvitation(user2, invite.invitation!.code);
      const connectionId = accept.connection!.connection_id;
      const sharedKey = connectionService.getSharedKey(accept.connection!.shared_key_id)!;
      messagingService.setSharedKey(connectionId, sharedKey);

      // Oversized message (>64KB)
      const oversized = 'x'.repeat(65 * 1024);
      const result = await messagingService.sendMessage(user1, connectionId, user2, oversized);
      expect(result.success).toBe(false);
      expect(result.error).toContain('exceeds maximum size');
    });

    it('should handle rapid message deletion', async () => {
      const user1 = 'user-1';
      const user2 = 'user-2';

      const invite = await connectionService.createInvitation(user1);
      const accept = await connectionService.acceptInvitation(user2, invite.invitation!.code);
      const connectionId = accept.connection!.connection_id;
      const sharedKey = connectionService.getSharedKey(accept.connection!.shared_key_id)!;
      messagingService.setSharedKey(connectionId, sharedKey);

      // Send messages
      const sentMessages: any[] = [];
      for (let i = 0; i < 10; i++) {
        const result = await messagingService.sendMessage(
          user1,
          connectionId,
          user2,
          `Message ${i}`
        );
        sentMessages.push(result.message);
      }

      // Delete all messages rapidly
      for (const msg of sentMessages) {
        const deleted = messagingService.deleteMessage(msg.message_id);
        expect(deleted).toBe(true);
      }

      // Verify all deleted
      const remaining = messagingService.getMessages(connectionId);
      expect(remaining.length).toBe(0);

      // Double delete should return false
      const doubleDelete = messagingService.deleteMessage(sentMessages[0].message_id);
      expect(doubleDelete).toBe(false);
    });
  });
});
