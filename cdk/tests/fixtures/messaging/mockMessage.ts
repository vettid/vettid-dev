/**
 * Mock Messaging Fixtures
 *
 * Provides mock utilities for encrypted messaging testing:
 * - Message encryption with XChaCha20-Poly1305
 * - Message decryption and verification
 * - Message history management
 * - Read receipts and delivery tracking
 *
 * @see lambda/handlers/messaging/ (pending implementation)
 */

import * as crypto from 'crypto';

// ============================================
// Types
// ============================================

export interface EncryptedMessage {
  message_id: string;
  connection_id: string;
  sender_guid: string;
  recipient_guid: string;
  encrypted_content: string; // Base64 encoded
  nonce: string; // Base64 encoded (24 bytes for XChaCha20)
  content_type: 'text' | 'image' | 'file' | 'profile_update';
  created_at: string;
  delivered_at?: string;
  read_at?: string;
  status: 'pending' | 'sent' | 'delivered' | 'read' | 'failed';
}

export interface DecryptedMessage {
  message_id: string;
  connection_id: string;
  sender_guid: string;
  recipient_guid: string;
  content: string;
  content_type: 'text' | 'image' | 'file' | 'profile_update';
  created_at: string;
  delivered_at?: string;
  read_at?: string;
  status: 'pending' | 'sent' | 'delivered' | 'read' | 'failed';
}

export interface MessageChunk {
  chunk_id: string;
  message_id: string;
  chunk_index: number; // Alias for sequence
  sequence: number;
  total_chunks: number;
  encrypted_data: string;
  nonce: string;
}

export interface DeliveryReceipt {
  receipt_id: string;
  message_id: string;
  recipient_guid: string;
  status: 'delivered' | 'read';
  timestamp: string;
}

export interface MessageSearchResult {
  message_id: string;
  connection_id: string;
  content_preview: string;
  sender_guid: string;
  created_at: string;
  match_context: string;
}

// ============================================
// Encryption Constants
// ============================================

const XCHACHA20_NONCE_LENGTH = 24;
const POLY1305_TAG_LENGTH = 16;
const MAX_MESSAGE_SIZE = 64 * 1024; // 64KB
const CHUNK_SIZE = 16 * 1024; // 16KB chunks for large messages

// ============================================
// Encryption Functions
// ============================================

/**
 * Encrypt message content using XChaCha20-Poly1305
 * Note: Node.js doesn't have native XChaCha20, so we simulate with ChaCha20-Poly1305
 * In production, use libsodium or similar library
 */
export function encryptMessage(
  content: string,
  sharedKey: Buffer
): { ciphertext: Buffer; nonce: Buffer; authTag: Buffer } {
  // Generate 24-byte nonce for XChaCha20 (simulated with 12+12)
  const nonce = crypto.randomBytes(XCHACHA20_NONCE_LENGTH);

  // For simulation, use first 12 bytes as IV for chacha20-poly1305
  const iv = nonce.slice(0, 12);

  const cipher = crypto.createCipheriv('chacha20-poly1305', sharedKey, iv, {
    authTagLength: POLY1305_TAG_LENGTH,
  });

  const plaintext = Buffer.from(content, 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return { ciphertext, nonce, authTag };
}

/**
 * Decrypt message content using XChaCha20-Poly1305
 */
export function decryptMessage(
  ciphertext: Buffer,
  nonce: Buffer,
  authTag: Buffer,
  sharedKey: Buffer
): string {
  const iv = nonce.slice(0, 12);

  const decipher = crypto.createDecipheriv('chacha20-poly1305', sharedKey, iv, {
    authTagLength: POLY1305_TAG_LENGTH,
  });
  decipher.setAuthTag(authTag);

  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plaintext.toString('utf8');
}

/**
 * Encrypt and package message for transmission
 */
export function packageEncryptedMessage(
  content: string,
  sharedKey: Buffer
): { encryptedContent: string; nonce: string } {
  const { ciphertext, nonce, authTag } = encryptMessage(content, sharedKey);

  // Combine ciphertext and auth tag
  const combined = Buffer.concat([ciphertext, authTag]);

  return {
    encryptedContent: combined.toString('base64'),
    nonce: nonce.toString('base64'),
  };
}

/**
 * Unpackage and decrypt message
 */
export function unpackageDecryptedMessage(
  encryptedContent: string,
  nonceBase64: string,
  sharedKey: Buffer
): string {
  const combined = Buffer.from(encryptedContent, 'base64');
  const nonce = Buffer.from(nonceBase64, 'base64');

  // Split ciphertext and auth tag
  const ciphertext = combined.slice(0, -POLY1305_TAG_LENGTH);
  const authTag = combined.slice(-POLY1305_TAG_LENGTH);

  return decryptMessage(ciphertext, nonce, authTag, sharedKey);
}

// ============================================
// Message Chunking
// ============================================

/**
 * Split large message into encrypted chunks
 */
export function chunkMessage(
  content: string,
  messageId: string,
  sharedKey: Buffer
): MessageChunk[] {
  const data = Buffer.from(content, 'utf8');
  const chunks: MessageChunk[] = [];
  const totalChunks = Math.ceil(data.length / CHUNK_SIZE);

  for (let i = 0; i < totalChunks; i++) {
    const start = i * CHUNK_SIZE;
    const end = Math.min(start + CHUNK_SIZE, data.length);
    const chunkData = data.slice(start, end);

    const { ciphertext, nonce, authTag } = encryptMessage(chunkData.toString('utf8'), sharedKey);
    const combined = Buffer.concat([ciphertext, authTag]);

    chunks.push({
      chunk_id: `${messageId}-chunk-${i}`,
      message_id: messageId,
      chunk_index: i,
      sequence: i,
      total_chunks: totalChunks,
      encrypted_data: combined.toString('base64'),
      nonce: nonce.toString('base64'),
    });
  }

  return chunks;
}

/**
 * Reassemble message from chunks
 */
export function reassembleMessage(chunks: MessageChunk[], sharedKey: Buffer): string {
  if (chunks.length === 0) {
    throw new Error('No chunks to reassemble');
  }

  // Validate we have all chunks
  const totalChunks = chunks[0].total_chunks;
  if (chunks.length !== totalChunks) {
    throw new Error(`Missing chunks: got ${chunks.length}, expected ${totalChunks}`);
  }

  // Sort by sequence
  const sorted = [...chunks].sort((a, b) => a.sequence - b.sequence);

  // Verify sequence integrity
  for (let i = 0; i < sorted.length; i++) {
    if (sorted[i].sequence !== i) {
      throw new Error(`Missing chunk at sequence ${i}`);
    }
  }

  const decryptedParts: string[] = [];
  for (const chunk of sorted) {
    const decrypted = unpackageDecryptedMessage(chunk.encrypted_data, chunk.nonce, sharedKey);
    decryptedParts.push(decrypted);
  }

  return decryptedParts.join('');
}

// ============================================
// Mock Message Factory
// ============================================

export interface CreateMessageOptions {
  senderId: string;
  recipientId: string;
  connectionId: string;
  content: string;
  contentType?: 'text' | 'image' | 'file' | 'profile_update';
  sharedKey: Buffer;
}

/**
 * Create a mock encrypted message
 */
export function createMockMessage(options: CreateMessageOptions): EncryptedMessage {
  const messageId = crypto.randomUUID();
  const { encryptedContent, nonce } = packageEncryptedMessage(options.content, options.sharedKey);

  return {
    message_id: messageId,
    connection_id: options.connectionId,
    sender_guid: options.senderId,
    recipient_guid: options.recipientId,
    encrypted_content: encryptedContent,
    nonce,
    content_type: options.contentType || 'text',
    created_at: new Date().toISOString(),
    status: 'pending',
  };
}

/**
 * Decrypt a mock message
 */
export function decryptMockMessage(
  message: EncryptedMessage,
  sharedKey: Buffer
): DecryptedMessage {
  const content = unpackageDecryptedMessage(message.encrypted_content, message.nonce, sharedKey);

  return {
    message_id: message.message_id,
    connection_id: message.connection_id,
    sender_guid: message.sender_guid,
    recipient_guid: message.recipient_guid,
    content,
    content_type: message.content_type,
    created_at: message.created_at,
    delivered_at: message.delivered_at,
    read_at: message.read_at,
    status: message.status,
  };
}

// ============================================
// Mock Messaging Service
// ============================================

export class MockMessagingService {
  private messages: Map<string, EncryptedMessage> = new Map();
  private messagesByConnection: Map<string, string[]> = new Map(); // connection_id -> message_ids
  private userUnread: Map<string, Map<string, number>> = new Map(); // user_guid -> (connection_id -> count)
  private sharedKeys: Map<string, Buffer> = new Map(); // connection_id -> shared_key
  private messageQueue: Map<string, EncryptedMessage[]> = new Map(); // recipient_guid -> queued messages

  /**
   * Set shared key for a connection
   */
  setSharedKey(connectionId: string, sharedKey: Buffer): void {
    this.sharedKeys.set(connectionId, sharedKey);
  }

  /**
   * Get shared key for a connection
   */
  getSharedKey(connectionId: string): Buffer | undefined {
    return this.sharedKeys.get(connectionId);
  }

  /**
   * Send a message
   */
  async sendMessage(
    senderId: string,
    connectionId: string,
    recipientId: string,
    content: string,
    contentType: 'text' | 'image' | 'file' | 'profile_update' = 'text'
  ): Promise<{ success: boolean; message?: EncryptedMessage; error?: string }> {
    // Validate content size
    if (Buffer.from(content).length > MAX_MESSAGE_SIZE) {
      return { success: false, error: `Message exceeds maximum size of ${MAX_MESSAGE_SIZE} bytes` };
    }

    // Get shared key
    const sharedKey = this.sharedKeys.get(connectionId);
    if (!sharedKey) {
      return { success: false, error: 'Connection key not found' };
    }

    // Create encrypted message
    const message = createMockMessage({
      senderId,
      recipientId,
      connectionId,
      content,
      contentType,
      sharedKey,
    });

    // Store message
    this.messages.set(message.message_id, message);
    this.addMessageToConnection(connectionId, message.message_id);

    // Update status
    message.status = 'sent';

    // Increment unread count for recipient
    this.incrementUnread(recipientId, connectionId);

    return { success: true, message };
  }

  /**
   * Add message to connection index
   */
  private addMessageToConnection(connectionId: string, messageId: string): void {
    let messages = this.messagesByConnection.get(connectionId);
    if (!messages) {
      messages = [];
      this.messagesByConnection.set(connectionId, messages);
    }
    messages.push(messageId);
  }

  /**
   * Increment unread count
   */
  private incrementUnread(userGuid: string, connectionId: string): void {
    let userUnreads = this.userUnread.get(userGuid);
    if (!userUnreads) {
      userUnreads = new Map();
      this.userUnread.set(userGuid, userUnreads);
    }
    const current = userUnreads.get(connectionId) || 0;
    userUnreads.set(connectionId, current + 1);
  }

  /**
   * Receive/deliver a message
   */
  async deliverMessage(
    messageId: string
  ): Promise<{ success: boolean; error?: string }> {
    const message = this.messages.get(messageId);
    if (!message) {
      return { success: false, error: 'Message not found' };
    }

    message.status = 'delivered';
    message.delivered_at = new Date().toISOString();

    return { success: true };
  }

  /**
   * Mark message as read
   */
  async markAsRead(
    userGuid: string,
    messageId: string
  ): Promise<{ success: boolean; error?: string }> {
    const message = this.messages.get(messageId);
    if (!message) {
      return { success: false, error: 'Message not found' };
    }

    if (message.recipient_guid !== userGuid) {
      return { success: false, error: 'Not the recipient of this message' };
    }

    message.status = 'read';
    message.read_at = new Date().toISOString();

    // Decrement unread count
    const userUnreads = this.userUnread.get(userGuid);
    if (userUnreads) {
      const current = userUnreads.get(message.connection_id) || 0;
      if (current > 0) {
        userUnreads.set(message.connection_id, current - 1);
      }
    }

    return { success: true };
  }

  /**
   * Get messages for a connection
   */
  getMessages(
    connectionId: string,
    options: { limit?: number; before?: string; after?: string } = {}
  ): EncryptedMessage[] {
    const messageIds = this.messagesByConnection.get(connectionId) || [];
    let messages = messageIds
      .map(id => this.messages.get(id))
      .filter((m): m is EncryptedMessage => m !== undefined)
      .sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime());

    // Apply filters
    if (options.after) {
      const afterTime = new Date(options.after).getTime();
      messages = messages.filter(m => new Date(m.created_at).getTime() > afterTime);
    }

    if (options.before) {
      const beforeTime = new Date(options.before).getTime();
      messages = messages.filter(m => new Date(m.created_at).getTime() < beforeTime);
    }

    if (options.limit) {
      messages = messages.slice(-options.limit);
    }

    return messages;
  }

  /**
   * Get decrypted messages for a connection
   */
  getDecryptedMessages(
    connectionId: string,
    options: { limit?: number; before?: string; after?: string } = {}
  ): DecryptedMessage[] {
    const sharedKey = this.sharedKeys.get(connectionId);
    if (!sharedKey) {
      return [];
    }

    const messages = this.getMessages(connectionId, options);
    return messages.map(m => decryptMockMessage(m, sharedKey));
  }

  /**
   * Get unread count for user
   */
  getUnreadCount(userGuid: string, connectionId?: string): number {
    const userUnreads = this.userUnread.get(userGuid);
    if (!userUnreads) return 0;

    if (connectionId) {
      return userUnreads.get(connectionId) || 0;
    }

    // Total across all connections
    let total = 0;
    for (const count of userUnreads.values()) {
      total += count;
    }
    return total;
  }

  /**
   * Search messages
   */
  searchMessages(
    userGuid: string,
    query: string,
    connectionId?: string
  ): MessageSearchResult[] {
    const results: MessageSearchResult[] = [];
    const searchLower = query.toLowerCase();

    for (const message of this.messages.values()) {
      // Check if user is sender or recipient
      if (message.sender_guid !== userGuid && message.recipient_guid !== userGuid) {
        continue;
      }

      // Filter by connection if specified
      if (connectionId && message.connection_id !== connectionId) {
        continue;
      }

      // Try to decrypt and search
      const sharedKey = this.sharedKeys.get(message.connection_id);
      if (!sharedKey) continue;

      try {
        const decrypted = decryptMockMessage(message, sharedKey);
        if (decrypted.content.toLowerCase().includes(searchLower)) {
          // Find match position for context
          const pos = decrypted.content.toLowerCase().indexOf(searchLower);
          const start = Math.max(0, pos - 20);
          const end = Math.min(decrypted.content.length, pos + query.length + 20);

          results.push({
            message_id: message.message_id,
            connection_id: message.connection_id,
            content_preview: decrypted.content.slice(0, 100),
            sender_guid: message.sender_guid,
            created_at: message.created_at,
            match_context: decrypted.content.slice(start, end),
          });
        }
      } catch {
        // Skip if decryption fails
      }
    }

    return results;
  }

  /**
   * Queue message for offline recipient
   */
  queueMessage(message: EncryptedMessage): void {
    let queue = this.messageQueue.get(message.recipient_guid);
    if (!queue) {
      queue = [];
      this.messageQueue.set(message.recipient_guid, queue);
    }
    queue.push(message);
  }

  /**
   * Get queued messages for user
   */
  getQueuedMessages(userGuid: string): EncryptedMessage[] {
    return this.messageQueue.get(userGuid) || [];
  }

  /**
   * Clear queued messages for user
   */
  clearQueue(userGuid: string): void {
    this.messageQueue.delete(userGuid);
  }

  /**
   * Get message by ID
   */
  getMessage(messageId: string): EncryptedMessage | undefined {
    return this.messages.get(messageId);
  }

  /**
   * Delete message
   */
  deleteMessage(messageId: string): boolean {
    const message = this.messages.get(messageId);
    if (!message) return false;

    // Remove from connection index
    const connectionMessages = this.messagesByConnection.get(message.connection_id);
    if (connectionMessages) {
      const index = connectionMessages.indexOf(messageId);
      if (index >= 0) {
        connectionMessages.splice(index, 1);
      }
    }

    this.messages.delete(messageId);
    return true;
  }

  /**
   * Get message count for connection
   */
  getMessageCount(connectionId: string): number {
    return (this.messagesByConnection.get(connectionId) || []).length;
  }

  /**
   * Clear all state
   */
  clear(): void {
    this.messages.clear();
    this.messagesByConnection.clear();
    this.userUnread.clear();
    this.sharedKeys.clear();
    this.messageQueue.clear();
  }
}

// ============================================
// Mock Profile Service
// ============================================

export interface Profile {
  user_guid: string;
  display_name: string;
  bio?: string;
  avatar_url?: string;
  location?: string;
  visibility: 'connections' | 'public' | 'private';
  version: number;
  last_updated: string;
}

export class MockProfileService {
  private profiles: Map<string, Profile> = new Map();
  private connections: Map<string, Set<string>> = new Map(); // user_guid -> Set of connected user_guids

  /**
   * Create a new profile
   */
  createProfile(
    userGuid: string,
    options: {
      display_name: string;
      bio?: string;
      avatar_url?: string;
      location?: string;
      visibility?: 'connections' | 'public' | 'private';
    }
  ): Profile {
    const profile: Profile = {
      user_guid: userGuid,
      display_name: options.display_name,
      bio: options.bio,
      avatar_url: options.avatar_url,
      location: options.location,
      visibility: options.visibility || 'connections',
      version: 1,
      last_updated: new Date().toISOString(),
    };
    this.profiles.set(userGuid, profile);
    return profile;
  }

  /**
   * Get a profile
   */
  getProfile(userGuid: string): Profile | undefined {
    return this.profiles.get(userGuid);
  }

  /**
   * Update a profile
   */
  updateProfile(
    userGuid: string,
    updates: Partial<Omit<Profile, 'user_guid' | 'version' | 'last_updated'>>
  ): Profile | undefined {
    const profile = this.profiles.get(userGuid);
    if (!profile) return undefined;

    const updated: Profile = {
      ...profile,
      ...updates,
      version: profile.version + 1,
      last_updated: new Date().toISOString(),
    };
    this.profiles.set(userGuid, updated);
    return updated;
  }

  /**
   * Register a connection between two users
   */
  registerConnection(userGuid1: string, userGuid2: string): void {
    // Add user2 to user1's connections
    let conns1 = this.connections.get(userGuid1);
    if (!conns1) {
      conns1 = new Set();
      this.connections.set(userGuid1, conns1);
    }
    conns1.add(userGuid2);

    // Add user1 to user2's connections
    let conns2 = this.connections.get(userGuid2);
    if (!conns2) {
      conns2 = new Set();
      this.connections.set(userGuid2, conns2);
    }
    conns2.add(userGuid1);
  }

  /**
   * Get visible profile based on visibility settings and connection status
   */
  getVisibleProfile(profileOwnerGuid: string, viewerGuid: string): Profile | null {
    const profile = this.profiles.get(profileOwnerGuid);
    if (!profile) return null;

    // Owner can always see their own profile
    if (profileOwnerGuid === viewerGuid) {
      return profile;
    }

    switch (profile.visibility) {
      case 'public':
        return profile;
      case 'connections':
        const connections = this.connections.get(profileOwnerGuid);
        if (connections?.has(viewerGuid)) {
          return profile;
        }
        return null;
      case 'private':
        return null;
      default:
        return null;
    }
  }

  /**
   * Clear all state
   */
  clear(): void {
    this.profiles.clear();
    this.connections.clear();
  }
}

// ============================================
// Export singletons for tests
// ============================================

export const mockMessagingService = new MockMessagingService();
export const mockProfileService = new MockProfileService();
