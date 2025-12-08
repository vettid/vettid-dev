/**
 * Mock Connection Fixtures
 *
 * Provides mock utilities for connection testing:
 * - Connection invitation generation
 * - X25519 key pair generation
 * - Shared key derivation via ECDH
 * - Connection establishment mocking
 *
 * @see lambda/handlers/connections/ (pending implementation)
 */

import * as crypto from 'crypto';

// ============================================
// Types
// ============================================

export interface ConnectionInvitation {
  invitation_id: string;
  code: string;
  creator_guid: string;
  creator_display_name: string;
  creator_avatar_url?: string;
  creator_public_key: string; // Base64 encoded X25519 public key
  created_at: string;
  expires_at: string;
  status: 'pending' | 'accepted' | 'expired' | 'revoked';
  qr_data: string;
  deep_link: string;
  ttl?: number; // DynamoDB TTL
}

export interface Connection {
  connection_id: string;
  owner_guid: string;
  peer_guid: string;
  peer_display_name: string;
  peer_avatar_url?: string;
  peer_public_key: string;
  shared_key_id: string; // Reference to encrypted shared key in vault
  status: 'active' | 'revoked' | 'blocked';
  created_at: string;
  last_message_at?: string;
  unread_count: number;
  profile_version: number;
}

export interface ConnectionKeyPair {
  publicKey: Buffer;
  privateKey: Buffer;
  publicKeyBase64: string;
  privateKeyBase64: string;
}

export interface UserProfile {
  user_guid: string;
  display_name: string;
  avatar_url?: string;
  bio?: string;
  location?: string;
  version: number;
  last_updated: string;
  visibility: 'connections' | 'public' | 'private';
}

export interface ProfileUpdateEvent {
  event_type: 'profile_update';
  user_guid: string;
  version: number;
  fields_updated: string[];
  timestamp: string;
}

// ============================================
// Key Generation and Exchange
// ============================================

/**
 * Generate X25519 key pair for connection encryption
 */
export function createMockKeyPair(): ConnectionKeyPair {
  // Generate X25519 key pair using Node.js crypto
  const keyPair = crypto.generateKeyPairSync('x25519');

  const publicKeyDer = keyPair.publicKey.export({ type: 'spki', format: 'der' });
  const privateKeyDer = keyPair.privateKey.export({ type: 'pkcs8', format: 'der' });

  // Extract raw keys (last 32 bytes of DER encoding for X25519)
  const publicKey = publicKeyDer.slice(-32);
  const privateKey = privateKeyDer.slice(-32);

  return {
    publicKey,
    privateKey,
    publicKeyBase64: publicKey.toString('base64'),
    privateKeyBase64: privateKey.toString('base64'),
  };
}

/**
 * Derive shared secret using X25519 ECDH
 */
export function deriveSharedSecret(
  privateKey: Buffer,
  peerPublicKey: Buffer
): Buffer {
  // Reconstruct key objects for diffieHellman
  const privateKeyObj = crypto.createPrivateKey({
    key: Buffer.concat([
      // PKCS#8 prefix for X25519 private key
      Buffer.from('302e020100300506032b656e04220420', 'hex'),
      privateKey,
    ]),
    format: 'der',
    type: 'pkcs8',
  });

  const publicKeyObj = crypto.createPublicKey({
    key: Buffer.concat([
      // SPKI prefix for X25519 public key
      Buffer.from('302a300506032b656e032100', 'hex'),
      peerPublicKey,
    ]),
    format: 'der',
    type: 'spki',
  });

  return crypto.diffieHellman({
    privateKey: privateKeyObj,
    publicKey: publicKeyObj,
  });
}

/**
 * Derive connection encryption key using HKDF
 */
export function deriveConnectionKey(
  sharedSecret: Buffer,
  connectionId: string,
  info = 'vettid-connection-v1'
): Buffer {
  const derived = crypto.hkdfSync(
    'sha256',
    sharedSecret,
    Buffer.from(connectionId),
    Buffer.from(info),
    32 // 256-bit key for XChaCha20-Poly1305
  );
  return Buffer.from(derived);
}

// ============================================
// Mock Invitation Factory
// ============================================

export interface CreateInvitationOptions {
  creatorGuid: string;
  creatorDisplayName?: string;
  creatorAvatarUrl?: string;
  expiresInHours?: number;
  creatorKeyPair?: ConnectionKeyPair;
}

/**
 * Create a mock connection invitation
 */
export function createMockInvitation(options: CreateInvitationOptions): ConnectionInvitation {
  const invitationId = crypto.randomUUID();
  const code = generateInviteCode();
  const keyPair = options.creatorKeyPair || createMockKeyPair();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + (options.expiresInHours || 24) * 60 * 60 * 1000);

  const qrData = JSON.stringify({
    type: 'vettid-connection',
    version: 1,
    code,
    pk: keyPair.publicKeyBase64,
  });

  return {
    invitation_id: invitationId,
    code,
    creator_guid: options.creatorGuid,
    creator_display_name: options.creatorDisplayName || 'Test User',
    creator_avatar_url: options.creatorAvatarUrl,
    creator_public_key: keyPair.publicKeyBase64,
    created_at: now.toISOString(),
    expires_at: expiresAt.toISOString(),
    status: 'pending',
    qr_data: qrData,
    deep_link: `vettid://connect/${code}`,
    ttl: Math.floor(expiresAt.getTime() / 1000),
  };
}

/**
 * Generate a short, user-friendly invite code
 */
function generateInviteCode(): string {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // Exclude similar characters
  let code = '';
  const bytes = crypto.randomBytes(8);
  for (let i = 0; i < 8; i++) {
    code += chars[bytes[i] % chars.length];
  }
  // Format: XXXX-XXXX
  return `${code.slice(0, 4)}-${code.slice(4)}`;
}

// ============================================
// Mock Connection Factory
// ============================================

export interface CreateConnectionOptions {
  ownerGuid: string;
  peerGuid: string;
  peerDisplayName?: string;
  peerAvatarUrl?: string;
  status?: 'active' | 'revoked' | 'blocked';
  ownerKeyPair?: ConnectionKeyPair;
  peerKeyPair?: ConnectionKeyPair;
}

export interface MockConnectionResult {
  connection: Connection;
  ownerKeyPair: ConnectionKeyPair;
  peerKeyPair: ConnectionKeyPair;
  sharedKey: Buffer;
}

/**
 * Create a mock established connection
 */
export function createMockConnection(options: CreateConnectionOptions): MockConnectionResult {
  const connectionId = crypto.randomUUID();
  const ownerKeyPair = options.ownerKeyPair || createMockKeyPair();
  const peerKeyPair = options.peerKeyPair || createMockKeyPair();

  // Derive shared secret
  const sharedSecret = deriveSharedSecret(ownerKeyPair.privateKey, peerKeyPair.publicKey);
  const sharedKey = deriveConnectionKey(sharedSecret, connectionId);

  const connection: Connection = {
    connection_id: connectionId,
    owner_guid: options.ownerGuid,
    peer_guid: options.peerGuid,
    peer_display_name: options.peerDisplayName || 'Test Peer',
    peer_avatar_url: options.peerAvatarUrl,
    peer_public_key: peerKeyPair.publicKeyBase64,
    shared_key_id: `sk-${crypto.randomUUID()}`,
    status: options.status || 'active',
    created_at: new Date().toISOString(),
    unread_count: 0,
    profile_version: 1,
  };

  return {
    connection,
    ownerKeyPair,
    peerKeyPair,
    sharedKey,
  };
}

// ============================================
// Mock Profile Factory
// ============================================

export interface CreateProfileOptions {
  userGuid: string;
  displayName?: string;
  avatarUrl?: string;
  bio?: string;
  location?: string;
  visibility?: 'connections' | 'public' | 'private';
}

/**
 * Create a mock user profile
 */
export function createMockProfile(options: CreateProfileOptions): UserProfile {
  return {
    user_guid: options.userGuid,
    display_name: options.displayName || 'Test User',
    avatar_url: options.avatarUrl,
    bio: options.bio,
    location: options.location,
    version: 1,
    last_updated: new Date().toISOString(),
    visibility: options.visibility || 'connections',
  };
}

// ============================================
// Mock Connection Service
// ============================================

export class MockConnectionService {
  private invitations: Map<string, ConnectionInvitation> = new Map();
  private invitationsByCode: Map<string, string> = new Map(); // code -> invitation_id
  private connections: Map<string, Connection> = new Map();
  private userConnections: Map<string, string[]> = new Map(); // user_guid -> connection_ids
  private sharedKeys: Map<string, Buffer> = new Map(); // shared_key_id -> key
  private profiles: Map<string, UserProfile> = new Map();
  private userKeyPairs: Map<string, ConnectionKeyPair> = new Map();

  private maxPendingInvitations = 10;
  private defaultExpiryHours = 24;

  /**
   * Set user's key pair
   */
  setUserKeyPair(userGuid: string, keyPair: ConnectionKeyPair): void {
    this.userKeyPairs.set(userGuid, keyPair);
  }

  /**
   * Get or create user's key pair
   */
  getUserKeyPair(userGuid: string): ConnectionKeyPair {
    let keyPair = this.userKeyPairs.get(userGuid);
    if (!keyPair) {
      keyPair = createMockKeyPair();
      this.userKeyPairs.set(userGuid, keyPair);
    }
    return keyPair;
  }

  /**
   * Create a connection invitation
   */
  async createInvitation(
    creatorGuid: string,
    options: { displayName?: string; expiresInHours?: number } = {}
  ): Promise<{ success: boolean; invitation?: ConnectionInvitation; error?: string }> {
    // Check pending invitations limit
    const pendingCount = this.getPendingInvitationCount(creatorGuid);
    if (pendingCount >= this.maxPendingInvitations) {
      return {
        success: false,
        error: `Maximum pending invitations (${this.maxPendingInvitations}) reached`,
      };
    }

    const keyPair = this.getUserKeyPair(creatorGuid);
    const invitation = createMockInvitation({
      creatorGuid,
      creatorDisplayName: options.displayName,
      expiresInHours: options.expiresInHours || this.defaultExpiryHours,
      creatorKeyPair: keyPair,
    });

    this.invitations.set(invitation.invitation_id, invitation);
    this.invitationsByCode.set(invitation.code, invitation.invitation_id);

    return { success: true, invitation };
  }

  /**
   * Get pending invitation count for user
   */
  private getPendingInvitationCount(userGuid: string): number {
    let count = 0;
    const now = new Date();
    for (const inv of this.invitations.values()) {
      if (
        inv.creator_guid === userGuid &&
        inv.status === 'pending' &&
        new Date(inv.expires_at) > now
      ) {
        count++;
      }
    }
    return count;
  }

  /**
   * Accept a connection invitation
   */
  async acceptInvitation(
    acceptorGuid: string,
    code: string,
    acceptorDisplayName?: string
  ): Promise<{ success: boolean; connection?: Connection; error?: string }> {
    // Find invitation by code
    const invitationId = this.invitationsByCode.get(code);
    if (!invitationId) {
      return { success: false, error: 'Invalid invitation code' };
    }

    const invitation = this.invitations.get(invitationId);
    if (!invitation) {
      return { success: false, error: 'Invitation not found' };
    }

    // Validate invitation
    if (invitation.status !== 'pending') {
      return { success: false, error: `Invitation is ${invitation.status}` };
    }

    if (new Date(invitation.expires_at) < new Date()) {
      invitation.status = 'expired';
      return { success: false, error: 'Invitation has expired' };
    }

    if (invitation.creator_guid === acceptorGuid) {
      return { success: false, error: 'Cannot accept your own invitation' };
    }

    // Check for existing connection
    if (this.connectionExists(invitation.creator_guid, acceptorGuid)) {
      return { success: false, error: 'Connection already exists' };
    }

    // Perform key exchange
    const acceptorKeyPair = this.getUserKeyPair(acceptorGuid);
    const creatorPublicKey = Buffer.from(invitation.creator_public_key, 'base64');

    const sharedSecret = deriveSharedSecret(acceptorKeyPair.privateKey, creatorPublicKey);
    const connectionId = crypto.randomUUID();
    const sharedKey = deriveConnectionKey(sharedSecret, connectionId);
    const sharedKeyId = `sk-${crypto.randomUUID()}`;

    // Store shared key
    this.sharedKeys.set(sharedKeyId, sharedKey);

    // Create connection for acceptor (peer is creator)
    const acceptorConnection: Connection = {
      connection_id: connectionId,
      owner_guid: acceptorGuid,
      peer_guid: invitation.creator_guid,
      peer_display_name: invitation.creator_display_name,
      peer_avatar_url: invitation.creator_avatar_url,
      peer_public_key: invitation.creator_public_key,
      shared_key_id: sharedKeyId,
      status: 'active',
      created_at: new Date().toISOString(),
      unread_count: 0,
      profile_version: 1,
    };

    // Create connection for creator (peer is acceptor)
    const creatorConnectionId = crypto.randomUUID();
    const creatorConnection: Connection = {
      connection_id: creatorConnectionId,
      owner_guid: invitation.creator_guid,
      peer_guid: acceptorGuid,
      peer_display_name: acceptorDisplayName || 'New Connection',
      peer_public_key: acceptorKeyPair.publicKeyBase64,
      shared_key_id: sharedKeyId, // Same shared key
      status: 'active',
      created_at: new Date().toISOString(),
      unread_count: 0,
      profile_version: 1,
    };

    // Store connections
    this.connections.set(connectionId, acceptorConnection);
    this.connections.set(creatorConnectionId, creatorConnection);

    // Track user connections
    this.addUserConnection(acceptorGuid, connectionId);
    this.addUserConnection(invitation.creator_guid, creatorConnectionId);

    // Update invitation status
    invitation.status = 'accepted';

    return { success: true, connection: acceptorConnection };
  }

  /**
   * Check if connection exists between two users
   */
  private connectionExists(userGuid1: string, userGuid2: string): boolean {
    const user1Connections = this.userConnections.get(userGuid1) || [];
    for (const connId of user1Connections) {
      const conn = this.connections.get(connId);
      if (conn && conn.peer_guid === userGuid2 && conn.status === 'active') {
        return true;
      }
    }
    return false;
  }

  /**
   * Add connection to user's list
   */
  private addUserConnection(userGuid: string, connectionId: string): void {
    let connections = this.userConnections.get(userGuid);
    if (!connections) {
      connections = [];
      this.userConnections.set(userGuid, connections);
    }
    connections.push(connectionId);
  }

  /**
   * Get invitation by code
   */
  getInvitation(code: string): ConnectionInvitation | undefined {
    const invitationId = this.invitationsByCode.get(code);
    if (!invitationId) return undefined;
    return this.invitations.get(invitationId);
  }

  /**
   * Get connection by ID
   */
  getConnection(connectionId: string): Connection | undefined {
    return this.connections.get(connectionId);
  }

  /**
   * Get shared key for connection
   */
  getSharedKey(sharedKeyId: string): Buffer | undefined {
    return this.sharedKeys.get(sharedKeyId);
  }

  /**
   * Get user's connections
   */
  getUserConnections(userGuid: string): Connection[] {
    const connectionIds = this.userConnections.get(userGuid) || [];
    return connectionIds
      .map(id => this.connections.get(id))
      .filter((c): c is Connection => c !== undefined);
  }

  /**
   * Revoke a connection
   */
  async revokeConnection(
    userGuid: string,
    connectionId: string
  ): Promise<{ success: boolean; error?: string }> {
    const connection = this.connections.get(connectionId);
    if (!connection) {
      return { success: false, error: 'Connection not found' };
    }

    if (connection.owner_guid !== userGuid) {
      return { success: false, error: 'Not authorized to revoke this connection' };
    }

    if (connection.status === 'revoked') {
      return { success: false, error: 'Connection already revoked' };
    }

    // Update status
    connection.status = 'revoked';

    // Find and revoke peer's connection
    const peerConnections = this.userConnections.get(connection.peer_guid) || [];
    for (const peerConnId of peerConnections) {
      const peerConn = this.connections.get(peerConnId);
      if (peerConn && peerConn.peer_guid === userGuid) {
        peerConn.status = 'revoked';
        break;
      }
    }

    // Delete shared key
    this.sharedKeys.delete(connection.shared_key_id);

    return { success: true };
  }

  /**
   * Set user profile
   */
  setProfile(profile: UserProfile): void {
    this.profiles.set(profile.user_guid, profile);
  }

  /**
   * Get user profile
   */
  getProfile(userGuid: string): UserProfile | undefined {
    return this.profiles.get(userGuid);
  }

  /**
   * Update profile
   */
  async updateProfile(
    userGuid: string,
    updates: Partial<Omit<UserProfile, 'user_guid' | 'version' | 'last_updated'>>
  ): Promise<{ success: boolean; profile?: UserProfile; error?: string }> {
    let profile = this.profiles.get(userGuid);
    if (!profile) {
      profile = createMockProfile({ userGuid });
    }

    // Apply updates
    const updatedProfile: UserProfile = {
      ...profile,
      ...updates,
      version: profile.version + 1,
      last_updated: new Date().toISOString(),
    };

    this.profiles.set(userGuid, updatedProfile);
    return { success: true, profile: updatedProfile };
  }

  /**
   * Clear all state
   */
  clear(): void {
    this.invitations.clear();
    this.invitationsByCode.clear();
    this.connections.clear();
    this.userConnections.clear();
    this.sharedKeys.clear();
    this.profiles.clear();
    this.userKeyPairs.clear();
  }

  /**
   * Expire an invitation
   */
  expireInvitation(code: string): void {
    const invitationId = this.invitationsByCode.get(code);
    if (invitationId) {
      const invitation = this.invitations.get(invitationId);
      if (invitation) {
        invitation.status = 'expired';
      }
    }
  }

  /**
   * Get connection public key for a user in a connection
   */
  getConnectionPublicKey(connectionId: string, userGuid: string): Buffer | undefined {
    const connection = this.connections.get(connectionId);
    if (!connection) return undefined;

    // If the user is the owner, return the peer's public key
    if (connection.owner_guid === userGuid) {
      return Buffer.from(connection.peer_public_key, 'base64');
    }

    // Otherwise find the user's key pair
    const keyPair = this.userKeyPairs.get(userGuid);
    return keyPair?.publicKey;
  }

  /**
   * Rotate the shared key for a connection
   */
  rotateKey(connectionId: string, newKey: Buffer): void {
    const connection = this.connections.get(connectionId);
    if (connection) {
      const oldKeyId = connection.shared_key_id;
      const newKeyId = `sk-${crypto.randomUUID()}`;

      // Delete old key
      this.sharedKeys.delete(oldKeyId);

      // Store new key
      this.sharedKeys.set(newKeyId, newKey);

      // Update connection
      connection.shared_key_id = newKeyId;

      // Update peer's connection too
      for (const conn of this.connections.values()) {
        if (conn.connection_id !== connectionId && conn.shared_key_id === oldKeyId) {
          conn.shared_key_id = newKeyId;
        }
      }
    }
  }
}

// ============================================
// Export singleton for tests
// ============================================

export const mockConnectionService = new MockConnectionService();
