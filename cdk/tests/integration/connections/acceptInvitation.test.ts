/**
 * Integration Tests: Accept Connection Invitation
 *
 * Tests the connection acceptance endpoint:
 * - Invitation validation (exists, not expired, not used)
 * - X25519 key exchange
 * - Shared secret derivation via HKDF
 * - Connection establishment for both parties
 * - Profile exchange
 *
 * @see lambda/handlers/connections/acceptInvitation.ts (pending implementation)
 */

import {
  createMockInvitation,
  createMockKeyPair,
  deriveSharedSecret,
  deriveConnectionKey,
  MockConnectionService,
} from '../../fixtures/connections/mockConnection';

// ============================================
// Tests
// ============================================

describe('Accept Connection Invitation', () => {
  let connectionService: MockConnectionService;
  const creatorGuid = 'user-creator-123';
  const acceptorGuid = 'user-acceptor-456';

  beforeEach(() => {
    connectionService = new MockConnectionService();
  });

  afterEach(() => {
    connectionService.clear();
  });

  describe('Invitation Validation', () => {
    it('should validate invitation code exists', async () => {
      const result = await connectionService.acceptInvitation(
        acceptorGuid,
        'INVALID-CODE'
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('Invalid invitation code');
    });

    it('should reject expired invitations', async () => {
      // Create invitation that's already expired
      const invitation = createMockInvitation({
        creatorGuid,
        expiresInHours: -1, // Expired
      });

      // Manually add expired invitation
      const createResult = await connectionService.createInvitation(creatorGuid, {
        expiresInHours: 24,
      });

      // Manually expire it
      const inv = connectionService.getInvitation(createResult.invitation!.code);
      if (inv) {
        inv.expires_at = new Date(Date.now() - 1000).toISOString();
      }

      const result = await connectionService.acceptInvitation(
        acceptorGuid,
        createResult.invitation!.code
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('expired');
    });

    it('should reject already-accepted invitations', async () => {
      const createResult = await connectionService.createInvitation(creatorGuid);

      // First acceptance
      const firstAccept = await connectionService.acceptInvitation(
        acceptorGuid,
        createResult.invitation!.code
      );
      expect(firstAccept.success).toBe(true);

      // Try to accept again
      const secondAccept = await connectionService.acceptInvitation(
        'another-user-789',
        createResult.invitation!.code
      );

      expect(secondAccept.success).toBe(false);
      expect(secondAccept.error).toContain('accepted');
    });

    it('should reject revoked invitations', async () => {
      const createResult = await connectionService.createInvitation(creatorGuid);

      // Manually revoke
      const inv = connectionService.getInvitation(createResult.invitation!.code);
      if (inv) {
        inv.status = 'revoked';
      }

      const result = await connectionService.acceptInvitation(
        acceptorGuid,
        createResult.invitation!.code
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('revoked');
    });

    it('should reject self-connection attempts', async () => {
      const createResult = await connectionService.createInvitation(creatorGuid);

      const result = await connectionService.acceptInvitation(
        creatorGuid, // Same user trying to accept their own invitation
        createResult.invitation!.code
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('own invitation');
    });

    it('should reject duplicate connections', async () => {
      // Create first connection
      const firstInvite = await connectionService.createInvitation(creatorGuid);
      await connectionService.acceptInvitation(acceptorGuid, firstInvite.invitation!.code);

      // Create another invitation
      const secondInvite = await connectionService.createInvitation(creatorGuid);

      // Try to connect again
      const result = await connectionService.acceptInvitation(
        acceptorGuid,
        secondInvite.invitation!.code
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('already exists');
    });
  });

  describe('Key Exchange', () => {
    it('should perform X25519 key exchange', async () => {
      const createResult = await connectionService.createInvitation(creatorGuid);
      const acceptResult = await connectionService.acceptInvitation(
        acceptorGuid,
        createResult.invitation!.code
      );

      expect(acceptResult.success).toBe(true);
      expect(acceptResult.connection?.shared_key_id).toBeDefined();

      // Verify shared key exists
      const sharedKey = connectionService.getSharedKey(acceptResult.connection!.shared_key_id);
      expect(sharedKey).toBeDefined();
      expect(sharedKey?.length).toBe(32); // 256-bit key
    });

    it('should derive same shared secret from both directions', () => {
      const keyPair1 = createMockKeyPair();
      const keyPair2 = createMockKeyPair();

      // Derive from direction 1
      const shared1 = deriveSharedSecret(keyPair1.privateKey, keyPair2.publicKey);

      // Derive from direction 2
      const shared2 = deriveSharedSecret(keyPair2.privateKey, keyPair1.publicKey);

      expect(shared1.equals(shared2)).toBe(true);
    });

    it('should generate per-connection encryption key', async () => {
      // Create two different connections
      const invite1 = await connectionService.createInvitation(creatorGuid);
      const accept1 = await connectionService.acceptInvitation(acceptorGuid, invite1.invitation!.code);

      connectionService.clear();

      const invite2 = await connectionService.createInvitation(creatorGuid);
      const accept2 = await connectionService.acceptInvitation(acceptorGuid, invite2.invitation!.code);

      // Different connections should have different shared keys
      expect(accept1.connection?.shared_key_id).not.toBe(accept2.connection?.shared_key_id);
    });

    it('should derive connection key using HKDF', () => {
      const keyPair1 = createMockKeyPair();
      const keyPair2 = createMockKeyPair();
      const connectionId = 'test-connection-123';

      const sharedSecret = deriveSharedSecret(keyPair1.privateKey, keyPair2.publicKey);
      const connectionKey = deriveConnectionKey(sharedSecret, connectionId);

      expect(connectionKey.length).toBe(32); // 256-bit key
    });

    it('should produce different keys for different connection IDs', () => {
      const keyPair1 = createMockKeyPair();
      const keyPair2 = createMockKeyPair();

      const sharedSecret = deriveSharedSecret(keyPair1.privateKey, keyPair2.publicKey);

      const key1 = deriveConnectionKey(sharedSecret, 'connection-1');
      const key2 = deriveConnectionKey(sharedSecret, 'connection-2');

      expect(key1.equals(key2)).toBe(false);
    });
  });

  describe('Connection Establishment', () => {
    it('should create connection record for acceptor', async () => {
      const createResult = await connectionService.createInvitation(creatorGuid, {
        displayName: 'Creator Name',
      });

      const acceptResult = await connectionService.acceptInvitation(
        acceptorGuid,
        createResult.invitation!.code,
        'Acceptor Name'
      );

      expect(acceptResult.success).toBe(true);
      expect(acceptResult.connection).toBeDefined();
      expect(acceptResult.connection?.owner_guid).toBe(acceptorGuid);
      expect(acceptResult.connection?.peer_guid).toBe(creatorGuid);
      expect(acceptResult.connection?.peer_display_name).toBe('Creator Name');
    });

    it('should create connection record for creator', async () => {
      const createResult = await connectionService.createInvitation(creatorGuid);
      await connectionService.acceptInvitation(
        acceptorGuid,
        createResult.invitation!.code,
        'Acceptor Name'
      );

      const creatorConnections = connectionService.getUserConnections(creatorGuid);
      expect(creatorConnections.length).toBe(1);
      expect(creatorConnections[0].owner_guid).toBe(creatorGuid);
      expect(creatorConnections[0].peer_guid).toBe(acceptorGuid);
      expect(creatorConnections[0].peer_display_name).toBe('Acceptor Name');
    });

    it('should set connection status to active', async () => {
      const createResult = await connectionService.createInvitation(creatorGuid);
      const acceptResult = await connectionService.acceptInvitation(
        acceptorGuid,
        createResult.invitation!.code
      );

      expect(acceptResult.success).toBe(true);
      expect(acceptResult.connection?.status).toBe('active');
    });

    it('should include peer public key', async () => {
      const createResult = await connectionService.createInvitation(creatorGuid);
      const acceptResult = await connectionService.acceptInvitation(
        acceptorGuid,
        createResult.invitation!.code
      );

      expect(acceptResult.success).toBe(true);
      expect(acceptResult.connection?.peer_public_key).toBeDefined();

      // Verify it's the creator's public key
      expect(acceptResult.connection?.peer_public_key).toBe(
        createResult.invitation!.creator_public_key
      );
    });

    it('should initialize unread count to zero', async () => {
      const createResult = await connectionService.createInvitation(creatorGuid);
      const acceptResult = await connectionService.acceptInvitation(
        acceptorGuid,
        createResult.invitation!.code
      );

      expect(acceptResult.success).toBe(true);
      expect(acceptResult.connection?.unread_count).toBe(0);
    });

    it('should set initial profile version', async () => {
      const createResult = await connectionService.createInvitation(creatorGuid);
      const acceptResult = await connectionService.acceptInvitation(
        acceptorGuid,
        createResult.invitation!.code
      );

      expect(acceptResult.success).toBe(true);
      expect(acceptResult.connection?.profile_version).toBe(1);
    });

    it('should include created_at timestamp', async () => {
      const before = new Date();
      const createResult = await connectionService.createInvitation(creatorGuid);
      const acceptResult = await connectionService.acceptInvitation(
        acceptorGuid,
        createResult.invitation!.code
      );
      const after = new Date();

      expect(acceptResult.success).toBe(true);
      const createdAt = new Date(acceptResult.connection!.created_at);
      expect(createdAt.getTime()).toBeGreaterThanOrEqual(before.getTime());
      expect(createdAt.getTime()).toBeLessThanOrEqual(after.getTime());
    });
  });

  describe('Bi-directional Connection', () => {
    it('should allow messaging in both directions', async () => {
      const createResult = await connectionService.createInvitation(creatorGuid);
      await connectionService.acceptInvitation(acceptorGuid, createResult.invitation!.code);

      const creatorConnections = connectionService.getUserConnections(creatorGuid);
      const acceptorConnections = connectionService.getUserConnections(acceptorGuid);

      expect(creatorConnections.length).toBe(1);
      expect(acceptorConnections.length).toBe(1);

      // Both should reference the same shared key
      expect(creatorConnections[0].shared_key_id).toBe(acceptorConnections[0].shared_key_id);
    });

    it('should use same shared key for both parties', async () => {
      const createResult = await connectionService.createInvitation(creatorGuid);
      const acceptResult = await connectionService.acceptInvitation(
        acceptorGuid,
        createResult.invitation!.code
      );

      const creatorConnections = connectionService.getUserConnections(creatorGuid);

      // Both connections should have the same shared_key_id
      expect(acceptResult.connection?.shared_key_id).toBe(creatorConnections[0].shared_key_id);

      // Shared key should exist and be retrievable
      const sharedKey = connectionService.getSharedKey(acceptResult.connection!.shared_key_id);
      expect(sharedKey).toBeDefined();
    });
  });

  describe('Multiple Connections', () => {
    it('should allow user to have multiple connections', async () => {
      const user2 = 'user-2';
      const user3 = 'user-3';

      // Create connections with multiple users
      const invite1 = await connectionService.createInvitation(creatorGuid);
      await connectionService.acceptInvitation(user2, invite1.invitation!.code);

      const invite2 = await connectionService.createInvitation(creatorGuid);
      await connectionService.acceptInvitation(user3, invite2.invitation!.code);

      const creatorConnections = connectionService.getUserConnections(creatorGuid);
      expect(creatorConnections.length).toBe(2);
    });

    it('should maintain separate keys for each connection', async () => {
      const user2 = 'user-2';
      const user3 = 'user-3';

      const invite1 = await connectionService.createInvitation(creatorGuid);
      const accept1 = await connectionService.acceptInvitation(user2, invite1.invitation!.code);

      const invite2 = await connectionService.createInvitation(creatorGuid);
      const accept2 = await connectionService.acceptInvitation(user3, invite2.invitation!.code);

      expect(accept1.connection?.shared_key_id).not.toBe(accept2.connection?.shared_key_id);

      const key1 = connectionService.getSharedKey(accept1.connection!.shared_key_id);
      const key2 = connectionService.getSharedKey(accept2.connection!.shared_key_id);

      expect(key1?.equals(key2!)).toBe(false);
    });
  });

  describe('Invitation Status Updates', () => {
    it('should update invitation status to accepted', async () => {
      const createResult = await connectionService.createInvitation(creatorGuid);
      await connectionService.acceptInvitation(acceptorGuid, createResult.invitation!.code);

      const invitation = connectionService.getInvitation(createResult.invitation!.code);
      expect(invitation?.status).toBe('accepted');
    });
  });
});
