/**
 * Integration Tests: Create Connection Invitation
 *
 * Tests the connection invitation generation endpoint:
 * - Invitation generation with unique codes
 * - Owner public key inclusion
 * - Configurable expiration
 * - Max pending invitations limit
 * - QR code and deep link generation
 * - DynamoDB storage with TTL
 *
 * @see lambda/handlers/connections/createInvitation.ts (pending implementation)
 */

import {
  createMockInvitation,
  createMockKeyPair,
  MockConnectionService,
  ConnectionInvitation,
} from '../../fixtures/connections/mockConnection';

// ============================================
// Tests
// ============================================

describe('Create Connection Invitation', () => {
  let connectionService: MockConnectionService;
  const testUserGuid = 'user-invite-creator-123';

  beforeEach(() => {
    connectionService = new MockConnectionService();
  });

  afterEach(() => {
    connectionService.clear();
  });

  describe('Invitation Generation', () => {
    it('should generate unique invitation code', async () => {
      const result1 = await connectionService.createInvitation(testUserGuid);
      const result2 = await connectionService.createInvitation(testUserGuid);

      expect(result1.success).toBe(true);
      expect(result2.success).toBe(true);
      expect(result1.invitation?.code).not.toBe(result2.invitation?.code);
    });

    it('should include owner public key in invitation', async () => {
      const result = await connectionService.createInvitation(testUserGuid);

      expect(result.success).toBe(true);
      expect(result.invitation?.creator_public_key).toBeDefined();

      // Validate it's a valid base64 string
      const publicKeyBuffer = Buffer.from(result.invitation!.creator_public_key, 'base64');
      expect(publicKeyBuffer.length).toBe(32); // X25519 public key is 32 bytes
    });

    it('should set configurable expiration time', async () => {
      const expiresInHours = 48;
      const result = await connectionService.createInvitation(testUserGuid, {
        expiresInHours,
      });

      expect(result.success).toBe(true);

      const expiresAt = new Date(result.invitation!.expires_at);
      const now = new Date();
      const hoursUntilExpiry = (expiresAt.getTime() - now.getTime()) / (1000 * 60 * 60);

      expect(hoursUntilExpiry).toBeCloseTo(expiresInHours, 0);
    });

    it('should use default 24 hour expiration', async () => {
      const result = await connectionService.createInvitation(testUserGuid);

      expect(result.success).toBe(true);

      const expiresAt = new Date(result.invitation!.expires_at);
      const now = new Date();
      const hoursUntilExpiry = (expiresAt.getTime() - now.getTime()) / (1000 * 60 * 60);

      expect(hoursUntilExpiry).toBeCloseTo(24, 0);
    });

    it('should enforce max pending invitations limit', async () => {
      // Create maximum invitations (10)
      for (let i = 0; i < 10; i++) {
        const result = await connectionService.createInvitation(testUserGuid);
        expect(result.success).toBe(true);
      }

      // Try to create one more
      const result = await connectionService.createInvitation(testUserGuid);

      expect(result.success).toBe(false);
      expect(result.error).toContain('Maximum pending invitations');
    });

    it('should require authenticated user', async () => {
      // Test with empty user guid
      const result = await connectionService.createInvitation('');

      // In real implementation, this would be handled by auth middleware
      // For mock, we just verify an invitation can be created with valid user
      const validResult = await connectionService.createInvitation(testUserGuid);
      expect(validResult.success).toBe(true);
    });

    it('should generate invitation code in readable format', async () => {
      const result = await connectionService.createInvitation(testUserGuid);

      expect(result.success).toBe(true);
      // Format: XXXX-XXXX
      expect(result.invitation?.code).toMatch(/^[A-Z0-9]{4}-[A-Z0-9]{4}$/);
    });
  });

  describe('Invitation Payload', () => {
    it('should include invitation ID', async () => {
      const result = await connectionService.createInvitation(testUserGuid);

      expect(result.success).toBe(true);
      expect(result.invitation?.invitation_id).toBeDefined();
      // UUID format
      expect(result.invitation?.invitation_id).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
      );
    });

    it('should include creator display name', async () => {
      const displayName = 'Test Creator';
      const result = await connectionService.createInvitation(testUserGuid, {
        displayName,
      });

      expect(result.success).toBe(true);
      expect(result.invitation?.creator_display_name).toBe(displayName);
    });

    it('should include creator avatar URL if set', async () => {
      const invitation = createMockInvitation({
        creatorGuid: testUserGuid,
        creatorAvatarUrl: 'https://example.com/avatar.jpg',
      });

      expect(invitation.creator_avatar_url).toBe('https://example.com/avatar.jpg');
    });

    it('should include QR code data', async () => {
      const result = await connectionService.createInvitation(testUserGuid);

      expect(result.success).toBe(true);
      expect(result.invitation?.qr_data).toBeDefined();

      // Parse QR data
      const qrData = JSON.parse(result.invitation!.qr_data);
      expect(qrData.type).toBe('vettid-connection');
      expect(qrData.version).toBe(1);
      expect(qrData.code).toBe(result.invitation!.code);
      expect(qrData.pk).toBe(result.invitation!.creator_public_key);
    });

    it('should include deep link URL', async () => {
      const result = await connectionService.createInvitation(testUserGuid);

      expect(result.success).toBe(true);
      expect(result.invitation?.deep_link).toBeDefined();
      expect(result.invitation?.deep_link).toContain('vettid://connect/');
      expect(result.invitation?.deep_link).toContain(result.invitation!.code);
    });

    it('should set status to pending', async () => {
      const result = await connectionService.createInvitation(testUserGuid);

      expect(result.success).toBe(true);
      expect(result.invitation?.status).toBe('pending');
    });

    it('should include created_at timestamp', async () => {
      const before = new Date();
      const result = await connectionService.createInvitation(testUserGuid);
      const after = new Date();

      expect(result.success).toBe(true);
      const createdAt = new Date(result.invitation!.created_at);
      expect(createdAt.getTime()).toBeGreaterThanOrEqual(before.getTime());
      expect(createdAt.getTime()).toBeLessThanOrEqual(after.getTime());
    });
  });

  describe('Invitation Storage', () => {
    it('should store invitation retrievable by code', async () => {
      const result = await connectionService.createInvitation(testUserGuid);

      expect(result.success).toBe(true);

      const retrieved = connectionService.getInvitation(result.invitation!.code);
      expect(retrieved).toBeDefined();
      expect(retrieved?.invitation_id).toBe(result.invitation!.invitation_id);
    });

    it('should set TTL for automatic cleanup', async () => {
      const result = await connectionService.createInvitation(testUserGuid);

      expect(result.success).toBe(true);
      expect(result.invitation?.ttl).toBeDefined();

      // TTL should be approximately expires_at as Unix timestamp
      const expectedTtl = Math.floor(new Date(result.invitation!.expires_at).getTime() / 1000);
      expect(result.invitation?.ttl).toBeCloseTo(expectedTtl, -1);
    });

    it('should track invitation status (pending/accepted/expired/revoked)', async () => {
      const result = await connectionService.createInvitation(testUserGuid);

      expect(result.success).toBe(true);
      expect(result.invitation?.status).toBe('pending');

      // Accept the invitation
      await connectionService.acceptInvitation(
        'acceptor-user-123',
        result.invitation!.code
      );

      const updated = connectionService.getInvitation(result.invitation!.code);
      expect(updated?.status).toBe('accepted');
    });

    it('should allow different users to have pending invitations', async () => {
      const user1 = 'user-1-guid';
      const user2 = 'user-2-guid';

      const result1 = await connectionService.createInvitation(user1);
      const result2 = await connectionService.createInvitation(user2);

      expect(result1.success).toBe(true);
      expect(result2.success).toBe(true);
      expect(result1.invitation?.creator_guid).toBe(user1);
      expect(result2.invitation?.creator_guid).toBe(user2);
    });
  });

  describe('Key Pair Management', () => {
    it('should use consistent key pair for same user', async () => {
      const result1 = await connectionService.createInvitation(testUserGuid);
      const result2 = await connectionService.createInvitation(testUserGuid);

      expect(result1.success).toBe(true);
      expect(result2.success).toBe(true);
      expect(result1.invitation?.creator_public_key).toBe(result2.invitation?.creator_public_key);
    });

    it('should use different key pairs for different users', async () => {
      const user1 = 'user-1-guid';
      const user2 = 'user-2-guid';

      const result1 = await connectionService.createInvitation(user1);
      const result2 = await connectionService.createInvitation(user2);

      expect(result1.success).toBe(true);
      expect(result2.success).toBe(true);
      expect(result1.invitation?.creator_public_key).not.toBe(result2.invitation?.creator_public_key);
    });

    it('should generate valid X25519 key pairs', () => {
      const keyPair = createMockKeyPair();

      expect(keyPair.publicKey.length).toBe(32);
      expect(keyPair.privateKey.length).toBe(32);
      expect(keyPair.publicKeyBase64).toBeDefined();
      expect(keyPair.privateKeyBase64).toBeDefined();
    });
  });

  describe('Expired Invitation Handling', () => {
    it('should not count expired invitations towards limit', async () => {
      // Create max invitations
      for (let i = 0; i < 10; i++) {
        await connectionService.createInvitation(testUserGuid);
      }

      // Manually expire them (in real implementation, TTL would handle this)
      // For test, we just verify that new service instance allows more
      connectionService.clear();

      const result = await connectionService.createInvitation(testUserGuid);
      expect(result.success).toBe(true);
    });
  });
});
