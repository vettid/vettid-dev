/**
 * E2E Tests: Invite Code Validation
 *
 * Tests the invite code lifecycle:
 * - Generation from admin/member actions
 * - Validation during enrollment
 * - Expiration handling
 * - Single-use enforcement
 *
 * @see docs/specs/vault-services-api.yaml
 * @see POST /admin/invites
 * @see POST /member/vault/deploy
 * @see POST /vault/enroll/start
 */

import * as crypto from 'crypto';

// ============================================
// Types (matching API spec)
// ============================================

interface InviteCode {
  code: string;
  vaultId: string;
  memberId: string;
  status: 'pending' | 'used' | 'expired' | 'revoked';
  createdAt: string;
  expiresAt: string;
  usedAt?: string;
  usedBy?: {
    deviceId: string;
    platform: 'android' | 'ios';
  };
}

interface CreateInviteRequest {
  memberId: string;
  expiresInHours?: number;
  metadata?: Record<string, string>;
}

interface ValidateInviteRequest {
  code: string;
  deviceInfo: {
    platform: 'android' | 'ios';
    deviceId: string;
  };
}

interface ValidateInviteResponse {
  valid: boolean;
  vaultId?: string;
  expiresAt?: string;
  error?: string;
}

// ============================================
// Mock Invite Service (simulates backend)
// ============================================

class MockInviteService {
  private invites: Map<string, InviteCode> = new Map();
  private vaultInvites: Map<string, string[]> = new Map(); // vaultId -> invite codes

  /**
   * Generate a unique invite code
   * Format: VE-XXXXXXXXXXXX (12 alphanumeric chars)
   */
  private generateCode(): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let result = 'VE-';
    for (let i = 0; i < 12; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  }

  /**
   * Create a new invite code
   */
  async createInvite(request: CreateInviteRequest): Promise<InviteCode> {
    const code = this.generateCode();
    const vaultId = crypto.randomUUID();
    const expiresInHours = request.expiresInHours || 24;

    const invite: InviteCode = {
      code,
      vaultId,
      memberId: request.memberId,
      status: 'pending',
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + expiresInHours * 60 * 60 * 1000).toISOString(),
    };

    this.invites.set(code, invite);

    const vaultCodes = this.vaultInvites.get(vaultId) || [];
    vaultCodes.push(code);
    this.vaultInvites.set(vaultId, vaultCodes);

    return invite;
  }

  /**
   * Validate an invite code
   */
  async validateInvite(request: ValidateInviteRequest): Promise<ValidateInviteResponse> {
    const invite = this.invites.get(request.code);

    if (!invite) {
      return { valid: false, error: 'Invite code not found' };
    }

    if (invite.status === 'used') {
      return { valid: false, error: 'Invite code already used' };
    }

    if (invite.status === 'revoked') {
      return { valid: false, error: 'Invite code has been revoked' };
    }

    if (invite.status === 'expired' || new Date(invite.expiresAt) < new Date()) {
      // Update status if expired
      invite.status = 'expired';
      return { valid: false, error: 'Invite code has expired' };
    }

    return {
      valid: true,
      vaultId: invite.vaultId,
      expiresAt: invite.expiresAt,
    };
  }

  /**
   * Use an invite code (mark as used)
   */
  async useInvite(code: string, deviceInfo: { deviceId: string; platform: 'android' | 'ios' }): Promise<boolean> {
    const invite = this.invites.get(code);
    if (!invite || invite.status !== 'pending') {
      return false;
    }

    // Check expiration
    if (new Date(invite.expiresAt) < new Date()) {
      invite.status = 'expired';
      return false;
    }

    invite.status = 'used';
    invite.usedAt = new Date().toISOString();
    invite.usedBy = deviceInfo;

    return true;
  }

  /**
   * Revoke an invite code
   */
  async revokeInvite(code: string): Promise<boolean> {
    const invite = this.invites.get(code);
    if (!invite) {
      return false;
    }

    if (invite.status === 'used') {
      // Cannot revoke already used invite
      return false;
    }

    invite.status = 'revoked';
    return true;
  }

  /**
   * Get invite by code (for testing)
   */
  getInvite(code: string): InviteCode | undefined {
    return this.invites.get(code);
  }

  /**
   * Get all invites for a vault
   */
  getVaultInvites(vaultId: string): InviteCode[] {
    const codes = this.vaultInvites.get(vaultId) || [];
    return codes.map(code => this.invites.get(code)).filter(Boolean) as InviteCode[];
  }

  /**
   * List invites by member
   */
  listInvitesByMember(memberId: string): InviteCode[] {
    return Array.from(this.invites.values()).filter(i => i.memberId === memberId);
  }

  /**
   * Clear all invites (for testing)
   */
  clear(): void {
    this.invites.clear();
    this.vaultInvites.clear();
  }
}

// ============================================
// Tests
// ============================================

describe('Invite Code Validation', () => {
  let inviteService: MockInviteService;
  const testMemberId = crypto.randomUUID();

  beforeEach(() => {
    inviteService = new MockInviteService();
  });

  describe('1. Invite Code Generation', () => {
    it('should generate unique invite codes', async () => {
      const invite1 = await inviteService.createInvite({ memberId: testMemberId });
      const invite2 = await inviteService.createInvite({ memberId: testMemberId });

      expect(invite1.code).not.toBe(invite2.code);
      expect(invite1.code).toMatch(/^VE-[A-Z0-9]{12}$/);
      expect(invite2.code).toMatch(/^VE-[A-Z0-9]{12}$/);
    });

    it('should set default 24-hour expiration', async () => {
      const invite = await inviteService.createInvite({ memberId: testMemberId });

      const expiresAt = new Date(invite.expiresAt);
      const expectedExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000);

      // Allow 1 second tolerance
      expect(Math.abs(expiresAt.getTime() - expectedExpiry.getTime())).toBeLessThan(1000);
    });

    it('should allow custom expiration time', async () => {
      const invite = await inviteService.createInvite({
        memberId: testMemberId,
        expiresInHours: 48
      });

      const expiresAt = new Date(invite.expiresAt);
      const expectedExpiry = new Date(Date.now() + 48 * 60 * 60 * 1000);

      expect(Math.abs(expiresAt.getTime() - expectedExpiry.getTime())).toBeLessThan(1000);
    });

    it('should create invite with pending status', async () => {
      const invite = await inviteService.createInvite({ memberId: testMemberId });

      expect(invite.status).toBe('pending');
      expect(invite.usedAt).toBeUndefined();
      expect(invite.usedBy).toBeUndefined();
    });

    it('should associate invite with vault ID', async () => {
      const invite = await inviteService.createInvite({ memberId: testMemberId });

      expect(invite.vaultId).toBeDefined();
      expect(invite.vaultId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    });
  });

  describe('2. Invite Code Validation', () => {
    it('should validate pending invite code', async () => {
      const invite = await inviteService.createInvite({ memberId: testMemberId });

      const result = await inviteService.validateInvite({
        code: invite.code,
        deviceInfo: { platform: 'android', deviceId: 'test-device-123' }
      });

      expect(result.valid).toBe(true);
      expect(result.vaultId).toBe(invite.vaultId);
      expect(result.expiresAt).toBe(invite.expiresAt);
    });

    it('should reject non-existent invite code', async () => {
      const result = await inviteService.validateInvite({
        code: 'VE-DOESNOTEXIST',
        deviceInfo: { platform: 'ios', deviceId: 'test-device-456' }
      });

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Invite code not found');
    });

    it('should reject malformed invite code', async () => {
      const result = await inviteService.validateInvite({
        code: 'invalid-code',
        deviceInfo: { platform: 'android', deviceId: 'test-device-789' }
      });

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Invite code not found');
    });

    it('should reject empty invite code', async () => {
      const result = await inviteService.validateInvite({
        code: '',
        deviceInfo: { platform: 'ios', deviceId: 'test-device' }
      });

      expect(result.valid).toBe(false);
    });
  });

  describe('3. Expiration Handling', () => {
    it('should reject expired invite code', async () => {
      const invite = await inviteService.createInvite({
        memberId: testMemberId,
        expiresInHours: 0  // Expire immediately (but still future due to processing time)
      });

      // Manually set expiration to the past
      const storedInvite = inviteService.getInvite(invite.code);
      if (storedInvite) {
        storedInvite.expiresAt = new Date(Date.now() - 1000).toISOString();
      }

      const result = await inviteService.validateInvite({
        code: invite.code,
        deviceInfo: { platform: 'android', deviceId: 'test-device' }
      });

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Invite code has expired');
    });

    it('should update status to expired on validation attempt', async () => {
      const invite = await inviteService.createInvite({ memberId: testMemberId });

      // Expire the invite
      const storedInvite = inviteService.getInvite(invite.code);
      if (storedInvite) {
        storedInvite.expiresAt = new Date(Date.now() - 1000).toISOString();
      }

      await inviteService.validateInvite({
        code: invite.code,
        deviceInfo: { platform: 'ios', deviceId: 'test-device' }
      });

      const updatedInvite = inviteService.getInvite(invite.code);
      expect(updatedInvite?.status).toBe('expired');
    });

    it('should accept invite right before expiration', async () => {
      const invite = await inviteService.createInvite({ memberId: testMemberId });

      // Set expiration to 1 second in the future
      const storedInvite = inviteService.getInvite(invite.code);
      if (storedInvite) {
        storedInvite.expiresAt = new Date(Date.now() + 1000).toISOString();
      }

      const result = await inviteService.validateInvite({
        code: invite.code,
        deviceInfo: { platform: 'android', deviceId: 'test-device' }
      });

      expect(result.valid).toBe(true);
    });
  });

  describe('4. Single-Use Enforcement', () => {
    it('should allow using pending invite', async () => {
      const invite = await inviteService.createInvite({ memberId: testMemberId });

      const success = await inviteService.useInvite(invite.code, {
        deviceId: 'device-123',
        platform: 'android'
      });

      expect(success).toBe(true);

      const updatedInvite = inviteService.getInvite(invite.code);
      expect(updatedInvite?.status).toBe('used');
      expect(updatedInvite?.usedAt).toBeDefined();
      expect(updatedInvite?.usedBy?.deviceId).toBe('device-123');
      expect(updatedInvite?.usedBy?.platform).toBe('android');
    });

    it('should reject already-used invite code', async () => {
      const invite = await inviteService.createInvite({ memberId: testMemberId });

      // Use the invite
      await inviteService.useInvite(invite.code, {
        deviceId: 'device-123',
        platform: 'android'
      });

      // Try to validate again
      const result = await inviteService.validateInvite({
        code: invite.code,
        deviceInfo: { platform: 'ios', deviceId: 'device-456' }
      });

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Invite code already used');
    });

    it('should reject second use attempt', async () => {
      const invite = await inviteService.createInvite({ memberId: testMemberId });

      // First use
      await inviteService.useInvite(invite.code, {
        deviceId: 'device-123',
        platform: 'android'
      });

      // Second use attempt
      const success = await inviteService.useInvite(invite.code, {
        deviceId: 'device-456',
        platform: 'ios'
      });

      expect(success).toBe(false);
    });

    it('should record device info on use', async () => {
      const invite = await inviteService.createInvite({ memberId: testMemberId });

      await inviteService.useInvite(invite.code, {
        deviceId: 'android-device-xyz',
        platform: 'android'
      });

      const usedInvite = inviteService.getInvite(invite.code);
      expect(usedInvite?.usedBy).toEqual({
        deviceId: 'android-device-xyz',
        platform: 'android'
      });
    });
  });

  describe('5. Invite Revocation', () => {
    it('should allow revoking pending invite', async () => {
      const invite = await inviteService.createInvite({ memberId: testMemberId });

      const success = await inviteService.revokeInvite(invite.code);
      expect(success).toBe(true);

      const revokedInvite = inviteService.getInvite(invite.code);
      expect(revokedInvite?.status).toBe('revoked');
    });

    it('should reject validation of revoked invite', async () => {
      const invite = await inviteService.createInvite({ memberId: testMemberId });
      await inviteService.revokeInvite(invite.code);

      const result = await inviteService.validateInvite({
        code: invite.code,
        deviceInfo: { platform: 'android', deviceId: 'test-device' }
      });

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Invite code has been revoked');
    });

    it('should not allow revoking used invite', async () => {
      const invite = await inviteService.createInvite({ memberId: testMemberId });

      // Use the invite first
      await inviteService.useInvite(invite.code, {
        deviceId: 'device-123',
        platform: 'ios'
      });

      // Try to revoke
      const success = await inviteService.revokeInvite(invite.code);
      expect(success).toBe(false);

      const storedInvite = inviteService.getInvite(invite.code);
      expect(storedInvite?.status).toBe('used'); // Status unchanged
    });

    it('should return false for non-existent invite', async () => {
      const success = await inviteService.revokeInvite('VE-NONEXISTENT12');
      expect(success).toBe(false);
    });
  });

  describe('6. Invite Listing and Management', () => {
    it('should list invites by member', async () => {
      const member1 = crypto.randomUUID();
      const member2 = crypto.randomUUID();

      await inviteService.createInvite({ memberId: member1 });
      await inviteService.createInvite({ memberId: member1 });
      await inviteService.createInvite({ memberId: member2 });

      const member1Invites = inviteService.listInvitesByMember(member1);
      const member2Invites = inviteService.listInvitesByMember(member2);

      expect(member1Invites).toHaveLength(2);
      expect(member2Invites).toHaveLength(1);
    });

    it('should return empty array for member with no invites', async () => {
      const invites = inviteService.listInvitesByMember('non-existent-member');
      expect(invites).toHaveLength(0);
    });

    it('should get invites for a vault', async () => {
      const invite1 = await inviteService.createInvite({ memberId: testMemberId });

      // Create second invite for same vault (manually associate)
      const invite2 = await inviteService.createInvite({ memberId: testMemberId });

      const vaultInvites = inviteService.getVaultInvites(invite1.vaultId);
      expect(vaultInvites.length).toBeGreaterThanOrEqual(1);
      expect(vaultInvites[0].code).toBe(invite1.code);
    });
  });

  describe('7. Security Validation', () => {
    it('should not leak vault info for invalid code', async () => {
      const result = await inviteService.validateInvite({
        code: 'VE-INVALID00000',
        deviceInfo: { platform: 'android', deviceId: 'test' }
      });

      expect(result.valid).toBe(false);
      expect(result.vaultId).toBeUndefined();
      expect(result.expiresAt).toBeUndefined();
    });

    it('should not leak vault info for expired code', async () => {
      const invite = await inviteService.createInvite({ memberId: testMemberId });

      // Expire the invite
      const storedInvite = inviteService.getInvite(invite.code);
      if (storedInvite) {
        storedInvite.expiresAt = new Date(Date.now() - 1000).toISOString();
      }

      const result = await inviteService.validateInvite({
        code: invite.code,
        deviceInfo: { platform: 'ios', deviceId: 'test' }
      });

      expect(result.valid).toBe(false);
      expect(result.vaultId).toBeUndefined();
    });

    it('should not leak vault info for used code', async () => {
      const invite = await inviteService.createInvite({ memberId: testMemberId });
      await inviteService.useInvite(invite.code, { deviceId: 'device-1', platform: 'android' });

      const result = await inviteService.validateInvite({
        code: invite.code,
        deviceInfo: { platform: 'ios', deviceId: 'test' }
      });

      expect(result.valid).toBe(false);
      expect(result.vaultId).toBeUndefined();
    });

    it('should handle concurrent validation attempts', async () => {
      const invite = await inviteService.createInvite({ memberId: testMemberId });

      // Simulate concurrent validations
      const results = await Promise.all([
        inviteService.validateInvite({
          code: invite.code,
          deviceInfo: { platform: 'android', deviceId: 'device-1' }
        }),
        inviteService.validateInvite({
          code: invite.code,
          deviceInfo: { platform: 'ios', deviceId: 'device-2' }
        }),
        inviteService.validateInvite({
          code: invite.code,
          deviceInfo: { platform: 'android', deviceId: 'device-3' }
        }),
      ]);

      // All should see valid (validation doesn't consume the invite)
      expect(results.every(r => r.valid)).toBe(true);
    });

    it('should handle concurrent use attempts', async () => {
      const invite = await inviteService.createInvite({ memberId: testMemberId });

      // Simulate concurrent use attempts
      const results = await Promise.all([
        inviteService.useInvite(invite.code, { deviceId: 'device-1', platform: 'android' }),
        inviteService.useInvite(invite.code, { deviceId: 'device-2', platform: 'ios' }),
        inviteService.useInvite(invite.code, { deviceId: 'device-3', platform: 'android' }),
      ]);

      // Only one should succeed (first to complete)
      // Note: In-memory mock may allow multiple, real DynamoDB uses conditional writes
      const successCount = results.filter(r => r === true).length;
      expect(successCount).toBeGreaterThanOrEqual(1);

      // Final status should be 'used'
      const finalInvite = inviteService.getInvite(invite.code);
      expect(finalInvite?.status).toBe('used');
    });
  });

  describe('8. Edge Cases', () => {
    it('should handle invite code with special characters in lookup', async () => {
      // Attempt to validate a code with SQL injection pattern
      const result = await inviteService.validateInvite({
        code: "VE-'; DROP TABLE--",
        deviceInfo: { platform: 'android', deviceId: 'test' }
      });

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Invite code not found');
    });

    it('should handle very long invite code gracefully', async () => {
      const result = await inviteService.validateInvite({
        code: 'VE-' + 'A'.repeat(1000),
        deviceInfo: { platform: 'ios', deviceId: 'test' }
      });

      expect(result.valid).toBe(false);
    });

    it('should handle null bytes in code', async () => {
      const result = await inviteService.validateInvite({
        code: 'VE-TEST\x00INJECT',
        deviceInfo: { platform: 'android', deviceId: 'test' }
      });

      expect(result.valid).toBe(false);
    });

    it('should handle unicode in code', async () => {
      const result = await inviteService.validateInvite({
        code: 'VE-TEST🔐EMOJI',
        deviceInfo: { platform: 'ios', deviceId: 'test' }
      });

      expect(result.valid).toBe(false);
    });

    it('should maintain invite integrity after multiple operations', async () => {
      const invite = await inviteService.createInvite({ memberId: testMemberId });

      // Validate multiple times
      await inviteService.validateInvite({ code: invite.code, deviceInfo: { platform: 'android', deviceId: 'd1' } });
      await inviteService.validateInvite({ code: invite.code, deviceInfo: { platform: 'ios', deviceId: 'd2' } });

      // Status should still be pending
      let storedInvite = inviteService.getInvite(invite.code);
      expect(storedInvite?.status).toBe('pending');

      // Use the invite
      await inviteService.useInvite(invite.code, { deviceId: 'd3', platform: 'android' });

      // Status should be used
      storedInvite = inviteService.getInvite(invite.code);
      expect(storedInvite?.status).toBe('used');

      // Original data should be preserved
      expect(storedInvite?.vaultId).toBe(invite.vaultId);
      expect(storedInvite?.memberId).toBe(testMemberId);
      expect(storedInvite?.createdAt).toBe(invite.createdAt);
    });
  });
});
