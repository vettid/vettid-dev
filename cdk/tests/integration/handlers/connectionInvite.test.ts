/**
 * Integration Tests: Connection Invite Handler
 *
 * Tests the first-party connection invite handler:
 * - Generate invite code
 * - Include owner public key
 * - Set invite expiration
 * - Enforce max pending invites
 * - Revoke existing invites
 *
 * @see vault-manager/internal/handlers/builtin/connections.go (pending implementation)
 */

import * as crypto from 'crypto';
import {
  createConnectionInviteHandlerPackage,
  createExecutionContext,
} from '../../fixtures/handlers/mockHandler';

// ============================================
// Types
// ============================================

interface ConnectionInvite {
  invite_code: string;
  owner_id: string;
  owner_public_key: string;
  created_at: string;
  expires_at: string;
  max_uses: number;
  used_count: number;
  status: 'active' | 'expired' | 'revoked' | 'exhausted';
  note?: string;
}

interface CreateInviteInput {
  expires_in_hours?: number;
  max_uses?: number;
  note?: string;
}

interface CreateInviteResult {
  success: boolean;
  invite?: ConnectionInvite;
  error?: string;
}

// ============================================
// Mock Connection Invite Service
// ============================================

class MockConnectionInviteService {
  private invites: Map<string, ConnectionInvite> = new Map();
  private userInvites: Map<string, string[]> = new Map(); // user_id -> invite_codes
  private userPublicKeys: Map<string, string> = new Map();

  private maxPendingInvites = 5;
  private defaultExpiryHours = 24;
  private maxExpiryHours = 168; // 7 days
  private minExpiryHours = 1;
  private maxUses = 10;

  /**
   * Set user's public key
   */
  setUserPublicKey(userId: string, publicKey: string): void {
    this.userPublicKeys.set(userId, publicKey);
  }

  /**
   * Create a connection invite
   */
  async createInvite(
    userId: string,
    input: CreateInviteInput = {}
  ): Promise<CreateInviteResult> {
    // Check public key exists
    const publicKey = this.userPublicKeys.get(userId);
    if (!publicKey) {
      return { success: false, error: 'User public key not found' };
    }

    // Check pending invites limit
    const pendingCount = this.getPendingInviteCount(userId);
    if (pendingCount >= this.maxPendingInvites) {
      return {
        success: false,
        error: `Maximum pending invites (${this.maxPendingInvites}) reached`,
      };
    }

    // Validate expiry
    const expiryHours = input.expires_in_hours ?? this.defaultExpiryHours;
    if (expiryHours < this.minExpiryHours || expiryHours > this.maxExpiryHours) {
      return {
        success: false,
        error: `Expiry must be between ${this.minExpiryHours} and ${this.maxExpiryHours} hours`,
      };
    }

    // Validate max_uses
    const maxUses = input.max_uses ?? 1;
    if (maxUses < 1 || maxUses > this.maxUses) {
      return {
        success: false,
        error: `max_uses must be between 1 and ${this.maxUses}`,
      };
    }

    // Validate note length
    if (input.note && input.note.length > 200) {
      return {
        success: false,
        error: 'Note exceeds maximum length of 200 characters',
      };
    }

    // Generate invite
    const inviteCode = this.generateInviteCode();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + expiryHours * 60 * 60 * 1000);

    const invite: ConnectionInvite = {
      invite_code: inviteCode,
      owner_id: userId,
      owner_public_key: publicKey,
      created_at: now.toISOString(),
      expires_at: expiresAt.toISOString(),
      max_uses: maxUses,
      used_count: 0,
      status: 'active',
      note: input.note,
    };

    this.invites.set(inviteCode, invite);

    // Track user's invites
    let userInviteCodes = this.userInvites.get(userId);
    if (!userInviteCodes) {
      userInviteCodes = [];
      this.userInvites.set(userId, userInviteCodes);
    }
    userInviteCodes.push(inviteCode);

    return { success: true, invite };
  }

  /**
   * Generate a unique invite code
   */
  private generateInviteCode(): string {
    const bytes = crypto.randomBytes(12);
    return bytes.toString('base64url');
  }

  /**
   * Get pending invite count for user
   */
  getPendingInviteCount(userId: string): number {
    const inviteCodes = this.userInvites.get(userId) || [];
    return inviteCodes.filter(code => {
      const invite = this.invites.get(code);
      return invite && invite.status === 'active' && !this.isExpired(invite);
    }).length;
  }

  /**
   * Check if invite is expired
   */
  private isExpired(invite: ConnectionInvite): boolean {
    return new Date() > new Date(invite.expires_at);
  }

  /**
   * Get invite by code
   */
  getInvite(inviteCode: string): ConnectionInvite | undefined {
    const invite = this.invites.get(inviteCode);
    if (invite && this.isExpired(invite) && invite.status === 'active') {
      invite.status = 'expired';
    }
    return invite;
  }

  /**
   * Get all invites for user
   */
  getUserInvites(userId: string): ConnectionInvite[] {
    const inviteCodes = this.userInvites.get(userId) || [];
    return inviteCodes
      .map(code => this.getInvite(code))
      .filter((invite): invite is ConnectionInvite => invite !== undefined);
  }

  /**
   * Revoke an invite
   */
  revokeInvite(userId: string, inviteCode: string): boolean {
    const invite = this.invites.get(inviteCode);
    if (!invite || invite.owner_id !== userId) {
      return false;
    }

    if (invite.status !== 'active') {
      return false;
    }

    invite.status = 'revoked';
    return true;
  }

  /**
   * Use an invite (simulates accepting)
   */
  useInvite(inviteCode: string): boolean {
    const invite = this.invites.get(inviteCode);
    if (!invite) return false;

    if (invite.status !== 'active') return false;
    if (this.isExpired(invite)) {
      invite.status = 'expired';
      return false;
    }

    invite.used_count++;
    if (invite.used_count >= invite.max_uses) {
      invite.status = 'exhausted';
    }

    return true;
  }

  /**
   * Clear all state
   */
  clear(): void {
    this.invites.clear();
    this.userInvites.clear();
    this.userPublicKeys.clear();
  }
}

// ============================================
// Tests
// ============================================

describe('Connection Invite Handler', () => {
  let inviteService: MockConnectionInviteService;
  const testUserId = 'user-invite-123';
  const testPublicKey = 'public-key-xyz789';

  beforeEach(() => {
    inviteService = new MockConnectionInviteService();
    inviteService.setUserPublicKey(testUserId, testPublicKey);
  });

  afterEach(() => {
    inviteService.clear();
  });

  it('should generate invite code', async () => {
    const result = await inviteService.createInvite(testUserId);

    expect(result.success).toBe(true);
    expect(result.invite?.invite_code).toBeDefined();
    expect(result.invite?.invite_code.length).toBeGreaterThan(10);
  });

  it('should include owner public key', async () => {
    const result = await inviteService.createInvite(testUserId);

    expect(result.success).toBe(true);
    expect(result.invite?.owner_public_key).toBe(testPublicKey);
  });

  it('should set invite expiration', async () => {
    const result = await inviteService.createInvite(testUserId, {
      expires_in_hours: 48,
    });

    expect(result.success).toBe(true);
    expect(result.invite?.expires_at).toBeDefined();

    const expiresAt = new Date(result.invite!.expires_at);
    const now = new Date();
    const hoursUntilExpiry = (expiresAt.getTime() - now.getTime()) / (1000 * 60 * 60);

    expect(hoursUntilExpiry).toBeCloseTo(48, 0);
  });

  it('should enforce max pending invites', async () => {
    // Create max invites
    for (let i = 0; i < 5; i++) {
      await inviteService.createInvite(testUserId);
    }

    expect(inviteService.getPendingInviteCount(testUserId)).toBe(5);

    // Try to create one more
    const result = await inviteService.createInvite(testUserId);

    expect(result.success).toBe(false);
    expect(result.error).toContain('Maximum pending invites');
  });

  it('should revoke existing invite', async () => {
    const createResult = await inviteService.createInvite(testUserId);
    const inviteCode = createResult.invite!.invite_code;

    const revoked = inviteService.revokeInvite(testUserId, inviteCode);

    expect(revoked).toBe(true);

    const invite = inviteService.getInvite(inviteCode);
    expect(invite?.status).toBe('revoked');
  });

  it('should not revoke invite belonging to another user', async () => {
    const createResult = await inviteService.createInvite(testUserId);
    const inviteCode = createResult.invite!.invite_code;

    const revoked = inviteService.revokeInvite('other-user', inviteCode);

    expect(revoked).toBe(false);
  });

  it('should use default expiry when not specified', async () => {
    const result = await inviteService.createInvite(testUserId);

    const expiresAt = new Date(result.invite!.expires_at);
    const now = new Date();
    const hoursUntilExpiry = (expiresAt.getTime() - now.getTime()) / (1000 * 60 * 60);

    expect(hoursUntilExpiry).toBeCloseTo(24, 0); // Default 24 hours
  });

  it('should validate expiry range', async () => {
    // Too short
    const tooShort = await inviteService.createInvite(testUserId, {
      expires_in_hours: 0,
    });
    expect(tooShort.success).toBe(false);
    expect(tooShort.error).toContain('between');

    // Too long
    const tooLong = await inviteService.createInvite(testUserId, {
      expires_in_hours: 200,
    });
    expect(tooLong.success).toBe(false);
    expect(tooLong.error).toContain('between');
  });

  it('should validate max_uses range', async () => {
    // Too few
    const tooFew = await inviteService.createInvite(testUserId, {
      max_uses: 0,
    });
    expect(tooFew.success).toBe(false);

    // Too many
    const tooMany = await inviteService.createInvite(testUserId, {
      max_uses: 100,
    });
    expect(tooMany.success).toBe(false);
  });

  it('should track invite usage', async () => {
    const result = await inviteService.createInvite(testUserId, {
      max_uses: 3,
    });
    const inviteCode = result.invite!.invite_code;

    // Use invite multiple times
    expect(inviteService.useInvite(inviteCode)).toBe(true);
    expect(inviteService.useInvite(inviteCode)).toBe(true);
    expect(inviteService.useInvite(inviteCode)).toBe(true);

    // Should be exhausted now
    expect(inviteService.useInvite(inviteCode)).toBe(false);

    const invite = inviteService.getInvite(inviteCode);
    expect(invite?.status).toBe('exhausted');
  });

  it('should include optional note', async () => {
    const note = 'Invite for my friend John';

    const result = await inviteService.createInvite(testUserId, {
      note,
    });

    expect(result.success).toBe(true);
    expect(result.invite?.note).toBe(note);
  });

  it('should validate note length', async () => {
    const longNote = 'x'.repeat(250); // Exceeds 200 char limit

    const result = await inviteService.createInvite(testUserId, {
      note: longNote,
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain('Note');
    expect(result.error).toContain('200');
  });

  it('should generate unique invite codes', async () => {
    const codes = new Set<string>();

    for (let i = 0; i < 10; i++) {
      // Clear and reset to allow more invites
      inviteService.clear();
      inviteService.setUserPublicKey(testUserId, testPublicKey);

      const result = await inviteService.createInvite(testUserId);
      if (result.invite) {
        codes.add(result.invite.invite_code);
      }
    }

    expect(codes.size).toBe(10);
  });

  it('should list all user invites', async () => {
    await inviteService.createInvite(testUserId, { note: 'Invite 1' });
    await inviteService.createInvite(testUserId, { note: 'Invite 2' });
    await inviteService.createInvite(testUserId, { note: 'Invite 3' });

    const invites = inviteService.getUserInvites(testUserId);

    expect(invites).toHaveLength(3);
  });

  it('should require user public key', async () => {
    inviteService.clear(); // Remove the public key

    const result = await inviteService.createInvite(testUserId);

    expect(result.success).toBe(false);
    expect(result.error).toContain('public key');
  });

  it('should mark expired invites correctly', async () => {
    const result = await inviteService.createInvite(testUserId, {
      expires_in_hours: 1,
    });
    const inviteCode = result.invite!.invite_code;

    // Manually expire the invite for testing
    const invite = inviteService.getInvite(inviteCode);
    if (invite) {
      invite.expires_at = new Date(Date.now() - 1000).toISOString();
    }

    // Getting the invite should mark it expired
    const expiredInvite = inviteService.getInvite(inviteCode);
    expect(expiredInvite?.status).toBe('expired');
  });

  it('should not allow using expired invite', async () => {
    const result = await inviteService.createInvite(testUserId);
    const inviteCode = result.invite!.invite_code;

    // Manually expire
    const invite = inviteService.getInvite(inviteCode);
    if (invite) {
      invite.expires_at = new Date(Date.now() - 1000).toISOString();
    }

    const used = inviteService.useInvite(inviteCode);
    expect(used).toBe(false);
  });

  it('should not count expired invites towards pending limit', async () => {
    // Create max invites
    for (let i = 0; i < 5; i++) {
      const result = await inviteService.createInvite(testUserId);
      // Expire them
      const invite = inviteService.getInvite(result.invite!.invite_code);
      if (invite) {
        invite.expires_at = new Date(Date.now() - 1000).toISOString();
      }
    }

    // Should be able to create new invites
    expect(inviteService.getPendingInviteCount(testUserId)).toBe(0);

    const newResult = await inviteService.createInvite(testUserId);
    expect(newResult.success).toBe(true);
  });

  it('should include timestamps', async () => {
    const beforeCreate = new Date();
    const result = await inviteService.createInvite(testUserId);
    const afterCreate = new Date();

    expect(result.invite?.created_at).toBeDefined();
    const createdTime = new Date(result.invite!.created_at);
    expect(createdTime.getTime()).toBeGreaterThanOrEqual(beforeCreate.getTime());
    expect(createdTime.getTime()).toBeLessThanOrEqual(afterCreate.getTime());
  });
});
