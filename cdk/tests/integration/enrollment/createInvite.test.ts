/**
 * Integration Tests: Create Invite Endpoint
 *
 * Tests the POST /member/vault/deploy endpoint that:
 * - Creates a new vault for the member
 * - Generates an enrollment invite code
 * - Returns QR code data for mobile enrollment
 *
 * @see cdk/coordination/specs/vault-services-api.yaml
 * @see POST /member/vault/deploy
 */

import * as crypto from 'crypto';

// ============================================
// Types (matching API spec)
// ============================================

interface DeployVaultRequest {
  // Request body is empty - member ID from JWT token
}

interface DeployVaultResponse {
  vaultId: string;
  status: 'pending_enrollment';
  enrollmentQr: {
    data: string;  // Base64 encoded QR code data
    type: 'vettid_vault_enrollment';
  };
  expiresAt: string;
}

interface QRCodeData {
  type: 'vettid_vault_enrollment';
  vaultId: string;
  inviteCode: string;
  apiEndpoint: string;
  expiresAt: string;
}

interface MemberContext {
  memberId: string;
  email: string;
  subscriptionTier: 'free' | 'basic' | 'premium';
  vaultLimit: number;
}

// ============================================
// Mock Handler (simulates Lambda handler)
// ============================================

class MockCreateInviteHandler {
  private vaults: Map<string, {
    vaultId: string;
    memberId: string;
    status: string;
    inviteCode: string;
    createdAt: string;
    expiresAt: string;
  }> = new Map();

  private memberVaults: Map<string, string[]> = new Map(); // memberId -> vaultIds

  private readonly apiEndpoint = 'https://api.vettid.dev';
  private readonly inviteExpiryHours = 24;
  private readonly vaultLimits = {
    free: 1,
    basic: 3,
    premium: 10,
  };

  /**
   * Generate unique invite code
   */
  private generateInviteCode(): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let result = 'VE-';
    for (let i = 0; i < 12; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  }

  /**
   * Handle vault deployment request
   */
  async handle(memberContext: MemberContext): Promise<{
    statusCode: number;
    body: DeployVaultResponse | { error: string };
  }> {
    // Validate member context
    if (!memberContext.memberId) {
      return {
        statusCode: 401,
        body: { error: 'Unauthorized: Missing member ID' },
      };
    }

    // Check vault limit
    const existingVaults = this.memberVaults.get(memberContext.memberId) || [];
    const activeVaults = existingVaults.filter(vid => {
      const vault = this.vaults.get(vid);
      return vault && vault.status !== 'terminated';
    });

    const limit = this.vaultLimits[memberContext.subscriptionTier];
    if (activeVaults.length >= limit) {
      return {
        statusCode: 403,
        body: { error: `Vault limit reached: ${limit} vaults for ${memberContext.subscriptionTier} tier` },
      };
    }

    // Check for pending enrollment (only one at a time)
    const pendingVault = activeVaults.find(vid => {
      const vault = this.vaults.get(vid);
      return vault && vault.status === 'pending_enrollment';
    });

    if (pendingVault) {
      const vault = this.vaults.get(pendingVault)!;
      // Check if expired
      if (new Date(vault.expiresAt) > new Date()) {
        return {
          statusCode: 409,
          body: { error: 'Pending enrollment already exists. Complete or wait for expiry.' },
        };
      }
      // Mark as expired and allow new deployment
      vault.status = 'expired';
    }

    // Create new vault
    const vaultId = crypto.randomUUID();
    const inviteCode = this.generateInviteCode();
    const expiresAt = new Date(Date.now() + this.inviteExpiryHours * 60 * 60 * 1000).toISOString();

    const vault = {
      vaultId,
      memberId: memberContext.memberId,
      status: 'pending_enrollment',
      inviteCode,
      createdAt: new Date().toISOString(),
      expiresAt,
    };

    this.vaults.set(vaultId, vault);

    // Track member's vaults
    const memberVaultList = this.memberVaults.get(memberContext.memberId) || [];
    memberVaultList.push(vaultId);
    this.memberVaults.set(memberContext.memberId, memberVaultList);

    // Generate QR code data
    const qrData: QRCodeData = {
      type: 'vettid_vault_enrollment',
      vaultId,
      inviteCode,
      apiEndpoint: this.apiEndpoint,
      expiresAt,
    };

    const response: DeployVaultResponse = {
      vaultId,
      status: 'pending_enrollment',
      enrollmentQr: {
        data: Buffer.from(JSON.stringify(qrData)).toString('base64'),
        type: 'vettid_vault_enrollment',
      },
      expiresAt,
    };

    return {
      statusCode: 201,
      body: response,
    };
  }

  /**
   * Get vault by ID (for testing)
   */
  getVault(vaultId: string) {
    return this.vaults.get(vaultId);
  }

  /**
   * Get member's vaults (for testing)
   */
  getMemberVaults(memberId: string) {
    const ids = this.memberVaults.get(memberId) || [];
    return ids.map(id => this.vaults.get(id)).filter(Boolean);
  }

  /**
   * Update vault status (for testing)
   */
  updateVaultStatus(vaultId: string, status: string): void {
    const vault = this.vaults.get(vaultId);
    if (vault) {
      vault.status = status;
    }
  }

  /**
   * Clear all data (for testing)
   */
  clear(): void {
    this.vaults.clear();
    this.memberVaults.clear();
  }
}

// ============================================
// Tests
// ============================================

describe('Create Invite (Deploy Vault) Integration Tests', () => {
  let handler: MockCreateInviteHandler;

  beforeEach(() => {
    handler = new MockCreateInviteHandler();
  });

  describe('Successful Vault Deployment', () => {
    it('should create vault with 201 status', async () => {
      const result = await handler.handle({
        memberId: crypto.randomUUID(),
        email: 'member@test.com',
        subscriptionTier: 'basic',
        vaultLimit: 3,
      });

      expect(result.statusCode).toBe(201);
    });

    it('should return valid vault ID', async () => {
      const result = await handler.handle({
        memberId: crypto.randomUUID(),
        email: 'member@test.com',
        subscriptionTier: 'basic',
        vaultLimit: 3,
      });

      const body = result.body as DeployVaultResponse;
      expect(body.vaultId).toBeDefined();
      expect(body.vaultId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    });

    it('should return pending_enrollment status', async () => {
      const result = await handler.handle({
        memberId: crypto.randomUUID(),
        email: 'member@test.com',
        subscriptionTier: 'premium',
        vaultLimit: 10,
      });

      const body = result.body as DeployVaultResponse;
      expect(body.status).toBe('pending_enrollment');
    });

    it('should return valid QR code data', async () => {
      const result = await handler.handle({
        memberId: crypto.randomUUID(),
        email: 'member@test.com',
        subscriptionTier: 'basic',
        vaultLimit: 3,
      });

      const body = result.body as DeployVaultResponse;
      expect(body.enrollmentQr).toBeDefined();
      expect(body.enrollmentQr.type).toBe('vettid_vault_enrollment');
      expect(body.enrollmentQr.data).toBeDefined();

      // Decode and validate QR data
      const qrData = JSON.parse(Buffer.from(body.enrollmentQr.data, 'base64').toString()) as QRCodeData;
      expect(qrData.type).toBe('vettid_vault_enrollment');
      expect(qrData.vaultId).toBe(body.vaultId);
      expect(qrData.inviteCode).toMatch(/^VE-[A-Z0-9]{12}$/);
      expect(qrData.apiEndpoint).toBeDefined();
    });

    it('should set 24-hour expiration', async () => {
      const result = await handler.handle({
        memberId: crypto.randomUUID(),
        email: 'member@test.com',
        subscriptionTier: 'basic',
        vaultLimit: 3,
      });

      const body = result.body as DeployVaultResponse;
      const expiresAt = new Date(body.expiresAt);
      const expectedExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000);

      expect(Math.abs(expiresAt.getTime() - expectedExpiry.getTime())).toBeLessThan(1000);
    });

    it('should store vault in database', async () => {
      const memberId = crypto.randomUUID();
      const result = await handler.handle({
        memberId,
        email: 'member@test.com',
        subscriptionTier: 'basic',
        vaultLimit: 3,
      });

      const body = result.body as DeployVaultResponse;
      const vault = handler.getVault(body.vaultId);

      expect(vault).toBeDefined();
      expect(vault?.memberId).toBe(memberId);
      expect(vault?.status).toBe('pending_enrollment');
    });
  });

  describe('Authorization', () => {
    it('should reject request without member ID', async () => {
      const result = await handler.handle({
        memberId: '',
        email: 'member@test.com',
        subscriptionTier: 'basic',
        vaultLimit: 3,
      });

      expect(result.statusCode).toBe(401);
      expect((result.body as { error: string }).error).toContain('Unauthorized');
    });
  });

  describe('Vault Limits', () => {
    it('should enforce free tier limit (1 vault)', async () => {
      const memberId = crypto.randomUUID();
      const context: MemberContext = {
        memberId,
        email: 'free@test.com',
        subscriptionTier: 'free',
        vaultLimit: 1,
      };

      // First vault should succeed
      const result1 = await handler.handle(context);
      expect(result1.statusCode).toBe(201);

      // Mark first vault as enrolled (not pending)
      const body1 = result1.body as DeployVaultResponse;
      handler.updateVaultStatus(body1.vaultId, 'enrolled');

      // Second vault should fail
      const result2 = await handler.handle(context);
      expect(result2.statusCode).toBe(403);
      expect((result2.body as { error: string }).error).toContain('Vault limit reached');
    });

    it('should enforce basic tier limit (3 vaults)', async () => {
      const memberId = crypto.randomUUID();
      const context: MemberContext = {
        memberId,
        email: 'basic@test.com',
        subscriptionTier: 'basic',
        vaultLimit: 3,
      };

      // Create 3 vaults
      for (let i = 0; i < 3; i++) {
        const result = await handler.handle(context);
        expect(result.statusCode).toBe(201);
        const body = result.body as DeployVaultResponse;
        handler.updateVaultStatus(body.vaultId, 'enrolled');
      }

      // Fourth vault should fail
      const result = await handler.handle(context);
      expect(result.statusCode).toBe(403);
    });

    it('should not count terminated vaults toward limit', async () => {
      const memberId = crypto.randomUUID();
      const context: MemberContext = {
        memberId,
        email: 'free@test.com',
        subscriptionTier: 'free',
        vaultLimit: 1,
      };

      // Create and terminate first vault
      const result1 = await handler.handle(context);
      expect(result1.statusCode).toBe(201);
      const body1 = result1.body as DeployVaultResponse;
      handler.updateVaultStatus(body1.vaultId, 'terminated');

      // Second vault should succeed
      const result2 = await handler.handle(context);
      expect(result2.statusCode).toBe(201);
    });
  });

  describe('Pending Enrollment Handling', () => {
    it('should reject if pending enrollment exists', async () => {
      const memberId = crypto.randomUUID();
      const context: MemberContext = {
        memberId,
        email: 'member@test.com',
        subscriptionTier: 'basic',
        vaultLimit: 3,
      };

      // First deployment
      const result1 = await handler.handle(context);
      expect(result1.statusCode).toBe(201);

      // Second deployment while first is pending
      const result2 = await handler.handle(context);
      expect(result2.statusCode).toBe(409);
      expect((result2.body as { error: string }).error).toContain('Pending enrollment');
    });

    it('should allow new deployment after pending expires', async () => {
      const memberId = crypto.randomUUID();
      const context: MemberContext = {
        memberId,
        email: 'member@test.com',
        subscriptionTier: 'basic',
        vaultLimit: 3,
      };

      // First deployment
      const result1 = await handler.handle(context);
      expect(result1.statusCode).toBe(201);
      const body1 = result1.body as DeployVaultResponse;

      // Expire the pending enrollment
      const vault = handler.getVault(body1.vaultId);
      if (vault) {
        vault.expiresAt = new Date(Date.now() - 1000).toISOString();
      }

      // Second deployment should succeed
      const result2 = await handler.handle(context);
      expect(result2.statusCode).toBe(201);

      // First vault should be marked as expired
      expect(handler.getVault(body1.vaultId)?.status).toBe('expired');
    });

    it('should allow new deployment after enrollment completes', async () => {
      const memberId = crypto.randomUUID();
      const context: MemberContext = {
        memberId,
        email: 'member@test.com',
        subscriptionTier: 'basic',
        vaultLimit: 3,
      };

      // First deployment and complete enrollment
      const result1 = await handler.handle(context);
      expect(result1.statusCode).toBe(201);
      const body1 = result1.body as DeployVaultResponse;
      handler.updateVaultStatus(body1.vaultId, 'enrolled');

      // Second deployment should succeed
      const result2 = await handler.handle(context);
      expect(result2.statusCode).toBe(201);
    });
  });

  describe('QR Code Content', () => {
    it('should include all required fields in QR data', async () => {
      const result = await handler.handle({
        memberId: crypto.randomUUID(),
        email: 'member@test.com',
        subscriptionTier: 'basic',
        vaultLimit: 3,
      });

      const body = result.body as DeployVaultResponse;
      const qrData = JSON.parse(Buffer.from(body.enrollmentQr.data, 'base64').toString()) as QRCodeData;

      expect(qrData.type).toBe('vettid_vault_enrollment');
      expect(qrData.vaultId).toBeDefined();
      expect(qrData.inviteCode).toBeDefined();
      expect(qrData.apiEndpoint).toBeDefined();
      expect(qrData.expiresAt).toBeDefined();
    });

    it('should generate unique invite codes', async () => {
      const memberId = crypto.randomUUID();

      const inviteCodes: string[] = [];
      for (let i = 0; i < 5; i++) {
        const result = await handler.handle({
          memberId,
          email: 'member@test.com',
          subscriptionTier: 'premium',
          vaultLimit: 10,
        });

        const body = result.body as DeployVaultResponse;
        handler.updateVaultStatus(body.vaultId, 'enrolled');

        const qrData = JSON.parse(Buffer.from(body.enrollmentQr.data, 'base64').toString()) as QRCodeData;
        inviteCodes.push(qrData.inviteCode);
      }

      const uniqueCodes = new Set(inviteCodes);
      expect(uniqueCodes.size).toBe(5);
    });

    it('should match expiry in QR data and response', async () => {
      const result = await handler.handle({
        memberId: crypto.randomUUID(),
        email: 'member@test.com',
        subscriptionTier: 'basic',
        vaultLimit: 3,
      });

      const body = result.body as DeployVaultResponse;
      const qrData = JSON.parse(Buffer.from(body.enrollmentQr.data, 'base64').toString()) as QRCodeData;

      expect(qrData.expiresAt).toBe(body.expiresAt);
    });

    it('should include correct API endpoint', async () => {
      const result = await handler.handle({
        memberId: crypto.randomUUID(),
        email: 'member@test.com',
        subscriptionTier: 'basic',
        vaultLimit: 3,
      });

      const body = result.body as DeployVaultResponse;
      const qrData = JSON.parse(Buffer.from(body.enrollmentQr.data, 'base64').toString()) as QRCodeData;

      expect(qrData.apiEndpoint).toBe('https://api.vettid.dev');
    });
  });

  describe('Database Operations', () => {
    it('should track member vault associations', async () => {
      const memberId = crypto.randomUUID();

      for (let i = 0; i < 3; i++) {
        const result = await handler.handle({
          memberId,
          email: 'member@test.com',
          subscriptionTier: 'premium',
          vaultLimit: 10,
        });
        const body = result.body as DeployVaultResponse;
        handler.updateVaultStatus(body.vaultId, 'enrolled');
      }

      const memberVaults = handler.getMemberVaults(memberId);
      expect(memberVaults).toHaveLength(3);
      expect(memberVaults.every(v => v?.memberId === memberId)).toBe(true);
    });
  });
});
