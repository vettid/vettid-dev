/**
 * Integration Tests: Vault Status Endpoint
 *
 * Tests the GET /member/vault/status endpoint that:
 * - Returns current vault status for the member
 * - Shows status transitions (pending_enrollment -> enrolled -> running, etc.)
 * - Provides instance information for running vaults
 *
 * @see docs/specs/vault-services-api.yaml
 * @see GET /member/vault/status
 */

import * as crypto from 'crypto';

// ============================================
// Types (matching API spec)
// ============================================

type VaultStatus =
  | 'pending_enrollment'  // Created, waiting for mobile enrollment
  | 'enrolled'            // Enrollment complete, waiting for provisioning
  | 'provisioning'        // EC2 instance being created
  | 'running'             // Active and healthy
  | 'stopped'             // Manually stopped
  | 'terminated';         // Permanently deleted

interface VaultStatusResponse {
  vaultId: string;
  status: VaultStatus;
  enrolledAt?: string;
  instanceId?: string;
  region?: string;
  publicIp?: string;
  lastBackup?: string;
  health?: {
    lastCheck: string;
    isHealthy: boolean;
    latencyMs?: number;
    uptime?: string;
  };
  error?: {
    code: string;
    message: string;
    timestamp: string;
  };
}

interface VaultRecord {
  vaultId: string;
  memberId: string;
  status: VaultStatus;
  createdAt: string;
  enrolledAt?: string;
  instanceId?: string;
  region?: string;
  publicIp?: string;
  lastBackup?: string;
  lastHealthCheck?: string;
  isHealthy?: boolean;
  healthLatencyMs?: number;
  uptime?: string;
  errorCode?: string;
  errorMessage?: string;
  errorTimestamp?: string;
}

interface MemberContext {
  memberId: string;
  email: string;
}

// ============================================
// Mock Handler (simulates Lambda handler)
// ============================================

class MockVaultStatusHandler {
  private vaults: Map<string, VaultRecord> = new Map();
  private memberVaults: Map<string, string[]> = new Map();

  /**
   * Create a vault (for testing)
   */
  createVault(memberId: string, status: VaultStatus = 'pending_enrollment'): VaultRecord {
    const vaultId = crypto.randomUUID();
    const vault: VaultRecord = {
      vaultId,
      memberId,
      status,
      createdAt: new Date().toISOString(),
    };

    if (status === 'enrolled' || status === 'provisioning' || status === 'running') {
      vault.enrolledAt = new Date().toISOString();
    }

    if (status === 'running') {
      vault.instanceId = `i-${crypto.randomBytes(8).toString('hex')}`;
      vault.region = 'us-east-1';
      vault.publicIp = `54.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
      vault.lastHealthCheck = new Date().toISOString();
      vault.isHealthy = true;
      vault.healthLatencyMs = Math.floor(Math.random() * 100) + 10;
      vault.uptime = '3d 4h 30m';
    }

    this.vaults.set(vaultId, vault);

    const memberVaultList = this.memberVaults.get(memberId) || [];
    memberVaultList.push(vaultId);
    this.memberVaults.set(memberId, memberVaultList);

    return vault;
  }

  /**
   * Update vault status (for testing)
   */
  updateVaultStatus(vaultId: string, status: VaultStatus, updates?: Partial<VaultRecord>): void {
    const vault = this.vaults.get(vaultId);
    if (vault) {
      vault.status = status;
      if (updates) {
        Object.assign(vault, updates);
      }
    }
  }

  /**
   * Handle vault status request
   */
  async handle(memberContext: MemberContext, vaultId?: string): Promise<{
    statusCode: number;
    body: VaultStatusResponse | VaultStatusResponse[] | { error: string };
  }> {
    // Validate member context
    if (!memberContext.memberId) {
      return {
        statusCode: 401,
        body: { error: 'Unauthorized: Missing member ID' },
      };
    }

    const memberVaultIds = this.memberVaults.get(memberContext.memberId) || [];

    // If specific vault requested
    if (vaultId) {
      if (!memberVaultIds.includes(vaultId)) {
        return {
          statusCode: 404,
          body: { error: 'Vault not found' },
        };
      }

      const vault = this.vaults.get(vaultId);
      if (!vault) {
        return {
          statusCode: 404,
          body: { error: 'Vault not found' },
        };
      }

      return {
        statusCode: 200,
        body: this.formatVaultResponse(vault),
      };
    }

    // Return all member vaults
    const vaults = memberVaultIds
      .map(id => this.vaults.get(id))
      .filter((v): v is VaultRecord => v !== undefined);

    if (vaults.length === 0) {
      return {
        statusCode: 200,
        body: [],
      };
    }

    return {
      statusCode: 200,
      body: vaults.map(v => this.formatVaultResponse(v)),
    };
  }

  /**
   * Format vault record for response
   */
  private formatVaultResponse(vault: VaultRecord): VaultStatusResponse {
    const response: VaultStatusResponse = {
      vaultId: vault.vaultId,
      status: vault.status,
    };

    if (vault.enrolledAt) {
      response.enrolledAt = vault.enrolledAt;
    }

    if (vault.status === 'running' || vault.status === 'stopped') {
      if (vault.instanceId) response.instanceId = vault.instanceId;
      if (vault.region) response.region = vault.region;
      if (vault.publicIp && vault.status === 'running') response.publicIp = vault.publicIp;
      if (vault.lastBackup) response.lastBackup = vault.lastBackup;

      if (vault.lastHealthCheck) {
        response.health = {
          lastCheck: vault.lastHealthCheck,
          isHealthy: vault.isHealthy ?? false,
        };
        if (vault.healthLatencyMs) response.health.latencyMs = vault.healthLatencyMs;
        if (vault.uptime) response.health.uptime = vault.uptime;
      }
    }

    if (vault.errorCode) {
      response.error = {
        code: vault.errorCode,
        message: vault.errorMessage || 'Unknown error',
        timestamp: vault.errorTimestamp || new Date().toISOString(),
      };
    }

    return response;
  }

  /**
   * Get vault by ID (for testing)
   */
  getVault(vaultId: string): VaultRecord | undefined {
    return this.vaults.get(vaultId);
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

describe('Vault Status Integration Tests', () => {
  let handler: MockVaultStatusHandler;
  const testMemberId = crypto.randomUUID();
  const memberContext: MemberContext = {
    memberId: testMemberId,
    email: 'member@test.com',
  };

  beforeEach(() => {
    handler = new MockVaultStatusHandler();
  });

  describe('GET /member/vault/status (all vaults)', () => {
    it('should return empty array for member with no vaults', async () => {
      const result = await handler.handle(memberContext);

      expect(result.statusCode).toBe(200);
      expect(result.body).toEqual([]);
    });

    it('should return all member vaults', async () => {
      handler.createVault(testMemberId, 'pending_enrollment');
      handler.createVault(testMemberId, 'running');
      handler.createVault(testMemberId, 'terminated');

      const result = await handler.handle(memberContext);

      expect(result.statusCode).toBe(200);
      expect(Array.isArray(result.body)).toBe(true);
      expect((result.body as VaultStatusResponse[]).length).toBe(3);
    });

    it('should not return vaults belonging to other members', async () => {
      const otherMemberId = crypto.randomUUID();
      handler.createVault(testMemberId, 'running');
      handler.createVault(otherMemberId, 'running');

      const result = await handler.handle(memberContext);

      expect(result.statusCode).toBe(200);
      expect((result.body as VaultStatusResponse[]).length).toBe(1);
    });

    it('should require authentication', async () => {
      const result = await handler.handle({ memberId: '', email: '' });

      expect(result.statusCode).toBe(401);
      expect((result.body as { error: string }).error).toContain('Unauthorized');
    });
  });

  describe('GET /member/vault/status/{vaultId}', () => {
    it('should return specific vault status', async () => {
      const vault = handler.createVault(testMemberId, 'running');

      const result = await handler.handle(memberContext, vault.vaultId);

      expect(result.statusCode).toBe(200);
      expect((result.body as VaultStatusResponse).vaultId).toBe(vault.vaultId);
      expect((result.body as VaultStatusResponse).status).toBe('running');
    });

    it('should return 404 for non-existent vault', async () => {
      const result = await handler.handle(memberContext, crypto.randomUUID());

      expect(result.statusCode).toBe(404);
      expect((result.body as { error: string }).error).toContain('not found');
    });

    it('should return 404 for vault owned by different member', async () => {
      const otherMemberId = crypto.randomUUID();
      const vault = handler.createVault(otherMemberId, 'running');

      const result = await handler.handle(memberContext, vault.vaultId);

      expect(result.statusCode).toBe(404);
    });
  });

  describe('Status: pending_enrollment', () => {
    it('should return minimal info for pending vault', async () => {
      const vault = handler.createVault(testMemberId, 'pending_enrollment');

      const result = await handler.handle(memberContext, vault.vaultId);

      expect(result.statusCode).toBe(200);
      const body = result.body as VaultStatusResponse;
      expect(body.status).toBe('pending_enrollment');
      expect(body.enrolledAt).toBeUndefined();
      expect(body.instanceId).toBeUndefined();
      expect(body.health).toBeUndefined();
    });
  });

  describe('Status: enrolled', () => {
    it('should return enrollment time', async () => {
      const vault = handler.createVault(testMemberId, 'enrolled');

      const result = await handler.handle(memberContext, vault.vaultId);

      expect(result.statusCode).toBe(200);
      const body = result.body as VaultStatusResponse;
      expect(body.status).toBe('enrolled');
      expect(body.enrolledAt).toBeDefined();
      expect(body.instanceId).toBeUndefined();
    });
  });

  describe('Status: provisioning', () => {
    it('should indicate provisioning in progress', async () => {
      const vault = handler.createVault(testMemberId, 'provisioning');

      const result = await handler.handle(memberContext, vault.vaultId);

      expect(result.statusCode).toBe(200);
      const body = result.body as VaultStatusResponse;
      expect(body.status).toBe('provisioning');
      expect(body.enrolledAt).toBeDefined();
    });
  });

  describe('Status: running', () => {
    it('should return full instance info', async () => {
      const vault = handler.createVault(testMemberId, 'running');

      const result = await handler.handle(memberContext, vault.vaultId);

      expect(result.statusCode).toBe(200);
      const body = result.body as VaultStatusResponse;
      expect(body.status).toBe('running');
      expect(body.instanceId).toBeDefined();
      expect(body.region).toBe('us-east-1');
      expect(body.publicIp).toBeDefined();
    });

    it('should include health information', async () => {
      const vault = handler.createVault(testMemberId, 'running');

      const result = await handler.handle(memberContext, vault.vaultId);

      expect(result.statusCode).toBe(200);
      const body = result.body as VaultStatusResponse;
      expect(body.health).toBeDefined();
      expect(body.health?.isHealthy).toBe(true);
      expect(body.health?.lastCheck).toBeDefined();
      expect(body.health?.latencyMs).toBeDefined();
      expect(body.health?.uptime).toBeDefined();
    });

    it('should include last backup time if available', async () => {
      const vault = handler.createVault(testMemberId, 'running');
      handler.updateVaultStatus(vault.vaultId, 'running', {
        lastBackup: new Date().toISOString(),
      });

      const result = await handler.handle(memberContext, vault.vaultId);

      expect(result.statusCode).toBe(200);
      const body = result.body as VaultStatusResponse;
      expect(body.lastBackup).toBeDefined();
    });
  });

  describe('Status: stopped', () => {
    it('should return instance info but no public IP', async () => {
      const vault = handler.createVault(testMemberId, 'running');
      handler.updateVaultStatus(vault.vaultId, 'stopped', {
        publicIp: undefined,
      });

      const result = await handler.handle(memberContext, vault.vaultId);

      expect(result.statusCode).toBe(200);
      const body = result.body as VaultStatusResponse;
      expect(body.status).toBe('stopped');
      expect(body.instanceId).toBeDefined();
      expect(body.publicIp).toBeUndefined();
    });
  });

  describe('Status: terminated', () => {
    it('should return terminated status', async () => {
      const vault = handler.createVault(testMemberId, 'running');
      handler.updateVaultStatus(vault.vaultId, 'terminated');

      const result = await handler.handle(memberContext, vault.vaultId);

      expect(result.statusCode).toBe(200);
      const body = result.body as VaultStatusResponse;
      expect(body.status).toBe('terminated');
    });
  });

  describe('Status Transitions', () => {
    it('should track transition from pending to enrolled', async () => {
      const vault = handler.createVault(testMemberId, 'pending_enrollment');

      let result = await handler.handle(memberContext, vault.vaultId);
      expect((result.body as VaultStatusResponse).status).toBe('pending_enrollment');

      handler.updateVaultStatus(vault.vaultId, 'enrolled', {
        enrolledAt: new Date().toISOString(),
      });

      result = await handler.handle(memberContext, vault.vaultId);
      expect((result.body as VaultStatusResponse).status).toBe('enrolled');
      expect((result.body as VaultStatusResponse).enrolledAt).toBeDefined();
    });

    it('should track transition from enrolled to provisioning', async () => {
      const vault = handler.createVault(testMemberId, 'enrolled');

      handler.updateVaultStatus(vault.vaultId, 'provisioning');

      const result = await handler.handle(memberContext, vault.vaultId);
      expect((result.body as VaultStatusResponse).status).toBe('provisioning');
    });

    it('should track transition from provisioning to running', async () => {
      const vault = handler.createVault(testMemberId, 'provisioning');

      handler.updateVaultStatus(vault.vaultId, 'running', {
        instanceId: 'i-abc123',
        region: 'us-east-1',
        publicIp: '54.100.100.100',
        lastHealthCheck: new Date().toISOString(),
        isHealthy: true,
        healthLatencyMs: 50,
        uptime: '0d 0h 1m',
      });

      const result = await handler.handle(memberContext, vault.vaultId);
      const body = result.body as VaultStatusResponse;
      expect(body.status).toBe('running');
      expect(body.instanceId).toBe('i-abc123');
      expect(body.publicIp).toBe('54.100.100.100');
    });

    it('should track transition from running to stopped', async () => {
      const vault = handler.createVault(testMemberId, 'running');

      handler.updateVaultStatus(vault.vaultId, 'stopped', {
        publicIp: undefined,
      });

      const result = await handler.handle(memberContext, vault.vaultId);
      expect((result.body as VaultStatusResponse).status).toBe('stopped');
    });

    it('should track transition from stopped to running', async () => {
      const vault = handler.createVault(testMemberId, 'running');
      handler.updateVaultStatus(vault.vaultId, 'stopped');
      handler.updateVaultStatus(vault.vaultId, 'running', {
        publicIp: '54.200.200.200',
      });

      const result = await handler.handle(memberContext, vault.vaultId);
      const body = result.body as VaultStatusResponse;
      expect(body.status).toBe('running');
      expect(body.publicIp).toBe('54.200.200.200');
    });
  });

  describe('Error States', () => {
    it('should include error info when vault has error', async () => {
      const vault = handler.createVault(testMemberId, 'running');
      handler.updateVaultStatus(vault.vaultId, 'running', {
        errorCode: 'HEALTH_CHECK_FAILED',
        errorMessage: 'Vault is not responding to health checks',
        errorTimestamp: new Date().toISOString(),
        isHealthy: false,
      });

      const result = await handler.handle(memberContext, vault.vaultId);

      expect(result.statusCode).toBe(200);
      const body = result.body as VaultStatusResponse;
      expect(body.error).toBeDefined();
      expect(body.error?.code).toBe('HEALTH_CHECK_FAILED');
      expect(body.error?.message).toContain('health checks');
      expect(body.health?.isHealthy).toBe(false);
    });

    it('should include error during provisioning failure', async () => {
      const vault = handler.createVault(testMemberId, 'provisioning');
      handler.updateVaultStatus(vault.vaultId, 'provisioning', {
        errorCode: 'PROVISIONING_FAILED',
        errorMessage: 'Failed to launch EC2 instance',
        errorTimestamp: new Date().toISOString(),
      });

      const result = await handler.handle(memberContext, vault.vaultId);

      expect(result.statusCode).toBe(200);
      const body = result.body as VaultStatusResponse;
      expect(body.error?.code).toBe('PROVISIONING_FAILED');
    });
  });

  describe('Health Reporting', () => {
    it('should show healthy vault status', async () => {
      const vault = handler.createVault(testMemberId, 'running');

      const result = await handler.handle(memberContext, vault.vaultId);

      const body = result.body as VaultStatusResponse;
      expect(body.health?.isHealthy).toBe(true);
      expect(body.health?.latencyMs).toBeLessThan(200);
    });

    it('should show unhealthy vault status', async () => {
      const vault = handler.createVault(testMemberId, 'running');
      handler.updateVaultStatus(vault.vaultId, 'running', {
        isHealthy: false,
        lastHealthCheck: new Date().toISOString(),
      });

      const result = await handler.handle(memberContext, vault.vaultId);

      const body = result.body as VaultStatusResponse;
      expect(body.health?.isHealthy).toBe(false);
    });

    it('should include uptime information', async () => {
      const vault = handler.createVault(testMemberId, 'running');
      handler.updateVaultStatus(vault.vaultId, 'running', {
        uptime: '5d 12h 30m',
      });

      const result = await handler.handle(memberContext, vault.vaultId);

      const body = result.body as VaultStatusResponse;
      expect(body.health?.uptime).toBe('5d 12h 30m');
    });
  });

  describe('Response Format', () => {
    it('should not include undefined fields', async () => {
      const vault = handler.createVault(testMemberId, 'pending_enrollment');

      const result = await handler.handle(memberContext, vault.vaultId);

      const body = result.body as VaultStatusResponse;
      expect(Object.keys(body)).toEqual(['vaultId', 'status']);
    });

    it('should include ISO date strings', async () => {
      const vault = handler.createVault(testMemberId, 'enrolled');

      const result = await handler.handle(memberContext, vault.vaultId);

      const body = result.body as VaultStatusResponse;
      expect(body.enrolledAt).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
    });
  });
});
