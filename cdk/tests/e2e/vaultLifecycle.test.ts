/**
 * E2E Tests: Full Vault Lifecycle
 *
 * Tests the complete vault lifecycle:
 * - Provision → Initialize → Health → Stop → Restart → Terminate
 * - Recovery from failures
 * - Concurrent operations
 *
 * Uses mock services to simulate actual AWS infrastructure behavior.
 */

import * as crypto from 'crypto';

// ============================================
// Types
// ============================================

interface VaultState {
  user_guid: string;
  instance_id?: string;
  status: 'none' | 'provisioning' | 'running' | 'stopped' | 'terminated' | 'failed';
  initialized: boolean;
  nats_account_active: boolean;
  security_group_id?: string;
  owner_space_id?: string;
  message_space_id?: string;
  local_nats_running: boolean;
  central_nats_connected: boolean;
  vault_manager_running: boolean;
  pending_events: number;
}

interface MemberClaims {
  user_guid: string;
  email: string;
}

// ============================================
// Mock Vault Lifecycle Service
// ============================================

class MockVaultLifecycleService {
  private vaults: Map<string, VaultState> = new Map();

  /**
   * Create NATS account (prerequisite)
   */
  async createNatsAccount(userGuid: string): Promise<{ owner_space_id: string; message_space_id: string }> {
    let vault = this.vaults.get(userGuid);
    if (!vault) {
      vault = this.createInitialState(userGuid);
      this.vaults.set(userGuid, vault);
    }

    vault.nats_account_active = true;
    vault.owner_space_id = `OwnerSpace.${userGuid}`;
    vault.message_space_id = `MessageSpace.${userGuid}`;

    return {
      owner_space_id: vault.owner_space_id,
      message_space_id: vault.message_space_id,
    };
  }

  /**
   * Provision vault
   */
  async provision(claims: MemberClaims): Promise<{
    success: boolean;
    instance_id?: string;
    error?: string;
  }> {
    const vault = this.vaults.get(claims.user_guid);
    if (!vault) {
      return { success: false, error: 'NATS account not created' };
    }

    if (!vault.nats_account_active) {
      return { success: false, error: 'NATS account not active' };
    }

    if (vault.status !== 'none' && vault.status !== 'terminated' && vault.status !== 'failed') {
      return { success: false, error: 'Vault already exists' };
    }

    vault.status = 'provisioning';
    vault.instance_id = `i-${crypto.randomBytes(8).toString('hex')}`;
    vault.security_group_id = `sg-${crypto.randomBytes(8).toString('hex')}`;

    // Simulate provisioning delay
    await new Promise(resolve => setTimeout(resolve, 10));

    vault.status = 'running';

    return { success: true, instance_id: vault.instance_id };
  }

  /**
   * Initialize vault
   */
  async initialize(claims: MemberClaims, instanceId: string): Promise<{
    success: boolean;
    error?: string;
  }> {
    const vault = this.vaults.get(claims.user_guid);
    if (!vault) {
      return { success: false, error: 'Vault not found' };
    }

    if (vault.instance_id !== instanceId) {
      return { success: false, error: 'Instance ID mismatch' };
    }

    if (vault.status !== 'running') {
      return { success: false, error: `Cannot initialize: vault is ${vault.status}` };
    }

    if (vault.initialized) {
      return { success: true }; // Already initialized
    }

    vault.local_nats_running = true;
    vault.central_nats_connected = true;
    vault.vault_manager_running = true;
    vault.initialized = true;

    return { success: true };
  }

  /**
   * Get health status
   */
  async getHealth(claims: MemberClaims): Promise<{
    success: boolean;
    status?: 'healthy' | 'unhealthy' | 'degraded';
    error?: string;
  }> {
    const vault = this.vaults.get(claims.user_guid);
    if (!vault) {
      return { success: false, error: 'Vault not found' };
    }

    if (!vault.initialized) {
      return { success: false, error: 'Vault not initialized' };
    }

    if (vault.status !== 'running') {
      return { success: false, error: `Vault is ${vault.status}` };
    }

    const isHealthy = vault.local_nats_running &&
                      vault.central_nats_connected &&
                      vault.vault_manager_running;

    return {
      success: true,
      status: isHealthy ? 'healthy' : 'unhealthy',
    };
  }

  /**
   * Stop vault
   */
  async stop(claims: MemberClaims, instanceId: string): Promise<{
    success: boolean;
    error?: string;
  }> {
    const vault = this.vaults.get(claims.user_guid);
    if (!vault) {
      return { success: false, error: 'Vault not found' };
    }

    if (vault.instance_id !== instanceId) {
      return { success: false, error: 'Instance ID mismatch' };
    }

    if (vault.status === 'stopped') {
      return { success: true }; // Already stopped
    }

    if (vault.status !== 'running') {
      return { success: false, error: `Cannot stop: vault is ${vault.status}` };
    }

    // Flush events
    vault.pending_events = 0;
    vault.central_nats_connected = false;
    vault.vault_manager_running = false;
    vault.local_nats_running = false;
    vault.status = 'stopped';

    return { success: true };
  }

  /**
   * Restart vault (start after stop)
   */
  async restart(claims: MemberClaims, instanceId: string): Promise<{
    success: boolean;
    error?: string;
  }> {
    const vault = this.vaults.get(claims.user_guid);
    if (!vault) {
      return { success: false, error: 'Vault not found' };
    }

    if (vault.instance_id !== instanceId) {
      return { success: false, error: 'Instance ID mismatch' };
    }

    if (vault.status !== 'stopped') {
      return { success: false, error: `Cannot restart: vault is ${vault.status}` };
    }

    vault.status = 'running';
    vault.local_nats_running = true;
    vault.central_nats_connected = true;
    vault.vault_manager_running = true;

    return { success: true };
  }

  /**
   * Terminate vault
   */
  async terminate(claims: MemberClaims, instanceId: string): Promise<{
    success: boolean;
    error?: string;
  }> {
    const vault = this.vaults.get(claims.user_guid);
    if (!vault) {
      return { success: false, error: 'Vault not found' };
    }

    if (vault.instance_id !== instanceId) {
      return { success: false, error: 'Instance ID mismatch' };
    }

    if (vault.status === 'terminated') {
      return { success: true }; // Already terminated
    }

    // Stop if running
    if (vault.status === 'running') {
      vault.pending_events = 0;
      vault.central_nats_connected = false;
      vault.vault_manager_running = false;
      vault.local_nats_running = false;
    }

    vault.status = 'terminated';
    vault.initialized = false;

    return { success: true };
  }

  /**
   * Simulate initialization failure
   */
  simulateInitializationFailure(userGuid: string): void {
    const vault = this.vaults.get(userGuid);
    if (vault) {
      vault.local_nats_running = false;
      vault.central_nats_connected = false;
      vault.vault_manager_running = false;
      vault.initialized = false;
      vault.status = 'failed';
    }
  }

  /**
   * Get vault state
   */
  getVaultState(userGuid: string): VaultState | undefined {
    return this.vaults.get(userGuid);
  }

  private createInitialState(userGuid: string): VaultState {
    return {
      user_guid: userGuid,
      status: 'none',
      initialized: false,
      nats_account_active: false,
      local_nats_running: false,
      central_nats_connected: false,
      vault_manager_running: false,
      pending_events: 0,
    };
  }

  clear(): void {
    this.vaults.clear();
  }
}

// ============================================
// Tests
// ============================================

describe('Full Vault Lifecycle', () => {
  let service: MockVaultLifecycleService;

  beforeEach(() => {
    service = new MockVaultLifecycleService();
  });

  describe('Complete Lifecycle: provision → initialize → health → stop → terminate', () => {
    it('should complete full lifecycle successfully', async () => {
      const userGuid = crypto.randomUUID();
      const claims: MemberClaims = { user_guid: userGuid, email: 'user@test.com' };

      // Step 1: Create NATS account
      const natsResult = await service.createNatsAccount(userGuid);
      expect(natsResult.owner_space_id).toBe(`OwnerSpace.${userGuid}`);

      // Step 2: Provision
      const provisionResult = await service.provision(claims);
      expect(provisionResult.success).toBe(true);
      expect(provisionResult.instance_id).toBeDefined();

      const instanceId = provisionResult.instance_id!;

      // Step 3: Initialize
      const initResult = await service.initialize(claims, instanceId);
      expect(initResult.success).toBe(true);

      // Step 4: Health check
      const healthResult = await service.getHealth(claims);
      expect(healthResult.success).toBe(true);
      expect(healthResult.status).toBe('healthy');

      // Step 5: Stop
      const stopResult = await service.stop(claims, instanceId);
      expect(stopResult.success).toBe(true);

      // Step 6: Terminate
      const terminateResult = await service.terminate(claims, instanceId);
      expect(terminateResult.success).toBe(true);

      // Verify final state
      const finalState = service.getVaultState(userGuid);
      expect(finalState?.status).toBe('terminated');
    });

    it('should track state through lifecycle', async () => {
      const userGuid = crypto.randomUUID();
      const claims: MemberClaims = { user_guid: userGuid, email: 'user@test.com' };

      await service.createNatsAccount(userGuid);

      // Before provision
      let state = service.getVaultState(userGuid);
      expect(state?.status).toBe('none');

      // After provision
      const { instance_id } = await service.provision(claims);
      state = service.getVaultState(userGuid);
      expect(state?.status).toBe('running');
      expect(state?.initialized).toBe(false);

      // After initialize
      await service.initialize(claims, instance_id!);
      state = service.getVaultState(userGuid);
      expect(state?.initialized).toBe(true);
      expect(state?.local_nats_running).toBe(true);
      expect(state?.central_nats_connected).toBe(true);

      // After stop
      await service.stop(claims, instance_id!);
      state = service.getVaultState(userGuid);
      expect(state?.status).toBe('stopped');
      expect(state?.local_nats_running).toBe(false);
      expect(state?.central_nats_connected).toBe(false);

      // After terminate
      await service.terminate(claims, instance_id!);
      state = service.getVaultState(userGuid);
      expect(state?.status).toBe('terminated');
    });
  });

  describe('Restart After Stop', () => {
    it('should allow restart after stop', async () => {
      const userGuid = crypto.randomUUID();
      const claims: MemberClaims = { user_guid: userGuid, email: 'user@test.com' };

      await service.createNatsAccount(userGuid);
      const { instance_id } = await service.provision(claims);
      await service.initialize(claims, instance_id!);
      await service.stop(claims, instance_id!);

      // Restart
      const restartResult = await service.restart(claims, instance_id!);
      expect(restartResult.success).toBe(true);

      // Verify running
      const state = service.getVaultState(userGuid);
      expect(state?.status).toBe('running');
      expect(state?.local_nats_running).toBe(true);
      expect(state?.central_nats_connected).toBe(true);
    });

    it('should maintain initialized state after restart', async () => {
      const userGuid = crypto.randomUUID();
      const claims: MemberClaims = { user_guid: userGuid, email: 'user@test.com' };

      await service.createNatsAccount(userGuid);
      const { instance_id } = await service.provision(claims);
      await service.initialize(claims, instance_id!);
      await service.stop(claims, instance_id!);
      await service.restart(claims, instance_id!);

      const state = service.getVaultState(userGuid);
      expect(state?.initialized).toBe(true);
    });

    it('should be healthy after restart', async () => {
      const userGuid = crypto.randomUUID();
      const claims: MemberClaims = { user_guid: userGuid, email: 'user@test.com' };

      await service.createNatsAccount(userGuid);
      const { instance_id } = await service.provision(claims);
      await service.initialize(claims, instance_id!);
      await service.stop(claims, instance_id!);
      await service.restart(claims, instance_id!);

      const healthResult = await service.getHealth(claims);
      expect(healthResult.status).toBe('healthy');
    });
  });

  describe('Recovery From Initialization Failure', () => {
    it('should recover from initialization failure', async () => {
      const userGuid = crypto.randomUUID();
      const claims: MemberClaims = { user_guid: userGuid, email: 'user@test.com' };

      await service.createNatsAccount(userGuid);
      const { instance_id } = await service.provision(claims);

      // Simulate failure
      service.simulateInitializationFailure(userGuid);

      // Terminate and re-provision
      await service.terminate(claims, instance_id!);

      const reprovisionResult = await service.provision(claims);
      expect(reprovisionResult.success).toBe(true);

      const newInstanceId = reprovisionResult.instance_id!;
      expect(newInstanceId).not.toBe(instance_id);

      const reinitResult = await service.initialize(claims, newInstanceId);
      expect(reinitResult.success).toBe(true);

      const healthResult = await service.getHealth(claims);
      expect(healthResult.status).toBe('healthy');
    });

    it('should allow re-provisioning after failed state', async () => {
      const userGuid = crypto.randomUUID();
      const claims: MemberClaims = { user_guid: userGuid, email: 'user@test.com' };

      await service.createNatsAccount(userGuid);
      const { instance_id } = await service.provision(claims);

      // Simulate failure
      service.simulateInitializationFailure(userGuid);

      const state = service.getVaultState(userGuid);
      expect(state?.status).toBe('failed');

      // Should be able to terminate
      await service.terminate(claims, instance_id!);

      // Should be able to re-provision
      const reprovisionResult = await service.provision(claims);
      expect(reprovisionResult.success).toBe(true);
    });
  });

  describe('Concurrent Health Checks', () => {
    it('should handle concurrent health checks', async () => {
      const userGuid = crypto.randomUUID();
      const claims: MemberClaims = { user_guid: userGuid, email: 'user@test.com' };

      await service.createNatsAccount(userGuid);
      const { instance_id } = await service.provision(claims);
      await service.initialize(claims, instance_id!);

      // Concurrent health checks
      const healthChecks = await Promise.all([
        service.getHealth(claims),
        service.getHealth(claims),
        service.getHealth(claims),
        service.getHealth(claims),
        service.getHealth(claims),
      ]);

      expect(healthChecks.every(h => h.success)).toBe(true);
      expect(healthChecks.every(h => h.status === 'healthy')).toBe(true);
    });
  });

  describe('Error Cases', () => {
    it('should fail provision without NATS account', async () => {
      const claims: MemberClaims = { user_guid: crypto.randomUUID(), email: 'user@test.com' };

      const result = await service.provision(claims);
      expect(result.success).toBe(false);
      expect(result.error).toContain('NATS account');
    });

    it('should fail initialize before provision', async () => {
      const userGuid = crypto.randomUUID();
      const claims: MemberClaims = { user_guid: userGuid, email: 'user@test.com' };

      await service.createNatsAccount(userGuid);

      const result = await service.initialize(claims, 'i-fake');
      expect(result.success).toBe(false);
    });

    it('should fail health check before initialize', async () => {
      const userGuid = crypto.randomUUID();
      const claims: MemberClaims = { user_guid: userGuid, email: 'user@test.com' };

      await service.createNatsAccount(userGuid);
      await service.provision(claims);

      const result = await service.getHealth(claims);
      expect(result.success).toBe(false);
      expect(result.error).toContain('not initialized');
    });

    it('should fail stop on terminated vault', async () => {
      const userGuid = crypto.randomUUID();
      const claims: MemberClaims = { user_guid: userGuid, email: 'user@test.com' };

      await service.createNatsAccount(userGuid);
      const { instance_id } = await service.provision(claims);
      await service.terminate(claims, instance_id!);

      const result = await service.stop(claims, instance_id!);
      expect(result.success).toBe(false);
    });

    it('should fail restart on running vault', async () => {
      const userGuid = crypto.randomUUID();
      const claims: MemberClaims = { user_guid: userGuid, email: 'user@test.com' };

      await service.createNatsAccount(userGuid);
      const { instance_id } = await service.provision(claims);
      await service.initialize(claims, instance_id!);

      const result = await service.restart(claims, instance_id!);
      expect(result.success).toBe(false);
      expect(result.error).toContain('running');
    });
  });

  describe('Multi-User Scenarios', () => {
    it('should handle multiple users independently', async () => {
      const users = Array.from({ length: 3 }, () => ({
        userGuid: crypto.randomUUID(),
        claims: { user_guid: '', email: '' } as MemberClaims,
      }));

      users.forEach(u => {
        u.claims = { user_guid: u.userGuid, email: `${u.userGuid}@test.com` };
      });

      // All users create NATS accounts and provision
      for (const { userGuid, claims } of users) {
        await service.createNatsAccount(userGuid);
        const { instance_id } = await service.provision(claims);
        await service.initialize(claims, instance_id!);
      }

      // All should be healthy
      for (const { claims } of users) {
        const health = await service.getHealth(claims);
        expect(health.success).toBe(true);
        expect(health.status).toBe('healthy');
      }

      // Stop one user, others unaffected
      const { instance_id } = service.getVaultState(users[0].userGuid)!;
      await service.stop(users[0].claims, instance_id!);

      expect(service.getVaultState(users[0].userGuid)?.status).toBe('stopped');
      expect(service.getVaultState(users[1].userGuid)?.status).toBe('running');
      expect(service.getVaultState(users[2].userGuid)?.status).toBe('running');
    });
  });
});
