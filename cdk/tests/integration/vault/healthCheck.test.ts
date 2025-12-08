/**
 * Integration Tests: Vault Health Check
 *
 * Tests the GET /vault/health endpoint that:
 * - Returns health status for running vault
 * - Includes local NATS status
 * - Includes central NATS connection status
 * - Includes Vault Manager process status
 * - Includes memory/CPU usage
 *
 * @see cdk/lambda/handlers/vault/health.ts (pending implementation)
 */

import * as crypto from 'crypto';

// ============================================
// Types (based on task specification)
// ============================================

interface HealthResponse {
  status: 'healthy' | 'unhealthy' | 'degraded';
  uptime_seconds: number;
  local_nats: {
    status: 'running' | 'stopped';
    connections: number;
  };
  central_nats: {
    status: 'connected' | 'disconnected';
    latency_ms: number;
  };
  vault_manager: {
    status: 'running' | 'stopped';
    memory_mb: number;
    cpu_percent: number;
    handlers_loaded: number;
  };
  last_event_at?: string;
}

interface VaultInstanceRecord {
  user_guid: string;
  instance_id: string;
  status: 'provisioning' | 'running' | 'stopped' | 'terminated' | 'failed';
  initialized: boolean;
  started_at?: string;
  local_nats: {
    status: 'running' | 'stopped';
    connections: number;
  };
  central_nats: {
    status: 'connected' | 'disconnected';
    latency_ms: number;
  };
  vault_manager: {
    status: 'running' | 'stopped';
    memory_mb: number;
    cpu_percent: number;
    handlers_loaded: number;
  };
  last_event_at?: string;
}

interface MemberClaims {
  user_guid: string;
  email: string;
}

// ============================================
// Mock Health Check Handler
// ============================================

class MockHealthCheckHandler {
  private instances: Map<string, VaultInstanceRecord> = new Map();

  /**
   * Add instance for testing
   */
  addInstance(instance: VaultInstanceRecord): void {
    this.instances.set(instance.user_guid, instance);
  }

  /**
   * Get instance for user
   */
  getInstance(userGuid: string): VaultInstanceRecord | undefined {
    return this.instances.get(userGuid);
  }

  /**
   * Update instance health status
   */
  updateHealth(
    userGuid: string,
    updates: Partial<Pick<VaultInstanceRecord, 'local_nats' | 'central_nats' | 'vault_manager'>>
  ): void {
    const instance = this.instances.get(userGuid);
    if (instance) {
      if (updates.local_nats) {
        instance.local_nats = { ...instance.local_nats, ...updates.local_nats };
      }
      if (updates.central_nats) {
        instance.central_nats = { ...instance.central_nats, ...updates.central_nats };
      }
      if (updates.vault_manager) {
        instance.vault_manager = { ...instance.vault_manager, ...updates.vault_manager };
      }
    }
  }

  /**
   * Calculate overall health status
   */
  private calculateHealthStatus(instance: VaultInstanceRecord): 'healthy' | 'unhealthy' | 'degraded' {
    // Check critical components
    const localNatsRunning = instance.local_nats.status === 'running';
    const centralNatsConnected = instance.central_nats.status === 'connected';
    const vaultManagerRunning = instance.vault_manager.status === 'running';

    // All components must be running for healthy
    if (localNatsRunning && centralNatsConnected && vaultManagerRunning) {
      // Check for high latency or resource usage
      if (instance.central_nats.latency_ms > 1000) {
        return 'degraded';
      }
      if (instance.vault_manager.memory_mb > 400) {
        return 'degraded';
      }
      if (instance.vault_manager.cpu_percent > 80) {
        return 'degraded';
      }
      return 'healthy';
    }

    // If any critical component is down
    if (!localNatsRunning || !vaultManagerRunning) {
      return 'unhealthy';
    }

    // Central NATS disconnected but local services running
    if (!centralNatsConnected) {
      return 'degraded';
    }

    return 'unhealthy';
  }

  /**
   * Calculate uptime in seconds
   */
  private calculateUptime(startedAt?: string): number {
    if (!startedAt) return 0;
    const startTime = new Date(startedAt).getTime();
    const now = Date.now();
    return Math.floor((now - startTime) / 1000);
  }

  /**
   * Handle health check request
   */
  async handle(claims: MemberClaims | null): Promise<{
    statusCode: number;
    body: HealthResponse | { error: string };
  }> {
    // Require authentication
    if (!claims) {
      return {
        statusCode: 401,
        body: { error: 'Unauthorized: Missing authentication' },
      };
    }

    const userGuid = claims.user_guid;

    if (!userGuid) {
      return {
        statusCode: 400,
        body: { error: 'Missing user_guid in token' },
      };
    }

    // Check for vault instance
    const instance = this.instances.get(userGuid);
    if (!instance) {
      return {
        statusCode: 404,
        body: { error: 'Vault not provisioned' },
      };
    }

    // Check if initialized
    if (!instance.initialized) {
      return {
        statusCode: 400,
        body: { error: 'Vault not initialized' },
      };
    }

    // Check instance status
    if (instance.status !== 'running') {
      return {
        statusCode: 503,
        body: { error: `Vault is ${instance.status}` },
      };
    }

    const healthStatus = this.calculateHealthStatus(instance);
    const uptime = this.calculateUptime(instance.started_at);

    const response: HealthResponse = {
      status: healthStatus,
      uptime_seconds: uptime,
      local_nats: instance.local_nats,
      central_nats: instance.central_nats,
      vault_manager: instance.vault_manager,
      last_event_at: instance.last_event_at,
    };

    return {
      statusCode: 200,
      body: response,
    };
  }

  /**
   * Clear all data
   */
  clear(): void {
    this.instances.clear();
  }
}

// ============================================
// Helper Functions
// ============================================

function createHealthyInstance(
  userGuid: string,
  options: {
    uptimeHours?: number;
    connections?: number;
    latencyMs?: number;
    memoryMb?: number;
    cpuPercent?: number;
    handlersLoaded?: number;
    lastEventAt?: string;
  } = {}
): VaultInstanceRecord {
  const uptimeMs = (options.uptimeHours || 1) * 60 * 60 * 1000;
  const startedAt = new Date(Date.now() - uptimeMs).toISOString();

  return {
    user_guid: userGuid,
    instance_id: `i-${crypto.randomBytes(8).toString('hex')}`,
    status: 'running',
    initialized: true,
    started_at: startedAt,
    local_nats: {
      status: 'running',
      connections: options.connections ?? 2,
    },
    central_nats: {
      status: 'connected',
      latency_ms: options.latencyMs ?? 15,
    },
    vault_manager: {
      status: 'running',
      memory_mb: options.memoryMb ?? 128,
      cpu_percent: options.cpuPercent ?? 5,
      handlers_loaded: options.handlersLoaded ?? 10,
    },
    last_event_at: options.lastEventAt,
  };
}

// ============================================
// Tests
// ============================================

describe('GET /vault/health - Vault Health Check', () => {
  let handler: MockHealthCheckHandler;

  beforeEach(() => {
    handler = new MockHealthCheckHandler();
  });

  describe('Healthy Status', () => {
    it('should return healthy for running vault', async () => {
      const userGuid = crypto.randomUUID();
      handler.addInstance(createHealthyInstance(userGuid));

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);

      expect(result.statusCode).toBe(200);
      const body = result.body as HealthResponse;
      expect(body.status).toBe('healthy');
    });

    it('should include uptime_seconds', async () => {
      const userGuid = crypto.randomUUID();
      handler.addInstance(createHealthyInstance(userGuid, { uptimeHours: 2 }));

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);
      const body = result.body as HealthResponse;

      // Should be approximately 2 hours = 7200 seconds (with some tolerance)
      expect(body.uptime_seconds).toBeGreaterThan(7000);
      expect(body.uptime_seconds).toBeLessThan(7400);
    });
  });

  describe('Local NATS Status', () => {
    it('should include local NATS status', async () => {
      const userGuid = crypto.randomUUID();
      handler.addInstance(createHealthyInstance(userGuid));

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);
      const body = result.body as HealthResponse;

      expect(body.local_nats).toBeDefined();
      expect(body.local_nats.status).toBe('running');
    });

    it('should include local NATS connection count', async () => {
      const userGuid = crypto.randomUUID();
      handler.addInstance(createHealthyInstance(userGuid, { connections: 5 }));

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);
      const body = result.body as HealthResponse;

      expect(body.local_nats.connections).toBe(5);
    });

    it('should return unhealthy when local NATS stopped', async () => {
      const userGuid = crypto.randomUUID();
      const instance = createHealthyInstance(userGuid);
      instance.local_nats.status = 'stopped';
      handler.addInstance(instance);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);
      const body = result.body as HealthResponse;

      expect(body.status).toBe('unhealthy');
    });
  });

  describe('Central NATS Status', () => {
    it('should include central NATS connection status', async () => {
      const userGuid = crypto.randomUUID();
      handler.addInstance(createHealthyInstance(userGuid));

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);
      const body = result.body as HealthResponse;

      expect(body.central_nats).toBeDefined();
      expect(body.central_nats.status).toBe('connected');
    });

    it('should include central NATS latency', async () => {
      const userGuid = crypto.randomUUID();
      handler.addInstance(createHealthyInstance(userGuid, { latencyMs: 25 }));

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);
      const body = result.body as HealthResponse;

      expect(body.central_nats.latency_ms).toBe(25);
    });

    it('should return degraded when central NATS disconnected', async () => {
      const userGuid = crypto.randomUUID();
      const instance = createHealthyInstance(userGuid);
      instance.central_nats.status = 'disconnected';
      handler.addInstance(instance);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);
      const body = result.body as HealthResponse;

      expect(body.status).toBe('degraded');
    });

    it('should return degraded with high latency', async () => {
      const userGuid = crypto.randomUUID();
      handler.addInstance(createHealthyInstance(userGuid, { latencyMs: 1500 }));

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);
      const body = result.body as HealthResponse;

      expect(body.status).toBe('degraded');
    });
  });

  describe('Vault Manager Status', () => {
    it('should include Vault Manager process status', async () => {
      const userGuid = crypto.randomUUID();
      handler.addInstance(createHealthyInstance(userGuid));

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);
      const body = result.body as HealthResponse;

      expect(body.vault_manager).toBeDefined();
      expect(body.vault_manager.status).toBe('running');
    });

    it('should include memory usage', async () => {
      const userGuid = crypto.randomUUID();
      handler.addInstance(createHealthyInstance(userGuid, { memoryMb: 150 }));

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);
      const body = result.body as HealthResponse;

      expect(body.vault_manager.memory_mb).toBe(150);
    });

    it('should include CPU usage', async () => {
      const userGuid = crypto.randomUUID();
      handler.addInstance(createHealthyInstance(userGuid, { cpuPercent: 10 }));

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);
      const body = result.body as HealthResponse;

      expect(body.vault_manager.cpu_percent).toBe(10);
    });

    it('should include handlers loaded count', async () => {
      const userGuid = crypto.randomUUID();
      handler.addInstance(createHealthyInstance(userGuid, { handlersLoaded: 15 }));

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);
      const body = result.body as HealthResponse;

      expect(body.vault_manager.handlers_loaded).toBe(15);
    });

    it('should return unhealthy when Vault Manager stopped', async () => {
      const userGuid = crypto.randomUUID();
      const instance = createHealthyInstance(userGuid);
      instance.vault_manager.status = 'stopped';
      handler.addInstance(instance);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);
      const body = result.body as HealthResponse;

      expect(body.status).toBe('unhealthy');
    });

    it('should return degraded with high memory usage', async () => {
      const userGuid = crypto.randomUUID();
      handler.addInstance(createHealthyInstance(userGuid, { memoryMb: 450 }));

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);
      const body = result.body as HealthResponse;

      expect(body.status).toBe('degraded');
    });

    it('should return degraded with high CPU usage', async () => {
      const userGuid = crypto.randomUUID();
      handler.addInstance(createHealthyInstance(userGuid, { cpuPercent: 90 }));

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);
      const body = result.body as HealthResponse;

      expect(body.status).toBe('degraded');
    });
  });

  describe('Last Event Tracking', () => {
    it('should include last_event_at when present', async () => {
      const userGuid = crypto.randomUUID();
      const lastEventAt = new Date().toISOString();
      handler.addInstance(createHealthyInstance(userGuid, { lastEventAt }));

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);
      const body = result.body as HealthResponse;

      expect(body.last_event_at).toBe(lastEventAt);
    });

    it('should omit last_event_at when no events', async () => {
      const userGuid = crypto.randomUUID();
      handler.addInstance(createHealthyInstance(userGuid));

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);
      const body = result.body as HealthResponse;

      expect(body.last_event_at).toBeUndefined();
    });
  });

  describe('Authentication', () => {
    it('should require authentication', async () => {
      const result = await handler.handle(null);

      expect(result.statusCode).toBe(401);
      expect((result.body as { error: string }).error).toContain('Unauthorized');
    });

    it('should reject missing user_guid', async () => {
      const claims = {
        user_guid: '',
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);

      expect(result.statusCode).toBe(400);
    });
  });

  describe('Vault Not Provisioned', () => {
    it('should require vault to be provisioned', async () => {
      const claims: MemberClaims = {
        user_guid: crypto.randomUUID(),
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);

      expect(result.statusCode).toBe(404);
      expect((result.body as { error: string }).error).toContain('not provisioned');
    });
  });

  describe('Vault Not Initialized', () => {
    it('should require vault to be initialized', async () => {
      const userGuid = crypto.randomUUID();
      const instance = createHealthyInstance(userGuid);
      instance.initialized = false;
      handler.addInstance(instance);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);

      expect(result.statusCode).toBe(400);
      expect((result.body as { error: string }).error).toContain('not initialized');
    });
  });

  describe('Vault Not Running', () => {
    it('should return 503 if vault is stopped', async () => {
      const userGuid = crypto.randomUUID();
      const instance = createHealthyInstance(userGuid);
      instance.status = 'stopped';
      handler.addInstance(instance);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);

      expect(result.statusCode).toBe(503);
      expect((result.body as { error: string }).error).toContain('stopped');
    });

    it('should return 503 if vault is terminated', async () => {
      const userGuid = crypto.randomUUID();
      const instance = createHealthyInstance(userGuid);
      instance.status = 'terminated';
      handler.addInstance(instance);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);

      expect(result.statusCode).toBe(503);
    });
  });

  describe('Response Format', () => {
    it('should include all required fields', async () => {
      const userGuid = crypto.randomUUID();
      handler.addInstance(createHealthyInstance(userGuid));

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);
      const body = result.body as HealthResponse;

      expect(body).toHaveProperty('status');
      expect(body).toHaveProperty('uptime_seconds');
      expect(body).toHaveProperty('local_nats');
      expect(body).toHaveProperty('central_nats');
      expect(body).toHaveProperty('vault_manager');

      expect(body.local_nats).toHaveProperty('status');
      expect(body.local_nats).toHaveProperty('connections');

      expect(body.central_nats).toHaveProperty('status');
      expect(body.central_nats).toHaveProperty('latency_ms');

      expect(body.vault_manager).toHaveProperty('status');
      expect(body.vault_manager).toHaveProperty('memory_mb');
      expect(body.vault_manager).toHaveProperty('cpu_percent');
      expect(body.vault_manager).toHaveProperty('handlers_loaded');
    });

    it('should return 200 status code for health check', async () => {
      const userGuid = crypto.randomUUID();
      handler.addInstance(createHealthyInstance(userGuid));

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);

      expect(result.statusCode).toBe(200);
    });
  });

  describe('Health Status Combinations', () => {
    it('should return healthy when all components healthy', async () => {
      const userGuid = crypto.randomUUID();
      handler.addInstance(createHealthyInstance(userGuid, {
        latencyMs: 10,
        memoryMb: 100,
        cpuPercent: 5,
      }));

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);
      const body = result.body as HealthResponse;

      expect(body.status).toBe('healthy');
    });

    it('should return degraded for multiple degradation factors', async () => {
      const userGuid = crypto.randomUUID();
      handler.addInstance(createHealthyInstance(userGuid, {
        latencyMs: 1200, // High latency
        memoryMb: 300, // Moderate memory
      }));

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);
      const body = result.body as HealthResponse;

      expect(body.status).toBe('degraded');
    });

    it('should return unhealthy when multiple critical components down', async () => {
      const userGuid = crypto.randomUUID();
      const instance = createHealthyInstance(userGuid);
      instance.local_nats.status = 'stopped';
      instance.vault_manager.status = 'stopped';
      handler.addInstance(instance);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);
      const body = result.body as HealthResponse;

      expect(body.status).toBe('unhealthy');
    });
  });
});
