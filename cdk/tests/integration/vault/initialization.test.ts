/**
 * Integration Tests: Vault Initialization
 *
 * Tests the POST /vault/initialize endpoint that:
 * - Configures vault after EC2 is running
 * - Assigns OwnerSpace and MessageSpace namespaces
 * - Starts local NATS server
 * - Connects to central NATS cluster
 * - Installs user credentials
 *
 * @see cdk/lambda/handlers/vault/initialize.ts (pending implementation)
 */

import * as crypto from 'crypto';

// ============================================
// Types (based on task specification)
// ============================================

interface InitializeRequest {
  instance_id: string;
}

interface InitializeResponse {
  status: 'initialized' | 'failed';
  local_nats_status: 'running' | 'stopped';
  central_nats_status: 'connected' | 'disconnected';
  owner_space_id: string;
  message_space_id: string;
}

interface VaultInstanceRecord {
  user_guid: string;
  instance_id: string;
  status: 'provisioning' | 'running' | 'stopped' | 'terminated' | 'failed';
  region: string;
  availability_zone: string;
  private_ip?: string;
  initialized: boolean;
  initialization_status?: 'pending' | 'initializing' | 'initialized' | 'failed';
  local_nats_status?: 'running' | 'stopped';
  central_nats_status?: 'connected' | 'disconnected';
}

interface NatsAccountRecord {
  user_guid: string;
  owner_space_id: string;
  message_space_id: string;
  status: 'active' | 'suspended' | 'revoked';
}

interface MemberClaims {
  user_guid: string;
  email: string;
}

// ============================================
// Mock Initialize Handler
// ============================================

class MockInitializeHandler {
  private instances: Map<string, VaultInstanceRecord> = new Map();
  private natsAccounts: Map<string, NatsAccountRecord> = new Map();
  private instancesByInstanceId: Map<string, string> = new Map(); // instance_id -> user_guid

  /**
   * Add NATS account for testing
   */
  addNatsAccount(account: NatsAccountRecord): void {
    this.natsAccounts.set(account.user_guid, account);
  }

  /**
   * Add instance for testing
   */
  addInstance(instance: VaultInstanceRecord): void {
    this.instances.set(instance.user_guid, instance);
    this.instancesByInstanceId.set(instance.instance_id, instance.user_guid);
  }

  /**
   * Get instance for user
   */
  getInstance(userGuid: string): VaultInstanceRecord | undefined {
    return this.instances.get(userGuid);
  }

  /**
   * Simulate EC2 not ready
   */
  setInstanceNotReady(userGuid: string): void {
    const instance = this.instances.get(userGuid);
    if (instance) {
      instance.status = 'provisioning';
      delete instance.private_ip;
    }
  }

  /**
   * Handle initialize request
   */
  async handle(
    claims: MemberClaims | null,
    body: InitializeRequest | null
  ): Promise<{
    statusCode: number;
    body: InitializeResponse | { error: string };
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

    // Validate request
    if (!body || !body.instance_id) {
      return {
        statusCode: 400,
        body: { error: 'Missing instance_id in request' },
      };
    }

    // Verify instance belongs to user
    const instance = this.instances.get(userGuid);
    if (!instance) {
      return {
        statusCode: 404,
        body: { error: 'Vault instance not found' },
      };
    }

    if (instance.instance_id !== body.instance_id) {
      return {
        statusCode: 403,
        body: { error: 'Instance does not belong to this user' },
      };
    }

    // Check EC2 is running
    if (instance.status !== 'running') {
      return {
        statusCode: 400,
        body: { error: `Cannot initialize: EC2 instance is ${instance.status}. Wait until running.` },
      };
    }

    // Check if already initialized
    if (instance.initialized) {
      const natsAccount = this.natsAccounts.get(userGuid)!;
      return {
        statusCode: 200,
        body: {
          status: 'initialized',
          local_nats_status: instance.local_nats_status || 'running',
          central_nats_status: instance.central_nats_status || 'connected',
          owner_space_id: natsAccount.owner_space_id,
          message_space_id: natsAccount.message_space_id,
        },
      };
    }

    // Get NATS account
    const natsAccount = this.natsAccounts.get(userGuid);
    if (!natsAccount) {
      return {
        statusCode: 400,
        body: { error: 'NATS account not found' },
      };
    }

    // Simulate initialization steps
    instance.initialization_status = 'initializing';

    // 1. Start local NATS server
    instance.local_nats_status = 'running';

    // 2. Connect to central NATS cluster
    instance.central_nats_status = 'connected';

    // 3. Mark as initialized
    instance.initialized = true;
    instance.initialization_status = 'initialized';

    const response: InitializeResponse = {
      status: 'initialized',
      local_nats_status: 'running',
      central_nats_status: 'connected',
      owner_space_id: natsAccount.owner_space_id,
      message_space_id: natsAccount.message_space_id,
    };

    return {
      statusCode: 200,
      body: response,
    };
  }

  /**
   * Simulate initialization failure
   */
  simulateInitializationFailure(
    userGuid: string,
    failureType: 'local_nats' | 'central_nats' | 'credentials'
  ): void {
    const instance = this.instances.get(userGuid);
    if (instance) {
      instance.initialization_status = 'failed';
      if (failureType === 'local_nats') {
        instance.local_nats_status = 'stopped';
      } else if (failureType === 'central_nats') {
        instance.central_nats_status = 'disconnected';
      }
    }
  }

  /**
   * Clear all data
   */
  clear(): void {
    this.instances.clear();
    this.natsAccounts.clear();
    this.instancesByInstanceId.clear();
  }
}

// ============================================
// Helper Functions
// ============================================

function createTestNatsAccount(userGuid: string): NatsAccountRecord {
  return {
    user_guid: userGuid,
    owner_space_id: `OwnerSpace.${userGuid}`,
    message_space_id: `MessageSpace.${userGuid}`,
    status: 'active',
  };
}

function createTestInstance(
  userGuid: string,
  options: {
    status?: VaultInstanceRecord['status'];
    initialized?: boolean;
    privateIp?: string;
  } = {}
): VaultInstanceRecord {
  return {
    user_guid: userGuid,
    instance_id: `i-${crypto.randomBytes(8).toString('hex')}`,
    status: options.status || 'running',
    region: 'us-east-1',
    availability_zone: 'us-east-1a',
    private_ip: options.privateIp || '10.0.1.100',
    initialized: options.initialized || false,
  };
}

// ============================================
// Tests
// ============================================

describe('POST /vault/initialize - Vault Initialization', () => {
  let handler: MockInitializeHandler;

  beforeEach(() => {
    handler = new MockInitializeHandler();
  });

  describe('Successful Initialization', () => {
    it('should configure vault after EC2 is running', async () => {
      const userGuid = crypto.randomUUID();
      handler.addNatsAccount(createTestNatsAccount(userGuid));
      const instance = createTestInstance(userGuid, { status: 'running' });
      handler.addInstance(instance);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims, { instance_id: instance.instance_id });

      expect(result.statusCode).toBe(200);
      const body = result.body as InitializeResponse;
      expect(body.status).toBe('initialized');
    });

    it('should assign OwnerSpace namespace', async () => {
      const userGuid = crypto.randomUUID();
      handler.addNatsAccount(createTestNatsAccount(userGuid));
      const instance = createTestInstance(userGuid, { status: 'running' });
      handler.addInstance(instance);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims, { instance_id: instance.instance_id });
      const body = result.body as InitializeResponse;

      expect(body.owner_space_id).toBe(`OwnerSpace.${userGuid}`);
    });

    it('should assign MessageSpace namespace', async () => {
      const userGuid = crypto.randomUUID();
      handler.addNatsAccount(createTestNatsAccount(userGuid));
      const instance = createTestInstance(userGuid, { status: 'running' });
      handler.addInstance(instance);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims, { instance_id: instance.instance_id });
      const body = result.body as InitializeResponse;

      expect(body.message_space_id).toBe(`MessageSpace.${userGuid}`);
    });

    it('should start local NATS server', async () => {
      const userGuid = crypto.randomUUID();
      handler.addNatsAccount(createTestNatsAccount(userGuid));
      const instance = createTestInstance(userGuid, { status: 'running' });
      handler.addInstance(instance);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims, { instance_id: instance.instance_id });
      const body = result.body as InitializeResponse;

      expect(body.local_nats_status).toBe('running');
    });

    it('should connect to central NATS cluster', async () => {
      const userGuid = crypto.randomUUID();
      handler.addNatsAccount(createTestNatsAccount(userGuid));
      const instance = createTestInstance(userGuid, { status: 'running' });
      handler.addInstance(instance);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims, { instance_id: instance.instance_id });
      const body = result.body as InitializeResponse;

      expect(body.central_nats_status).toBe('connected');
    });

    it('should return initialization status', async () => {
      const userGuid = crypto.randomUUID();
      handler.addNatsAccount(createTestNatsAccount(userGuid));
      const instance = createTestInstance(userGuid, { status: 'running' });
      handler.addInstance(instance);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims, { instance_id: instance.instance_id });
      const body = result.body as InitializeResponse;

      expect(body.status).toBe('initialized');
    });

    it('should mark instance as initialized', async () => {
      const userGuid = crypto.randomUUID();
      handler.addNatsAccount(createTestNatsAccount(userGuid));
      const instance = createTestInstance(userGuid, { status: 'running' });
      handler.addInstance(instance);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      await handler.handle(claims, { instance_id: instance.instance_id });

      const updatedInstance = handler.getInstance(userGuid);
      expect(updatedInstance?.initialized).toBe(true);
    });
  });

  describe('Authentication', () => {
    it('should require authentication', async () => {
      const result = await handler.handle(null, { instance_id: 'i-test' });

      expect(result.statusCode).toBe(401);
      expect((result.body as { error: string }).error).toContain('Unauthorized');
    });

    it('should reject missing user_guid', async () => {
      const claims = {
        user_guid: '',
        email: 'member@test.com',
      };

      const result = await handler.handle(claims, { instance_id: 'i-test' });

      expect(result.statusCode).toBe(400);
      expect((result.body as { error: string }).error).toContain('user_guid');
    });
  });

  describe('Request Validation', () => {
    it('should require instance_id', async () => {
      const userGuid = crypto.randomUUID();
      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims, null);

      expect(result.statusCode).toBe(400);
      expect((result.body as { error: string }).error).toContain('instance_id');
    });

    it('should validate instance belongs to user', async () => {
      const user1 = crypto.randomUUID();
      const user2 = crypto.randomUUID();

      handler.addNatsAccount(createTestNatsAccount(user1));
      handler.addNatsAccount(createTestNatsAccount(user2));

      const instance1 = createTestInstance(user1, { status: 'running' });
      const instance2 = createTestInstance(user2, { status: 'running' });
      handler.addInstance(instance1);
      handler.addInstance(instance2);

      // User1 tries to initialize user2's instance
      const claims: MemberClaims = {
        user_guid: user1,
        email: 'user1@test.com',
      };

      const result = await handler.handle(claims, { instance_id: instance2.instance_id });

      expect(result.statusCode).toBe(403);
      expect((result.body as { error: string }).error).toContain('does not belong');
    });
  });

  describe('EC2 State Validation', () => {
    it('should fail gracefully if EC2 not ready', async () => {
      const userGuid = crypto.randomUUID();
      handler.addNatsAccount(createTestNatsAccount(userGuid));
      const instance = createTestInstance(userGuid, { status: 'provisioning' });
      handler.addInstance(instance);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims, { instance_id: instance.instance_id });

      expect(result.statusCode).toBe(400);
      expect((result.body as { error: string }).error).toContain('provisioning');
    });

    it('should fail if EC2 is stopped', async () => {
      const userGuid = crypto.randomUUID();
      handler.addNatsAccount(createTestNatsAccount(userGuid));
      const instance = createTestInstance(userGuid, { status: 'stopped' });
      handler.addInstance(instance);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims, { instance_id: instance.instance_id });

      expect(result.statusCode).toBe(400);
      expect((result.body as { error: string }).error).toContain('stopped');
    });

    it('should fail if EC2 is terminated', async () => {
      const userGuid = crypto.randomUUID();
      handler.addNatsAccount(createTestNatsAccount(userGuid));
      const instance = createTestInstance(userGuid, { status: 'terminated' });
      handler.addInstance(instance);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims, { instance_id: instance.instance_id });

      expect(result.statusCode).toBe(400);
      expect((result.body as { error: string }).error).toContain('terminated');
    });

    it('should fail if EC2 is in failed state', async () => {
      const userGuid = crypto.randomUUID();
      handler.addNatsAccount(createTestNatsAccount(userGuid));
      const instance = createTestInstance(userGuid, { status: 'failed' });
      handler.addInstance(instance);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims, { instance_id: instance.instance_id });

      expect(result.statusCode).toBe(400);
      expect((result.body as { error: string }).error).toContain('failed');
    });
  });

  describe('Instance Not Found', () => {
    it('should return 404 for non-existent instance', async () => {
      const userGuid = crypto.randomUUID();
      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims, { instance_id: 'i-nonexistent' });

      expect(result.statusCode).toBe(404);
      expect((result.body as { error: string }).error).toContain('not found');
    });
  });

  describe('Idempotency', () => {
    it('should return success if already initialized', async () => {
      const userGuid = crypto.randomUUID();
      handler.addNatsAccount(createTestNatsAccount(userGuid));
      const instance = createTestInstance(userGuid, {
        status: 'running',
        initialized: true,
      });
      instance.local_nats_status = 'running';
      instance.central_nats_status = 'connected';
      handler.addInstance(instance);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims, { instance_id: instance.instance_id });

      expect(result.statusCode).toBe(200);
      const body = result.body as InitializeResponse;
      expect(body.status).toBe('initialized');
    });

    it('should preserve NATS status on re-initialization', async () => {
      const userGuid = crypto.randomUUID();
      handler.addNatsAccount(createTestNatsAccount(userGuid));
      const instance = createTestInstance(userGuid, {
        status: 'running',
        initialized: true,
      });
      instance.local_nats_status = 'running';
      instance.central_nats_status = 'connected';
      handler.addInstance(instance);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims, { instance_id: instance.instance_id });
      const body = result.body as InitializeResponse;

      expect(body.local_nats_status).toBe('running');
      expect(body.central_nats_status).toBe('connected');
    });
  });

  describe('NATS Account Requirement', () => {
    it('should require NATS account', async () => {
      const userGuid = crypto.randomUUID();
      // Don't add NATS account
      const instance = createTestInstance(userGuid, { status: 'running' });
      handler.addInstance(instance);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims, { instance_id: instance.instance_id });

      expect(result.statusCode).toBe(400);
      expect((result.body as { error: string }).error).toContain('NATS account');
    });
  });

  describe('Response Format', () => {
    it('should include all required fields', async () => {
      const userGuid = crypto.randomUUID();
      handler.addNatsAccount(createTestNatsAccount(userGuid));
      const instance = createTestInstance(userGuid, { status: 'running' });
      handler.addInstance(instance);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims, { instance_id: instance.instance_id });
      const body = result.body as InitializeResponse;

      expect(body).toHaveProperty('status');
      expect(body).toHaveProperty('local_nats_status');
      expect(body).toHaveProperty('central_nats_status');
      expect(body).toHaveProperty('owner_space_id');
      expect(body).toHaveProperty('message_space_id');
    });

    it('should return 200 status code on success', async () => {
      const userGuid = crypto.randomUUID();
      handler.addNatsAccount(createTestNatsAccount(userGuid));
      const instance = createTestInstance(userGuid, { status: 'running' });
      handler.addInstance(instance);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims, { instance_id: instance.instance_id });

      expect(result.statusCode).toBe(200);
    });
  });

  describe('Multi-User Isolation', () => {
    it('should initialize separate instances for different users', async () => {
      const users = [crypto.randomUUID(), crypto.randomUUID()];
      const instances: VaultInstanceRecord[] = [];

      for (const userGuid of users) {
        handler.addNatsAccount(createTestNatsAccount(userGuid));
        const instance = createTestInstance(userGuid, { status: 'running' });
        handler.addInstance(instance);
        instances.push(instance);
      }

      for (let i = 0; i < users.length; i++) {
        const claims: MemberClaims = {
          user_guid: users[i],
          email: `user${i}@test.com`,
        };

        const result = await handler.handle(claims, { instance_id: instances[i].instance_id });
        expect(result.statusCode).toBe(200);

        const body = result.body as InitializeResponse;
        expect(body.owner_space_id).toBe(`OwnerSpace.${users[i]}`);
        expect(body.message_space_id).toBe(`MessageSpace.${users[i]}`);
      }
    });
  });
});
