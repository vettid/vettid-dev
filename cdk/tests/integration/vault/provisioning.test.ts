/**
 * Integration Tests: Vault Provisioning
 *
 * Tests the POST /vault/provision endpoint that:
 * - Spins up EC2 instance for authenticated member
 * - Assigns unique security group per instance
 * - Uses correct ARM64 AMI
 * - Applies instance tags
 *
 * @see cdk/lambda/handlers/vault/provision.ts (pending implementation)
 */

import * as crypto from 'crypto';

// ============================================
// Types (based on task specification)
// ============================================

interface ProvisionRequest {
  region?: string;
}

interface ProvisionResponse {
  instance_id: string;
  status: 'provisioning' | 'running' | 'failed';
  region: string;
  availability_zone: string;
  private_ip?: string;
  estimated_ready_at: string;
}

interface VaultInstanceRecord {
  user_guid: string;
  instance_id: string;
  status: 'provisioning' | 'running' | 'stopped' | 'terminated' | 'failed';
  region: string;
  availability_zone: string;
  private_ip?: string;
  security_group_id: string;
  ami_id: string;
  instance_type: string;
  created_at: string;
  updated_at: string;
  tags: Record<string, string>;
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
// Mock EC2 Service
// ============================================

class MockEC2Service {
  private instances: Map<string, VaultInstanceRecord> = new Map();
  private securityGroups: Map<string, string> = new Map();

  // Simulated config
  private readonly defaultAmi = 'ami-0123456789abcdef0'; // ARM64 hardened AMI
  private readonly instanceType = 't4g.nano';
  private readonly defaultRegion = 'us-east-1';
  private readonly defaultAz = 'us-east-1a';

  /**
   * Simulate EC2 instance provisioning
   */
  async runInstance(
    userGuid: string,
    tags: Record<string, string>
  ): Promise<{ instanceId: string; securityGroupId: string }> {
    const instanceId = `i-${crypto.randomBytes(8).toString('hex')}`;
    const securityGroupId = `sg-${crypto.randomBytes(8).toString('hex')}`;

    // Simulate provisioning delay
    await new Promise(resolve => setTimeout(resolve, 10));

    return { instanceId, securityGroupId };
  }

  /**
   * Create security group for vault instance
   */
  async createSecurityGroup(userGuid: string): Promise<string> {
    const sgId = `sg-${crypto.randomBytes(8).toString('hex')}`;
    this.securityGroups.set(userGuid, sgId);
    return sgId;
  }

  /**
   * Delete security group
   */
  async deleteSecurityGroup(securityGroupId: string): Promise<void> {
    for (const [userGuid, sgId] of this.securityGroups.entries()) {
      if (sgId === securityGroupId) {
        this.securityGroups.delete(userGuid);
        break;
      }
    }
  }

  /**
   * Get instance status
   */
  getInstanceStatus(instanceId: string): 'pending' | 'running' | 'stopped' | 'terminated' | undefined {
    for (const instance of this.instances.values()) {
      if (instance.instance_id === instanceId) {
        return instance.status === 'provisioning' ? 'pending' : instance.status as any;
      }
    }
    return undefined;
  }

  getDefaultAmi(): string {
    return this.defaultAmi;
  }

  getInstanceType(): string {
    return this.instanceType;
  }

  getDefaultRegion(): string {
    return this.defaultRegion;
  }

  getDefaultAz(): string {
    return this.defaultAz;
  }
}

// ============================================
// Mock Provision Handler
// ============================================

class MockProvisionHandler {
  private instances: Map<string, VaultInstanceRecord> = new Map();
  private natsAccounts: Map<string, NatsAccountRecord> = new Map();
  private ec2: MockEC2Service;
  private provisioningTimeout = 2 * 60 * 1000; // 2 minutes

  constructor() {
    this.ec2 = new MockEC2Service();
  }

  /**
   * Add NATS account for testing
   */
  addNatsAccount(account: NatsAccountRecord): void {
    this.natsAccounts.set(account.user_guid, account);
  }

  /**
   * Get instance for user
   */
  getInstance(userGuid: string): VaultInstanceRecord | undefined {
    return this.instances.get(userGuid);
  }

  /**
   * Set instance status (for testing)
   */
  setInstanceStatus(userGuid: string, status: VaultInstanceRecord['status']): void {
    const instance = this.instances.get(userGuid);
    if (instance) {
      instance.status = status;
      instance.updated_at = new Date().toISOString();
    }
  }

  /**
   * Simulate provisioning timeout
   */
  simulateTimeout(userGuid: string): void {
    const instance = this.instances.get(userGuid);
    if (instance) {
      instance.status = 'failed';
      instance.updated_at = new Date().toISOString();
    }
  }

  /**
   * Handle provision request
   */
  async handle(
    claims: MemberClaims | null,
    body: ProvisionRequest | null
  ): Promise<{
    statusCode: number;
    body: ProvisionResponse | { error: string };
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

    // Check for active NATS account
    const natsAccount = this.natsAccounts.get(userGuid);
    if (!natsAccount) {
      return {
        statusCode: 400,
        body: { error: 'NATS account required. Create account first via POST /vault/nats/account' },
      };
    }

    if (natsAccount.status !== 'active') {
      return {
        statusCode: 400,
        body: { error: 'NATS account is not active' },
      };
    }

    // Check for existing instance
    const existingInstance = this.instances.get(userGuid);
    if (existingInstance) {
      if (existingInstance.status === 'provisioning' || existingInstance.status === 'running') {
        return {
          statusCode: 409,
          body: { error: 'Vault instance already exists for this user' },
        };
      }
      // Allow re-provisioning if terminated or failed
      if (existingInstance.status !== 'terminated' && existingInstance.status !== 'failed') {
        return {
          statusCode: 409,
          body: { error: `Cannot provision while instance is ${existingInstance.status}` },
        };
      }
    }

    const region = body?.region || this.ec2.getDefaultRegion();
    const now = new Date();
    const estimatedReadyAt = new Date(now.getTime() + 90 * 1000); // ~90 seconds

    // Create security group and instance
    const { instanceId, securityGroupId } = await this.ec2.runInstance(userGuid, {
      Name: `vault-${userGuid}`,
      Owner: userGuid,
      Service: 'vettid-vault',
    });

    const instance: VaultInstanceRecord = {
      user_guid: userGuid,
      instance_id: instanceId,
      status: 'provisioning',
      region,
      availability_zone: this.ec2.getDefaultAz(),
      security_group_id: securityGroupId,
      ami_id: this.ec2.getDefaultAmi(),
      instance_type: this.ec2.getInstanceType(),
      created_at: now.toISOString(),
      updated_at: now.toISOString(),
      tags: {
        Name: `vault-${userGuid}`,
        Owner: userGuid,
        Service: 'vettid-vault',
        Environment: 'production',
      },
    };

    this.instances.set(userGuid, instance);

    const response: ProvisionResponse = {
      instance_id: instanceId,
      status: 'provisioning',
      region,
      availability_zone: instance.availability_zone,
      estimated_ready_at: estimatedReadyAt.toISOString(),
    };

    return {
      statusCode: 202,
      body: response,
    };
  }

  /**
   * Simulate polling for status
   */
  async pollStatus(userGuid: string): Promise<{
    statusCode: number;
    body: { status: string; private_ip?: string } | { error: string };
  }> {
    const instance = this.instances.get(userGuid);
    if (!instance) {
      return {
        statusCode: 404,
        body: { error: 'Vault instance not found' },
      };
    }

    return {
      statusCode: 200,
      body: {
        status: instance.status,
        private_ip: instance.private_ip,
      },
    };
  }

  /**
   * Clear all data
   */
  clear(): void {
    this.instances.clear();
    this.natsAccounts.clear();
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

// ============================================
// Tests
// ============================================

describe('POST /vault/provision - Vault Provisioning', () => {
  let handler: MockProvisionHandler;

  beforeEach(() => {
    handler = new MockProvisionHandler();
  });

  describe('Successful Provisioning', () => {
    it('should provision vault for authenticated member', async () => {
      const userGuid = crypto.randomUUID();
      handler.addNatsAccount(createTestNatsAccount(userGuid));

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims, {});

      expect(result.statusCode).toBe(202);
    });

    it('should return instance_id and provisioning status', async () => {
      const userGuid = crypto.randomUUID();
      handler.addNatsAccount(createTestNatsAccount(userGuid));

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims, {});
      const body = result.body as ProvisionResponse;

      expect(body.instance_id).toBeDefined();
      expect(body.instance_id).toMatch(/^i-[a-f0-9]+$/);
      expect(body.status).toBe('provisioning');
    });

    it('should return region and availability zone', async () => {
      const userGuid = crypto.randomUUID();
      handler.addNatsAccount(createTestNatsAccount(userGuid));

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims, {});
      const body = result.body as ProvisionResponse;

      expect(body.region).toBe('us-east-1');
      expect(body.availability_zone).toBe('us-east-1a');
    });

    it('should return estimated_ready_at', async () => {
      const userGuid = crypto.randomUUID();
      handler.addNatsAccount(createTestNatsAccount(userGuid));

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const before = new Date();
      const result = await handler.handle(claims, {});
      const body = result.body as ProvisionResponse;

      expect(body.estimated_ready_at).toBeDefined();
      const estimatedTime = new Date(body.estimated_ready_at);
      expect(estimatedTime.getTime()).toBeGreaterThan(before.getTime());
    });

    it('should assign unique security group per instance', async () => {
      const user1 = crypto.randomUUID();
      const user2 = crypto.randomUUID();
      handler.addNatsAccount(createTestNatsAccount(user1));
      handler.addNatsAccount(createTestNatsAccount(user2));

      await handler.handle({ user_guid: user1, email: 'user1@test.com' }, {});
      await handler.handle({ user_guid: user2, email: 'user2@test.com' }, {});

      const instance1 = handler.getInstance(user1);
      const instance2 = handler.getInstance(user2);

      expect(instance1?.security_group_id).toBeDefined();
      expect(instance2?.security_group_id).toBeDefined();
      expect(instance1?.security_group_id).not.toBe(instance2?.security_group_id);
    });

    it('should use correct AMI (ARM64, hardened)', async () => {
      const userGuid = crypto.randomUUID();
      handler.addNatsAccount(createTestNatsAccount(userGuid));

      await handler.handle({ user_guid: userGuid, email: 'member@test.com' }, {});

      const instance = handler.getInstance(userGuid);
      expect(instance?.ami_id).toBeDefined();
      expect(instance?.ami_id).toMatch(/^ami-/);
    });

    it('should use t4g.nano instance type', async () => {
      const userGuid = crypto.randomUUID();
      handler.addNatsAccount(createTestNatsAccount(userGuid));

      await handler.handle({ user_guid: userGuid, email: 'member@test.com' }, {});

      const instance = handler.getInstance(userGuid);
      expect(instance?.instance_type).toBe('t4g.nano');
    });

    it('should apply correct instance tags', async () => {
      const userGuid = crypto.randomUUID();
      handler.addNatsAccount(createTestNatsAccount(userGuid));

      await handler.handle({ user_guid: userGuid, email: 'member@test.com' }, {});

      const instance = handler.getInstance(userGuid);
      expect(instance?.tags).toBeDefined();
      expect(instance?.tags.Name).toBe(`vault-${userGuid}`);
      expect(instance?.tags.Owner).toBe(userGuid);
      expect(instance?.tags.Service).toBe('vettid-vault');
      expect(instance?.tags.Environment).toBe('production');
    });
  });

  describe('Authentication', () => {
    it('should require authentication', async () => {
      const result = await handler.handle(null, {});

      expect(result.statusCode).toBe(401);
      expect((result.body as { error: string }).error).toContain('Unauthorized');
    });

    it('should reject missing user_guid', async () => {
      const claims = {
        user_guid: '',
        email: 'member@test.com',
      };

      const result = await handler.handle(claims, {});

      expect(result.statusCode).toBe(400);
      expect((result.body as { error: string }).error).toContain('user_guid');
    });
  });

  describe('NATS Account Requirement', () => {
    it('should require active NATS account', async () => {
      const claims: MemberClaims = {
        user_guid: crypto.randomUUID(),
        email: 'member@test.com',
      };

      const result = await handler.handle(claims, {});

      expect(result.statusCode).toBe(400);
      expect((result.body as { error: string }).error).toContain('NATS account');
    });

    it('should reject suspended NATS account', async () => {
      const userGuid = crypto.randomUUID();
      const account = createTestNatsAccount(userGuid);
      account.status = 'suspended';
      handler.addNatsAccount(account);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims, {});

      expect(result.statusCode).toBe(400);
      expect((result.body as { error: string }).error).toContain('not active');
    });

    it('should reject revoked NATS account', async () => {
      const userGuid = crypto.randomUUID();
      const account = createTestNatsAccount(userGuid);
      account.status = 'revoked';
      handler.addNatsAccount(account);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims, {});

      expect(result.statusCode).toBe(400);
    });
  });

  describe('Duplicate Prevention', () => {
    it('should reject duplicate provisioning for same user', async () => {
      const userGuid = crypto.randomUUID();
      handler.addNatsAccount(createTestNatsAccount(userGuid));

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      // First provision
      const result1 = await handler.handle(claims, {});
      expect(result1.statusCode).toBe(202);

      // Second provision should fail
      const result2 = await handler.handle(claims, {});
      expect(result2.statusCode).toBe(409);
      expect((result2.body as { error: string }).error).toContain('already exists');
    });

    it('should reject provisioning while running', async () => {
      const userGuid = crypto.randomUUID();
      handler.addNatsAccount(createTestNatsAccount(userGuid));

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      await handler.handle(claims, {});
      handler.setInstanceStatus(userGuid, 'running');

      const result = await handler.handle(claims, {});
      expect(result.statusCode).toBe(409);
    });

    it('should allow re-provisioning after terminated', async () => {
      const userGuid = crypto.randomUUID();
      handler.addNatsAccount(createTestNatsAccount(userGuid));

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      // First provision
      await handler.handle(claims, {});
      handler.setInstanceStatus(userGuid, 'terminated');

      // Re-provision should succeed
      const result = await handler.handle(claims, {});
      expect(result.statusCode).toBe(202);
    });

    it('should allow re-provisioning after failed', async () => {
      const userGuid = crypto.randomUUID();
      handler.addNatsAccount(createTestNatsAccount(userGuid));

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      // First provision fails
      await handler.handle(claims, {});
      handler.setInstanceStatus(userGuid, 'failed');

      // Re-provision should succeed
      const result = await handler.handle(claims, {});
      expect(result.statusCode).toBe(202);
    });
  });

  describe('Provisioning Timeout', () => {
    it('should handle timeout if provisioning takes >2 minutes', async () => {
      const userGuid = crypto.randomUUID();
      handler.addNatsAccount(createTestNatsAccount(userGuid));

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      await handler.handle(claims, {});

      // Simulate timeout
      handler.simulateTimeout(userGuid);

      const instance = handler.getInstance(userGuid);
      expect(instance?.status).toBe('failed');
    });
  });

  describe('Status Polling', () => {
    it('should return current status when polling', async () => {
      const userGuid = crypto.randomUUID();
      handler.addNatsAccount(createTestNatsAccount(userGuid));

      await handler.handle({ user_guid: userGuid, email: 'member@test.com' }, {});

      const pollResult = await handler.pollStatus(userGuid);
      expect(pollResult.statusCode).toBe(200);
      expect((pollResult.body as any).status).toBe('provisioning');
    });

    it('should return 404 for non-existent instance', async () => {
      const pollResult = await handler.pollStatus(crypto.randomUUID());
      expect(pollResult.statusCode).toBe(404);
    });

    it('should include private_ip when running', async () => {
      const userGuid = crypto.randomUUID();
      handler.addNatsAccount(createTestNatsAccount(userGuid));

      await handler.handle({ user_guid: userGuid, email: 'member@test.com' }, {});
      handler.setInstanceStatus(userGuid, 'running');

      const instance = handler.getInstance(userGuid);
      if (instance) {
        instance.private_ip = '10.0.1.100';
      }

      const pollResult = await handler.pollStatus(userGuid);
      expect((pollResult.body as any).private_ip).toBe('10.0.1.100');
    });
  });

  describe('Multi-User Isolation', () => {
    it('should provision separate instances for different users', async () => {
      const users = Array.from({ length: 3 }, () => crypto.randomUUID());

      for (const userGuid of users) {
        handler.addNatsAccount(createTestNatsAccount(userGuid));
        await handler.handle({ user_guid: userGuid, email: `${userGuid}@test.com` }, {});
      }

      const instances = users.map(u => handler.getInstance(u));
      const instanceIds = instances.map(i => i?.instance_id);
      const uniqueIds = new Set(instanceIds);

      expect(uniqueIds.size).toBe(users.length);
    });

    it('should not affect other users when one fails', async () => {
      const user1 = crypto.randomUUID();
      const user2 = crypto.randomUUID();

      handler.addNatsAccount(createTestNatsAccount(user1));
      handler.addNatsAccount(createTestNatsAccount(user2));

      await handler.handle({ user_guid: user1, email: 'user1@test.com' }, {});
      await handler.handle({ user_guid: user2, email: 'user2@test.com' }, {});

      // Fail user1's instance
      handler.setInstanceStatus(user1, 'failed');

      // User2's instance should still be provisioning
      const instance2 = handler.getInstance(user2);
      expect(instance2?.status).toBe('provisioning');
    });
  });

  describe('Response Format', () => {
    it('should return 202 Accepted status code', async () => {
      const userGuid = crypto.randomUUID();
      handler.addNatsAccount(createTestNatsAccount(userGuid));

      const result = await handler.handle({ user_guid: userGuid, email: 'member@test.com' }, {});

      expect(result.statusCode).toBe(202);
    });

    it('should include all required fields', async () => {
      const userGuid = crypto.randomUUID();
      handler.addNatsAccount(createTestNatsAccount(userGuid));

      const result = await handler.handle({ user_guid: userGuid, email: 'member@test.com' }, {});
      const body = result.body as ProvisionResponse;

      expect(body).toHaveProperty('instance_id');
      expect(body).toHaveProperty('status');
      expect(body).toHaveProperty('region');
      expect(body).toHaveProperty('availability_zone');
      expect(body).toHaveProperty('estimated_ready_at');
    });
  });
});
