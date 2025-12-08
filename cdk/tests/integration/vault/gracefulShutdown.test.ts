/**
 * Integration Tests: Vault Graceful Shutdown
 *
 * Tests the POST /vault/stop and POST /vault/terminate endpoints that:
 * - Stop vault gracefully with event flush
 * - Disconnect from central NATS
 * - Preserve state for restart (stop)
 * - Terminate EC2 instance and cleanup (terminate)
 * - Revoke NATS credentials
 *
 * @see cdk/lambda/handlers/vault/stop.ts (pending implementation)
 * @see cdk/lambda/handlers/vault/terminate.ts (pending implementation)
 */

import * as crypto from 'crypto';

// ============================================
// Types
// ============================================

interface StopRequest {
  instance_id: string;
  force?: boolean;
}

interface StopResponse {
  status: 'stopped' | 'stopping' | 'failed';
  events_flushed: number;
  state_preserved: boolean;
}

interface TerminateRequest {
  instance_id: string;
}

interface TerminateResponse {
  status: 'terminated' | 'terminating' | 'failed';
  cleanup: {
    security_group_deleted: boolean;
    nats_credentials_revoked: boolean;
    state_cleared: boolean;
  };
}

interface VaultInstanceRecord {
  user_guid: string;
  instance_id: string;
  status: 'provisioning' | 'running' | 'stopping' | 'stopped' | 'terminating' | 'terminated' | 'failed';
  initialized: boolean;
  security_group_id: string;
  pending_events: number;
  state_preserved: boolean;
  nats_credentials_active: boolean;
  central_nats_connected: boolean;
}

interface MemberClaims {
  user_guid: string;
  email: string;
}

// ============================================
// Mock Shutdown Handler
// ============================================

class MockShutdownHandler {
  private instances: Map<string, VaultInstanceRecord> = new Map();
  private deletedSecurityGroups: Set<string> = new Set();

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
   * Check if security group was deleted
   */
  wasSecurityGroupDeleted(securityGroupId: string): boolean {
    return this.deletedSecurityGroups.has(securityGroupId);
  }

  /**
   * Handle stop request
   */
  async handleStop(
    claims: MemberClaims | null,
    body: StopRequest | null
  ): Promise<{
    statusCode: number;
    body: StopResponse | { error: string };
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

    if (!body || !body.instance_id) {
      return {
        statusCode: 400,
        body: { error: 'Missing instance_id in request' },
      };
    }

    // Get instance
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

    // Check current status
    if (instance.status === 'stopped') {
      return {
        statusCode: 200,
        body: {
          status: 'stopped',
          events_flushed: 0,
          state_preserved: true,
        },
      };
    }

    if (instance.status !== 'running') {
      return {
        statusCode: 400,
        body: { error: `Cannot stop vault in ${instance.status} state` },
      };
    }

    // Perform graceful stop
    instance.status = 'stopping';

    // 1. Flush pending events
    const eventsFlushed = instance.pending_events;
    instance.pending_events = 0;

    // 2. Disconnect from central NATS
    instance.central_nats_connected = false;

    // 3. Preserve state for restart
    instance.state_preserved = true;

    // 4. Update status
    instance.status = 'stopped';

    const response: StopResponse = {
      status: 'stopped',
      events_flushed: eventsFlushed,
      state_preserved: true,
    };

    return {
      statusCode: 200,
      body: response,
    };
  }

  /**
   * Handle terminate request
   */
  async handleTerminate(
    claims: MemberClaims | null,
    body: TerminateRequest | null
  ): Promise<{
    statusCode: number;
    body: TerminateResponse | { error: string };
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

    if (!body || !body.instance_id) {
      return {
        statusCode: 400,
        body: { error: 'Missing instance_id in request' },
      };
    }

    // Get instance
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

    // Idempotent: already terminated
    if (instance.status === 'terminated') {
      return {
        statusCode: 200,
        body: {
          status: 'terminated',
          cleanup: {
            security_group_deleted: true,
            nats_credentials_revoked: true,
            state_cleared: true,
          },
        },
      };
    }

    // Cannot terminate if still running (must stop first)
    if (instance.status === 'running') {
      // Auto-stop before terminate
      instance.status = 'stopping';
      instance.pending_events = 0;
      instance.central_nats_connected = false;
      instance.status = 'stopped';
    }

    // Perform termination
    instance.status = 'terminating';

    // 1. Terminate EC2 instance (simulated)

    // 2. Clean up security group
    this.deletedSecurityGroups.add(instance.security_group_id);

    // 3. Revoke NATS credentials
    instance.nats_credentials_active = false;

    // 4. Clear state
    instance.state_preserved = false;

    // 5. Update status
    instance.status = 'terminated';

    const response: TerminateResponse = {
      status: 'terminated',
      cleanup: {
        security_group_deleted: true,
        nats_credentials_revoked: true,
        state_cleared: true,
      },
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
    this.deletedSecurityGroups.clear();
  }
}

// ============================================
// Helper Functions
// ============================================

function createTestInstance(
  userGuid: string,
  options: {
    status?: VaultInstanceRecord['status'];
    pendingEvents?: number;
    initialized?: boolean;
  } = {}
): VaultInstanceRecord {
  return {
    user_guid: userGuid,
    instance_id: `i-${crypto.randomBytes(8).toString('hex')}`,
    status: options.status || 'running',
    initialized: options.initialized ?? true,
    security_group_id: `sg-${crypto.randomBytes(8).toString('hex')}`,
    pending_events: options.pendingEvents ?? 5,
    state_preserved: false,
    nats_credentials_active: true,
    central_nats_connected: true,
  };
}

// ============================================
// Tests
// ============================================

describe('Vault Lifecycle - Graceful Shutdown', () => {
  let handler: MockShutdownHandler;

  beforeEach(() => {
    handler = new MockShutdownHandler();
  });

  describe('POST /vault/stop', () => {
    describe('Successful Stop', () => {
      it('should stop vault gracefully', async () => {
        const userGuid = crypto.randomUUID();
        const instance = createTestInstance(userGuid);
        handler.addInstance(instance);

        const claims: MemberClaims = {
          user_guid: userGuid,
          email: 'member@test.com',
        };

        const result = await handler.handleStop(claims, { instance_id: instance.instance_id });

        expect(result.statusCode).toBe(200);
        const body = result.body as StopResponse;
        expect(body.status).toBe('stopped');
      });

      it('should flush pending events', async () => {
        const userGuid = crypto.randomUUID();
        const instance = createTestInstance(userGuid, { pendingEvents: 10 });
        handler.addInstance(instance);

        const claims: MemberClaims = {
          user_guid: userGuid,
          email: 'member@test.com',
        };

        const result = await handler.handleStop(claims, { instance_id: instance.instance_id });
        const body = result.body as StopResponse;

        expect(body.events_flushed).toBe(10);

        // Verify events were cleared
        const updatedInstance = handler.getInstance(userGuid);
        expect(updatedInstance?.pending_events).toBe(0);
      });

      it('should disconnect from central NATS', async () => {
        const userGuid = crypto.randomUUID();
        const instance = createTestInstance(userGuid);
        handler.addInstance(instance);

        const claims: MemberClaims = {
          user_guid: userGuid,
          email: 'member@test.com',
        };

        await handler.handleStop(claims, { instance_id: instance.instance_id });

        const updatedInstance = handler.getInstance(userGuid);
        expect(updatedInstance?.central_nats_connected).toBe(false);
      });

      it('should preserve state for restart', async () => {
        const userGuid = crypto.randomUUID();
        const instance = createTestInstance(userGuid);
        handler.addInstance(instance);

        const claims: MemberClaims = {
          user_guid: userGuid,
          email: 'member@test.com',
        };

        const result = await handler.handleStop(claims, { instance_id: instance.instance_id });
        const body = result.body as StopResponse;

        expect(body.state_preserved).toBe(true);

        const updatedInstance = handler.getInstance(userGuid);
        expect(updatedInstance?.state_preserved).toBe(true);
      });

      it('should update instance status to stopped', async () => {
        const userGuid = crypto.randomUUID();
        const instance = createTestInstance(userGuid);
        handler.addInstance(instance);

        const claims: MemberClaims = {
          user_guid: userGuid,
          email: 'member@test.com',
        };

        await handler.handleStop(claims, { instance_id: instance.instance_id });

        const updatedInstance = handler.getInstance(userGuid);
        expect(updatedInstance?.status).toBe('stopped');
      });
    });

    describe('Idempotency', () => {
      it('should be idempotent for already stopped vault', async () => {
        const userGuid = crypto.randomUUID();
        const instance = createTestInstance(userGuid, { status: 'stopped' });
        handler.addInstance(instance);

        const claims: MemberClaims = {
          user_guid: userGuid,
          email: 'member@test.com',
        };

        const result = await handler.handleStop(claims, { instance_id: instance.instance_id });

        expect(result.statusCode).toBe(200);
        const body = result.body as StopResponse;
        expect(body.status).toBe('stopped');
      });
    });

    describe('State Validation', () => {
      it('should reject stop for provisioning vault', async () => {
        const userGuid = crypto.randomUUID();
        const instance = createTestInstance(userGuid, { status: 'provisioning' });
        handler.addInstance(instance);

        const claims: MemberClaims = {
          user_guid: userGuid,
          email: 'member@test.com',
        };

        const result = await handler.handleStop(claims, { instance_id: instance.instance_id });

        expect(result.statusCode).toBe(400);
        expect((result.body as { error: string }).error).toContain('provisioning');
      });

      it('should reject stop for terminated vault', async () => {
        const userGuid = crypto.randomUUID();
        const instance = createTestInstance(userGuid, { status: 'terminated' });
        handler.addInstance(instance);

        const claims: MemberClaims = {
          user_guid: userGuid,
          email: 'member@test.com',
        };

        const result = await handler.handleStop(claims, { instance_id: instance.instance_id });

        expect(result.statusCode).toBe(400);
      });
    });

    describe('Authentication', () => {
      it('should require authentication', async () => {
        const result = await handler.handleStop(null, { instance_id: 'i-test' });

        expect(result.statusCode).toBe(401);
      });

      it('should validate instance ownership', async () => {
        const user1 = crypto.randomUUID();
        const user2 = crypto.randomUUID();

        const instance1 = createTestInstance(user1);
        const instance2 = createTestInstance(user2);
        handler.addInstance(instance1);
        handler.addInstance(instance2);

        const claims: MemberClaims = {
          user_guid: user1,
          email: 'user1@test.com',
        };

        const result = await handler.handleStop(claims, { instance_id: instance2.instance_id });

        expect(result.statusCode).toBe(403);
      });
    });
  });

  describe('POST /vault/terminate', () => {
    describe('Successful Termination', () => {
      it('should terminate EC2 instance', async () => {
        const userGuid = crypto.randomUUID();
        const instance = createTestInstance(userGuid, { status: 'stopped' });
        handler.addInstance(instance);

        const claims: MemberClaims = {
          user_guid: userGuid,
          email: 'member@test.com',
        };

        const result = await handler.handleTerminate(claims, { instance_id: instance.instance_id });

        expect(result.statusCode).toBe(200);
        const body = result.body as TerminateResponse;
        expect(body.status).toBe('terminated');
      });

      it('should clean up security group', async () => {
        const userGuid = crypto.randomUUID();
        const instance = createTestInstance(userGuid, { status: 'stopped' });
        handler.addInstance(instance);

        const claims: MemberClaims = {
          user_guid: userGuid,
          email: 'member@test.com',
        };

        const result = await handler.handleTerminate(claims, { instance_id: instance.instance_id });
        const body = result.body as TerminateResponse;

        expect(body.cleanup.security_group_deleted).toBe(true);
        expect(handler.wasSecurityGroupDeleted(instance.security_group_id)).toBe(true);
      });

      it('should revoke NATS credentials', async () => {
        const userGuid = crypto.randomUUID();
        const instance = createTestInstance(userGuid, { status: 'stopped' });
        handler.addInstance(instance);

        const claims: MemberClaims = {
          user_guid: userGuid,
          email: 'member@test.com',
        };

        const result = await handler.handleTerminate(claims, { instance_id: instance.instance_id });
        const body = result.body as TerminateResponse;

        expect(body.cleanup.nats_credentials_revoked).toBe(true);

        const updatedInstance = handler.getInstance(userGuid);
        expect(updatedInstance?.nats_credentials_active).toBe(false);
      });

      it('should update vault status to terminated', async () => {
        const userGuid = crypto.randomUUID();
        const instance = createTestInstance(userGuid, { status: 'stopped' });
        handler.addInstance(instance);

        const claims: MemberClaims = {
          user_guid: userGuid,
          email: 'member@test.com',
        };

        await handler.handleTerminate(claims, { instance_id: instance.instance_id });

        const updatedInstance = handler.getInstance(userGuid);
        expect(updatedInstance?.status).toBe('terminated');
      });

      it('should clear preserved state', async () => {
        const userGuid = crypto.randomUUID();
        const instance = createTestInstance(userGuid, { status: 'stopped' });
        instance.state_preserved = true;
        handler.addInstance(instance);

        const claims: MemberClaims = {
          user_guid: userGuid,
          email: 'member@test.com',
        };

        const result = await handler.handleTerminate(claims, { instance_id: instance.instance_id });
        const body = result.body as TerminateResponse;

        expect(body.cleanup.state_cleared).toBe(true);

        const updatedInstance = handler.getInstance(userGuid);
        expect(updatedInstance?.state_preserved).toBe(false);
      });
    });

    describe('Auto-Stop Before Terminate', () => {
      it('should auto-stop running vault before terminate', async () => {
        const userGuid = crypto.randomUUID();
        const instance = createTestInstance(userGuid, { status: 'running' });
        handler.addInstance(instance);

        const claims: MemberClaims = {
          user_guid: userGuid,
          email: 'member@test.com',
        };

        const result = await handler.handleTerminate(claims, { instance_id: instance.instance_id });

        expect(result.statusCode).toBe(200);
        const body = result.body as TerminateResponse;
        expect(body.status).toBe('terminated');
      });
    });

    describe('Idempotency', () => {
      it('should be idempotent', async () => {
        const userGuid = crypto.randomUUID();
        const instance = createTestInstance(userGuid, { status: 'terminated' });
        handler.addInstance(instance);

        const claims: MemberClaims = {
          user_guid: userGuid,
          email: 'member@test.com',
        };

        const result1 = await handler.handleTerminate(claims, { instance_id: instance.instance_id });
        const result2 = await handler.handleTerminate(claims, { instance_id: instance.instance_id });

        expect(result1.statusCode).toBe(200);
        expect(result2.statusCode).toBe(200);

        const body1 = result1.body as TerminateResponse;
        const body2 = result2.body as TerminateResponse;

        expect(body1.status).toBe('terminated');
        expect(body2.status).toBe('terminated');
      });
    });

    describe('Authentication', () => {
      it('should require authentication', async () => {
        const result = await handler.handleTerminate(null, { instance_id: 'i-test' });

        expect(result.statusCode).toBe(401);
      });

      it('should validate instance ownership', async () => {
        const user1 = crypto.randomUUID();
        const user2 = crypto.randomUUID();

        const instance1 = createTestInstance(user1);
        const instance2 = createTestInstance(user2);
        handler.addInstance(instance1);
        handler.addInstance(instance2);

        const claims: MemberClaims = {
          user_guid: user1,
          email: 'user1@test.com',
        };

        const result = await handler.handleTerminate(claims, { instance_id: instance2.instance_id });

        expect(result.statusCode).toBe(403);
      });

      it('should return 404 for non-existent instance', async () => {
        const claims: MemberClaims = {
          user_guid: crypto.randomUUID(),
          email: 'member@test.com',
        };

        const result = await handler.handleTerminate(claims, { instance_id: 'i-nonexistent' });

        expect(result.statusCode).toBe(404);
      });
    });

    describe('Response Format', () => {
      it('should include all cleanup details', async () => {
        const userGuid = crypto.randomUUID();
        const instance = createTestInstance(userGuid, { status: 'stopped' });
        handler.addInstance(instance);

        const claims: MemberClaims = {
          user_guid: userGuid,
          email: 'member@test.com',
        };

        const result = await handler.handleTerminate(claims, { instance_id: instance.instance_id });
        const body = result.body as TerminateResponse;

        expect(body).toHaveProperty('status');
        expect(body).toHaveProperty('cleanup');
        expect(body.cleanup).toHaveProperty('security_group_deleted');
        expect(body.cleanup).toHaveProperty('nats_credentials_revoked');
        expect(body.cleanup).toHaveProperty('state_cleared');
      });
    });
  });

  describe('Multi-User Isolation', () => {
    it('should not affect other users when stopping', async () => {
      const user1 = crypto.randomUUID();
      const user2 = crypto.randomUUID();

      const instance1 = createTestInstance(user1);
      const instance2 = createTestInstance(user2);
      handler.addInstance(instance1);
      handler.addInstance(instance2);

      await handler.handleStop(
        { user_guid: user1, email: 'user1@test.com' },
        { instance_id: instance1.instance_id }
      );

      const updatedInstance2 = handler.getInstance(user2);
      expect(updatedInstance2?.status).toBe('running');
      expect(updatedInstance2?.central_nats_connected).toBe(true);
    });

    it('should not affect other users when terminating', async () => {
      const user1 = crypto.randomUUID();
      const user2 = crypto.randomUUID();

      const instance1 = createTestInstance(user1, { status: 'stopped' });
      const instance2 = createTestInstance(user2);
      handler.addInstance(instance1);
      handler.addInstance(instance2);

      await handler.handleTerminate(
        { user_guid: user1, email: 'user1@test.com' },
        { instance_id: instance1.instance_id }
      );

      const updatedInstance2 = handler.getInstance(user2);
      expect(updatedInstance2?.status).toBe('running');
      expect(updatedInstance2?.nats_credentials_active).toBe(true);
      expect(handler.wasSecurityGroupDeleted(instance2.security_group_id)).toBe(false);
    });
  });
});
