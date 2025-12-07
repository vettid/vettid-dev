/**
 * Integration Tests: Create NATS Account
 *
 * Tests the POST /vault/nats/account endpoint that:
 * - Creates a NATS namespace for authenticated members
 * - Returns OwnerSpace and MessageSpace IDs
 * - Generates unique account identifiers
 *
 * @see cdk/lambda/handlers/nats/createMemberAccount.ts
 */

import * as crypto from 'crypto';

// ============================================
// Types (matching handler implementation)
// ============================================

interface NatsAccountRecord {
  user_guid: string;
  owner_space_id: string;
  message_space_id: string;
  account_public_key: string;
  status: 'active' | 'suspended' | 'revoked';
  created_at: string;
  updated_at: string;
}

interface CreateAccountResponse {
  owner_space_id: string;
  message_space_id: string;
  nats_endpoint: string;
  status: string;
}

interface MemberClaims {
  user_guid: string;
  email: string;
  groups?: string[];
}

// ============================================
// Mock Handler (simulates Lambda handler)
// ============================================

class MockCreateAccountHandler {
  private accounts: Map<string, NatsAccountRecord> = new Map();
  private readonly natsDomain = 'nats.vettid.dev';

  /**
   * Generate account public key placeholder
   */
  private generateAccountPlaceholder(userGuid: string): string {
    const hash = crypto.createHash('sha256').update(userGuid).digest('hex').substring(0, 32);
    return `A${hash.toUpperCase()}`;
  }

  /**
   * Handle account creation request
   */
  async handle(claims: MemberClaims | null): Promise<{
    statusCode: number;
    body: CreateAccountResponse | { error: string };
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

    // Check if account already exists
    const existingAccount = this.accounts.get(userGuid);

    if (existingAccount) {
      if (existingAccount.status === 'active') {
        return {
          statusCode: 409,
          body: { error: 'NATS account already exists for this member' },
        };
      }
      return {
        statusCode: 409,
        body: { error: 'NATS account exists but is not active. Contact support.' },
      };
    }

    // Generate unique account IDs
    const ownerSpaceId = `OwnerSpace.${userGuid}`;
    const messageSpaceId = `MessageSpace.${userGuid}`;
    const accountPublicKey = this.generateAccountPlaceholder(userGuid);

    const now = new Date().toISOString();

    // Create account record
    const accountRecord: NatsAccountRecord = {
      user_guid: userGuid,
      owner_space_id: ownerSpaceId,
      message_space_id: messageSpaceId,
      account_public_key: accountPublicKey,
      status: 'active',
      created_at: now,
      updated_at: now,
    };

    this.accounts.set(userGuid, accountRecord);

    const response: CreateAccountResponse = {
      owner_space_id: ownerSpaceId,
      message_space_id: messageSpaceId,
      nats_endpoint: `nats://${this.natsDomain}:4222`,
      status: 'active',
    };

    return {
      statusCode: 201,
      body: response,
    };
  }

  /**
   * Get account by user_guid (for testing)
   */
  getAccount(userGuid: string): NatsAccountRecord | undefined {
    return this.accounts.get(userGuid);
  }

  /**
   * Set account status (for testing)
   */
  setAccountStatus(userGuid: string, status: 'active' | 'suspended' | 'revoked'): void {
    const account = this.accounts.get(userGuid);
    if (account) {
      account.status = status;
      account.updated_at = new Date().toISOString();
    }
  }

  /**
   * Clear all accounts (for testing)
   */
  clear(): void {
    this.accounts.clear();
  }
}

// ============================================
// Tests
// ============================================

describe('POST /vault/nats/account - Create NATS Account', () => {
  let handler: MockCreateAccountHandler;

  beforeEach(() => {
    handler = new MockCreateAccountHandler();
  });

  describe('Successful Account Creation', () => {
    it('should create NATS account for authenticated member', async () => {
      const claims: MemberClaims = {
        user_guid: crypto.randomUUID(),
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);

      expect(result.statusCode).toBe(201);
    });

    it('should return OwnerSpace and MessageSpace IDs', async () => {
      const userGuid = crypto.randomUUID();
      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);

      const body = result.body as CreateAccountResponse;
      expect(body.owner_space_id).toBe(`OwnerSpace.${userGuid}`);
      expect(body.message_space_id).toBe(`MessageSpace.${userGuid}`);
    });

    it('should return nats_endpoint', async () => {
      const claims: MemberClaims = {
        user_guid: crypto.randomUUID(),
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);

      const body = result.body as CreateAccountResponse;
      expect(body.nats_endpoint).toBe('nats://nats.vettid.dev:4222');
    });

    it('should return active status', async () => {
      const claims: MemberClaims = {
        user_guid: crypto.randomUUID(),
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);

      const body = result.body as CreateAccountResponse;
      expect(body.status).toBe('active');
    });

    it('should store account in database', async () => {
      const userGuid = crypto.randomUUID();
      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      await handler.handle(claims);

      const account = handler.getAccount(userGuid);
      expect(account).toBeDefined();
      expect(account?.user_guid).toBe(userGuid);
      expect(account?.status).toBe('active');
      expect(account?.created_at).toBeDefined();
    });

    it('should generate unique account public key placeholder', async () => {
      const claims1: MemberClaims = {
        user_guid: crypto.randomUUID(),
        email: 'member1@test.com',
      };
      const claims2: MemberClaims = {
        user_guid: crypto.randomUUID(),
        email: 'member2@test.com',
      };

      await handler.handle(claims1);
      await handler.handle(claims2);

      const account1 = handler.getAccount(claims1.user_guid);
      const account2 = handler.getAccount(claims2.user_guid);

      expect(account1?.account_public_key).toBeDefined();
      expect(account2?.account_public_key).toBeDefined();
      expect(account1?.account_public_key).not.toBe(account2?.account_public_key);

      // Should start with 'A' (NATS account key prefix)
      expect(account1?.account_public_key).toMatch(/^A[A-F0-9]+$/);
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
      expect((result.body as { error: string }).error).toContain('user_guid');
    });
  });

  describe('Duplicate Account Prevention', () => {
    it('should return 409 if account already exists', async () => {
      const claims: MemberClaims = {
        user_guid: crypto.randomUUID(),
        email: 'member@test.com',
      };

      // First creation should succeed
      const result1 = await handler.handle(claims);
      expect(result1.statusCode).toBe(201);

      // Second creation should fail with 409
      const result2 = await handler.handle(claims);
      expect(result2.statusCode).toBe(409);
      expect((result2.body as { error: string }).error).toContain('already exists');
    });

    it('should return 409 for suspended account', async () => {
      const userGuid = crypto.randomUUID();
      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      await handler.handle(claims);
      handler.setAccountStatus(userGuid, 'suspended');

      const result = await handler.handle(claims);

      expect(result.statusCode).toBe(409);
      expect((result.body as { error: string }).error).toContain('not active');
    });

    it('should return 409 for revoked account', async () => {
      const userGuid = crypto.randomUUID();
      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      await handler.handle(claims);
      handler.setAccountStatus(userGuid, 'revoked');

      const result = await handler.handle(claims);

      expect(result.statusCode).toBe(409);
      expect((result.body as { error: string }).error).toContain('not active');
    });
  });

  describe('Account ID Generation', () => {
    it('should generate consistent OwnerSpace ID format', async () => {
      const userGuid = crypto.randomUUID();
      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);
      const body = result.body as CreateAccountResponse;

      expect(body.owner_space_id).toMatch(/^OwnerSpace\.[0-9a-f-]{36}$/);
    });

    it('should generate consistent MessageSpace ID format', async () => {
      const userGuid = crypto.randomUUID();
      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);
      const body = result.body as CreateAccountResponse;

      expect(body.message_space_id).toMatch(/^MessageSpace\.[0-9a-f-]{36}$/);
    });

    it('should use user_guid in namespace IDs', async () => {
      const userGuid = crypto.randomUUID();
      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);
      const body = result.body as CreateAccountResponse;

      expect(body.owner_space_id).toContain(userGuid);
      expect(body.message_space_id).toContain(userGuid);
    });
  });

  describe('Response Format', () => {
    it('should include all required fields', async () => {
      const claims: MemberClaims = {
        user_guid: crypto.randomUUID(),
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);
      const body = result.body as CreateAccountResponse;

      expect(body).toHaveProperty('owner_space_id');
      expect(body).toHaveProperty('message_space_id');
      expect(body).toHaveProperty('nats_endpoint');
      expect(body).toHaveProperty('status');
    });

    it('should return 201 status code on success', async () => {
      const claims: MemberClaims = {
        user_guid: crypto.randomUUID(),
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);

      expect(result.statusCode).toBe(201);
    });
  });

  describe('Multiple Users', () => {
    it('should create separate accounts for different users', async () => {
      const users = [
        { user_guid: crypto.randomUUID(), email: 'user1@test.com' },
        { user_guid: crypto.randomUUID(), email: 'user2@test.com' },
        { user_guid: crypto.randomUUID(), email: 'user3@test.com' },
      ];

      for (const user of users) {
        const result = await handler.handle(user);
        expect(result.statusCode).toBe(201);
      }

      // Verify each user has their own account
      for (const user of users) {
        const account = handler.getAccount(user.user_guid);
        expect(account).toBeDefined();
        expect(account?.owner_space_id).toContain(user.user_guid);
      }
    });

    it('should not interfere with other users accounts', async () => {
      const user1 = { user_guid: crypto.randomUUID(), email: 'user1@test.com' };
      const user2 = { user_guid: crypto.randomUUID(), email: 'user2@test.com' };

      await handler.handle(user1);
      await handler.handle(user2);

      // Suspend user1's account
      handler.setAccountStatus(user1.user_guid, 'suspended');

      // User2's account should still be active
      const account2 = handler.getAccount(user2.user_guid);
      expect(account2?.status).toBe('active');
    });
  });
});
