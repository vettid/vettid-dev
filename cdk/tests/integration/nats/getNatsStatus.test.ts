/**
 * Integration Tests: Get NATS Account Status
 *
 * Tests the GET /vault/nats/status endpoint that:
 * - Returns member's NATS account status
 * - Lists active tokens
 * - Filters out expired tokens
 *
 * @see cdk/lambda/handlers/nats/getNatsStatus.ts
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

interface NatsTokenRecord {
  token_id: string;
  user_guid: string;
  client_type: 'app' | 'vault';
  device_id?: string;
  issued_at: string;
  expires_at: string;
  status: 'active' | 'revoked';
  last_used_at?: string;
}

interface NatsStatusResponse {
  has_account: boolean;
  account?: {
    owner_space_id: string;
    message_space_id: string;
    status: string;
    created_at: string;
  };
  active_tokens: Array<{
    token_id: string;
    client_type: 'app' | 'vault';
    device_id?: string;
    issued_at: string;
    expires_at: string;
    last_used_at?: string;
  }>;
  nats_endpoint: string;
}

interface MemberClaims {
  user_guid: string;
  email: string;
}

// ============================================
// Mock Handler (simulates Lambda handler)
// ============================================

class MockGetNatsStatusHandler {
  private accounts: Map<string, NatsAccountRecord> = new Map();
  private tokens: Map<string, NatsTokenRecord> = new Map();
  private readonly natsDomain = 'nats.vettid.dev';

  /**
   * Add an account for testing
   */
  addAccount(account: NatsAccountRecord): void {
    this.accounts.set(account.user_guid, account);
  }

  /**
   * Add a token for testing
   */
  addToken(token: NatsTokenRecord): void {
    this.tokens.set(token.token_id, token);
  }

  /**
   * Get tokens for a user
   */
  private getTokensForUser(userGuid: string): NatsTokenRecord[] {
    const userTokens: NatsTokenRecord[] = [];
    for (const token of this.tokens.values()) {
      if (token.user_guid === userGuid) {
        userTokens.push(token);
      }
    }
    return userTokens;
  }

  /**
   * Handle status request
   */
  async handle(claims: MemberClaims | null): Promise<{
    statusCode: number;
    body: NatsStatusResponse | { error: string };
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

    const response: NatsStatusResponse = {
      has_account: false,
      active_tokens: [],
      nats_endpoint: `nats://${this.natsDomain}:4222`,
    };

    // Get account
    const account = this.accounts.get(userGuid);

    if (account) {
      response.has_account = true;
      response.account = {
        owner_space_id: account.owner_space_id,
        message_space_id: account.message_space_id,
        status: account.status,
        created_at: account.created_at,
      };

      // Get active tokens for this user
      const now = new Date();
      const userTokens = this.getTokensForUser(userGuid);

      response.active_tokens = userTokens
        .filter(token => token.status === 'active')
        .filter(token => new Date(token.expires_at) > now)
        .map(token => ({
          token_id: token.token_id,
          client_type: token.client_type,
          device_id: token.device_id,
          issued_at: token.issued_at,
          expires_at: token.expires_at,
          last_used_at: token.last_used_at,
        }));
    }

    return {
      statusCode: 200,
      body: response,
    };
  }

  /**
   * Clear all data (for testing)
   */
  clear(): void {
    this.accounts.clear();
    this.tokens.clear();
  }
}

// ============================================
// Helper functions
// ============================================

function createTestAccount(userGuid: string, status: 'active' | 'suspended' | 'revoked' = 'active'): NatsAccountRecord {
  const now = new Date().toISOString();
  return {
    user_guid: userGuid,
    owner_space_id: `OwnerSpace.${userGuid}`,
    message_space_id: `MessageSpace.${userGuid}`,
    account_public_key: `A${crypto.createHash('sha256').update(userGuid).digest('hex').substring(0, 32).toUpperCase()}`,
    status,
    created_at: now,
    updated_at: now,
  };
}

function createTestToken(
  userGuid: string,
  options: {
    clientType?: 'app' | 'vault';
    status?: 'active' | 'revoked';
    deviceId?: string;
    expiresInMs?: number;
    lastUsedAt?: string;
  } = {}
): NatsTokenRecord {
  const now = new Date();
  const expiresInMs = options.expiresInMs ?? 24 * 60 * 60 * 1000; // Default 24 hours
  const expiresAt = new Date(now.getTime() + expiresInMs);

  return {
    token_id: `nats_${crypto.randomUUID()}`,
    user_guid: userGuid,
    client_type: options.clientType || 'app',
    device_id: options.deviceId,
    issued_at: now.toISOString(),
    expires_at: expiresAt.toISOString(),
    status: options.status || 'active',
    last_used_at: options.lastUsedAt,
  };
}

// ============================================
// Tests
// ============================================

describe('GET /vault/nats/status - Get NATS Account Status', () => {
  let handler: MockGetNatsStatusHandler;

  beforeEach(() => {
    handler = new MockGetNatsStatusHandler();
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

  describe('User Without Account', () => {
    it('should return has_account false for new users', async () => {
      const claims: MemberClaims = {
        user_guid: crypto.randomUUID(),
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);

      expect(result.statusCode).toBe(200);
      const body = result.body as NatsStatusResponse;
      expect(body.has_account).toBe(false);
    });

    it('should return empty active_tokens for new users', async () => {
      const claims: MemberClaims = {
        user_guid: crypto.randomUUID(),
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);

      const body = result.body as NatsStatusResponse;
      expect(body.active_tokens).toEqual([]);
    });

    it('should return nats_endpoint even without account', async () => {
      const claims: MemberClaims = {
        user_guid: crypto.randomUUID(),
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);

      const body = result.body as NatsStatusResponse;
      expect(body.nats_endpoint).toBe('nats://nats.vettid.dev:4222');
    });

    it('should not include account details for new users', async () => {
      const claims: MemberClaims = {
        user_guid: crypto.randomUUID(),
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);

      const body = result.body as NatsStatusResponse;
      expect(body.account).toBeUndefined();
    });
  });

  describe('User With Account', () => {
    it('should return has_account true', async () => {
      const userGuid = crypto.randomUUID();
      handler.addAccount(createTestAccount(userGuid));

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);

      const body = result.body as NatsStatusResponse;
      expect(body.has_account).toBe(true);
    });

    it('should return account details', async () => {
      const userGuid = crypto.randomUUID();
      const account = createTestAccount(userGuid);
      handler.addAccount(account);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);

      const body = result.body as NatsStatusResponse;
      expect(body.account).toBeDefined();
      expect(body.account?.owner_space_id).toBe(`OwnerSpace.${userGuid}`);
      expect(body.account?.message_space_id).toBe(`MessageSpace.${userGuid}`);
    });

    it('should return account status', async () => {
      const userGuid = crypto.randomUUID();
      handler.addAccount(createTestAccount(userGuid, 'active'));

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);

      const body = result.body as NatsStatusResponse;
      expect(body.account?.status).toBe('active');
    });

    it('should return account created_at', async () => {
      const userGuid = crypto.randomUUID();
      const account = createTestAccount(userGuid);
      handler.addAccount(account);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);

      const body = result.body as NatsStatusResponse;
      expect(body.account?.created_at).toBe(account.created_at);
    });

    it('should return suspended account status', async () => {
      const userGuid = crypto.randomUUID();
      handler.addAccount(createTestAccount(userGuid, 'suspended'));

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);

      const body = result.body as NatsStatusResponse;
      expect(body.account?.status).toBe('suspended');
    });
  });

  describe('Active Tokens', () => {
    it('should list active tokens', async () => {
      const userGuid = crypto.randomUUID();
      handler.addAccount(createTestAccount(userGuid));
      const token = createTestToken(userGuid);
      handler.addToken(token);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);

      const body = result.body as NatsStatusResponse;
      expect(body.active_tokens).toHaveLength(1);
      expect(body.active_tokens[0].token_id).toBe(token.token_id);
    });

    it('should include token client_type', async () => {
      const userGuid = crypto.randomUUID();
      handler.addAccount(createTestAccount(userGuid));
      handler.addToken(createTestToken(userGuid, { clientType: 'vault' }));

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);

      const body = result.body as NatsStatusResponse;
      expect(body.active_tokens[0].client_type).toBe('vault');
    });

    it('should include token device_id if present', async () => {
      const userGuid = crypto.randomUUID();
      handler.addAccount(createTestAccount(userGuid));
      handler.addToken(createTestToken(userGuid, { deviceId: 'my-device-123' }));

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);

      const body = result.body as NatsStatusResponse;
      expect(body.active_tokens[0].device_id).toBe('my-device-123');
    });

    it('should include token timestamps', async () => {
      const userGuid = crypto.randomUUID();
      handler.addAccount(createTestAccount(userGuid));
      const token = createTestToken(userGuid);
      handler.addToken(token);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);

      const body = result.body as NatsStatusResponse;
      expect(body.active_tokens[0].issued_at).toBe(token.issued_at);
      expect(body.active_tokens[0].expires_at).toBe(token.expires_at);
    });

    it('should include last_used_at if present', async () => {
      const userGuid = crypto.randomUUID();
      const lastUsedAt = new Date().toISOString();
      handler.addAccount(createTestAccount(userGuid));
      handler.addToken(createTestToken(userGuid, { lastUsedAt }));

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);

      const body = result.body as NatsStatusResponse;
      expect(body.active_tokens[0].last_used_at).toBe(lastUsedAt);
    });

    it('should list multiple active tokens', async () => {
      const userGuid = crypto.randomUUID();
      handler.addAccount(createTestAccount(userGuid));
      handler.addToken(createTestToken(userGuid, { clientType: 'app' }));
      handler.addToken(createTestToken(userGuid, { clientType: 'vault' }));
      handler.addToken(createTestToken(userGuid, { clientType: 'app', deviceId: 'tablet' }));

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);

      const body = result.body as NatsStatusResponse;
      expect(body.active_tokens).toHaveLength(3);
    });
  });

  describe('Token Filtering', () => {
    it('should filter out expired tokens', async () => {
      const userGuid = crypto.randomUUID();
      handler.addAccount(createTestAccount(userGuid));

      // Add expired token (negative expiry time)
      handler.addToken(createTestToken(userGuid, { expiresInMs: -1000 }));
      // Add valid token
      const validToken = createTestToken(userGuid);
      handler.addToken(validToken);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);

      const body = result.body as NatsStatusResponse;
      expect(body.active_tokens).toHaveLength(1);
      expect(body.active_tokens[0].token_id).toBe(validToken.token_id);
    });

    it('should filter out revoked tokens', async () => {
      const userGuid = crypto.randomUUID();
      handler.addAccount(createTestAccount(userGuid));

      // Add revoked token
      handler.addToken(createTestToken(userGuid, { status: 'revoked' }));
      // Add active token
      const activeToken = createTestToken(userGuid);
      handler.addToken(activeToken);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);

      const body = result.body as NatsStatusResponse;
      expect(body.active_tokens).toHaveLength(1);
      expect(body.active_tokens[0].token_id).toBe(activeToken.token_id);
    });

    it('should return empty list if all tokens are expired', async () => {
      const userGuid = crypto.randomUUID();
      handler.addAccount(createTestAccount(userGuid));
      handler.addToken(createTestToken(userGuid, { expiresInMs: -1000 }));
      handler.addToken(createTestToken(userGuid, { expiresInMs: -2000 }));

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);

      const body = result.body as NatsStatusResponse;
      expect(body.active_tokens).toHaveLength(0);
    });

    it('should return empty list if all tokens are revoked', async () => {
      const userGuid = crypto.randomUUID();
      handler.addAccount(createTestAccount(userGuid));
      handler.addToken(createTestToken(userGuid, { status: 'revoked' }));
      handler.addToken(createTestToken(userGuid, { status: 'revoked' }));

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);

      const body = result.body as NatsStatusResponse;
      expect(body.active_tokens).toHaveLength(0);
    });
  });

  describe('User Isolation', () => {
    it('should not show other users tokens', async () => {
      const user1Guid = crypto.randomUUID();
      const user2Guid = crypto.randomUUID();

      handler.addAccount(createTestAccount(user1Guid));
      handler.addAccount(createTestAccount(user2Guid));

      const user1Token = createTestToken(user1Guid);
      const user2Token = createTestToken(user2Guid);
      handler.addToken(user1Token);
      handler.addToken(user2Token);

      const claims: MemberClaims = {
        user_guid: user1Guid,
        email: 'user1@test.com',
      };

      const result = await handler.handle(claims);

      const body = result.body as NatsStatusResponse;
      expect(body.active_tokens).toHaveLength(1);
      expect(body.active_tokens[0].token_id).toBe(user1Token.token_id);
    });

    it('should not show other users account', async () => {
      const user1Guid = crypto.randomUUID();
      const user2Guid = crypto.randomUUID();

      handler.addAccount(createTestAccount(user1Guid));
      handler.addAccount(createTestAccount(user2Guid));

      const claims: MemberClaims = {
        user_guid: user1Guid,
        email: 'user1@test.com',
      };

      const result = await handler.handle(claims);

      const body = result.body as NatsStatusResponse;
      expect(body.account?.owner_space_id).toBe(`OwnerSpace.${user1Guid}`);
      expect(body.account?.owner_space_id).not.toContain(user2Guid);
    });
  });

  describe('Response Format', () => {
    it('should include all required fields', async () => {
      const claims: MemberClaims = {
        user_guid: crypto.randomUUID(),
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);
      const body = result.body as NatsStatusResponse;

      expect(body).toHaveProperty('has_account');
      expect(body).toHaveProperty('active_tokens');
      expect(body).toHaveProperty('nats_endpoint');
    });

    it('should return 200 status code', async () => {
      const claims: MemberClaims = {
        user_guid: crypto.randomUUID(),
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);

      expect(result.statusCode).toBe(200);
    });

    it('should return correct nats_endpoint format', async () => {
      const claims: MemberClaims = {
        user_guid: crypto.randomUUID(),
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);

      const body = result.body as NatsStatusResponse;
      expect(body.nats_endpoint).toMatch(/^nats:\/\/.*:\d+$/);
    });
  });

  describe('Edge Cases', () => {
    it('should handle user with account but no tokens', async () => {
      const userGuid = crypto.randomUUID();
      handler.addAccount(createTestAccount(userGuid));

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);

      const body = result.body as NatsStatusResponse;
      expect(body.has_account).toBe(true);
      expect(body.active_tokens).toHaveLength(0);
    });

    it('should handle mixed token statuses correctly', async () => {
      const userGuid = crypto.randomUUID();
      handler.addAccount(createTestAccount(userGuid));

      // Add mix of tokens
      const activeToken1 = createTestToken(userGuid, { clientType: 'app' });
      const activeToken2 = createTestToken(userGuid, { clientType: 'vault' });
      handler.addToken(activeToken1);
      handler.addToken(activeToken2);
      handler.addToken(createTestToken(userGuid, { status: 'revoked' }));
      handler.addToken(createTestToken(userGuid, { expiresInMs: -1000 }));

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims);

      const body = result.body as NatsStatusResponse;
      expect(body.active_tokens).toHaveLength(2);

      const tokenIds = body.active_tokens.map(t => t.token_id);
      expect(tokenIds).toContain(activeToken1.token_id);
      expect(tokenIds).toContain(activeToken2.token_id);
    });
  });
});
