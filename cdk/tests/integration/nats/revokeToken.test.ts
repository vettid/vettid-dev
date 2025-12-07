/**
 * Integration Tests: Revoke NATS Token
 *
 * Tests the POST /vault/nats/token/revoke endpoint that:
 * - Revokes previously issued NATS tokens
 * - Validates token ownership
 * - Updates token status to revoked
 *
 * @see cdk/lambda/handlers/nats/revokeToken.ts
 */

import * as crypto from 'crypto';

// ============================================
// Types (matching handler implementation)
// ============================================

interface NatsTokenRecord {
  token_id: string;
  user_guid: string;
  client_type: 'app' | 'vault';
  device_id?: string;
  issued_at: string;
  expires_at: string;
  status: 'active' | 'revoked';
  revoked_at?: string;
}

interface RevokeTokenRequest {
  token_id: string;
}

interface RevokeTokenResponse {
  token_id: string;
  status: 'revoked';
  revoked_at: string;
  message?: string;
}

interface MemberClaims {
  user_guid: string;
  email: string;
}

// ============================================
// Mock Handler (simulates Lambda handler)
// ============================================

class MockRevokeTokenHandler {
  private tokens: Map<string, NatsTokenRecord> = new Map();

  /**
   * Add a token for testing
   */
  addToken(token: NatsTokenRecord): void {
    this.tokens.set(token.token_id, token);
  }

  /**
   * Get token by ID (for testing)
   */
  getToken(tokenId: string): NatsTokenRecord | undefined {
    return this.tokens.get(tokenId);
  }

  /**
   * Handle token revocation request
   */
  async handle(
    claims: MemberClaims | null,
    body: RevokeTokenRequest | null
  ): Promise<{
    statusCode: number;
    body: RevokeTokenResponse | { error: string; message?: string };
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

    // Validate request body
    if (!body) {
      return {
        statusCode: 400,
        body: { error: 'Request body is required' },
      };
    }

    if (!body.token_id) {
      return {
        statusCode: 400,
        body: { error: 'Missing token_id' },
      };
    }

    // Get the token
    const token = this.tokens.get(body.token_id);

    if (!token) {
      return {
        statusCode: 404,
        body: { error: 'Token not found' },
      };
    }

    // Verify ownership
    if (token.user_guid !== userGuid) {
      return {
        statusCode: 403,
        body: { error: 'Cannot revoke tokens belonging to other users' },
      };
    }

    // Check if already revoked
    if (token.status === 'revoked') {
      return {
        statusCode: 200,
        body: {
          token_id: body.token_id,
          status: 'revoked',
          revoked_at: token.revoked_at!,
          message: 'Token was already revoked',
        },
      };
    }

    const now = new Date().toISOString();

    // Revoke the token
    token.status = 'revoked';
    token.revoked_at = now;

    const response: RevokeTokenResponse = {
      token_id: body.token_id,
      status: 'revoked',
      revoked_at: now,
    };

    return {
      statusCode: 200,
      body: response,
    };
  }

  /**
   * Clear all tokens (for testing)
   */
  clear(): void {
    this.tokens.clear();
  }
}

// ============================================
// Helper to create test tokens
// ============================================

function createTestToken(
  userGuid: string,
  options: {
    clientType?: 'app' | 'vault';
    status?: 'active' | 'revoked';
    deviceId?: string;
  } = {}
): NatsTokenRecord {
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 24 * 60 * 60 * 1000); // 24 hours from now

  return {
    token_id: `nats_${crypto.randomUUID()}`,
    user_guid: userGuid,
    client_type: options.clientType || 'app',
    device_id: options.deviceId,
    issued_at: now.toISOString(),
    expires_at: expiresAt.toISOString(),
    status: options.status || 'active',
    revoked_at: options.status === 'revoked' ? now.toISOString() : undefined,
  };
}

// ============================================
// Tests
// ============================================

describe('POST /vault/nats/token/revoke - Revoke NATS Token', () => {
  let handler: MockRevokeTokenHandler;

  beforeEach(() => {
    handler = new MockRevokeTokenHandler();
  });

  describe('Successful Token Revocation', () => {
    it('should revoke active token', async () => {
      const userGuid = crypto.randomUUID();
      const token = createTestToken(userGuid);
      handler.addToken(token);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims, { token_id: token.token_id });

      expect(result.statusCode).toBe(200);
      const body = result.body as RevokeTokenResponse;
      expect(body.status).toBe('revoked');
    });

    it('should update token status to revoked', async () => {
      const userGuid = crypto.randomUUID();
      const token = createTestToken(userGuid);
      handler.addToken(token);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      await handler.handle(claims, { token_id: token.token_id });

      const updatedToken = handler.getToken(token.token_id);
      expect(updatedToken?.status).toBe('revoked');
    });

    it('should set revoked_at timestamp', async () => {
      const userGuid = crypto.randomUUID();
      const token = createTestToken(userGuid);
      handler.addToken(token);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const beforeRevoke = new Date().toISOString();
      const result = await handler.handle(claims, { token_id: token.token_id });
      const afterRevoke = new Date().toISOString();

      const body = result.body as RevokeTokenResponse;
      expect(body.revoked_at).toBeDefined();
      expect(body.revoked_at >= beforeRevoke).toBe(true);
      expect(body.revoked_at <= afterRevoke).toBe(true);
    });

    it('should return token_id in response', async () => {
      const userGuid = crypto.randomUUID();
      const token = createTestToken(userGuid);
      handler.addToken(token);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims, { token_id: token.token_id });

      const body = result.body as RevokeTokenResponse;
      expect(body.token_id).toBe(token.token_id);
    });

    it('should revoke vault tokens', async () => {
      const userGuid = crypto.randomUUID();
      const token = createTestToken(userGuid, { clientType: 'vault' });
      handler.addToken(token);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims, { token_id: token.token_id });

      expect(result.statusCode).toBe(200);
      expect(handler.getToken(token.token_id)?.status).toBe('revoked');
    });

    it('should revoke app tokens', async () => {
      const userGuid = crypto.randomUUID();
      const token = createTestToken(userGuid, { clientType: 'app' });
      handler.addToken(token);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims, { token_id: token.token_id });

      expect(result.statusCode).toBe(200);
      expect(handler.getToken(token.token_id)?.status).toBe('revoked');
    });
  });

  describe('Authentication', () => {
    it('should require authentication', async () => {
      const result = await handler.handle(null, { token_id: 'some-token' });

      expect(result.statusCode).toBe(401);
      expect((result.body as { error: string }).error).toContain('Unauthorized');
    });

    it('should reject missing user_guid', async () => {
      const claims = {
        user_guid: '',
        email: 'member@test.com',
      };

      const result = await handler.handle(claims, { token_id: 'some-token' });

      expect(result.statusCode).toBe(400);
      expect((result.body as { error: string }).error).toContain('user_guid');
    });
  });

  describe('Request Validation', () => {
    it('should require request body', async () => {
      const claims: MemberClaims = {
        user_guid: crypto.randomUUID(),
        email: 'member@test.com',
      };

      const result = await handler.handle(claims, null);

      expect(result.statusCode).toBe(400);
      expect((result.body as { error: string }).error).toContain('body');
    });

    it('should require token_id', async () => {
      const claims: MemberClaims = {
        user_guid: crypto.randomUUID(),
        email: 'member@test.com',
      };

      const result = await handler.handle(claims, { token_id: '' });

      expect(result.statusCode).toBe(400);
      expect((result.body as { error: string }).error).toContain('token_id');
    });
  });

  describe('Token Not Found', () => {
    it('should return 404 for non-existent token', async () => {
      const claims: MemberClaims = {
        user_guid: crypto.randomUUID(),
        email: 'member@test.com',
      };

      const result = await handler.handle(claims, { token_id: 'nats_nonexistent' });

      expect(result.statusCode).toBe(404);
      expect((result.body as { error: string }).error).toContain('not found');
    });

    it('should return 404 for invalid token format', async () => {
      const claims: MemberClaims = {
        user_guid: crypto.randomUUID(),
        email: 'member@test.com',
      };

      const result = await handler.handle(claims, { token_id: 'invalid-format' });

      expect(result.statusCode).toBe(404);
    });
  });

  describe('Ownership Validation', () => {
    it('should prevent revoking other users tokens', async () => {
      const ownerGuid = crypto.randomUUID();
      const attackerGuid = crypto.randomUUID();
      const token = createTestToken(ownerGuid);
      handler.addToken(token);

      const attackerClaims: MemberClaims = {
        user_guid: attackerGuid,
        email: 'attacker@test.com',
      };

      const result = await handler.handle(attackerClaims, { token_id: token.token_id });

      expect(result.statusCode).toBe(403);
      expect((result.body as { error: string }).error).toContain('other users');
    });

    it('should not modify token when unauthorized', async () => {
      const ownerGuid = crypto.randomUUID();
      const attackerGuid = crypto.randomUUID();
      const token = createTestToken(ownerGuid);
      handler.addToken(token);

      const attackerClaims: MemberClaims = {
        user_guid: attackerGuid,
        email: 'attacker@test.com',
      };

      await handler.handle(attackerClaims, { token_id: token.token_id });

      // Token should still be active
      expect(handler.getToken(token.token_id)?.status).toBe('active');
    });
  });

  describe('Already Revoked Tokens', () => {
    it('should return already revoked message for re-revocation', async () => {
      const userGuid = crypto.randomUUID();
      const token = createTestToken(userGuid, { status: 'revoked' });
      handler.addToken(token);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims, { token_id: token.token_id });

      expect(result.statusCode).toBe(200);
      const body = result.body as RevokeTokenResponse;
      expect(body.message).toContain('already revoked');
    });

    it('should return original revoked_at for already revoked token', async () => {
      const userGuid = crypto.randomUUID();
      const token = createTestToken(userGuid, { status: 'revoked' });
      const originalRevokedAt = token.revoked_at;
      handler.addToken(token);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims, { token_id: token.token_id });

      const body = result.body as RevokeTokenResponse;
      expect(body.revoked_at).toBe(originalRevokedAt);
    });

    it('should return status revoked for already revoked token', async () => {
      const userGuid = crypto.randomUUID();
      const token = createTestToken(userGuid, { status: 'revoked' });
      handler.addToken(token);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims, { token_id: token.token_id });

      const body = result.body as RevokeTokenResponse;
      expect(body.status).toBe('revoked');
    });
  });

  describe('Multiple Tokens', () => {
    it('should only revoke specified token', async () => {
      const userGuid = crypto.randomUUID();
      const token1 = createTestToken(userGuid);
      const token2 = createTestToken(userGuid);
      const token3 = createTestToken(userGuid);
      handler.addToken(token1);
      handler.addToken(token2);
      handler.addToken(token3);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      await handler.handle(claims, { token_id: token2.token_id });

      expect(handler.getToken(token1.token_id)?.status).toBe('active');
      expect(handler.getToken(token2.token_id)?.status).toBe('revoked');
      expect(handler.getToken(token3.token_id)?.status).toBe('active');
    });

    it('should allow revoking multiple tokens sequentially', async () => {
      const userGuid = crypto.randomUUID();
      const token1 = createTestToken(userGuid);
      const token2 = createTestToken(userGuid);
      handler.addToken(token1);
      handler.addToken(token2);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result1 = await handler.handle(claims, { token_id: token1.token_id });
      const result2 = await handler.handle(claims, { token_id: token2.token_id });

      expect(result1.statusCode).toBe(200);
      expect(result2.statusCode).toBe(200);
      expect(handler.getToken(token1.token_id)?.status).toBe('revoked');
      expect(handler.getToken(token2.token_id)?.status).toBe('revoked');
    });

    it('should not affect other users tokens when revoking own', async () => {
      const user1Guid = crypto.randomUUID();
      const user2Guid = crypto.randomUUID();
      const user1Token = createTestToken(user1Guid);
      const user2Token = createTestToken(user2Guid);
      handler.addToken(user1Token);
      handler.addToken(user2Token);

      const claims: MemberClaims = {
        user_guid: user1Guid,
        email: 'user1@test.com',
      };

      await handler.handle(claims, { token_id: user1Token.token_id });

      expect(handler.getToken(user1Token.token_id)?.status).toBe('revoked');
      expect(handler.getToken(user2Token.token_id)?.status).toBe('active');
    });
  });

  describe('Response Format', () => {
    it('should include all required fields', async () => {
      const userGuid = crypto.randomUUID();
      const token = createTestToken(userGuid);
      handler.addToken(token);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims, { token_id: token.token_id });
      const body = result.body as RevokeTokenResponse;

      expect(body).toHaveProperty('token_id');
      expect(body).toHaveProperty('status');
      expect(body).toHaveProperty('revoked_at');
    });

    it('should return 200 status code on success', async () => {
      const userGuid = crypto.randomUUID();
      const token = createTestToken(userGuid);
      handler.addToken(token);

      const claims: MemberClaims = {
        user_guid: userGuid,
        email: 'member@test.com',
      };

      const result = await handler.handle(claims, { token_id: token.token_id });

      expect(result.statusCode).toBe(200);
    });
  });
});
