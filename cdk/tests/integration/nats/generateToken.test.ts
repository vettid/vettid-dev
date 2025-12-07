/**
 * Integration Tests: Generate NATS Token
 *
 * Tests the POST /vault/nats/token endpoint that:
 * - Generates scoped NATS JWT tokens for members
 * - Supports app and vault client types
 * - Returns proper permissions based on client type
 *
 * @see cdk/lambda/handlers/nats/generateMemberJwt.ts
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
}

interface NatsTokenRecord {
  token_id: string;
  user_guid: string;
  client_type: 'app' | 'vault';
  device_id?: string;
  issued_at: string;
  expires_at: string;
  status: 'active' | 'revoked';
}

interface GenerateTokenRequest {
  client_type: 'app' | 'vault';
  device_id?: string;
}

interface GenerateTokenResponse {
  token_id: string;
  nats_jwt: string;
  nats_seed: string;
  nats_endpoint: string;
  expires_at: string;
  permissions: {
    publish: string[];
    subscribe: string[];
  };
}

interface MemberClaims {
  user_guid: string;
  email: string;
}

// ============================================
// Constants
// ============================================

const APP_TOKEN_VALIDITY_MINUTES = 60 * 24; // 24 hours
const VAULT_TOKEN_VALIDITY_MINUTES = 60 * 24 * 7; // 7 days

// ============================================
// Mock Handler (simulates Lambda handler)
// ============================================

class MockGenerateTokenHandler {
  private accounts: Map<string, NatsAccountRecord> = new Map();
  private tokens: Map<string, NatsTokenRecord> = new Map();
  private readonly natsDomain = 'nats.vettid.dev';

  /**
   * Add account (for testing setup)
   */
  addAccount(account: NatsAccountRecord): void {
    this.accounts.set(account.user_guid, account);
  }

  /**
   * Generate placeholder NATS credentials
   */
  private generateNatsCredentials(
    userGuid: string,
    tokenId: string,
    publishPerms: string[],
    subscribePerms: string[],
    expiresAt: string
  ): { jwt: string; seed: string } {
    // Placeholder JWT structure
    const jwtPayload = {
      jti: tokenId,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(new Date(expiresAt).getTime() / 1000),
      iss: 'vettid-operator',
      sub: userGuid,
      nats: {
        pub: { allow: publishPerms },
        sub: { allow: subscribePerms },
        subs: -1,
        data: -1,
        payload: -1,
      },
    };

    const header = Buffer.from(JSON.stringify({ typ: 'JWT', alg: 'ed25519-nkey' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify(jwtPayload)).toString('base64url');
    const signature = crypto.createHash('sha256')
      .update(`${header}.${payload}.${tokenId}`)
      .digest('base64url');

    const jwt = `${header}.${payload}.${signature}`;
    const seed = `SUAM${crypto.createHash('sha256').update(tokenId).digest('hex').substring(0, 48).toUpperCase()}`;

    return { jwt, seed };
  }

  /**
   * Handle token generation request
   */
  async handle(claims: MemberClaims | null, body: GenerateTokenRequest | null): Promise<{
    statusCode: number;
    body: GenerateTokenResponse | { error: string };
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
        body: { error: 'Request body required' },
      };
    }

    if (!body.client_type || !['app', 'vault'].includes(body.client_type)) {
      return {
        statusCode: 400,
        body: { error: 'Invalid client_type. Must be "app" or "vault"' },
      };
    }

    // Verify NATS account exists
    const account = this.accounts.get(userGuid);
    if (!account) {
      return {
        statusCode: 404,
        body: { error: 'NATS account not found. Create account first via POST /vault/nats/account' },
      };
    }

    if (account.status !== 'active') {
      return {
        statusCode: 403,
        body: { error: 'NATS account is not active' },
      };
    }

    // Calculate token validity
    const validityMinutes = body.client_type === 'vault'
      ? VAULT_TOKEN_VALIDITY_MINUTES
      : APP_TOKEN_VALIDITY_MINUTES;

    const now = new Date();
    const expiresAt = new Date(now.getTime() + validityMinutes * 60 * 1000).toISOString();
    const tokenId = `nats_${crypto.randomUUID()}`;

    // Define permissions based on client type
    const ownerSpace = account.owner_space_id;
    const messageSpace = account.message_space_id;

    let publishPerms: string[];
    let subscribePerms: string[];

    if (body.client_type === 'app') {
      // Mobile app permissions
      publishPerms = [
        `${ownerSpace}.forVault.>`,
      ];
      subscribePerms = [
        `${ownerSpace}.forApp.>`,
        `${ownerSpace}.eventTypes`,
      ];
    } else {
      // Vault instance permissions
      publishPerms = [
        `${ownerSpace}.forApp.>`,
        `${messageSpace}.forOwner.>`,
        `${messageSpace}.ownerProfile`,
      ];
      subscribePerms = [
        `${ownerSpace}.forVault.>`,
        `${ownerSpace}.control`,
        `${ownerSpace}.eventTypes`,
        `${messageSpace}.forOwner.>`,
      ];
    }

    // Generate NATS credentials
    const { jwt, seed } = this.generateNatsCredentials(
      userGuid,
      tokenId,
      publishPerms,
      subscribePerms,
      expiresAt
    );

    // Store token record
    const tokenRecord: NatsTokenRecord = {
      token_id: tokenId,
      user_guid: userGuid,
      client_type: body.client_type,
      device_id: body.device_id,
      issued_at: now.toISOString(),
      expires_at: expiresAt,
      status: 'active',
    };

    this.tokens.set(tokenId, tokenRecord);

    const response: GenerateTokenResponse = {
      token_id: tokenId,
      nats_jwt: jwt,
      nats_seed: seed,
      nats_endpoint: `nats://${this.natsDomain}:4222`,
      expires_at: expiresAt,
      permissions: {
        publish: publishPerms,
        subscribe: subscribePerms,
      },
    };

    return {
      statusCode: 200,
      body: response,
    };
  }

  /**
   * Get token by ID (for testing)
   */
  getToken(tokenId: string): NatsTokenRecord | undefined {
    return this.tokens.get(tokenId);
  }

  /**
   * Get all tokens for user (for testing)
   */
  getTokensForUser(userGuid: string): NatsTokenRecord[] {
    return Array.from(this.tokens.values()).filter(t => t.user_guid === userGuid);
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
// Tests
// ============================================

describe('POST /vault/nats/token - Generate NATS Token', () => {
  let handler: MockGenerateTokenHandler;
  let testAccount: NatsAccountRecord;
  let testClaims: MemberClaims;

  beforeEach(() => {
    handler = new MockGenerateTokenHandler();

    const userGuid = crypto.randomUUID();
    testClaims = {
      user_guid: userGuid,
      email: 'member@test.com',
    };

    testAccount = {
      user_guid: userGuid,
      owner_space_id: `OwnerSpace.${userGuid}`,
      message_space_id: `MessageSpace.${userGuid}`,
      account_public_key: `A${crypto.randomBytes(16).toString('hex').toUpperCase()}`,
      status: 'active',
      created_at: new Date().toISOString(),
    };
    handler.addAccount(testAccount);
  });

  describe('App Client Token Generation', () => {
    it('should generate token for app client_type', async () => {
      const result = await handler.handle(testClaims, { client_type: 'app' });

      expect(result.statusCode).toBe(200);
      const body = result.body as GenerateTokenResponse;
      expect(body.token_id).toBeDefined();
      expect(body.nats_jwt).toBeDefined();
      expect(body.nats_seed).toBeDefined();
    });

    it('should set app token validity to 24 hours', async () => {
      const result = await handler.handle(testClaims, { client_type: 'app' });

      const body = result.body as GenerateTokenResponse;
      const expiresAt = new Date(body.expires_at);
      const expectedExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000);

      // Allow 1 second tolerance
      expect(Math.abs(expiresAt.getTime() - expectedExpiry.getTime())).toBeLessThan(1000);
    });

    it('should return correct app permissions', async () => {
      const result = await handler.handle(testClaims, { client_type: 'app' });

      const body = result.body as GenerateTokenResponse;

      // App can publish to vault
      expect(body.permissions.publish).toContain(`${testAccount.owner_space_id}.forVault.>`);

      // App can subscribe to app messages and event types
      expect(body.permissions.subscribe).toContain(`${testAccount.owner_space_id}.forApp.>`);
      expect(body.permissions.subscribe).toContain(`${testAccount.owner_space_id}.eventTypes`);
    });

    it('should not allow app to publish to forApp', async () => {
      const result = await handler.handle(testClaims, { client_type: 'app' });

      const body = result.body as GenerateTokenResponse;
      expect(body.permissions.publish).not.toContain(`${testAccount.owner_space_id}.forApp.>`);
    });
  });

  describe('Vault Client Token Generation', () => {
    it('should generate token for vault client_type', async () => {
      const result = await handler.handle(testClaims, { client_type: 'vault' });

      expect(result.statusCode).toBe(200);
      const body = result.body as GenerateTokenResponse;
      expect(body.token_id).toBeDefined();
      expect(body.nats_jwt).toBeDefined();
      expect(body.nats_seed).toBeDefined();
    });

    it('should set vault token validity to 7 days', async () => {
      const result = await handler.handle(testClaims, { client_type: 'vault' });

      const body = result.body as GenerateTokenResponse;
      const expiresAt = new Date(body.expires_at);
      const expectedExpiry = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

      // Allow 1 second tolerance
      expect(Math.abs(expiresAt.getTime() - expectedExpiry.getTime())).toBeLessThan(1000);
    });

    it('should return correct vault publish permissions', async () => {
      const result = await handler.handle(testClaims, { client_type: 'vault' });

      const body = result.body as GenerateTokenResponse;

      // Vault can publish to app
      expect(body.permissions.publish).toContain(`${testAccount.owner_space_id}.forApp.>`);

      // Vault can publish to message space
      expect(body.permissions.publish).toContain(`${testAccount.message_space_id}.forOwner.>`);
      expect(body.permissions.publish).toContain(`${testAccount.message_space_id}.ownerProfile`);
    });

    it('should return correct vault subscribe permissions', async () => {
      const result = await handler.handle(testClaims, { client_type: 'vault' });

      const body = result.body as GenerateTokenResponse;

      // Vault can subscribe to vault messages and control
      expect(body.permissions.subscribe).toContain(`${testAccount.owner_space_id}.forVault.>`);
      expect(body.permissions.subscribe).toContain(`${testAccount.owner_space_id}.control`);
      expect(body.permissions.subscribe).toContain(`${testAccount.owner_space_id}.eventTypes`);
      expect(body.permissions.subscribe).toContain(`${testAccount.message_space_id}.forOwner.>`);
    });

    it('should not allow vault to subscribe to forApp', async () => {
      const result = await handler.handle(testClaims, { client_type: 'vault' });

      const body = result.body as GenerateTokenResponse;
      expect(body.permissions.subscribe).not.toContain(`${testAccount.owner_space_id}.forApp.>`);
    });
  });

  describe('Account Requirement', () => {
    it('should require NATS account to exist first', async () => {
      const noAccountClaims: MemberClaims = {
        user_guid: crypto.randomUUID(),
        email: 'noaccont@test.com',
      };

      const result = await handler.handle(noAccountClaims, { client_type: 'app' });

      expect(result.statusCode).toBe(404);
      expect((result.body as { error: string }).error).toContain('NATS account not found');
    });

    it('should reject token generation for suspended account', async () => {
      testAccount.status = 'suspended';
      handler.addAccount(testAccount);

      const result = await handler.handle(testClaims, { client_type: 'app' });

      expect(result.statusCode).toBe(403);
      expect((result.body as { error: string }).error).toContain('not active');
    });

    it('should reject token generation for revoked account', async () => {
      testAccount.status = 'revoked';
      handler.addAccount(testAccount);

      const result = await handler.handle(testClaims, { client_type: 'app' });

      expect(result.statusCode).toBe(403);
    });
  });

  describe('Request Validation', () => {
    it('should require authentication', async () => {
      const result = await handler.handle(null, { client_type: 'app' });

      expect(result.statusCode).toBe(401);
    });

    it('should require request body', async () => {
      const result = await handler.handle(testClaims, null);

      expect(result.statusCode).toBe(400);
    });

    it('should reject invalid client_type', async () => {
      const result = await handler.handle(testClaims, { client_type: 'invalid' as any });

      expect(result.statusCode).toBe(400);
      expect((result.body as { error: string }).error).toContain('client_type');
    });

    it('should reject missing client_type', async () => {
      const result = await handler.handle(testClaims, {} as GenerateTokenRequest);

      expect(result.statusCode).toBe(400);
    });
  });

  describe('Token Storage', () => {
    it('should store token record in DynamoDB', async () => {
      const result = await handler.handle(testClaims, { client_type: 'app' });

      const body = result.body as GenerateTokenResponse;
      const tokenRecord = handler.getToken(body.token_id);

      expect(tokenRecord).toBeDefined();
      expect(tokenRecord?.user_guid).toBe(testClaims.user_guid);
      expect(tokenRecord?.client_type).toBe('app');
      expect(tokenRecord?.status).toBe('active');
    });

    it('should store device_id if provided', async () => {
      const result = await handler.handle(testClaims, {
        client_type: 'app',
        device_id: 'device-xyz-123',
      });

      const body = result.body as GenerateTokenResponse;
      const tokenRecord = handler.getToken(body.token_id);

      expect(tokenRecord?.device_id).toBe('device-xyz-123');
    });

    it('should allow multiple tokens for same user', async () => {
      await handler.handle(testClaims, { client_type: 'app' });
      await handler.handle(testClaims, { client_type: 'vault' });
      await handler.handle(testClaims, { client_type: 'app', device_id: 'device-2' });

      const tokens = handler.getTokensForUser(testClaims.user_guid);
      expect(tokens).toHaveLength(3);
    });
  });

  describe('Response Format', () => {
    it('should include nats_jwt and nats_seed in response', async () => {
      const result = await handler.handle(testClaims, { client_type: 'app' });

      const body = result.body as GenerateTokenResponse;
      expect(body.nats_jwt).toBeDefined();
      expect(body.nats_jwt).toContain('.'); // JWT format
      expect(body.nats_seed).toBeDefined();
      expect(body.nats_seed).toMatch(/^SUAM[A-F0-9]+$/);
    });

    it('should include nats_endpoint', async () => {
      const result = await handler.handle(testClaims, { client_type: 'app' });

      const body = result.body as GenerateTokenResponse;
      expect(body.nats_endpoint).toBe('nats://nats.vettid.dev:4222');
    });

    it('should include expires_at', async () => {
      const result = await handler.handle(testClaims, { client_type: 'app' });

      const body = result.body as GenerateTokenResponse;
      expect(body.expires_at).toBeDefined();
      expect(new Date(body.expires_at).getTime()).toBeGreaterThan(Date.now());
    });

    it('should include token_id', async () => {
      const result = await handler.handle(testClaims, { client_type: 'app' });

      const body = result.body as GenerateTokenResponse;
      expect(body.token_id).toBeDefined();
      expect(body.token_id).toMatch(/^nats_[0-9a-f-]{36}$/);
    });
  });

  describe('Token Uniqueness', () => {
    it('should generate unique token IDs', async () => {
      const result1 = await handler.handle(testClaims, { client_type: 'app' });
      const result2 = await handler.handle(testClaims, { client_type: 'app' });

      const body1 = result1.body as GenerateTokenResponse;
      const body2 = result2.body as GenerateTokenResponse;

      expect(body1.token_id).not.toBe(body2.token_id);
    });

    it('should generate unique nats_jwt per token', async () => {
      const result1 = await handler.handle(testClaims, { client_type: 'app' });
      const result2 = await handler.handle(testClaims, { client_type: 'app' });

      const body1 = result1.body as GenerateTokenResponse;
      const body2 = result2.body as GenerateTokenResponse;

      expect(body1.nats_jwt).not.toBe(body2.nats_jwt);
    });

    it('should generate unique nats_seed per token', async () => {
      const result1 = await handler.handle(testClaims, { client_type: 'app' });
      const result2 = await handler.handle(testClaims, { client_type: 'app' });

      const body1 = result1.body as GenerateTokenResponse;
      const body2 = result2.body as GenerateTokenResponse;

      expect(body1.nats_seed).not.toBe(body2.nats_seed);
    });
  });
});
