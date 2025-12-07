/**
 * Integration Tests: NATS Namespace Isolation
 *
 * Tests that NATS namespaces properly isolate users:
 * - Each user has unique OwnerSpace and MessageSpace
 * - Users cannot access other users' namespaces
 * - Token permissions are properly scoped
 * - Cross-user operations are prevented
 *
 * This test suite verifies the security boundaries of the NATS infrastructure.
 */

import * as crypto from 'crypto';

// ============================================
// Types
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
  permissions: {
    publish: string[];
    subscribe: string[];
  };
  expires_at: string;
  status: 'active' | 'revoked';
}

interface MemberClaims {
  user_guid: string;
  email: string;
}

// ============================================
// Mock NATS Permission Validator
// ============================================

class MockNatsPermissionValidator {
  private accounts: Map<string, NatsAccountRecord> = new Map();
  private tokens: Map<string, NatsTokenRecord> = new Map();

  /**
   * Create account for user
   */
  createAccount(userGuid: string): NatsAccountRecord {
    const now = new Date().toISOString();
    const account: NatsAccountRecord = {
      user_guid: userGuid,
      owner_space_id: `OwnerSpace.${userGuid}`,
      message_space_id: `MessageSpace.${userGuid}`,
      account_public_key: `A${crypto.createHash('sha256').update(userGuid).digest('hex').substring(0, 32).toUpperCase()}`,
      status: 'active',
      created_at: now,
      updated_at: now,
    };
    this.accounts.set(userGuid, account);
    return account;
  }

  /**
   * Get account for user
   */
  getAccount(userGuid: string): NatsAccountRecord | undefined {
    return this.accounts.get(userGuid);
  }

  /**
   * Generate app token with proper permissions
   */
  generateAppToken(userGuid: string): NatsTokenRecord {
    const account = this.accounts.get(userGuid);
    if (!account) {
      throw new Error('Account not found');
    }

    const token: NatsTokenRecord = {
      token_id: `nats_${crypto.randomUUID()}`,
      user_guid: userGuid,
      client_type: 'app',
      permissions: {
        publish: [
          `${account.owner_space_id}.forVault.>`,
        ],
        subscribe: [
          `${account.owner_space_id}.forApp.>`,
          `${account.owner_space_id}.eventTypes`,
        ],
      },
      expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
      status: 'active',
    };

    this.tokens.set(token.token_id, token);
    return token;
  }

  /**
   * Generate vault token with proper permissions
   */
  generateVaultToken(userGuid: string): NatsTokenRecord {
    const account = this.accounts.get(userGuid);
    if (!account) {
      throw new Error('Account not found');
    }

    const token: NatsTokenRecord = {
      token_id: `nats_${crypto.randomUUID()}`,
      user_guid: userGuid,
      client_type: 'vault',
      permissions: {
        publish: [
          `${account.owner_space_id}.forApp.>`,
          `${account.message_space_id}.forOwner.>`,
          `${account.message_space_id}.ownerProfile`,
        ],
        subscribe: [
          `${account.owner_space_id}.forVault.>`,
          `${account.owner_space_id}.control`,
          `${account.owner_space_id}.eventTypes`,
          `${account.message_space_id}.forOwner.>`,
        ],
      },
      expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
      status: 'active',
    };

    this.tokens.set(token.token_id, token);
    return token;
  }

  /**
   * Check if a subject matches a permission pattern
   */
  matchesPattern(subject: string, pattern: string): boolean {
    // Handle exact match
    if (subject === pattern) return true;

    // Handle wildcard patterns
    const patternParts = pattern.split('.');
    const subjectParts = subject.split('.');

    for (let i = 0; i < patternParts.length; i++) {
      const patternPart = patternParts[i];

      // > matches all remaining segments
      if (patternPart === '>') {
        return true;
      }

      // * matches exactly one segment
      if (patternPart === '*') {
        if (i >= subjectParts.length) return false;
        continue;
      }

      // Exact match required
      if (i >= subjectParts.length || patternPart !== subjectParts[i]) {
        return false;
      }
    }

    // Subject must have same length as pattern (unless pattern ends with >)
    return patternParts.length === subjectParts.length;
  }

  /**
   * Check if token can publish to subject
   */
  canPublish(tokenId: string, subject: string): boolean {
    const token = this.tokens.get(tokenId);
    if (!token || token.status !== 'active') return false;
    if (new Date(token.expires_at) < new Date()) return false;

    return token.permissions.publish.some(pattern =>
      this.matchesPattern(subject, pattern)
    );
  }

  /**
   * Check if token can subscribe to subject
   */
  canSubscribe(tokenId: string, subject: string): boolean {
    const token = this.tokens.get(tokenId);
    if (!token || token.status !== 'active') return false;
    if (new Date(token.expires_at) < new Date()) return false;

    return token.permissions.subscribe.some(pattern =>
      this.matchesPattern(subject, pattern)
    );
  }

  /**
   * Clear all data
   */
  clear(): void {
    this.accounts.clear();
    this.tokens.clear();
  }
}

// ============================================
// Tests
// ============================================

describe('NATS Namespace Isolation', () => {
  let validator: MockNatsPermissionValidator;

  beforeEach(() => {
    validator = new MockNatsPermissionValidator();
  });

  describe('Namespace Uniqueness', () => {
    it('should generate unique OwnerSpace for each user', () => {
      const user1 = crypto.randomUUID();
      const user2 = crypto.randomUUID();

      const account1 = validator.createAccount(user1);
      const account2 = validator.createAccount(user2);

      expect(account1.owner_space_id).not.toBe(account2.owner_space_id);
    });

    it('should generate unique MessageSpace for each user', () => {
      const user1 = crypto.randomUUID();
      const user2 = crypto.randomUUID();

      const account1 = validator.createAccount(user1);
      const account2 = validator.createAccount(user2);

      expect(account1.message_space_id).not.toBe(account2.message_space_id);
    });

    it('should include user_guid in OwnerSpace ID', () => {
      const userGuid = crypto.randomUUID();
      const account = validator.createAccount(userGuid);

      expect(account.owner_space_id).toContain(userGuid);
    });

    it('should include user_guid in MessageSpace ID', () => {
      const userGuid = crypto.randomUUID();
      const account = validator.createAccount(userGuid);

      expect(account.message_space_id).toContain(userGuid);
    });

    it('should generate unique account public keys', () => {
      const user1 = crypto.randomUUID();
      const user2 = crypto.randomUUID();

      const account1 = validator.createAccount(user1);
      const account2 = validator.createAccount(user2);

      expect(account1.account_public_key).not.toBe(account2.account_public_key);
    });
  });

  describe('App Token Permissions', () => {
    it('should allow app to publish to own forVault namespace', () => {
      const userGuid = crypto.randomUUID();
      validator.createAccount(userGuid);
      const token = validator.generateAppToken(userGuid);

      const canPublish = validator.canPublish(
        token.token_id,
        `OwnerSpace.${userGuid}.forVault.command`
      );

      expect(canPublish).toBe(true);
    });

    it('should allow app to subscribe to own forApp namespace', () => {
      const userGuid = crypto.randomUUID();
      validator.createAccount(userGuid);
      const token = validator.generateAppToken(userGuid);

      const canSubscribe = validator.canSubscribe(
        token.token_id,
        `OwnerSpace.${userGuid}.forApp.response`
      );

      expect(canSubscribe).toBe(true);
    });

    it('should allow app to subscribe to own eventTypes', () => {
      const userGuid = crypto.randomUUID();
      validator.createAccount(userGuid);
      const token = validator.generateAppToken(userGuid);

      const canSubscribe = validator.canSubscribe(
        token.token_id,
        `OwnerSpace.${userGuid}.eventTypes`
      );

      expect(canSubscribe).toBe(true);
    });

    it('should NOT allow app to publish to own forApp namespace', () => {
      const userGuid = crypto.randomUUID();
      validator.createAccount(userGuid);
      const token = validator.generateAppToken(userGuid);

      const canPublish = validator.canPublish(
        token.token_id,
        `OwnerSpace.${userGuid}.forApp.response`
      );

      expect(canPublish).toBe(false);
    });

    it('should NOT allow app to subscribe to own forVault namespace', () => {
      const userGuid = crypto.randomUUID();
      validator.createAccount(userGuid);
      const token = validator.generateAppToken(userGuid);

      const canSubscribe = validator.canSubscribe(
        token.token_id,
        `OwnerSpace.${userGuid}.forVault.command`
      );

      expect(canSubscribe).toBe(false);
    });
  });

  describe('Vault Token Permissions', () => {
    it('should allow vault to publish to own forApp namespace', () => {
      const userGuid = crypto.randomUUID();
      validator.createAccount(userGuid);
      const token = validator.generateVaultToken(userGuid);

      const canPublish = validator.canPublish(
        token.token_id,
        `OwnerSpace.${userGuid}.forApp.response`
      );

      expect(canPublish).toBe(true);
    });

    it('should allow vault to subscribe to own forVault namespace', () => {
      const userGuid = crypto.randomUUID();
      validator.createAccount(userGuid);
      const token = validator.generateVaultToken(userGuid);

      const canSubscribe = validator.canSubscribe(
        token.token_id,
        `OwnerSpace.${userGuid}.forVault.command`
      );

      expect(canSubscribe).toBe(true);
    });

    it('should allow vault to subscribe to own control subject', () => {
      const userGuid = crypto.randomUUID();
      validator.createAccount(userGuid);
      const token = validator.generateVaultToken(userGuid);

      const canSubscribe = validator.canSubscribe(
        token.token_id,
        `OwnerSpace.${userGuid}.control`
      );

      expect(canSubscribe).toBe(true);
    });

    it('should allow vault to publish to own MessageSpace forOwner', () => {
      const userGuid = crypto.randomUUID();
      validator.createAccount(userGuid);
      const token = validator.generateVaultToken(userGuid);

      const canPublish = validator.canPublish(
        token.token_id,
        `MessageSpace.${userGuid}.forOwner.notification`
      );

      expect(canPublish).toBe(true);
    });

    it('should allow vault to subscribe to own MessageSpace forOwner', () => {
      const userGuid = crypto.randomUUID();
      validator.createAccount(userGuid);
      const token = validator.generateVaultToken(userGuid);

      const canSubscribe = validator.canSubscribe(
        token.token_id,
        `MessageSpace.${userGuid}.forOwner.message`
      );

      expect(canSubscribe).toBe(true);
    });

    it('should allow vault to publish own profile', () => {
      const userGuid = crypto.randomUUID();
      validator.createAccount(userGuid);
      const token = validator.generateVaultToken(userGuid);

      const canPublish = validator.canPublish(
        token.token_id,
        `MessageSpace.${userGuid}.ownerProfile`
      );

      expect(canPublish).toBe(true);
    });
  });

  describe('Cross-User Isolation - App Token', () => {
    it('should NOT allow app to publish to other user forVault namespace', () => {
      const user1 = crypto.randomUUID();
      const user2 = crypto.randomUUID();

      validator.createAccount(user1);
      validator.createAccount(user2);
      const token = validator.generateAppToken(user1);

      const canPublish = validator.canPublish(
        token.token_id,
        `OwnerSpace.${user2}.forVault.command`
      );

      expect(canPublish).toBe(false);
    });

    it('should NOT allow app to subscribe to other user forApp namespace', () => {
      const user1 = crypto.randomUUID();
      const user2 = crypto.randomUUID();

      validator.createAccount(user1);
      validator.createAccount(user2);
      const token = validator.generateAppToken(user1);

      const canSubscribe = validator.canSubscribe(
        token.token_id,
        `OwnerSpace.${user2}.forApp.response`
      );

      expect(canSubscribe).toBe(false);
    });

    it('should NOT allow app to subscribe to other user eventTypes', () => {
      const user1 = crypto.randomUUID();
      const user2 = crypto.randomUUID();

      validator.createAccount(user1);
      validator.createAccount(user2);
      const token = validator.generateAppToken(user1);

      const canSubscribe = validator.canSubscribe(
        token.token_id,
        `OwnerSpace.${user2}.eventTypes`
      );

      expect(canSubscribe).toBe(false);
    });
  });

  describe('Cross-User Isolation - Vault Token', () => {
    it('should NOT allow vault to publish to other user forApp namespace', () => {
      const user1 = crypto.randomUUID();
      const user2 = crypto.randomUUID();

      validator.createAccount(user1);
      validator.createAccount(user2);
      const token = validator.generateVaultToken(user1);

      const canPublish = validator.canPublish(
        token.token_id,
        `OwnerSpace.${user2}.forApp.response`
      );

      expect(canPublish).toBe(false);
    });

    it('should NOT allow vault to subscribe to other user forVault namespace', () => {
      const user1 = crypto.randomUUID();
      const user2 = crypto.randomUUID();

      validator.createAccount(user1);
      validator.createAccount(user2);
      const token = validator.generateVaultToken(user1);

      const canSubscribe = validator.canSubscribe(
        token.token_id,
        `OwnerSpace.${user2}.forVault.command`
      );

      expect(canSubscribe).toBe(false);
    });

    it('should NOT allow vault to subscribe to other user control', () => {
      const user1 = crypto.randomUUID();
      const user2 = crypto.randomUUID();

      validator.createAccount(user1);
      validator.createAccount(user2);
      const token = validator.generateVaultToken(user1);

      const canSubscribe = validator.canSubscribe(
        token.token_id,
        `OwnerSpace.${user2}.control`
      );

      expect(canSubscribe).toBe(false);
    });

    it('should NOT allow vault to publish to other user MessageSpace', () => {
      const user1 = crypto.randomUUID();
      const user2 = crypto.randomUUID();

      validator.createAccount(user1);
      validator.createAccount(user2);
      const token = validator.generateVaultToken(user1);

      const canPublish = validator.canPublish(
        token.token_id,
        `MessageSpace.${user2}.forOwner.notification`
      );

      expect(canPublish).toBe(false);
    });

    it('should NOT allow vault to subscribe to other user MessageSpace', () => {
      const user1 = crypto.randomUUID();
      const user2 = crypto.randomUUID();

      validator.createAccount(user1);
      validator.createAccount(user2);
      const token = validator.generateVaultToken(user1);

      const canSubscribe = validator.canSubscribe(
        token.token_id,
        `MessageSpace.${user2}.forOwner.message`
      );

      expect(canSubscribe).toBe(false);
    });

    it('should NOT allow vault to publish other user profile', () => {
      const user1 = crypto.randomUUID();
      const user2 = crypto.randomUUID();

      validator.createAccount(user1);
      validator.createAccount(user2);
      const token = validator.generateVaultToken(user1);

      const canPublish = validator.canPublish(
        token.token_id,
        `MessageSpace.${user2}.ownerProfile`
      );

      expect(canPublish).toBe(false);
    });
  });

  describe('Token Expiry Enforcement', () => {
    it('should deny expired token publish', () => {
      const userGuid = crypto.randomUUID();
      validator.createAccount(userGuid);
      const token = validator.generateAppToken(userGuid);

      // Manually expire the token
      const storedToken = (validator as any).tokens.get(token.token_id);
      storedToken.expires_at = new Date(Date.now() - 1000).toISOString();

      const canPublish = validator.canPublish(
        token.token_id,
        `OwnerSpace.${userGuid}.forVault.command`
      );

      expect(canPublish).toBe(false);
    });

    it('should deny expired token subscribe', () => {
      const userGuid = crypto.randomUUID();
      validator.createAccount(userGuid);
      const token = validator.generateAppToken(userGuid);

      // Manually expire the token
      const storedToken = (validator as any).tokens.get(token.token_id);
      storedToken.expires_at = new Date(Date.now() - 1000).toISOString();

      const canSubscribe = validator.canSubscribe(
        token.token_id,
        `OwnerSpace.${userGuid}.forApp.response`
      );

      expect(canSubscribe).toBe(false);
    });
  });

  describe('Token Revocation Enforcement', () => {
    it('should deny revoked token publish', () => {
      const userGuid = crypto.randomUUID();
      validator.createAccount(userGuid);
      const token = validator.generateAppToken(userGuid);

      // Revoke the token
      const storedToken = (validator as any).tokens.get(token.token_id);
      storedToken.status = 'revoked';

      const canPublish = validator.canPublish(
        token.token_id,
        `OwnerSpace.${userGuid}.forVault.command`
      );

      expect(canPublish).toBe(false);
    });

    it('should deny revoked token subscribe', () => {
      const userGuid = crypto.randomUUID();
      validator.createAccount(userGuid);
      const token = validator.generateAppToken(userGuid);

      // Revoke the token
      const storedToken = (validator as any).tokens.get(token.token_id);
      storedToken.status = 'revoked';

      const canSubscribe = validator.canSubscribe(
        token.token_id,
        `OwnerSpace.${userGuid}.forApp.response`
      );

      expect(canSubscribe).toBe(false);
    });
  });

  describe('Invalid Token Handling', () => {
    it('should deny non-existent token publish', () => {
      const canPublish = validator.canPublish(
        'nats_nonexistent',
        'OwnerSpace.someuser.forVault.command'
      );

      expect(canPublish).toBe(false);
    });

    it('should deny non-existent token subscribe', () => {
      const canSubscribe = validator.canSubscribe(
        'nats_nonexistent',
        'OwnerSpace.someuser.forApp.response'
      );

      expect(canSubscribe).toBe(false);
    });
  });

  describe('Pattern Matching', () => {
    it('should match wildcard > for all remaining segments', () => {
      const userGuid = crypto.randomUUID();
      validator.createAccount(userGuid);
      const token = validator.generateAppToken(userGuid);

      // forVault.> should match any suffix
      expect(validator.canPublish(
        token.token_id,
        `OwnerSpace.${userGuid}.forVault.command.foo.bar`
      )).toBe(true);
    });

    it('should not match partial prefix incorrectly', () => {
      const userGuid = crypto.randomUUID();
      validator.createAccount(userGuid);
      const token = validator.generateAppToken(userGuid);

      // Should not match different base subject
      expect(validator.canPublish(
        token.token_id,
        `OwnerSpace.${userGuid}.forApp.command`
      )).toBe(false);
    });

    it('should match exact subject for eventTypes', () => {
      const userGuid = crypto.randomUUID();
      validator.createAccount(userGuid);
      const token = validator.generateAppToken(userGuid);

      // eventTypes is exact match, not wildcard
      expect(validator.canSubscribe(
        token.token_id,
        `OwnerSpace.${userGuid}.eventTypes`
      )).toBe(true);

      // Should not match eventTypes.foo
      expect(validator.canSubscribe(
        token.token_id,
        `OwnerSpace.${userGuid}.eventTypes.foo`
      )).toBe(false);
    });
  });

  describe('Multi-User Scenario', () => {
    it('should maintain isolation across many users', () => {
      const users = Array.from({ length: 10 }, () => crypto.randomUUID());

      // Create accounts and tokens for all users
      const tokens = users.map(userGuid => {
        validator.createAccount(userGuid);
        return {
          userGuid,
          appToken: validator.generateAppToken(userGuid),
          vaultToken: validator.generateVaultToken(userGuid),
        };
      });

      // Each user's app token should only access their own namespace
      for (const { userGuid, appToken } of tokens) {
        // Can publish to own forVault
        expect(validator.canPublish(
          appToken.token_id,
          `OwnerSpace.${userGuid}.forVault.test`
        )).toBe(true);

        // Cannot publish to any other user's forVault
        for (const otherUser of users.filter(u => u !== userGuid)) {
          expect(validator.canPublish(
            appToken.token_id,
            `OwnerSpace.${otherUser}.forVault.test`
          )).toBe(false);
        }
      }
    });

    it('should allow different client types for same user', () => {
      const userGuid = crypto.randomUUID();
      validator.createAccount(userGuid);

      const appToken = validator.generateAppToken(userGuid);
      const vaultToken = validator.generateVaultToken(userGuid);

      // App publishes to forVault, vault subscribes
      expect(validator.canPublish(
        appToken.token_id,
        `OwnerSpace.${userGuid}.forVault.command`
      )).toBe(true);
      expect(validator.canSubscribe(
        vaultToken.token_id,
        `OwnerSpace.${userGuid}.forVault.command`
      )).toBe(true);

      // Vault publishes to forApp, app subscribes
      expect(validator.canPublish(
        vaultToken.token_id,
        `OwnerSpace.${userGuid}.forApp.response`
      )).toBe(true);
      expect(validator.canSubscribe(
        appToken.token_id,
        `OwnerSpace.${userGuid}.forApp.response`
      )).toBe(true);
    });
  });
});
