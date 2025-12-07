/**
 * Integration Tests: Validate Invite Endpoint
 *
 * Tests the POST /vault/enroll/start endpoint that:
 * - Validates the invite code from QR scan
 * - Returns attestation challenge
 * - Returns transaction keys for password encryption
 *
 * @see cdk/coordination/specs/vault-services-api.yaml
 * @see POST /vault/enroll/start
 */

import * as crypto from 'crypto';
import {
  generateTransactionKeyPool,
  TransactionKeyPair,
} from '../../../lambda/common/crypto';

// ============================================
// Types (matching API spec)
// ============================================

interface EnrollStartRequest {
  inviteCode: string;
  deviceInfo: {
    platform: 'android' | 'ios';
    osVersion: string;
    appVersion: string;
    deviceModel?: string;
  };
}

interface EnrollStartResponse {
  sessionId: string;
  attestationChallenge: string;  // Base64 encoded 32 bytes
  transactionKeys: Array<{
    keyId: string;
    publicKey: string;  // Base64 encoded X25519 public key
  }>;
  expiresAt: string;
}

interface InviteRecord {
  code: string;
  vaultId: string;
  memberId: string;
  status: 'pending' | 'used' | 'expired' | 'revoked';
  createdAt: string;
  expiresAt: string;
}

interface EnrollmentSession {
  sessionId: string;
  inviteCode: string;
  vaultId: string;
  state: 'started' | 'attested' | 'password_set' | 'finalized';
  deviceInfo: EnrollStartRequest['deviceInfo'];
  attestationChallenge: Buffer;
  transactionKeys: TransactionKeyPair[];
  createdAt: Date;
  expiresAt: Date;
}

// ============================================
// Mock Handler (simulates Lambda handler)
// ============================================

class MockValidateInviteHandler {
  private invites: Map<string, InviteRecord> = new Map();
  private sessions: Map<string, EnrollmentSession> = new Map();
  private readonly sessionTimeoutMinutes = 30;
  private readonly transactionKeyCount = 10;

  /**
   * Register an invite (for testing setup)
   */
  registerInvite(invite: InviteRecord): void {
    this.invites.set(invite.code, invite);
  }

  /**
   * Handle enrollment start request
   */
  async handle(request: EnrollStartRequest): Promise<{
    statusCode: number;
    body: EnrollStartResponse | { error: string };
  }> {
    // Validate request
    if (!request.inviteCode) {
      return {
        statusCode: 400,
        body: { error: 'Invite code is required' },
      };
    }

    if (!request.deviceInfo) {
      return {
        statusCode: 400,
        body: { error: 'Device info is required' },
      };
    }

    if (!request.deviceInfo.platform || !['android', 'ios'].includes(request.deviceInfo.platform)) {
      return {
        statusCode: 400,
        body: { error: 'Invalid platform: must be android or ios' },
      };
    }

    if (!request.deviceInfo.osVersion) {
      return {
        statusCode: 400,
        body: { error: 'OS version is required' },
      };
    }

    if (!request.deviceInfo.appVersion) {
      return {
        statusCode: 400,
        body: { error: 'App version is required' },
      };
    }

    // Validate invite code format
    if (!request.inviteCode.match(/^VE-[A-Z0-9]{12}$/)) {
      return {
        statusCode: 400,
        body: { error: 'Invalid invite code format' },
      };
    }

    // Lookup invite
    const invite = this.invites.get(request.inviteCode);
    if (!invite) {
      return {
        statusCode: 404,
        body: { error: 'Invite code not found' },
      };
    }

    // Check invite status
    if (invite.status === 'used') {
      return {
        statusCode: 410,
        body: { error: 'Invite code has already been used' },
      };
    }

    if (invite.status === 'revoked') {
      return {
        statusCode: 410,
        body: { error: 'Invite code has been revoked' },
      };
    }

    // Check expiration
    if (new Date(invite.expiresAt) < new Date()) {
      invite.status = 'expired';
      return {
        statusCode: 410,
        body: { error: 'Invite code has expired' },
      };
    }

    if (invite.status === 'expired') {
      return {
        statusCode: 410,
        body: { error: 'Invite code has expired' },
      };
    }

    // Check if session already exists for this invite
    const existingSession = Array.from(this.sessions.values()).find(
      s => s.inviteCode === request.inviteCode && s.state !== 'finalized' && s.expiresAt > new Date()
    );

    if (existingSession) {
      return {
        statusCode: 409,
        body: { error: 'Enrollment session already in progress' },
      };
    }

    // Generate attestation challenge (32 random bytes)
    const attestationChallenge = crypto.randomBytes(32);

    // Generate transaction keys
    const transactionKeys = generateTransactionKeyPool(this.transactionKeyCount);

    // Create enrollment session
    const session: EnrollmentSession = {
      sessionId: crypto.randomUUID(),
      inviteCode: request.inviteCode,
      vaultId: invite.vaultId,
      state: 'started',
      deviceInfo: request.deviceInfo,
      attestationChallenge,
      transactionKeys,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + this.sessionTimeoutMinutes * 60 * 1000),
    };

    this.sessions.set(session.sessionId, session);

    // Return response
    const response: EnrollStartResponse = {
      sessionId: session.sessionId,
      attestationChallenge: attestationChallenge.toString('base64'),
      transactionKeys: transactionKeys.map(tk => ({
        keyId: tk.keyId,
        publicKey: tk.publicKey.toString('base64'),
      })),
      expiresAt: session.expiresAt.toISOString(),
    };

    return {
      statusCode: 200,
      body: response,
    };
  }

  /**
   * Get session by ID (for testing)
   */
  getSession(sessionId: string): EnrollmentSession | undefined {
    return this.sessions.get(sessionId);
  }

  /**
   * Get invite by code (for testing)
   */
  getInvite(code: string): InviteRecord | undefined {
    return this.invites.get(code);
  }

  /**
   * Mark invite as used (for testing)
   */
  useInvite(code: string): void {
    const invite = this.invites.get(code);
    if (invite) {
      invite.status = 'used';
    }
  }

  /**
   * Clear all data (for testing)
   */
  clear(): void {
    this.invites.clear();
    this.sessions.clear();
  }
}

// ============================================
// Tests
// ============================================

describe('Validate Invite (Enroll Start) Integration Tests', () => {
  let handler: MockValidateInviteHandler;
  let validInvite: InviteRecord;

  beforeEach(() => {
    handler = new MockValidateInviteHandler();

    // Create a valid invite (12 chars after VE-)
    validInvite = {
      code: 'VE-TESTCODE1234',
      vaultId: crypto.randomUUID(),
      memberId: crypto.randomUUID(),
      status: 'pending',
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
    };
    handler.registerInvite(validInvite);
  });

  describe('Successful Validation', () => {
    it('should return 200 for valid invite code', async () => {
      const result = await handler.handle({
        inviteCode: validInvite.code,
        deviceInfo: {
          platform: 'android',
          osVersion: '14',
          appVersion: '1.0.0',
        },
      });

      expect(result.statusCode).toBe(200);
    });

    it('should return session ID', async () => {
      const result = await handler.handle({
        inviteCode: validInvite.code,
        deviceInfo: {
          platform: 'android',
          osVersion: '14',
          appVersion: '1.0.0',
        },
      });

      const body = result.body as EnrollStartResponse;
      expect(body.sessionId).toBeDefined();
      expect(body.sessionId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    });

    it('should return 32-byte attestation challenge', async () => {
      const result = await handler.handle({
        inviteCode: validInvite.code,
        deviceInfo: {
          platform: 'ios',
          osVersion: '17.0',
          appVersion: '2.0.0',
        },
      });

      const body = result.body as EnrollStartResponse;
      expect(body.attestationChallenge).toBeDefined();

      const challenge = Buffer.from(body.attestationChallenge, 'base64');
      expect(challenge.length).toBe(32);
    });

    it('should return 10 transaction keys', async () => {
      const result = await handler.handle({
        inviteCode: validInvite.code,
        deviceInfo: {
          platform: 'android',
          osVersion: '14',
          appVersion: '1.0.0',
        },
      });

      const body = result.body as EnrollStartResponse;
      expect(body.transactionKeys).toHaveLength(10);

      for (const tk of body.transactionKeys) {
        expect(tk.keyId).toBeDefined();
        expect(tk.publicKey).toBeDefined();

        const publicKey = Buffer.from(tk.publicKey, 'base64');
        expect(publicKey.length).toBe(32); // X25519 public key
      }
    });

    it('should set 30-minute session expiry', async () => {
      const result = await handler.handle({
        inviteCode: validInvite.code,
        deviceInfo: {
          platform: 'android',
          osVersion: '14',
          appVersion: '1.0.0',
        },
      });

      const body = result.body as EnrollStartResponse;
      const expiresAt = new Date(body.expiresAt);
      const expectedExpiry = new Date(Date.now() + 30 * 60 * 1000);

      expect(Math.abs(expiresAt.getTime() - expectedExpiry.getTime())).toBeLessThan(1000);
    });

    it('should create enrollment session', async () => {
      const result = await handler.handle({
        inviteCode: validInvite.code,
        deviceInfo: {
          platform: 'android',
          osVersion: '14',
          appVersion: '1.0.0',
          deviceModel: 'Pixel 8',
        },
      });

      const body = result.body as EnrollStartResponse;
      const session = handler.getSession(body.sessionId);

      expect(session).toBeDefined();
      expect(session?.inviteCode).toBe(validInvite.code);
      expect(session?.vaultId).toBe(validInvite.vaultId);
      expect(session?.state).toBe('started');
      expect(session?.deviceInfo.platform).toBe('android');
      expect(session?.deviceInfo.deviceModel).toBe('Pixel 8');
    });
  });

  describe('Request Validation', () => {
    it('should reject empty invite code', async () => {
      const result = await handler.handle({
        inviteCode: '',
        deviceInfo: {
          platform: 'android',
          osVersion: '14',
          appVersion: '1.0.0',
        },
      });

      expect(result.statusCode).toBe(400);
      expect((result.body as { error: string }).error).toContain('required');
    });

    it('should reject malformed invite code', async () => {
      const result = await handler.handle({
        inviteCode: 'invalid-code',
        deviceInfo: {
          platform: 'android',
          osVersion: '14',
          appVersion: '1.0.0',
        },
      });

      expect(result.statusCode).toBe(400);
      expect((result.body as { error: string }).error).toContain('Invalid invite code format');
    });

    it('should reject missing device info', async () => {
      const result = await handler.handle({
        inviteCode: validInvite.code,
        deviceInfo: undefined as any,
      });

      expect(result.statusCode).toBe(400);
      expect((result.body as { error: string }).error).toContain('Device info');
    });

    it('should reject invalid platform', async () => {
      const result = await handler.handle({
        inviteCode: validInvite.code,
        deviceInfo: {
          platform: 'windows' as any,
          osVersion: '11',
          appVersion: '1.0.0',
        },
      });

      expect(result.statusCode).toBe(400);
      expect((result.body as { error: string }).error).toContain('Invalid platform');
    });

    it('should reject missing OS version', async () => {
      const result = await handler.handle({
        inviteCode: validInvite.code,
        deviceInfo: {
          platform: 'android',
          osVersion: '',
          appVersion: '1.0.0',
        },
      });

      expect(result.statusCode).toBe(400);
      expect((result.body as { error: string }).error).toContain('OS version');
    });

    it('should reject missing app version', async () => {
      const result = await handler.handle({
        inviteCode: validInvite.code,
        deviceInfo: {
          platform: 'ios',
          osVersion: '17.0',
          appVersion: '',
        },
      });

      expect(result.statusCode).toBe(400);
      expect((result.body as { error: string }).error).toContain('App version');
    });
  });

  describe('Invite Status Handling', () => {
    it('should reject non-existent invite code', async () => {
      const result = await handler.handle({
        inviteCode: 'VE-DOESNOTEXIST',
        deviceInfo: {
          platform: 'android',
          osVersion: '14',
          appVersion: '1.0.0',
        },
      });

      expect(result.statusCode).toBe(404);
      expect((result.body as { error: string }).error).toContain('not found');
    });

    it('should reject used invite code', async () => {
      handler.useInvite(validInvite.code);

      const result = await handler.handle({
        inviteCode: validInvite.code,
        deviceInfo: {
          platform: 'android',
          osVersion: '14',
          appVersion: '1.0.0',
        },
      });

      expect(result.statusCode).toBe(410);
      expect((result.body as { error: string }).error).toContain('already been used');
    });

    it('should reject revoked invite code', async () => {
      const revokedInvite: InviteRecord = {
        code: 'VE-REVOKEDCODE0',
        vaultId: crypto.randomUUID(),
        memberId: crypto.randomUUID(),
        status: 'revoked',
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
      };
      handler.registerInvite(revokedInvite);

      const result = await handler.handle({
        inviteCode: revokedInvite.code,
        deviceInfo: {
          platform: 'ios',
          osVersion: '17.0',
          appVersion: '1.0.0',
        },
      });

      expect(result.statusCode).toBe(410);
      expect((result.body as { error: string }).error).toContain('revoked');
    });

    it('should reject expired invite code', async () => {
      const expiredInvite: InviteRecord = {
        code: 'VE-EXPIREDCODE0',
        vaultId: crypto.randomUUID(),
        memberId: crypto.randomUUID(),
        status: 'pending',
        createdAt: new Date(Date.now() - 48 * 60 * 60 * 1000).toISOString(),
        expiresAt: new Date(Date.now() - 1000).toISOString(),
      };
      handler.registerInvite(expiredInvite);

      const result = await handler.handle({
        inviteCode: expiredInvite.code,
        deviceInfo: {
          platform: 'android',
          osVersion: '14',
          appVersion: '1.0.0',
        },
      });

      expect(result.statusCode).toBe(410);
      expect((result.body as { error: string }).error).toContain('expired');
    });

    it('should update status to expired when checking expired invite', async () => {
      const expiredInvite: InviteRecord = {
        code: 'VE-TOBEEXPIRED0',
        vaultId: crypto.randomUUID(),
        memberId: crypto.randomUUID(),
        status: 'pending',
        createdAt: new Date(Date.now() - 48 * 60 * 60 * 1000).toISOString(),
        expiresAt: new Date(Date.now() - 1000).toISOString(),
      };
      handler.registerInvite(expiredInvite);

      await handler.handle({
        inviteCode: expiredInvite.code,
        deviceInfo: {
          platform: 'android',
          osVersion: '14',
          appVersion: '1.0.0',
        },
      });

      const updatedInvite = handler.getInvite(expiredInvite.code);
      expect(updatedInvite?.status).toBe('expired');
    });
  });

  describe('Session Handling', () => {
    it('should reject if session already in progress', async () => {
      // First request
      const result1 = await handler.handle({
        inviteCode: validInvite.code,
        deviceInfo: {
          platform: 'android',
          osVersion: '14',
          appVersion: '1.0.0',
        },
      });
      expect(result1.statusCode).toBe(200);

      // Second request with same invite
      const result2 = await handler.handle({
        inviteCode: validInvite.code,
        deviceInfo: {
          platform: 'ios',
          osVersion: '17.0',
          appVersion: '1.0.0',
        },
      });

      expect(result2.statusCode).toBe(409);
      expect((result2.body as { error: string }).error).toContain('already in progress');
    });

    it('should generate unique attestation challenges', async () => {
      const invite2: InviteRecord = {
        code: 'VE-SECONDINVIT0',
        vaultId: crypto.randomUUID(),
        memberId: crypto.randomUUID(),
        status: 'pending',
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
      };
      handler.registerInvite(invite2);

      const result1 = await handler.handle({
        inviteCode: validInvite.code,
        deviceInfo: { platform: 'android', osVersion: '14', appVersion: '1.0.0' },
      });

      const result2 = await handler.handle({
        inviteCode: invite2.code,
        deviceInfo: { platform: 'ios', osVersion: '17.0', appVersion: '1.0.0' },
      });

      const body1 = result1.body as EnrollStartResponse;
      const body2 = result2.body as EnrollStartResponse;

      expect(body1.attestationChallenge).not.toBe(body2.attestationChallenge);
    });

    it('should generate unique transaction key IDs', async () => {
      const result = await handler.handle({
        inviteCode: validInvite.code,
        deviceInfo: { platform: 'android', osVersion: '14', appVersion: '1.0.0' },
      });

      const body = result.body as EnrollStartResponse;
      const keyIds = body.transactionKeys.map(tk => tk.keyId);
      const uniqueKeyIds = new Set(keyIds);

      expect(uniqueKeyIds.size).toBe(10);
    });
  });

  describe('Platform-Specific Handling', () => {
    it('should accept Android device', async () => {
      const result = await handler.handle({
        inviteCode: validInvite.code,
        deviceInfo: {
          platform: 'android',
          osVersion: '14',
          appVersion: '1.0.0',
          deviceModel: 'Pixel 8 Pro',
        },
      });

      expect(result.statusCode).toBe(200);
      const body = result.body as EnrollStartResponse;
      const session = handler.getSession(body.sessionId);
      expect(session?.deviceInfo.platform).toBe('android');
    });

    it('should accept iOS device', async () => {
      const result = await handler.handle({
        inviteCode: validInvite.code,
        deviceInfo: {
          platform: 'ios',
          osVersion: '17.2',
          appVersion: '2.1.0',
          deviceModel: 'iPhone 15 Pro',
        },
      });

      expect(result.statusCode).toBe(200);
      const body = result.body as EnrollStartResponse;
      const session = handler.getSession(body.sessionId);
      expect(session?.deviceInfo.platform).toBe('ios');
    });
  });

  describe('Security', () => {
    it('should not expose vault ID in response', async () => {
      const result = await handler.handle({
        inviteCode: validInvite.code,
        deviceInfo: { platform: 'android', osVersion: '14', appVersion: '1.0.0' },
      });

      const body = result.body as EnrollStartResponse;
      expect(body).not.toHaveProperty('vaultId');
    });

    it('should not expose member ID in response', async () => {
      const result = await handler.handle({
        inviteCode: validInvite.code,
        deviceInfo: { platform: 'android', osVersion: '14', appVersion: '1.0.0' },
      });

      const body = result.body as EnrollStartResponse;
      expect(body).not.toHaveProperty('memberId');
    });

    it('should store private keys in session for later decryption', async () => {
      const result = await handler.handle({
        inviteCode: validInvite.code,
        deviceInfo: { platform: 'android', osVersion: '14', appVersion: '1.0.0' },
      });

      const body = result.body as EnrollStartResponse;
      const session = handler.getSession(body.sessionId);

      expect(session?.transactionKeys).toHaveLength(10);
      for (const tk of session!.transactionKeys) {
        expect(tk.privateKey).toBeDefined();
        expect(tk.privateKey.length).toBe(32); // X25519 private key
      }
    });

    it('should not expose private keys in response', async () => {
      const result = await handler.handle({
        inviteCode: validInvite.code,
        deviceInfo: { platform: 'android', osVersion: '14', appVersion: '1.0.0' },
      });

      const body = result.body as EnrollStartResponse;
      for (const tk of body.transactionKeys) {
        expect(tk).not.toHaveProperty('privateKey');
      }
    });
  });
});
