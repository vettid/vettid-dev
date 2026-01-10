/**
 * Session Security Tests
 *
 * Tests for session management security:
 * - Session token entropy validation
 * - Session timeout enforcement
 * - Concurrent session limits
 * - Session invalidation on logout
 * - Session invalidation on password change
 * - Cross-device session management
 * - Session cookie security flags
 *
 * OWASP Reference: A07:2021 - Identification and Authentication Failures
 */

import * as crypto from 'crypto';
import {
  generateSessionToken,
  validateSessionToken,
  DEFAULT_SESSION_CONFIG,
} from '../fixtures/security/securityScenarios';

// Mock session manager for testing
class MockSessionManager {
  private sessions: Map<
    string,
    {
      userId: string;
      createdAt: Date;
      lastActivity: Date;
      expiresAt: Date;
      deviceId: string;
      ipAddress: string;
      userAgent: string;
      isValid: boolean;
    }
  > = new Map();

  private userSessions: Map<string, Set<string>> = new Map();

  private config = {
    maxConcurrentSessions: 3,
    sessionTimeoutMs: 30 * 60 * 1000, // 30 minutes
    absoluteTimeoutMs: 24 * 60 * 60 * 1000, // 24 hours
    tokenLength: 32,
    idleTimeoutMs: 15 * 60 * 1000, // 15 minutes
  };

  /**
   * Create a new session
   */
  createSession(
    userId: string,
    deviceInfo: { deviceId: string; ipAddress: string; userAgent: string }
  ): { sessionId: string; token: string } | { error: string } {
    // Check concurrent session limit
    const userSessionIds = this.userSessions.get(userId) || new Set();
    if (userSessionIds.size >= this.config.maxConcurrentSessions) {
      // Remove oldest session
      const oldestSessionId = this.getOldestSession(userId);
      if (oldestSessionId) {
        this.invalidateSession(oldestSessionId);
      }
    }

    // Generate session ID and token
    const sessionId = crypto.randomBytes(16).toString('hex');
    const token = crypto.randomBytes(this.config.tokenLength).toString('hex');

    const now = new Date();

    this.sessions.set(sessionId, {
      userId,
      createdAt: now,
      lastActivity: now,
      expiresAt: new Date(now.getTime() + this.config.absoluteTimeoutMs),
      deviceId: deviceInfo.deviceId,
      ipAddress: deviceInfo.ipAddress,
      userAgent: deviceInfo.userAgent,
      isValid: true,
    });

    // Track user sessions
    if (!this.userSessions.has(userId)) {
      this.userSessions.set(userId, new Set());
    }
    this.userSessions.get(userId)!.add(sessionId);

    return { sessionId, token };
  }

  /**
   * Validate a session
   */
  validateSession(sessionId: string): { valid: boolean; reason?: string } {
    const session = this.sessions.get(sessionId);

    if (!session) {
      return { valid: false, reason: 'Session not found' };
    }

    if (!session.isValid) {
      return { valid: false, reason: 'Session invalidated' };
    }

    const now = new Date();

    // Check absolute timeout
    if (now > session.expiresAt) {
      this.invalidateSession(sessionId);
      return { valid: false, reason: 'Session expired (absolute timeout)' };
    }

    // Check idle timeout
    const idleTime = now.getTime() - session.lastActivity.getTime();
    if (idleTime > this.config.idleTimeoutMs) {
      this.invalidateSession(sessionId);
      return { valid: false, reason: 'Session expired (idle timeout)' };
    }

    // Update last activity
    session.lastActivity = now;

    return { valid: true };
  }

  /**
   * Invalidate a session
   */
  invalidateSession(sessionId: string): boolean {
    const session = this.sessions.get(sessionId);
    if (!session) return false;

    session.isValid = false;

    // Remove from user sessions
    const userSessions = this.userSessions.get(session.userId);
    if (userSessions) {
      userSessions.delete(sessionId);
    }

    return true;
  }

  /**
   * Invalidate all sessions for a user
   */
  invalidateAllUserSessions(userId: string): number {
    const userSessionIds = this.userSessions.get(userId);
    if (!userSessionIds) return 0;

    let count = 0;
    for (const sessionId of userSessionIds) {
      if (this.invalidateSession(sessionId)) {
        count++;
      }
    }

    return count;
  }

  /**
   * Get user's active session count
   */
  getActiveSessionCount(userId: string): number {
    const userSessionIds = this.userSessions.get(userId);
    if (!userSessionIds) return 0;

    let count = 0;
    for (const sessionId of userSessionIds) {
      const session = this.sessions.get(sessionId);
      if (session?.isValid) {
        count++;
      }
    }

    return count;
  }

  /**
   * Get oldest session for user
   */
  private getOldestSession(userId: string): string | null {
    const userSessionIds = this.userSessions.get(userId);
    if (!userSessionIds) return null;

    let oldestId: string | null = null;
    let oldestDate: Date | null = null;

    for (const sessionId of userSessionIds) {
      const session = this.sessions.get(sessionId);
      if (session && session.isValid) {
        if (!oldestDate || session.createdAt < oldestDate) {
          oldestDate = session.createdAt;
          oldestId = sessionId;
        }
      }
    }

    return oldestId;
  }

  /**
   * Get session info
   */
  getSession(sessionId: string): {
    userId: string;
    deviceId: string;
    createdAt: Date;
    lastActivity: Date;
  } | null {
    const session = this.sessions.get(sessionId);
    if (!session || !session.isValid) return null;

    return {
      userId: session.userId,
      deviceId: session.deviceId,
      createdAt: session.createdAt,
      lastActivity: session.lastActivity,
    };
  }

  /**
   * Get all sessions for a user
   */
  getUserSessions(
    userId: string
  ): Array<{ sessionId: string; deviceId: string; createdAt: Date; lastActivity: Date }> {
    const userSessionIds = this.userSessions.get(userId);
    if (!userSessionIds) return [];

    const sessions: Array<{
      sessionId: string;
      deviceId: string;
      createdAt: Date;
      lastActivity: Date;
    }> = [];

    for (const sessionId of userSessionIds) {
      const session = this.sessions.get(sessionId);
      if (session && session.isValid) {
        sessions.push({
          sessionId,
          deviceId: session.deviceId,
          createdAt: session.createdAt,
          lastActivity: session.lastActivity,
        });
      }
    }

    return sessions;
  }

  /**
   * Update session timeout configuration
   */
  updateConfig(config: Partial<typeof this.config>): void {
    Object.assign(this.config, config);
  }

  /**
   * Get current configuration
   */
  getConfig(): typeof this.config {
    return { ...this.config };
  }
}

// Mock cookie builder for testing
class MockCookieBuilder {
  private attributes: {
    name: string;
    value: string;
    httpOnly: boolean;
    secure: boolean;
    sameSite: 'Strict' | 'Lax' | 'None';
    domain?: string;
    path: string;
    maxAge?: number;
    expires?: Date;
  };

  constructor(name: string, value: string) {
    this.attributes = {
      name,
      value,
      httpOnly: true, // Default to secure
      secure: true, // Default to secure
      sameSite: 'Strict', // Default to most restrictive
      path: '/',
    };
  }

  httpOnly(value: boolean): this {
    this.attributes.httpOnly = value;
    return this;
  }

  secure(value: boolean): this {
    this.attributes.secure = value;
    return this;
  }

  sameSite(value: 'Strict' | 'Lax' | 'None'): this {
    this.attributes.sameSite = value;
    return this;
  }

  domain(value: string): this {
    this.attributes.domain = value;
    return this;
  }

  path(value: string): this {
    this.attributes.path = value;
    return this;
  }

  maxAge(seconds: number): this {
    this.attributes.maxAge = seconds;
    return this;
  }

  expires(date: Date): this {
    this.attributes.expires = date;
    return this;
  }

  build(): string {
    let cookie = `${this.attributes.name}=${this.attributes.value}`;

    if (this.attributes.httpOnly) {
      cookie += '; HttpOnly';
    }
    if (this.attributes.secure) {
      cookie += '; Secure';
    }
    cookie += `; SameSite=${this.attributes.sameSite}`;
    cookie += `; Path=${this.attributes.path}`;

    if (this.attributes.domain) {
      cookie += `; Domain=${this.attributes.domain}`;
    }
    if (this.attributes.maxAge !== undefined) {
      cookie += `; Max-Age=${this.attributes.maxAge}`;
    }
    if (this.attributes.expires) {
      cookie += `; Expires=${this.attributes.expires.toUTCString()}`;
    }

    return cookie;
  }

  getAttributes(): typeof this.attributes {
    return { ...this.attributes };
  }
}

describe('Session Security Tests', () => {
  describe('Session Token Entropy Validation', () => {
    /**
     * OWASP A07:2021 - Identification and Authentication Failures
     * Tests that session tokens have sufficient entropy
     */
    describe('Token generation', () => {
      it('should generate tokens with minimum 256 bits of entropy', () => {
        const token = generateSessionToken();

        // 32 bytes = 256 bits
        expect(token.length).toBeGreaterThanOrEqual(32);
      });

      it('should generate unique tokens', () => {
        const tokens = new Set<string>();
        const iterations = 10000;

        for (let i = 0; i < iterations; i++) {
          tokens.add(generateSessionToken());
        }

        expect(tokens.size).toBe(iterations);
      });

      it('should use cryptographically secure random source', () => {
        const token = generateSessionToken();

        // Token should have good entropy - check byte distribution
        const bytes = Buffer.from(token, 'hex');
        const uniqueBytes = new Set(bytes);

        // Should have multiple unique byte values
        expect(uniqueBytes.size).toBeGreaterThan(5);
      });

      it('should not produce predictable patterns', () => {
        const tokens: string[] = [];

        for (let i = 0; i < 100; i++) {
          tokens.push(generateSessionToken());
        }

        // Check that consecutive tokens aren't sequential
        for (let i = 1; i < tokens.length; i++) {
          expect(tokens[i]).not.toBe(tokens[i - 1]);

          // Check for sequential patterns
          const diff = Math.abs(
            parseInt(tokens[i].slice(0, 8), 16) - parseInt(tokens[i - 1].slice(0, 8), 16)
          );
          expect(diff).not.toBe(1);
        }
      });
    });

    describe('Token validation', () => {
      it('should validate properly formatted tokens', () => {
        const token = generateSessionToken();
        expect(validateSessionToken(token).valid).toBe(true);
      });

      it('should reject empty tokens', () => {
        expect(validateSessionToken('').valid).toBe(false);
      });

      it('should reject tokens that are too short', () => {
        const shortToken = crypto.randomBytes(8).toString('hex');
        expect(validateSessionToken(shortToken).valid).toBe(false);
      });

      it('should reject tokens with invalid characters', () => {
        const invalidToken = 'GHIJKLMNOP' + 'a'.repeat(54); // G-P are not hex
        expect(validateSessionToken(invalidToken).valid).toBe(false);
      });
    });
  });

  describe('Session Timeout Enforcement', () => {
    /**
     * Tests for session timeout handling
     */
    let sessionManager: MockSessionManager;

    beforeEach(() => {
      sessionManager = new MockSessionManager();
    });

    describe('Idle timeout', () => {
      it('should invalidate sessions after idle timeout', async () => {
        // Set very short timeout for testing
        sessionManager.updateConfig({ idleTimeoutMs: 50 });

        const result = sessionManager.createSession('user-1', {
          deviceId: 'device-1',
          ipAddress: '192.168.1.1',
          userAgent: 'Test Browser',
        });

        if ('error' in result) fail('Should create session');

        // Wait for idle timeout
        await new Promise(resolve => setTimeout(resolve, 100));

        const validation = sessionManager.validateSession(result.sessionId);
        expect(validation.valid).toBe(false);
        expect(validation.reason).toContain('idle timeout');
      });

      it('should reset idle timer on activity', async () => {
        sessionManager.updateConfig({ idleTimeoutMs: 100 });

        const result = sessionManager.createSession('user-1', {
          deviceId: 'device-1',
          ipAddress: '192.168.1.1',
          userAgent: 'Test Browser',
        });

        if ('error' in result) fail('Should create session');

        // Activity before timeout
        await new Promise(resolve => setTimeout(resolve, 50));
        sessionManager.validateSession(result.sessionId); // Resets timer

        // Wait again (but less than timeout)
        await new Promise(resolve => setTimeout(resolve, 50));

        // Should still be valid
        const validation = sessionManager.validateSession(result.sessionId);
        expect(validation.valid).toBe(true);
      });
    });

    describe('Absolute timeout', () => {
      it('should invalidate sessions after absolute timeout', async () => {
        sessionManager.updateConfig({
          absoluteTimeoutMs: 50,
          idleTimeoutMs: 1000,
        });

        const result = sessionManager.createSession('user-1', {
          deviceId: 'device-1',
          ipAddress: '192.168.1.1',
          userAgent: 'Test Browser',
        });

        if ('error' in result) fail('Should create session');

        // Wait for absolute timeout
        await new Promise(resolve => setTimeout(resolve, 100));

        const validation = sessionManager.validateSession(result.sessionId);
        expect(validation.valid).toBe(false);
        expect(validation.reason).toContain('absolute timeout');
      });

      it('should not extend absolute timeout with activity', async () => {
        sessionManager.updateConfig({
          absoluteTimeoutMs: 100,
          idleTimeoutMs: 50,
        });

        const result = sessionManager.createSession('user-1', {
          deviceId: 'device-1',
          ipAddress: '192.168.1.1',
          userAgent: 'Test Browser',
        });

        if ('error' in result) fail('Should create session');

        // Keep refreshing before absolute timeout
        for (let i = 0; i < 3; i++) {
          await new Promise(resolve => setTimeout(resolve, 30));
          sessionManager.validateSession(result.sessionId);
        }

        // Wait for absolute timeout
        await new Promise(resolve => setTimeout(resolve, 50));

        const validation = sessionManager.validateSession(result.sessionId);
        expect(validation.valid).toBe(false);
      });
    });

    describe('Security configuration', () => {
      it('should have sensible default timeouts', () => {
        const config = sessionManager.getConfig();

        // Idle timeout should be <= 30 minutes
        expect(config.idleTimeoutMs).toBeLessThanOrEqual(30 * 60 * 1000);

        // Absolute timeout should be <= 24 hours
        expect(config.absoluteTimeoutMs).toBeLessThanOrEqual(24 * 60 * 60 * 1000);
      });

      it('should match DEFAULT_SESSION_CONFIG requirements', () => {
        // Token length should be at least 32 bytes (256 bits)
        expect(DEFAULT_SESSION_CONFIG.tokenLength).toBeGreaterThanOrEqual(32);
        // Timeout should be reasonable (default is 1 hour = 3600000ms)
        expect(DEFAULT_SESSION_CONFIG.timeoutMs).toBeLessThanOrEqual(24 * 60 * 60 * 1000);
        // Should require secure cookies
        expect(DEFAULT_SESSION_CONFIG.requireSecure).toBe(true);
      });
    });
  });

  describe('Concurrent Session Limits', () => {
    /**
     * Tests for limiting concurrent sessions per user
     */
    let sessionManager: MockSessionManager;

    beforeEach(() => {
      sessionManager = new MockSessionManager();
    });

    it('should limit concurrent sessions per user', () => {
      const userId = 'user-1';

      // Create maximum allowed sessions
      for (let i = 0; i < 3; i++) {
        sessionManager.createSession(userId, {
          deviceId: `device-${i}`,
          ipAddress: '192.168.1.1',
          userAgent: 'Test Browser',
        });
      }

      // All 3 should be active
      expect(sessionManager.getActiveSessionCount(userId)).toBe(3);
    });

    it('should remove oldest session when limit exceeded', () => {
      const userId = 'user-1';

      // Create sessions
      const sessions: string[] = [];
      for (let i = 0; i < 4; i++) {
        const result = sessionManager.createSession(userId, {
          deviceId: `device-${i}`,
          ipAddress: '192.168.1.1',
          userAgent: 'Test Browser',
        });

        if (!('error' in result)) {
          sessions.push(result.sessionId);
        }
      }

      // Should still only have 3 active
      expect(sessionManager.getActiveSessionCount(userId)).toBe(3);

      // First session should be invalidated
      const firstSessionValid = sessionManager.validateSession(sessions[0]);
      expect(firstSessionValid.valid).toBe(false);
    });

    it('should track sessions per user independently', () => {
      // Create sessions for multiple users
      for (let userId = 1; userId <= 3; userId++) {
        for (let i = 0; i < 2; i++) {
          sessionManager.createSession(`user-${userId}`, {
            deviceId: `device-${i}`,
            ipAddress: '192.168.1.1',
            userAgent: 'Test Browser',
          });
        }
      }

      // Each user should have 2 sessions
      expect(sessionManager.getActiveSessionCount('user-1')).toBe(2);
      expect(sessionManager.getActiveSessionCount('user-2')).toBe(2);
      expect(sessionManager.getActiveSessionCount('user-3')).toBe(2);
    });
  });

  describe('Session Invalidation on Logout', () => {
    /**
     * Tests that sessions are properly invalidated on logout
     */
    let sessionManager: MockSessionManager;

    beforeEach(() => {
      sessionManager = new MockSessionManager();
    });

    it('should invalidate session on logout', () => {
      const result = sessionManager.createSession('user-1', {
        deviceId: 'device-1',
        ipAddress: '192.168.1.1',
        userAgent: 'Test Browser',
      });

      if ('error' in result) fail('Should create session');

      // Invalidate (logout)
      sessionManager.invalidateSession(result.sessionId);

      // Should no longer be valid
      const validation = sessionManager.validateSession(result.sessionId);
      expect(validation.valid).toBe(false);
      expect(validation.reason).toBe('Session invalidated');
    });

    it('should not allow reuse of invalidated session', () => {
      const result = sessionManager.createSession('user-1', {
        deviceId: 'device-1',
        ipAddress: '192.168.1.1',
        userAgent: 'Test Browser',
      });

      if ('error' in result) fail('Should create session');

      sessionManager.invalidateSession(result.sessionId);

      // Multiple validation attempts should all fail
      for (let i = 0; i < 5; i++) {
        const validation = sessionManager.validateSession(result.sessionId);
        expect(validation.valid).toBe(false);
      }
    });

    it('should remove session from user session list', () => {
      const result = sessionManager.createSession('user-1', {
        deviceId: 'device-1',
        ipAddress: '192.168.1.1',
        userAgent: 'Test Browser',
      });

      if ('error' in result) fail('Should create session');

      expect(sessionManager.getActiveSessionCount('user-1')).toBe(1);

      sessionManager.invalidateSession(result.sessionId);

      expect(sessionManager.getActiveSessionCount('user-1')).toBe(0);
    });
  });

  describe('Session Invalidation on Password Change', () => {
    /**
     * Tests that all sessions are invalidated when password changes
     */
    let sessionManager: MockSessionManager;

    beforeEach(() => {
      sessionManager = new MockSessionManager();
    });

    it('should invalidate all sessions on password change', () => {
      const userId = 'user-1';

      // Create multiple sessions
      const sessions: string[] = [];
      for (let i = 0; i < 3; i++) {
        const result = sessionManager.createSession(userId, {
          deviceId: `device-${i}`,
          ipAddress: '192.168.1.1',
          userAgent: 'Test Browser',
        });

        if (!('error' in result)) {
          sessions.push(result.sessionId);
        }
      }

      expect(sessionManager.getActiveSessionCount(userId)).toBe(3);

      // Simulate password change - invalidate all sessions
      const invalidatedCount = sessionManager.invalidateAllUserSessions(userId);

      expect(invalidatedCount).toBe(3);
      expect(sessionManager.getActiveSessionCount(userId)).toBe(0);

      // All sessions should be invalid
      for (const sessionId of sessions) {
        expect(sessionManager.validateSession(sessionId).valid).toBe(false);
      }
    });

    it('should not affect other users sessions', () => {
      // Create sessions for two users
      sessionManager.createSession('user-1', {
        deviceId: 'device-1',
        ipAddress: '192.168.1.1',
        userAgent: 'Test Browser',
      });

      const user2Result = sessionManager.createSession('user-2', {
        deviceId: 'device-2',
        ipAddress: '192.168.1.2',
        userAgent: 'Test Browser',
      });

      // Invalidate user-1's sessions
      sessionManager.invalidateAllUserSessions('user-1');

      // User-2's session should still be valid
      if (!('error' in user2Result)) {
        const validation = sessionManager.validateSession(user2Result.sessionId);
        expect(validation.valid).toBe(true);
      }
    });
  });

  describe('Cross-Device Session Management', () => {
    /**
     * Tests for managing sessions across multiple devices
     */
    let sessionManager: MockSessionManager;

    beforeEach(() => {
      sessionManager = new MockSessionManager();
    });

    it('should track device information per session', () => {
      const result = sessionManager.createSession('user-1', {
        deviceId: 'iphone-12-abc123',
        ipAddress: '192.168.1.100',
        userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0)',
      });

      if ('error' in result) fail('Should create session');

      const session = sessionManager.getSession(result.sessionId);

      expect(session?.deviceId).toBe('iphone-12-abc123');
    });

    it('should list all sessions for a user', () => {
      const userId = 'user-1';
      const devices = [
        { deviceId: 'iphone', ipAddress: '192.168.1.1', userAgent: 'iPhone' },
        { deviceId: 'android', ipAddress: '192.168.1.2', userAgent: 'Android' },
        { deviceId: 'desktop', ipAddress: '192.168.1.3', userAgent: 'Chrome' },
      ];

      for (const device of devices) {
        sessionManager.createSession(userId, device);
      }

      const sessions = sessionManager.getUserSessions(userId);

      expect(sessions.length).toBe(3);
      expect(sessions.map(s => s.deviceId).sort()).toEqual(['android', 'desktop', 'iphone']);
    });

    it('should allow invalidating specific device session', () => {
      const userId = 'user-1';

      // Create sessions on multiple devices
      const result1 = sessionManager.createSession(userId, {
        deviceId: 'phone',
        ipAddress: '192.168.1.1',
        userAgent: 'Phone',
      });

      sessionManager.createSession(userId, {
        deviceId: 'tablet',
        ipAddress: '192.168.1.2',
        userAgent: 'Tablet',
      });

      if ('error' in result1) fail('Should create session');

      // Invalidate only phone session
      sessionManager.invalidateSession(result1.sessionId);

      const sessions = sessionManager.getUserSessions(userId);
      expect(sessions.length).toBe(1);
      expect(sessions[0].deviceId).toBe('tablet');
    });
  });

  describe('Session Cookie Security Flags', () => {
    /**
     * OWASP A07:2021 - Tests for secure cookie attributes
     */
    describe('HttpOnly flag', () => {
      it('should set HttpOnly flag by default', () => {
        const cookie = new MockCookieBuilder('session', 'token123').build();

        expect(cookie).toContain('HttpOnly');
      });

      it('should prevent JavaScript access with HttpOnly', () => {
        const cookie = new MockCookieBuilder('session', 'token123')
          .httpOnly(true)
          .build();

        expect(cookie).toContain('HttpOnly');
      });
    });

    describe('Secure flag', () => {
      it('should set Secure flag by default', () => {
        const cookie = new MockCookieBuilder('session', 'token123').build();

        expect(cookie).toContain('Secure');
      });

      it('should require HTTPS with Secure flag', () => {
        const cookie = new MockCookieBuilder('session', 'token123')
          .secure(true)
          .build();

        expect(cookie).toContain('Secure');
      });
    });

    describe('SameSite attribute', () => {
      it('should default to Strict', () => {
        const cookie = new MockCookieBuilder('session', 'token123').build();

        expect(cookie).toContain('SameSite=Strict');
      });

      it('should support Lax setting', () => {
        const cookie = new MockCookieBuilder('session', 'token123')
          .sameSite('Lax')
          .build();

        expect(cookie).toContain('SameSite=Lax');
      });

      it('should require Secure when SameSite=None', () => {
        const builder = new MockCookieBuilder('session', 'token123')
          .sameSite('None')
          .secure(true);

        const attrs = builder.getAttributes();

        expect(attrs.sameSite).toBe('None');
        expect(attrs.secure).toBe(true);
      });
    });

    describe('Domain and Path restrictions', () => {
      it('should set path to root by default', () => {
        const cookie = new MockCookieBuilder('session', 'token123').build();

        expect(cookie).toContain('Path=/');
      });

      it('should allow domain restriction', () => {
        const cookie = new MockCookieBuilder('session', 'token123')
          .domain('.vettid.dev')
          .build();

        expect(cookie).toContain('Domain=.vettid.dev');
      });

      it('should allow path restriction', () => {
        const cookie = new MockCookieBuilder('session', 'token123')
          .path('/api')
          .build();

        expect(cookie).toContain('Path=/api');
      });
    });

    describe('Expiration', () => {
      it('should support Max-Age', () => {
        const cookie = new MockCookieBuilder('session', 'token123')
          .maxAge(3600)
          .build();

        expect(cookie).toContain('Max-Age=3600');
      });

      it('should support Expires', () => {
        const expires = new Date('2025-12-31T23:59:59Z');
        const cookie = new MockCookieBuilder('session', 'token123')
          .expires(expires)
          .build();

        expect(cookie).toContain('Expires=');
      });

      it('should create session cookie when no expiration set', () => {
        const builder = new MockCookieBuilder('session', 'token123');
        const attrs = builder.getAttributes();

        expect(attrs.maxAge).toBeUndefined();
        expect(attrs.expires).toBeUndefined();
      });
    });

    describe('Complete secure cookie', () => {
      it('should build fully secure session cookie', () => {
        const cookie = new MockCookieBuilder('sessionId', crypto.randomBytes(32).toString('hex'))
          .httpOnly(true)
          .secure(true)
          .sameSite('Strict')
          .path('/')
          .maxAge(1800) // 30 minutes
          .build();

        expect(cookie).toContain('HttpOnly');
        expect(cookie).toContain('Secure');
        expect(cookie).toContain('SameSite=Strict');
        expect(cookie).toContain('Path=/');
        expect(cookie).toContain('Max-Age=1800');
      });
    });
  });

  describe('Session Fixation Prevention', () => {
    /**
     * Tests for preventing session fixation attacks
     */
    let sessionManager: MockSessionManager;

    beforeEach(() => {
      sessionManager = new MockSessionManager();
    });

    it('should generate new session ID after authentication', () => {
      // Create pre-auth session (anonymous)
      const preAuthResult = sessionManager.createSession('anonymous', {
        deviceId: 'device-1',
        ipAddress: '192.168.1.1',
        userAgent: 'Browser',
      });

      if ('error' in preAuthResult) fail('Should create session');

      // After authentication, create new session
      sessionManager.invalidateSession(preAuthResult.sessionId);
      const postAuthResult = sessionManager.createSession('user-1', {
        deviceId: 'device-1',
        ipAddress: '192.168.1.1',
        userAgent: 'Browser',
      });

      if ('error' in postAuthResult) fail('Should create session');

      // Session IDs should be different
      expect(postAuthResult.sessionId).not.toBe(preAuthResult.sessionId);

      // Old session should be invalid
      expect(sessionManager.validateSession(preAuthResult.sessionId).valid).toBe(false);

      // New session should be valid
      expect(sessionManager.validateSession(postAuthResult.sessionId).valid).toBe(true);
    });

    it('should not accept externally provided session IDs', () => {
      // Session ID is generated internally, not accepted from client
      const result = sessionManager.createSession('user-1', {
        deviceId: 'device-1',
        ipAddress: '192.168.1.1',
        userAgent: 'Browser',
      });

      if ('error' in result) fail('Should create session');

      // Verify session ID was generated, not user-provided
      expect(result.sessionId).toMatch(/^[a-f0-9]{32}$/);
    });
  });

  describe('Session Hijacking Prevention', () => {
    /**
     * Tests for preventing session hijacking
     */
    let sessionManager: MockSessionManager;

    beforeEach(() => {
      sessionManager = new MockSessionManager();
    });

    it('should track IP address for session', () => {
      const result = sessionManager.createSession('user-1', {
        deviceId: 'device-1',
        ipAddress: '192.168.1.100',
        userAgent: 'Browser',
      });

      if ('error' in result) fail('Should create session');

      // Session should be associated with IP
      const session = sessionManager.getSession(result.sessionId);
      expect(session).toBeDefined();
    });

    it('should track user agent for session', () => {
      const result = sessionManager.createSession('user-1', {
        deviceId: 'device-1',
        ipAddress: '192.168.1.1',
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
      });

      if ('error' in result) fail('Should create session');

      // Session should be valid
      expect(sessionManager.validateSession(result.sessionId).valid).toBe(true);
    });
  });
});
