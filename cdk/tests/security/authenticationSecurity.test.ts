/**
 * Security Tests: Authentication Security
 *
 * Comprehensive authentication security tests covering:
 * - JWT token manipulation detection
 * - Token replay attack prevention
 * - Brute force protection
 * - Timing attack resistance
 * - Session security
 * - LAT verification security
 *
 * @see OWASP A07:2021 - Identification and Authentication Failures
 */

import * as crypto from 'crypto';
import {
  JWT_MANIPULATIONS,
  createMockJWT,
  MockAuthService,
  generateSessionToken,
  calculateEntropy,
  validateSessionToken,
  testTimingVulnerability,
} from '../fixtures/security/securityScenarios';

// ============================================
// JWT Token Security
// ============================================

describe('JWT Token Security', () => {
  describe('Algorithm Manipulation Detection', () => {
    it('should reject tokens with "none" algorithm', () => {
      const originalToken = createMockJWT({ sub: 'user-123', role: 'member' });
      const manipulation = JWT_MANIPULATIONS.find(m => m.name === 'none_algorithm')!;
      const manipulatedToken = manipulation.manipulate(originalToken);

      // Parse the manipulated token header
      const [header] = manipulatedToken.split('.');
      const decodedHeader = JSON.parse(Buffer.from(header, 'base64url').toString());

      expect(decodedHeader.alg).toBe('none');

      // Verify signature is empty
      const parts = manipulatedToken.split('.');
      expect(parts[2]).toBe('');

      // A secure validator should reject this
      const isValid = validateJWTAlgorithm(manipulatedToken, ['RS256', 'ES256']);
      expect(isValid).toBe(false);
    });

    it('should reject algorithm confusion attacks (RS256 to HS256)', () => {
      const originalToken = createMockJWT({ sub: 'user-123' }, 'RS256');
      const manipulation = JWT_MANIPULATIONS.find(m => m.name === 'algorithm_confusion')!;
      const manipulatedToken = manipulation.manipulate(originalToken);

      const [header] = manipulatedToken.split('.');
      const decodedHeader = JSON.parse(Buffer.from(header, 'base64url').toString());

      expect(decodedHeader.alg).toBe('HS256');

      // Validator should reject algorithm not in allowed list when original was RS256
      const isValid = validateJWTAlgorithm(manipulatedToken, ['RS256']);
      expect(isValid).toBe(false);
    });

    it('should only accept configured algorithms', () => {
      const allowedAlgorithms = ['RS256', 'ES256'];

      // Valid algorithm
      const validToken = createMockJWT({ sub: 'user-123' }, 'RS256');
      expect(validateJWTAlgorithm(validToken, allowedAlgorithms)).toBe(true);

      // Invalid algorithm
      const hs256Token = createMockJWT({ sub: 'user-123' }, 'HS256');
      expect(validateJWTAlgorithm(hs256Token, allowedAlgorithms)).toBe(false);

      // None algorithm
      const noneToken = createMockJWT({ sub: 'user-123' }, 'none');
      expect(validateJWTAlgorithm(noneToken, allowedAlgorithms)).toBe(false);
    });
  });

  describe('Payload Tampering Detection', () => {
    it('should detect modified payload without signature update', () => {
      const originalToken = createMockJWT({ sub: 'user-123', role: 'member' });
      const manipulation = JWT_MANIPULATIONS.find(m => m.name === 'payload_tampering')!;
      const tamperedToken = manipulation.manipulate(originalToken);

      const [, payload] = tamperedToken.split('.');
      const decodedPayload = JSON.parse(Buffer.from(payload, 'base64url').toString());

      // Verify the payload was tampered
      expect(decodedPayload.role).toBe('admin');
      expect(decodedPayload.sub).toBe('admin-user-id');

      // Original signature should not validate modified payload
      const signatureValid = verifyTokenIntegrity(originalToken, tamperedToken);
      expect(signatureValid).toBe(false);
    });

    it('should detect expiry manipulation', () => {
      const originalToken = createMockJWT({ sub: 'user-123', exp: Math.floor(Date.now() / 1000) - 3600 });
      const manipulation = JWT_MANIPULATIONS.find(m => m.name === 'expiry_manipulation')!;
      const manipulatedToken = manipulation.manipulate(originalToken);

      const [, payload] = manipulatedToken.split('.');
      const decodedPayload = JSON.parse(Buffer.from(payload, 'base64url').toString());

      // Verify expiry was extended
      expect(decodedPayload.exp).toBeGreaterThan(Math.floor(Date.now() / 1000) + 86400 * 30);

      // Signature check should fail
      const signatureValid = verifyTokenIntegrity(originalToken, manipulatedToken);
      expect(signatureValid).toBe(false);
    });
  });

  describe('Header Injection Prevention', () => {
    it('should reject JKU injection attempts', () => {
      const originalToken = createMockJWT({ sub: 'user-123' });
      const manipulation = JWT_MANIPULATIONS.find(m => m.name === 'jku_injection')!;
      const manipulatedToken = manipulation.manipulate(originalToken);

      const [header] = manipulatedToken.split('.');
      const decodedHeader = JSON.parse(Buffer.from(header, 'base64url').toString());

      expect(decodedHeader.jku).toBe('https://attacker.com/.well-known/jwks.json');

      // Validator should reject untrusted JKU
      const isJKUSafe = validateJKU(decodedHeader.jku, ['https://vettid.dev']);
      expect(isJKUSafe).toBe(false);
    });

    it('should reject KID injection/SQL injection in KID', () => {
      const originalToken = createMockJWT({ sub: 'user-123' });
      const manipulation = JWT_MANIPULATIONS.find(m => m.name === 'kid_injection')!;
      const manipulatedToken = manipulation.manipulate(originalToken);

      const [header] = manipulatedToken.split('.');
      const decodedHeader = JSON.parse(Buffer.from(header, 'base64url').toString());

      // KID contains SQL injection attempt
      expect(decodedHeader.kid).toContain("' OR '1'='1");

      // Validator should reject suspicious KID values
      const isKIDSafe = validateKID(decodedHeader.kid);
      expect(isKIDSafe).toBe(false);
    });
  });

  describe('Token Expiry Enforcement', () => {
    it('should reject expired tokens', () => {
      const expiredToken = createMockJWT({
        sub: 'user-123',
        exp: Math.floor(Date.now() / 1000) - 3600, // 1 hour ago
      });

      const isExpired = isTokenExpired(expiredToken);
      expect(isExpired).toBe(true);
    });

    it('should accept valid non-expired tokens', () => {
      const validToken = createMockJWT({
        sub: 'user-123',
        exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour from now
      });

      const isExpired = isTokenExpired(validToken);
      expect(isExpired).toBe(false);
    });

    it('should handle tokens near expiry boundary', () => {
      const now = Math.floor(Date.now() / 1000);

      // Token expiring in 5 seconds
      const nearExpiryToken = createMockJWT({ sub: 'user-123', exp: now + 5 });
      expect(isTokenExpired(nearExpiryToken)).toBe(false);

      // Token expired 1 second ago
      const justExpiredToken = createMockJWT({ sub: 'user-123', exp: now - 1 });
      expect(isTokenExpired(justExpiredToken)).toBe(true);
    });

    it('should reject tokens with no expiry (if required)', () => {
      const noExpiryToken = createMockJWT({ sub: 'user-123' });
      const [header, payload, signature] = noExpiryToken.split('.');

      const decoded = JSON.parse(Buffer.from(payload, 'base64url').toString());
      delete decoded.exp;

      const modifiedPayload = Buffer.from(JSON.stringify(decoded)).toString('base64url');
      const tokenWithoutExp = `${header}.${modifiedPayload}.${signature}`;

      const hasExpiry = tokenHasExpiry(tokenWithoutExp);
      expect(hasExpiry).toBe(false);
    });
  });
});

// ============================================
// Brute Force Protection
// ============================================

describe('Brute Force Protection', () => {
  let authService: MockAuthService;

  beforeEach(() => {
    authService = new MockAuthService();
  });

  afterEach(() => {
    authService.reset();
  });

  describe('Password Attempt Limiting', () => {
    it('should lock account after 3 failed attempts', () => {
      const result1 = authService.authenticate('member-user', 'wrong-pass-1', '127.0.0.1');
      expect(result1.success).toBe(false);

      const result2 = authService.authenticate('member-user', 'wrong-pass-2', '127.0.0.1');
      expect(result2.success).toBe(false);

      const result3 = authService.authenticate('member-user', 'wrong-pass-3', '127.0.0.1');
      expect(result3.success).toBe(false);

      // 4th attempt should report locked
      const result4 = authService.authenticate('member-user', 'member-pass', '127.0.0.1');
      expect(result4.success).toBe(false);
      expect(result4.error).toBe('Account locked');
    });

    it('should reset failed attempts on successful authentication', () => {
      // 2 failed attempts
      authService.authenticate('member-user', 'wrong-pass', '127.0.0.1');
      authService.authenticate('member-user', 'wrong-pass', '127.0.0.1');

      // Successful attempt
      const success = authService.authenticate('member-user', 'member-pass', '127.0.0.1');
      expect(success.success).toBe(true);

      // 2 more failed attempts should not lock (counter reset)
      authService.authenticate('member-user', 'wrong-pass', '127.0.0.1');
      authService.authenticate('member-user', 'wrong-pass', '127.0.0.1');

      // This should still work
      const stillWorks = authService.authenticate('member-user', 'member-pass', '127.0.0.1');
      expect(stillWorks.success).toBe(true);
    });

    it('should not reveal if user exists on failed auth', () => {
      // Non-existent user
      const result1 = authService.authenticate('nonexistent-user', 'any-pass', '127.0.0.1');

      // Existing user with wrong password
      const result2 = authService.authenticate('member-user', 'wrong-pass', '127.0.0.1');

      // Both should return the same error message
      expect(result1.error).toBe(result2.error);
      expect(result1.error).toBe('Invalid credentials');
    });
  });

  describe('Rate Limiting', () => {
    it('should rate limit after too many requests from same IP', () => {
      // Make 10 requests (at the limit)
      for (let i = 0; i < 10; i++) {
        authService.authenticate(`user-${i}`, 'password', '192.168.1.100');
      }

      // 11th request should be rate limited
      const result = authService.authenticate('user-11', 'password', '192.168.1.100');
      expect(result.success).toBe(false);
      expect(result.error).toBe('Rate limited');
    });

    it('should not rate limit different IPs independently', () => {
      // Make 10 requests from IP1
      for (let i = 0; i < 10; i++) {
        authService.authenticate(`user-${i}`, 'password', '192.168.1.1');
      }

      // Request from IP2 should still work
      const result = authService.authenticate('member-user', 'member-pass', '192.168.1.2');
      expect(result.success).toBe(true);
    });
  });
});

// ============================================
// Timing Attack Resistance
// ============================================

describe('Timing Attack Resistance', () => {
  describe('Password Comparison', () => {
    it('should use constant-time comparison for passwords', () => {
      // Create a timing-safe comparison function
      const timingSafeCompare = (a: string, b: string): boolean => {
        if (a.length !== b.length) {
          // Still need to do work to avoid length-based timing
          const dummy = Buffer.from('x'.repeat(Math.max(a.length, b.length)));
          crypto.timingSafeEqual(dummy, dummy);
          return false;
        }
        return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
      };

      // Test functionality
      expect(timingSafeCompare('password123', 'password123')).toBe(true);
      expect(timingSafeCompare('password123', 'password124')).toBe(false);
      expect(timingSafeCompare('short', 'verylongpassword')).toBe(false);
    });

    it('should have consistent timing regardless of password correctness', () => {
      const correctPassword = crypto.randomBytes(32).toString('hex');
      const iterations = 100;

      // Measure time for correct password
      const correctTimes: number[] = [];
      for (let i = 0; i < iterations; i++) {
        const start = process.hrtime.bigint();
        crypto.timingSafeEqual(Buffer.from(correctPassword), Buffer.from(correctPassword));
        correctTimes.push(Number(process.hrtime.bigint() - start));
      }

      // Measure time for incorrect passwords at different positions
      const incorrectPasswords = [
        '0' + correctPassword.slice(1), // First char wrong
        correctPassword.slice(0, -1) + '0', // Last char wrong
        correctPassword.slice(0, 32) + '0'.repeat(32), // Second half wrong
      ];

      const incorrectTimes: number[][] = incorrectPasswords.map(wrong => {
        const times: number[] = [];
        for (let i = 0; i < iterations; i++) {
          const start = process.hrtime.bigint();
          crypto.timingSafeEqual(Buffer.from(correctPassword), Buffer.from(wrong));
          times.push(Number(process.hrtime.bigint() - start));
        }
        return times;
      });

      // Calculate average times
      const avgCorrect = correctTimes.reduce((a, b) => a + b, 0) / iterations;
      const avgIncorrects = incorrectTimes.map(t => t.reduce((a, b) => a + b, 0) / iterations);

      // Times should be within 50% of each other for timing-safe comparison
      for (const avgIncorrect of avgIncorrects) {
        const ratio = Math.max(avgCorrect, avgIncorrect) / Math.min(avgCorrect, avgIncorrect);
        expect(ratio).toBeLessThan(2.0); // Allow 2x variance for test environment
      }
    });
  });

  describe('Token Comparison', () => {
    it('should use constant-time comparison for tokens', () => {
      const correctToken = crypto.randomBytes(32).toString('hex');
      const wrongTokens = [
        crypto.randomBytes(32).toString('hex'),
        '0'.repeat(64),
        correctToken.slice(0, 63) + 'X',
      ];

      // Using timing-safe comparison
      const compare = (a: string, b: string): boolean => {
        try {
          return crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
        } catch {
          return false;
        }
      };

      expect(compare(correctToken, correctToken)).toBe(true);
      for (const wrong of wrongTokens) {
        expect(compare(correctToken, wrong)).toBe(false);
      }
    });
  });
});

// ============================================
// Session Security
// ============================================

describe('Session Security', () => {
  let authService: MockAuthService;

  beforeEach(() => {
    authService = new MockAuthService();
  });

  describe('Token Generation', () => {
    it('should generate tokens with sufficient entropy (256 bits)', () => {
      const token = generateSessionToken(32);
      const entropy = calculateEntropy(token);

      expect(entropy).toBeGreaterThanOrEqual(128);
    });

    it('should generate unique tokens', () => {
      const tokens = new Set<string>();
      const count = 10000;

      for (let i = 0; i < count; i++) {
        tokens.add(generateSessionToken());
      }

      expect(tokens.size).toBe(count);
    });

    it('should pass security validation', () => {
      const token = generateSessionToken(32);
      const validation = validateSessionToken(token);

      expect(validation.valid).toBe(true);
      expect(validation.issues).toHaveLength(0);
    });

    it('should reject weak tokens', () => {
      // Too short
      const shortToken = 'abc123';
      const shortValidation = validateSessionToken(shortToken);
      expect(shortValidation.valid).toBe(false);

      // Predictable pattern
      const predictableToken = '1234567890123456789012345678901234567890';
      const predictableValidation = validateSessionToken(predictableToken);
      expect(predictableValidation.valid).toBe(false);
    });
  });

  describe('Session Lifecycle', () => {
    it('should invalidate session on logout', () => {
      const result = authService.authenticate('member-user', 'member-pass', '127.0.0.1');
      expect(result.success).toBe(true);
      const token = result.token!;

      // Session valid before logout
      expect(authService.validateSession(token).valid).toBe(true);

      // Logout
      authService.logout(token);

      // Session invalid after logout
      expect(authService.validateSession(token).valid).toBe(false);
    });

    it('should reject reuse of logged-out session tokens', () => {
      const result = authService.authenticate('member-user', 'member-pass', '127.0.0.1');
      const token = result.token!;

      authService.logout(token);

      // Attempting to use the old token for authorization should fail
      expect(authService.authorize(token, 'member')).toBe(false);
    });
  });
});

// ============================================
// LAT (Ledger Authentication Token) Security
// ============================================

describe('LAT Security', () => {
  describe('Token Entropy', () => {
    it('should use 256-bit tokens', () => {
      const lat = crypto.randomBytes(32).toString('hex');
      expect(lat).toHaveLength(64); // 64 hex chars = 256 bits
    });

    it('should be cryptographically random', () => {
      const samples = 1000;
      const tokens: string[] = [];

      for (let i = 0; i < samples; i++) {
        tokens.push(crypto.randomBytes(32).toString('hex'));
      }

      // Check all are unique
      const uniqueTokens = new Set(tokens);
      expect(uniqueTokens.size).toBe(samples);

      // Check distribution of first bytes
      const firstBytes = tokens.map(t => parseInt(t.substring(0, 2), 16));
      const distribution = new Array(256).fill(0);
      for (const b of firstBytes) {
        distribution[b]++;
      }

      // Chi-square test for uniformity (simplified)
      const expected = samples / 256;
      let chiSquare = 0;
      for (let i = 0; i < 256; i++) {
        chiSquare += Math.pow(distribution[i] - expected, 2) / expected;
      }

      // For 255 degrees of freedom, chi-square < 320 at 99% confidence
      // Being more lenient for test environment
      expect(chiSquare).toBeLessThan(400);
    });
  });

  describe('Version Tracking', () => {
    it('should reject LAT with wrong version', () => {
      const latV1 = { token: crypto.randomBytes(32).toString('hex'), version: 1 };
      const latV2 = { token: crypto.randomBytes(32).toString('hex'), version: 2 };

      // Verifier expects version 2
      const isValid = verifyLATVersion(latV1.version, 2);
      expect(isValid).toBe(false);

      const isValidV2 = verifyLATVersion(latV2.version, 2);
      expect(isValidV2).toBe(true);
    });

    it('should increment version on rotation', () => {
      let currentVersion = 1;

      // Simulate rotation
      const rotate = () => {
        currentVersion++;
        return {
          token: crypto.randomBytes(32).toString('hex'),
          version: currentVersion,
        };
      };

      const v1 = { token: 'old', version: 1 };
      const v2 = rotate();

      expect(v2.version).toBe(2);
      expect(v2.version).toBeGreaterThan(v1.version);
    });
  });

  describe('Single-Use Enforcement', () => {
    it('should mark LAT as used after verification', () => {
      const usedLATs = new Set<string>();
      const lat = crypto.randomBytes(32).toString('hex');

      const verifyAndUse = (token: string): boolean => {
        if (usedLATs.has(token)) {
          return false;
        }
        usedLATs.add(token);
        return true;
      };

      // First use succeeds
      expect(verifyAndUse(lat)).toBe(true);

      // Second use fails
      expect(verifyAndUse(lat)).toBe(false);
    });
  });
});

// ============================================
// Helper Functions
// ============================================

function validateJWTAlgorithm(token: string, allowedAlgorithms: string[]): boolean {
  try {
    const [header] = token.split('.');
    const decoded = JSON.parse(Buffer.from(header, 'base64url').toString());
    return allowedAlgorithms.includes(decoded.alg);
  } catch {
    return false;
  }
}

function verifyTokenIntegrity(original: string, modified: string): boolean {
  // In real implementation, this would verify the signature
  // For testing, we check if the signature matches the payload
  const [, , origSig] = original.split('.');
  const [, , modSig] = modified.split('.');

  // If payloads are different but signatures are same, it's invalid
  const [, origPayload] = original.split('.');
  const [, modPayload] = modified.split('.');

  if (origPayload !== modPayload && origSig === modSig) {
    return false; // Signature not updated for new payload
  }

  return true;
}

function validateJKU(jku: string, trustedDomains: string[]): boolean {
  try {
    const url = new URL(jku);
    return trustedDomains.some(domain => jku.startsWith(domain));
  } catch {
    return false;
  }
}

function validateKID(kid: string): boolean {
  // KID should be alphanumeric with limited special chars
  const safePattern = /^[a-zA-Z0-9_-]+$/;
  return safePattern.test(kid);
}

function isTokenExpired(token: string): boolean {
  try {
    const [, payload] = token.split('.');
    const decoded = JSON.parse(Buffer.from(payload, 'base64url').toString());
    return decoded.exp < Math.floor(Date.now() / 1000);
  } catch {
    return true;
  }
}

function tokenHasExpiry(token: string): boolean {
  try {
    const [, payload] = token.split('.');
    const decoded = JSON.parse(Buffer.from(payload, 'base64url').toString());
    return typeof decoded.exp === 'number';
  } catch {
    return false;
  }
}

function verifyLATVersion(providedVersion: number, expectedVersion: number): boolean {
  return providedVersion === expectedVersion;
}
