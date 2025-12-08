/**
 * Smoke Tests
 *
 * Phase 10: Production Readiness & Polish
 *
 * Quick validation tests for CI/CD pipelines.
 * These tests verify critical functionality works without
 * running the full test suite.
 *
 * Run with: npm run test:smoke
 */

import * as crypto from 'crypto';

describe('Smoke Tests', () => {
  describe('Cryptographic Operations', () => {
    test('should generate random bytes', () => {
      const bytes = crypto.randomBytes(32);
      expect(bytes).toHaveLength(32);
      expect(bytes).toBeInstanceOf(Buffer);
    });

    test('should generate UUIDs', () => {
      const uuid = crypto.randomUUID();
      expect(uuid).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
    });

    test('should hash with SHA-256', () => {
      const data = Buffer.from('test data');
      const hash = crypto.createHash('sha256').update(data).digest();
      expect(hash).toHaveLength(32);
    });

    test('should encrypt/decrypt with AES-GCM', () => {
      const key = crypto.randomBytes(32);
      const iv = crypto.randomBytes(12);
      const plaintext = 'Hello, World!';

      // Encrypt
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
      const encrypted = Buffer.concat([
        cipher.update(plaintext, 'utf8'),
        cipher.final(),
      ]);
      const tag = cipher.getAuthTag();

      // Decrypt
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAuthTag(tag);
      const decrypted = Buffer.concat([
        decipher.update(encrypted),
        decipher.final(),
      ]).toString('utf8');

      expect(decrypted).toBe(plaintext);
    });

    test('should generate Ed25519 key pairs', () => {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
      expect(publicKey).toBeDefined();
      expect(privateKey).toBeDefined();
    });

    test('should sign and verify with Ed25519', () => {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
      const message = Buffer.from('test message');

      const signature = crypto.sign(null, message, privateKey);
      const isValid = crypto.verify(null, message, publicKey, signature);

      expect(isValid).toBe(true);
    });

    test('should generate X25519 key pairs', () => {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
      expect(publicKey).toBeDefined();
      expect(privateKey).toBeDefined();
    });

    test('should derive shared secret with X25519', () => {
      const alice = crypto.generateKeyPairSync('x25519');
      const bob = crypto.generateKeyPairSync('x25519');

      const aliceSecret = crypto.diffieHellman({
        privateKey: alice.privateKey,
        publicKey: bob.publicKey,
      });

      const bobSecret = crypto.diffieHellman({
        privateKey: bob.privateKey,
        publicKey: alice.publicKey,
      });

      expect(aliceSecret).toEqual(bobSecret);
    });
  });

  describe('Key Derivation', () => {
    test('should derive key with PBKDF2', () => {
      const password = 'test-password';
      const salt = crypto.randomBytes(16);
      const iterations = 10000;
      const keyLength = 32;

      const key = crypto.pbkdf2Sync(password, salt, iterations, keyLength, 'sha256');
      expect(key).toHaveLength(keyLength);
    });

    test('should produce consistent keys with same inputs', () => {
      const password = 'test-password';
      const salt = Buffer.from('consistent-salt-value');

      const key1 = crypto.pbkdf2Sync(password, salt, 10000, 32, 'sha256');
      const key2 = crypto.pbkdf2Sync(password, salt, 10000, 32, 'sha256');

      expect(key1).toEqual(key2);
    });
  });

  describe('Data Validation', () => {
    test('should validate email format', () => {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

      expect(emailRegex.test('user@example.com')).toBe(true);
      expect(emailRegex.test('user.name@domain.co.uk')).toBe(true);
      expect(emailRegex.test('invalid-email')).toBe(false);
      expect(emailRegex.test('@domain.com')).toBe(false);
    });

    test('should validate UUID format', () => {
      const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

      expect(uuidRegex.test(crypto.randomUUID())).toBe(true);
      expect(uuidRegex.test('not-a-uuid')).toBe(false);
    });

    test('should detect injection attempts', () => {
      const maliciousPatterns = [
        /['";]|--|\bOR\b|\bAND\b|\bUNION\b|\bSELECT\b|\bDROP\b/i, // SQL
        /<script>|javascript:|on\w+\s*=/i, // XSS
        /\$\{|\$\(|`.*`/i, // Template injection
      ];

      const testInputs = [
        { input: "'; DROP TABLE users;--", isMalicious: true },
        { input: '<script>alert(1)</script>', isMalicious: true },
        { input: 'normal text', isMalicious: false },
        { input: 'user@example.com', isMalicious: false },
      ];

      for (const { input, isMalicious } of testInputs) {
        const detected = maliciousPatterns.some(p => p.test(input));
        expect(detected).toBe(isMalicious);
      }
    });
  });

  describe('Error Handling', () => {
    test('should sanitize error messages', () => {
      const sensitivePatterns = [/password/i, /secret/i, /token/i, /key/i];

      const errorMessage = 'Failed with password=abc123 and api_key=xyz';
      let sanitized = errorMessage;

      for (const pattern of sensitivePatterns) {
        sanitized = sanitized.replace(pattern, '[REDACTED]');
      }

      expect(sanitized).not.toContain('password');
      expect(sanitized).not.toContain('key');
    });

    test('should handle JSON parsing errors', () => {
      const invalidJSON = 'not valid json';

      expect(() => {
        JSON.parse(invalidJSON);
      }).toThrow();
    });

    test('should handle missing required fields', () => {
      interface User {
        id: string;
        email: string;
        name: string;
      }

      const validateUser = (data: Partial<User>): string[] => {
        const errors: string[] = [];
        if (!data.id) errors.push('id is required');
        if (!data.email) errors.push('email is required');
        if (!data.name) errors.push('name is required');
        return errors;
      };

      expect(validateUser({})).toHaveLength(3);
      expect(validateUser({ id: '1' })).toHaveLength(2);
      expect(validateUser({ id: '1', email: 'a@b.com', name: 'Test' })).toHaveLength(0);
    });
  });

  describe('Buffer Operations', () => {
    test('should convert between hex and buffer', () => {
      const original = crypto.randomBytes(32);
      const hex = original.toString('hex');
      const restored = Buffer.from(hex, 'hex');

      expect(restored).toEqual(original);
    });

    test('should convert between base64 and buffer', () => {
      const original = crypto.randomBytes(32);
      const base64 = original.toString('base64');
      const restored = Buffer.from(base64, 'base64');

      expect(restored).toEqual(original);
    });

    test('should convert between base64url and buffer', () => {
      const original = crypto.randomBytes(32);
      const base64url = original.toString('base64url');
      const restored = Buffer.from(base64url, 'base64url');

      expect(restored).toEqual(original);
    });

    test('should concatenate buffers', () => {
      const a = Buffer.from('Hello, ');
      const b = Buffer.from('World!');
      const combined = Buffer.concat([a, b]);

      expect(combined.toString()).toBe('Hello, World!');
    });
  });

  describe('Timing Safety', () => {
    test('should use constant-time comparison', () => {
      const a = Buffer.from('secret-value-12345');
      const b = Buffer.from('secret-value-12345');
      const c = Buffer.from('different-value-00');

      // timingSafeEqual requires same length buffers
      expect(crypto.timingSafeEqual(a, b)).toBe(true);
      expect(crypto.timingSafeEqual(a, c)).toBe(false);
    });
  });

  describe('Environment', () => {
    test('should have Node.js crypto available', () => {
      expect(crypto).toBeDefined();
      expect(crypto.randomBytes).toBeDefined();
      expect(crypto.createHash).toBeDefined();
      expect(crypto.createCipheriv).toBeDefined();
    });

    test('should have required Node.js version features', () => {
      // Check for features available in Node.js 18+
      expect(crypto.randomUUID).toBeDefined();
      expect(crypto.generateKeyPairSync).toBeDefined();
    });
  });
});

describe('Performance Smoke Tests', () => {
  const TIMEOUT_MS = 100;

  test('should complete encryption within timeout', () => {
    const start = performance.now();
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(12);
    const plaintext = crypto.randomBytes(1024);

    for (let i = 0; i < 100; i++) {
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
      cipher.update(plaintext);
      cipher.final();
      cipher.getAuthTag();
    }

    const elapsed = performance.now() - start;
    expect(elapsed).toBeLessThan(TIMEOUT_MS);
  });

  test('should complete hashing within timeout', () => {
    const start = performance.now();
    const data = crypto.randomBytes(1024);

    for (let i = 0; i < 1000; i++) {
      crypto.createHash('sha256').update(data).digest();
    }

    const elapsed = performance.now() - start;
    expect(elapsed).toBeLessThan(TIMEOUT_MS);
  });

  test('should complete key generation within timeout', () => {
    const start = performance.now();

    for (let i = 0; i < 10; i++) {
      crypto.generateKeyPairSync('ed25519');
    }

    const elapsed = performance.now() - start;
    expect(elapsed).toBeLessThan(TIMEOUT_MS);
  });
});
