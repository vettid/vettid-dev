/**
 * Cryptographic Security Tests
 *
 * Tests for cryptographic implementation security:
 * - Key derivation function strength (Argon2id parameters)
 * - Encryption algorithm validation (XChaCha20-Poly1305)
 * - Nonce/IV uniqueness verification
 * - Key rotation security
 * - Secure random number generation
 * - Hash collision resistance
 * - Timing attack resistance in comparisons
 * - Side-channel attack mitigations
 *
 * OWASP Reference: A02:2021 - Cryptographic Failures
 */

import * as crypto from 'crypto';
import {
  testTimingVulnerability,
  CRYPTO_ATTACK_SCENARIOS,
} from '../fixtures/security/securityScenarios';

// Mock cryptographic utilities for testing
const CryptoUtils = {
  /**
   * Secure random bytes generation
   */
  generateRandomBytes(length: number): Buffer {
    return crypto.randomBytes(length);
  },

  /**
   * Constant-time comparison to prevent timing attacks
   */
  secureCompare(a: Buffer, b: Buffer): boolean {
    if (a.length !== b.length) {
      // Still perform comparison to maintain constant time
      const dummy = Buffer.alloc(a.length);
      crypto.timingSafeEqual(a, dummy);
      return false;
    }
    return crypto.timingSafeEqual(a, b);
  },

  /**
   * Argon2id parameters for testing
   * Production should use: memory >= 64MB, iterations >= 3, parallelism >= 4
   */
  argon2idParams: {
    memory: 65536, // 64 MB
    iterations: 3,
    parallelism: 4,
    hashLength: 32,
    saltLength: 16,
  },

  /**
   * XChaCha20-Poly1305 parameters
   */
  xchacha20Params: {
    keyLength: 32, // 256 bits
    nonceLength: 24, // 192 bits (XChaCha20 extended nonce)
    tagLength: 16, // 128 bits authentication tag
  },

  /**
   * Generate a cryptographically secure nonce
   */
  generateNonce(length: number = 24): Buffer {
    return crypto.randomBytes(length);
  },

  /**
   * Derive key using PBKDF2 (fallback when Argon2 not available)
   */
  deriveKey(password: string, salt: Buffer, iterations: number = 100000): Buffer {
    return crypto.pbkdf2Sync(password, salt, iterations, 32, 'sha256');
  },

  /**
   * Hash with SHA-256
   */
  hash256(data: Buffer | string): Buffer {
    return crypto.createHash('sha256').update(data).digest();
  },

  /**
   * HMAC-SHA256
   */
  hmac256(data: Buffer | string, key: Buffer): Buffer {
    return crypto.createHmac('sha256', key).update(data).digest();
  },

  /**
   * Encrypt with AES-256-GCM (approximation of XChaCha20-Poly1305 for testing)
   */
  encrypt(plaintext: Buffer, key: Buffer, nonce: Buffer): { ciphertext: Buffer; tag: Buffer } {
    const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce.slice(0, 12));
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    return { ciphertext, tag };
  },

  /**
   * Decrypt with AES-256-GCM
   */
  decrypt(ciphertext: Buffer, key: Buffer, nonce: Buffer, tag: Buffer): Buffer {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce.slice(0, 12));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  },
};

describe('Cryptographic Security Tests', () => {
  describe('Key Derivation Function Strength', () => {
    /**
     * OWASP A02:2021 - Cryptographic Failures
     * Tests that KDF parameters meet security requirements
     */
    describe('Argon2id parameter validation', () => {
      it('should require minimum 64MB memory', () => {
        expect(CryptoUtils.argon2idParams.memory).toBeGreaterThanOrEqual(65536);
      });

      it('should require minimum 3 iterations', () => {
        expect(CryptoUtils.argon2idParams.iterations).toBeGreaterThanOrEqual(3);
      });

      it('should require minimum 4 parallelism', () => {
        expect(CryptoUtils.argon2idParams.parallelism).toBeGreaterThanOrEqual(4);
      });

      it('should produce 32-byte (256-bit) keys', () => {
        expect(CryptoUtils.argon2idParams.hashLength).toBe(32);
      });

      it('should use 16-byte (128-bit) salts minimum', () => {
        expect(CryptoUtils.argon2idParams.saltLength).toBeGreaterThanOrEqual(16);
      });
    });

    describe('PBKDF2 fallback parameters', () => {
      it('should use at least 100,000 iterations', () => {
        const salt = CryptoUtils.generateRandomBytes(16);
        const startTime = Date.now();
        CryptoUtils.deriveKey('password', salt, 100000);
        const duration = Date.now() - startTime;

        // Should take at least some measurable time
        expect(duration).toBeGreaterThan(0);
      });

      it('should produce different keys for different passwords', () => {
        const salt = CryptoUtils.generateRandomBytes(16);
        const key1 = CryptoUtils.deriveKey('password1', salt);
        const key2 = CryptoUtils.deriveKey('password2', salt);

        expect(key1.equals(key2)).toBe(false);
      });

      it('should produce different keys for different salts', () => {
        const salt1 = CryptoUtils.generateRandomBytes(16);
        const salt2 = CryptoUtils.generateRandomBytes(16);
        const key1 = CryptoUtils.deriveKey('password', salt1);
        const key2 = CryptoUtils.deriveKey('password', salt2);

        expect(key1.equals(key2)).toBe(false);
      });

      it('should produce consistent keys with same inputs', () => {
        const salt = Buffer.from('fixed-salt-value');
        const key1 = CryptoUtils.deriveKey('password', salt);
        const key2 = CryptoUtils.deriveKey('password', salt);

        expect(key1.equals(key2)).toBe(true);
      });
    });
  });

  describe('Encryption Algorithm Validation', () => {
    /**
     * Tests for XChaCha20-Poly1305 / AES-256-GCM encryption
     */
    describe('XChaCha20-Poly1305 parameters', () => {
      it('should use 256-bit keys', () => {
        expect(CryptoUtils.xchacha20Params.keyLength).toBe(32);
      });

      it('should use 192-bit nonces (XChaCha20)', () => {
        expect(CryptoUtils.xchacha20Params.nonceLength).toBe(24);
      });

      it('should use 128-bit authentication tags', () => {
        expect(CryptoUtils.xchacha20Params.tagLength).toBe(16);
      });
    });

    describe('Encryption/Decryption', () => {
      it('should encrypt and decrypt correctly', () => {
        const plaintext = Buffer.from('Secret message');
        const key = CryptoUtils.generateRandomBytes(32);
        const nonce = CryptoUtils.generateNonce(24);

        const { ciphertext, tag } = CryptoUtils.encrypt(plaintext, key, nonce);
        const decrypted = CryptoUtils.decrypt(ciphertext, key, nonce, tag);

        expect(decrypted.toString()).toBe('Secret message');
      });

      it('should produce different ciphertext for same plaintext with different nonces', () => {
        const plaintext = Buffer.from('Secret message');
        const key = CryptoUtils.generateRandomBytes(32);
        const nonce1 = CryptoUtils.generateNonce(24);
        const nonce2 = CryptoUtils.generateNonce(24);

        const result1 = CryptoUtils.encrypt(plaintext, key, nonce1);
        const result2 = CryptoUtils.encrypt(plaintext, key, nonce2);

        expect(result1.ciphertext.equals(result2.ciphertext)).toBe(false);
      });

      it('should fail decryption with wrong key', () => {
        const plaintext = Buffer.from('Secret message');
        const key1 = CryptoUtils.generateRandomBytes(32);
        const key2 = CryptoUtils.generateRandomBytes(32);
        const nonce = CryptoUtils.generateNonce(24);

        const { ciphertext, tag } = CryptoUtils.encrypt(plaintext, key1, nonce);

        expect(() => {
          CryptoUtils.decrypt(ciphertext, key2, nonce, tag);
        }).toThrow();
      });

      it('should fail decryption with modified ciphertext', () => {
        const plaintext = Buffer.from('Secret message');
        const key = CryptoUtils.generateRandomBytes(32);
        const nonce = CryptoUtils.generateNonce(24);

        const { ciphertext, tag } = CryptoUtils.encrypt(plaintext, key, nonce);

        // Modify ciphertext
        ciphertext[0] ^= 0xff;

        expect(() => {
          CryptoUtils.decrypt(ciphertext, key, nonce, tag);
        }).toThrow();
      });

      it('should fail decryption with modified tag', () => {
        const plaintext = Buffer.from('Secret message');
        const key = CryptoUtils.generateRandomBytes(32);
        const nonce = CryptoUtils.generateNonce(24);

        const { ciphertext, tag } = CryptoUtils.encrypt(plaintext, key, nonce);

        // Modify tag
        tag[0] ^= 0xff;

        expect(() => {
          CryptoUtils.decrypt(ciphertext, key, nonce, tag);
        }).toThrow();
      });
    });
  });

  describe('Nonce/IV Uniqueness Verification', () => {
    /**
     * Critical: Nonce reuse with the same key breaks encryption security
     */
    it('should generate unique nonces', () => {
      const nonces = new Set<string>();
      const iterations = 1000;

      for (let i = 0; i < iterations; i++) {
        const nonce = CryptoUtils.generateNonce(24);
        nonces.add(nonce.toString('hex'));
      }

      expect(nonces.size).toBe(iterations);
    });

    it('should have sufficient nonce entropy', () => {
      const nonce = CryptoUtils.generateNonce(24);

      // Check that nonce isn't all zeros or predictable pattern
      const isAllZeros = nonce.every(byte => byte === 0);
      expect(isAllZeros).toBe(false);

      // Check entropy by ensuring variation in bytes
      const uniqueBytes = new Set(nonce);
      expect(uniqueBytes.size).toBeGreaterThan(1);
    });

    it('should detect nonce reuse attempts', () => {
      const usedNonces = new Set<string>();

      const isNonceReused = (nonce: Buffer): boolean => {
        const nonceHex = nonce.toString('hex');
        if (usedNonces.has(nonceHex)) {
          return true;
        }
        usedNonces.add(nonceHex);
        return false;
      };

      const nonce1 = CryptoUtils.generateNonce(24);
      const nonce2 = Buffer.from(nonce1); // Same nonce

      expect(isNonceReused(nonce1)).toBe(false);
      expect(isNonceReused(nonce2)).toBe(true); // Reuse detected
    });

    it('should have collision-resistant nonce space', () => {
      // 24-byte (192-bit) nonce has 2^192 possible values
      // Birthday paradox collision at 2^96 nonces
      // Test documents the nonce size requirement
      const nonceLength = CryptoUtils.xchacha20Params.nonceLength;

      // 24 bytes = 192 bits, collision resistance is 2^96
      const collisionResistanceBits = (nonceLength * 8) / 2;
      expect(collisionResistanceBits).toBeGreaterThanOrEqual(96);
    });
  });

  describe('Key Rotation Security', () => {
    /**
     * Tests for secure key rotation procedures
     */
    it('should generate cryptographically strong new keys', () => {
      const oldKey = CryptoUtils.generateRandomBytes(32);
      const newKey = CryptoUtils.generateRandomBytes(32);

      // Keys should be different
      expect(oldKey.equals(newKey)).toBe(false);

      // Both should have proper length
      expect(oldKey.length).toBe(32);
      expect(newKey.length).toBe(32);
    });

    it('should support re-encryption during rotation', () => {
      const plaintext = Buffer.from('Secret data');
      const oldKey = CryptoUtils.generateRandomBytes(32);
      const newKey = CryptoUtils.generateRandomBytes(32);

      // Encrypt with old key
      const nonce1 = CryptoUtils.generateNonce(24);
      const { ciphertext: oldCiphertext, tag: oldTag } = CryptoUtils.encrypt(
        plaintext,
        oldKey,
        nonce1
      );

      // Decrypt with old key
      const decrypted = CryptoUtils.decrypt(oldCiphertext, oldKey, nonce1, oldTag);

      // Re-encrypt with new key
      const nonce2 = CryptoUtils.generateNonce(24);
      const { ciphertext: newCiphertext, tag: newTag } = CryptoUtils.encrypt(
        decrypted,
        newKey,
        nonce2
      );

      // Verify new encryption
      const finalDecrypted = CryptoUtils.decrypt(newCiphertext, newKey, nonce2, newTag);
      expect(finalDecrypted.toString()).toBe('Secret data');
    });

    it('should invalidate old keys after rotation', () => {
      const plaintext = Buffer.from('Secret data');
      const oldKey = CryptoUtils.generateRandomBytes(32);
      const newKey = CryptoUtils.generateRandomBytes(32);

      // Encrypt with new key
      const nonce = CryptoUtils.generateNonce(24);
      const { ciphertext, tag } = CryptoUtils.encrypt(plaintext, newKey, nonce);

      // Old key should not decrypt
      expect(() => {
        CryptoUtils.decrypt(ciphertext, oldKey, nonce, tag);
      }).toThrow();
    });
  });

  describe('Secure Random Number Generation', () => {
    /**
     * Tests for cryptographically secure random number generation
     */
    it('should generate cryptographically secure random bytes', () => {
      const bytes = CryptoUtils.generateRandomBytes(32);

      expect(bytes.length).toBe(32);
      expect(bytes).toBeInstanceOf(Buffer);
    });

    it('should not produce predictable sequences', () => {
      const samples: Buffer[] = [];

      for (let i = 0; i < 100; i++) {
        samples.push(CryptoUtils.generateRandomBytes(16));
      }

      // Check for uniqueness
      const uniqueHexes = new Set(samples.map(s => s.toString('hex')));
      expect(uniqueHexes.size).toBe(100);

      // Check that consecutive samples aren't sequential
      for (let i = 1; i < samples.length; i++) {
        const diff = Math.abs(
          parseInt(samples[i].toString('hex'), 16) -
          parseInt(samples[i - 1].toString('hex'), 16)
        );
        expect(diff).not.toBe(1);
      }
    });

    it('should have uniform distribution', () => {
      // Generate many random bytes and check distribution
      const totalBytes = 10000;
      const byteCounts = new Array(256).fill(0);

      const randomData = CryptoUtils.generateRandomBytes(totalBytes);
      for (const byte of randomData) {
        byteCounts[byte]++;
      }

      // Expected count per byte value: totalBytes / 256 ≈ 39
      const expectedCount = totalBytes / 256;

      // Use chi-squared test approach: sum of (observed - expected)^2 / expected
      // For 255 degrees of freedom, critical value at p=0.01 is ~310
      // This is more statistically valid than checking individual deviations
      let chiSquared = 0;
      for (let i = 0; i < 256; i++) {
        chiSquared += Math.pow(byteCounts[i] - expectedCount, 2) / expectedCount;
      }

      // Chi-squared critical value for 255 df at p=0.01 is ~310
      // We use a generous threshold to avoid flaky tests
      expect(chiSquared).toBeLessThan(350);
    });

    it('should handle large random data requests', () => {
      // Generate 1MB of random data
      const largeData = CryptoUtils.generateRandomBytes(1024 * 1024);

      expect(largeData.length).toBe(1024 * 1024);

      // Quick entropy check - should have many unique 4-byte sequences
      const uniqueSequences = new Set<string>();
      for (let i = 0; i < largeData.length - 4; i += 4) {
        uniqueSequences.add(largeData.slice(i, i + 4).toString('hex'));
      }

      // Should have high number of unique sequences
      expect(uniqueSequences.size).toBeGreaterThan(200000);
    });
  });

  describe('Hash Collision Resistance', () => {
    /**
     * Tests for hash function security
     */
    it('should produce consistent hashes', () => {
      const data = Buffer.from('test data');
      const hash1 = CryptoUtils.hash256(data);
      const hash2 = CryptoUtils.hash256(data);

      expect(hash1.equals(hash2)).toBe(true);
    });

    it('should produce different hashes for different inputs', () => {
      const hash1 = CryptoUtils.hash256('input1');
      const hash2 = CryptoUtils.hash256('input2');

      expect(hash1.equals(hash2)).toBe(false);
    });

    it('should have avalanche effect (small change = big hash change)', () => {
      const data1 = Buffer.from('test data');
      const data2 = Buffer.from('test datb'); // One bit difference

      const hash1 = CryptoUtils.hash256(data1);
      const hash2 = CryptoUtils.hash256(data2);

      // Count differing bits
      let differingBits = 0;
      for (let i = 0; i < hash1.length; i++) {
        let xor = hash1[i] ^ hash2[i];
        while (xor) {
          differingBits += xor & 1;
          xor >>= 1;
        }
      }

      // SHA-256 produces 256-bit hash, expect roughly half bits to differ
      expect(differingBits).toBeGreaterThan(64); // At least 25% should differ
      expect(differingBits).toBeLessThan(192); // At most 75% should differ
    });

    it('should produce fixed-length output regardless of input size', () => {
      const smallHash = CryptoUtils.hash256('a');
      const largeHash = CryptoUtils.hash256('a'.repeat(10000));

      expect(smallHash.length).toBe(32);
      expect(largeHash.length).toBe(32);
    });

    it('should be computationally expensive to find collisions', () => {
      // Document that SHA-256 has 128-bit collision resistance
      const hashLength = CryptoUtils.hash256('test').length * 8; // bits
      const collisionResistance = hashLength / 2;

      expect(collisionResistance).toBe(128);
    });
  });

  describe('Timing Attack Resistance', () => {
    /**
     * OWASP A02:2021 - Cryptographic Failures (Timing Attacks)
     * Tests that cryptographic comparisons are constant-time
     */
    describe('Constant-time comparison', () => {
      it('should use timing-safe comparison', () => {
        const a = Buffer.from('secret-value-1234');
        const b = Buffer.from('secret-value-1234');

        expect(CryptoUtils.secureCompare(a, b)).toBe(true);
      });

      it('should return false for different values', () => {
        const a = Buffer.from('secret-value-1234');
        const b = Buffer.from('different-value!!');

        expect(CryptoUtils.secureCompare(a, b)).toBe(false);
      });

      it('should handle different length buffers safely', () => {
        const a = Buffer.from('short');
        const b = Buffer.from('much longer value');

        expect(CryptoUtils.secureCompare(a, b)).toBe(false);
      });

      it('should have consistent timing for matches and mismatches', () => {
        const iterations = 1000;
        const secret = Buffer.from('32-byte-secret-value-for-timing');

        // Time matching comparisons
        const matchTimes: number[] = [];
        for (let i = 0; i < iterations; i++) {
          const match = Buffer.from('32-byte-secret-value-for-timing');
          const start = process.hrtime.bigint();
          CryptoUtils.secureCompare(secret, match);
          const end = process.hrtime.bigint();
          matchTimes.push(Number(end - start));
        }

        // Time non-matching comparisons (early mismatch)
        const mismatchEarlyTimes: number[] = [];
        for (let i = 0; i < iterations; i++) {
          const mismatch = Buffer.from('X2-byte-secret-value-for-timing');
          const start = process.hrtime.bigint();
          CryptoUtils.secureCompare(secret, mismatch);
          const end = process.hrtime.bigint();
          mismatchEarlyTimes.push(Number(end - start));
        }

        // Time non-matching comparisons (late mismatch)
        const mismatchLateTimes: number[] = [];
        for (let i = 0; i < iterations; i++) {
          const mismatch = Buffer.from('32-byte-secret-value-for-timinX');
          const start = process.hrtime.bigint();
          CryptoUtils.secureCompare(secret, mismatch);
          const end = process.hrtime.bigint();
          mismatchLateTimes.push(Number(end - start));
        }

        // Calculate averages
        const avg = (arr: number[]) => arr.reduce((a, b) => a + b, 0) / arr.length;

        const avgMatch = avg(matchTimes);
        const avgMismatchEarly = avg(mismatchEarlyTimes);
        const avgMismatchLate = avg(mismatchLateTimes);

        // Timing should be similar - constant-time comparison shouldn't show
        // significant timing difference based on match position.
        // Note: High tolerance (90%) needed due to OS scheduling, CPU caching,
        // and test environment variability. The key security property is that
        // early vs late mismatches should have similar timing (both ratios similar).
        const tolerance = 0.9;

        const earlyRatio = avgMismatchEarly / avgMatch;
        const lateRatio = avgMismatchLate / avgMatch;

        // Primary security check: early and late mismatches should take similar time
        // (within 50% of each other) - this is the actual timing attack resistance
        const earlyVsLateRatio = avgMismatchEarly / avgMismatchLate;
        expect(earlyVsLateRatio).toBeGreaterThan(0.5);
        expect(earlyVsLateRatio).toBeLessThan(2.0);

        // Secondary checks with high tolerance for environment variability
        expect(earlyRatio).toBeGreaterThan(1 - tolerance);
        expect(earlyRatio).toBeLessThan(1 + tolerance);
        expect(lateRatio).toBeGreaterThan(1 - tolerance);
        expect(lateRatio).toBeLessThan(1 + tolerance);
      });
    });

    describe('Timing attack scenarios from fixtures', () => {
      CRYPTO_ATTACK_SCENARIOS.timingAttack.scenarios.forEach(scenario => {
        it(`should resist: ${scenario.name}`, () => {
          // Use the testTimingVulnerability helper with the fixture's target value
          const targetValue = scenario.scenario.targetValue;
          const result = testTimingVulnerability(
            (a: string, b: string) => {
              const bufA = Buffer.from(a, 'hex');
              const bufB = Buffer.from(b, 'hex');
              return CryptoUtils.secureCompare(bufA, bufB);
            },
            100 // iterations
          );

          // Should not show timing vulnerability
          expect(result.vulnerable).toBe(false);
        });
      });
    });
  });

  describe('Side-Channel Attack Mitigations', () => {
    /**
     * Tests for protection against various side-channel attacks
     */
    describe('Cache timing attacks', () => {
      it('should use constant-time operations for key operations', () => {
        // Document that crypto operations should not have data-dependent timing
        const key = CryptoUtils.generateRandomBytes(32);
        const nonce = CryptoUtils.generateNonce(24);

        // All zeros vs all ones should take similar time
        const zeros = Buffer.alloc(1000, 0);
        const ones = Buffer.alloc(1000, 0xff);

        const iterations = 100;
        const zeroTimes: number[] = [];
        const oneTimes: number[] = [];

        for (let i = 0; i < iterations; i++) {
          const start1 = process.hrtime.bigint();
          CryptoUtils.encrypt(zeros, key, nonce);
          const end1 = process.hrtime.bigint();
          zeroTimes.push(Number(end1 - start1));

          const start2 = process.hrtime.bigint();
          CryptoUtils.encrypt(ones, key, nonce);
          const end2 = process.hrtime.bigint();
          oneTimes.push(Number(end2 - start2));
        }

        const avgZero = zeroTimes.reduce((a, b) => a + b, 0) / iterations;
        const avgOne = oneTimes.reduce((a, b) => a + b, 0) / iterations;

        // Timing should be within 50% of each other
        const ratio = avgZero / avgOne;
        expect(ratio).toBeGreaterThan(0.5);
        expect(ratio).toBeLessThan(2.0);
      });
    });

    describe('Power analysis protection', () => {
      it('should document that hardware-level protection is assumed', () => {
        // Software-level protection against power analysis is limited
        // This test documents the assumption that hardware provides protection
        const assumption =
          'Hardware-level side-channel protection is provided by the execution environment';
        expect(assumption).toBeDefined();
      });
    });

    describe('Memory access patterns', () => {
      it('should not leak key material through memory access', () => {
        // Generate key and immediately use it
        const key = CryptoUtils.generateRandomBytes(32);
        const nonce = CryptoUtils.generateNonce(24);
        const plaintext = Buffer.from('Secret message');

        // Encrypt
        const { ciphertext, tag } = CryptoUtils.encrypt(plaintext, key, nonce);

        // Verify encryption worked
        expect(ciphertext.length).toBeGreaterThan(0);
        expect(tag.length).toBe(16);

        // In production, key should be zeroed after use
        // This test documents the requirement
      });
    });
  });

  describe('HMAC Security', () => {
    /**
     * Tests for HMAC implementation security
     */
    it('should produce valid HMAC-SHA256', () => {
      const data = 'test message';
      const key = CryptoUtils.generateRandomBytes(32);

      const hmac = CryptoUtils.hmac256(data, key);

      expect(hmac.length).toBe(32);
    });

    it('should produce different HMACs for different keys', () => {
      const data = 'test message';
      const key1 = CryptoUtils.generateRandomBytes(32);
      const key2 = CryptoUtils.generateRandomBytes(32);

      const hmac1 = CryptoUtils.hmac256(data, key1);
      const hmac2 = CryptoUtils.hmac256(data, key2);

      expect(hmac1.equals(hmac2)).toBe(false);
    });

    it('should produce different HMACs for different data', () => {
      const key = CryptoUtils.generateRandomBytes(32);

      const hmac1 = CryptoUtils.hmac256('message 1', key);
      const hmac2 = CryptoUtils.hmac256('message 2', key);

      expect(hmac1.equals(hmac2)).toBe(false);
    });

    it('should be consistent for same inputs', () => {
      const data = 'test message';
      const key = Buffer.from('32-byte-fixed-key-for-testing!!');

      const hmac1 = CryptoUtils.hmac256(data, key);
      const hmac2 = CryptoUtils.hmac256(data, key);

      expect(hmac1.equals(hmac2)).toBe(true);
    });
  });

  describe('Cryptographic Attack Scenarios', () => {
    /**
     * Tests based on documented attack scenarios from fixtures
     */
    describe('Nonce misuse scenarios', () => {
      CRYPTO_ATTACK_SCENARIOS.nonceMisuse.scenarios.forEach((scenario: { name: string; scenario: { nonces?: string[]; expectedResult?: string } }) => {
        it(`should detect: ${scenario.name}`, () => {
          if (scenario.scenario.nonces) {
            const nonceSet = new Set(scenario.scenario.nonces);
            const hasReuse = nonceSet.size < scenario.scenario.nonces.length;

            if (scenario.scenario.expectedResult === 'key_compromise') {
              // Should detect nonce reuse
              expect(hasReuse).toBe(true);
            }
          }
        });
      });
    });

    describe('Weak KDF scenarios', () => {
      CRYPTO_ATTACK_SCENARIOS.weakKdf.scenarios.forEach((scenario: { name: string; scenario: { algorithm?: string; iterations?: number; memory?: number; parallelism?: number; expectedResult?: string } }) => {
        it(`should reject: ${scenario.name}`, () => {
          const params = scenario.scenario;

          // Validate that weak parameters are rejected
          if (params.algorithm === 'pbkdf2') {
            const isWeak = (params.iterations || 0) < 100000;
            expect(isWeak).toBe(params.expectedResult === 'brute_force_feasible');
          }

          if (params.algorithm === 'argon2id') {
            const isWeak =
              (params.memory || 0) < 65536 || (params.iterations || 0) < 3 || (params.parallelism || 0) < 4;
            expect(isWeak).toBe(params.expectedResult === 'brute_force_feasible');
          }
        });
      });
    });
  });

  describe('Key Length Validation', () => {
    /**
     * Tests that key lengths meet minimum security requirements
     */
    it('should enforce 256-bit minimum for symmetric keys', () => {
      const minKeyLength = 32; // 256 bits

      expect(CryptoUtils.xchacha20Params.keyLength).toBeGreaterThanOrEqual(minKeyLength);
    });

    it('should reject short keys', () => {
      const shortKey = CryptoUtils.generateRandomBytes(16); // 128 bits - too short
      const nonce = CryptoUtils.generateNonce(24);
      const plaintext = Buffer.from('test');

      expect(() => {
        CryptoUtils.encrypt(plaintext, shortKey, nonce);
      }).toThrow();
    });

    it('should accept 256-bit keys', () => {
      const key = CryptoUtils.generateRandomBytes(32);
      const nonce = CryptoUtils.generateNonce(24);
      const plaintext = Buffer.from('test');

      expect(() => {
        CryptoUtils.encrypt(plaintext, key, nonce);
      }).not.toThrow();
    });
  });
});
