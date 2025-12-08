/**
 * Unit Tests: Production Crypto Module (lambda/common/crypto.ts)
 *
 * Tests the production cryptographic implementations:
 * - X25519 key generation and ECDH
 * - HKDF-SHA256 key derivation
 * - ChaCha20-Poly1305 encryption/decryption
 * - Password hashing with Argon2id
 * - Ed25519 signing and verification
 * - LAT generation and verification
 * - Transaction key pool management
 * - Serialization helpers
 *
 * @see cdk/coordination/specs/credential-format.md
 * @see cdk/lambda/common/crypto.ts
 */

import {
  generateX25519KeyPair,
  deriveSharedSecret,
  hkdf,
  encryptWithPublicKey,
  decryptWithPrivateKey,
  encryptCredentialBlob,
  decryptCredentialBlob,
  encryptWithTransactionKey,
  decryptWithTransactionKey,
  hashPassword,
  verifyPassword,
  needsRehash,
  generateLAT,
  hashLATToken,
  verifyLATToken,
  generateTransactionKeyPool,
  serializeEncryptedBlob,
  deserializeEncryptedBlob,
  packEncryptedBlob,
  unpackEncryptedBlob,
  generateEd25519KeyPair,
  signMessage,
  verifySignature,
  signPayload,
  verifySignedPayload,
  generateChallenge,
  signChallengeResponse,
  verifyChallengeResponse,
  X25519KeyPair,
  EncryptedBlob,
  LAT,
  TransactionKeyPair,
  Ed25519KeyPair,
} from '../../../lambda/common/crypto';

// ============================================
// X25519 Key Generation Tests
// ============================================

describe('X25519 Key Generation', () => {
  describe('generateX25519KeyPair', () => {
    it('should generate valid 32-byte public key', () => {
      const keyPair = generateX25519KeyPair();

      expect(keyPair.publicKey).toBeInstanceOf(Buffer);
      expect(keyPair.publicKey.length).toBe(32);
    });

    it('should generate valid 32-byte private key', () => {
      const keyPair = generateX25519KeyPair();

      expect(keyPair.privateKey).toBeInstanceOf(Buffer);
      expect(keyPair.privateKey.length).toBe(32);
    });

    it('should generate unique key pairs', () => {
      const keyPair1 = generateX25519KeyPair();
      const keyPair2 = generateX25519KeyPair();

      expect(keyPair1.publicKey.equals(keyPair2.publicKey)).toBe(false);
      expect(keyPair1.privateKey.equals(keyPair2.privateKey)).toBe(false);
    });

    it('should generate cryptographically random keys', () => {
      const keyPairs = Array.from({ length: 100 }, () => generateX25519KeyPair());
      const publicKeys = new Set(keyPairs.map(kp => kp.publicKey.toString('hex')));

      // All 100 keys should be unique
      expect(publicKeys.size).toBe(100);
    });
  });
});

// ============================================
// X25519 Key Exchange (ECDH) Tests
// ============================================

describe('X25519 Key Exchange', () => {
  describe('deriveSharedSecret', () => {
    it('should derive same shared secret from both directions', () => {
      const alice = generateX25519KeyPair();
      const bob = generateX25519KeyPair();

      const aliceShared = deriveSharedSecret(alice.privateKey, bob.publicKey);
      const bobShared = deriveSharedSecret(bob.privateKey, alice.publicKey);

      expect(aliceShared.equals(bobShared)).toBe(true);
    });

    it('should produce 32-byte shared secret', () => {
      const alice = generateX25519KeyPair();
      const bob = generateX25519KeyPair();

      const shared = deriveSharedSecret(alice.privateKey, bob.publicKey);

      expect(shared.length).toBe(32);
    });

    it('should produce different secrets for different key pairs', () => {
      const alice = generateX25519KeyPair();
      const bob1 = generateX25519KeyPair();
      const bob2 = generateX25519KeyPair();

      const shared1 = deriveSharedSecret(alice.privateKey, bob1.publicKey);
      const shared2 = deriveSharedSecret(alice.privateKey, bob2.publicKey);

      expect(shared1.equals(shared2)).toBe(false);
    });

    it('should be deterministic for same input keys', () => {
      const alice = generateX25519KeyPair();
      const bob = generateX25519KeyPair();

      const shared1 = deriveSharedSecret(alice.privateKey, bob.publicKey);
      const shared2 = deriveSharedSecret(alice.privateKey, bob.publicKey);

      expect(shared1.equals(shared2)).toBe(true);
    });
  });
});

// ============================================
// HKDF-SHA256 Tests
// ============================================

describe('HKDF Key Derivation', () => {
  describe('hkdf', () => {
    it('should derive key of requested length', () => {
      const ikm = Buffer.alloc(32, 0x42);

      const key16 = hkdf(ikm, 16, 'test');
      const key32 = hkdf(ikm, 32, 'test');
      const key64 = hkdf(ikm, 64, 'test');

      expect(key16.length).toBe(16);
      expect(key32.length).toBe(32);
      expect(key64.length).toBe(64);
    });

    it('should produce different keys for different info strings', () => {
      const ikm = Buffer.alloc(32, 0x42);

      const key1 = hkdf(ikm, 32, 'info-1');
      const key2 = hkdf(ikm, 32, 'info-2');

      expect(key1.equals(key2)).toBe(false);
    });

    it('should produce same key for same inputs', () => {
      const ikm = Buffer.alloc(32, 0x42);

      const key1 = hkdf(ikm, 32, 'test-info');
      const key2 = hkdf(ikm, 32, 'test-info');

      expect(key1.equals(key2)).toBe(true);
    });

    it('should produce different keys for different IKM', () => {
      const ikm1 = Buffer.alloc(32, 0x42);
      const ikm2 = Buffer.alloc(32, 0x43);

      const key1 = hkdf(ikm1, 32, 'test');
      const key2 = hkdf(ikm2, 32, 'test');

      expect(key1.equals(key2)).toBe(false);
    });

    it('should support optional salt', () => {
      const ikm = Buffer.alloc(32, 0x42);
      const salt = Buffer.alloc(16, 0xaa);

      const keyNoSalt = hkdf(ikm, 32, 'test');
      const keyWithSalt = hkdf(ikm, 32, 'test', salt);

      expect(keyNoSalt.equals(keyWithSalt)).toBe(false);
    });
  });
});

// ============================================
// ChaCha20-Poly1305 Encryption Tests
// ============================================

describe('ChaCha20-Poly1305 Encryption', () => {
  describe('encryptWithPublicKey / decryptWithPrivateKey', () => {
    it('should encrypt and decrypt data correctly', () => {
      const keyPair = generateX25519KeyPair();
      const plaintext = Buffer.from('Hello, World!');

      const encrypted = encryptWithPublicKey(plaintext, keyPair.publicKey);
      const decrypted = decryptWithPrivateKey(encrypted, keyPair.privateKey);

      expect(decrypted.toString()).toBe('Hello, World!');
    });

    it('should produce different ciphertext each time (ephemeral key)', () => {
      const keyPair = generateX25519KeyPair();
      const plaintext = Buffer.from('Hello, World!');

      const encrypted1 = encryptWithPublicKey(plaintext, keyPair.publicKey);
      const encrypted2 = encryptWithPublicKey(plaintext, keyPair.publicKey);

      expect(encrypted1.ephemeralPublicKey.equals(encrypted2.ephemeralPublicKey)).toBe(false);
      expect(encrypted1.ciphertext.equals(encrypted2.ciphertext)).toBe(false);
    });

    it('should include 12-byte nonce', () => {
      const keyPair = generateX25519KeyPair();
      const plaintext = Buffer.from('Hello, World!');

      const encrypted = encryptWithPublicKey(plaintext, keyPair.publicKey);

      expect(encrypted.nonce.length).toBe(12);
    });

    it('should include 32-byte ephemeral public key', () => {
      const keyPair = generateX25519KeyPair();
      const plaintext = Buffer.from('Hello, World!');

      const encrypted = encryptWithPublicKey(plaintext, keyPair.publicKey);

      expect(encrypted.ephemeralPublicKey.length).toBe(32);
    });

    it('should fail decryption with wrong private key', () => {
      const keyPair1 = generateX25519KeyPair();
      const keyPair2 = generateX25519KeyPair();
      const plaintext = Buffer.from('Hello, World!');

      const encrypted = encryptWithPublicKey(plaintext, keyPair1.publicKey);

      expect(() => decryptWithPrivateKey(encrypted, keyPair2.privateKey)).toThrow('Decryption failed');
    });

    it('should fail decryption with modified ciphertext', () => {
      const keyPair = generateX25519KeyPair();
      const plaintext = Buffer.from('Hello, World!');

      const encrypted = encryptWithPublicKey(plaintext, keyPair.publicKey);
      encrypted.ciphertext[0] ^= 0xff; // Flip bits

      expect(() => decryptWithPrivateKey(encrypted, keyPair.privateKey)).toThrow();
    });

    it('should fail decryption with modified auth tag', () => {
      const keyPair = generateX25519KeyPair();
      const plaintext = Buffer.from('Hello, World!');

      const encrypted = encryptWithPublicKey(plaintext, keyPair.publicKey);
      // Auth tag is at the end of ciphertext
      const tagIndex = encrypted.ciphertext.length - 1;
      encrypted.ciphertext[tagIndex] ^= 0xff;

      expect(() => decryptWithPrivateKey(encrypted, keyPair.privateKey)).toThrow();
    });

    it('should support custom context', () => {
      const keyPair = generateX25519KeyPair();
      const plaintext = Buffer.from('Secret data');

      const encrypted = encryptWithPublicKey(plaintext, keyPair.publicKey, 'custom-context');
      const decrypted = decryptWithPrivateKey(encrypted, keyPair.privateKey, 'custom-context');

      expect(decrypted.toString()).toBe('Secret data');
    });

    it('should fail with wrong context', () => {
      const keyPair = generateX25519KeyPair();
      const plaintext = Buffer.from('Secret data');

      const encrypted = encryptWithPublicKey(plaintext, keyPair.publicKey, 'context-1');

      expect(() => decryptWithPrivateKey(encrypted, keyPair.privateKey, 'context-2')).toThrow();
    });
  });

  describe('encryptCredentialBlob / decryptCredentialBlob', () => {
    it('should encrypt and decrypt credential data', () => {
      const keyPair = generateX25519KeyPair();
      const credential = Buffer.from(JSON.stringify({
        guid: 'test-guid',
        passwordHash: '$hash',
        policies: { ttlHours: 24 },
      }));

      const encrypted = encryptCredentialBlob(credential, keyPair.publicKey);
      const decrypted = decryptCredentialBlob(encrypted, keyPair.privateKey);

      const parsed = JSON.parse(decrypted.toString());
      expect(parsed.guid).toBe('test-guid');
    });

    it('should use credential-specific context', () => {
      const keyPair = generateX25519KeyPair();
      const data = Buffer.from('test');

      // Encrypt with credential context
      const encrypted = encryptCredentialBlob(data, keyPair.publicKey);

      // Should decrypt with default credential context
      const decrypted = decryptCredentialBlob(encrypted, keyPair.privateKey);
      expect(decrypted.toString()).toBe('test');
    });
  });

  describe('encryptWithTransactionKey / decryptWithTransactionKey', () => {
    it('should encrypt and decrypt transaction data', () => {
      const keyPair = generateX25519KeyPair();
      const password = Buffer.from('my-secret-password');

      const encrypted = encryptWithTransactionKey(password, keyPair.publicKey);
      const decrypted = decryptWithTransactionKey(encrypted, keyPair.privateKey);

      expect(decrypted.toString()).toBe('my-secret-password');
    });

    it('should use transaction-specific context', () => {
      const keyPair = generateX25519KeyPair();
      const data = Buffer.from('password');

      // Encrypt with transaction context
      const encrypted = encryptWithTransactionKey(data, keyPair.publicKey);

      // Should NOT decrypt with credential context (different context)
      expect(() => decryptWithPrivateKey(encrypted, keyPair.privateKey, 'credential-encryption-v1')).toThrow();

      // Should decrypt with transaction context
      const decrypted = decryptWithTransactionKey(encrypted, keyPair.privateKey);
      expect(decrypted.toString()).toBe('password');
    });
  });
});

// ============================================
// Password Hashing Tests (Argon2id)
// ============================================

describe('Password Hashing (Argon2id)', () => {
  describe('hashPassword', () => {
    it('should return Argon2id PHC-formatted hash string', async () => {
      const hash = await hashPassword('test-password');

      // Argon2id format: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
      expect(hash).toMatch(/^\$argon2id\$/);
      expect(hash).toContain('$v=19$');
      expect(hash).toContain('m=65536');
      expect(hash).toContain('t=3');
      expect(hash).toContain('p=4');
    });

    it('should produce different hash for same password (random salt)', async () => {
      const hash1 = await hashPassword('test-password');
      const hash2 = await hashPassword('test-password');

      expect(hash1).not.toBe(hash2);
    });

    it('should produce hash with expected components', async () => {
      const hash = await hashPassword('test');
      const parts = hash.split('$').filter(Boolean);

      // Format: argon2id$v=19$m=65536,t=3,p=4$salt$hash
      expect(parts.length).toBe(5);
      expect(parts[0]).toBe('argon2id');
      expect(parts[1]).toBe('v=19');
      expect(parts[2]).toMatch(/^m=\d+,t=\d+,p=\d+$/);
    });
  });

  describe('verifyPassword', () => {
    it('should verify correct password', async () => {
      const password = 'correct-password';
      const hash = await hashPassword(password);

      const result = await verifyPassword(hash, password);

      expect(result).toBe(true);
    });

    it('should reject incorrect password', async () => {
      const hash = await hashPassword('correct-password');

      const result = await verifyPassword(hash, 'wrong-password');

      expect(result).toBe(false);
    });

    it('should handle empty password', async () => {
      const hash = await hashPassword('');

      const correctResult = await verifyPassword(hash, '');
      const wrongResult = await verifyPassword(hash, 'non-empty');

      expect(correctResult).toBe(true);
      expect(wrongResult).toBe(false);
    });

    it('should reject password with extra/missing characters', async () => {
      const hash = await hashPassword('password123');

      const missingChar = await verifyPassword(hash, 'password12');
      const extraChar = await verifyPassword(hash, 'password1234');
      const wrongChar = await verifyPassword(hash, 'password124');

      expect(missingChar).toBe(false);
      expect(extraChar).toBe(false);
      expect(wrongChar).toBe(false);
    });

    it('should throw for unsupported hash format', async () => {
      await expect(verifyPassword('$unsupported$v=1$salt$hash', 'test')).rejects.toThrow('Unsupported hash format');
    });

    it('should verify legacy PBKDF2 hash', async () => {
      // Legacy format: $pbkdf2-sha256$i=100000$<salt>$<hash>
      // This hash was generated for password 'test-password' with known salt
      const { pbkdf2Sync } = await import('crypto');
      const salt = Buffer.from('testsalt12345678');
      const hash = pbkdf2Sync('legacy-password', salt, 100000, 32, 'sha256');
      const legacyHash = `$pbkdf2-sha256$i=100000$${salt.toString('base64')}$${hash.toString('base64')}`;

      const result = await verifyPassword(legacyHash, 'legacy-password');
      expect(result).toBe(true);
    });
  });

  describe('needsRehash', () => {
    it('should return false for Argon2id hash', async () => {
      const hash = await hashPassword('test');
      expect(needsRehash(hash)).toBe(false);
    });

    it('should return true for PBKDF2 hash', () => {
      const pbkdf2Hash = '$pbkdf2-sha256$i=100000$salt$hash';
      expect(needsRehash(pbkdf2Hash)).toBe(true);
    });

    it('should return true for argon2i (not argon2id)', () => {
      const argon2iHash = '$argon2i$v=19$m=65536$salt$hash';
      expect(needsRehash(argon2iHash)).toBe(true);
    });
  });
});

// ============================================
// LAT (Ledger Authentication Token) Tests
// ============================================

describe('LAT Generation and Verification', () => {
  describe('generateLAT', () => {
    it('should generate LAT with 64-character hex token', () => {
      const lat = generateLAT();

      expect(lat.token).toMatch(/^[0-9a-f]{64}$/);
      expect(lat.token.length).toBe(64);
    });

    it('should generate LAT with specified version', () => {
      const lat1 = generateLAT(1);
      const lat5 = generateLAT(5);

      expect(lat1.version).toBe(1);
      expect(lat5.version).toBe(5);
    });

    it('should default to version 1', () => {
      const lat = generateLAT();

      expect(lat.version).toBe(1);
    });

    it('should generate unique tokens', () => {
      const tokens = Array.from({ length: 100 }, () => generateLAT().token);
      const uniqueTokens = new Set(tokens);

      expect(uniqueTokens.size).toBe(100);
    });
  });

  describe('hashLATToken', () => {
    it('should return 64-character hex hash', () => {
      const lat = generateLAT();
      const hash = hashLATToken(lat.token);

      expect(hash).toMatch(/^[0-9a-f]{64}$/);
      expect(hash.length).toBe(64);
    });

    it('should produce different hash from original token', () => {
      const lat = generateLAT();
      const hash = hashLATToken(lat.token);

      expect(hash).not.toBe(lat.token);
    });

    it('should produce same hash for same token', () => {
      const token = 'a'.repeat(64);

      const hash1 = hashLATToken(token);
      const hash2 = hashLATToken(token);

      expect(hash1).toBe(hash2);
    });

    it('should produce different hash for different tokens', () => {
      const hash1 = hashLATToken('a'.repeat(64));
      const hash2 = hashLATToken('b'.repeat(64));

      expect(hash1).not.toBe(hash2);
    });
  });

  describe('verifyLATToken', () => {
    it('should verify matching token and hash', () => {
      const lat = generateLAT();
      const storedHash = hashLATToken(lat.token);

      const result = verifyLATToken(lat.token, storedHash);

      expect(result).toBe(true);
    });

    it('should reject non-matching token', () => {
      const lat = generateLAT();
      const storedHash = hashLATToken(lat.token);
      const wrongToken = generateLAT().token;

      const result = verifyLATToken(wrongToken, storedHash);

      expect(result).toBe(false);
    });

    it('should reject modified token', () => {
      const lat = generateLAT();
      const storedHash = hashLATToken(lat.token);

      // Flip one character
      const modifiedToken = lat.token.charAt(0) === '0'
        ? '1' + lat.token.slice(1)
        : '0' + lat.token.slice(1);

      const result = verifyLATToken(modifiedToken, storedHash);

      expect(result).toBe(false);
    });
  });
});

// ============================================
// Transaction Key Pool Tests
// ============================================

describe('Transaction Key Pool', () => {
  describe('generateTransactionKeyPool', () => {
    it('should generate requested number of keys', () => {
      const pool5 = generateTransactionKeyPool(5);
      const pool20 = generateTransactionKeyPool(20);

      expect(pool5.length).toBe(5);
      expect(pool20.length).toBe(20);
    });

    it('should generate keys with tk_ prefix', () => {
      const pool = generateTransactionKeyPool(5);

      pool.forEach(key => {
        expect(key.keyId).toMatch(/^tk_[0-9a-f]{16}$/);
      });
    });

    it('should generate 32-byte key pairs', () => {
      const pool = generateTransactionKeyPool(5);

      pool.forEach(key => {
        expect(key.publicKey.length).toBe(32);
        expect(key.privateKey.length).toBe(32);
      });
    });

    it('should set algorithm to X25519', () => {
      const pool = generateTransactionKeyPool(5);

      pool.forEach(key => {
        expect(key.algorithm).toBe('X25519');
      });
    });

    it('should generate unique key IDs', () => {
      const pool = generateTransactionKeyPool(100);
      const keyIds = new Set(pool.map(k => k.keyId));

      expect(keyIds.size).toBe(100);
    });

    it('should generate unique key pairs', () => {
      const pool = generateTransactionKeyPool(100);
      const publicKeys = new Set(pool.map(k => k.publicKey.toString('hex')));

      expect(publicKeys.size).toBe(100);
    });

    it('should work with pool for ECDH operations', () => {
      const pool = generateTransactionKeyPool(1);
      const tk = pool[0];

      // Encrypt with public key
      const plaintext = Buffer.from('test password');
      const encrypted = encryptWithTransactionKey(plaintext, tk.publicKey);

      // Decrypt with private key
      const decrypted = decryptWithTransactionKey(encrypted, tk.privateKey);

      expect(decrypted.toString()).toBe('test password');
    });
  });
});

// ============================================
// Serialization Tests
// ============================================

describe('Serialization Helpers', () => {
  describe('serializeEncryptedBlob / deserializeEncryptedBlob', () => {
    it('should serialize to base64 strings', () => {
      const keyPair = generateX25519KeyPair();
      const encrypted = encryptWithPublicKey(Buffer.from('test'), keyPair.publicKey);

      const serialized = serializeEncryptedBlob(encrypted);

      expect(typeof serialized.ciphertext).toBe('string');
      expect(typeof serialized.nonce).toBe('string');
      expect(typeof serialized.ephemeral_public_key).toBe('string');
    });

    it('should deserialize back to buffers', () => {
      const keyPair = generateX25519KeyPair();
      const original = encryptWithPublicKey(Buffer.from('test'), keyPair.publicKey);

      const serialized = serializeEncryptedBlob(original);
      const deserialized = deserializeEncryptedBlob(serialized);

      expect(deserialized.ciphertext).toBeInstanceOf(Buffer);
      expect(deserialized.nonce).toBeInstanceOf(Buffer);
      expect(deserialized.ephemeralPublicKey).toBeInstanceOf(Buffer);
    });

    it('should roundtrip correctly', () => {
      const keyPair = generateX25519KeyPair();
      const plaintext = Buffer.from('Hello, World!');
      const original = encryptWithPublicKey(plaintext, keyPair.publicKey);

      const serialized = serializeEncryptedBlob(original);
      const deserialized = deserializeEncryptedBlob(serialized);
      const decrypted = decryptWithPrivateKey(deserialized, keyPair.privateKey);

      expect(decrypted.toString()).toBe('Hello, World!');
    });

    it('should be JSON-serializable', () => {
      const keyPair = generateX25519KeyPair();
      const encrypted = encryptWithPublicKey(Buffer.from('test'), keyPair.publicKey);

      const serialized = serializeEncryptedBlob(encrypted);
      const jsonStr = JSON.stringify(serialized);
      const parsed = JSON.parse(jsonStr);
      const deserialized = deserializeEncryptedBlob(parsed);

      const decrypted = decryptWithPrivateKey(deserialized, keyPair.privateKey);
      expect(decrypted.toString()).toBe('test');
    });
  });

  describe('packEncryptedBlob / unpackEncryptedBlob', () => {
    it('should pack into contiguous buffer', () => {
      const keyPair = generateX25519KeyPair();
      const encrypted = encryptWithPublicKey(Buffer.from('test'), keyPair.publicKey);

      const packed = packEncryptedBlob(encrypted);

      // 12 (nonce) + 32 (ephemeral) + ciphertext length
      const expectedLength = 12 + 32 + encrypted.ciphertext.length;
      expect(packed.length).toBe(expectedLength);
    });

    it('should unpack correctly', () => {
      const keyPair = generateX25519KeyPair();
      const original = encryptWithPublicKey(Buffer.from('test'), keyPair.publicKey);

      const packed = packEncryptedBlob(original);
      const unpacked = unpackEncryptedBlob(packed);

      expect(unpacked.nonce.equals(original.nonce)).toBe(true);
      expect(unpacked.ephemeralPublicKey.equals(original.ephemeralPublicKey)).toBe(true);
      expect(unpacked.ciphertext.equals(original.ciphertext)).toBe(true);
    });

    it('should roundtrip pack/unpack correctly', () => {
      const keyPair = generateX25519KeyPair();
      const plaintext = Buffer.from('Hello, World!');
      const original = encryptWithPublicKey(plaintext, keyPair.publicKey);

      const packed = packEncryptedBlob(original);
      const unpacked = unpackEncryptedBlob(packed);
      const decrypted = decryptWithPrivateKey(unpacked, keyPair.privateKey);

      expect(decrypted.toString()).toBe('Hello, World!');
    });

    it('should support custom nonce length', () => {
      // Create a blob with non-standard nonce length (for XChaCha20)
      const nonce = Buffer.alloc(24, 0x11); // 24-byte nonce
      const ephemeralPublicKey = Buffer.alloc(32, 0x22);
      const ciphertext = Buffer.alloc(100, 0x33);

      const packed = Buffer.concat([nonce, ephemeralPublicKey, ciphertext]);
      const unpacked = unpackEncryptedBlob(packed, 24);

      expect(unpacked.nonce.length).toBe(24);
      expect(unpacked.ephemeralPublicKey.length).toBe(32);
      expect(unpacked.ciphertext.length).toBe(100);
    });
  });
});

// ============================================
// Security Property Tests
// ============================================

describe('Security Properties', () => {
  describe('Forward Secrecy', () => {
    it('should use unique ephemeral key per encryption', () => {
      const keyPair = generateX25519KeyPair();
      const plaintext = Buffer.from('same message');

      const encrypted1 = encryptWithPublicKey(plaintext, keyPair.publicKey);
      const encrypted2 = encryptWithPublicKey(plaintext, keyPair.publicKey);

      // Ephemeral keys should be different
      expect(encrypted1.ephemeralPublicKey.equals(encrypted2.ephemeralPublicKey)).toBe(false);
    });

    it('should produce unpredictable ciphertext', () => {
      const keyPair = generateX25519KeyPair();
      const plaintext = Buffer.from('predictable input');

      const ciphertexts = Array.from({ length: 10 }, () =>
        encryptWithPublicKey(plaintext, keyPair.publicKey).ciphertext.toString('hex')
      );
      const unique = new Set(ciphertexts);

      expect(unique.size).toBe(10);
    });
  });

  describe('Key Material Sensitivity', () => {
    it('should have distinct public and private keys', () => {
      const keyPair = generateX25519KeyPair();

      expect(keyPair.publicKey.equals(keyPair.privateKey)).toBe(false);
    });

    it('should not expose private key in encryption output', () => {
      const keyPair = generateX25519KeyPair();
      const plaintext = Buffer.from('test');

      const encrypted = encryptWithPublicKey(plaintext, keyPair.publicKey);

      // Ephemeral public key should be different from recipient's keys
      expect(encrypted.ephemeralPublicKey.equals(keyPair.publicKey)).toBe(false);
      expect(encrypted.ephemeralPublicKey.equals(keyPair.privateKey)).toBe(false);
    });
  });

  describe('Nonce Uniqueness', () => {
    it('should generate unique nonces', () => {
      const keyPair = generateX25519KeyPair();
      const plaintext = Buffer.from('test');

      const nonces = Array.from({ length: 100 }, () =>
        encryptWithPublicKey(plaintext, keyPair.publicKey).nonce.toString('hex')
      );
      const unique = new Set(nonces);

      expect(unique.size).toBe(100);
    });
  });

  describe('Timing-Safe Comparison', () => {
    it('should verify LAT in constant time', () => {
      const lat = generateLAT();
      const storedHash = hashLATToken(lat.token);

      // Run multiple verifications to check for timing consistency
      const iterations = 100;
      const timings: bigint[] = [];

      for (let i = 0; i < iterations; i++) {
        const start = process.hrtime.bigint();
        verifyLATToken(lat.token, storedHash);
        timings.push(process.hrtime.bigint() - start);
      }

      // Basic statistical check - times should be relatively consistent
      const mean = timings.reduce((a, b) => a + b) / BigInt(timings.length);
      const variance = timings.reduce((acc, t) => acc + (t - mean) * (t - mean), BigInt(0)) / BigInt(timings.length);
      const stdDev = Math.sqrt(Number(variance));
      const cv = stdDev / Number(mean);

      // CV should be reasonable (timing variations exist but should be bounded)
      expect(cv).toBeLessThan(2.0);
    });
  });
});

// ============================================
// Edge Case Tests
// ============================================

describe('Edge Cases', () => {
  describe('Empty Data Handling', () => {
    it('should encrypt and decrypt empty buffer', () => {
      const keyPair = generateX25519KeyPair();
      const empty = Buffer.alloc(0);

      const encrypted = encryptWithPublicKey(empty, keyPair.publicKey);
      const decrypted = decryptWithPrivateKey(encrypted, keyPair.privateKey);

      expect(decrypted.length).toBe(0);
    });

    it('should hash empty password', async () => {
      const hash = await hashPassword('');
      expect(hash).toMatch(/^\$argon2id\$/);
    });
  });

  describe('Large Data Handling', () => {
    it('should encrypt and decrypt 1MB data', () => {
      const keyPair = generateX25519KeyPair();
      const largeData = Buffer.alloc(1024 * 1024, 0x42);

      const encrypted = encryptWithPublicKey(largeData, keyPair.publicKey);
      const decrypted = decryptWithPrivateKey(encrypted, keyPair.privateKey);

      expect(decrypted.equals(largeData)).toBe(true);
    });

    it('should derive long HKDF output', () => {
      const ikm = Buffer.alloc(32, 0x42);
      const key = hkdf(ikm, 1024, 'test');

      expect(key.length).toBe(1024);
    });
  });

  describe('Unicode Handling', () => {
    it('should encrypt and decrypt unicode data', () => {
      const keyPair = generateX25519KeyPair();
      const unicode = Buffer.from('Hello, 世界! 🔐');

      const encrypted = encryptWithPublicKey(unicode, keyPair.publicKey);
      const decrypted = decryptWithPrivateKey(encrypted, keyPair.privateKey);

      expect(decrypted.toString()).toBe('Hello, 世界! 🔐');
    });

    it('should hash unicode password', async () => {
      const password = 'пароль123🔑';
      const hash = await hashPassword(password);

      const result = await verifyPassword(hash, password);
      expect(result).toBe(true);
    });
  });
});

// ============================================
// Ed25519 Signing Tests
// ============================================

describe('Ed25519 Signing', () => {
  describe('generateEd25519KeyPair', () => {
    it('should generate valid 32-byte public key', () => {
      const keyPair = generateEd25519KeyPair();

      expect(keyPair.publicKey).toBeInstanceOf(Buffer);
      expect(keyPair.publicKey.length).toBe(32);
    });

    it('should generate valid 32-byte private key (seed)', () => {
      const keyPair = generateEd25519KeyPair();

      expect(keyPair.privateKey).toBeInstanceOf(Buffer);
      expect(keyPair.privateKey.length).toBe(32);
    });

    it('should generate unique key pairs', () => {
      const keyPair1 = generateEd25519KeyPair();
      const keyPair2 = generateEd25519KeyPair();

      expect(keyPair1.publicKey.equals(keyPair2.publicKey)).toBe(false);
      expect(keyPair1.privateKey.equals(keyPair2.privateKey)).toBe(false);
    });

    it('should generate cryptographically random keys', () => {
      const keyPairs = Array.from({ length: 100 }, () => generateEd25519KeyPair());
      const publicKeys = new Set(keyPairs.map(kp => kp.publicKey.toString('hex')));

      expect(publicKeys.size).toBe(100);
    });
  });

  describe('signMessage / verifySignature', () => {
    it('should sign and verify a message', () => {
      const keyPair = generateEd25519KeyPair();
      const message = Buffer.from('Hello, World!');

      const signature = signMessage(message, keyPair.privateKey);
      const valid = verifySignature(message, signature, keyPair.publicKey);

      expect(valid).toBe(true);
    });

    it('should produce 64-byte signature', () => {
      const keyPair = generateEd25519KeyPair();
      const message = Buffer.from('Test message');

      const signature = signMessage(message, keyPair.privateKey);

      expect(signature.length).toBe(64);
    });

    it('should reject tampered message', () => {
      const keyPair = generateEd25519KeyPair();
      const message = Buffer.from('Original message');
      const tamperedMessage = Buffer.from('Tampered message');

      const signature = signMessage(message, keyPair.privateKey);
      const valid = verifySignature(tamperedMessage, signature, keyPair.publicKey);

      expect(valid).toBe(false);
    });

    it('should reject wrong public key', () => {
      const keyPair1 = generateEd25519KeyPair();
      const keyPair2 = generateEd25519KeyPair();
      const message = Buffer.from('Test message');

      const signature = signMessage(message, keyPair1.privateKey);
      const valid = verifySignature(message, signature, keyPair2.publicKey);

      expect(valid).toBe(false);
    });

    it('should reject modified signature', () => {
      const keyPair = generateEd25519KeyPair();
      const message = Buffer.from('Test message');

      const signature = signMessage(message, keyPair.privateKey);
      signature[0] ^= 0xff; // Flip bits in signature

      const valid = verifySignature(message, signature, keyPair.publicKey);

      expect(valid).toBe(false);
    });

    it('should be deterministic for same key and message', () => {
      const keyPair = generateEd25519KeyPair();
      const message = Buffer.from('Same message');

      const signature1 = signMessage(message, keyPair.privateKey);
      const signature2 = signMessage(message, keyPair.privateKey);

      expect(signature1.equals(signature2)).toBe(true);
    });

    it('should produce different signatures for different messages', () => {
      const keyPair = generateEd25519KeyPair();
      const message1 = Buffer.from('Message 1');
      const message2 = Buffer.from('Message 2');

      const signature1 = signMessage(message1, keyPair.privateKey);
      const signature2 = signMessage(message2, keyPair.privateKey);

      expect(signature1.equals(signature2)).toBe(false);
    });

    it('should handle empty message', () => {
      const keyPair = generateEd25519KeyPair();
      const empty = Buffer.alloc(0);

      const signature = signMessage(empty, keyPair.privateKey);
      const valid = verifySignature(empty, signature, keyPair.publicKey);

      expect(valid).toBe(true);
    });

    it('should handle large message', () => {
      const keyPair = generateEd25519KeyPair();
      const large = Buffer.alloc(1024 * 1024, 0x42);

      const signature = signMessage(large, keyPair.privateKey);
      const valid = verifySignature(large, signature, keyPair.publicKey);

      expect(valid).toBe(true);
    });
  });

  describe('signPayload / verifySignedPayload', () => {
    it('should sign and verify JSON payload', () => {
      const keyPair = generateEd25519KeyPair();
      const payload = { action: 'transfer', amount: 100 };

      const signed = signPayload(payload, keyPair.privateKey);
      const valid = verifySignedPayload(signed, keyPair.publicKey);

      expect(valid).toBe(true);
    });

    it('should include timestamp in payload', () => {
      const keyPair = generateEd25519KeyPair();
      const payload = { test: 'data' };

      const signed = signPayload(payload, keyPair.privateKey);

      expect(signed.timestamp).toBeDefined();
      expect(signed.payload.timestamp).toBe(signed.timestamp);
    });

    it('should include base64 signature', () => {
      const keyPair = generateEd25519KeyPair();
      const payload = { test: 'data' };

      const signed = signPayload(payload, keyPair.privateKey);

      // Should be valid base64
      expect(() => Buffer.from(signed.signature, 'base64')).not.toThrow();
      // Decoded should be 64 bytes
      expect(Buffer.from(signed.signature, 'base64').length).toBe(64);
    });

    it('should reject tampered payload', () => {
      const keyPair = generateEd25519KeyPair();
      const payload = { amount: 100 };

      const signed = signPayload(payload, keyPair.privateKey);
      signed.payload.amount = 1000; // Tamper with payload

      const valid = verifySignedPayload(signed, keyPair.publicKey);

      expect(valid).toBe(false);
    });

    it('should reject expired timestamp', () => {
      const keyPair = generateEd25519KeyPair();
      const payload = { test: 'data' };

      const signed = signPayload(payload, keyPair.privateKey);
      // Set timestamp to 10 minutes ago
      const oldTime = new Date(Date.now() - 10 * 60 * 1000).toISOString();
      signed.timestamp = oldTime;
      signed.payload.timestamp = oldTime;
      // Re-sign with old timestamp
      const message = Buffer.from(JSON.stringify(signed.payload), 'utf8');
      signed.signature = signMessage(message, keyPair.privateKey).toString('base64');

      // Default maxAge is 5 minutes
      const valid = verifySignedPayload(signed, keyPair.publicKey);

      expect(valid).toBe(false);
    });

    it('should accept timestamp within maxAge', () => {
      const keyPair = generateEd25519KeyPair();
      const payload = { test: 'data' };

      const signed = signPayload(payload, keyPair.privateKey);
      // Use longer maxAge (10 minutes)
      const valid = verifySignedPayload(signed, keyPair.publicKey, 10 * 60 * 1000);

      expect(valid).toBe(true);
    });

    it('should reject future timestamp', () => {
      const keyPair = generateEd25519KeyPair();
      const payload = { test: 'data' };

      const signed = signPayload(payload, keyPair.privateKey);
      // Set timestamp to 10 minutes in future
      const futureTime = new Date(Date.now() + 10 * 60 * 1000).toISOString();
      signed.timestamp = futureTime;
      signed.payload.timestamp = futureTime;
      // Re-sign with future timestamp
      const message = Buffer.from(JSON.stringify(signed.payload), 'utf8');
      signed.signature = signMessage(message, keyPair.privateKey).toString('base64');

      const valid = verifySignedPayload(signed, keyPair.publicKey);

      expect(valid).toBe(false);
    });
  });

  describe('generateChallenge', () => {
    it('should generate 64-character hex challenge (32 bytes)', () => {
      const challenge = generateChallenge();

      expect(challenge).toMatch(/^[0-9a-f]{64}$/);
      expect(challenge.length).toBe(64);
    });

    it('should support custom length', () => {
      const challenge16 = generateChallenge(16);
      const challenge64 = generateChallenge(64);

      expect(challenge16.length).toBe(32); // 16 bytes = 32 hex chars
      expect(challenge64.length).toBe(128); // 64 bytes = 128 hex chars
    });

    it('should generate unique challenges', () => {
      const challenges = Array.from({ length: 100 }, () => generateChallenge());
      const unique = new Set(challenges);

      expect(unique.size).toBe(100);
    });
  });

  describe('signChallengeResponse / verifyChallengeResponse', () => {
    it('should sign and verify challenge response', () => {
      const keyPair = generateEd25519KeyPair();
      const challenge = generateChallenge();
      const data = { deviceId: 'device-123', timestamp: Date.now() };

      const response = signChallengeResponse(challenge, data, keyPair.privateKey);
      const valid = verifyChallengeResponse(response, keyPair.publicKey);

      expect(valid).toBe(true);
    });

    it('should include original challenge in response', () => {
      const keyPair = generateEd25519KeyPair();
      const challenge = generateChallenge();
      const data = { test: 'value' };

      const response = signChallengeResponse(challenge, data, keyPair.privateKey);

      expect(response.challenge).toBe(challenge);
    });

    it('should include original data in response', () => {
      const keyPair = generateEd25519KeyPair();
      const challenge = generateChallenge();
      const data = { foo: 'bar', num: 42 };

      const response = signChallengeResponse(challenge, data, keyPair.privateKey);

      expect(response.data).toEqual(data);
    });

    it('should reject wrong challenge', () => {
      const keyPair = generateEd25519KeyPair();
      const challenge = generateChallenge();
      const wrongChallenge = generateChallenge();
      const data = { test: 'value' };

      const response = signChallengeResponse(challenge, data, keyPair.privateKey);
      response.challenge = wrongChallenge; // Replace with wrong challenge

      const valid = verifyChallengeResponse(response, keyPair.publicKey);

      expect(valid).toBe(false);
    });

    it('should reject modified data', () => {
      const keyPair = generateEd25519KeyPair();
      const challenge = generateChallenge();
      const data = { amount: 100 };

      const response = signChallengeResponse(challenge, data, keyPair.privateKey);
      response.data.amount = 1000; // Tamper with data

      const valid = verifyChallengeResponse(response, keyPair.publicKey);

      expect(valid).toBe(false);
    });

    it('should reject wrong public key', () => {
      const keyPair1 = generateEd25519KeyPair();
      const keyPair2 = generateEd25519KeyPair();
      const challenge = generateChallenge();
      const data = { test: 'value' };

      const response = signChallengeResponse(challenge, data, keyPair1.privateKey);
      const valid = verifyChallengeResponse(response, keyPair2.publicKey);

      expect(valid).toBe(false);
    });
  });
});
