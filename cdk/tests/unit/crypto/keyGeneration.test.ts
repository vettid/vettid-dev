/**
 * Key generation tests
 * Tests for LAT and transaction key generation
 */

import {
  generateLAT,
  verifyLAT,
  generateTransactionKeyPool,
  generateX25519KeyPair,
  LAT
} from '../../utils/cryptoTestUtils';

describe('LAT (Ledger Authentication Token)', () => {
  test('should generate valid LAT', () => {
    const lat = generateLAT();

    expect(lat.token).toBeTruthy();
    expect(lat.token.length).toBe(64); // 32 bytes = 64 hex chars
    expect(lat.version).toBe(1);
  });

  test('should generate unique tokens', () => {
    const lat1 = generateLAT();
    const lat2 = generateLAT();

    expect(lat1.token).not.toBe(lat2.token);
  });

  test('should respect version parameter', () => {
    const lat = generateLAT(42);

    expect(lat.version).toBe(42);
  });

  test('should verify matching LATs', () => {
    const lat = generateLAT();
    const copy: LAT = { token: lat.token, version: lat.version };

    expect(verifyLAT(copy, lat)).toBe(true);
  });

  test('should reject LAT with wrong token', () => {
    const lat1 = generateLAT();
    const lat2 = generateLAT();
    lat2.version = lat1.version; // Same version, different token

    expect(verifyLAT(lat2, lat1)).toBe(false);
  });

  test('should reject LAT with wrong version', () => {
    const lat = generateLAT();
    const copy: LAT = { token: lat.token, version: lat.version + 1 };

    expect(verifyLAT(copy, lat)).toBe(false);
  });

  test('should use constant-time comparison', () => {
    // This test verifies the structure but can't directly test timing
    const lat1 = generateLAT();
    const lat2: LAT = { token: lat1.token, version: lat1.version };

    // Should not throw
    expect(() => verifyLAT(lat2, lat1)).not.toThrow();
  });
});

describe('Transaction Key Pool', () => {
  test('should generate correct number of keys', () => {
    const keys = generateTransactionKeyPool(20);

    expect(keys.length).toBe(20);
  });

  test('should generate keys with correct structure', () => {
    const keys = generateTransactionKeyPool(1);
    const key = keys[0];

    expect(key.keyId).toMatch(/^tk_[a-f0-9]{32}$/);
    expect(key.publicKey).toBeTruthy();
    expect(key.algorithm).toBe('X25519');
    expect(key.createdAt).toBeTruthy();

    // Verify public key is base64-encoded and correct length
    const decoded = Buffer.from(key.publicKey, 'base64');
    expect(decoded.length).toBe(32);
  });

  test('should generate unique key IDs', () => {
    const keys = generateTransactionKeyPool(100);
    const keyIds = keys.map(k => k.keyId);
    const uniqueIds = new Set(keyIds);

    expect(uniqueIds.size).toBe(100);
  });

  test('should generate unique public keys', () => {
    const keys = generateTransactionKeyPool(100);
    const publicKeys = keys.map(k => k.publicKey);
    const uniqueKeys = new Set(publicKeys);

    expect(uniqueKeys.size).toBe(100);
  });

  test('should include valid timestamps', () => {
    const before = new Date().toISOString();
    const keys = generateTransactionKeyPool(1);
    const after = new Date().toISOString();

    expect(keys[0].createdAt >= before).toBe(true);
    expect(keys[0].createdAt <= after).toBe(true);
  });

  test('should handle zero count', () => {
    const keys = generateTransactionKeyPool(0);

    expect(keys.length).toBe(0);
  });

  test('should handle large count', () => {
    const keys = generateTransactionKeyPool(1000);

    expect(keys.length).toBe(1000);
  });
});

describe('X25519 Key Pair Generation', () => {
  test('should generate valid key pairs for transaction keys', () => {
    // Generate multiple key pairs and verify they can be used
    const pairs = Array.from({ length: 10 }, () => generateX25519KeyPair());

    for (const pair of pairs) {
      expect(pair.publicKey.length).toBe(32);
      expect(pair.privateKey.length).toBe(32);
    }
  });

  test('should generate keys suitable for base64 encoding', () => {
    const keyPair = generateX25519KeyPair();

    const publicBase64 = keyPair.publicKey.toString('base64');
    const privateBase64 = keyPair.privateKey.toString('base64');

    // Should be able to decode back
    const decodedPublic = Buffer.from(publicBase64, 'base64');
    const decodedPrivate = Buffer.from(privateBase64, 'base64');

    expect(decodedPublic.equals(keyPair.publicKey)).toBe(true);
    expect(decodedPrivate.equals(keyPair.privateKey)).toBe(true);
  });
});
