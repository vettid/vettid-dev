/**
 * Credential encryption/decryption tests
 * Tests for X25519 + ChaCha20-Poly1305 operations
 */

import {
  generateX25519KeyPair,
  deriveSharedSecret,
  deriveKey,
  encrypt,
  decrypt,
  encryptCredentialBlob,
  decryptCredentialBlob,
  DecryptedCredential
} from '../../utils/cryptoTestUtils';

describe('X25519 Key Exchange', () => {
  test('should generate valid key pairs', () => {
    const keyPair = generateX25519KeyPair();

    expect(keyPair.publicKey).toBeInstanceOf(Buffer);
    expect(keyPair.privateKey).toBeInstanceOf(Buffer);
    expect(keyPair.publicKey.length).toBe(32);
    expect(keyPair.privateKey.length).toBe(32);
  });

  test('should generate unique key pairs', () => {
    const keyPair1 = generateX25519KeyPair();
    const keyPair2 = generateX25519KeyPair();

    expect(keyPair1.publicKey.equals(keyPair2.publicKey)).toBe(false);
    expect(keyPair1.privateKey.equals(keyPair2.privateKey)).toBe(false);
  });

  test('should derive same shared secret from both sides', () => {
    const alice = generateX25519KeyPair();
    const bob = generateX25519KeyPair();

    const aliceShared = deriveSharedSecret(alice.privateKey, bob.publicKey);
    const bobShared = deriveSharedSecret(bob.privateKey, alice.publicKey);

    expect(aliceShared.equals(bobShared)).toBe(true);
    expect(aliceShared.length).toBe(32);
  });
});

describe('HKDF Key Derivation', () => {
  test('should derive key of correct length', () => {
    const sharedSecret = Buffer.alloc(32, 0x42);
    const key = deriveKey(sharedSecret, 'test-info', 32);

    expect(key).toBeInstanceOf(Buffer);
    expect(key.length).toBe(32);
  });

  test('should produce different keys for different info strings', () => {
    const sharedSecret = Buffer.alloc(32, 0x42);
    const key1 = deriveKey(sharedSecret, 'info-1');
    const key2 = deriveKey(sharedSecret, 'info-2');

    expect(key1.equals(key2)).toBe(false);
  });

  test('should produce same key for same inputs', () => {
    const sharedSecret = Buffer.alloc(32, 0x42);
    const key1 = deriveKey(sharedSecret, 'test-info');
    const key2 = deriveKey(sharedSecret, 'test-info');

    expect(key1.equals(key2)).toBe(true);
  });
});

describe('ChaCha20-Poly1305 Encryption', () => {
  test('should encrypt and decrypt data correctly', () => {
    const key = Buffer.alloc(32, 0x42);
    const plaintext = Buffer.from('Hello, World!');

    const encrypted = encrypt(plaintext, key);
    const decrypted = decrypt(encrypted, key);

    expect(decrypted.toString()).toBe('Hello, World!');
  });

  test('should produce different ciphertext for same plaintext (random nonce)', () => {
    const key = Buffer.alloc(32, 0x42);
    const plaintext = Buffer.from('Hello, World!');

    const encrypted1 = encrypt(plaintext, key);
    const encrypted2 = encrypt(plaintext, key);

    expect(encrypted1.nonce.equals(encrypted2.nonce)).toBe(false);
    expect(encrypted1.ciphertext.equals(encrypted2.ciphertext)).toBe(false);
  });

  test('should fail decryption with wrong key', () => {
    const key1 = Buffer.alloc(32, 0x42);
    const key2 = Buffer.alloc(32, 0x43);
    const plaintext = Buffer.from('Hello, World!');

    const encrypted = encrypt(plaintext, key1);

    expect(() => decrypt(encrypted, key2)).toThrow();
  });

  test('should fail decryption with modified ciphertext', () => {
    const key = Buffer.alloc(32, 0x42);
    const plaintext = Buffer.from('Hello, World!');

    const encrypted = encrypt(plaintext, key);
    encrypted.ciphertext[0] ^= 0xff; // Flip bits

    expect(() => decrypt(encrypted, key)).toThrow();
  });

  test('should fail decryption with modified tag', () => {
    const key = Buffer.alloc(32, 0x42);
    const plaintext = Buffer.from('Hello, World!');

    const encrypted = encrypt(plaintext, key);
    encrypted.tag[0] ^= 0xff; // Flip bits

    expect(() => decrypt(encrypted, key)).toThrow();
  });
});

describe('Credential Blob Encryption', () => {
  const sampleCredential: DecryptedCredential = {
    guid: '550e8400-e29b-41d4-a716-446655440000',
    passwordHash: '$test$v=1$salt$hash',
    hashAlgorithm: 'argon2id',
    hashVersion: '1.0',
    policies: {
      ttlHours: 24,
      maxFailedAttempts: 3
    },
    secrets: {
      vaultAccessKey: 'test-key',
      customSecrets: { pin: '1234' }
    }
  };

  test('should encrypt and decrypt credential blob', () => {
    const keyPair = generateX25519KeyPair();

    const encrypted = encryptCredentialBlob(sampleCredential, keyPair.publicKey);
    const decrypted = decryptCredentialBlob(encrypted, keyPair.privateKey);

    expect(decrypted.guid).toBe(sampleCredential.guid);
    expect(decrypted.passwordHash).toBe(sampleCredential.passwordHash);
    expect(decrypted.secrets.vaultAccessKey).toBe(sampleCredential.secrets.vaultAccessKey);
  });

  test('should include correct metadata in encrypted blob', () => {
    const keyPair = generateX25519KeyPair();

    const encrypted = encryptCredentialBlob(sampleCredential, keyPair.publicKey);

    expect(encrypted.userGuid).toBe(sampleCredential.guid);
    expect(encrypted.cekVersion).toBe(1);
    expect(encrypted.ephemeralPublicKey).toBeTruthy();
    expect(encrypted.encryptedBlob).toBeTruthy();
  });

  test('should produce different encrypted blob each time (ephemeral key)', () => {
    const keyPair = generateX25519KeyPair();

    const encrypted1 = encryptCredentialBlob(sampleCredential, keyPair.publicKey);
    const encrypted2 = encryptCredentialBlob(sampleCredential, keyPair.publicKey);

    expect(encrypted1.ephemeralPublicKey).not.toBe(encrypted2.ephemeralPublicKey);
    expect(encrypted1.encryptedBlob).not.toBe(encrypted2.encryptedBlob);
  });

  test('should fail decryption with wrong private key', () => {
    const keyPair1 = generateX25519KeyPair();
    const keyPair2 = generateX25519KeyPair();

    const encrypted = encryptCredentialBlob(sampleCredential, keyPair1.publicKey);

    expect(() => decryptCredentialBlob(encrypted, keyPair2.privateKey)).toThrow();
  });
});
