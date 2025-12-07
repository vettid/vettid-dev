/**
 * Cryptographic test utilities
 * Provides helpers for testing Protean credential operations
 */

import * as crypto from 'crypto';

// ============================================
// X25519 Key Operations
// ============================================

export interface KeyPair {
  publicKey: Buffer;
  privateKey: Buffer;
}

/**
 * Generate X25519 key pair
 * Note: Node.js 18+ has native X25519 support
 */
export function generateX25519KeyPair(): KeyPair {
  const keyPair = crypto.generateKeyPairSync('x25519');

  return {
    publicKey: keyPair.publicKey.export({ type: 'spki', format: 'der' }).slice(-32),
    privateKey: keyPair.privateKey.export({ type: 'pkcs8', format: 'der' }).slice(-32)
  };
}

/**
 * Derive shared secret using X25519 ECDH
 */
export function deriveSharedSecret(
  privateKey: Buffer,
  publicKey: Buffer
): Buffer {
  // Create key objects from raw bytes
  const privateKeyObj = crypto.createPrivateKey({
    key: Buffer.concat([
      Buffer.from('302e020100300506032b656e04220420', 'hex'), // PKCS#8 header for X25519
      privateKey
    ]),
    format: 'der',
    type: 'pkcs8'
  });

  const publicKeyObj = crypto.createPublicKey({
    key: Buffer.concat([
      Buffer.from('302a300506032b656e032100', 'hex'), // SPKI header for X25519
      publicKey
    ]),
    format: 'der',
    type: 'spki'
  });

  return crypto.diffieHellman({
    privateKey: privateKeyObj,
    publicKey: publicKeyObj
  });
}

// ============================================
// HKDF Key Derivation
// ============================================

/**
 * Derive key using HKDF-SHA256
 */
export function deriveKey(
  sharedSecret: Buffer,
  info: string,
  length: number = 32
): Buffer {
  return crypto.hkdfSync('sha256', sharedSecret, Buffer.alloc(0), info, length);
}

// ============================================
// XChaCha20-Poly1305 (Simulated)
// ============================================
// Note: Node.js doesn't have native XChaCha20-Poly1305
// For production, use libsodium or tweetnacl
// This uses ChaCha20-Poly1305 for testing purposes

export interface EncryptedData {
  nonce: Buffer;
  ciphertext: Buffer;
  tag: Buffer;
}

/**
 * Encrypt data using ChaCha20-Poly1305
 * Note: For testing only - use XChaCha20-Poly1305 in production
 */
export function encrypt(
  plaintext: Buffer,
  key: Buffer
): EncryptedData {
  const nonce = crypto.randomBytes(12); // 12 bytes for ChaCha20-Poly1305

  const cipher = crypto.createCipheriv('chacha20-poly1305', key, nonce, {
    authTagLength: 16
  });

  const ciphertext = Buffer.concat([
    cipher.update(plaintext),
    cipher.final()
  ]);

  const tag = cipher.getAuthTag();

  return { nonce, ciphertext, tag };
}

/**
 * Decrypt data using ChaCha20-Poly1305
 */
export function decrypt(
  encrypted: EncryptedData,
  key: Buffer
): Buffer {
  const decipher = crypto.createDecipheriv('chacha20-poly1305', key, encrypted.nonce, {
    authTagLength: 16
  });

  decipher.setAuthTag(encrypted.tag);

  return Buffer.concat([
    decipher.update(encrypted.ciphertext),
    decipher.final()
  ]);
}

// ============================================
// Credential Blob Operations
// ============================================

export interface CredentialBlob {
  userGuid: string;
  encryptedBlob: string; // base64
  ephemeralPublicKey: string; // base64
  cekVersion: number;
}

export interface DecryptedCredential {
  guid: string;
  passwordHash: string;
  hashAlgorithm: string;
  hashVersion: string;
  policies: {
    ttlHours: number;
    maxFailedAttempts: number;
  };
  secrets: Record<string, any>;
}

/**
 * Encrypt a credential blob
 */
export function encryptCredentialBlob(
  credential: DecryptedCredential,
  recipientPublicKey: Buffer
): CredentialBlob {
  // Generate ephemeral key pair
  const ephemeral = generateX25519KeyPair();

  // Derive shared secret
  const sharedSecret = deriveSharedSecret(ephemeral.privateKey, recipientPublicKey);

  // Derive encryption key
  const encryptionKey = deriveKey(sharedSecret, 'credential-encryption-v1');

  // Encrypt credential
  const plaintext = Buffer.from(JSON.stringify(credential));
  const encrypted = encrypt(plaintext, encryptionKey);

  // Combine nonce, ciphertext, and tag
  const encryptedBlob = Buffer.concat([
    encrypted.nonce,
    encrypted.ciphertext,
    encrypted.tag
  ]);

  return {
    userGuid: credential.guid,
    encryptedBlob: encryptedBlob.toString('base64'),
    ephemeralPublicKey: ephemeral.publicKey.toString('base64'),
    cekVersion: 1
  };
}

/**
 * Decrypt a credential blob
 */
export function decryptCredentialBlob(
  blob: CredentialBlob,
  recipientPrivateKey: Buffer
): DecryptedCredential {
  const ephemeralPublicKey = Buffer.from(blob.ephemeralPublicKey, 'base64');
  const encryptedData = Buffer.from(blob.encryptedBlob, 'base64');

  // Derive shared secret
  const sharedSecret = deriveSharedSecret(recipientPrivateKey, ephemeralPublicKey);

  // Derive encryption key
  const encryptionKey = deriveKey(sharedSecret, 'credential-encryption-v1');

  // Extract nonce, ciphertext, and tag
  const nonce = encryptedData.slice(0, 12);
  const tag = encryptedData.slice(-16);
  const ciphertext = encryptedData.slice(12, -16);

  // Decrypt
  const plaintext = decrypt({ nonce, ciphertext, tag }, encryptionKey);

  return JSON.parse(plaintext.toString());
}

// ============================================
// Argon2 Password Hashing (Simulated)
// ============================================
// Note: For testing, we use a simpler hash
// In production, use argon2 or hash-wasm

/**
 * Hash password (simplified for testing)
 * In production, use Argon2id
 */
export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16);
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');

  // Return in a format similar to Argon2
  return `$test$v=1$${salt.toString('base64')}$${hash.toString('base64')}`;
}

/**
 * Verify password (simplified for testing)
 */
export function verifyPassword(hash: string, password: string): boolean {
  const parts = hash.split('$');
  if (parts.length !== 5 || parts[1] !== 'test') {
    return false;
  }

  const salt = Buffer.from(parts[3], 'base64');
  const storedHash = Buffer.from(parts[4], 'base64');
  const computedHash = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');

  return crypto.timingSafeEqual(storedHash, computedHash);
}

// ============================================
// LAT (Ledger Authentication Token)
// ============================================

export interface LAT {
  token: string;
  version: number;
}

/**
 * Generate a new LAT
 */
export function generateLAT(version: number = 1): LAT {
  const token = crypto.randomBytes(32).toString('hex');
  return { token, version };
}

/**
 * Verify LAT matches (constant-time)
 */
export function verifyLAT(received: LAT, stored: LAT): boolean {
  if (received.version !== stored.version) {
    return false;
  }

  const receivedBuffer = Buffer.from(received.token, 'hex');
  const storedBuffer = Buffer.from(stored.token, 'hex');

  if (receivedBuffer.length !== storedBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(receivedBuffer, storedBuffer);
}

// ============================================
// Transaction Keys
// ============================================

export interface TransactionKey {
  keyId: string;
  publicKey: string; // base64
  algorithm: string;
  createdAt: string;
}

/**
 * Generate transaction key pool
 */
export function generateTransactionKeyPool(count: number = 20): TransactionKey[] {
  const keys: TransactionKey[] = [];

  for (let i = 0; i < count; i++) {
    const keyPair = generateX25519KeyPair();
    keys.push({
      keyId: `tk_${crypto.randomBytes(16).toString('hex')}`,
      publicKey: keyPair.publicKey.toString('base64'),
      algorithm: 'X25519',
      createdAt: new Date().toISOString()
    });
  }

  return keys;
}
