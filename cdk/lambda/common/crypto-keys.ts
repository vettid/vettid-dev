/**
 * Cryptographic utilities for key operations (no native dependencies)
 *
 * Implements:
 * - X25519 key exchange
 * - ChaCha20-Poly1305 authenticated encryption
 * - HKDF-SHA256 key derivation
 * - Ed25519 signing
 *
 * This module has NO native dependencies and works on all Node.js versions.
 * Password hashing (argon2) is in crypto-password.ts
 *
 * @see cdk/coordination/specs/credential-format.md
 */

import {
  generateKeyPairSync,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  createHash,
  createHmac,
  randomBytes,
  createCipheriv,
  createDecipheriv,
  timingSafeEqual,
  KeyObject,
  sign,
  verify,
} from 'crypto';

// ============================================
// Types
// ============================================

export interface X25519KeyPair {
  publicKey: Buffer;   // 32 bytes raw X25519 public key
  privateKey: Buffer;  // 32 bytes raw X25519 private key
}

export interface EncryptedBlob {
  ciphertext: Buffer;        // Encrypted data with auth tag
  nonce: Buffer;             // 24-byte nonce (XChaCha20) or 12-byte (ChaCha20)
  ephemeralPublicKey: Buffer; // 32-byte X25519 public key
}

export interface TransactionKeyPair {
  keyId: string;
  publicKey: Buffer;
  privateKey: Buffer;
  algorithm: string;
}

export interface Ed25519KeyPair {
  publicKey: Buffer;   // 32 bytes raw Ed25519 public key
  privateKey: Buffer;  // 64 bytes raw Ed25519 private key (32-byte seed + 32-byte public)
}

export interface SignedMessage {
  message: Buffer;
  signature: Buffer;   // 64-byte Ed25519 signature
}

// ============================================
// X25519 Key Operations
// ============================================

/**
 * Generate an X25519 key pair for key exchange
 * @returns Raw 32-byte public and private keys
 */
export function generateX25519KeyPair(): X25519KeyPair {
  const keyPair = generateKeyPairSync('x25519');

  // Export to DER format and extract raw bytes
  const publicKeyDer = keyPair.publicKey.export({ type: 'spki', format: 'der' });
  const privateKeyDer = keyPair.privateKey.export({ type: 'pkcs8', format: 'der' });

  // X25519 public key in SPKI has 12-byte header, private key in PKCS8 has 16-byte header
  const publicKey = publicKeyDer.slice(12);
  const privateKey = privateKeyDer.slice(16);

  return { publicKey, privateKey };
}

/**
 * Convert raw X25519 private key to KeyObject for crypto operations
 */
function rawToPrivateKeyObject(rawPrivateKey: Buffer): KeyObject {
  // PKCS8 header for X25519 private key
  const pkcs8Header = Buffer.from([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
    0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
  ]);
  const pkcs8Der = Buffer.concat([pkcs8Header, rawPrivateKey]);
  return createPrivateKey({ key: pkcs8Der, format: 'der', type: 'pkcs8' });
}

/**
 * Convert raw X25519 public key to KeyObject for crypto operations
 */
function rawToPublicKeyObject(rawPublicKey: Buffer): KeyObject {
  // SPKI header for X25519 public key
  const spkiHeader = Buffer.from([
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
    0x6e, 0x03, 0x21, 0x00,
  ]);
  const spkiDer = Buffer.concat([spkiHeader, rawPublicKey]);
  return createPublicKey({ key: spkiDer, format: 'der', type: 'spki' });
}

/**
 * Perform X25519 ECDH to derive shared secret
 * @param privateKey Raw 32-byte private key
 * @param publicKey Raw 32-byte public key
 * @returns 32-byte shared secret
 */
export function deriveSharedSecret(privateKey: Buffer, publicKey: Buffer): Buffer {
  const privateKeyObject = rawToPrivateKeyObject(privateKey);
  const publicKeyObject = rawToPublicKeyObject(publicKey);

  return diffieHellman({
    privateKey: privateKeyObject,
    publicKey: publicKeyObject,
  });
}

// ============================================
// HKDF Key Derivation
// ============================================

/**
 * Default HKDF salt for VettID key derivation
 * Must match exactly across iOS, Android, and backend
 */
const HKDF_DEFAULT_SALT = Buffer.from('VettID-HKDF-Salt-v1', 'utf8');

/**
 * HKDF-SHA256 key derivation
 * @param ikm Input key material (shared secret)
 * @param length Output key length in bytes
 * @param info Context/application-specific info string
 * @param salt Optional salt (if not provided, uses VettID default salt)
 * @returns Derived key of specified length
 */
export function hkdf(
  ikm: Buffer,
  length: number,
  info: string,
  salt?: Buffer
): Buffer {
  // HKDF-Extract - use VettID default salt if not provided
  const actualSalt = salt || HKDF_DEFAULT_SALT;
  const prk = createHmac('sha256', actualSalt).update(ikm).digest();

  // HKDF-Expand
  const infoBuffer = Buffer.from(info, 'utf8');
  const n = Math.ceil(length / 32);
  let okm = Buffer.alloc(0);
  let prev = Buffer.alloc(0);

  for (let i = 1; i <= n; i++) {
    const data = Buffer.concat([prev, infoBuffer, Buffer.from([i])]);
    prev = createHmac('sha256', prk).update(data).digest();
    okm = Buffer.concat([okm, prev]);
  }

  return okm.slice(0, length);
}

// ============================================
// ChaCha20-Poly1305 Encryption
// ============================================

/**
 * Encrypt data using ChaCha20-Poly1305 with ECIES pattern
 *
 * Uses ephemeral key for each encryption to ensure:
 * - Different ciphertext each time (even for same plaintext)
 * - Forward secrecy for individual messages
 *
 * @param plaintext Data to encrypt
 * @param recipientPublicKey Recipient's X25519 public key (32 bytes)
 * @param context Key derivation context string
 * @returns Encrypted blob with ephemeral public key
 */
export function encryptWithPublicKey(
  plaintext: Buffer,
  recipientPublicKey: Buffer,
  context: string = 'credential-encryption-v1'
): EncryptedBlob {
  // Generate ephemeral key pair
  const ephemeral = generateX25519KeyPair();

  // Derive shared secret via ECDH
  const sharedSecret = deriveSharedSecret(ephemeral.privateKey, recipientPublicKey);

  // Derive symmetric key using HKDF
  const symmetricKey = hkdf(sharedSecret, 32, context);

  // Generate 12-byte nonce for ChaCha20-Poly1305
  const nonce = randomBytes(12);

  // Encrypt with ChaCha20-Poly1305
  const cipher = createCipheriv('chacha20-poly1305', symmetricKey, nonce, {
    authTagLength: 16,
  });

  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();

  // Combine ciphertext and auth tag
  const ciphertext = Buffer.concat([encrypted, authTag]);

  // Clear sensitive data
  sharedSecret.fill(0);
  symmetricKey.fill(0);
  ephemeral.privateKey.fill(0);

  return {
    ciphertext,
    nonce,
    ephemeralPublicKey: ephemeral.publicKey,
  };
}

/**
 * Decrypt data using ChaCha20-Poly1305 with ECIES pattern
 *
 * @param encrypted Encrypted blob with ephemeral public key
 * @param recipientPrivateKey Recipient's X25519 private key (32 bytes)
 * @param context Key derivation context string
 * @returns Decrypted plaintext
 * @throws Error if decryption fails (authentication failure)
 */
export function decryptWithPrivateKey(
  encrypted: EncryptedBlob,
  recipientPrivateKey: Buffer,
  context: string = 'credential-encryption-v1'
): Buffer {
  // Derive shared secret via ECDH
  const sharedSecret = deriveSharedSecret(recipientPrivateKey, encrypted.ephemeralPublicKey);

  // Derive symmetric key using HKDF
  const symmetricKey = hkdf(sharedSecret, 32, context);

  // Split ciphertext and auth tag
  const ciphertextOnly = encrypted.ciphertext.slice(0, -16);
  const authTag = encrypted.ciphertext.slice(-16);

  // Decrypt with ChaCha20-Poly1305
  const decipher = createDecipheriv('chacha20-poly1305', symmetricKey, encrypted.nonce, {
    authTagLength: 16,
  });
  decipher.setAuthTag(authTag);

  try {
    const decrypted = Buffer.concat([decipher.update(ciphertextOnly), decipher.final()]);

    // Clear sensitive data
    sharedSecret.fill(0);
    symmetricKey.fill(0);

    return decrypted;
  } catch (error) {
    // Clear sensitive data even on failure
    sharedSecret.fill(0);
    symmetricKey.fill(0);
    throw new Error('Decryption failed: authentication error');
  }
}

/**
 * Encrypt credential blob for storage
 * Wrapper for encryptWithPublicKey with credential-specific context
 */
export function encryptCredentialBlob(plaintext: Buffer, cekPublicKey: Buffer): EncryptedBlob {
  return encryptWithPublicKey(plaintext, cekPublicKey, 'credential-encryption-v1');
}

/**
 * Decrypt credential blob
 * Wrapper for decryptWithPrivateKey with credential-specific context
 */
export function decryptCredentialBlob(encrypted: EncryptedBlob, cekPrivateKey: Buffer): Buffer {
  return decryptWithPrivateKey(encrypted, cekPrivateKey, 'credential-encryption-v1');
}

/**
 * Encrypt data with transaction key
 * Uses transaction-specific context
 */
export function encryptWithTransactionKey(plaintext: Buffer, utkPublicKey: Buffer): EncryptedBlob {
  return encryptWithPublicKey(plaintext, utkPublicKey, 'transaction-encryption-v1');
}

/**
 * Decrypt data with transaction key
 * Uses transaction-specific context
 */
export function decryptWithTransactionKey(encrypted: EncryptedBlob, ltkPrivateKey: Buffer): Buffer {
  return decryptWithPrivateKey(encrypted, ltkPrivateKey, 'transaction-encryption-v1');
}

// ============================================
// Transaction Key Pool
// ============================================

/**
 * Generate a pool of transaction keys
 * @param count Number of keys to generate
 * @param userGuid User identifier for key association
 * @returns Array of transaction key pairs
 */
export function generateTransactionKeyPool(count: number, userGuid?: string): TransactionKeyPair[] {
  const pool: TransactionKeyPair[] = [];

  for (let i = 0; i < count; i++) {
    const keyPair = generateX25519KeyPair();
    const keyId = `tk_${randomBytes(8).toString('hex')}`;

    pool.push({
      keyId,
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
      algorithm: 'X25519',
    });
  }

  return pool;
}

// ============================================
// Serialization Helpers
// ============================================

/**
 * Serialize encrypted blob for transmission/storage
 */
export function serializeEncryptedBlob(encrypted: EncryptedBlob): {
  ciphertext: string;
  nonce: string;
  ephemeral_public_key: string;
} {
  return {
    ciphertext: encrypted.ciphertext.toString('base64'),
    nonce: encrypted.nonce.toString('base64'),
    ephemeral_public_key: encrypted.ephemeralPublicKey.toString('base64'),
  };
}

/**
 * Deserialize encrypted blob from transmission/storage
 */
export function deserializeEncryptedBlob(serialized: {
  ciphertext: string;
  nonce: string;
  ephemeral_public_key: string;
}): EncryptedBlob {
  return {
    ciphertext: Buffer.from(serialized.ciphertext, 'base64'),
    nonce: Buffer.from(serialized.nonce, 'base64'),
    ephemeralPublicKey: Buffer.from(serialized.ephemeral_public_key, 'base64'),
  };
}

/**
 * Create combined blob format: nonce || ephemeralPubKey || ciphertext
 * This format is used for on-device storage
 */
export function packEncryptedBlob(encrypted: EncryptedBlob): Buffer {
  return Buffer.concat([
    encrypted.nonce,
    encrypted.ephemeralPublicKey,
    encrypted.ciphertext,
  ]);
}

/**
 * Unpack combined blob format
 */
export function unpackEncryptedBlob(packed: Buffer, nonceLength: number = 12): EncryptedBlob {
  const nonce = packed.slice(0, nonceLength);
  const ephemeralPublicKey = packed.slice(nonceLength, nonceLength + 32);
  const ciphertext = packed.slice(nonceLength + 32);

  return { ciphertext, nonce, ephemeralPublicKey };
}

// ============================================
// Ed25519 Signing Operations
// ============================================

/**
 * Generate an Ed25519 key pair for signing
 * @returns Raw public key (32 bytes) and private key (seed, 32 bytes)
 */
export function generateEd25519KeyPair(): Ed25519KeyPair {
  const keyPair = generateKeyPairSync('ed25519');

  // Export to DER format and extract raw bytes
  const publicKeyDer = keyPair.publicKey.export({ type: 'spki', format: 'der' });
  const privateKeyDer = keyPair.privateKey.export({ type: 'pkcs8', format: 'der' });

  // Ed25519 public key in SPKI has 12-byte header
  // Ed25519 private key in PKCS8 has 16-byte header, contains 32-byte seed
  const publicKey = publicKeyDer.slice(12);
  const privateKey = privateKeyDer.slice(16);

  return { publicKey, privateKey };
}

/**
 * Convert raw Ed25519 private key to KeyObject for crypto operations
 */
function rawEd25519ToPrivateKeyObject(rawPrivateKey: Buffer): KeyObject {
  // PKCS8 header for Ed25519 private key
  const pkcs8Header = Buffer.from([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
    0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
  ]);
  const pkcs8Der = Buffer.concat([pkcs8Header, rawPrivateKey]);
  return createPrivateKey({ key: pkcs8Der, format: 'der', type: 'pkcs8' });
}

/**
 * Convert raw Ed25519 public key to KeyObject for crypto operations
 */
function rawEd25519ToPublicKeyObject(rawPublicKey: Buffer): KeyObject {
  // SPKI header for Ed25519 public key
  const spkiHeader = Buffer.from([
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
    0x70, 0x03, 0x21, 0x00,
  ]);
  const spkiDer = Buffer.concat([spkiHeader, rawPublicKey]);
  return createPublicKey({ key: spkiDer, format: 'der', type: 'spki' });
}

/**
 * Sign a message using Ed25519
 *
 * @param message Data to sign
 * @param privateKey Raw 32-byte Ed25519 private key (seed)
 * @returns 64-byte Ed25519 signature
 */
export function signMessage(message: Buffer, privateKey: Buffer): Buffer {
  const privateKeyObject = rawEd25519ToPrivateKeyObject(privateKey);

  const signature = sign(null, message, privateKeyObject);
  return signature;
}

/**
 * Verify an Ed25519 signature
 *
 * @param message Original message
 * @param signature 64-byte Ed25519 signature
 * @param publicKey Raw 32-byte Ed25519 public key
 * @returns true if signature is valid
 */
export function verifySignature(message: Buffer, signature: Buffer, publicKey: Buffer): boolean {
  try {
    const publicKeyObject = rawEd25519ToPublicKeyObject(publicKey);
    return verify(null, message, publicKeyObject, signature);
  } catch {
    return false;
  }
}

/**
 * Sign a JSON payload with timestamp for request signing
 *
 * @param payload JSON object to sign
 * @param privateKey Raw 32-byte Ed25519 private key
 * @returns Signed payload with signature and timestamp
 */
export function signPayload(
  payload: Record<string, unknown>,
  privateKey: Buffer
): {
  payload: Record<string, unknown>;
  timestamp: string;
  signature: string;
} {
  const timestamp = new Date().toISOString();
  const payloadWithTimestamp = { ...payload, timestamp };
  const message = Buffer.from(JSON.stringify(payloadWithTimestamp), 'utf8');
  const signature = signMessage(message, privateKey);

  return {
    payload: payloadWithTimestamp,
    timestamp,
    signature: signature.toString('base64'),
  };
}

/**
 * Verify a signed payload
 *
 * @param signedPayload Payload with signature and timestamp
 * @param publicKey Raw 32-byte Ed25519 public key
 * @param maxAgeMs Maximum age of timestamp in milliseconds (default 5 minutes)
 * @returns true if signature is valid and timestamp is recent
 */
export function verifySignedPayload(
  signedPayload: {
    payload: Record<string, unknown>;
    timestamp: string;
    signature: string;
  },
  publicKey: Buffer,
  maxAgeMs: number = 5 * 60 * 1000
): boolean {
  // Check timestamp freshness
  const timestampDate = new Date(signedPayload.timestamp);
  const now = Date.now();
  const age = now - timestampDate.getTime();

  if (age < 0 || age > maxAgeMs) {
    return false; // Timestamp is in the future or too old
  }

  // Verify signature
  const message = Buffer.from(JSON.stringify(signedPayload.payload), 'utf8');
  const signature = Buffer.from(signedPayload.signature, 'base64');

  return verifySignature(message, signature, publicKey);
}

/**
 * Generate a cryptographically secure random challenge
 *
 * @param length Length in bytes (default 32)
 * @returns Random challenge as hex string
 */
export function generateChallenge(length: number = 32): string {
  return randomBytes(length).toString('hex');
}

/**
 * Sign a challenge response for attestation verification
 *
 * @param challenge Challenge string (hex)
 * @param additionalData Additional data to include in signature
 * @param privateKey Raw 32-byte Ed25519 private key
 * @returns Challenge response with signature
 */
export function signChallengeResponse(
  challenge: string,
  additionalData: Record<string, unknown>,
  privateKey: Buffer
): {
  challenge: string;
  data: Record<string, unknown>;
  signature: string;
} {
  const message = Buffer.concat([
    Buffer.from(challenge, 'hex'),
    Buffer.from(JSON.stringify(additionalData), 'utf8'),
  ]);

  const signature = signMessage(message, privateKey);

  return {
    challenge,
    data: additionalData,
    signature: signature.toString('base64'),
  };
}

/**
 * Verify a challenge response
 *
 * @param response Challenge response with signature
 * @param publicKey Raw 32-byte Ed25519 public key
 * @returns true if signature is valid
 */
export function verifyChallengeResponse(
  response: {
    challenge: string;
    data: Record<string, unknown>;
    signature: string;
  },
  publicKey: Buffer
): boolean {
  const message = Buffer.concat([
    Buffer.from(response.challenge, 'hex'),
    Buffer.from(JSON.stringify(response.data), 'utf8'),
  ]);

  const signature = Buffer.from(response.signature, 'base64');

  return verifySignature(message, signature, publicKey);
}
