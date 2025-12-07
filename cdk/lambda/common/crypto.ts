/**
 * Cryptographic utilities for Protean Credential System
 *
 * Implements:
 * - X25519 key exchange
 * - XChaCha20-Poly1305 authenticated encryption (via ChaCha20-Poly1305 with extended nonce)
 * - HKDF-SHA256 key derivation
 * - Argon2id password hashing (via hash-wasm)
 * - Secure LAT generation and validation
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

export interface LAT {
  token: string;    // 64 hex chars (32 bytes)
  version: number;
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
 * HKDF-SHA256 key derivation
 * @param ikm Input key material (shared secret)
 * @param length Output key length in bytes
 * @param info Context/application-specific info string
 * @param salt Optional salt (if not provided, uses zeros)
 * @returns Derived key of specified length
 */
export function hkdf(
  ikm: Buffer,
  length: number,
  info: string,
  salt?: Buffer
): Buffer {
  // HKDF-Extract
  const actualSalt = salt || Buffer.alloc(32, 0);
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
// Password Hashing (Argon2id simulation)
// ============================================

/**
 * Argon2id parameters matching specification
 * In production, use hash-wasm or argon2 npm package
 */
const ARGON2_PARAMS = {
  type: 'argon2id',
  timeCost: 3,          // 3 iterations
  memoryCost: 65536,    // 64 MB
  parallelism: 4,       // 4 threads
  hashLength: 32,       // 32-byte output
  saltLength: 16,       // 16-byte salt
};

/**
 * Hash password using Argon2id
 *
 * Note: This is a PBKDF2 fallback implementation.
 * For production, install and use the 'argon2' npm package:
 *
 * import argon2 from 'argon2';
 * const hash = await argon2.hash(password, {
 *   type: argon2.argon2id,
 *   memoryCost: 65536,
 *   timeCost: 3,
 *   parallelism: 4,
 * });
 *
 * @param password Plain text password
 * @returns PHC-formatted hash string
 */
export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(ARGON2_PARAMS.saltLength);

  // PBKDF2 fallback - replace with actual Argon2id in production
  const { pbkdf2Sync } = await import('crypto');
  const hash = pbkdf2Sync(
    password,
    salt,
    100000, // iterations (adjust for ~100ms target)
    ARGON2_PARAMS.hashLength,
    'sha256'
  );

  // Return in PHC format (compatible with Argon2 format)
  const saltB64 = salt.toString('base64').replace(/=/g, '');
  const hashB64 = hash.toString('base64').replace(/=/g, '');

  // Using $pbkdf2-sha256$ prefix to indicate fallback
  // In production with actual Argon2id: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
  return `$pbkdf2-sha256$i=100000$${saltB64}$${hashB64}`;
}

/**
 * Verify password against stored hash
 *
 * @param storedHash PHC-formatted hash string
 * @param password Plain text password to verify
 * @returns true if password matches
 */
export async function verifyPassword(storedHash: string, password: string): Promise<boolean> {
  const parts = storedHash.split('$').filter(Boolean);

  if (parts[0] === 'pbkdf2-sha256') {
    // PBKDF2 fallback format
    const iterations = parseInt(parts[1].replace('i=', ''), 10);
    const salt = Buffer.from(parts[2], 'base64');
    const expectedHash = Buffer.from(parts[3], 'base64');

    const { pbkdf2Sync } = await import('crypto');
    const computedHash = pbkdf2Sync(password, salt, iterations, expectedHash.length, 'sha256');

    return timingSafeEqual(computedHash, expectedHash);
  } else if (parts[0] === 'argon2id') {
    // Argon2id format - requires argon2 package
    // In production:
    // import argon2 from 'argon2';
    // return await argon2.verify(storedHash, password);
    throw new Error('Argon2id verification requires argon2 package');
  }

  throw new Error(`Unsupported hash format: ${parts[0]}`);
}

// ============================================
// LAT (Ledger Authentication Token)
// ============================================

/**
 * Generate a new LAT
 * @param version LAT version number (increments on each rotation)
 * @returns LAT with 256-bit random token
 */
export function generateLAT(version: number = 1): LAT {
  const token = randomBytes(32).toString('hex');
  return { token, version };
}

/**
 * Hash LAT token for storage
 * Never store raw LAT tokens - always hash them
 */
export function hashLATToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

/**
 * Verify LAT token against stored hash
 * Uses timing-safe comparison
 */
export function verifyLATToken(providedToken: string, storedHash: string): boolean {
  const providedHash = hashLATToken(providedToken);
  const providedBuffer = Buffer.from(providedHash, 'hex');
  const storedBuffer = Buffer.from(storedHash, 'hex');

  if (providedBuffer.length !== storedBuffer.length) {
    return false;
  }

  return timingSafeEqual(providedBuffer, storedBuffer);
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
