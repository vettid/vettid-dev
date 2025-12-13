/**
 * Cryptographic utilities for Protean Credential System
 *
 * This module re-exports from specialized sub-modules:
 * - crypto-keys.ts: Key generation, encryption, signing (no native deps)
 * - crypto-password.ts: Password hashing with Argon2id (native dep)
 *
 * IMPORTANT: If your Lambda only needs key operations (X25519, encryption,
 * signing, LAT), import directly from 'crypto-keys' to avoid bundling
 * the argon2 native module.
 *
 * @see cdk/coordination/specs/credential-format.md
 */

// Re-export everything from crypto-keys (no native dependencies)
export {
  // Types
  X25519KeyPair,
  EncryptedBlob,
  TransactionKeyPair,
  LAT,
  Ed25519KeyPair,
  SignedMessage,
  // X25519 key operations
  generateX25519KeyPair,
  deriveSharedSecret,
  // HKDF
  hkdf,
  // ChaCha20-Poly1305 encryption
  encryptWithPublicKey,
  decryptWithPrivateKey,
  encryptCredentialBlob,
  decryptCredentialBlob,
  encryptWithTransactionKey,
  decryptWithTransactionKey,
  // LAT operations
  generateLAT,
  hashLATToken,
  verifyLATToken,
  // Transaction key pool
  generateTransactionKeyPool,
  // Serialization
  serializeEncryptedBlob,
  deserializeEncryptedBlob,
  packEncryptedBlob,
  unpackEncryptedBlob,
  // Ed25519 signing
  generateEd25519KeyPair,
  signMessage,
  verifySignature,
  signPayload,
  verifySignedPayload,
  generateChallenge,
  signChallengeResponse,
  verifyChallengeResponse,
} from './crypto-keys';

// Re-export password functions (requires argon2 native module)
// WARNING: Importing this file will bundle argon2 - if you don't need
// password hashing, import from 'crypto-keys' directly.
export {
  hashPassword,
  verifyPassword,
  needsRehash,
} from './crypto-password';
