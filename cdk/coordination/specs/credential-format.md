# Protean Credential Format Specification

This document defines the format and cryptographic operations for the Protean Credential System used in VettID Vault Services.

## Overview

The Protean Credential System uses three types of rotating keys:

| Key Type | Purpose | Rotation |
|----------|---------|----------|
| **CEK** (Credential Encryption Key) | Encrypt credential blob | After each authentication |
| **TK** (Transaction Key) | Encrypt sensitive data in transit | After each use |
| **LAT** (Ledger Authentication Token) | Mutual authentication | After each transaction |

## Cryptographic Algorithms

| Algorithm | Usage | Library |
|-----------|-------|---------|
| X25519 | Key exchange (CEK, TK) | TweetNaCl, libsodium, CryptoKit |
| XChaCha20-Poly1305 | Authenticated encryption | TweetNaCl, libsodium |
| Argon2id | Password hashing | argon2-browser, Swift Crypto |
| Ed25519 | Signatures | TweetNaCl, CryptoKit |

## Credential Blob Structure

### On-Device Storage

The credential blob stored on the mobile device:

```json
{
  "user_guid": "550e8400-e29b-41d4-a716-446655440000",
  "encrypted_blob": "<base64-encoded ciphertext>",
  "ephemeral_public_key": "<base64-encoded 32-byte X25519 public key>",
  "cek_version": 42
}
```

### Decrypted Blob Contents

After decryption with the CEK private key:

```json
{
  "guid": "550e8400-e29b-41d4-a716-446655440000",
  "password_hash": "$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>",
  "hash_algorithm": "argon2id",
  "hash_version": "1.0",
  "policies": {
    "ttl_hours": 24,
    "max_failed_attempts": 3
  },
  "secrets": {
    "vault_access_key": "<base64-encoded key>",
    "backup_private_key": "<base64-encoded X25519 private key>",
    "custom_secrets": {
      // User-defined secrets
    }
  },
  "vault_credential": {
    // Second Protean credential for vault communication
    "encrypted_blob": "...",
    "ephemeral_public_key": "...",
    "version": 1
  },
  "vault_credential_backups": [
    // Previous 3 versions for backup compatibility
  ]
}
```

## Encryption Operations

### Encrypt Credential Blob

```typescript
interface EncryptedBlob {
  ciphertext: Uint8Array;        // XChaCha20-Poly1305 ciphertext
  ephemeralPublicKey: Uint8Array; // 32-byte X25519 public key
}

function encryptCredentialBlob(
  plaintext: Uint8Array,
  recipientPublicKey: Uint8Array  // CEK public key
): EncryptedBlob {
  // 1. Generate ephemeral X25519 key pair
  const ephemeralKeyPair = nacl.box.keyPair();

  // 2. Derive shared secret via ECDH
  const sharedSecret = nacl.scalarMult(
    ephemeralKeyPair.secretKey,
    recipientPublicKey
  );

  // 3. Derive symmetric key using HKDF-SHA256
  const symmetricKey = hkdf(
    sharedSecret,
    32,                           // 32 bytes for XChaCha20
    'credential-encryption-v1'    // info string
  );

  // 4. Encrypt with XChaCha20-Poly1305
  const nonce = randomBytes(24);  // 24-byte nonce
  const ciphertext = xchacha20poly1305.seal(
    symmetricKey,
    nonce,
    plaintext
  );

  return {
    ciphertext: concat(nonce, ciphertext),
    ephemeralPublicKey: ephemeralKeyPair.publicKey
  };
}
```

### Decrypt Credential Blob

```typescript
function decryptCredentialBlob(
  encrypted: EncryptedBlob,
  recipientPrivateKey: Uint8Array  // CEK private key
): Uint8Array {
  // 1. Derive shared secret
  const sharedSecret = nacl.scalarMult(
    recipientPrivateKey,
    encrypted.ephemeralPublicKey
  );

  // 2. Derive symmetric key
  const symmetricKey = hkdf(
    sharedSecret,
    32,
    'credential-encryption-v1'
  );

  // 3. Extract nonce and ciphertext
  const nonce = encrypted.ciphertext.slice(0, 24);
  const ciphertext = encrypted.ciphertext.slice(24);

  // 4. Decrypt
  const plaintext = xchacha20poly1305.open(
    symmetricKey,
    nonce,
    ciphertext
  );

  if (plaintext === null) {
    throw new Error('Decryption failed');
  }

  return plaintext;
}
```

## Password Hashing (Argon2id)

### Parameters

```typescript
const ARGON2_PARAMS = {
  type: 'argon2id',     // Hybrid mode (recommended)
  timeCost: 3,          // 3 iterations
  memoryCost: 65536,    // 64 MB
  parallelism: 4,       // 4 threads
  hashLength: 32,       // 32-byte output
  saltLength: 16        // 16-byte salt
};
```

### Hash Format

Argon2 produces a PHC string format:

```
$argon2id$v=19$m=65536,t=3,p=4$<base64-salt>$<base64-hash>
```

### Implementation

```typescript
// Hash password (during enrollment or password change)
async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  const hash = await argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 4,
    salt: salt
  });
  return hash;  // Returns PHC string
}

// Verify password (during authentication)
async function verifyPassword(
  storedHash: string,
  password: string
): Promise<boolean> {
  try {
    return await argon2.verify(storedHash, password);
  } catch {
    return false;
  }
}
```

## Transaction Keys (TK)

### Key Structure

```typescript
interface TransactionKey {
  keyId: string;           // Unique identifier
  publicKey: Uint8Array;   // X25519 public key (32 bytes)
  algorithm: 'X25519';
  createdAt: string;       // ISO8601 timestamp
}

// Server-side only
interface TransactionKeyPrivate extends TransactionKey {
  encryptedPrivateKey: Uint8Array;  // Encrypted with KMS
  status: 'unused' | 'used';
}
```

### Usage Flow

```typescript
// Mobile app: Encrypt sensitive data
function encryptWithTransactionKey(
  data: Uint8Array,
  transactionKey: TransactionKey
): { keyId: string; ciphertext: Uint8Array } {
  // Generate ephemeral key for this encryption
  const ephemeral = nacl.box.keyPair();

  // Derive shared secret
  const sharedSecret = nacl.scalarMult(
    ephemeral.secretKey,
    transactionKey.publicKey
  );

  // Derive symmetric key
  const symmetricKey = hkdf(sharedSecret, 32, 'transaction-encryption-v1');

  // Encrypt
  const nonce = randomBytes(24);
  const ciphertext = xchacha20poly1305.seal(symmetricKey, nonce, data);

  return {
    keyId: transactionKey.keyId,
    ciphertext: concat(ephemeral.publicKey, nonce, ciphertext)
  };
}

// Server: Decrypt
function decryptWithTransactionKey(
  keyId: string,
  ciphertext: Uint8Array
): Uint8Array {
  // Retrieve private key from storage
  const privateKey = await getTransactionKeyPrivate(keyId);

  // Extract components
  const ephemeralPublicKey = ciphertext.slice(0, 32);
  const nonce = ciphertext.slice(32, 56);
  const encrypted = ciphertext.slice(56);

  // Derive shared secret
  const sharedSecret = nacl.scalarMult(privateKey, ephemeralPublicKey);

  // Derive symmetric key
  const symmetricKey = hkdf(sharedSecret, 32, 'transaction-encryption-v1');

  // Decrypt
  const plaintext = xchacha20poly1305.open(symmetricKey, nonce, encrypted);

  // Mark key as used
  await markTransactionKeyUsed(keyId);

  return plaintext;
}
```

### Key Pool Management

- **Initial pool size:** 20 keys at enrollment
- **Replenishment threshold:** 10 unused keys
- **Replenishment quantity:** 10 new keys
- **Mobile app responsibility:** Request replenishment when pool low

## Ledger Authentication Token (LAT)

### Token Structure

```typescript
interface LAT {
  token: string;    // 256-bit random token (64 hex chars)
  version: number;  // Increments on each use
}
```

### Token Generation

```typescript
function generateLAT(): LAT {
  const token = randomBytes(32);
  return {
    token: toHex(token),
    version: 1
  };
}
```

### Validation Flow

```typescript
// Server: Get current LAT
async function getCurrentLAT(userGuid: string): Promise<LAT> {
  const activeLat = await db.query(
    'SELECT token, version FROM ledger_auth_tokens WHERE user_guid = ? AND status = "active"',
    [userGuid]
  );
  return activeLat;
}

// Mobile: Verify LAT before sending credentials
function verifyLAT(received: LAT, stored: LAT): boolean {
  // Constant-time comparison
  return timingSafeEqual(received.token, stored.token) &&
         received.version === stored.version;
}

// Server: Rotate LAT after successful auth
async function rotateLAT(userGuid: string): Promise<LAT> {
  const newLat = generateLAT();
  newLat.version = (await getCurrentLAT(userGuid)).version + 1;

  await db.transaction(async (tx) => {
    // Mark old LAT as used
    await tx.query(
      'UPDATE ledger_auth_tokens SET status = "used" WHERE user_guid = ? AND status = "active"',
      [userGuid]
    );

    // Insert new LAT
    await tx.query(
      'INSERT INTO ledger_auth_tokens (token, version, user_guid, status) VALUES (?, ?, ?, "active")',
      [hashToken(newLat.token), newLat.version, userGuid]
    );
  });

  return newLat;
}
```

### Security Properties

- **Version-based validation:** No time-based expiration
- **Single active LAT:** Only one active LAT per user
- **Phishing prevention:** Mobile app verifies server identity before sending credentials
- **Replay prevention:** LAT changes after each successful authentication

## CEK Rotation

After each successful authentication:

```typescript
async function rotateCEK(userGuid: string): Promise<{
  newBlob: EncryptedBlob;
  newPublicKey: Uint8Array;
}> {
  // 1. Generate new CEK key pair
  const newKeyPair = nacl.box.keyPair();

  // 2. Get current blob and decrypt
  const currentBlob = await getCurrentCredentialBlob(userGuid);
  const currentPrivateKey = await getCEKPrivateKey(userGuid);
  const plaintext = decryptCredentialBlob(currentBlob, currentPrivateKey);

  // 3. Re-encrypt with new key
  const newBlob = encryptCredentialBlob(plaintext, newKeyPair.publicKey);

  // 4. Store new private key (encrypted with KMS)
  await storeCEKPrivateKey(userGuid, newKeyPair.secretKey);

  // 5. Increment version
  const newVersion = currentBlob.cek_version + 1;

  return {
    newBlob: {
      ...newBlob,
      user_guid: userGuid,
      cek_version: newVersion
    },
    newPublicKey: newKeyPair.publicKey
  };
}
```

## Mobile Storage Recommendations

### Android

```kotlin
// Use EncryptedSharedPreferences
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

val sharedPreferences = EncryptedSharedPreferences.create(
    context,
    "vettid_credentials",
    masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)

// Store credential blob
sharedPreferences.edit()
    .putString("credential_blob", credentialBlobJson)
    .putString("lat_token", lat.token)
    .putInt("lat_version", lat.version)
    .apply()
```

### iOS

```swift
// Use Keychain with biometric protection
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: "dev.vettid.credentials",
    kSecAttrAccount as String: "credential_blob",
    kSecValueData as String: credentialBlobData,
    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    kSecAttrAccessControl as String: SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        .biometryCurrentSet,
        nil
    )!
]

SecItemAdd(query as CFDictionary, nil)
```

## Wire Format Examples

### Enrollment Finalize Response

```json
{
  "credentialBlob": {
    "userGuid": "550e8400-e29b-41d4-a716-446655440000",
    "encryptedBlob": "nonce24bytes...ciphertext...",
    "ephemeralPublicKey": "32bytepublickey...",
    "cekVersion": 1
  },
  "lat": {
    "token": "a1b2c3d4e5f6...64hexchars",
    "version": 1
  },
  "transactionKeys": [
    {
      "keyId": "tk_abc123",
      "publicKey": "32bytepublickey...",
      "algorithm": "X25519",
      "createdAt": "2025-01-01T00:00:00Z"
    }
    // ... 19 more keys
  ]
}
```

### Authentication Execute Response

```json
{
  "success": true,
  "newCredentialBlob": {
    "userGuid": "550e8400-e29b-41d4-a716-446655440000",
    "encryptedBlob": "newnonce24bytes...newciphertext...",
    "ephemeralPublicKey": "new32bytepublickey...",
    "cekVersion": 43
  },
  "newLat": {
    "token": "b2c3d4e5f6a7...64hexchars",
    "version": 43
  },
  "actionToken": "eyJhbGciOiJFZDI1NTE5...",
  "newTransactionKeys": [
    // Replenished keys if pool was low
  ]
}
```

## Security Checklist

- [ ] Use constant-time comparison for all token/hash verification
- [ ] Clear sensitive data from memory after use
- [ ] Use secure random number generation
- [ ] Validate all cryptographic outputs (check for null/failure)
- [ ] Log authentication attempts (without sensitive data)
- [ ] Implement rate limiting on authentication endpoints
- [ ] Use TLS 1.3 for all API communication
- [ ] Encrypt private keys at rest (KMS/HSM)
