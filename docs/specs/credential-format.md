# Protean Credential Format Specification

**Version:** 2.0
**Last Updated:** 2026-01-19
**Status:** Active

This document defines the format and cryptographic operations for the Protean Credential System used in VettID Vault Services.

---

## Overview

The Protean Credential System uses rotating keys for security:

| Key Type | Purpose | Rotation |
|----------|---------|----------|
| **CEK** (Credential Encryption Key) | Encrypt credential blob | After each authentication |
| **UTK** (User Transaction Key) | Encrypt sensitive payloads to vault | Single-use |
| **LTK** (Ledger Transaction Key) | Decrypt UTK-encrypted payloads (vault-side) | Paired with UTK |

## Cryptographic Algorithms

| Algorithm | Usage | Parameters |
|-----------|-------|------------|
| X25519 | Key exchange (CEK, UTK) | 32-byte keys |
| XChaCha20-Poly1305 | Authenticated encryption | 24-byte nonce |
| Argon2id | Password hashing | t=3, m=65536 (64MB), p=4 |
| Ed25519 | Identity signatures | 32-byte public, 64-byte private |
| HKDF-SHA256 | Key derivation | Domain-separated |

### HKDF Domain Separation

All HKDF operations use domain strings as salt for cryptographic separation:

| Domain | Purpose |
|--------|---------|
| `vettid-cek-v1` | CEK credential encryption |
| `vettid-utk-v1` | UTK payload encryption |
| `vettid-pin-v1` | PIN-related encryption |

---

## Credential Blob Structure

### On-Device Storage (App Side)

The app stores these items locally:

```json
{
  "encrypted_credential": "<base64: ephemeral_pubkey || nonce || ciphertext>",
  "password_salt": "<base64-16-bytes>",
  "argon2_params": {
    "t": 3,
    "m": 65536,
    "p": 4
  },
  "utks": [
    {
      "id": "utk-xxx",
      "public_key": "<base64-32-bytes>"
    }
  ]
}
```

| Field | Description |
|-------|-------------|
| `encrypted_credential` | CEK-encrypted Protean Credential (opaque to app) |
| `password_salt` | Extracted from PHC string for re-hashing |
| `argon2_params` | Extracted from PHC string for re-hashing |
| `utks` | Available UTKs for encrypting payloads to vault |

**Note:** The app cannot decrypt `encrypted_credential` - only the vault can.

---

### Decrypted Credential Structure (Vault Side)

The Protean Credential format inside the encrypted blob:

```json
{
  "format_version": 2,

  "identity": {
    "private_key": "<base64-Ed25519-seed-32-bytes>",
    "public_key": "<base64-Ed25519-32-bytes>"
  },

  "master_secret": "<base64-32-bytes>",

  "auth": {
    "type": "password",
    "hash": "$argon2id$v=19$m=65536,t=3,p=4$<base64-salt>$<base64-hash>"
  },

  "crypto_metadata": {
    "cipher": "xchacha20-poly1305",
    "kex": "x25519",
    "kdf": "hkdf-sha256",
    "domain": "vettid-cek-v1"
  },

  "binding": {
    "vault_id": "vault-xxx",
    "bound_at": 1705555555
  },

  "crypto_keys": [
    {
      "id": "key-xxx",
      "label": "ethereum-main",
      "type": "secp256k1",
      "private_key": "<base64>",
      "public_key": "<base64>",
      "derivation_path": "m/44'/60'/0'/0/0",
      "created_at": 1705555555
    }
  ],

  "timestamps": {
    "created_at": 1705555555,
    "last_modified": 1705666666,
    "auth_changed_at": 1705600000
  },

  "version": 1
}
```

### Field Descriptions

#### Top-Level Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `format_version` | int | Yes | Credential format version (currently 2) |
| `version` | int | Yes | Credential instance version (increments on changes) |

#### Identity Object

| Field | Type | Description |
|-------|------|-------------|
| `private_key` | base64 | Ed25519 seed (32 bytes) for signing |
| `public_key` | base64 | Ed25519 public key (32 bytes) - user's identity |

#### Auth Object

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | Authentication type: `"password"` or `"pin"` |
| `hash` | string | PHC-format Argon2id hash (self-describing) |

**PHC Format:** `$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>`

#### Crypto Metadata Object

| Field | Type | Description |
|-------|------|-------------|
| `cipher` | string | Symmetric cipher: `"xchacha20-poly1305"` |
| `kex` | string | Key exchange: `"x25519"` |
| `kdf` | string | Key derivation: `"hkdf-sha256"` |
| `domain` | string | HKDF domain used: `"vettid-cek-v1"` |

This enables algorithm agility - future credentials can use different algorithms.

#### Binding Object

| Field | Type | Description |
|-------|------|-------------|
| `vault_id` | string | ID of the vault this credential is bound to |
| `bound_at` | int64 | Unix timestamp when binding was created |

**Security:** The vault verifies the `vault_id` matches before performing operations.

#### Crypto Keys Array

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique key identifier |
| `label` | string | Yes | Human-readable label |
| `type` | string | Yes | Key type: `"secp256k1"`, `"ed25519"`, etc. |
| `private_key` | base64 | Yes | Private key material |
| `public_key` | base64 | Yes | Public key (stored for efficiency) |
| `derivation_path` | string | No | BIP32 path for HD keys |
| `created_at` | int64 | Yes | Unix timestamp |

#### Timestamps Object

| Field | Type | Description |
|-------|------|-------------|
| `created_at` | int64 | When credential was first created |
| `last_modified` | int64 | When credential was last changed |
| `auth_changed_at` | int64 | When password/PIN was last changed |

---

## Encryption Operations

### Encrypt Credential Blob

```typescript
function encryptCredentialBlob(
  plaintext: Uint8Array,
  recipientPublicKey: Uint8Array  // CEK public key
): Uint8Array {
  // 1. Generate ephemeral X25519 key pair
  const ephemeralKeyPair = x25519.generateKeyPair();

  // 2. Derive shared secret via ECDH
  const sharedSecret = x25519.sharedKey(
    ephemeralKeyPair.secretKey,
    recipientPublicKey
  );

  // 3. Derive symmetric key using HKDF-SHA256 with domain separation
  const symmetricKey = hkdf(
    sharedSecret,
    'vettid-cek-v1',  // Domain as salt
    null,             // No info
    32                // 32 bytes for XChaCha20
  );

  // 4. Encrypt with XChaCha20-Poly1305
  const nonce = randomBytes(24);  // 24-byte nonce
  const ciphertext = xchacha20poly1305.seal(
    symmetricKey,
    nonce,
    plaintext
  );

  // 5. Format: ephemeral_pubkey (32) || nonce (24) || ciphertext
  return concat(ephemeralKeyPair.publicKey, nonce, ciphertext);
}
```

### Decrypt Credential Blob

```typescript
function decryptCredentialBlob(
  encrypted: Uint8Array,
  recipientPrivateKey: Uint8Array  // CEK private key
): Uint8Array {
  // 1. Extract components
  const ephemeralPublicKey = encrypted.slice(0, 32);
  const nonce = encrypted.slice(32, 56);
  const ciphertext = encrypted.slice(56);

  // 2. Derive shared secret
  const sharedSecret = x25519.sharedKey(
    recipientPrivateKey,
    ephemeralPublicKey
  );

  // 3. Derive symmetric key with domain separation
  const symmetricKey = hkdf(
    sharedSecret,
    'vettid-cek-v1',  // Domain as salt
    null,
    32
  );

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

---

## Password Hashing (Argon2id)

### Parameters

```typescript
const ARGON2_PARAMS = {
  type: 'argon2id',     // Hybrid mode (recommended)
  timeCost: 3,          // 3 iterations
  memoryCost: 65536,    // 64 MB (OWASP minimum)
  parallelism: 4,       // 4 threads
  hashLength: 32,       // 32-byte output
  saltLength: 16        // 16-byte salt
};
```

### PHC String Format

All password hashes use PHC (Password Hashing Competition) string format:

```
$argon2id$v=19$m=65536,t=3,p=4$<base64-salt>$<base64-hash>
```

| Component | Description |
|-----------|-------------|
| `$argon2id$` | Algorithm identifier |
| `v=19` | Argon2 version (0x13 = 19) |
| `m=65536` | Memory in KB (64 MB) |
| `t=3` | Time/iterations |
| `p=4` | Parallelism |
| `<salt>` | Base64-encoded salt (no padding) |
| `<hash>` | Base64-encoded hash (no padding) |

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

// Verify password
async function verifyPassword(
  storedHash: string,  // PHC string
  password: string
): Promise<boolean> {
  try {
    return await argon2.verify(storedHash, password);
  } catch {
    return false;
  }
}
```

---

## UTK/LTK Operations

### Key Structure

```typescript
interface UTK {
  id: string;              // Unique identifier
  publicKey: Uint8Array;   // X25519 public key (32 bytes)
}

// Vault-side only
interface LTK {
  id: string;              // Matches UTK id
  privateKey: Uint8Array;  // X25519 private key (32 bytes)
  usedAt: number | null;   // Null if unused
}
```

### Encrypt with UTK (App Side)

```typescript
function encryptWithUTK(
  data: Uint8Array,
  utk: UTK
): { utk_id: string; ciphertext: Uint8Array } {
  // Generate ephemeral key
  const ephemeral = x25519.generateKeyPair();

  // Derive shared secret
  const sharedSecret = x25519.sharedKey(
    ephemeral.secretKey,
    utk.publicKey
  );

  // Derive symmetric key with UTK domain
  const symmetricKey = hkdf(
    sharedSecret,
    'vettid-utk-v1',  // UTK domain
    null,
    32
  );

  // Encrypt with XChaCha20-Poly1305
  const nonce = randomBytes(24);
  const encrypted = xchacha20poly1305.seal(symmetricKey, nonce, data);

  // Format: ephemeral_pubkey (32) || nonce (24) || ciphertext
  return {
    utk_id: utk.id,
    ciphertext: concat(ephemeral.publicKey, nonce, encrypted)
  };
}
```

### Decrypt with LTK (Vault Side)

```typescript
function decryptWithLTK(
  ltk: LTK,
  ciphertext: Uint8Array
): Uint8Array {
  // Extract components
  const ephemeralPublicKey = ciphertext.slice(0, 32);
  const nonce = ciphertext.slice(32, 56);
  const encrypted = ciphertext.slice(56);

  // Derive shared secret
  const sharedSecret = x25519.sharedKey(
    ltk.privateKey,
    ephemeralPublicKey
  );

  // Derive symmetric key with UTK domain
  const symmetricKey = hkdf(
    sharedSecret,
    'vettid-utk-v1',
    null,
    32
  );

  // Decrypt
  return xchacha20poly1305.open(symmetricKey, nonce, encrypted);
}
```

---

## CEK Rotation

After each successful authentication, the CEK is rotated:

```typescript
async function rotateCEK(
  credential: ProteanCredential,
  currentCEKPrivate: Uint8Array
): Promise<{
  newEncryptedCredential: Uint8Array;
  newCEKPublic: Uint8Array;
  newCEKPrivate: Uint8Array;
}> {
  // 1. Generate new CEK key pair
  const newKeyPair = x25519.generateKeyPair();

  // 2. Update credential timestamps
  credential.timestamps.last_modified = Date.now() / 1000;
  credential.version += 1;

  // 3. Serialize and encrypt with new CEK
  const plaintext = JSON.stringify(credential);
  const newEncrypted = encryptCredentialBlob(
    new TextEncoder().encode(plaintext),
    newKeyPair.publicKey
  );

  return {
    newEncryptedCredential: newEncrypted,
    newCEKPublic: newKeyPair.publicKey,
    newCEKPrivate: newKeyPair.secretKey
  };
}
```

---

## Format Migration

When loading a credential, check `format_version` and migrate if needed:

```typescript
function migrateCredential(credential: any): ProteanCredential {
  const version = credential.format_version || 1;

  if (version === 1) {
    // Migrate from v1 to v2
    return {
      format_version: 2,
      identity: {
        private_key: credential.identity_private_key,
        public_key: credential.identity_public_key
      },
      master_secret: credential.vault_master_secret,
      auth: {
        type: credential.auth_type || 'password',
        hash: credential.password_hash
      },
      crypto_metadata: {
        cipher: 'xchacha20-poly1305',
        kex: 'x25519',
        kdf: 'hkdf-sha256',
        domain: 'vettid-cek-v1'
      },
      binding: null,  // Will be set on first vault operation
      crypto_keys: (credential.crypto_keys || []).map(k => ({
        ...k,
        public_key: derivePublicKey(k.type, k.private_key)
      })),
      timestamps: {
        created_at: credential.created_at,
        last_modified: credential.created_at,
        auth_changed_at: credential.created_at
      },
      version: credential.version
    };
  }

  return credential;
}
```

---

## Mobile Storage Recommendations

### Android

```kotlin
// Use EncryptedSharedPreferences for credential storage
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

// Store credential data
sharedPreferences.edit()
    .putString("encrypted_credential", base64Encode(encryptedBlob))
    .putString("password_salt", base64Encode(salt))
    .putString("argon2_params", paramsJson)
    .apply()
```

### iOS

```swift
// Use Keychain with biometric protection
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: "dev.vettid.credentials",
    kSecAttrAccount as String: "encrypted_credential",
    kSecValueData as String: encryptedCredentialData,
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

---

## Security Checklist

- [ ] Use constant-time comparison for all hash verification
- [ ] Clear sensitive data from memory after use
- [ ] Use cryptographically secure random number generation
- [ ] Validate all cryptographic outputs (check for null/failure)
- [ ] Verify vault binding before performing operations
- [ ] Use XChaCha20-Poly1305 with 24-byte random nonces
- [ ] Use domain separation in HKDF (`vettid-cek-v1`, `vettid-utk-v1`)
- [ ] Validate PHC string format and minimum Argon2id parameters
- [ ] Log authentication attempts (without sensitive data)
- [ ] Implement rate limiting on authentication endpoints

---

## Changelog

- **2026-01-19 (v2.0)**: Major format revision
  - Added `format_version` for migration support
  - Restructured to grouped objects (`identity`, `auth`, `timestamps`)
  - Added `crypto_metadata` for algorithm agility
  - Added `binding` for vault binding
  - Enhanced `crypto_keys` with `public_key` and `derivation_path`
  - Unified auth to single PHC-format `hash` field
  - Updated HKDF to use domain separation
  - Removed redundant `hash_algorithm` and `hash_version` fields

- **2025-01-01 (v1.0)**: Initial specification
