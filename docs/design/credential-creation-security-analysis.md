# Credential Creation Security Analysis

**Status:** APPROVED
**Date:** 2026-01-19
**Author:** Architecture Team

---

## Overview

This document analyzes the security of the credential password setup during enrollment, specifically examining:
1. Where the Argon2id salt and hash should be generated
2. What data the app stores locally vs what's in the encrypted credential
3. How credential restore works when the app has no local data
4. Cryptographic algorithm choices

---

## Security Decisions

### 1. Password Hash Format: PHC String

**Decision:** Use Argon2id PHC (Password Hashing Competition) string format.

```
$argon2id$v=19$m=65536,t=3,p=4$<base64-salt>$<base64-hash>
```

**Rationale:**
- Self-describing - includes algorithm, version, and all parameters
- Prevents parameter mismatch bugs during verification
- Future-proof - if we upgrade params, old hashes still verify correctly
- Standard format recognized by all Argon2 libraries

### 2. Cipher Algorithm: XChaCha20-Poly1305

**Decision:** Use XChaCha20-Poly1305 (24-byte nonce) instead of ChaCha20-Poly1305 (12-byte nonce).

**Rationale:**
- 24-byte nonce eliminates birthday collision risk with random nonces
- Safe for ~2^96 messages vs ~2^32 for ChaCha20
- Negligible performance overhead (~3%)
- libsodium standard, well-supported

### 3. HKDF: Domain Separation Pattern

**Decision:** Use domain-specific constants for HKDF key derivation.

```go
DomainCEK = "vettid-cek-v1"  // Credential encryption
DomainUTK = "vettid-utk-v1"  // UTK payload encryption
DomainPIN = "vettid-pin-v1"  // PIN encryption
```

**Rationale:**
- Prevents key confusion attacks
- Different contexts produce cryptographically independent keys
- Clear purpose for each domain
- Versioned for future upgrades

### 4. Argon2id Parameters: 64 MB Memory

**Decision:** Use 64 MB memory (not 256 MB).

```
Argon2id: t=3, m=65536 (64MB), p=4, keyLen=32
```

**Rationale:**
- 64 MB is OWASP recommended minimum
- Device compatibility - works on all mobile devices including 2GB RAM
- Acceptable UX - ~0.5-1 second hashing time
- Enclave rate-limiting provides additional brute-force protection
- 256 MB risks OOM on budget devices and causes noticeable delays

---

## Key Constraint: App Cannot Read Encrypted Credential

The encrypted credential blob is **opaque to the app**. Only the vault (with CEK) can decrypt it.

This creates a challenge for password verification:
- App needs to recompute hash for verification
- But app can't extract params from encrypted credential

**Solution:** App stores password hash params locally (extracted from PHC string after creation).

---

## Data Storage Locations

| Data | Location | Readable By | Purpose |
|------|----------|-------------|---------|
| `encrypted_credential` | App local storage | Vault only | Contains identity keys, master secret, password_hash, etc. |
| `password_salt` | App local storage | App | Extracted from PHC string for re-hashing |
| `argon2_params` | App local storage | App | Extracted from PHC string for re-hashing |
| `utks` | App local storage | App | For encrypting payloads to vault |

**App's local storage after enrollment:**
```json
{
  "encrypted_credential": "<base64 opaque blob>",
  "password_salt": "<base64 16 bytes>",
  "argon2_params": {"t": 3, "m": 65536, "p": 4},
  "utks": [
    {"id": "utk-xxx", "public_key": "<base64>"}
  ]
}
```

**Inside encrypted credential (vault-readable only):**
```json
{
  "version": 1,
  "owner_id": "usr_xxx",
  "created_at": 1705555555,
  "last_modified": 1705555555,

  "password_hash": "$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>",
  "auth_type": "password",

  "identity_keypair": {
    "type": "ed25519",
    "public_key": "<base64>",
    "private_key": "<base64>"
  },
  "master_secret": "<base64 32 bytes>",
  "crypto_keys": []
}
```

**Note:** Salt and params are in BOTH places:
- Credential has PHC string (self-contained for restore)
- App extracts and stores salt/params locally for normal verification

---

## Flow 1: Credential Creation (Enrollment)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Credential Creation (Enrollment)                         │
│                                                                             │
│  ┌──────────────┐                              ┌──────────────────────┐     │
│  │   Mobile App │                              │   Vault (Enclave)    │     │
│  └──────┬───────┘                              └──────────┬───────────┘     │
│         │                                                 │                 │
│         │ 1. User enters credential password              │                 │
│         │                                                 │                 │
│         │ 2. App generates (MUST use secure RNG):         │                 │
│         │    salt = SecureRandom(16 bytes)                │                 │
│         │                                                 │                 │
│         │ 3. App computes Argon2id:                       │                 │
│         │    hash = Argon2id(password, salt,              │                 │
│         │            t=3, m=65536, p=4, keyLen=32)        │                 │
│         │                                                 │                 │
│         │ 4. App formats as PHC string:                   │                 │
│         │    "$argon2id$v=19$m=65536,t=3,p=4$             │                 │
│         │     <base64-salt>$<base64-hash>"                │                 │
│         │                                                 │                 │
│         │ 5. App encrypts with UTK (domain: vettid-utk-v1):                 │
│         │    XChaCha20-Poly1305 encryption                │                 │
│         │    payload = { password_hash: "<PHC string>" }  │                 │
│         │                                                 │                 │
│         │ 6. Publish to forVault.credential.create        │                 │
│         │    {                                            │                 │
│         │      id: "<uuid>",                              │                 │
│         │      type: "credential.create",                 │                 │
│         │      utk_id: "<utk-from-pin-setup>",            │                 │
│         │      encrypted_payload: "<base64>",             │                 │
│         │      timestamp: "<ISO8601>"                     │                 │
│         │    }                                            │                 │
│         │ ────────────────────────────────────────────────►                 │
│         │                                                 │                 │
│         │                                      7. Validate message:         │
│         │                                         • timestamp < 5 min old   │
│         │                                         • utk_id exists & unused  │
│         │                                                 │                 │
│         │                                      8. Decrypt payload with LTK  │
│         │                                         XChaCha20-Poly1305        │
│         │                                         (domain: vettid-utk-v1)   │
│         │                                                 │                 │
│         │                                      9. Validate PHC string:      │
│         │                                         • Parse and verify format │
│         │                                         • Check m >= 65536        │
│         │                                         • Check t >= 3            │
│         │                                         • Check p >= 1            │
│         │                                                 │                 │
│         │                                     10. Mark UTK as used          │
│         │                                                 │                 │
│         │                                     11. Create Protean Credential:│
│         │                                         • Generate identity keys  │
│         │                                         • Generate master secret  │
│         │                                         • Store PHC string as     │
│         │                                           password_hash           │
│         │                                                 │                 │
│         │                                     12. Encrypt credential w/CEK  │
│         │                                         XChaCha20-Poly1305        │
│         │                                         (domain: vettid-cek-v1)   │
│         │                                                 │                 │
│         │                                     13. Generate new UTKs         │
│         │                                                 │                 │
│         │ 14. Response on forApp.credential.create.response                 │
│         │ ◄────────────────────────────────────────────────                 │
│         │    {                                            │                 │
│         │      status: "created",                         │                 │
│         │      encrypted_credential: "<base64>",          │                 │
│         │      new_utks: [...],                           │                 │
│         │      event_id: "<original request id>"          │                 │
│         │    }                                            │                 │
│         │                                                 │                 │
│         │ 15. App stores LOCALLY:                         │                 │
│         │     • encrypted_credential (opaque)             │                 │
│         │     • password_salt (extracted from PHC)        │                 │
│         │     • argon2_params (extracted from PHC)        │                 │
│         │     • new_utks                                  │                 │
│         │                                                 │                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Flow 2: Password Verification (Normal Operation)

After enrollment, when user performs operations:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Password Verification (Normal Operation)                 │
│                                                                             │
│  ┌──────────────┐                              ┌──────────────────────┐     │
│  │   Mobile App │                              │   Vault (Enclave)    │     │
│  └──────┬───────┘                              └──────────┬───────────┘     │
│         │                                                 │                 │
│         │ 1. User initiates operation (e.g., sign tx)     │                 │
│         │                                                 │                 │
│         │ 2. App retrieves from LOCAL storage:            │                 │
│         │    • password_salt                              │                 │
│         │    • argon2_params                              │                 │
│         │    • encrypted_credential                       │                 │
│         │    • utk                                        │                 │
│         │                                                 │                 │
│         │ 3. User enters password                         │                 │
│         │                                                 │                 │
│         │ 4. App computes hash using local salt/params:   │                 │
│         │    hash = Argon2id(password, local_salt,        │                 │
│         │                    local_params)                │                 │
│         │                                                 │                 │
│         │ 5. App encrypts hash with UTK                   │                 │
│         │    (XChaCha20-Poly1305, domain: vettid-utk-v1)  │                 │
│         │                                                 │                 │
│         │ 6. Send operation request                       │                 │
│         │    {                                            │                 │
│         │      credential: "<encrypted blob>",            │                 │
│         │      operation: "sign_transaction",             │                 │
│         │      encrypted_password_hash: "<UTK encrypted>",│                 │
│         │      utk_id: "utk-xxx",                         │                 │
│         │      params: {...}                              │                 │
│         │    }                                            │                 │
│         │ ────────────────────────────────────────────────►                 │
│         │                                                 │                 │
│         │                                      7. Decrypt credential w/CEK  │
│         │                                      8. Decrypt hash with LTK     │
│         │                                      9. Parse stored PHC string,  │
│         │                                         extract salt/params       │
│         │                                     10. Recompute expected hash   │
│         │                                     11. Constant-time compare     │
│         │                                                 │                 │
│         │                                     12. If match:                 │
│         │                                         • Perform operation       │
│         │                                         • Rotate CEK              │
│         │                                         • Re-encrypt credential   │
│         │                                                 │                 │
│         │ 13. Response                                    │                 │
│         │ ◄────────────────────────────────────────────────                 │
│         │    {                                            │                 │
│         │      result: {...},                             │                 │
│         │      new_credential: "<re-encrypted>",          │                 │
│         │      new_utks: [...]                            │                 │
│         │    }                                            │                 │
│         │                                                 │                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Flow 3: Credential Restore (New Device)

When user loses device and restores credential from backup:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Credential Restore (New Device)                          │
│                                                                             │
│  ┌──────────────┐                              ┌──────────────────────┐     │
│  │   Mobile App │                              │   Vault (Enclave)    │     │
│  │  (New Device)│                              │                      │     │
│  └──────┬───────┘                              └──────────┬───────────┘     │
│         │                                                 │                 │
│         │  PROBLEM: App has NO local data                 │                 │
│         │  - No password_salt                             │                 │
│         │  - No argon2_params                             │                 │
│         │  - No UTKs                                      │                 │
│         │                                                 │                 │
│         │ 1. User authenticates to VettID account         │                 │
│         │    (email/phone verification)                   │                 │
│         │                                                 │                 │
│         │ 2. App downloads from backup:                   │                 │
│         │    • encrypted_credential (opaque blob)         │                 │
│         │    • bootstrap UTKs (for restore flow)          │                 │
│         │                                                 │                 │
│         │ 3. Request restore                              │                 │
│         │    {                                            │                 │
│         │      credential: "<encrypted blob>",            │                 │
│         │      operation: "restore"                       │                 │
│         │    }                                            │                 │
│         │ ────────────────────────────────────────────────►                 │
│         │                                                 │                 │
│         │                                      4. Decrypt credential w/CEK  │
│         │                                         Parse PHC string to get:  │
│         │                                         • password_salt           │
│         │                                         • argon2_params           │
│         │                                                 │                 │
│         │ 5. Challenge WITH salt/params (restore-only)    │                 │
│         │ ◄────────────────────────────────────────────────                 │
│         │    {                                            │                 │
│         │      challenge_id: "xyz",                       │                 │
│         │      utk_id: "utk-restore-xxx",                 │                 │
│         │      password_salt: "<base64>",    ← RESTORE ONLY                 │
│         │      argon2_params: {t:3, m:65536, p:4},        │                 │
│         │      expires_in: 60                             │                 │
│         │    }                                            │                 │
│         │                                                 │                 │
│         │ 6. User enters password                         │                 │
│         │                                                 │                 │
│         │ 7. App computes hash using RECEIVED salt:       │                 │
│         │    hash = Argon2id(password, received_salt,     │                 │
│         │                    received_params)             │                 │
│         │                                                 │                 │
│         │ 8. App encrypts hash with UTK                   │                 │
│         │                                                 │                 │
│         │ 9. Challenge response                           │                 │
│         │    {                                            │                 │
│         │      challenge_id: "xyz",                       │                 │
│         │      encrypted_password_hash: "<UTK encrypted>",│                 │
│         │      utk_id: "utk-restore-xxx"                  │                 │
│         │    }                                            │                 │
│         │ ────────────────────────────────────────────────►                 │
│         │                                                 │                 │
│         │                                     10. Decrypt hash with LTK     │
│         │                                     11. Verify against stored PHC │
│         │                                                 │                 │
│         │                                     12. If valid:                 │
│         │                                         • Rotate CEK              │
│         │                                         • Generate new UTKs       │
│         │                                         • Re-encrypt credential   │
│         │                                                 │                 │
│         │ 13. Restore success                             │                 │
│         │ ◄────────────────────────────────────────────────                 │
│         │    {                                            │                 │
│         │      status: "restored",                        │                 │
│         │      encrypted_credential: "<re-encrypted>",    │                 │
│         │      new_utks: [...]                            │                 │
│         │    }                                            │                 │
│         │                                                 │                 │
│         │ 14. App stores LOCALLY (now has everything):    │                 │
│         │     • encrypted_credential                      │                 │
│         │     • password_salt (from challenge)            │                 │
│         │     • argon2_params (from challenge)            │                 │
│         │     • new_utks                                  │                 │
│         │                                                 │                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Implementation Changes Required

### Backend (Vault-Manager)

#### 1. crypto.go - XChaCha20-Poly1305 + Domain Separation

```go
import "golang.org/x/crypto/chacha20poly1305"

// Domain constants
const (
    DomainCEK = "vettid-cek-v1"
    DomainUTK = "vettid-utk-v1"
    DomainPIN = "vettid-pin-v1"
)

// Use XChaCha20-Poly1305 (24-byte nonce)
func encryptWithDomain(recipientPubKey []byte, plaintext []byte, domain string) ([]byte, error) {
    // ... ECDH key exchange ...

    // HKDF with domain separation
    hkdfReader := hkdf.New(sha256.New, sharedSecret, []byte(domain), nil)
    encKey := make([]byte, chacha20poly1305.KeySize)
    hkdfReader.Read(encKey)

    // XChaCha20-Poly1305 (24-byte nonce)
    aead, _ := chacha20poly1305.NewX(encKey)
    nonce := make([]byte, chacha20poly1305.NonceSizeX)  // 24 bytes
    rand.Read(nonce)

    ciphertext := aead.Seal(nil, nonce, plaintext, nil)
    // Return: ephemeral_pub (32) || nonce (24) || ciphertext
}
```

#### 2. credential_types.go - PHC String Format

```go
type CredentialCreatePayload struct {
    PasswordHash string `json:"password_hash"` // PHC string format
}

type ProteanCredential struct {
    Version      int    `json:"version"`
    OwnerID      string `json:"owner_id"`
    CreatedAt    int64  `json:"created_at"`
    LastModified int64  `json:"last_modified"`

    PasswordHash string `json:"password_hash"` // PHC string: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
    AuthType     string `json:"auth_type"`

    IdentityKeypair IdentityKeypair `json:"identity_keypair"`
    MasterSecret    string          `json:"master_secret"`
    CryptoKeys      []CryptoKey     `json:"crypto_keys"`
}
```

#### 3. protean_credential_handler.go - PHC Validation

```go
import "github.com/matthewhartstonge/argon2"

func validatePHCString(phc string) error {
    // Parse PHC format: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
    raw, err := argon2.Decode([]byte(phc))
    if err != nil {
        return errors.New("invalid PHC string format")
    }

    if raw.Config.Mode != argon2.ModeArgon2id {
        return errors.New("must use argon2id")
    }
    if raw.Config.MemoryCost < 65536 {
        return errors.New("memory cost must be >= 65536 (64MB)")
    }
    if raw.Config.TimeCost < 3 {
        return errors.New("time cost must be >= 3")
    }
    if raw.Config.Parallelism < 1 {
        return errors.New("parallelism must be >= 1")
    }

    return nil
}
```

### Mobile Apps (Android/iOS)

#### Local Storage Structure

```kotlin
// Android
data class VaultLocalData(
    val encryptedCredential: ByteArray,
    val passwordSalt: ByteArray,        // Extracted from PHC
    val argon2Params: Argon2Params,     // Extracted from PHC
    val utks: List<UTK>
)

// After credential creation, parse PHC string to extract salt/params
fun extractFromPHC(phcString: String): Pair<ByteArray, Argon2Params> {
    // Parse: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
    val parts = phcString.split("$")
    val params = parseParams(parts[3])  // m=65536,t=3,p=4
    val salt = Base64.decode(parts[4])
    return Pair(salt, params)
}
```

#### XChaCha20-Poly1305 Encryption

```kotlin
// Android - use libsodium or Tink
fun encryptWithUTK(payload: ByteArray, utkPublicKey: ByteArray): ByteArray {
    // Generate ephemeral keypair
    val ephemeral = X25519.generateKeyPair()

    // ECDH
    val sharedSecret = X25519.computeSharedSecret(ephemeral.privateKey, utkPublicKey)

    // HKDF with domain
    val encKey = HKDF.derive(sharedSecret, "vettid-utk-v1".toByteArray(), 32)

    // XChaCha20-Poly1305 (24-byte nonce)
    val nonce = SecureRandom().generateSeed(24)
    val ciphertext = XChaCha20Poly1305.encrypt(encKey, nonce, payload)

    // Return: ephemeral_pub || nonce || ciphertext
    return ephemeral.publicKey + nonce + ciphertext
}
```

---

## Security Checklist

### App Requirements
- [ ] Use hardware-backed secure RNG (SecRandomCopyBytes / SecureRandom)
- [ ] Use Argon2id with t=3, m=65536 (64MB), p=4, keyLen=32
- [ ] Generate PHC string format for password hash
- [ ] Extract and store salt/params locally after credential creation
- [ ] Use XChaCha20-Poly1305 for encryption
- [ ] Use domain separation (`vettid-utk-v1`) in HKDF
- [ ] Zero password from memory after hashing
- [ ] Never log or persist plaintext password

### Vault Requirements
- [ ] Validate PHC string format and minimum parameters
- [ ] Use XChaCha20-Poly1305 for encryption
- [ ] Use domain separation in HKDF
- [ ] Use constant-time comparison for hash verification
- [ ] Zero decrypted payload after processing
- [ ] Single-use UTK enforcement (prevent replay)
- [ ] Include salt/params in restore challenge only
- [ ] Rate-limit restore attempts

### Transport Requirements
- [ ] All payloads encrypted with ECIES (UTK/LTK)
- [ ] Domain separation in HKDF (`vettid-utk-v1` for payloads)
- [ ] XChaCha20-Poly1305 with 24-byte random nonce
- [ ] Timestamp validation (reject messages > 5 min old)
- [ ] Include event_id in all responses for correlation

---

## Changelog

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 0.1 | 2026-01-19 | Architecture Team | Initial draft |
| 0.2 | 2026-01-19 | Architecture Team | Added restore flow, clarified salt storage |
| 1.0 | 2026-01-19 | Architecture Team | APPROVED: PHC string format, XChaCha20-Poly1305, domain separation, 64MB Argon2id |
