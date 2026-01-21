# App-Vault End-to-End Encryption

## Overview

This document specifies the application-layer encryption for app-to-vault communication over NATS. This provides defense-in-depth beyond the transport-layer TLS (ACM on NLB), ensuring that even if NATS infrastructure is compromised, message contents remain confidential.

## Security Layers

```
┌─────────────────────────────────────────────────────────────────┐
│  Mobile App                                      Vault Instance │
│  ──────────                                      ────────────── │
│  ┌─────────────────────────┐    ┌─────────────────────────────┐│
│  │ Application Layer       │    │ Application Layer           ││
│  │ E2E Encrypted Payload   │◄──►│ E2E Encrypted Payload       ││
│  │ (ChaCha20-Poly1305)     │    │ (ChaCha20-Poly1305)         ││
│  └─────────────────────────┘    └─────────────────────────────┘│
│            │                              │                     │
│  ┌─────────────────────────┐    ┌─────────────────────────────┐│
│  │ Transport Layer         │    │ Transport Layer             ││
│  │ TLS 1.2+ (ACM Cert)     │◄──►│ TLS 1.2+ (ACM Cert)         ││
│  │ via NLB                 │    │ NATS Cluster                ││
│  └─────────────────────────┘    └─────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

**Layer 1: TLS (Transport)**
- NLB terminates TLS with ACM certificate (publicly trusted)
- Protects against network-level eavesdropping
- Standard protection for all NATS traffic

**Layer 2: E2E Encryption (Application)**
- Encrypts message payloads before sending to NATS
- Only app and vault can decrypt - NATS sees ciphertext only
- Uses per-session symmetric key derived from ECDH

## Key Exchange Protocol

### During Enrollment (Bootstrap)

The key exchange happens during the initial bootstrap handshake:

```
┌──────────────────────────────────────────────────────────────────────┐
│ 1. Vault Generates Session Keys on First Boot                        │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  vault-manager startup:                                               │
│    vault_session_keypair = X25519.generate()                         │
│    store vault_session_keypair in secure memory                       │
│                                                                       │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│ 2. App Calls app.bootstrap                                            │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  Mobile App:                                                          │
│    app_session_keypair = X25519.generate()                           │
│                                                                       │
│  NATS Publish → ${ownerSpace}.forVault.app.bootstrap                  │
│  {                                                                    │
│    "request_id": "...",                                              │
│    "app_session_public_key": base64(app_session_keypair.publicKey), │
│    "device_id": "...",                                               │
│    "timestamp": "..."                                                │
│  }                                                                   │
│                                                                       │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│ 3. Vault Responds with Session Key                                    │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  vault-manager:                                                       │
│    shared_secret = X25519(vault_session_private, app_session_public) │
│    session_key = HKDF(shared_secret, "app-vault-session-v1")         │
│                                                                       │
│  NATS Reply → ${ownerSpace}.forApp.bootstrap.{request_id}            │
│  {                                                                    │
│    "status": "success",                                              │
│    "vault_session_public_key": base64(vault_session_keypair.pubKey),│
│    "nats_credentials": "...",  // Full NATS creds                    │
│    "session_id": "...",        // For key rotation                   │
│    "session_expires_at": "..." // Session lifetime                   │
│  }                                                                   │
│                                                                       │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│ 4. App Derives Session Key                                            │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  Mobile App:                                                          │
│    shared_secret = X25519(app_session_private, vault_session_public) │
│    session_key = HKDF(shared_secret, "app-vault-session-v1")         │
│    // Both sides now have identical session_key                      │
│                                                                       │
└──────────────────────────────────────────────────────────────────────┘
```

## Message Encryption

### Encrypted Message Format

All app-vault messages (except bootstrap) use this envelope:

```typescript
interface EncryptedMessage {
  // Envelope (plaintext, visible to NATS)
  version: 1;
  session_id: string;      // Identifies which session key to use

  // Encrypted payload
  ciphertext: string;      // Base64 ChaCha20-Poly1305 encrypted
  nonce: string;           // Base64 12-byte nonce

  // Optional: For forward secrecy (ephemeral re-keying)
  ephemeral_public_key?: string;  // Base64 X25519 public key
}

interface DecryptedPayload {
  // Original message fields
  type: string;
  request_id: string;
  timestamp: string;
  // ... handler-specific fields
}
```

### Encryption Algorithm

```typescript
// Sender encrypts:
function encryptAppVaultMessage(
  payload: object,
  sessionKey: Buffer
): EncryptedMessage {
  const nonce = crypto.randomBytes(12);
  const plaintext = Buffer.from(JSON.stringify(payload), 'utf8');

  const cipher = crypto.createCipheriv('chacha20-poly1305', sessionKey, nonce, {
    authTagLength: 16
  });

  const encrypted = Buffer.concat([
    cipher.update(plaintext),
    cipher.final(),
    cipher.getAuthTag()  // 16 bytes appended
  ]);

  return {
    version: 1,
    session_id: currentSessionId,
    ciphertext: encrypted.toString('base64'),
    nonce: nonce.toString('base64')
  };
}

// Receiver decrypts:
function decryptAppVaultMessage(
  message: EncryptedMessage,
  sessionKey: Buffer
): object {
  const nonce = Buffer.from(message.nonce, 'base64');
  const ciphertext = Buffer.from(message.ciphertext, 'base64');

  // Split ciphertext and auth tag
  const authTag = ciphertext.slice(-16);
  const encrypted = ciphertext.slice(0, -16);

  const decipher = crypto.createDecipheriv('chacha20-poly1305', sessionKey, nonce, {
    authTagLength: 16
  });
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final()
  ]);

  return JSON.parse(decrypted.toString('utf8'));
}
```

## Session Key Rotation

### Automatic Rotation Triggers

1. **Time-based**: Every 24 hours
2. **Message count**: Every 1000 messages
3. **Explicit request**: App or vault requests rotation

### Rotation Protocol

```
┌──────────────────────────────────────────────────────────────────────┐
│ Key Rotation Flow                                                     │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  App (initiator):                                                     │
│    new_app_keypair = X25519.generate()                               │
│                                                                       │
│  NATS Publish → ${ownerSpace}.forVault.session.rotate                 │
│  ENCRYPTED with current session_key:                                  │
│  {                                                                    │
│    "type": "session.rotate",                                         │
│    "new_app_public_key": base64(new_app_keypair.publicKey),          │
│    "reason": "scheduled|message_count|explicit"                      │
│  }                                                                   │
│                                                                       │
│  Vault:                                                               │
│    new_vault_keypair = X25519.generate()                             │
│    new_session_key = HKDF(X25519(new_vault_priv, new_app_pub), ...)  │
│                                                                       │
│  NATS Reply (encrypted with OLD session key):                         │
│  {                                                                    │
│    "status": "success",                                              │
│    "new_vault_public_key": base64(new_vault_keypair.publicKey),      │
│    "new_session_id": "...",                                          │
│    "effective_at": "..."  // Grace period for in-flight messages     │
│  }                                                                   │
│                                                                       │
│  Both sides:                                                          │
│    - Keep old session key for grace period (decrypt in-flight msgs)  │
│    - Use new session key for all new messages                        │
│    - Delete old key after grace period                               │
│                                                                       │
└──────────────────────────────────────────────────────────────────────┘
```

## Forward Secrecy Option

For high-sensitivity operations, messages can use ephemeral keys:

```typescript
interface EphemeralEncryptedMessage {
  version: 1;
  session_id: string;

  // Ephemeral ECDH for this specific message
  ephemeral_public_key: string;  // Sender's ephemeral X25519 public key
  ciphertext: string;
  nonce: string;
}
```

With ephemeral mode:
1. Sender generates new X25519 key pair for each message
2. Derives per-message key using ephemeral + recipient's session public key
3. Even if session key is compromised, past messages remain secure

## Implementation Locations

### Vault-Manager (Go)

```go
// internal/crypto/session.go
type SessionManager struct {
    sessionKey    []byte
    sessionId     string
    keypair       *x25519.KeyPair
    messageCount  int
    createdAt     time.Time
}

func (s *SessionManager) Encrypt(payload []byte) (*EncryptedMessage, error)
func (s *SessionManager) Decrypt(msg *EncryptedMessage) ([]byte, error)
func (s *SessionManager) ShouldRotate() bool
func (s *SessionManager) Rotate(peerPublicKey []byte) error
```

### Android App (Kotlin)

```kotlin
// core/crypto/SessionCrypto.kt
class SessionCrypto(
    private val sessionKey: ByteArray,
    private val sessionId: String,
    private val vaultPublicKey: ByteArray
) {
    fun encrypt(payload: JsonObject): EncryptedMessage
    fun decrypt(message: EncryptedMessage): JsonObject
    fun requestRotation(): RotationRequest
    fun completeRotation(response: RotationResponse): SessionCrypto
}
```

### Backend Lambda (TypeScript)

No changes needed - backend doesn't see decrypted app-vault messages.

## Message Topics Summary

| Topic | Encrypted? | Notes |
|-------|-----------|-------|
| `${ownerSpace}.forVault.app.bootstrap` | No | Key exchange message |
| `${ownerSpace}.forApp.bootstrap.>` | No | Key exchange response |
| `${ownerSpace}.forVault.*` (all others) | Yes | App → Vault |
| `${ownerSpace}.forApp.*` (all others) | Yes | Vault → App |
| `${ownerSpace}.forServices.*` | Yes | Vault → Backend |

## Threat Model

### Protected Against

1. **Compromised NATS cluster**: Cannot read message contents
2. **Network sniffing (post-TLS)**: Defense-in-depth
3. **Storage attacks**: Encrypted at rest in NATS JetStream
4. **Future session compromise**: Past messages protected (with ephemeral mode)

### Not Protected Against

1. **Compromised vault-manager process**: Has session key in memory
2. **Compromised mobile app**: Has session key in memory
3. **Active MITM during bootstrap**: TLS layer prevents this

## Android Implementation Notes

```kotlin
// Add to NatsClient.kt

class SecureNatsClient(
    private val connection: Connection,
    private val sessionCrypto: SessionCrypto
) {
    /**
     * Send encrypted message to vault
     */
    suspend fun publishSecure(topic: String, payload: JsonObject): String {
        val encrypted = sessionCrypto.encrypt(payload)
        val requestId = payload.getString("request_id")

        connection.publish(topic, encrypted.toJson().toString().toByteArray())
        return requestId
    }

    /**
     * Subscribe to encrypted responses from vault
     */
    fun subscribeSecure(
        topic: String,
        handler: (JsonObject) -> Unit
    ): Dispatcher {
        return connection.createDispatcher { msg ->
            val encrypted = EncryptedMessage.fromJson(String(msg.data))
            val decrypted = sessionCrypto.decrypt(encrypted)
            handler(decrypted)
        }.subscribe(topic)
    }
}
```

## Vault-Manager Implementation Notes

```go
// Add to internal/nats/handlers.go

func (h *Handlers) wrapSecure(
    handler func(msg *nats.Msg, payload []byte) ([]byte, error),
) nats.MsgHandler {
    return func(msg *nats.Msg) {
        // Decrypt incoming
        encrypted := parseEncryptedMessage(msg.Data)
        plaintext, err := h.session.Decrypt(encrypted)
        if err != nil {
            h.replyError(msg, "decryption_failed")
            return
        }

        // Call handler
        response, err := handler(msg, plaintext)
        if err != nil {
            h.replyError(msg, err.Error())
            return
        }

        // Encrypt response
        encryptedResponse := h.session.Encrypt(response)
        msg.Respond(encryptedResponse.ToJSON())
    }
}
```

## Rollout Plan

### Phase 1: Add Key Exchange to Bootstrap
- Modify `app.bootstrap` handler to exchange session keys
- Store session key in vault-manager memory
- Return vault's public key in bootstrap response

### Phase 2: Add Encryption to Vault-Manager
- Create `SessionCrypto` module in vault-manager
- Wrap all forVault handlers with encryption layer
- Keep unencrypted fallback for backward compatibility

### Phase 3: Add Encryption to Android App
- Create `SessionCrypto` class
- Store session key in encrypted preferences
- Update NatsClient to use encryption

### Phase 4: Remove Fallback
- Remove unencrypted message handling
- All app-vault communication E2E encrypted
