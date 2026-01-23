# NATS Account Management API

This document describes the REST API endpoints for NATS account and credential management. Mobile apps use these endpoints to obtain NATS credentials for connecting to the VettID central NATS cluster.

## Overview

VettID uses NATS with Ed25519 nkeys for authentication. Each member has:
- **Account**: A namespace isolation boundary signed by the VettID operator
- **User Credentials**: JWT + NKey seed for authenticating to NATS

The mobile app requests credentials via REST API, then uses them to connect to NATS.

## API Endpoints

### Base URL
```
https://api.vettid.dev
```

### Authentication
All endpoints require a valid Cognito JWT token in the `Authorization` header:
```
Authorization: Bearer <cognito_jwt>
```

---

## Create Member Account

Creates or retrieves a NATS account for the authenticated member. This must be called once after enrollment before requesting user credentials.

**Endpoint:** `POST /nats/account`

**Request Body:** None required

**Response:**
```json
{
  "account_public_key": "AABCD...",
  "owner_space": "OwnerSpace.abc123",
  "message_space": "MessageSpace.abc123",
  "created_at": "2024-01-15T10:30:00Z"
}
```

**Response Fields:**
| Field | Type | Description |
|-------|------|-------------|
| `account_public_key` | string | NATS account public key (starts with 'A') |
| `owner_space` | string | OwnerSpace namespace for app-vault communication |
| `message_space` | string | MessageSpace namespace for connections |
| `created_at` | string | ISO8601 timestamp of account creation |

**Error Responses:**
- `401 Unauthorized` - Invalid or missing JWT
- `404 Not Found` - Member not enrolled
- `500 Internal Server Error` - Account creation failed

---

## Generate App Credentials

Generates NATS user credentials for the mobile app to connect to OwnerSpace.

**Endpoint:** `POST /nats/credentials`

**Request Body:**
```json
{
  "client_type": "app"
}
```

**Response:**
```json
{
  "jwt": "eyJ...",
  "seed": "SUAB...",
  "public_key": "UABC...",
  "nats_creds": "-----BEGIN NATS USER JWT-----\n...",
  "expires_at": "2024-01-16T10:30:00Z",
  "nats_url": "tls://nats.vettid.dev:443",
  "owner_space": "OwnerSpace.abc123",
  "message_space": "MessageSpace.abc123"
}
```

**Response Fields:**
| Field | Type | Description |
|-------|------|-------------|
| `jwt` | string | NATS user JWT (base64url encoded) |
| `seed` | string | NATS user seed (starts with 'SU') |
| `public_key` | string | NATS user public key (starts with 'U') |
| `nats_creds` | string | Full credentials file content (for file-based auth) |
| `expires_at` | string | ISO8601 timestamp when credentials expire |
| `nats_url` | string | NATS server URL to connect to |
| `owner_space` | string | OwnerSpace namespace prefix |
| `message_space` | string | MessageSpace namespace prefix |

**App Permissions:**
| Permission | Topics |
|------------|--------|
| Publish | `{owner_space}.forVault.>` |
| Subscribe | `{owner_space}.forApp.>`, `{owner_space}.eventTypes`, `Directory.>` |

**Error Responses:**
- `400 Bad Request` - Invalid client_type
- `401 Unauthorized` - Invalid or missing JWT
- `404 Not Found` - Account not created (call POST /nats/account first)

---

## Generate Vault Credentials (Vault Services Only)

Generates NATS credentials for a vault instance. This endpoint is called by Vault Services during vault provisioning.

**Endpoint:** `POST /nats/credentials`

**Request Body:**
```json
{
  "client_type": "vault"
}
```

**Response:** Same format as app credentials

**Vault Permissions:**
| Permission | Topics |
|------------|--------|
| Publish | `{owner_space}.forApp.>`, `{owner_space}.forServices.>`, `{message_space}.forOwner.>`, `{message_space}.ownerProfile`, `{message_space}.call.>` |
| Subscribe | `{owner_space}.forVault.>`, `{owner_space}.eventTypes`, `{message_space}.forOwner.>`, `{message_space}.fromService.>`, `{message_space}.call.>`, `Broadcast.>`, `Directory.>` |

---

## Generate Control Token (Admin Only)

Generates a control token for Vault Services to send commands to vaults. This is an admin-only endpoint.

**Endpoint:** `POST /admin/nats/control-token`

**Request Body:**
```json
{
  "member_guid": "abc123-def456-..."
}
```

**Response:**
```json
{
  "jwt": "eyJ...",
  "seed": "SUAB...",
  "public_key": "UABC...",
  "nats_creds": "-----BEGIN NATS USER JWT-----\n...",
  "expires_at": "2024-01-15T11:30:00Z"
}
```

**Control Permissions:**
| Permission | Topics |
|------------|--------|
| Publish | `{owner_space}.control` |
| Subscribe | (none) |

---

## Mobile App Integration

### 1. Initial Setup (After Enrollment)

```swift
// iOS Example
func setupNatsAccount() async throws -> NatsAccountInfo {
    let response = try await apiClient.post("/nats/account")
    return try JSONDecoder().decode(NatsAccountInfo.self, from: response.data)
}
```

```kotlin
// Android Example
suspend fun setupNatsAccount(): NatsAccountInfo {
    return apiClient.post("/nats/account")
}
```

### 2. Get Credentials

```swift
// iOS Example
func getNatsCredentials() async throws -> NatsCredentials {
    let body = ["client_type": "app"]
    let response = try await apiClient.post("/nats/credentials", body: body)
    return try JSONDecoder().decode(NatsCredentials.self, from: response.data)
}
```

```kotlin
// Android Example
suspend fun getNatsCredentials(): NatsCredentials {
    return apiClient.post("/nats/credentials", body = mapOf("client_type" to "app"))
}
```

### 3. Connect to NATS

```swift
// iOS Example using NATS.swift
import NATS

func connectToNats(creds: NatsCredentials) async throws -> NatsClient {
    let client = NatsClient()
    try await client.connect(
        url: creds.natsUrl,
        jwt: creds.jwt,
        seed: creds.seed
    )
    return client
}
```

```kotlin
// Android Example using nats.java
import io.nats.client.Nats
import io.nats.client.Options

fun connectToNats(creds: NatsCredentials): Connection {
    val options = Options.Builder()
        .server(creds.natsUrl)
        .authHandler(Nats.credentials(creds.jwt, creds.seed))
        .build()
    return Nats.connect(options)
}
```

### 4. Subscribe to Responses

```swift
// iOS
let subscription = try await client.subscribe(
    "\(creds.ownerSpace).forApp.>"
)
for try await message in subscription {
    handleVaultResponse(message)
}
```

```kotlin
// Android
val dispatcher = connection.createDispatcher { message ->
    handleVaultResponse(message)
}
dispatcher.subscribe("${creds.ownerSpace}.forApp.>")
```

### 5. Send Events to Vault

```swift
// iOS
func sendEvent(type: String, payload: Data) async throws {
    let event = VaultEvent(
        eventId: UUID().uuidString,
        type: type,
        timestamp: ISO8601DateFormatter().string(from: Date()),
        payload: payload
    )
    try await client.publish(
        "\(creds.ownerSpace).forVault.\(type)",
        data: JSONEncoder().encode(event)
    )
}
```

```kotlin
// Android
suspend fun sendEvent(type: String, payload: ByteArray) {
    val event = VaultEvent(
        eventId = UUID.randomUUID().toString(),
        type = type,
        timestamp = Instant.now().toString(),
        payload = payload
    )
    connection.publish(
        "${creds.ownerSpace}.forVault.$type",
        Json.encodeToString(event).toByteArray()
    )
}
```

---

## Credential Lifecycle

### Expiration
- Default credential lifetime: **24 hours**
- Apps should request new credentials before expiration
- Implement automatic credential refresh in the NATS connection wrapper

### Refresh Strategy
```swift
// iOS - Credential refresh wrapper
class NatsConnectionManager {
    private var credentials: NatsCredentials?
    private var client: NatsClient?

    func ensureConnected() async throws {
        if let creds = credentials,
           creds.expiresAt > Date().addingTimeInterval(300) {
            // Still valid for > 5 minutes
            return
        }

        // Refresh credentials
        credentials = try await getNatsCredentials()
        client = try await connectToNats(creds: credentials!)
    }
}
```

### Error Handling
- `AUTHORIZATION_VIOLATION` - Credentials expired or revoked, refresh required
- `CONNECTION_CLOSED` - Network issue, attempt reconnection
- `NATS_CLUSTER_UNAVAILABLE` - Central NATS is down, retry with backoff

---

## Security Considerations

1. **Never store seeds long-term** - Request fresh credentials on app launch
2. **Validate JWT expiration** - Check `expires_at` before each operation
3. **Use TLS** - All NATS connections must use secure transport
4. **Handle revocation** - If credentials are revoked, re-authenticate with Cognito
5. **Rate limiting** - Credential requests are rate-limited to 10/minute per member

---

## Service Connection Topics (B2C)

Third-party services (banks, apps, etc.) communicate with user vaults via the `fromService` topic hierarchy:

### MessageSpace Service Topics

```
MessageSpace.{user_guid}.fromService.{service_id}/
├── auth.*            # Auth request/challenge
├── consent.*         # Consent request for data access
├── payment.*         # Payment request
├── data.*            # Data operations (get/store)
├── contract-update   # Contract version update notification
└── notify            # Push notification from service
```

**SECURITY CRITICAL:** Services can ONLY publish to `fromService` topics - they cannot subscribe to any MessageSpace topics. This ensures services cannot observe user data or communications.

### Service NATS Authentication

Services authenticate to NATS with service-specific credentials:
- **Publish allow:** `MessageSpace.*.fromService.{service_id}.>`
- **Subscribe deny:** ALL MessageSpace topics
- Rate limits: 50 MB/sec, 1 MB max payload

---

## Directory Namespace

The Directory namespace provides real-time service discovery for mobile apps and vaults.

### Topics

```
Directory/
├── services.{service_id}      # Service profile updates
├── announcements              # System-wide service announcements
└── categories.{category}      # Category-specific listings
```

### Access

| Client | Permission |
|--------|------------|
| Mobile App | Subscribe only |
| Vault | Subscribe only |
| Backend | Publish only |

### Example: Subscribe to Service Updates

```swift
// iOS - Subscribe to all directory updates
let subscription = try await client.subscribe("Directory.>")
for try await message in subscription {
    let update = try JSONDecoder().decode(ServiceUpdate.self, from: message.payload)
    handleServiceUpdate(update)
}
```

```kotlin
// Android - Subscribe to specific service
val dispatcher = connection.createDispatcher { message ->
    val update = Json.decodeFromString<ServiceUpdate>(String(message.data))
    handleServiceUpdate(update)
}
dispatcher.subscribe("Directory.services.my-bank-app")
```

---

## NKey Prefixes Reference

| Prefix | Type | Example |
|--------|------|---------|
| O | Operator | `ODHEK4P75YYD...` |
| A | Account | `AA3QFYZ22A62...` |
| U | User | `UABC123DEF45...` |
| SO | Operator Seed | `SOAIBDPBAUTN...` |
| SA | Account Seed | `SAABCDEFGHIJ...` |
| SU | User Seed | `SUAIBDPBAUTN...` |
