# Service Connections Feature

**Feature**: B2C Service Connections for VettID Vault

## Overview

Enable users to connect to services (apps, businesses, organizations) that run their own VettID Service Vaults. Service connections use the same vault-to-vault NATS communication as peer connections, but with additional contract-based permissions and data access controls.

**Key Principle**: Services are vaults too. A service runs a VettID Service Vault that communicates with user vaults over NATS, using the same E2E encryption and bidirectional consent model as peer connections.

---

## Architecture

### Service Vault vs User Vault

| Aspect | User Vault | Service Vault |
|--------|-----------|---------------|
| **Runs on** | User's device (via enclave) | Service's infrastructure (via enclave) |
| **Identity** | User GUID | Service GUID |
| **Connections** | Peers + Services | Users only |
| **Data contracts** | Accepts contracts | Defines contracts |
| **Storage** | Personal data | Service-specific data per user |
| **Verification** | Email, identity | Organization verification |

### Communication Flow

```
┌─────────────────┐                NATS                ┌─────────────────┐
│   User Vault    │◄──────────────────────────────────►│  Service Vault  │
│  (on device)    │         E2E Encrypted              │  (on service)   │
└─────────────────┘                                    └─────────────────┘
        │                                                      │
        │ Stores:                                              │ Stores:
        │ - Service connection                                 │ - User connection
        │ - Accepted contract                                  │ - Contract definition
        │ - Service-provided data                              │ - User-provided data
        │ - Access history                                     │ - Request history
```

---

## Service Connection Flow (Bidirectional Consent)

```
┌─────────────────┐                                    ┌─────────────────┐
│      User       │                                    │     Service     │
│   (Consumer)    │                                    │   (Provider)    │
└────────┬────────┘                                    └────────┬────────┘
         │                                                      │
         │ 1. DISCOVER SERVICE                                  │
         │    - Scan QR code / click link / search              │
         │    - Contains service_guid + NATS connection info    │
         ▼                                                      │
    ┌─────────┐                                                 │
    │ Service │──── Request service profile + contract ────────►│
    │  Info   │                                                 │
    └─────────┘                                                 │
         │◄────────── Service profile + contract ───────────────│
         │                                                      │
         ▼                                                      │
    2. REVIEW CONTRACT                                          │
       - Display service profile + verification status          │
       - Show required/optional fields                          │
       - Show what service can access/store                     │
       - Check if user has required fields                      │
       - [ACCEPT] or [REJECT]                                   │
         │                                                      │
         ├──────────[REJECT]────────► Connection terminated     │
         │                                                      │
         └──────────[ACCEPT]────────►                           │
                                     3. INITIATE CONNECTION     │
                                        - Send user profile     │
                                        - Send NATS credentials │
                                        - Exchange E2E keys     │
         │◄─────────────────────────────────────────────────────│
         │                                                      │
         ▼                                                      ▼
    4. CONNECTION ACTIVE                               4. CONNECTION ACTIVE
       - Store service connection                         - Store user connection
       - Cache service profile                            - Cache user profile
       - Subscribe to service events                      - Subscribe to user events
       - Track contract version                           - Enforce contract
```

### Step-by-Step Protocol

#### Step 1: Discover Service
```typescript
// User scans QR or clicks deep link containing:
{
  type: "vettid-service",
  service_guid: string,
  nats_endpoint: string,           // NATS connection info
  invitation_token: string,        // One-time token for initial connection
  expires_at: string
}
```

#### Step 2: Request Service Profile & Contract
```typescript
// Request to service vault
{
  action: "service.profile.get",
  invitation_token: string
}

// Response from service vault
{
  service_guid: string,
  service_name: string,
  service_description: string,
  service_logo_url: string,
  service_category: string,        // "retail", "healthcare", "finance", etc.
  organization: {
    name: string,
    verified: boolean,
    verification_type: string      // "business", "nonprofit", "government"
  },
  contract: ServiceDataContract,
  temp_nats_credentials: string    // For completing connection
}
```

#### Step 3: Accept Contract & Initiate Connection
```typescript
// Request to service vault
{
  action: "service.connection.initiate",
  service_guid: string,
  user_profile: SharedProfile,     // Fields user chose to share
  user_nats_credentials: string,   // Reciprocal credentials
  user_e2e_public_key: string,
  contract_version: number         // Accepting this version
}

// Response
{
  connection_id: string,
  service_e2e_public_key: string,
  status: "active"
}
```

---

## Data Models

### ServiceConnectionRecord (User Vault)
```go
type ServiceConnectionRecord struct {
    ConnectionRecord // Embed base (E2E keys, status, activity)

    // Service identification
    IsServiceConnection bool   `json:"is_service_connection"`
    ServiceGUID         string `json:"service_guid"`
    ServiceName         string `json:"service_name"`
    ServiceLogoURL      string `json:"service_logo_url,omitempty"`
    ServiceDescription  string `json:"service_description,omitempty"`
    ServiceCategory     string `json:"service_category,omitempty"`

    // Organization verification
    OrganizationName     string `json:"organization_name,omitempty"`
    OrganizationVerified bool   `json:"organization_verified"`
    VerificationType     string `json:"verification_type,omitempty"`

    // Contract tracking
    ContractID         string    `json:"contract_id"`
    ContractVersion    int       `json:"contract_version"`
    ContractAcceptedAt time.Time `json:"contract_accepted_at"`

    // Usability fields (same as peer connections)
    Tags       []string `json:"tags,omitempty"`
    IsFavorite bool     `json:"is_favorite"`
    IsArchived bool     `json:"is_archived"`
    IsMuted    bool     `json:"is_muted"`
}
```

### UserConnectionRecord (Service Vault)
```go
type UserConnectionRecord struct {
    ConnectionRecord // Embed base

    // User identification
    UserGUID    string `json:"user_guid"`
    UserProfile map[string]string `json:"user_profile"` // Shared fields only

    // Contract enforcement
    ContractID      string    `json:"contract_id"`
    ContractVersion int       `json:"contract_version"`
    AcceptedAt      time.Time `json:"accepted_at"`

    // Rate limiting state
    RequestCount    int       `json:"request_count"`
    RequestWindowAt time.Time `json:"request_window_at"`
}
```

### ServiceDataContract
```go
type ServiceDataContract struct {
    ContractID  string `json:"contract_id"`
    ServiceGUID string `json:"service_guid"`
    Version     int    `json:"version"`

    // Human-readable info
    Title       string `json:"title"`
    Description string `json:"description"`
    TermsURL    string `json:"terms_url,omitempty"`
    PrivacyURL  string `json:"privacy_url,omitempty"`

    // Field access levels
    RequiredFields []FieldSpec `json:"required_fields"` // Must have to connect
    OptionalFields []FieldSpec `json:"optional_fields"` // Requested but not required
    OnDemandFields []string    `json:"on_demand_fields"` // Service can read anytime
    ConsentFields  []string    `json:"consent_fields"`   // Requires per-request approval

    // Service permissions
    CanStoreData      bool     `json:"can_store_data"`
    StorageCategories []string `json:"storage_categories,omitempty"`
    CanSendMessages   bool     `json:"can_send_messages"`
    CanRequestAuth    bool     `json:"can_request_auth"`

    // Rate limits
    MaxRequestsPerHour int `json:"max_requests_per_hour,omitempty"`
    MaxStorageMB       int `json:"max_storage_mb,omitempty"`

    // Timestamps
    CreatedAt time.Time  `json:"created_at"`
    ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

type FieldSpec struct {
    Field       string `json:"field"`
    Purpose     string `json:"purpose"`      // Why service needs this
    Retention   string `json:"retention"`    // How long service keeps it
}
```

### ServiceStorageRecord (User Vault - Service's sandbox)
```go
type ServiceStorageRecord struct {
    Key             string     `json:"key"`
    ConnectionID    string     `json:"connection_id"`
    Category        string     `json:"category"`
    VisibilityLevel string     `json:"visibility_level"` // "hidden", "metadata", "viewable"
    EncryptedValue  []byte     `json:"encrypted_value"`
    Label           string     `json:"label,omitempty"`
    Description     string     `json:"description,omitempty"`
    DataType        string     `json:"data_type,omitempty"`
    CreatedAt       time.Time  `json:"created_at"`
    UpdatedAt       time.Time  `json:"updated_at"`
    ExpiresAt       *time.Time `json:"expires_at,omitempty"`
}
```

### ServiceRequest
```go
type ServiceRequest struct {
    RequestID       string     `json:"request_id"`
    ConnectionID    string     `json:"connection_id"`
    RequestType     string     `json:"request_type"` // "auth", "consent", "payment"
    RequestedFields []string   `json:"requested_fields,omitempty"`
    RequestedAction string     `json:"requested_action,omitempty"`
    Purpose         string     `json:"purpose,omitempty"`
    Amount          *Money     `json:"amount,omitempty"` // For payment requests
    Status          string     `json:"status"` // "pending", "approved", "denied", "expired"
    RequestedAt     time.Time  `json:"requested_at"`
    ExpiresAt       time.Time  `json:"expires_at"`
    RespondedAt     *time.Time `json:"responded_at,omitempty"`
}
```

---

## NATS Topics

### Service-to-User Communication
```
# User vault subscribes to:
{user_space}.forVault.service.request.auth      # Service requests authentication
{user_space}.forVault.service.request.consent   # Service requests field consent
{user_space}.forVault.service.request.payment   # Service requests payment
{user_space}.forVault.service.data.store        # Service stores data in user's sandbox
{user_space}.forVault.service.data.update       # Service updates stored data
{user_space}.forVault.service.message           # Service sends message to user
{user_space}.forVault.service.contract.update   # Contract version changed
```

### User-to-Service Communication
```
# Service vault subscribes to:
{service_space}.forVault.user.connect           # User initiates connection
{service_space}.forVault.user.disconnect        # User revokes connection
{service_space}.forVault.user.profile.update    # User profile changed
{service_space}.forVault.user.request.respond   # User responds to request
{service_space}.forVault.user.data.get          # User retrieves stored data
```

### User Vault Handlers (forVault subjects)
```
# Service connection management
service.connection.discover    # Get service profile + contract
service.connection.initiate    # Accept contract, establish connection
service.connection.list        # List service connections
service.connection.get         # Get service connection details
service.connection.update      # Update tags, favorite, muted status
service.connection.revoke      # Revoke connection, optional data cleanup

# Service data in user's sandbox
service.data.list              # List data stored by services
service.data.get               # Get specific data item
service.data.delete            # Delete service data

# Service requests
service.request.list           # List pending/historical requests
service.request.respond        # Approve/deny request

# Contract management
service.contract.get           # Get current contract for connection
service.contract.history       # Get contract version history
```

---

## Usability Features

### 1. Clear Service Identification

**Visual distinction from peer connections:**
```
My Connections
├── 👤 People (12)
│   ├── Alice Cooper ✓
│   ├── Bob Smith ✓
│   └── ...
│
└── 🏢 Services (5)
    ├── Acme Retail ✓ᵛ (verified business)
    ├── City Health Clinic ✓ᵛ
    ├── LocalBank ✓ᵛ
    ├── CoffeeShop Rewards
    └── ...
```

**Implementation:**
- `IsServiceConnection` flag for filtering
- Service logo prominently displayed
- Organization verification badge (✓ᵛ for verified)
- Category icons (retail, health, finance, etc.)

### 2. Contract Review UX

**Before accepting, show:**
```
┌─────────────────────────────────────────────────────┐
│ 🏢 Acme Retail wants to connect                     │
│    ✓ᵛ Verified Business                            │
├─────────────────────────────────────────────────────┤
│                                                     │
│ They need:                                          │
│ ├── ✓ Email (required) - "For order confirmations" │
│ ├── ✓ Name (required) - "For shipping labels"      │
│ └── ○ Phone (optional) - "For delivery updates"    │
│                                                     │
│ They can:                                           │
│ ├── Store purchase history in your vault           │
│ ├── Send you messages                              │
│ └── Request payments                               │
│                                                     │
│ ⚠️ Missing required field: Email                   │
│    [Add Email to Profile]                          │
│                                                     │
├─────────────────────────────────────────────────────┤
│ [View Full Terms]  [Privacy Policy]                 │
│                                                     │
│         [Decline]              [Accept]             │
└─────────────────────────────────────────────────────┘
```

### 3. Service Connection Health

**Same health indicators as peer connections:**
- Last active: "2 hours ago"
- Contract status: "v2 accepted" or "New contract available (v3)"
- Data stored: "12 items, 2.3 MB"
- Request history: "3 requests this month"

### 4. Notification Preferences

**Per-service settings (extends peer connection settings):**
```kotlin
data class ServiceNotificationSettings(
    val level: NotificationLevel,        // ALL, IMPORTANT, MUTED
    val allowPaymentRequests: Boolean,   // Show payment request notifications
    val allowMessages: Boolean,          // Show service messages
    val bypassQuietHours: Boolean        // For critical services
)
```

### 5. Service Organization

**Tags, favorites, archive (same as peers):**
- User-defined tags: "Shopping", "Health", "Finance"
- Favorite services pinned to top
- Archive inactive services without revoking
- Search by name, category, tags

### 6. Activity Dashboard

**Per-service activity view:**
```
Acme Retail - Activity
├── Today
│   ├── 10:30 AM - Stored "Order #12345"
│   └── 10:31 AM - Requested payment: $49.99 ✓ Approved
│
├── Yesterday
│   └── 3:15 PM - Updated shipping address
│
└── Last Week
    ├── Stored 3 items
    └── 1 payment request ($129.00)
```

### 7. Data Transparency

**User controls service-stored data:**
```
Data stored by Acme Retail
├── 📦 Orders (3 items)
│   ├── Order #12345 - $49.99 - Jan 19
│   ├── Order #12344 - $129.00 - Jan 15
│   └── Order #12343 - $75.50 - Jan 10
│
├── 📍 Saved Addresses (1 item)
│   └── Home: 123 Main St...
│
└── [Delete All Data] [Export Data]
```

### 8. Request Management

**Pending requests in unified feed:**
```
Feed
├── 🔔 Acme Retail requests payment: $49.99
│   "Order #12345 - Winter Jacket"
│   [Approve] [Decline] [View Details]
│
├── 🔔 City Health requests: Date of Birth
│   "For appointment scheduling"
│   [Share] [Decline]
│
└── 🔔 LocalBank requests authentication
    "Confirm login from new device"
    [Approve] [Decline]
```

### 9. Offline Handling

**Same offline queue as peer connections:**
- Queue request responses when offline
- Cache service profiles for offline viewing
- Show "pending sync" indicators
- Auto-sync when online

### 10. Trust Indicators

**Trust signals for services:**
```kotlin
data class ServiceTrustInfo(
    val organizationVerified: Boolean,
    val verificationType: String,        // "business", "nonprofit", "government"
    val connectionAge: Duration,
    val totalTransactions: Int,
    val lastActivity: Instant,
    val contractVersion: Int,
    val userRating: Float?               // Future: community ratings
)
```

---

## Security Architecture

### 1. Vault-to-Vault Verification
- Services must run VettID Service Vault
- E2E encryption using X25519 key exchange
- Service identity verified through NATS credentials
- Organization verification through VettID registry (future)

### 2. Contract Enforcement
- Every data access checked against accepted contract
- On-demand fields: immediate access within rate limits
- Consent fields: creates approval request, blocks until approved
- Unauthorized access: blocked + logged + user notified

### 3. Rate Limiting
- Token bucket algorithm per connection
- `MaxRequestsPerHour` defined in contract
- Exceeding limit returns error + logs event
- User notified of excessive requests

### 4. Sandbox Isolation
- Each service's data namespaced: `service-data/{connection_id}/{key}`
- Services cannot access other services' data
- User has full visibility and delete capability

### 5. Revocation
- Immediate status change blocks all access
- User chooses: keep data, delete data, or export then delete
- Service notified of revocation
- All pending requests auto-denied

### 6. Contract Updates
- Service can publish new contract version
- User notified of changes
- User must accept new contract or connection limited
- Previous contract honored for grace period

---

## Storage Keys

### User Vault
```
connections/{connection_id}              # ServiceConnectionRecord
service-contracts/{connection_id}        # Accepted contract copy
service-data/{connection_id}/{key}       # ServiceStorageRecord
service-requests/{request_id}            # ServiceRequest
service-activity/{connection_id}/{date}  # Activity log
```

### Service Vault
```
users/{connection_id}                    # UserConnectionRecord
contracts/{contract_id}                  # ServiceDataContract (master)
user-data/{connection_id}/{key}          # User-provided data
requests/{request_id}                    # Outbound requests
```

---

## Event Types

```go
// Service connection events
EventTypeServiceConnectionInitiated  = "service.connection.initiated"
EventTypeServiceConnectionAccepted   = "service.connection.accepted"
EventTypeServiceConnectionRejected   = "service.connection.rejected"
EventTypeServiceConnectionRevoked    = "service.connection.revoked"

// Service data events
EventTypeServiceDataStored           = "service.data.stored"
EventTypeServiceDataAccessed         = "service.data.accessed"
EventTypeServiceDataDeleted          = "service.data.deleted"

// Service request events
EventTypeServiceAuthRequested        = "service.auth.requested"
EventTypeServiceConsentRequested     = "service.consent.requested"
EventTypeServicePaymentRequested     = "service.payment.requested"
EventTypeServiceRequestApproved      = "service.request.approved"
EventTypeServiceRequestDenied        = "service.request.denied"
EventTypeServiceRequestExpired       = "service.request.expired"

// Contract events
EventTypeServiceContractUpdated      = "service.contract.updated"
EventTypeServiceContractViolation    = "service.contract.violation"

// Rate limit events
EventTypeServiceRateLimitWarning     = "service.rate_limit.warning"
EventTypeServiceRateLimitExceeded    = "service.rate_limit.exceeded"
```

---

## Files to Create

### User Vault (vault-manager)

#### 1. `service_connections.go` (~600 lines)
- `HandleDiscover(msg)` - Get service profile + contract
- `HandleInitiate(msg)` - Accept contract, establish connection
- `HandleList(msg)` - List service connections with filters
- `HandleGet(msg)` - Get service connection details
- `HandleUpdate(msg)` - Update tags, favorite, muted, archived
- `HandleRevoke(msg)` - Revoke with data cleanup options

#### 2. `service_data.go` (~400 lines)
- `HandleList(msg)` - List data stored by services
- `HandleGet(msg)` - Get specific data item
- `HandleDelete(msg)` - Delete service data
- `HandleExport(msg)` - Export all data from a service

#### 3. `service_requests.go` (~400 lines)
- `HandleList(msg)` - List pending/historical requests
- `HandleRespond(msg)` - Approve/deny request
- `HandleIncomingAuth(msg)` - Process auth request from service
- `HandleIncomingConsent(msg)` - Process consent request
- `HandleIncomingPayment(msg)` - Process payment request

#### 4. `service_contracts.go` (~200 lines)
- `HandleGetContract(msg)` - Get contract for connection
- `HandleContractHistory(msg)` - Get version history
- `validateContract()` - Validate contract structure
- `checkRequiredFields()` - Check user has required fields

### Service Vault (service-vault-manager - new package)

#### 1. `user_connections.go` (~500 lines)
- `HandleConnect(msg)` - Accept user connection
- `HandleDisconnect(msg)` - Handle user revocation
- `HandleList(msg)` - List connected users
- `HandleGet(msg)` - Get user connection details

#### 2. `user_requests.go` (~400 lines)
- `HandleRequestAuth(msg)` - Send auth request to user
- `HandleRequestConsent(msg)` - Send consent request
- `HandleRequestPayment(msg)` - Send payment request
- `HandleUserResponse(msg)` - Process user's response

#### 3. `user_data.go` (~300 lines)
- `HandleStoreData(msg)` - Store data in user's sandbox
- `HandleGetData(msg)` - Read on-demand fields
- `HandleDeleteData(msg)` - Delete stored data

#### 4. `contract_manager.go` (~200 lines)
- `HandleGetContract(msg)` - Return current contract
- `HandleUpdateContract(msg)` - Publish new version
- `enforceContract()` - Validate requests against contract

---

## Files to Modify

### `connections.go`
- Add `IsServiceConnection` field to `ConnectionRecord`
- Add `ConnectionType` filter to `ListConnectionsRequest`
- Filter by type in `HandleList()`

### `messages.go`
- Add `ServiceConnectionHandler`, `ServiceDataHandler`, `ServiceRequestsHandler`
- Add routing for `service.*` operations

### `events_types.go`
- Add all service event types and classifications

---

## Implementation Phases

### Phase 1: Core Service Connections
- `service_connections.go`: discover, initiate, list, get, revoke
- Basic routing in `messages.go`
- Event types added
- Unit tests

### Phase 2: Contract & Data Management
- `service_contracts.go`: validation, required field checking
- `service_data.go`: list, get, delete, export
- Contract enforcement

### Phase 3: Service Requests
- `service_requests.go`: auth, consent, payment requests
- Feed integration for request notifications
- Request expiration handling

### Phase 4: Usability Polish
- Tags, favorites, archive for services
- Activity dashboard
- Notification preferences per service
- Offline queue support

### Phase 5: Service Vault SDK
- `service-vault-manager` package
- Documentation for service developers
- Example service implementation

---

## Verification

### Build & Test
```bash
cd /home/al/Projects/VettID/vettid-dev/enclave/vault-manager
go build ./...
go test -v ./...
```

### Manual Testing
1. Create mock service vault with contract
2. Discover service → verify profile + contract displayed
3. Test with missing required fields → verify detection
4. Accept contract → verify connection established
5. Service stores data → verify in user's sandbox
6. Service requests auth → verify feed notification
7. Approve/deny requests → verify response delivered
8. Revoke connection → verify access blocked
9. Test rate limiting → verify limits enforced
10. Test contract update → verify user notified

### Security Testing
1. Attempt access to unauthorized fields → blocked
2. Exceed rate limit → error returned
3. Access after revocation → blocked
4. Cross-service data access → impossible
5. Tampered contract → rejected
