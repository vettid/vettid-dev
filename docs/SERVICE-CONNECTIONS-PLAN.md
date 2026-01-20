# Service Connections Feature

**Feature**: B2C Service Connections for VettID Vault

## Overview

Enable users to connect to services (apps, businesses, organizations) that run their own VettID Service Vaults. Service connections use the same vault-to-vault NATS communication as peer connections, but with additional contract-based permissions and data access controls.

**Key Principles:**
1. **Services are vaults** - A service runs a VettID Service Vault that communicates with user vaults over NATS
2. **No data caching** - Services do NOT cache user profiles; they request data on-demand per contract terms
3. **Clean break on cancel** - If a user cancels a connection, the service loses all access immediately; user must re-accept to reconnect
4. **User controls contracts** - Services can update contracts, but users can reject updates (which terminates the connection)

---

## Architecture

### Service Vault vs User Vault

| Aspect | User Vault | Service Vault |
|--------|-----------|---------------|
| **Runs on** | User's device (via enclave) | Service's infrastructure (via enclave) |
| **Identity** | User GUID | Service GUID |
| **Connections** | Peers + Services | Users only |
| **Data contracts** | Accepts contracts | Defines contracts |
| **User data** | Stores own profile | On-demand access only (no caching) |
| **Storage** | Personal data + service sandbox | Contract definitions + request logs |
| **Verification** | Email, identity | Organization verification |

### Communication Flow

```
┌─────────────────┐                NATS                ┌─────────────────┐
│   User Vault    │◄──────────────────────────────────►│  Service Vault  │
│  (on device)    │         E2E Encrypted              │  (on service)   │
└─────────────────┘                                    └─────────────────┘
        │                                                      │
        │ Stores:                                              │ Stores:
        │ - Service connection                                 │ - User connection ID only
        │ - Accepted contract                                  │ - Contract definitions
        │ - Service-provided data                              │ - Request/response logs
        │ - Access history                                     │ - NO user profile data
        │ - Service profile (cached)                           │
```

---

## Service Profile

Services have rich profiles that users can view and trust. The profile includes verified contact information and trusted resources.

### ServiceProfile
```go
type ServiceProfile struct {
    // Identity
    ServiceGUID        string `json:"service_guid"`
    ServiceName        string `json:"service_name"`
    ServiceDescription string `json:"service_description"`
    ServiceLogoURL     string `json:"service_logo_url,omitempty"`
    ServiceCategory    string `json:"service_category"` // "retail", "healthcare", "finance", etc.

    // Organization
    Organization OrganizationInfo `json:"organization"`

    // Trusted Contact Information
    ContactInfo ServiceContactInfo `json:"contact_info"`

    // Trusted Resources (URLs, downloads)
    TrustedResources []TrustedResource `json:"trusted_resources"`

    // Current contract
    CurrentContract ServiceDataContract `json:"current_contract"`

    // Metadata
    ProfileVersion int       `json:"profile_version"`
    UpdatedAt      time.Time `json:"updated_at"`
}

type OrganizationInfo struct {
    Name             string `json:"name"`
    Verified         bool   `json:"verified"`
    VerificationType string `json:"verification_type"` // "business", "nonprofit", "government"
    VerifiedAt       string `json:"verified_at,omitempty"`
    RegistrationID   string `json:"registration_id,omitempty"` // Business registration number
    Country          string `json:"country,omitempty"`
}

type ServiceContactInfo struct {
    // Verified contact methods
    Emails       []VerifiedContact `json:"emails,omitempty"`
    PhoneNumbers []VerifiedContact `json:"phone_numbers,omitempty"`

    // Physical address (for businesses)
    Address *PhysicalAddress `json:"address,omitempty"`

    // Support channels
    SupportURL   string `json:"support_url,omitempty"`
    SupportEmail string `json:"support_email,omitempty"`
    SupportPhone string `json:"support_phone,omitempty"`
}

type VerifiedContact struct {
    Value      string `json:"value"`       // email or phone number
    Label      string `json:"label"`       // "Customer Support", "Billing", etc.
    Verified   bool   `json:"verified"`
    VerifiedAt string `json:"verified_at,omitempty"`
    Primary    bool   `json:"primary"`
}

type PhysicalAddress struct {
    Street     string `json:"street"`
    City       string `json:"city"`
    State      string `json:"state,omitempty"`
    PostalCode string `json:"postal_code"`
    Country    string `json:"country"`
}
```

### Trusted Resources

Services can publish trusted resources - genuine URLs and signed downloads that users can trust.

```go
type TrustedResource struct {
    ResourceID   string `json:"resource_id"`
    Type         string `json:"type"` // "website", "app_download", "document", "api"
    Label        string `json:"label"`
    Description  string `json:"description,omitempty"`
    URL          string `json:"url"`

    // For downloadable resources (APKs, etc.)
    Download *DownloadInfo `json:"download,omitempty"`

    // Verification
    AddedAt   time.Time `json:"added_at"`
    UpdatedAt time.Time `json:"updated_at"`
}

type DownloadInfo struct {
    Platform     string `json:"platform"`      // "android", "ios", "windows", "macos", "linux"
    Version      string `json:"version"`
    VersionCode  int    `json:"version_code,omitempty"` // For Android
    MinOSVersion string `json:"min_os_version,omitempty"`
    FileSize     int64  `json:"file_size"`     // Bytes
    FileName     string `json:"file_name"`

    // Cryptographic verification (REQUIRED for downloads)
    Signatures []DownloadSignature `json:"signatures"`
}

type DownloadSignature struct {
    Algorithm string `json:"algorithm"` // "sha256", "sha512"
    Hash      string `json:"hash"`      // Hex-encoded hash
    SignedBy  string `json:"signed_by"` // Service GUID or key identifier
    Signature string `json:"signature"` // Ed25519 signature of the hash
}
```

**Example Service Profile:**
```json
{
  "service_guid": "svc_acme_retail_001",
  "service_name": "Acme Retail",
  "service_description": "Online shopping with secure checkout",
  "service_category": "retail",
  "organization": {
    "name": "Acme Corporation",
    "verified": true,
    "verification_type": "business",
    "registration_id": "US-DE-12345678"
  },
  "contact_info": {
    "emails": [
      {"value": "support@acme.com", "label": "Customer Support", "verified": true, "primary": true},
      {"value": "billing@acme.com", "label": "Billing", "verified": true}
    ],
    "phone_numbers": [
      {"value": "+1-800-ACME-HELP", "label": "Customer Support", "verified": true, "primary": true}
    ],
    "support_url": "https://acme.com/support"
  },
  "trusted_resources": [
    {
      "resource_id": "web_main",
      "type": "website",
      "label": "Official Website",
      "url": "https://acme.com"
    },
    {
      "resource_id": "app_android",
      "type": "app_download",
      "label": "Android App",
      "url": "https://acme.com/downloads/acme-v2.3.1.apk",
      "download": {
        "platform": "android",
        "version": "2.3.1",
        "version_code": 231,
        "min_os_version": "8.0",
        "file_size": 45678901,
        "file_name": "acme-v2.3.1.apk",
        "signatures": [
          {
            "algorithm": "sha256",
            "hash": "a1b2c3d4e5f6...",
            "signed_by": "svc_acme_retail_001",
            "signature": "base64_ed25519_signature..."
          }
        ]
      }
    }
  ]
}
```

---

## Service Connection Flow

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
       - Show trusted resources (URLs, apps)                    │
       - Show required/optional fields                          │
       - Show what service can access/store                     │
       - Check if user has required fields                      │
       - [ACCEPT] or [REJECT]                                   │
         │                                                      │
         ├──────────[REJECT]────────► Connection terminated     │
         │                                                      │
         └──────────[ACCEPT]────────►                           │
                                     3. INITIATE CONNECTION     │
                                        - Exchange E2E keys     │
                                        - Send NATS credentials │
                                        - NO profile data sent  │
         │◄─────────────────────────────────────────────────────│
         │                                                      │
         ▼                                                      ▼
    4. CONNECTION ACTIVE                               4. CONNECTION ACTIVE
       - Store service connection                         - Store connection ID only
       - Cache service profile                            - Request data on-demand
       - Subscribe to contract updates                    - Enforce contract terms
       - Track contract version                           - Log all requests
```

### Key Differences from Peer Connections

1. **No profile exchange at connection time** - User does not send profile data when connecting
2. **On-demand data access** - Service requests specific fields as needed, per contract terms
3. **Service caches nothing** - Every data request goes to user's vault
4. **User caches service profile** - For offline viewing of service info and trusted resources

---

## Contract Updates

Services can update their contracts. Users must explicitly accept or reject updates.

### Contract Update Flow

```
┌─────────────────┐                                    ┌─────────────────┐
│      User       │                                    │     Service     │
└────────┬────────┘                                    └────────┬────────┘
         │                                                      │
         │◄─────────── Contract Update Notification ────────────│
         │             (new version available)                  │
         │                                                      │
         ▼                                                      │
    REVIEW CHANGES                                              │
    - Show what changed (new fields, permissions)               │
    - Highlight additions/removals                              │
    - [ACCEPT v3] or [REJECT & DISCONNECT]                      │
         │                                                      │
         ├────[REJECT]────► Connection terminated               │
         │                  Service loses all access            │
         │                  User must reconnect to use service  │
         │                                                      │
         └────[ACCEPT]────► Contract updated                    │
                            Service can now use new terms       │
```

### Contract Update Rules

1. **User always has final say** - Rejecting an update terminates the connection
2. **No grace period abuse** - Service cannot access data under old contract after update is published
3. **Changes must be explicit** - UI clearly shows what's new, removed, or changed
4. **Reconnection required after rejection** - User must go through full connection flow again

```go
type ContractUpdate struct {
    PreviousVersion int                 `json:"previous_version"`
    NewVersion      int                 `json:"new_version"`
    Changes         ContractChanges     `json:"changes"`
    Reason          string              `json:"reason"` // Why the update
    PublishedAt     time.Time           `json:"published_at"`
    RequiredBy      *time.Time          `json:"required_by,omitempty"` // Deadline to accept
}

type ContractChanges struct {
    AddedFields      []FieldSpec `json:"added_fields,omitempty"`
    RemovedFields    []string    `json:"removed_fields,omitempty"`
    ChangedFields    []FieldSpec `json:"changed_fields,omitempty"`
    PermissionChanges []string   `json:"permission_changes,omitempty"`
    RateLimitChanges  *string    `json:"rate_limit_changes,omitempty"`
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

    // Cached service profile (user can view offline)
    ServiceProfile ServiceProfile `json:"service_profile"`

    // Contract tracking
    ContractID              string    `json:"contract_id"`
    ContractVersion         int       `json:"contract_version"`
    ContractAcceptedAt      time.Time `json:"contract_accepted_at"`
    PendingContractVersion  *int      `json:"pending_contract_version,omitempty"`

    // Usability fields (same as peer connections)
    Tags       []string `json:"tags,omitempty"`
    IsFavorite bool     `json:"is_favorite"`
    IsArchived bool     `json:"is_archived"`
    IsMuted    bool     `json:"is_muted"`
}
```

### UserConnectionRecord (Service Vault)
```go
// NOTE: Services do NOT cache user profiles
type UserConnectionRecord struct {
    ConnectionID string `json:"connection_id"`

    // User identification (GUID only, no profile data)
    UserGUID string `json:"user_guid"`

    // E2E encryption keys
    LocalPrivateKey []byte    `json:"local_private_key"`
    LocalPublicKey  []byte    `json:"local_public_key"`
    PeerPublicKey   []byte    `json:"peer_public_key"`
    SharedSecret    []byte    `json:"shared_secret"`
    KeyExchangeAt   time.Time `json:"key_exchange_at"`

    // Connection state
    Status    string    `json:"status"` // "active", "suspended", "revoked"
    CreatedAt time.Time `json:"created_at"`
    RevokedAt time.Time `json:"revoked_at,omitempty"`

    // Contract enforcement
    ContractVersion int       `json:"contract_version"`
    AcceptedAt      time.Time `json:"accepted_at"`

    // Rate limiting state
    RequestCount       int       `json:"request_count"`
    RequestWindowStart time.Time `json:"request_window_start"`
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
    OnDemandFields []string    `json:"on_demand_fields"` // Service can request anytime
    ConsentFields  []string    `json:"consent_fields"`   // Requires per-request approval

    // Service permissions
    CanStoreData      bool     `json:"can_store_data"`
    StorageCategories []string `json:"storage_categories,omitempty"`
    CanSendMessages   bool     `json:"can_send_messages"`
    CanRequestAuth    bool     `json:"can_request_auth"`
    CanRequestPayment bool     `json:"can_request_payment"`

    // Rate limits
    MaxRequestsPerHour int `json:"max_requests_per_hour,omitempty"`
    MaxStorageMB       int `json:"max_storage_mb,omitempty"`

    // Timestamps
    CreatedAt time.Time  `json:"created_at"`
    ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

type FieldSpec struct {
    Field     string `json:"field"`
    Purpose   string `json:"purpose"`   // Why service needs this
    Retention string `json:"retention"` // "session", "until_revoked", "30_days", etc.
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
    RequestType     string     `json:"request_type"` // "data", "auth", "consent", "payment"
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
# User vault subscribes to (from connected services):
{user_space}.forVault.service.data.request      # Service requests on-demand fields
{user_space}.forVault.service.request.auth      # Service requests authentication
{user_space}.forVault.service.request.consent   # Service requests consent field access
{user_space}.forVault.service.request.payment   # Service requests payment
{user_space}.forVault.service.data.store        # Service stores data in user's sandbox
{user_space}.forVault.service.data.update       # Service updates stored data
{user_space}.forVault.service.message           # Service sends message to user
{user_space}.forVault.service.contract.update   # Contract version changed
{user_space}.forVault.service.profile.update    # Service profile changed
```

### User-to-Service Communication
```
# Service vault subscribes to:
{service_space}.forVault.user.connect           # User initiates connection
{service_space}.forVault.user.disconnect        # User revokes connection
{service_space}.forVault.user.request.respond   # User responds to data/auth/payment request
{service_space}.forVault.user.contract.respond  # User accepts/rejects contract update
```

### User Vault Handlers (forVault subjects)
```
# Service connection management
service.connection.discover    # Get service profile + contract
service.connection.initiate    # Accept contract, establish connection
service.connection.list        # List service connections
service.connection.get         # Get service connection details
service.connection.update      # Update tags, favorite, muted status
service.connection.revoke      # Revoke connection (clean break)

# Service data in user's sandbox
service.data.list              # List data stored by services
service.data.get               # Get specific data item
service.data.delete            # Delete service data

# Service requests
service.request.list           # List pending/historical requests
service.request.respond        # Approve/deny request

# Contract management
service.contract.get           # Get current contract for connection
service.contract.accept        # Accept pending contract update
service.contract.reject        # Reject update (terminates connection)
service.contract.history       # Get contract version history

# Service profile
service.profile.get            # Get cached service profile
service.profile.resources      # Get trusted resources list
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

### 2. Trusted Resources Display

**Users can view and verify service resources:**
```
┌─────────────────────────────────────────────────────┐
│ Acme Retail - Trusted Resources                     │
├─────────────────────────────────────────────────────┤
│                                                     │
│ 🌐 Official Websites                                │
│    └── https://acme.com ✓                          │
│                                                     │
│ 📱 Mobile Apps                                      │
│    ├── Android v2.3.1 (45.6 MB)                    │
│    │   SHA256: a1b2c3d4... ✓ Signed                │
│    │   [Download] [Verify]                         │
│    │                                                │
│    └── iOS v2.3.1                                  │
│        Available on App Store ✓                    │
│        [Open App Store]                            │
│                                                     │
│ 📞 Contact Information                              │
│    ├── support@acme.com ✓ Verified                 │
│    ├── +1-800-ACME-HELP ✓ Verified                 │
│    └── 123 Main St, Anytown, USA                   │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### 3. Contract Review UX

```
┌─────────────────────────────────────────────────────┐
│ 🏢 Acme Retail wants to connect                     │
│    ✓ᵛ Verified Business                            │
├─────────────────────────────────────────────────────┤
│                                                     │
│ They will request (on-demand, not stored):          │
│ ├── Email - "For order confirmations"              │
│ ├── Name - "For shipping labels"                   │
│ └── Phone (optional) - "For delivery updates"      │
│                                                     │
│ They can:                                           │
│ ├── Store purchase history in your vault           │
│ ├── Send you messages                              │
│ ├── Request payments                               │
│ └── Request up to 100 data queries/hour            │
│                                                     │
│ ⚠️ Missing required field: Email                   │
│    [Add Email to Profile]                          │
│                                                     │
├─────────────────────────────────────────────────────┤
│ [View Resources]  [Terms]  [Privacy]                │
│                                                     │
│         [Decline]              [Accept]             │
└─────────────────────────────────────────────────────┘
```

### 4. Contract Update Notification

```
┌─────────────────────────────────────────────────────┐
│ 🔔 Acme Retail updated their contract               │
│    Version 2 → Version 3                           │
├─────────────────────────────────────────────────────┤
│                                                     │
│ What's new:                                         │
│ ├── + Requesting: Date of Birth                    │
│ │     "For age verification on alcohol purchases"  │
│ └── + Permission: Request payments up to $500      │
│                                                     │
│ What's removed:                                     │
│ └── - No longer requesting: Mailing Address        │
│                                                     │
│ ⚠️ If you reject, you will be disconnected and     │
│    must reconnect to use Acme Retail again.        │
│                                                     │
├─────────────────────────────────────────────────────┤
│     [Reject & Disconnect]    [Accept Changes]       │
└─────────────────────────────────────────────────────┘
```

### 5. Other Usability Features

Same as peer connections:
- Tags, favorites, archive
- Activity dashboard per service
- Data transparency and user control
- Request management in unified feed
- Notification preferences per service
- Offline handling (for cached service profile)
- Trust indicators

---

## Security Architecture

### 1. No User Data Caching by Services
- Services store ONLY: connection ID, user GUID, E2E keys, contract version
- All user data requested on-demand via NATS
- User vault enforces contract on every request
- Prevents data retention after revocation

### 2. Clean Break on Cancellation
- User revokes → connection immediately terminated
- Service's stored connection record marked "revoked"
- All pending requests auto-denied
- Service cannot access any user data
- User must go through full connection flow to reconnect

### 3. Trusted Resource Verification
- Download hashes signed by service's Ed25519 key
- User can verify signatures before downloading
- Prevents malicious APK/binary distribution
- Service profile versioned and signed

### 4. Contract Enforcement
- Every data access checked against accepted contract version
- On-demand fields: immediate access within rate limits
- Consent fields: creates approval request, blocks until approved
- Unauthorized access: blocked + logged + user notified

### 5. Rate Limiting
- Token bucket algorithm per connection
- `MaxRequestsPerHour` defined in contract
- Exceeding limit returns error + logs event
- User notified of excessive requests

### 6. Sandbox Isolation
- Each service's data namespaced: `service-data/{connection_id}/{key}`
- Services cannot access other services' data
- User has full visibility and delete capability

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
connections/{connection_id}              # UserConnectionRecord (NO profile data)
contracts/{contract_id}                  # ServiceDataContract (master)
contract-history/{contract_id}/{version} # Previous contract versions
profile/current                          # ServiceProfile
profile/resources/{resource_id}          # TrustedResource
requests/{request_id}                    # Outbound requests + responses
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
EventTypeServiceDataRequested        = "service.data.requested"
EventTypeServiceDataProvided         = "service.data.provided"
EventTypeServiceDataDenied           = "service.data.denied"
EventTypeServiceDataStored           = "service.data.stored"
EventTypeServiceDataDeleted          = "service.data.deleted"

// Service request events
EventTypeServiceAuthRequested        = "service.auth.requested"
EventTypeServiceConsentRequested     = "service.consent.requested"
EventTypeServicePaymentRequested     = "service.payment.requested"
EventTypeServiceRequestApproved      = "service.request.approved"
EventTypeServiceRequestDenied        = "service.request.denied"
EventTypeServiceRequestExpired       = "service.request.expired"

// Contract events
EventTypeServiceContractUpdatePublished = "service.contract.update_published"
EventTypeServiceContractAccepted        = "service.contract.accepted"
EventTypeServiceContractRejected        = "service.contract.rejected"
EventTypeServiceContractViolation       = "service.contract.violation"

// Rate limit events
EventTypeServiceRateLimitWarning     = "service.rate_limit.warning"
EventTypeServiceRateLimitExceeded    = "service.rate_limit.exceeded"

// Resource events
EventTypeServiceResourceDownloaded   = "service.resource.downloaded"
EventTypeServiceResourceVerified     = "service.resource.verified"
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
- `HandleRevoke(msg)` - Revoke connection (clean break)

#### 2. `service_data.go` (~400 lines)
- `HandleIncomingDataRequest(msg)` - Process on-demand data request from service
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

#### 4. `service_contracts.go` (~300 lines)
- `HandleGetContract(msg)` - Get contract for connection
- `HandleAcceptUpdate(msg)` - Accept contract update
- `HandleRejectUpdate(msg)` - Reject update (triggers disconnect)
- `HandleContractHistory(msg)` - Get version history
- `validateContract()` - Validate contract structure
- `checkRequiredFields()` - Check user has required fields
- `enforceContract()` - Validate request against contract

#### 5. `service_resources.go` (~200 lines)
- `HandleGetResources(msg)` - Get trusted resources list
- `HandleVerifyDownload(msg)` - Verify download signature
- `verifySignature()` - Ed25519 signature verification

### Service Vault (service-vault-manager - new package)

#### 1. `user_connections.go` (~400 lines)
- `HandleConnect(msg)` - Accept user connection
- `HandleDisconnect(msg)` - Handle user revocation
- `HandleList(msg)` - List connected users
- `HandleGet(msg)` - Get user connection details (no profile data)

#### 2. `user_requests.go` (~500 lines)
- `HandleRequestData(msg)` - Request on-demand fields from user
- `HandleRequestAuth(msg)` - Send auth request to user
- `HandleRequestConsent(msg)` - Send consent request
- `HandleRequestPayment(msg)` - Send payment request
- `HandleUserResponse(msg)` - Process user's response

#### 3. `user_data.go` (~200 lines)
- `HandleStoreData(msg)` - Store data in user's sandbox
- `HandleDeleteData(msg)` - Delete stored data

#### 4. `contract_manager.go` (~300 lines)
- `HandleGetContract(msg)` - Return current contract
- `HandleUpdateContract(msg)` - Publish new version
- `enforceContract()` - Validate requests against contract
- `notifyUsers()` - Notify connected users of update

#### 5. `profile_manager.go` (~200 lines)
- `HandleGetProfile(msg)` - Return service profile
- `HandleUpdateProfile(msg)` - Update service profile
- `HandleAddResource(msg)` - Add trusted resource
- `HandleRemoveResource(msg)` - Remove trusted resource
- `signDownload()` - Sign download with Ed25519 key

---

## Files to Modify

### `connections.go`
- Add `IsServiceConnection` field to `ConnectionRecord`
- Add `ConnectionType` filter to `ListConnectionsRequest`
- Filter by type in `HandleList()`

### `messages.go`
- Add `ServiceConnectionHandler`, `ServiceDataHandler`, `ServiceRequestsHandler`, `ServiceContractsHandler`
- Add routing for `service.*` operations

### `events_types.go`
- Add all service event types and classifications

---

## Implementation Phases

### Phase 1: Core Service Connections
- Service profile and trusted resources data models
- `service_connections.go`: discover, initiate, list, get, revoke
- Basic routing in `messages.go`
- Event types added
- Unit tests

### Phase 2: Contract Management
- `service_contracts.go`: validation, updates, accept/reject
- Contract update notification flow
- Clean break on rejection

### Phase 3: On-Demand Data Access
- `service_data.go`: incoming requests, enforcement
- Rate limiting per connection
- Consent field handling

### Phase 4: Service Requests
- `service_requests.go`: auth, consent, payment requests
- Feed integration for request notifications
- Request expiration handling

### Phase 5: Trusted Resources
- `service_resources.go`: resource management, download verification
- Ed25519 signature verification
- Download hash validation

### Phase 6: Service Vault SDK
- `service-vault-manager` package
- Profile and contract management
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
1. Create mock service vault with profile and contract
2. Discover service → verify profile + trusted resources displayed
3. Test with missing required fields → verify detection
4. Accept contract → verify connection established
5. Service requests data → verify on-demand access works
6. Service stores data → verify in user's sandbox
7. Service requests auth → verify feed notification
8. Approve/deny requests → verify response delivered
9. Service updates contract → verify user notification
10. Accept contract update → verify new terms applied
11. Reject contract update → verify clean disconnection
12. Revoke connection → verify all access blocked
13. Attempt reconnect → verify full flow required
14. Download APK → verify signature validation

### Security Testing
1. Attempt access to unauthorized fields → blocked
2. Exceed rate limit → error returned
3. Access after revocation → blocked
4. Cross-service data access → impossible
5. Service caches user data → impossible (no storage location)
6. Tampered APK hash → signature verification fails
7. Contract update without notification → rejected
