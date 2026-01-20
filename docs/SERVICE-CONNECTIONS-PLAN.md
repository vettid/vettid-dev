# Plan: Service Connections Feature

> **Status: PENDING REVIEW**

**Feature**: B2C Service Connections for VettID Vault

## Overview

Enable users to connect to services (apps, websites, businesses) via QR code or deep link, with explicit data contracts, sandboxed storage, and strong security guarantees. Service connections are clearly distinguished from peer-to-peer connections.

---

## Key Concepts

### Service Connection Flow
1. User scans QR code / clicks link → initiates connection
2. Vault verifies service identity (DNS/HTTPS/Registry)
3. Contract displayed: required fields, permissions, storage
4. Missing required fields detected → user prompted to add
5. User accepts/rejects contract
6. Connection established with key rotation like peer connections

### Data Contract Model
- **Required Fields**: Must exist in profile to connect
- **Optional Fields**: Requested but not blocking
- **On-Demand Fields**: Service can access anytime
- **Consent Fields**: Require user approval per-request
- **Storage Permission**: Whether service can store data in vault

### Service Vault Storage
- **Sandboxed**: Each service gets isolated namespace
- **Visibility Levels**:
  - `hidden`: User sees nothing
  - `metadata`: User sees label/description but not value
  - `viewable`: User can see the actual value

---

## Data Models

### ServiceConnectionRecord
Extends `ConnectionRecord` with service-specific fields:
```go
type ServiceConnectionRecord struct {
    ConnectionRecord // Embed base (E2E keys, status, activity)

    IsServiceConnection bool   `json:"is_service_connection"`
    ServiceGUID         string `json:"service_guid"`
    ServiceName         string `json:"service_name"`
    ServiceLogoURL      string `json:"service_logo_url,omitempty"`
    ServiceDescription  string `json:"service_description,omitempty"`
    ServiceCategory     string `json:"service_category,omitempty"`
    ServiceURL          string `json:"service_url,omitempty"`

    VerificationStatus  string `json:"verification_status"` // "verified", "unverified"
    VerificationMethod  string `json:"verification_method,omitempty"`

    ContractID          string    `json:"contract_id"`
    ContractVersion     int       `json:"contract_version"`
    ContractAcceptedAt  time.Time `json:"contract_accepted_at"`
}
```

### ServiceDataContract
```go
type ServiceDataContract struct {
    ContractID     string   `json:"contract_id"`
    ServiceGUID    string   `json:"service_guid"`
    Version        int      `json:"version"`

    RequiredFields []string `json:"required_fields"`
    OptionalFields []string `json:"optional_fields"`
    OnDemandFields []string `json:"on_demand_fields"`
    ConsentFields  []string `json:"consent_fields"`

    CanStoreData       bool     `json:"can_store_data"`
    StorageCategories  []string `json:"storage_categories,omitempty"`
    CanRequestAuth     bool     `json:"can_request_auth"`
    MaxRequestsPerHour int      `json:"max_requests_per_hour,omitempty"`

    Title       string     `json:"title"`
    Description string     `json:"description"`
    TermsURL    string     `json:"terms_url,omitempty"`
    CreatedAt   time.Time  `json:"created_at"`
    ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}
```

### ServiceStorageRecord
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
    RequestType     string     `json:"request_type"` // "auth", "consent"
    RequestedFields []string   `json:"requested_fields,omitempty"`
    RequestedAction string     `json:"requested_action,omitempty"`
    Purpose         string     `json:"purpose,omitempty"`
    Status          string     `json:"status"` // "pending", "approved", "denied", "expired"
    RequestedAt     time.Time  `json:"requested_at"`
    ExpiresAt       time.Time  `json:"expires_at"`
    RespondedAt     *time.Time `json:"responded_at,omitempty"`
}
```

### ServiceVerification
```go
type ServiceVerification struct {
    ServiceGUID        string    `json:"service_guid"`
    VerificationStatus string    `json:"verification_status"`
    VerificationMethod string    `json:"verification_method"` // "dns", "https", "registry"
    VerifiedDomain     string    `json:"verified_domain,omitempty"`
    VerifiedAt         time.Time `json:"verified_at"`
    ExpiresAt          time.Time `json:"expires_at"` // 24-hour cache
}
```

---

## Storage Keys

```
connections/{connection_id}              # ServiceConnectionRecord (extends ConnectionRecord)
service-contracts/{contract_id}          # ServiceDataContract
service-data/{connection_id}/{key}       # ServiceStorageRecord
service-requests/{request_id}            # ServiceRequest
service-verifications/{service_guid}     # ServiceVerification (cached)
service-rate-limits/{connection_id}      # RateLimiter state
```

---

## Files to Create

### 1. `service_connections.go` (~800 lines)
**Handler**: `ServiceConnectionHandler`
- `HandleInitiate(msg)` - Verify service, load contract, check required fields
- `HandleAccept(msg)` - Create connection after contract acceptance
- `HandleReject(msg)` - Reject connection request
- `HandleRevoke(msg)` - Revoke connection with optional data cleanup
- `HandleList(msg)` - List service connections
- `HandleGet(msg)` - Get single service connection details
- `HandleGetContract(msg)` - Get contract for a connection

### 2. `service_data.go` (~600 lines)
**Handler**: `ServiceDataHandler`
- `HandleGet(msg)` - Get profile fields with contract enforcement
- `HandleStore(msg)` - Store data in service sandbox
- `HandleList(msg)` - List service-stored data (visibility filtered)
- `HandleDelete(msg)` - Delete service data
- `enforceContract()` - Validate field access against contract
- `checkRateLimit()` - Token bucket rate limiting

### 3. `service_requests.go` (~500 lines)
**Handler**: `ServiceRequestsHandler`
- `HandleAuthRequest(msg)` - Service requests user authentication
- `HandleConsentRequest(msg)` - Service requests data consent
- `HandleRespond(msg)` - User approves/denies request
- `HandleList(msg)` - List pending/historical requests
- Feed notification integration

### 4. `service_verification.go` (~400 lines)
- `verifyServiceIdentity()` - Orchestrate verification
- `verifyViaDNS()` - Check TXT record at `_vettid.{domain}`
- `verifyViaHTTPS()` - Validate certificate
- `verifyViaRegistry()` - Query centralized registry (optional)
- Verification caching (24-hour TTL)

### 5. `service_contracts.go` (~300 lines)
- `validateContract()` - Validate contract structure
- `enforceContractCompliance()` - Runtime field access checks
- `checkFieldsAvailable()` - Detect missing required fields
- `getContract()` - Load contract with caching

---

## Files to Modify

### `messages.go`
- Add handlers to `MessageHandler` struct
- Initialize in `NewMessageHandler()`
- Add routing case for "service" operation
- Add `handleServiceOperation()`, `handleServiceConnectionOperation()`, etc.

### `connections.go`
- Add `IsServiceConnection`, `ServiceGUID`, `ContractID` to `ConnectionRecord`
- Add `ConnectionType` filter to `ListConnectionsRequest`
- Filter by connection type in `HandleList()`

### `events_types.go`
Add event types:
```go
EventTypeServiceConnectionInitiated  = "service.connection.initiated"
EventTypeServiceConnectionAccepted   = "service.connection.accepted"
EventTypeServiceConnectionRejected   = "service.connection.rejected"
EventTypeServiceConnectionRevoked    = "service.connection.revoked"
EventTypeServiceDataAccessed         = "service.data.accessed"
EventTypeServiceDataStored           = "service.data.stored"
EventTypeServiceAuthRequested        = "service.auth.requested"
EventTypeServiceConsentRequested     = "service.consent.requested"
EventTypeServiceRequestApproved      = "service.request.approved"
EventTypeServiceRequestDenied        = "service.request.denied"
EventTypeServiceContractViolation    = "service.contract.violation"
EventTypeServiceRateLimitExceeded    = "service.rate_limit.exceeded"
```

### `profile.go`
- Add `CheckFieldsAvailable(fields []string)` helper method

---

## Message Subjects

```
# Service Connection
service.connection.initiate    # Start connection process
service.connection.accept      # Accept contract
service.connection.reject      # Reject connection
service.connection.revoke      # Revoke existing connection
service.connection.list        # List service connections
service.connection.get         # Get connection details
service.connection.contract    # Get contract details

# Service Data
service.data.get               # Get profile fields (contract-enforced)
service.data.store             # Store data in service sandbox
service.data.list              # List stored data
service.data.delete            # Delete stored data

# Service Requests
service.request.auth           # Request user authentication
service.request.consent        # Request data consent
service.request.respond        # User response to request
service.request.list           # List requests
```

---

## Security Architecture

### 1. Service Identity Verification
- **DNS**: TXT record `_vettid.{domain}` contains service_guid
- **HTTPS**: Certificate chain validation for domain
- **Registry**: Optional centralized VettID registry with signatures
- **Caching**: 24-hour TTL to reduce verification overhead

### 2. Contract Enforcement
- Every data access checked against contract
- On-demand fields: immediate access
- Consent fields: create approval request, block until approved
- Unauthorized fields: block + log violation event

### 3. Rate Limiting
- Token bucket algorithm per connection
- `MaxRequestsPerHour` defined in contract
- Exceeding limit logs event + returns error

### 4. Sandbox Isolation
- Storage namespaced: `service-data/{connection_id}/{key}`
- Connection ID verified on every operation
- No cross-connection access possible

### 5. Revocation
- Immediate status change blocks all access
- Optional data cleanup (user's choice)
- Event logged for audit

---

## Usability Features

### Clear Service Identification
- `IsServiceConnection` flag distinguishes from peers
- Service logo, name, verified badge displayed
- Connection list filterable by type

### Contract Review UX
- Human-readable title and description
- Required vs optional fields clearly marked
- Storage and auth permissions shown
- Link to full terms if available

### Missing Data Handling
- Before acceptance, check all required fields exist
- Return list of missing fields
- Prompt user to add profile data
- Retry connection after adding

### Notifications
- Auth requests appear in feed with accept/decline
- Consent requests show requested fields
- Contract violations alert user

### Activity Transparency
- All service data access logged
- User can view access history
- Data export available on revocation

---

## Implementation Phases

### Phase 1: Core Connection
- `service_connections.go`: initiate, accept, reject, list, get
- Basic routing in `messages.go`
- Event types added
- Unit tests

### Phase 2: Verification
- `service_verification.go`: DNS, HTTPS verification
- Verification caching
- Unverified service warnings

### Phase 3: Contract Enforcement
- `service_data.go`: get with enforcement, store, list, delete
- `service_contracts.go`: validation, compliance checking
- Contract violation logging

### Phase 4: Service Requests
- `service_requests.go`: auth, consent, respond, list
- Feed notification integration
- Request expiration

### Phase 5: Security Hardening
- Rate limiting implementation
- Revocation + data cleanup
- Security audit

### Phase 6: Polish
- Connection type filtering
- Activity dashboard
- Data export
- Documentation

---

## Verification

### Build & Test
```bash
cd /home/al/Projects/VettID/vettid-dev/enclave/vault-manager
go build ./...
go test -v ./...
```

### Manual Testing
1. Create mock service with contract
2. Initiate connection → verify contract displayed
3. Test with missing required fields → verify detection
4. Accept connection → verify stored correctly
5. Service data.get → verify contract enforcement
6. Service data.store → verify sandbox isolation
7. Service request.auth → verify feed notification
8. Revoke → verify access blocked, optional cleanup

### Security Testing
1. Attempt access to unauthorized fields → verify blocked
2. Exceed rate limit → verify error returned
3. Access after revocation → verify blocked
4. Cross-connection access → verify impossible
5. Service impersonation → verify verification fails
