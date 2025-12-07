# Task: Phase 4 - NATS Infrastructure Testing

## Phase
Phase 4: NATS Infrastructure

## Assigned To
Testing Instance

## Repository
`github.com/mesmerverse/vettid-dev`

## Status
Phase 3 complete. Ready for Phase 4 NATS infrastructure testing.

## New Infrastructure

### NATS Stack (`lib/nats-stack.ts`)
- Dedicated VPC with 3 AZs
- 3-node NATS cluster on t4g.small (ARM64)
- Network Load Balancer with ACM TLS
- Self-signed certificates for internal cluster communication
- Secrets Manager for operator keys and internal CA

### New DynamoDB Tables
- `NatsAccounts` - Member NATS namespace allocations
- `NatsTokens` - Issued NATS JWT tokens (with GSI on user_guid)

### New Lambda Handlers
1. `POST /vault/nats/account` - Create member NATS namespace
2. `POST /vault/nats/token` - Generate scoped NATS JWT token
3. `POST /vault/nats/token/revoke` - Revoke NATS token
4. `GET /vault/nats/status` - Get NATS account status

## Phase 4 Testing Tasks

### 1. NATS Account Creation Tests

```
cdk/tests/integration/nats/
├── createAccount.test.ts      # Test POST /vault/nats/account
├── generateToken.test.ts      # Test POST /vault/nats/token
├── revokeToken.test.ts        # Test POST /vault/nats/token/revoke
└── getNatsStatus.test.ts      # Test GET /vault/nats/status
```

Test cases for `createMemberAccount`:
```typescript
describe('POST /vault/nats/account', () => {
  it('should create NATS account for authenticated member');
  it('should return OwnerSpace and MessageSpace IDs');
  it('should return 409 if account already exists');
  it('should require authentication');
  it('should generate unique account public key placeholder');
});
```

### 2. Token Generation Tests

Test `generateMemberJwt` endpoint:
```typescript
describe('POST /vault/nats/token', () => {
  it('should generate token for app client_type');
  it('should generate token for vault client_type');
  it('should require NATS account to exist first');
  it('should return token with correct permissions');
  it('should set app token validity to 24 hours');
  it('should set vault token validity to 7 days');
  it('should include nats_jwt and nats_seed in response');
  it('should store token record in DynamoDB');
});
```

### 3. Token Revocation Tests

Test `revokeToken` endpoint:
```typescript
describe('POST /vault/nats/token/revoke', () => {
  it('should revoke active token');
  it('should return 404 for non-existent token');
  it('should prevent revoking other users tokens');
  it('should update token status to revoked');
  it('should return already revoked message for re-revocation');
});
```

### 4. Status Tests

Test `getNatsStatus` endpoint:
```typescript
describe('GET /vault/nats/status', () => {
  it('should return has_account: false for new users');
  it('should return account details after creation');
  it('should list active tokens');
  it('should filter out expired tokens');
  it('should return nats_endpoint');
});
```

### 5. Permission Tests

Test NATS permissions structure:
```typescript
describe('NATS Permissions', () => {
  describe('App client permissions', () => {
    it('should allow publish to OwnerSpace.forVault');
    it('should allow subscribe to OwnerSpace.forApp');
    it('should allow subscribe to OwnerSpace.eventTypes');
  });

  describe('Vault client permissions', () => {
    it('should allow publish to OwnerSpace.forApp');
    it('should allow publish to MessageSpace.forOwner');
    it('should allow subscribe to OwnerSpace.forVault');
    it('should allow subscribe to OwnerSpace.control');
  });
});
```

### 6. Namespace Isolation Tests

```typescript
describe('Namespace Isolation', () => {
  it('should prevent cross-namespace access');
  it('should verify account IDs are unique per user');
  it('should verify token cannot access other accounts');
});
```

## Response Structures

### Create Account Response
```typescript
{
  owner_space_id: string;       // "OwnerSpace.{user_guid}"
  message_space_id: string;     // "MessageSpace.{user_guid}"
  nats_endpoint: string;        // "nats://nats.vettid.dev:4222"
  status: 'active';
}
```

### Generate Token Response
```typescript
{
  token_id: string;
  nats_jwt: string;
  nats_seed: string;
  nats_endpoint: string;
  expires_at: string;
  permissions: {
    publish: string[];
    subscribe: string[];
  };
}
```

### NATS Status Response
```typescript
{
  has_account: boolean;
  account?: {
    owner_space_id: string;
    message_space_id: string;
    status: string;
    created_at: string;
  };
  active_tokens: Array<{
    token_id: string;
    client_type: 'app' | 'vault';
    device_id?: string;
    issued_at: string;
    expires_at: string;
    last_used_at?: string;
  }>;
  nats_endpoint: string;
}
```

## Acceptance Criteria

- [ ] Unit tests for all four NATS handlers
- [ ] Integration tests for account creation flow
- [ ] Token generation and revocation tests
- [ ] Permission structure validation tests
- [ ] Namespace isolation verification
- [ ] All existing tests still pass
- [ ] Test coverage for error cases (404, 409, 403)

## Status Update

```bash
cd /path/to/vettid-dev
git pull
# Edit cdk/coordination/status/testing.json
git add cdk/coordination/status/testing.json
git commit -m "Update Testing status: Phase 4 NATS infrastructure tests"
git push
```
