# Task: Phase 3 - Vault Lifecycle Testing

## Phase
Phase 3: Vault Services Enrollment

## Assigned To
Testing Instance

## Repository
`github.com/mesmerverse/vettid-dev`

## Status
Phase 2 complete. Ready for Phase 3 vault lifecycle testing.

## New Backend Handlers

Three new handlers have been created:

1. `POST /member/vault/deploy` - Member initiates vault deployment, returns QR code data
2. `GET /vault/status` - Get vault status for authenticated user
3. `POST /vault/sync` - Sync vault state and replenish transaction keys

## Phase 3 Testing Tasks

### 1. Vault Deployment Tests

Create tests for the new deploy vault handler:

```
cdk/tests/integration/vault/
├── deployVault.test.ts         # Test POST /member/vault/deploy
├── getVaultStatus.test.ts      # Test GET /vault/status
└── syncVault.test.ts           # Test POST /vault/sync
```

Test cases for `deployVault`:
- Member can initiate vault deployment
- Returns valid QR data structure with invite code
- Duplicate deployment returns existing pending invite
- Already-enrolled member cannot deploy again (409 Conflict)
- Invite expires after 30 minutes

### 2. Vault Status Tests

Test `getVaultStatus` endpoint:

```typescript
describe('GET /vault/status', () => {
  it('should return not_enrolled for new users');
  it('should return pending during enrollment');
  it('should return enrolled after finalization');
  it('should return active after first authentication');
  it('should include transaction_keys_remaining count');
  it('should include credential_version');
  it('should include device_type and security_level');
});
```

### 3. Vault Sync Tests

Test `syncVault` endpoint:

```typescript
describe('POST /vault/sync', () => {
  it('should update last_sync_at timestamp');
  it('should return current key count when above minimum');
  it('should replenish keys when below minimum (10)');
  it('should generate 20 new keys when replenishing');
  it('should return new transaction keys in response');
  it('should return 404 for non-enrolled users');
});
```

### 4. E2E Enrollment Flow Tests

Update e2e tests to include full flow:

```typescript
// tests/e2e/vaultLifecycle.test.ts
describe('Full Vault Lifecycle', () => {
  it('should complete: deploy → enroll → auth → sync');
  it('should track status transitions correctly');
  it('should replenish keys after multiple auths');
});
```

### 5. QR Code Validation Tests

Test QR data structure:

```typescript
describe('QR Code Data', () => {
  it('should have type: vettid_vault_enrollment');
  it('should include valid invite code');
  it('should include API endpoint');
  it('should include expiration timestamp');
  it('should be valid JSON parseable by mobile apps');
});
```

## Key Files to Test

- `lambda/handlers/member/deployVault.ts` - NEW
- `lambda/handlers/vault/getVaultStatus.ts` - NEW
- `lambda/handlers/vault/syncVault.ts` - NEW

## Response Structures

### Deploy Vault Response
```typescript
{
  invite_code: string;
  qr_data: string;  // JSON stringified
  expires_at: string;  // ISO timestamp
  enrollment_endpoint: string;  // "/vault/enroll/start"
}
```

### Vault Status Response
```typescript
{
  status: 'not_enrolled' | 'pending' | 'enrolled' | 'active' | 'error';
  user_guid?: string;
  enrolled_at?: string;
  last_auth_at?: string;
  last_sync_at?: string;
  device_type?: 'android' | 'ios';
  security_level?: string;
  transaction_keys_remaining?: number;
  credential_version?: number;
}
```

### Sync Response
```typescript
{
  status: 'synced' | 'keys_replenished';
  last_sync_at: string;
  transaction_keys_remaining: number;
  new_transaction_keys?: Array<{
    key_id: string;
    public_key: string;
    algorithm: string;
  }>;
  credential_version: number;
}
```

## Acceptance Criteria

- [ ] Unit tests for all three new handlers
- [ ] Integration tests for vault lifecycle
- [ ] E2E test for complete deploy → enroll → auth → sync flow
- [ ] QR data structure validated
- [ ] Transaction key replenishment verified
- [ ] Status transitions verified
- [ ] All existing tests still pass

## Status Update

```bash
cd /path/to/vettid-dev
git pull
# Edit cdk/coordination/status/testing.json
git add cdk/coordination/status/testing.json
git commit -m "Update Testing status: Phase 3 vault lifecycle tests complete"
git push
```
