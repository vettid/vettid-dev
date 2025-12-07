# Task: Phase 2 - Device Attestation Testing

## Phase
Phase 2: Device Attestation

## Assigned To
Testing Instance

## Repository
`github.com/mesmerverse/vettid-dev`

## Status
Phase 1 complete. Ready for Phase 2 attestation testing.

## Phase 2 Testing Tasks

### 1. Attestation Verification Tests

Create tests for the new attestation handlers:

```
cdk/tests/unit/attestation/
├── androidAttestation.test.ts   # Test verifyAndroidAttestation()
├── iosAttestation.test.ts       # Test verifyIosAttestation()
└── attestationUtils.test.ts     # Test challenge generation, etc.
```

Test cases:
- Valid attestation certificate chain parsing
- Invalid/expired certificate rejection
- Challenge verification
- Security level detection (hardware vs software)
- Root CA verification

### 2. Update Integration Tests

Update enrollment flow tests for new attestation step:

```typescript
// tests/integration/enrollment/enrollmentFlow.test.ts
describe('Enrollment with Attestation', () => {
  it('should require attestation before password');
  it('should reject invalid attestation');
  it('should accept valid Android attestation');
  it('should accept valid iOS attestation');
  it('should store attestation result in session');
});
```

### 3. Use Existing Fixtures

Your Phase 1 attestation fixtures are ready:
- `tests/fixtures/attestation/androidAttestation.ts`
- `tests/fixtures/attestation/iosAttestation.ts`

Use these mock certificates and attestation objects for testing.

### 4. Security Tests

Add attestation-specific security tests:
- Replay attack prevention (challenge reuse)
- Certificate chain validation
- Timing attack resistance for verification

## Key Files to Test

- `lambda/common/attestation.ts` - Attestation utilities
- `lambda/handlers/attestation/verifyAndroidAttestation.ts`
- `lambda/handlers/attestation/verifyIosAttestation.ts`
- `lambda/handlers/vault/enrollStart.ts` - Updated with attestation flow

## Acceptance Criteria

- [ ] Unit tests for attestation parsing and verification
- [ ] Integration tests for attestation in enrollment flow
- [ ] Mock fixtures generate valid test data
- [ ] Security tests for attestation replay prevention
- [ ] All existing tests still pass

## Status Update

```bash
cd /path/to/vettid-dev
git pull
# Edit cdk/coordination/status/testing.json
git add cdk/coordination/status/testing.json
git commit -m "Update Testing status: Phase 2 attestation tests complete"
git push
```
