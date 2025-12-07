# Task: Phase 1 - Backend Implementation Tests

## Phase
Phase 1: Protean Credential System - Core

## Assigned To
Testing Instance

## Repository
`github.com/mesmerverse/vettid-dev`

## Status
Your Phase 1 integration test scaffolding is complete (229 tests, 69 passing, 159 todo).

## Phase 1 Testing Tasks

Now that the test scaffolding exists, your focus shifts to:

### 1. Expand Implemented Tests

The following test files have comprehensive scaffolding with `it.todo()` placeholders. As the orchestrator implements backend Lambda handlers, you will fill in these tests:

**Files to monitor:**
- `cdk/tests/integration/enrollment/enrollmentFlow.test.ts`
- `cdk/tests/integration/attestation/deviceAttestation.test.ts`
- `cdk/tests/integration/ledger/latLifecycle.test.ts`
- `cdk/tests/security/bruteForce.test.ts`
- `cdk/tests/security/timingAttack.test.ts`
- `cdk/tests/security/replayAttack.test.ts`

### 2. Add Mock Data for Mobile Attestation

Create test fixtures for:
- Android Hardware Key Attestation certificates
- iOS App Attest attestation objects

Reference docs:
- https://developer.android.com/training/articles/security-key-attestation
- https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server

### 3. Database Integration Tests

When the Ledger (PostgreSQL) infrastructure is deployed, create:

```
cdk/tests/integration/ledger/
├── credentialLifecycle.test.ts  # Full credential CRUD
├── keyRotation.test.ts          # CEK/TK rotation
├── concurrentSession.test.ts    # Atomic session tests
└── transactionKeyPool.test.ts   # Key pool management
```

### 4. API Contract Tests

Validate Lambda handlers match OpenAPI spec:
- `POST /vault/enroll/start`
- `POST /vault/enroll/attestation`
- `POST /vault/enroll/set-password`
- `POST /vault/enroll/finalize`
- `POST /vault/auth/action-request`
- `POST /vault/auth/execute`

## Coordination

When you need new Lambda handlers or API changes:
1. Document the requirement in `cdk/coordination/results/issues/`
2. Update your status in `cdk/coordination/status/testing.json`

## Acceptance Criteria

- [ ] All existing 69 passing tests continue to pass
- [ ] Mock attestation data created for Android/iOS
- [ ] Test utilities documented for mobile instances
- [ ] Integration tests ready to activate when backend deploys
