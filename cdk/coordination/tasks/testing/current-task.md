# Task: Set Up Test Infrastructure

## Phase
Phase 0: Foundation & Coordination Setup

## Assigned To
Testing Instance

## Prerequisites
- [x] Coordination directory structure created
- [x] API specifications available in `cdk/coordination/specs/`

## Context

You are the **Testing Instance** for the VettID Vault Services project. Your role is to create and maintain the test infrastructure, write tests for all components, and validate security requirements.

Read these files first:
1. `cdk/docs/DEVELOPMENT_PLAN.md` - Overall development plan
2. `cdk/coordination/README.md` - Coordination protocol
3. `cdk/coordination/specs/vault-services-api.yaml` - API specification
4. `cdk/coordination/specs/credential-format.md` - Credential format spec

## Deliverables

### 1. Create Test Directory Structure

```
cdk/tests/
├── jest.config.js          # Jest configuration
├── setup.ts                # Global test setup
├── utils/
│   ├── testClient.ts       # HTTP API test client
│   ├── mockCognito.ts      # Mock Cognito tokens
│   ├── mockDynamoDB.ts     # DynamoDB local helpers
│   └── cryptoTestUtils.ts  # Crypto test helpers
├── unit/
│   └── .gitkeep
├── integration/
│   └── .gitkeep
├── e2e/
│   └── .gitkeep
└── security/
    └── .gitkeep
```

### 2. Configure Jest

Create `cdk/tests/jest.config.js` with:
- TypeScript support via ts-jest
- Path aliases matching the Lambda handlers
- Coverage reporting
- Test environment configuration

### 3. Create Base Test Utilities

**testClient.ts:**
- HTTP client for API testing
- Support for Bearer token authentication
- Response validation helpers

**mockCognito.ts:**
- Generate valid JWT tokens for testing
- Support both admin and member pools
- Include custom claims (user_guid, groups)

**cryptoTestUtils.ts:**
- X25519 key pair generation
- XChaCha20-Poly1305 encrypt/decrypt
- Argon2id hash generation
- LAT token generation

### 4. Create Initial Unit Tests

Create placeholder tests for Phase 1 crypto utilities:
- `unit/crypto/encryption.test.ts`
- `unit/crypto/argon2.test.ts`
- `unit/crypto/keyGeneration.test.ts`

### 5. Update package.json

Add test scripts:
```json
{
  "scripts": {
    "test": "jest",
    "test:unit": "jest --testPathPattern=unit",
    "test:integration": "jest --testPathPattern=integration",
    "test:e2e": "jest --testPathPattern=e2e",
    "test:security": "jest --testPathPattern=security",
    "test:coverage": "jest --coverage"
  }
}
```

Add dev dependencies:
- jest
- ts-jest
- @types/jest
- tweetnacl (for crypto tests)
- argon2-browser or hash-wasm (for Argon2 tests)

## Acceptance Criteria

- [ ] Jest runs successfully with `npm test`
- [ ] Test utilities compile without errors
- [ ] Mock token generation produces valid JWT structure
- [ ] Crypto test utilities can encrypt/decrypt correctly
- [ ] At least one passing placeholder test in each category
- [ ] Coverage reporting works

## Reporting

When complete:
1. Update `cdk/coordination/status/testing.json`:
   ```json
   {
     "instance": "testing",
     "phase": 0,
     "task": "Test infrastructure setup complete",
     "status": "completed",
     "completedTasks": ["Jest setup", "Test utilities", "Placeholder tests"],
     "lastUpdated": "<current timestamp>"
   }
   ```

2. Document any issues in `cdk/coordination/results/issues/`

## Notes

- The existing codebase uses Node.js 22 and TypeScript
- Lambda handlers are in `cdk/lambda/handlers/`
- Common utilities are in `cdk/lambda/common/`
- Existing patterns should be followed where applicable
