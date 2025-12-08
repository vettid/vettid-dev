# Task: Phase 6 - Handler System Testing

## Phase
Phase 6: Handler System (WASM)

## Assigned To
Testing Instance

## Repository
`github.com/mesmerverse/vettid-dev` (cdk/tests/)

## Status
Phase 5 complete. Ready for Phase 6 handler system testing.

## Overview

Phase 6 implements the WASM handler system for the Vault Manager. You need to create tests for:
1. Handler package verification and signatures
2. WASM execution in sandboxed environment
3. Resource limits and egress control
4. First-party handler functionality

## New Backend Endpoints

### Handler Registry
```
GET  /registry/handlers              # List available handlers
GET  /registry/handlers/{id}         # Get handler details and download URL
POST /admin/registry/handlers        # Upload new handler (admin)
POST /admin/registry/handlers/sign   # Sign handler package (admin)
POST /admin/registry/handlers/revoke # Revoke handler version (admin)
```

## Phase 6 Testing Tasks

### 1. Handler Verification Tests

Create handler signature and verification tests:

```typescript
// tests/integration/registry/handlerVerification.test.ts

describe('Handler Verification', () => {
  describe('Package Signature', () => {
    it('should verify valid Ed25519 signature');
    it('should reject invalid signature');
    it('should reject expired signature');
    it('should reject revoked handler');
    it('should verify signature chain for updates');
  });

  describe('Manifest Validation', () => {
    it('should validate required manifest fields');
    it('should validate handler version format');
    it('should validate input/output schema');
    it('should validate permission declarations');
    it('should reject manifest with undeclared capabilities');
  });

  describe('WASM Validation', () => {
    it('should validate WASM magic bytes');
    it('should validate required exports');
    it('should reject WASM with forbidden imports');
    it('should validate memory limits');
  });
});
```

### 2. Handler Execution Tests

Create WASM execution tests:

```typescript
// tests/integration/registry/handlerExecution.test.ts

describe('Handler Execution', () => {
  describe('Basic Execution', () => {
    it('should execute handler with valid input');
    it('should return handler output');
    it('should capture handler logs');
    it('should handle handler errors gracefully');
    it('should timeout long-running handlers');
  });

  describe('Input/Output', () => {
    it('should validate input against schema');
    it('should validate output against schema');
    it('should pass context to handler');
    it('should sanitize sensitive data in logs');
  });

  describe('State Management', () => {
    it('should persist handler state');
    it('should isolate state between executions');
    it('should cleanup state on handler uninstall');
  });
});
```

### 3. Sandbox Isolation Tests

Create sandbox security tests:

```typescript
// tests/integration/registry/handlerSandbox.test.ts

describe('Handler Sandbox', () => {
  describe('Memory Isolation', () => {
    it('should enforce memory limits');
    it('should terminate handler exceeding memory');
    it('should not leak memory between executions');
    it('should prevent reading outside allocated memory');
  });

  describe('CPU Isolation', () => {
    it('should enforce execution time limits');
    it('should terminate runaway handlers');
    it('should track CPU usage per handler');
  });

  describe('Filesystem Isolation', () => {
    it('should prevent filesystem access');
    it('should prevent reading environment variables');
    it('should prevent process spawning');
  });

  describe('Network Isolation', () => {
    it('should block unauthorized network access');
    it('should allow declared egress endpoints');
    it('should enforce rate limits on egress');
    it('should timeout slow network requests');
  });
});
```

### 4. Egress Control Tests

Create network egress tests:

```typescript
// tests/integration/registry/egressControl.test.ts

describe('Egress Control', () => {
  describe('Allowlist Enforcement', () => {
    it('should allow requests to declared hosts');
    it('should block requests to undeclared hosts');
    it('should support wildcard patterns');
    it('should enforce HTTPS only');
  });

  describe('Rate Limiting', () => {
    it('should enforce requests per minute limit');
    it('should enforce bandwidth limit');
    it('should queue excess requests');
    it('should reject when queue full');
  });

  describe('Request Validation', () => {
    it('should validate request headers');
    it('should strip sensitive headers');
    it('should inject authentication for known APIs');
    it('should log egress requests for audit');
  });
});
```

### 5. First-Party Handler Tests

Create tests for built-in handlers:

```typescript
// tests/integration/handlers/messagingSendText.test.ts

describe('Messaging Send Text Handler', () => {
  it('should send text message to connection');
  it('should encrypt message with connection key');
  it('should queue message for offline recipient');
  it('should return delivery receipt');
  it('should reject message to non-connected user');
  it('should enforce message size limit');
});

// tests/integration/handlers/profileUpdate.test.ts

describe('Profile Update Handler', () => {
  it('should update profile fields');
  it('should publish profile to MessageSpace');
  it('should validate profile schema');
  it('should reject unauthorized fields');
  it('should version profile updates');
});

// tests/integration/handlers/connectionInvite.test.ts

describe('Connection Invite Handler', () => {
  it('should generate invite code');
  it('should include owner public key');
  it('should set invite expiration');
  it('should enforce max pending invites');
  it('should revoke existing invite');
});
```

### 6. Registry API Tests

Create registry endpoint tests:

```typescript
// tests/integration/registry/listHandlers.test.ts

describe('List Handlers', () => {
  it('should return available handlers');
  it('should filter by category');
  it('should paginate results');
  it('should include version information');
  it('should indicate installed status');
});

// tests/integration/registry/uploadHandler.test.ts

describe('Upload Handler (Admin)', () => {
  it('should upload handler package');
  it('should validate package structure');
  it('should store in S3 with versioning');
  it('should require admin authentication');
  it('should reject duplicate versions');
});
```

### 7. E2E Handler Flow Tests

Create end-to-end tests:

```typescript
// tests/e2e/handlerLifecycle.test.ts

describe('Handler Lifecycle E2E', () => {
  it('should complete: upload → sign → list → install → execute → uninstall');
  it('should complete: upload → revoke → verify rejection');
  it('should handle: version upgrade with state migration');
  it('should handle: handler crash recovery');
});
```

## Test Utilities

Create mock handler packages:

```typescript
// tests/fixtures/handlers/mockHandler.ts

export function createMockHandlerPackage(options: {
  name: string;
  version: string;
  manifest: Partial<HandlerManifest>;
  wasmBehavior: 'success' | 'error' | 'timeout' | 'memory-exceed';
}): HandlerPackage;

export function createValidSignature(
  packageHash: Buffer,
  privateKey: Buffer
): Buffer;

export function createMockManifest(
  overrides?: Partial<HandlerManifest>
): HandlerManifest;
```

## Deliverables

- [ ] handlerVerification.test.ts (signature, manifest, WASM validation)
- [ ] handlerExecution.test.ts (execution, I/O, state)
- [ ] handlerSandbox.test.ts (memory, CPU, filesystem, network isolation)
- [ ] egressControl.test.ts (allowlist, rate limiting, request validation)
- [ ] messagingSendText.test.ts (first-party handler)
- [ ] profileUpdate.test.ts (first-party handler)
- [ ] connectionInvite.test.ts (first-party handler)
- [ ] listHandlers.test.ts, uploadHandler.test.ts (registry API)
- [ ] handlerLifecycle.test.ts (E2E)
- [ ] Mock handler package fixtures

## Acceptance Criteria

- [ ] All handler verification tests pass
- [ ] Sandbox isolation prevents unauthorized access
- [ ] Egress control enforces declared permissions
- [ ] First-party handlers function correctly
- [ ] Registry API tests cover CRUD operations
- [ ] E2E tests cover full handler lifecycle

## Notes

- WASM execution tests can use mock runtime initially
- First-party handler tests simulate vault manager behavior
- Sandbox tests should verify security boundaries thoroughly
- Consider fuzzing for manifest/WASM validation

## Status Update

```bash
cd /path/to/vettid-dev/cdk
git pull
# Create handler system tests
npm run test:unit  # Verify tests pass
git add tests/
git commit -m "Phase 6: Add handler system tests"
git push

# Update status
# Edit cdk/coordination/status/testing.json
git add cdk/coordination/status/testing.json
git commit -m "Update Testing status: Phase 6 handler system tests complete"
git push
```
