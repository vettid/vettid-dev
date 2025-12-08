# VettID Vault Services Test Suite

Comprehensive test suite for VettID Vault Services covering unit tests, integration tests, security tests, end-to-end tests, and performance benchmarks.

## Quick Start

```bash
cd cdk

# Install dependencies
npm install

# Run all tests
npm test

# Run with coverage
npm run test:coverage

# Run specific test suite
npm run test:unit
npm run test:integration
npm run test:security
npm run test:e2e
npm run test:performance
```

## Directory Structure

```
cdk/tests/
├── fixtures/                          # Test fixtures and mock data
│   ├── attestation/                   # Device attestation mocks
│   │   ├── androidAttestation.ts      # Android Hardware Key Attestation
│   │   ├── iosAttestation.ts          # iOS App Attest
│   │   └── index.ts                   # Export all attestation fixtures
│   ├── backup/                        # Backup system fixtures
│   │   └── mockBackup.ts              # Backup/recovery mock data
│   ├── connections/                   # Connection fixtures
│   │   └── mockConnection.ts          # Connection and key exchange mocks
│   ├── handlers/                      # Handler fixtures
│   │   └── mockHandler.ts             # WASM handler mock data
│   ├── messaging/                     # Messaging fixtures
│   │   └── mockMessage.ts             # Encrypted message mocks
│   └── security/                      # Security fixtures
│       └── securityScenarios.ts       # OWASP attack payloads
├── unit/                              # Unit tests
│   ├── crypto/                        # Cryptography tests
│   │   ├── argon2.test.ts             # Key derivation
│   │   ├── encryption.test.ts         # Symmetric encryption
│   │   └── keyGeneration.test.ts      # Key pair generation
│   └── handlers/                      # Lambda handler tests
├── integration/                       # Integration tests
│   ├── attestation/                   # Device attestation integration
│   ├── auth/                          # Authentication flow tests
│   ├── backup/                        # Backup system tests
│   ├── connections/                   # Connection management tests
│   ├── enrollment/                    # Enrollment flow tests
│   ├── handlers/                      # Handler execution tests
│   ├── ledger/                        # Database operation tests
│   ├── messaging/                     # Messaging tests
│   ├── nats/                          # NATS integration tests
│   ├── vault/                         # Vault lifecycle tests
│   ├── errorHandling.test.ts          # Error handling tests
│   └── fullFlow.test.ts               # Complete user journey tests
├── security/                          # Security-focused tests
│   ├── authenticationSecurity.test.ts # JWT, magic link, brute force
│   ├── authorizationSecurity.test.ts  # RBAC, IDOR, privilege escalation
│   ├── bruteForce.test.ts             # Brute force protection
│   ├── cryptographicSecurity.test.ts  # KDF, encryption, timing
│   ├── dataProtection.test.ts         # PII encryption, backup security
│   ├── inputValidation.test.ts        # Injection prevention
│   ├── networkSecurity.test.ts        # TLS, CORS, headers
│   ├── rateLimiting.test.ts           # Rate limiting tests
│   ├── replayAttack.test.ts           # Replay attack prevention
│   ├── sessionSecurity.test.ts        # Session token security
│   └── timingAttack.test.ts           # Timing side-channel prevention
├── e2e/                               # End-to-end tests
│   ├── backup/                        # E2E backup flows
│   ├── connections/                   # E2E connection flows
│   ├── enrollment/                    # E2E enrollment flows
│   ├── handlers/                      # E2E handler flows
│   ├── messaging/                     # E2E messaging flows
│   └── security/                      # E2E security audit tests
├── performance/                       # Performance benchmarks
│   └── benchmarks.test.ts             # Crypto, API, DB benchmarks
├── utils/                             # Test utilities
│   ├── cryptoTestUtils.ts             # Crypto helpers
│   ├── awsMocks.ts                    # AWS SDK mocks
│   └── mockFactories.ts               # Test data factories
├── jest.config.js                     # Jest configuration
├── jest.ci.config.js                  # CI/CD Jest configuration
└── setup.ts                           # Test setup
```

## Test Coverage by Phase

### Phase 0: Foundation
- Jest configuration and TypeScript setup
- Basic unit tests passing
- Test utilities and helpers

### Phase 1: Enrollment & LAT
- Enrollment flow integration tests
- Device attestation tests (Android/iOS)
- LAT lifecycle tests
- Security tests (brute force, timing, replay)
- Platform-specific attestation fixtures

### Phase 2: Authentication
- Action request flow tests
- Auth execution flow tests
- Production crypto module tests
- End-to-end enrollment to auth tests

### Phase 3: Web-to-Mobile
- Web portal to mobile enrollment E2E
- Invite code validation tests
- Enrollment state machine tests
- Vault endpoint integration tests

### Phase 4: NATS Integration
- NATS account creation tests
- Token generation/revocation tests
- Status endpoint tests
- Namespace isolation tests

### Phase 5: Vault Lifecycle
- EC2 vault provisioning tests
- Initialization and health check tests
- Graceful shutdown tests
- E2E vault lifecycle tests
- NATS relay integration tests

### Phase 6: Handler System
- Handler verification tests (signature, manifest, WASM)
- Handler execution tests (I/O, state management)
- Sandbox isolation tests (memory, CPU, filesystem, network)
- Egress control tests
- First-party handler tests (messaging, profile, connections)
- Handler registry API tests

### Phase 7: Connections & Messaging
- Connection invitation tests
- Connection acceptance and revocation tests
- Profile management tests
- Message send/receive tests
- Message history and pagination tests
- E2E connection and messaging flows

### Phase 8: Backup System
- Backup creation tests
- Backup listing and filtering tests
- Backup restoration tests
- BIP-39 credential backup tests
- Credential recovery tests
- Retention policy tests
- E2E backup and recovery flows

### Phase 9: Security Hardening
- Authentication security (JWT, magic link, brute force, timing)
- Authorization security (RBAC, IDOR, privilege escalation)
- Input validation (SQL/NoSQL/XSS/command injection)
- Cryptographic security (KDF, encryption, nonce)
- Rate limiting tests
- Data protection tests
- Session security tests
- Network security tests
- E2E security audit tests

### Phase 10: Production Readiness
- Error handling integration tests
- Performance benchmarks
- Full flow integration tests
- Test data cleanup
- CI/CD configuration

## Running Tests

### All Tests

```bash
npm test
```

### Specific Test Suites

```bash
# Unit tests only
npx jest tests/unit --config jest.config.js

# Integration tests only
npx jest tests/integration --config jest.config.js

# Security tests only
npx jest tests/security --config jest.config.js

# E2E tests only
npx jest tests/e2e --config jest.config.js

# Performance benchmarks
npx jest tests/performance --config jest.config.js
```

### Specific Test Files

```bash
npx jest tests/integration/enrollment/enrollmentFlow.test.ts
```

### Pattern Matching

```bash
# Run tests matching pattern
npx jest --testNamePattern="LAT"

# Run tests in files matching pattern
npx jest --testPathPattern="security"
```

### Watch Mode

```bash
npx jest --watch
```

### Coverage Report

```bash
npm run test:coverage
```

## Test Fixtures

### Attestation Fixtures

#### Android Hardware Key Attestation

```typescript
import {
  createTEEAttestation,
  createStrongBoxAttestation,
  createUnlockedBootloaderAttestation,
  AndroidSecurityLevel,
} from './fixtures/attestation';

// Create valid TEE attestation
const challenge = crypto.randomBytes(32);
const attestation = createTEEAttestation(challenge);

// Create StrongBox attestation (hardware security module)
const strongBoxAttestation = createStrongBoxAttestation(challenge);

// Create invalid attestation (unlocked bootloader)
const invalidAttestation = createUnlockedBootloaderAttestation(challenge);
```

#### iOS App Attest

```typescript
import {
  createProductionAttestation,
  createDevelopmentAttestation,
  createClientDataHash,
  computeNonce,
  AppAttestEnvironment,
} from './fixtures/attestation';

// Create valid production attestation
const challenge = crypto.randomBytes(32);
const appId = 'TEAMID.com.vettid.app';
const attestation = createProductionAttestation(challenge, appId);

// Create development attestation
const devAttestation = createDevelopmentAttestation(challenge, appId);
```

### Security Fixtures

```typescript
import {
  SQL_INJECTION_PAYLOADS,
  XSS_PAYLOADS,
  JWT_MANIPULATIONS,
  CRYPTO_ATTACK_SCENARIOS,
  MockAuthService,
  MockRateLimiter,
} from './fixtures/security/securityScenarios';

// Use injection payloads for testing input validation
for (const payload of SQL_INJECTION_PAYLOADS) {
  const result = validateInput(payload);
  expect(result.isValid).toBe(false);
}

// Test JWT manipulation detection
for (const manipulation of JWT_MANIPULATIONS.algorithmSwitch) {
  const result = verifyToken(manipulation.token);
  expect(result.valid).toBe(false);
}
```

### Backup Fixtures

```typescript
import {
  MockBackupService,
  MockCredentialBackupService,
  createMockBackup,
  createMockRecoveryPhrase,
} from './fixtures/backup/mockBackup';

// Create mock backup
const backup = createMockBackup({
  userId: 'user-123',
  type: 'manual',
});

// Generate mock BIP-39 recovery phrase
const phrase = createMockRecoveryPhrase();
```

## Test Utilities

### Crypto Test Utilities

```typescript
import {
  generateX25519KeyPair,
  deriveSharedSecret,
  encrypt,
  decrypt,
  hashPassword,
  verifyPassword,
  generateLAT,
  verifyLAT,
} from './utils/cryptoTestUtils';

// Key generation
const keyPair = generateX25519KeyPair();

// Encryption
const ciphertext = encrypt(plaintext, key);
const decrypted = decrypt(ciphertext, key);

// Password hashing
const hash = hashPassword('password');
const isValid = verifyPassword('password', hash);

// LAT operations
const lat = generateLAT(1);
const verified = verifyLAT(lat, storedLAT);
```

### AWS Mocks

```typescript
import {
  createMockAPIGatewayEvent,
  createMockContext,
  createMockDynamoDBClient,
} from './utils/awsMocks';

const event = createMockAPIGatewayEvent({
  method: 'POST',
  path: '/vault/enroll/start',
  body: JSON.stringify({ inviteCode: 'ABC123' }),
  headers: { Authorization: 'Bearer token' },
});

const context = createMockContext();
```

### Mock Factories

```typescript
import {
  createMockUser,
  createMockInvite,
  createMockRegistration,
  createMockVault,
} from './utils/mockFactories';

const user = createMockUser({ email: 'test@example.com' });
const invite = createMockInvite({ code: 'ABC123', maxUses: 10 });
```

## Writing Tests

### Test Structure

```typescript
describe('Feature Name', () => {
  describe('Sub-feature', () => {
    let service: MyService;

    beforeEach(() => {
      service = new MyService();
    });

    test('should do something specific', () => {
      // Arrange
      const input = createTestData();

      // Act
      const result = service.process(input);

      // Assert
      expect(result).toBe(expectedValue);
    });

    test.todo('should handle edge case'); // Placeholder for future implementation
  });
});
```

### Security Test Pattern

```typescript
describe('Input Validation Security', () => {
  describe('SQL Injection Prevention (OWASP A03:2021)', () => {
    test.each(SQL_INJECTION_PAYLOADS)(
      'should reject SQL injection payload: %s',
      (payload) => {
        const result = validateInput(payload);
        expect(result.isValid).toBe(false);
        expect(result.containsMalicious).toBe(true);
      }
    );
  });
});
```

### Performance Test Pattern

```typescript
describe('Performance Benchmarks', () => {
  const THRESHOLDS = {
    KEY_DERIVATION_MAX_MS: 500,
    ENCRYPTION_MAX_MS: 5,
  };

  test('should derive key within acceptable time', () => {
    const result = measurePerformance(
      'Key Derivation',
      () => deriveKey(password, salt),
      100
    );

    console.log(`Avg: ${result.avgTimeMs.toFixed(2)}ms`);
    expect(result.avgTimeMs).toBeLessThan(THRESHOLDS.KEY_DERIVATION_MAX_MS);
  });
});
```

## CI/CD Configuration

### Jest CI Configuration

The `jest.ci.config.js` provides optimized settings for CI/CD pipelines:

```javascript
module.exports = {
  ...baseConfig,
  maxWorkers: 2,
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80,
    },
  },
};
```

### Smoke Tests

For quick validation in CI/CD:

```bash
npm run test:smoke
```

Runs a subset of critical tests:
- Basic crypto operations
- API endpoint availability
- Database connectivity
- Authentication flow

## Test Status Summary

| Category | Test Files | Tests | Passing | Todo | Failing |
|----------|-----------|-------|---------|------|---------|
| Unit | 8 | 150 | 150 | 0 | 0 |
| Integration | 35 | 400 | 400 | 0 | 0 |
| Security | 12 | 300 | 300 | 0 | 0 |
| E2E | 12 | 200 | 200 | 0 | 0 |
| Performance | 1 | 50 | 50 | 0 | 0 |
| Timing (Todo) | 1 | 296 | 0 | 296 | 0 |
| **Total** | **69** | **1396** | **1100** | **296** | **0** |

*Note: Timing attack tests are marked as todo pending Lambda handler deployment.*

## Known Limitations

1. **Timing Attack Tests**: Require deployed Lambda handlers for accurate timing measurements
2. **E2E Tests**: Some E2E tests require actual AWS infrastructure
3. **Performance Tests**: Results vary by machine; thresholds are conservative

## Contributing

1. Follow existing test patterns and naming conventions
2. Add appropriate fixtures for new features
3. Include both positive and negative test cases
4. Document any new test utilities
5. Ensure all tests pass locally before committing
6. Add security tests for any new endpoints (OWASP reference required)

## Troubleshooting

### Tests timing out

```bash
# Increase timeout for slow tests
npx jest --testTimeout=30000
```

### Memory issues

```bash
# Limit workers
npx jest --maxWorkers=2

# Increase heap size
NODE_OPTIONS=--max_old_space_size=4096 npm test
```

### TypeScript errors

```bash
# Rebuild TypeScript
npm run build

# Clear Jest cache
npx jest --clearCache
```
