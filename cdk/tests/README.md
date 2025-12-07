# VettID Test Suite

This directory contains the test infrastructure for VettID Vault Services, including unit tests, integration tests, and security tests.

## Directory Structure

```
cdk/tests/
├── fixtures/                     # Test fixtures and mock data
│   └── attestation/             # Device attestation mocks
│       ├── androidAttestation.ts  # Android Hardware Key Attestation
│       ├── iosAttestation.ts      # iOS App Attest
│       └── index.ts               # Export all fixtures
├── integration/                  # Integration tests
│   ├── attestation/             # Device attestation tests
│   │   └── deviceAttestation.test.ts
│   ├── enrollment/              # Enrollment flow tests
│   │   └── enrollmentFlow.test.ts
│   └── ledger/                  # Database/ledger tests
│       ├── credentialLifecycle.test.ts
│       ├── keyRotation.test.ts
│       └── latLifecycle.test.ts
├── security/                    # Security-focused tests
│   ├── bruteForce.test.ts       # Brute force protection
│   ├── replayAttack.test.ts     # Replay attack prevention
│   └── timingAttack.test.ts     # Timing side-channel prevention
├── unit/                        # Unit tests
│   ├── crypto/                  # Cryptography tests
│   │   ├── argon2.test.ts
│   │   ├── encryption.test.ts
│   │   └── keyGeneration.test.ts
│   └── handlers/                # Lambda handler tests
├── utils/                       # Test utilities
│   ├── cryptoTestUtils.ts       # Crypto helpers
│   ├── awsMocks.ts              # AWS SDK mocks
│   └── mockFactories.ts         # Test data factories
├── jest.config.js               # Jest configuration
└── setup.ts                     # Test setup
```

## Running Tests

```bash
cd cdk

# Run all tests
npm test

# Run with coverage
npm run test:coverage

# Run specific test file
npx jest tests/integration/enrollment/enrollmentFlow.test.ts

# Run tests matching pattern
npx jest --testNamePattern="LAT"

# Run in watch mode
npx jest --watch
```

## Test Categories

### Unit Tests (`tests/unit/`)

Tests for individual functions and modules in isolation.

### Integration Tests (`tests/integration/`)

Tests for complete workflows that span multiple components.

### Security Tests (`tests/security/`)

Tests specifically for security properties:
- **bruteForce.test.ts**: Password attempt limits, rate limiting, account lockout
- **timingAttack.test.ts**: Constant-time operations for LAT and password verification
- **replayAttack.test.ts**: Single-use transaction keys, LAT versioning

## Test Fixtures

### Attestation Fixtures

Located in `tests/fixtures/attestation/`, these provide mock data for device attestation testing.

#### Android Hardware Key Attestation

```typescript
import {
  createTEEAttestation,
  createStrongBoxAttestation,
  createUnlockedBootloaderAttestation,
  AndroidSecurityLevel,
} from '../fixtures/attestation';

// Create valid TEE attestation
const challenge = crypto.randomBytes(32);
const attestation = createTEEAttestation(challenge);
// attestation.certChain: Buffer[] - Certificate chain
// attestation.extension: AttestationExtension - Parsed extension data
// attestation.keyId: string - Key identifier

// Create StrongBox attestation
const strongBoxAttestation = createStrongBoxAttestation(challenge);

// Create invalid attestation (unlocked bootloader)
const invalidAttestation = createUnlockedBootloaderAttestation(challenge);
```

#### iOS App Attest

```typescript
import {
  createProductionAttestation,
  createDevelopmentAttestation,
  createWrongAppIdAttestation,
  createClientDataHash,
  computeNonce,
  AppAttestEnvironment,
} from '../fixtures/attestation';

// Create valid production attestation
const challenge = crypto.randomBytes(32);
const appId = 'TEAMID.com.vettid.app';
const attestation = createProductionAttestation(challenge, appId);
// attestation.attestationObject: Buffer - CBOR-encoded attestation
// attestation.keyId: string - Key identifier
// attestation.decoded: AttestationObject - Parsed object

// Create development attestation
const devAttestation = createDevelopmentAttestation(challenge, appId);

// Compute verification values
const clientDataHash = createClientDataHash(challenge);
const nonce = computeNonce(attestation.decoded.authData, clientDataHash);
```

## Crypto Test Utilities

Located in `tests/utils/cryptoTestUtils.ts`:

```typescript
import {
  // Key operations
  generateX25519KeyPair,
  deriveSharedSecret,
  deriveKey,

  // Encryption
  encrypt,
  decrypt,
  encryptCredentialBlob,
  decryptCredentialBlob,

  // Password hashing
  hashPassword,
  verifyPassword,

  // LAT operations
  generateLAT,
  verifyLAT,

  // Transaction keys
  generateTransactionKeyPool,
} from '../utils/cryptoTestUtils';

// Generate X25519 key pair
const keyPair = generateX25519KeyPair();
// keyPair.publicKey: Buffer (32 bytes)
// keyPair.privateKey: Buffer (32 bytes)

// Encrypt credential blob
const credential = {
  guid: 'user-guid',
  passwordHash: hashPassword('password'),
  hashAlgorithm: 'argon2id',
  hashVersion: '1.0',
  policies: { ttlHours: 24, maxFailedAttempts: 3 },
  secrets: { key: 'value' },
};
const blob = encryptCredentialBlob(credential, keyPair.publicKey);

// Decrypt credential blob
const decrypted = decryptCredentialBlob(blob, keyPair.privateKey);

// Generate and verify LAT
const lat = generateLAT(1);
const isValid = verifyLAT(lat, storedLAT);

// Generate transaction key pool
const keys = generateTransactionKeyPool(20);
```

## Writing Tests

### Test Structure

```typescript
describe('Feature Name', () => {
  describe('Sub-feature', () => {
    it('should do something specific', () => {
      // Arrange
      const input = createTestData();

      // Act
      const result = functionUnderTest(input);

      // Assert
      expect(result).toBe(expectedValue);
    });

    // Placeholder for future implementation
    it.todo('should handle edge case');
  });
});
```

### Using Mocks

```typescript
import { createMockAPIGatewayEvent, createMockContext } from '../utils/awsMocks';
import { createMockInvite, createMockRegistration } from '../utils/mockFactories';

const event = createMockAPIGatewayEvent({
  method: 'POST',
  path: '/vault/enroll/start',
  body: JSON.stringify({ inviteCode: 'ABC123' }),
});

const context = createMockContext();
const invite = createMockInvite({ code: 'ABC123' });
```

## For Mobile Instances

### Android Instance

Use the Android attestation fixtures to validate your attestation generation:

```typescript
// Generate mock attestation matching your implementation
const { certChain, extension } = generateMockAndroidAttestation({
  challenge: serverChallenge,
  securityLevel: AndroidSecurityLevel.TRUSTED_ENVIRONMENT,
});

// Verify your certificate chain matches expected structure
expect(certChain).toHaveLength(3); // leaf, intermediate, root
expect(extension.attestationChallenge).toEqual(serverChallenge);
```

### iOS Instance

Use the iOS App Attest fixtures to validate your attestation generation:

```typescript
// Generate mock attestation matching your implementation
const { attestationObject, decoded } = generateMockiOSAttestation({
  challenge: serverChallenge,
  appId: 'TEAMID.com.vettid.app',
  environment: AppAttestEnvironment.PRODUCTION,
});

// Verify your attestation object structure
expect(decoded.fmt).toBe('apple-appattest');
expect(decoded.attStmt.x5c).toHaveLength(3);
```

## Test Status

| Category | Total | Passing | Todo | Failing |
|----------|-------|---------|------|---------|
| Integration | 89 | 35 | 54 | 0 |
| Security | 85 | 14 | 71 | 0 |
| Unit | 55 | 55 | 0 | 0 |
| **Total** | **229** | **104** | **125** | **0** |

## Contributing

1. Follow existing test patterns
2. Add appropriate test fixtures for new features
3. Include both positive and negative test cases
4. Document any new test utilities
5. Ensure all tests pass before committing
