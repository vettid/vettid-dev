/**
 * Unit Tests: NATS JWT Module (lambda/common/nats-jwt.ts)
 *
 * Tests the NATS JWT generation and credential formatting:
 * - Account JWT generation
 * - User JWT generation with permissions
 * - Credential file formatting
 * - JWT structure validation
 *
 * Note: These tests mock AWS Secrets Manager to avoid requiring
 * actual operator keys. Integration tests should use real keys.
 *
 * @see cdk/lambda/common/nats-jwt.ts
 */

import * as nkeys from 'nkeys.js';

// Mock AWS Secrets Manager before importing the module
const mockGetSecretValue = jest.fn();
jest.mock('@aws-sdk/client-secrets-manager', () => ({
  SecretsManagerClient: jest.fn().mockImplementation(() => ({
    send: mockGetSecretValue,
  })),
  GetSecretValueCommand: jest.fn().mockImplementation((params) => params),
}));

// Create test operator keys
const testOperatorKeyPair = nkeys.createOperator();
const testOperatorSeed = new TextDecoder().decode(testOperatorKeyPair.getSeed());
const testOperatorPublicKey = testOperatorKeyPair.getPublicKey();

const testSystemAccountKeyPair = nkeys.createAccount();
const testSystemAccountSeed = new TextDecoder().decode(testSystemAccountKeyPair.getSeed());
const testSystemAccountPublicKey = testSystemAccountKeyPair.getPublicKey();

// Setup mock to return test keys
beforeEach(() => {
  mockGetSecretValue.mockReset();
  mockGetSecretValue.mockResolvedValue({
    SecretString: JSON.stringify({
      operator_seed: testOperatorSeed,
      operator_public_key: testOperatorPublicKey,
      system_account_seed: testSystemAccountSeed,
      system_account_public_key: testSystemAccountPublicKey,
    }),
  });
});

// Import after mocking
import {
  createAccountJwt,
  createUserJwt,
  generateAccountCredentials,
  generateUserCredentials,
  formatCredsFile,
  getOperatorPublicKey,
  getSystemAccountPublicKey,
} from '../../../lambda/common/nats-jwt';

// ============================================
// JWT Structure Helpers
// ============================================

function decodeJwt(jwt: string): { header: any; payload: any; signature: string } {
  const parts = jwt.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT format');
  }

  return {
    header: JSON.parse(Buffer.from(parts[0], 'base64url').toString()),
    payload: JSON.parse(Buffer.from(parts[1], 'base64url').toString()),
    signature: parts[2],
  };
}

function verifyJwtSignature(jwt: string, publicKey: string): boolean {
  const parts = jwt.split('.');
  const dataToVerify = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
  const signature = Buffer.from(parts[2], 'base64url');

  try {
    const keyPair = nkeys.fromPublic(publicKey);
    return keyPair.verify(dataToVerify, signature);
  } catch {
    return false;
  }
}

// ============================================
// Account JWT Tests
// ============================================

describe('Account JWT Generation', () => {
  describe('createAccountJwt', () => {
    it('should generate a valid JWT structure', async () => {
      const accountKeyPair = nkeys.createAccount();
      const accountPublicKey = accountKeyPair.getPublicKey();

      const jwt = await createAccountJwt('test-account', accountPublicKey);
      const decoded = decodeJwt(jwt);

      expect(decoded.header.typ).toBe('JWT');
      expect(decoded.header.alg).toBe('ed25519-nkey');
    });

    it('should include correct account claims', async () => {
      const accountKeyPair = nkeys.createAccount();
      const accountPublicKey = accountKeyPair.getPublicKey();

      const jwt = await createAccountJwt('my-account', accountPublicKey);
      const decoded = decodeJwt(jwt);

      expect(decoded.payload.name).toBe('my-account');
      expect(decoded.payload.sub).toBe(accountPublicKey);
      expect(decoded.payload.iss).toBe(testOperatorPublicKey);
      expect(decoded.payload.nats.type).toBe('account');
      expect(decoded.payload.nats.version).toBe(2);
    });

    it('should include default account limits', async () => {
      const accountKeyPair = nkeys.createAccount();
      const accountPublicKey = accountKeyPair.getPublicKey();

      const jwt = await createAccountJwt('test-account', accountPublicKey);
      const decoded = decodeJwt(jwt);

      // SECURITY: Account limits prevent DoS attacks against the NATS cluster
      expect(decoded.payload.nats.limits).toEqual({
        subs: 100,           // Max subscriptions per account
        data: 10_000_000,    // 10 MB/sec data transfer
        payload: 1_048_576,  // 1 MB max message payload
        imports: 10,         // Max imports
        exports: 10,         // Max exports
        wildcards: true,     // Allow wildcards for OwnerSpace.{guid}.>
        conn: 10,            // Max connections (mobile + vault + backup)
        leaf: 0,             // No leaf nodes needed
      });
    });

    it('should set iat to current time', async () => {
      const accountKeyPair = nkeys.createAccount();
      const accountPublicKey = accountKeyPair.getPublicKey();
      const beforeTime = Math.floor(Date.now() / 1000);

      const jwt = await createAccountJwt('test-account', accountPublicKey);
      const decoded = decodeJwt(jwt);
      const afterTime = Math.floor(Date.now() / 1000);

      expect(decoded.payload.iat).toBeGreaterThanOrEqual(beforeTime);
      expect(decoded.payload.iat).toBeLessThanOrEqual(afterTime);
    });

    it('should generate unique jti for different accounts', async () => {
      const accountKeyPair1 = nkeys.createAccount();
      const accountKeyPair2 = nkeys.createAccount();

      const jwt1 = await createAccountJwt('test-account-1', accountKeyPair1.getPublicKey());
      const jwt2 = await createAccountJwt('test-account-2', accountKeyPair2.getPublicKey());

      const decoded1 = decodeJwt(jwt1);
      const decoded2 = decodeJwt(jwt2);

      // JTI is based on public key and timestamp, so different keys = different JTI
      expect(decoded1.payload.jti).not.toBe(decoded2.payload.jti);
    });

    it('should be signed by operator', async () => {
      const accountKeyPair = nkeys.createAccount();
      const accountPublicKey = accountKeyPair.getPublicKey();

      const jwt = await createAccountJwt('test-account', accountPublicKey);

      const isValid = verifyJwtSignature(jwt, testOperatorPublicKey);
      expect(isValid).toBe(true);
    });

    it('should fail verification with wrong key', async () => {
      const accountKeyPair = nkeys.createAccount();
      const accountPublicKey = accountKeyPair.getPublicKey();
      const wrongKeyPair = nkeys.createOperator();

      const jwt = await createAccountJwt('test-account', accountPublicKey);

      const isValid = verifyJwtSignature(jwt, wrongKeyPair.getPublicKey());
      expect(isValid).toBe(false);
    });
  });
});

// ============================================
// User JWT Tests
// ============================================

describe('User JWT Generation', () => {
  describe('createUserJwt', () => {
    it('should generate a valid JWT structure', async () => {
      const accountKeyPair = nkeys.createAccount();
      const accountSeed = new TextDecoder().decode(accountKeyPair.getSeed());
      const userKeyPair = nkeys.createUser();
      const userPublicKey = userKeyPair.getPublicKey();
      const expiresAt = new Date(Date.now() + 3600000);

      const jwt = await createUserJwt(
        'test-user',
        userPublicKey,
        accountSeed,
        { pub: { allow: ['test.>'] }, sub: { allow: ['test.>'] } },
        expiresAt
      );

      const decoded = decodeJwt(jwt);
      expect(decoded.header.typ).toBe('JWT');
      expect(decoded.header.alg).toBe('ed25519-nkey');
    });

    it('should include correct user claims', async () => {
      const accountKeyPair = nkeys.createAccount();
      const accountSeed = new TextDecoder().decode(accountKeyPair.getSeed());
      const accountPublicKey = accountKeyPair.getPublicKey();
      const userKeyPair = nkeys.createUser();
      const userPublicKey = userKeyPair.getPublicKey();
      const expiresAt = new Date(Date.now() + 3600000);

      const jwt = await createUserJwt(
        'my-user',
        userPublicKey,
        accountSeed,
        { pub: { allow: ['foo.>'] }, sub: { allow: ['bar.>'] } },
        expiresAt
      );

      const decoded = decodeJwt(jwt);
      expect(decoded.payload.name).toBe('my-user');
      expect(decoded.payload.sub).toBe(userPublicKey);
      expect(decoded.payload.iss).toBe(accountPublicKey);
      expect(decoded.payload.nats.type).toBe('user');
      expect(decoded.payload.nats.version).toBe(2);
    });

    it('should include pub/sub permissions', async () => {
      const accountKeyPair = nkeys.createAccount();
      const accountSeed = new TextDecoder().decode(accountKeyPair.getSeed());
      const userKeyPair = nkeys.createUser();
      const userPublicKey = userKeyPair.getPublicKey();
      const expiresAt = new Date(Date.now() + 3600000);

      const permissions = {
        pub: { allow: ['pub.test.>', 'pub.other'], deny: ['pub.secret'] },
        sub: { allow: ['sub.test.>'], deny: ['sub.internal'] },
      };

      const jwt = await createUserJwt(
        'test-user',
        userPublicKey,
        accountSeed,
        permissions,
        expiresAt
      );

      const decoded = decodeJwt(jwt);
      expect(decoded.payload.nats.pub).toEqual(permissions.pub);
      expect(decoded.payload.nats.sub).toEqual(permissions.sub);
    });

    it('should set correct expiration time', async () => {
      const accountKeyPair = nkeys.createAccount();
      const accountSeed = new TextDecoder().decode(accountKeyPair.getSeed());
      const userKeyPair = nkeys.createUser();
      const userPublicKey = userKeyPair.getPublicKey();
      const expiresAt = new Date(Date.now() + 7200000); // 2 hours from now

      const jwt = await createUserJwt(
        'test-user',
        userPublicKey,
        accountSeed,
        {},
        expiresAt
      );

      const decoded = decodeJwt(jwt);
      const expectedExp = Math.floor(expiresAt.getTime() / 1000);
      expect(decoded.payload.exp).toBe(expectedExp);
    });

    it('should be signed by account', async () => {
      const accountKeyPair = nkeys.createAccount();
      const accountSeed = new TextDecoder().decode(accountKeyPair.getSeed());
      const accountPublicKey = accountKeyPair.getPublicKey();
      const userKeyPair = nkeys.createUser();
      const userPublicKey = userKeyPair.getPublicKey();
      const expiresAt = new Date(Date.now() + 3600000);

      const jwt = await createUserJwt(
        'test-user',
        userPublicKey,
        accountSeed,
        {},
        expiresAt
      );

      const isValid = verifyJwtSignature(jwt, accountPublicKey);
      expect(isValid).toBe(true);
    });
  });
});

// ============================================
// Credential Generation Tests
// ============================================

describe('Credential Generation', () => {
  describe('generateAccountCredentials', () => {
    it('should generate account key pair with valid public key prefix', async () => {
      const creds = await generateAccountCredentials('test-member-guid');

      // Account public keys start with 'A'
      expect(creds.publicKey).toMatch(/^A/);
      expect(creds.publicKey.length).toBeGreaterThan(50);
    });

    it('should generate valid account seed', async () => {
      const creds = await generateAccountCredentials('test-member-guid');

      // Account seeds start with 'SA'
      expect(creds.seed).toMatch(/^SA/);
    });

    it('should generate account JWT', async () => {
      const creds = await generateAccountCredentials('test-member-guid');

      expect(creds.jwt).toBeDefined();
      expect(creds.accountJwt).toBeDefined();
      expect(creds.jwt).toBe(creds.accountJwt);

      const decoded = decodeJwt(creds.jwt);
      expect(decoded.payload.nats.type).toBe('account');
    });

    it('should use memberGuid prefix in account name', async () => {
      const creds = await generateAccountCredentials('abcd1234-5678-90ab-cdef');

      const decoded = decodeJwt(creds.jwt);
      expect(decoded.payload.name).toBe('account-abcd1234');
    });

    it('should generate unique credentials each time', async () => {
      const creds1 = await generateAccountCredentials('test-guid');
      const creds2 = await generateAccountCredentials('test-guid');

      expect(creds1.publicKey).not.toBe(creds2.publicKey);
      expect(creds1.seed).not.toBe(creds2.seed);
    });
  });

  describe('generateUserCredentials', () => {
    let accountSeed: string;

    beforeEach(() => {
      const accountKeyPair = nkeys.createAccount();
      accountSeed = new TextDecoder().decode(accountKeyPair.getSeed());
    });

    it('should generate user key pair with valid public key prefix', async () => {
      const expiresAt = new Date(Date.now() + 3600000);
      const creds = await generateUserCredentials(
        'test-user-guid',
        accountSeed,
        'app',
        'OwnerSpace.guid',
        'MessageSpace.guid',
        expiresAt
      );

      // User public keys start with 'U'
      expect(creds.publicKey).toMatch(/^U/);
    });

    it('should generate valid user seed', async () => {
      const expiresAt = new Date(Date.now() + 3600000);
      const creds = await generateUserCredentials(
        'test-user-guid',
        accountSeed,
        'app',
        'OwnerSpace.guid',
        'MessageSpace.guid',
        expiresAt
      );

      // User seeds start with 'SU'
      expect(creds.seed).toMatch(/^SU/);
    });

    it('should generate app permissions correctly', async () => {
      const expiresAt = new Date(Date.now() + 3600000);
      const ownerSpace = 'OwnerSpace.test-guid';
      const creds = await generateUserCredentials(
        'test-user-guid',
        accountSeed,
        'app',
        ownerSpace,
        'MessageSpace.test-guid',
        expiresAt
      );

      const decoded = decodeJwt(creds.jwt);
      expect(decoded.payload.nats.pub.allow).toContain(`${ownerSpace}.forVault.>`);
      expect(decoded.payload.nats.sub.allow).toContain(`${ownerSpace}.forApp.>`);
      expect(decoded.payload.nats.sub.allow).toContain(`${ownerSpace}.eventTypes`);
    });

    it('should generate vault permissions correctly', async () => {
      const expiresAt = new Date(Date.now() + 3600000);
      const ownerSpace = 'OwnerSpace.test-guid';
      const messageSpace = 'MessageSpace.test-guid';
      const creds = await generateUserCredentials(
        'test-user-guid',
        accountSeed,
        'vault',
        ownerSpace,
        messageSpace,
        expiresAt
      );

      const decoded = decodeJwt(creds.jwt);

      // Vault can publish to forApp and forOwner
      expect(decoded.payload.nats.pub.allow).toContain(`${ownerSpace}.forApp.>`);
      expect(decoded.payload.nats.pub.allow).toContain(`${messageSpace}.forOwner.>`);
      expect(decoded.payload.nats.pub.allow).toContain(`${messageSpace}.ownerProfile`);

      // Vault can subscribe to forVault, control, and forOwner
      expect(decoded.payload.nats.sub.allow).toContain(`${ownerSpace}.forVault.>`);
      expect(decoded.payload.nats.sub.allow).toContain(`${ownerSpace}.control`);
      expect(decoded.payload.nats.sub.allow).toContain(`${messageSpace}.forOwner.>`);
    });

    it('should generate control permissions correctly', async () => {
      const expiresAt = new Date(Date.now() + 3600000);
      const ownerSpace = 'OwnerSpace.test-guid';
      const creds = await generateUserCredentials(
        'test-user-guid',
        accountSeed,
        'control',
        ownerSpace,
        'MessageSpace.test-guid',
        expiresAt
      );

      const decoded = decodeJwt(creds.jwt);

      // Control can only publish to control topic
      expect(decoded.payload.nats.pub.allow).toContain(`${ownerSpace}.control`);
      expect(decoded.payload.nats.pub.allow.length).toBe(1);

      // Control has no subscriptions
      expect(decoded.payload.nats.sub.allow.length).toBe(0);
    });

    it('should use clientType prefix in user name', async () => {
      const expiresAt = new Date(Date.now() + 3600000);
      const creds = await generateUserCredentials(
        'abcd1234-5678-90ab-cdef',
        accountSeed,
        'app',
        'OwnerSpace.guid',
        'MessageSpace.guid',
        expiresAt
      );

      const decoded = decodeJwt(creds.jwt);
      expect(decoded.payload.name).toBe('app-abcd1234');
    });

    it('should set correct expiration', async () => {
      const expiresAt = new Date(Date.now() + 7200000);
      const creds = await generateUserCredentials(
        'test-user-guid',
        accountSeed,
        'app',
        'OwnerSpace.guid',
        'MessageSpace.guid',
        expiresAt
      );

      const decoded = decodeJwt(creds.jwt);
      const expectedExp = Math.floor(expiresAt.getTime() / 1000);
      expect(decoded.payload.exp).toBe(expectedExp);
    });
  });
});

// ============================================
// Credential File Formatting Tests
// ============================================

describe('Credential File Formatting', () => {
  describe('formatCredsFile', () => {
    it('should format credentials in NATS creds file format', () => {
      const jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiJ0ZXN0In0.c2lnbmF0dXJl';
      const seed = 'SUAIBDPBAUTNL7KB6P3WFHKUZMYB6F6SJTQCQ4LCZJ6CQZBTVOGZH7XFGI';

      const credsFile = formatCredsFile(jwt, seed);

      // Standard NATS creds format uses 5 dashes for both BEGIN and END
      expect(credsFile).toContain('-----BEGIN NATS USER JWT-----');
      expect(credsFile).toContain(jwt);
      expect(credsFile).toContain('-----END NATS USER JWT-----');
      expect(credsFile).toContain('-----BEGIN USER NKEY SEED-----');
      expect(credsFile).toContain(seed);
      expect(credsFile).toContain('-----END USER NKEY SEED-----');
    });

    it('should include security warning', () => {
      const credsFile = formatCredsFile('jwt', 'seed');

      expect(credsFile).toContain('IMPORTANT');
      expect(credsFile).toContain('NKEY Seed');
      expect(credsFile).toContain('sensitive');
      expect(credsFile).toContain('secrets');
    });

    it('should be parseable by NATS clients', () => {
      const jwt = 'test.jwt.token';
      const seed = 'SUAIBDPBAUTNL7KB6P3WFHKUZMYB6F6SJTQCQ4LCZJ6CQZBTVOGZH7XFGI';

      const credsFile = formatCredsFile(jwt, seed);

      // Extract JWT using regex similar to NATS client libraries (5 dashes)
      const jwtMatch = credsFile.match(
        /-----BEGIN NATS USER JWT-----\n([^\n]+)\n-----END NATS USER JWT-----/
      );
      expect(jwtMatch).not.toBeNull();
      expect(jwtMatch![1]).toBe(jwt);

      // Extract seed using regex similar to NATS client libraries (5 dashes)
      const seedMatch = credsFile.match(
        /-----BEGIN USER NKEY SEED-----\n([^\n]+)\n-----END USER NKEY SEED-----/
      );
      expect(seedMatch).not.toBeNull();
      expect(seedMatch![1]).toBe(seed);
    });
  });
});

// ============================================
// Operator Key Retrieval Tests
// ============================================

describe('Operator Key Retrieval', () => {
  describe('getOperatorPublicKey', () => {
    it('should return the operator public key', async () => {
      const publicKey = await getOperatorPublicKey();
      expect(publicKey).toBe(testOperatorPublicKey);
    });

    // Note: Caching tests are difficult with Jest mocks and module-level state
    // The caching functionality is tested implicitly through performance
    it('should work correctly with cached keys on subsequent calls', async () => {
      const publicKey1 = await getOperatorPublicKey();
      const publicKey2 = await getOperatorPublicKey();
      const publicKey3 = await getOperatorPublicKey();

      // All calls should return the same key
      expect(publicKey1).toBe(publicKey2);
      expect(publicKey2).toBe(publicKey3);
    });
  });

  describe('getSystemAccountPublicKey', () => {
    it('should return the system account public key', async () => {
      const publicKey = await getSystemAccountPublicKey();
      expect(publicKey).toBe(testSystemAccountPublicKey);
    });
  });

  // Note: Error handling tests require module isolation which is complex with
  // module-level caching. These scenarios should be tested in integration tests
  // where we can control the actual secret values.
});

// ============================================
// NKey Type Validation Tests
// ============================================

describe('NKey Type Validation', () => {
  it('should create operator keys with O prefix', () => {
    const keyPair = nkeys.createOperator();
    expect(keyPair.getPublicKey()).toMatch(/^O/);
  });

  it('should create account keys with A prefix', () => {
    const keyPair = nkeys.createAccount();
    expect(keyPair.getPublicKey()).toMatch(/^A/);
  });

  it('should create user keys with U prefix', () => {
    const keyPair = nkeys.createUser();
    expect(keyPair.getPublicKey()).toMatch(/^U/);
  });

  it('should create seeds with correct prefixes', () => {
    const operator = nkeys.createOperator();
    const account = nkeys.createAccount();
    const user = nkeys.createUser();

    expect(new TextDecoder().decode(operator.getSeed())).toMatch(/^SO/);
    expect(new TextDecoder().decode(account.getSeed())).toMatch(/^SA/);
    expect(new TextDecoder().decode(user.getSeed())).toMatch(/^SU/);
  });
});

// ============================================
// Security Tests
// ============================================

describe('Security Properties', () => {
  it('should generate cryptographically unique account keys', async () => {
    const accounts = await Promise.all(
      Array.from({ length: 20 }, () => generateAccountCredentials('test-guid'))
    );

    const publicKeys = new Set(accounts.map(a => a.publicKey));
    const seeds = new Set(accounts.map(a => a.seed));

    expect(publicKeys.size).toBe(20);
    expect(seeds.size).toBe(20);
  });

  it('should generate cryptographically unique user keys', async () => {
    const accountKeyPair = nkeys.createAccount();
    const accountSeed = new TextDecoder().decode(accountKeyPair.getSeed());
    const expiresAt = new Date(Date.now() + 3600000);

    const users = await Promise.all(
      Array.from({ length: 20 }, () =>
        generateUserCredentials(
          'test-guid',
          accountSeed,
          'app',
          'OwnerSpace.guid',
          'MessageSpace.guid',
          expiresAt
        )
      )
    );

    const publicKeys = new Set(users.map(u => u.publicKey));
    const seeds = new Set(users.map(u => u.seed));

    expect(publicKeys.size).toBe(20);
    expect(seeds.size).toBe(20);
  });

  it('should not expose operator seed in JWT', async () => {
    const creds = await generateAccountCredentials('test-guid');

    // JWT should not contain the operator seed
    expect(creds.jwt).not.toContain(testOperatorSeed);

    // Decoded JWT should not have seed anywhere
    const decoded = decodeJwt(creds.jwt);
    const payloadStr = JSON.stringify(decoded.payload);
    expect(payloadStr).not.toContain(testOperatorSeed);
  });

  it('should not expose account seed in user JWT', async () => {
    const accountKeyPair = nkeys.createAccount();
    const accountSeed = new TextDecoder().decode(accountKeyPair.getSeed());
    const expiresAt = new Date(Date.now() + 3600000);

    const creds = await generateUserCredentials(
      'test-guid',
      accountSeed,
      'app',
      'OwnerSpace.guid',
      'MessageSpace.guid',
      expiresAt
    );

    // JWT should not contain the account seed
    expect(creds.jwt).not.toContain(accountSeed);
  });
});
