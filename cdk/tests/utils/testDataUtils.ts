/**
 * Test Data Utilities
 *
 * Phase 10: Production Readiness & Polish
 *
 * Utilities for generating, managing, and cleaning up test data.
 * Ensures test isolation and prevents hardcoded secrets.
 */

import * as crypto from 'crypto';

// ============================================================================
// Test Data Generation
// ============================================================================

/**
 * Generates a unique test email address
 */
export function generateTestEmail(prefix: string = 'test'): string {
  const timestamp = Date.now();
  const random = crypto.randomBytes(4).toString('hex');
  return `${prefix}-${timestamp}-${random}@test.vettid.dev`;
}

/**
 * Generates a unique test user ID
 */
export function generateTestUserId(): string {
  return `test-user-${crypto.randomUUID()}`;
}

/**
 * Generates a unique test device ID
 */
export function generateTestDeviceId(): string {
  return `test-device-${crypto.randomUUID()}`;
}

/**
 * Generates a unique test vault ID
 */
export function generateTestVaultId(): string {
  return `test-vault-${crypto.randomUUID()}`;
}

/**
 * Generates a unique test connection ID
 */
export function generateTestConnectionId(): string {
  return `test-conn-${crypto.randomUUID()}`;
}

/**
 * Generates a unique test invite code
 */
export function generateTestInviteCode(): string {
  return `TEST-${crypto.randomBytes(6).toString('hex').toUpperCase()}`;
}

/**
 * Generates test encryption key (32 bytes for AES-256)
 */
export function generateTestEncryptionKey(): Buffer {
  return crypto.randomBytes(32);
}

/**
 * Generates test nonce/IV (12 bytes for AES-GCM, 24 for XChaCha20)
 */
export function generateTestNonce(size: 12 | 24 = 12): Buffer {
  return crypto.randomBytes(size);
}

/**
 * Generates a test JWT-like token (NOT for production use)
 */
export function generateTestToken(): string {
  const header = Buffer.from(JSON.stringify({ alg: 'TEST', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({
    sub: generateTestUserId(),
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
    test: true,
  })).toString('base64url');
  const signature = crypto.randomBytes(32).toString('base64url');
  return `${header}.${payload}.${signature}`;
}

// ============================================================================
// Test Data Cleanup
// ============================================================================

interface CleanupCallback {
  id: string;
  cleanup: () => Promise<void> | void;
}

class TestDataRegistry {
  private cleanupCallbacks: CleanupCallback[] = [];

  /**
   * Register a cleanup callback for test data
   */
  register(id: string, cleanup: () => Promise<void> | void): void {
    this.cleanupCallbacks.push({ id, cleanup });
  }

  /**
   * Run all cleanup callbacks
   */
  async cleanupAll(): Promise<{ successful: string[]; failed: string[] }> {
    const successful: string[] = [];
    const failed: string[] = [];

    for (const { id, cleanup } of this.cleanupCallbacks) {
      try {
        await cleanup();
        successful.push(id);
      } catch (error) {
        console.error(`Cleanup failed for ${id}:`, error);
        failed.push(id);
      }
    }

    this.cleanupCallbacks = [];
    return { successful, failed };
  }

  /**
   * Clear the registry without running cleanup
   */
  clear(): void {
    this.cleanupCallbacks = [];
  }

  /**
   * Get count of pending cleanups
   */
  get pendingCount(): number {
    return this.cleanupCallbacks.length;
  }
}

export const testDataRegistry = new TestDataRegistry();

// ============================================================================
// Mock Data Factories
// ============================================================================

export interface TestUser {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  status: 'pending' | 'approved' | 'rejected';
  createdAt: Date;
}

export interface TestDevice {
  id: string;
  userId: string;
  publicKey: string;
  attestationType: 'android' | 'ios';
  createdAt: Date;
}

export interface TestVault {
  id: string;
  userId: string;
  status: 'provisioning' | 'active' | 'suspended' | 'terminated';
  natsAccount: string;
  createdAt: Date;
}

export interface TestConnection {
  id: string;
  userId: string;
  connectedUserId: string;
  status: 'pending' | 'active' | 'revoked';
  createdAt: Date;
}

export interface TestMessage {
  id: string;
  connectionId: string;
  senderId: string;
  recipientId: string;
  content: string;
  timestamp: Date;
}

export interface TestBackup {
  id: string;
  userId: string;
  type: 'manual' | 'auto';
  size: number;
  createdAt: Date;
}

/**
 * Creates a test user with default values
 */
export function createTestUser(overrides: Partial<TestUser> = {}): TestUser {
  return {
    id: generateTestUserId(),
    email: generateTestEmail(),
    firstName: 'Test',
    lastName: 'User',
    status: 'pending',
    createdAt: new Date(),
    ...overrides,
  };
}

/**
 * Creates a test device with default values
 */
export function createTestDevice(overrides: Partial<TestDevice> = {}): TestDevice {
  return {
    id: generateTestDeviceId(),
    userId: generateTestUserId(),
    publicKey: crypto.randomBytes(32).toString('base64'),
    attestationType: 'android',
    createdAt: new Date(),
    ...overrides,
  };
}

/**
 * Creates a test vault with default values
 */
export function createTestVault(overrides: Partial<TestVault> = {}): TestVault {
  return {
    id: generateTestVaultId(),
    userId: generateTestUserId(),
    status: 'active',
    natsAccount: `test-nats-${crypto.randomBytes(4).toString('hex')}`,
    createdAt: new Date(),
    ...overrides,
  };
}

/**
 * Creates a test connection with default values
 */
export function createTestConnection(overrides: Partial<TestConnection> = {}): TestConnection {
  return {
    id: generateTestConnectionId(),
    userId: generateTestUserId(),
    connectedUserId: generateTestUserId(),
    status: 'active',
    createdAt: new Date(),
    ...overrides,
  };
}

/**
 * Creates a test message with default values
 */
export function createTestMessage(overrides: Partial<TestMessage> = {}): TestMessage {
  const connectionId = overrides.connectionId || generateTestConnectionId();
  const senderId = overrides.senderId || generateTestUserId();
  const recipientId = overrides.recipientId || generateTestUserId();

  return {
    id: `test-msg-${crypto.randomUUID()}`,
    connectionId,
    senderId,
    recipientId,
    content: 'Test message content',
    timestamp: new Date(),
    ...overrides,
  };
}

/**
 * Creates a test backup with default values
 */
export function createTestBackup(overrides: Partial<TestBackup> = {}): TestBackup {
  return {
    id: `test-backup-${crypto.randomUUID()}`,
    userId: generateTestUserId(),
    type: 'manual',
    size: 1024,
    createdAt: new Date(),
    ...overrides,
  };
}

// ============================================================================
// Test Data Validation
// ============================================================================

/**
 * Validates that a string doesn't contain production data patterns
 */
export function validateNoProductionData(value: string): boolean {
  const productionPatterns = [
    /^[A-Z0-9]{20}$/, // AWS Access Key ID pattern
    /^[A-Za-z0-9/+=]{40}$/, // AWS Secret Key pattern
    /arn:aws:[a-z]+:[a-z0-9-]*:\d{12}:/, // Real AWS ARN
    /@(?!test\.vettid\.dev).*\.com$/, // Non-test email domain
    /^sk_live_/, // Stripe live key
    /^pk_live_/, // Stripe live key
  ];

  for (const pattern of productionPatterns) {
    if (pattern.test(value)) {
      return false;
    }
  }

  return true;
}

/**
 * Validates that an object only contains test data
 */
export function validateTestDataOnly(obj: Record<string, unknown>): { valid: boolean; issues: string[] } {
  const issues: string[] = [];

  const checkValue = (value: unknown, path: string): void => {
    if (typeof value === 'string') {
      if (!validateNoProductionData(value)) {
        issues.push(`Potential production data at ${path}`);
      }
      if (value.includes('password') && !value.includes('test')) {
        issues.push(`Possible real password at ${path}`);
      }
    } else if (typeof value === 'object' && value !== null) {
      for (const [key, val] of Object.entries(value)) {
        checkValue(val, `${path}.${key}`);
      }
    }
  };

  checkValue(obj, 'root');

  return {
    valid: issues.length === 0,
    issues,
  };
}

// ============================================================================
// Test Isolation Utilities
// ============================================================================

/**
 * Creates an isolated test context with unique identifiers
 */
export function createTestContext(testName: string): {
  testId: string;
  prefix: string;
  generateId: (type: string) => string;
  cleanup: () => void;
} {
  const testId = `${testName}-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
  const prefix = `test-${testId}`;
  const generatedIds: string[] = [];

  return {
    testId,
    prefix,
    generateId: (type: string) => {
      const id = `${prefix}-${type}-${crypto.randomUUID()}`;
      generatedIds.push(id);
      return id;
    },
    cleanup: () => {
      generatedIds.length = 0;
    },
  };
}

/**
 * Creates a scoped test data set that can be easily cleaned up
 */
export function createScopedTestData(): {
  users: TestUser[];
  devices: TestDevice[];
  vaults: TestVault[];
  connections: TestConnection[];
  add: <T>(type: 'users' | 'devices' | 'vaults' | 'connections', item: T) => T;
  clear: () => void;
} {
  const data = {
    users: [] as TestUser[],
    devices: [] as TestDevice[],
    vaults: [] as TestVault[],
    connections: [] as TestConnection[],
  };

  return {
    ...data,
    add: <T>(type: 'users' | 'devices' | 'vaults' | 'connections', item: T): T => {
      (data[type] as unknown[]).push(item);
      return item;
    },
    clear: () => {
      data.users = [];
      data.devices = [];
      data.vaults = [];
      data.connections = [];
    },
  };
}

// ============================================================================
// Test Data Reset
// ============================================================================

/**
 * Resets test data stores (for use between tests)
 */
export function resetTestData(): void {
  testDataRegistry.clear();
}

/**
 * Creates a disposable test data manager for a single test
 */
export function createDisposableTestData(): {
  create: <T>(factory: () => T) => T;
  dispose: () => void;
} {
  const items: unknown[] = [];

  return {
    create: <T>(factory: () => T): T => {
      const item = factory();
      items.push(item);
      return item;
    },
    dispose: () => {
      items.length = 0;
    },
  };
}

// ============================================================================
// Export all utilities
// ============================================================================

export default {
  // Generation
  generateTestEmail,
  generateTestUserId,
  generateTestDeviceId,
  generateTestVaultId,
  generateTestConnectionId,
  generateTestInviteCode,
  generateTestEncryptionKey,
  generateTestNonce,
  generateTestToken,

  // Cleanup
  testDataRegistry,
  resetTestData,

  // Factories
  createTestUser,
  createTestDevice,
  createTestVault,
  createTestConnection,
  createTestMessage,
  createTestBackup,

  // Validation
  validateNoProductionData,
  validateTestDataOnly,

  // Isolation
  createTestContext,
  createScopedTestData,
  createDisposableTestData,
};
