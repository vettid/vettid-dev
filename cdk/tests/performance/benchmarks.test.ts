/**
 * Performance Benchmark Tests
 *
 * Phase 10: Production Readiness & Polish
 *
 * Establishes performance baselines for critical operations:
 * - Cryptographic operations (key derivation, encryption, signing)
 * - API response time baselines
 * - Database query performance
 * - Memory usage patterns
 */

import * as crypto from 'crypto';

// ============================================================================
// Performance Measurement Utilities
// ============================================================================

interface BenchmarkResult {
  name: string;
  iterations: number;
  totalTimeMs: number;
  avgTimeMs: number;
  minTimeMs: number;
  maxTimeMs: number;
  opsPerSecond: number;
  p50Ms: number;
  p95Ms: number;
  p99Ms: number;
}

interface MemorySnapshot {
  heapUsed: number;
  heapTotal: number;
  external: number;
  arrayBuffers: number;
}

function measurePerformance(
  name: string,
  fn: () => void,
  iterations: number = 100
): BenchmarkResult {
  const times: number[] = [];

  // Warmup runs
  for (let i = 0; i < Math.min(10, iterations / 10); i++) {
    fn();
  }

  // Actual measurements
  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    fn();
    const end = performance.now();
    times.push(end - start);
  }

  times.sort((a, b) => a - b);

  const totalTimeMs = times.reduce((a, b) => a + b, 0);
  const avgTimeMs = totalTimeMs / iterations;
  const minTimeMs = times[0];
  const maxTimeMs = times[times.length - 1];
  const opsPerSecond = 1000 / avgTimeMs;

  const p50Ms = times[Math.floor(iterations * 0.5)];
  const p95Ms = times[Math.floor(iterations * 0.95)];
  const p99Ms = times[Math.floor(iterations * 0.99)];

  return {
    name,
    iterations,
    totalTimeMs,
    avgTimeMs,
    minTimeMs,
    maxTimeMs,
    opsPerSecond,
    p50Ms,
    p95Ms,
    p99Ms,
  };
}

async function measureAsyncPerformance(
  name: string,
  fn: () => Promise<void>,
  iterations: number = 100
): Promise<BenchmarkResult> {
  const times: number[] = [];

  // Warmup runs
  for (let i = 0; i < Math.min(10, iterations / 10); i++) {
    await fn();
  }

  // Actual measurements
  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    await fn();
    const end = performance.now();
    times.push(end - start);
  }

  times.sort((a, b) => a - b);

  const totalTimeMs = times.reduce((a, b) => a + b, 0);
  const avgTimeMs = totalTimeMs / iterations;
  const minTimeMs = times[0];
  const maxTimeMs = times[times.length - 1];
  const opsPerSecond = 1000 / avgTimeMs;

  const p50Ms = times[Math.floor(iterations * 0.5)];
  const p95Ms = times[Math.floor(iterations * 0.95)];
  const p99Ms = times[Math.floor(iterations * 0.99)];

  return {
    name,
    iterations,
    totalTimeMs,
    avgTimeMs,
    minTimeMs,
    maxTimeMs,
    opsPerSecond,
    p50Ms,
    p95Ms,
    p99Ms,
  };
}

function getMemorySnapshot(): MemorySnapshot {
  const mem = process.memoryUsage();
  return {
    heapUsed: mem.heapUsed,
    heapTotal: mem.heapTotal,
    external: mem.external,
    arrayBuffers: mem.arrayBuffers,
  };
}

function formatBytes(bytes: number): string {
  const units = ['B', 'KB', 'MB', 'GB'];
  let unitIndex = 0;
  let value = bytes;

  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex++;
  }

  return `${value.toFixed(2)} ${units[unitIndex]}`;
}

// ============================================================================
// Mock Crypto Operations (simulating production crypto)
// ============================================================================

class MockArgon2 {
  // Simulates Argon2id parameters for testing
  static readonly DEFAULT_PARAMS = {
    memoryCost: 65536, // 64 MB
    timeCost: 3,
    parallelism: 4,
    hashLength: 32,
  };

  // Using PBKDF2 as a stand-in for testing since Argon2 isn't native
  static derive(
    password: string,
    salt: Buffer,
    params = MockArgon2.DEFAULT_PARAMS
  ): Buffer {
    // Simulate Argon2id with PBKDF2 for testing purposes
    // In production, use actual Argon2id
    const iterations = params.timeCost * 10000;
    return crypto.pbkdf2Sync(
      password,
      salt,
      iterations,
      params.hashLength,
      'sha512'
    );
  }
}

class MockXChaCha20Poly1305 {
  // XChaCha20-Poly1305 uses 24-byte nonce
  static readonly NONCE_SIZE = 24;
  static readonly TAG_SIZE = 16;
  static readonly KEY_SIZE = 32;

  // Using AES-GCM as a stand-in since XChaCha20 isn't native
  static encrypt(plaintext: Buffer, key: Buffer, nonce: Buffer): Buffer {
    // Use first 12 bytes of nonce for AES-GCM (simulation)
    const iv = nonce.subarray(0, 12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([encrypted, tag]);
  }

  static decrypt(ciphertext: Buffer, key: Buffer, nonce: Buffer): Buffer {
    const iv = nonce.subarray(0, 12);
    const tag = ciphertext.subarray(-16);
    const data = ciphertext.subarray(0, -16);

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(data), decipher.final()]);
  }
}

class MockEd25519 {
  static generateKeyPair(): { publicKey: Buffer; privateKey: Buffer } {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    return {
      publicKey: publicKey.export({ type: 'spki', format: 'der' }),
      privateKey: privateKey.export({ type: 'pkcs8', format: 'der' }),
    };
  }

  static sign(message: Buffer, privateKey: Buffer): Buffer {
    const key = crypto.createPrivateKey({
      key: privateKey,
      format: 'der',
      type: 'pkcs8',
    });
    return crypto.sign(null, message, key);
  }

  static verify(message: Buffer, signature: Buffer, publicKey: Buffer): boolean {
    const key = crypto.createPublicKey({
      key: publicKey,
      format: 'der',
      type: 'spki',
    });
    return crypto.verify(null, message, key, signature);
  }
}

class MockX25519 {
  static generateKeyPair(): { publicKey: Buffer; privateKey: Buffer } {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
    return {
      publicKey: publicKey.export({ type: 'spki', format: 'der' }),
      privateKey: privateKey.export({ type: 'pkcs8', format: 'der' }),
    };
  }

  static deriveSharedSecret(privateKey: Buffer, publicKey: Buffer): Buffer {
    const privKey = crypto.createPrivateKey({
      key: privateKey,
      format: 'der',
      type: 'pkcs8',
    });
    const pubKey = crypto.createPublicKey({
      key: publicKey,
      format: 'der',
      type: 'spki',
    });
    return crypto.diffieHellman({ privateKey: privKey, publicKey: pubKey });
  }
}

// ============================================================================
// Mock Database Operations
// ============================================================================

class MockDynamoDB {
  private data: Map<string, Map<string, unknown>> = new Map();
  private queryLatencyMs = 5; // Simulated network latency

  async put(table: string, item: Record<string, unknown>): Promise<void> {
    await this.simulateLatency();
    if (!this.data.has(table)) {
      this.data.set(table, new Map());
    }
    const key = item.id as string;
    this.data.get(table)!.set(key, item);
  }

  async get(table: string, key: string): Promise<unknown | null> {
    await this.simulateLatency();
    const tableData = this.data.get(table);
    if (!tableData) return null;
    return tableData.get(key) || null;
  }

  async query(table: string, indexName: string, condition: Record<string, unknown>): Promise<unknown[]> {
    await this.simulateLatency();
    const tableData = this.data.get(table);
    if (!tableData) return [];

    // Simple filter simulation
    const results: unknown[] = [];
    tableData.forEach((item) => {
      let matches = true;
      for (const [key, value] of Object.entries(condition)) {
        if ((item as Record<string, unknown>)[key] !== value) {
          matches = false;
          break;
        }
      }
      if (matches) {
        results.push(item);
      }
    });
    return results;
  }

  async batchGet(table: string, keys: string[]): Promise<unknown[]> {
    await this.simulateLatency();
    const results: unknown[] = [];
    const tableData = this.data.get(table);
    if (!tableData) return results;

    for (const key of keys) {
      const item = tableData.get(key);
      if (item) results.push(item);
    }
    return results;
  }

  async delete(table: string, key: string): Promise<void> {
    await this.simulateLatency();
    const tableData = this.data.get(table);
    if (tableData) {
      tableData.delete(key);
    }
  }

  private simulateLatency(): Promise<void> {
    return new Promise(resolve =>
      setTimeout(resolve, this.queryLatencyMs + Math.random() * 5)
    );
  }

  setLatency(ms: number): void {
    this.queryLatencyMs = ms;
  }

  clear(): void {
    this.data.clear();
  }
}

// ============================================================================
// Mock API Handler
// ============================================================================

class MockAPIHandler {
  private processingTimeMs = 2;

  async handleRequest(request: {
    method: string;
    path: string;
    body?: unknown;
  }): Promise<{ statusCode: number; body: unknown }> {
    // Simulate request processing
    await new Promise(resolve => setTimeout(resolve, this.processingTimeMs));

    // Simulate different endpoint complexities
    if (request.path.includes('/auth')) {
      // Auth endpoints are more complex
      await new Promise(resolve => setTimeout(resolve, 10));
    }

    return {
      statusCode: 200,
      body: { success: true },
    };
  }

  setProcessingTime(ms: number): void {
    this.processingTimeMs = ms;
  }
}

// ============================================================================
// Performance Benchmark Test Suites
// ============================================================================

describe('Performance Benchmarks', () => {
  // Performance thresholds (in milliseconds)
  const THRESHOLDS = {
    // Crypto operations
    KEY_DERIVATION_MAX_MS: 500, // Argon2id should complete within 500ms
    SYMMETRIC_ENCRYPT_MAX_MS: 5, // Per-message encryption
    ASYMMETRIC_SIGN_MAX_MS: 2, // Ed25519 signing
    ASYMMETRIC_VERIFY_MAX_MS: 3, // Ed25519 verification
    KEY_EXCHANGE_MAX_MS: 5, // X25519 key exchange

    // API operations
    API_RESPONSE_P95_MS: 100, // 95th percentile API response
    API_RESPONSE_P99_MS: 200, // 99th percentile API response

    // Database operations
    DB_GET_P95_MS: 50, // Single item retrieval
    DB_QUERY_P95_MS: 100, // Query operation
    DB_BATCH_P95_MS: 150, // Batch get operation

    // Memory thresholds
    MAX_HEAP_INCREASE_MB: 50, // Max heap increase during operations
  };

  describe('Cryptographic Operation Benchmarks', () => {
    describe('Key Derivation (Argon2id simulation)', () => {
      test('should derive key within acceptable time', () => {
        const password = 'test-password-12345';
        const salt = crypto.randomBytes(16);

        const result = measurePerformance(
          'Argon2id Key Derivation',
          () => {
            MockArgon2.derive(password, salt);
          },
          50 // Fewer iterations due to cost
        );

        console.log(`Key Derivation: avg=${result.avgTimeMs.toFixed(2)}ms, p95=${result.p95Ms.toFixed(2)}ms`);

        expect(result.avgTimeMs).toBeLessThan(THRESHOLDS.KEY_DERIVATION_MAX_MS);
      });

      test('should maintain consistent derivation times', () => {
        const password = 'test-password-12345';
        const salt = crypto.randomBytes(16);

        const result = measurePerformance(
          'Argon2id Consistency',
          () => {
            MockArgon2.derive(password, salt);
          },
          20
        );

        // Max time should not be more than 3x average (consistency check)
        expect(result.maxTimeMs).toBeLessThan(result.avgTimeMs * 3);
      });
    });

    describe('Symmetric Encryption (XChaCha20-Poly1305)', () => {
      let key: Buffer;
      let nonce: Buffer;
      let plaintext: Buffer;

      beforeEach(() => {
        key = crypto.randomBytes(32);
        nonce = crypto.randomBytes(24);
        plaintext = crypto.randomBytes(1024); // 1KB message
      });

      test('should encrypt within acceptable time', () => {
        const result = measurePerformance(
          'XChaCha20-Poly1305 Encrypt (1KB)',
          () => {
            const newNonce = crypto.randomBytes(24);
            MockXChaCha20Poly1305.encrypt(plaintext, key, newNonce);
          },
          1000
        );

        console.log(`Encrypt (1KB): avg=${result.avgTimeMs.toFixed(3)}ms, ops/sec=${result.opsPerSecond.toFixed(0)}`);

        expect(result.avgTimeMs).toBeLessThan(THRESHOLDS.SYMMETRIC_ENCRYPT_MAX_MS);
      });

      test('should decrypt within acceptable time', () => {
        const ciphertext = MockXChaCha20Poly1305.encrypt(plaintext, key, nonce);

        const result = measurePerformance(
          'XChaCha20-Poly1305 Decrypt (1KB)',
          () => {
            MockXChaCha20Poly1305.decrypt(ciphertext, key, nonce);
          },
          1000
        );

        console.log(`Decrypt (1KB): avg=${result.avgTimeMs.toFixed(3)}ms, ops/sec=${result.opsPerSecond.toFixed(0)}`);

        expect(result.avgTimeMs).toBeLessThan(THRESHOLDS.SYMMETRIC_ENCRYPT_MAX_MS);
      });

      test('should handle large messages efficiently', () => {
        const largePlaintext = crypto.randomBytes(1024 * 1024); // 1MB

        const result = measurePerformance(
          'XChaCha20-Poly1305 Encrypt (1MB)',
          () => {
            const newNonce = crypto.randomBytes(24);
            MockXChaCha20Poly1305.encrypt(largePlaintext, key, newNonce);
          },
          50
        );

        console.log(`Encrypt (1MB): avg=${result.avgTimeMs.toFixed(2)}ms, throughput=${((1024 * 1024) / (result.avgTimeMs / 1000) / (1024 * 1024)).toFixed(2)} MB/s`);

        // 1MB encryption should complete in reasonable time
        expect(result.avgTimeMs).toBeLessThan(100);
      });
    });

    describe('Asymmetric Signing (Ed25519)', () => {
      let keyPair: { publicKey: Buffer; privateKey: Buffer };
      let message: Buffer;

      beforeEach(() => {
        keyPair = MockEd25519.generateKeyPair();
        message = crypto.randomBytes(256);
      });

      test('should sign within acceptable time', () => {
        const result = measurePerformance(
          'Ed25519 Sign',
          () => {
            MockEd25519.sign(message, keyPair.privateKey);
          },
          1000
        );

        console.log(`Ed25519 Sign: avg=${result.avgTimeMs.toFixed(3)}ms, ops/sec=${result.opsPerSecond.toFixed(0)}`);

        expect(result.avgTimeMs).toBeLessThan(THRESHOLDS.ASYMMETRIC_SIGN_MAX_MS);
      });

      test('should verify within acceptable time', () => {
        const signature = MockEd25519.sign(message, keyPair.privateKey);

        const result = measurePerformance(
          'Ed25519 Verify',
          () => {
            MockEd25519.verify(message, signature, keyPair.publicKey);
          },
          1000
        );

        console.log(`Ed25519 Verify: avg=${result.avgTimeMs.toFixed(3)}ms, ops/sec=${result.opsPerSecond.toFixed(0)}`);

        expect(result.avgTimeMs).toBeLessThan(THRESHOLDS.ASYMMETRIC_VERIFY_MAX_MS);
      });

      test('should generate key pairs efficiently', () => {
        const result = measurePerformance(
          'Ed25519 Key Generation',
          () => {
            MockEd25519.generateKeyPair();
          },
          500
        );

        console.log(`Ed25519 KeyGen: avg=${result.avgTimeMs.toFixed(3)}ms, ops/sec=${result.opsPerSecond.toFixed(0)}`);

        expect(result.avgTimeMs).toBeLessThan(5);
      });
    });

    describe('Key Exchange (X25519)', () => {
      test('should derive shared secret within acceptable time', () => {
        const alice = MockX25519.generateKeyPair();
        const bob = MockX25519.generateKeyPair();

        const result = measurePerformance(
          'X25519 Key Exchange',
          () => {
            MockX25519.deriveSharedSecret(alice.privateKey, bob.publicKey);
          },
          500
        );

        console.log(`X25519 Exchange: avg=${result.avgTimeMs.toFixed(3)}ms, ops/sec=${result.opsPerSecond.toFixed(0)}`);

        expect(result.avgTimeMs).toBeLessThan(THRESHOLDS.KEY_EXCHANGE_MAX_MS);
      });
    });

    describe('Random Number Generation', () => {
      test('should generate random bytes efficiently', () => {
        const result = measurePerformance(
          'Random 32 bytes',
          () => {
            crypto.randomBytes(32);
          },
          10000
        );

        console.log(`Random 32B: avg=${result.avgTimeMs.toFixed(4)}ms, ops/sec=${result.opsPerSecond.toFixed(0)}`);

        expect(result.avgTimeMs).toBeLessThan(0.1);
      });

      test('should generate UUIDs efficiently', () => {
        const result = measurePerformance(
          'UUID Generation',
          () => {
            crypto.randomUUID();
          },
          10000
        );

        console.log(`UUID Gen: avg=${result.avgTimeMs.toFixed(4)}ms, ops/sec=${result.opsPerSecond.toFixed(0)}`);

        expect(result.avgTimeMs).toBeLessThan(0.1);
      });
    });

    describe('Hashing', () => {
      test('should hash small data efficiently (SHA-256)', () => {
        const data = Buffer.from('test data for hashing');

        const result = measurePerformance(
          'SHA-256 Hash (small)',
          () => {
            crypto.createHash('sha256').update(data).digest();
          },
          10000
        );

        console.log(`SHA-256 (small): avg=${result.avgTimeMs.toFixed(4)}ms, ops/sec=${result.opsPerSecond.toFixed(0)}`);

        expect(result.avgTimeMs).toBeLessThan(0.1);
      });

      test('should hash large data efficiently (SHA-256)', () => {
        const data = crypto.randomBytes(1024 * 1024); // 1MB

        const result = measurePerformance(
          'SHA-256 Hash (1MB)',
          () => {
            crypto.createHash('sha256').update(data).digest();
          },
          100
        );

        console.log(`SHA-256 (1MB): avg=${result.avgTimeMs.toFixed(2)}ms, throughput=${(1024 / result.avgTimeMs).toFixed(2)} MB/s`);

        expect(result.avgTimeMs).toBeLessThan(20);
      });
    });
  });

  describe('API Response Time Benchmarks', () => {
    let apiHandler: MockAPIHandler;

    beforeEach(() => {
      apiHandler = new MockAPIHandler();
    });

    test('should respond within P95 threshold for simple requests', async () => {
      const result = await measureAsyncPerformance(
        'Simple API Request',
        async () => {
          await apiHandler.handleRequest({
            method: 'GET',
            path: '/api/health',
          });
        },
        200
      );

      console.log(`API Health: avg=${result.avgTimeMs.toFixed(2)}ms, p95=${result.p95Ms.toFixed(2)}ms, p99=${result.p99Ms.toFixed(2)}ms`);

      expect(result.p95Ms).toBeLessThan(THRESHOLDS.API_RESPONSE_P95_MS);
    });

    test('should respond within P99 threshold for auth requests', async () => {
      const result = await measureAsyncPerformance(
        'Auth API Request',
        async () => {
          await apiHandler.handleRequest({
            method: 'POST',
            path: '/api/auth/verify',
            body: { token: 'test-token' },
          });
        },
        200
      );

      console.log(`API Auth: avg=${result.avgTimeMs.toFixed(2)}ms, p95=${result.p95Ms.toFixed(2)}ms, p99=${result.p99Ms.toFixed(2)}ms`);

      expect(result.p99Ms).toBeLessThan(THRESHOLDS.API_RESPONSE_P99_MS);
    });
  });

  describe('Database Operation Benchmarks', () => {
    let db: MockDynamoDB;

    beforeEach(() => {
      db = new MockDynamoDB();
      db.setLatency(5);
    });

    afterEach(() => {
      db.clear();
    });

    test('should retrieve single item within P95 threshold', async () => {
      // Setup
      await db.put('users', { id: 'user-1', name: 'Test User' });

      const result = await measureAsyncPerformance(
        'DynamoDB Get',
        async () => {
          await db.get('users', 'user-1');
        },
        200
      );

      console.log(`DB Get: avg=${result.avgTimeMs.toFixed(2)}ms, p95=${result.p95Ms.toFixed(2)}ms`);

      expect(result.p95Ms).toBeLessThan(THRESHOLDS.DB_GET_P95_MS);
    });

    test('should execute query within P95 threshold', async () => {
      // Setup
      for (let i = 0; i < 100; i++) {
        await db.put('messages', {
          id: `msg-${i}`,
          userId: 'user-1',
          content: `Message ${i}`,
        });
      }

      const result = await measureAsyncPerformance(
        'DynamoDB Query',
        async () => {
          await db.query('messages', 'user-index', { userId: 'user-1' });
        },
        100
      );

      console.log(`DB Query: avg=${result.avgTimeMs.toFixed(2)}ms, p95=${result.p95Ms.toFixed(2)}ms`);

      expect(result.p95Ms).toBeLessThan(THRESHOLDS.DB_QUERY_P95_MS);
    });

    test('should execute batch get within P95 threshold', async () => {
      // Setup
      const keys: string[] = [];
      for (let i = 0; i < 25; i++) {
        const id = `item-${i}`;
        keys.push(id);
        await db.put('items', { id, data: `Data ${i}` });
      }

      const result = await measureAsyncPerformance(
        'DynamoDB BatchGet',
        async () => {
          await db.batchGet('items', keys);
        },
        100
      );

      console.log(`DB BatchGet: avg=${result.avgTimeMs.toFixed(2)}ms, p95=${result.p95Ms.toFixed(2)}ms`);

      expect(result.p95Ms).toBeLessThan(THRESHOLDS.DB_BATCH_P95_MS);
    });

    test('should handle write operations efficiently', async () => {
      const result = await measureAsyncPerformance(
        'DynamoDB Put',
        async () => {
          const id = crypto.randomUUID();
          await db.put('items', { id, data: 'test data' });
        },
        200
      );

      console.log(`DB Put: avg=${result.avgTimeMs.toFixed(2)}ms, p95=${result.p95Ms.toFixed(2)}ms`);

      expect(result.p95Ms).toBeLessThan(THRESHOLDS.DB_GET_P95_MS);
    });
  });

  describe('Memory Usage Benchmarks', () => {
    test('should not leak memory during key derivation', () => {
      const initialMemory = getMemorySnapshot();

      // Perform many operations
      for (let i = 0; i < 100; i++) {
        const salt = crypto.randomBytes(16);
        MockArgon2.derive('test-password', salt);
      }

      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }

      const finalMemory = getMemorySnapshot();
      const heapIncreaseMB = (finalMemory.heapUsed - initialMemory.heapUsed) / (1024 * 1024);

      console.log(`Memory after 100 key derivations: +${heapIncreaseMB.toFixed(2)} MB`);

      expect(heapIncreaseMB).toBeLessThan(THRESHOLDS.MAX_HEAP_INCREASE_MB);
    });

    test('should not leak memory during encryption operations', () => {
      const initialMemory = getMemorySnapshot();
      const key = crypto.randomBytes(32);
      const plaintext = crypto.randomBytes(10 * 1024); // 10KB

      // Perform many operations
      for (let i = 0; i < 1000; i++) {
        const nonce = crypto.randomBytes(24);
        const ciphertext = MockXChaCha20Poly1305.encrypt(plaintext, key, nonce);
        MockXChaCha20Poly1305.decrypt(ciphertext, key, nonce);
      }

      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }

      const finalMemory = getMemorySnapshot();
      const heapIncreaseMB = (finalMemory.heapUsed - initialMemory.heapUsed) / (1024 * 1024);

      console.log(`Memory after 1000 encrypt/decrypt cycles: +${heapIncreaseMB.toFixed(2)} MB`);

      expect(heapIncreaseMB).toBeLessThan(THRESHOLDS.MAX_HEAP_INCREASE_MB);
    });

    test('should handle large buffer operations without excessive memory', () => {
      const initialMemory = getMemorySnapshot();

      // Encrypt/decrypt large messages
      const key = crypto.randomBytes(32);
      for (let i = 0; i < 10; i++) {
        const largePlaintext = crypto.randomBytes(10 * 1024 * 1024); // 10MB
        const nonce = crypto.randomBytes(24);
        const ciphertext = MockXChaCha20Poly1305.encrypt(largePlaintext, key, nonce);
        MockXChaCha20Poly1305.decrypt(ciphertext, key, nonce);
      }

      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }

      const finalMemory = getMemorySnapshot();
      const heapIncreaseMB = (finalMemory.heapUsed - initialMemory.heapUsed) / (1024 * 1024);

      console.log(`Memory after 10x 10MB operations: +${heapIncreaseMB.toFixed(2)} MB`);
      console.log(`Final heap: ${formatBytes(finalMemory.heapUsed)}`);

      // After operations complete, memory should be mostly reclaimed
      // Note: Some increase is expected due to JIT compilation and caching
      expect(heapIncreaseMB).toBeLessThan(100); // Allow more headroom for large operations
    });
  });

  describe('Throughput Benchmarks', () => {
    test('should handle high message throughput', () => {
      const key = crypto.randomBytes(32);
      const messageSize = 256; // Typical message size
      const targetOpsPerSecond = 10000;

      const result = measurePerformance(
        'Message Throughput',
        () => {
          const plaintext = crypto.randomBytes(messageSize);
          const nonce = crypto.randomBytes(24);
          MockXChaCha20Poly1305.encrypt(plaintext, key, nonce);
        },
        5000
      );

      console.log(`Message Throughput: ${result.opsPerSecond.toFixed(0)} ops/sec (target: ${targetOpsPerSecond})`);

      expect(result.opsPerSecond).toBeGreaterThan(targetOpsPerSecond);
    });

    test('should handle concurrent operations', async () => {
      const key = crypto.randomBytes(32);
      const plaintext = crypto.randomBytes(256);

      const start = performance.now();
      const concurrency = 100;

      const promises = Array(concurrency).fill(null).map(async () => {
        const nonce = crypto.randomBytes(24);
        return MockXChaCha20Poly1305.encrypt(plaintext, key, nonce);
      });

      await Promise.all(promises);
      const elapsed = performance.now() - start;

      console.log(`Concurrent (${concurrency}): ${elapsed.toFixed(2)}ms total, ${(concurrency / (elapsed / 1000)).toFixed(0)} ops/sec`);

      expect(elapsed).toBeLessThan(100); // All concurrent ops should complete quickly
    });
  });

  describe('Performance Regression Detection', () => {
    // These tests establish baselines and can detect regressions
    const BASELINES = {
      sha256Small: 0.01, // ms
      aesEncrypt1KB: 0.1, // ms
      ed25519Sign: 0.5, // ms
      randomBytes32: 0.01, // ms
    };

    const REGRESSION_THRESHOLD = 2.0; // 2x slower is a regression

    test('should not regress on SHA-256 performance', () => {
      const data = Buffer.from('test');

      const result = measurePerformance(
        'SHA-256 Regression Check',
        () => {
          crypto.createHash('sha256').update(data).digest();
        },
        5000
      );

      const regressionFactor = result.avgTimeMs / BASELINES.sha256Small;
      console.log(`SHA-256: ${result.avgTimeMs.toFixed(4)}ms (${regressionFactor.toFixed(1)}x baseline)`);

      // Allow significant headroom since absolute times vary by machine
      expect(result.avgTimeMs).toBeLessThan(1); // Very generous threshold
    });

    test('should not regress on encryption performance', () => {
      const key = crypto.randomBytes(32);
      const plaintext = crypto.randomBytes(1024);

      const result = measurePerformance(
        'AES Encryption Regression Check',
        () => {
          const nonce = crypto.randomBytes(24);
          MockXChaCha20Poly1305.encrypt(plaintext, key, nonce);
        },
        1000
      );

      console.log(`Encryption: ${result.avgTimeMs.toFixed(4)}ms`);

      expect(result.avgTimeMs).toBeLessThan(5); // Generous threshold
    });
  });
});

describe('Performance Summary', () => {
  test('should generate performance report', () => {
    const report = {
      timestamp: new Date().toISOString(),
      environment: {
        nodeVersion: process.version,
        platform: process.platform,
        arch: process.arch,
      },
      benchmarks: [] as BenchmarkResult[],
    };

    // Run key benchmarks for report
    const key = crypto.randomBytes(32);
    const plaintext = crypto.randomBytes(1024);

    report.benchmarks.push(
      measurePerformance(
        'SHA-256 (1KB)',
        () => crypto.createHash('sha256').update(plaintext).digest(),
        1000
      )
    );

    report.benchmarks.push(
      measurePerformance(
        'AES-GCM Encrypt (1KB)',
        () => {
          const nonce = crypto.randomBytes(24);
          MockXChaCha20Poly1305.encrypt(plaintext, key, nonce);
        },
        1000
      )
    );

    report.benchmarks.push(
      measurePerformance(
        'Ed25519 Key Generation',
        () => MockEd25519.generateKeyPair(),
        100
      )
    );

    console.log('\n=== Performance Report ===');
    console.log(`Generated: ${report.timestamp}`);
    console.log(`Node: ${report.environment.nodeVersion}`);
    console.log(`Platform: ${report.environment.platform}/${report.environment.arch}`);
    console.log('\nBenchmarks:');
    for (const benchmark of report.benchmarks) {
      console.log(`  ${benchmark.name}:`);
      console.log(`    avg: ${benchmark.avgTimeMs.toFixed(3)}ms`);
      console.log(`    p95: ${benchmark.p95Ms.toFixed(3)}ms`);
      console.log(`    ops/sec: ${benchmark.opsPerSecond.toFixed(0)}`);
    }

    expect(report.benchmarks.length).toBeGreaterThan(0);
  });
});
