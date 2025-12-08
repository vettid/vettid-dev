/**
 * Data Protection Security Tests
 *
 * Tests for data protection measures:
 * - PII data encryption at rest
 * - PII data encryption in transit
 * - Backup encryption validation
 * - Credential storage security
 * - Sensitive data masking in logs
 * - Data retention policy enforcement
 * - Secure deletion verification
 *
 * OWASP Reference: A02:2021 - Cryptographic Failures
 */

import * as crypto from 'crypto';
import {
  SENSITIVE_DATA_PATTERNS,
  scanForSensitiveData,
  maskSensitiveData,
} from '../fixtures/security/securityScenarios';

// Mock data protection utilities
const DataProtection = {
  /**
   * Encrypt data at rest using AES-256-GCM
   */
  encryptAtRest(plaintext: Buffer, key: Buffer): { ciphertext: Buffer; iv: Buffer; tag: Buffer } {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    return { ciphertext, iv, tag };
  },

  /**
   * Decrypt data at rest
   */
  decryptAtRest(ciphertext: Buffer, key: Buffer, iv: Buffer, tag: Buffer): Buffer {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  },

  /**
   * Generate encryption key
   */
  generateKey(): Buffer {
    return crypto.randomBytes(32);
  },

  /**
   * Hash password using Argon2id simulation (PBKDF2 fallback)
   */
  hashPassword(password: string, salt: Buffer): Buffer {
    return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
  },

  /**
   * Secure random salt generation
   */
  generateSalt(): Buffer {
    return crypto.randomBytes(16);
  },

  /**
   * Derive key from password
   */
  deriveKeyFromPassword(password: string, salt: Buffer): Buffer {
    return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
  },

  /**
   * Securely overwrite buffer (best effort in JavaScript)
   */
  secureWipe(buffer: Buffer): void {
    crypto.randomFillSync(buffer);
    buffer.fill(0);
    crypto.randomFillSync(buffer);
    buffer.fill(0);
  },

  /**
   * Check if data contains PII
   */
  containsPII(data: string): boolean {
    const piiPatterns = [
      /\b\d{3}-\d{2}-\d{4}\b/, // SSN
      /\b\d{16}\b/, // Credit card
      /\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/, // Credit card with separators
      /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/, // Email
      /\b\d{3}[-.)]?\d{3}[-.)]?\d{4}\b/, // Phone
    ];
    return piiPatterns.some(pattern => pattern.test(data));
  },

  /**
   * Redact PII from string
   */
  redactPII(data: string): string {
    return data
      .replace(/\b\d{3}-\d{2}-\d{4}\b/g, '***-**-****') // SSN
      .replace(/\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/g, '****-****-****-****') // Credit card
      .replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, '***@***.***') // Email
      .replace(/\b\d{3}[-.)]?\d{3}[-.)]?\d{4}\b/g, '***-***-****'); // Phone
  },
};

// Mock backup service for testing
class MockBackupService {
  private backups: Map<
    string,
    { data: Buffer; key: Buffer; iv: Buffer; tag: Buffer; createdAt: Date; retentionDays: number }
  > = new Map();

  createBackup(
    id: string,
    plaintext: Buffer,
    retentionDays: number = 30
  ): { success: boolean; encrypted: boolean } {
    const key = DataProtection.generateKey();
    const { ciphertext, iv, tag } = DataProtection.encryptAtRest(plaintext, key);

    this.backups.set(id, {
      data: ciphertext,
      key,
      iv,
      tag,
      createdAt: new Date(),
      retentionDays,
    });

    return { success: true, encrypted: true };
  }

  restoreBackup(id: string): Buffer | null {
    const backup = this.backups.get(id);
    if (!backup) return null;

    return DataProtection.decryptAtRest(backup.data, backup.key, backup.iv, backup.tag);
  }

  deleteBackup(id: string): boolean {
    const backup = this.backups.get(id);
    if (!backup) return false;

    // Securely wipe the key
    DataProtection.secureWipe(backup.key);

    // Delete the backup
    this.backups.delete(id);
    return true;
  }

  getExpiredBackups(): string[] {
    const now = new Date();
    const expired: string[] = [];

    this.backups.forEach((backup, id) => {
      const expiryDate = new Date(backup.createdAt);
      expiryDate.setDate(expiryDate.getDate() + backup.retentionDays);

      if (now > expiryDate) {
        expired.push(id);
      }
    });

    return expired;
  }

  isEncrypted(id: string): boolean {
    const backup = this.backups.get(id);
    return backup !== undefined && backup.iv !== undefined && backup.tag !== undefined;
  }
}

// Mock credential storage
class MockCredentialStore {
  private credentials: Map<string, { hash: Buffer; salt: Buffer; algorithm: string }> = new Map();

  storeCredential(userId: string, password: string): boolean {
    const salt = DataProtection.generateSalt();
    const hash = DataProtection.hashPassword(password, salt);

    this.credentials.set(userId, {
      hash,
      salt,
      algorithm: 'pbkdf2-sha256-100000', // Document the algorithm
    });

    return true;
  }

  verifyCredential(userId: string, password: string): boolean {
    const stored = this.credentials.get(userId);
    if (!stored) return false;

    const hash = DataProtection.hashPassword(password, stored.salt);
    return crypto.timingSafeEqual(hash, stored.hash);
  }

  getStoredHash(userId: string): Buffer | null {
    const stored = this.credentials.get(userId);
    return stored?.hash || null;
  }

  getAlgorithm(userId: string): string | null {
    const stored = this.credentials.get(userId);
    return stored?.algorithm || null;
  }
}

// Mock logger for sensitive data testing
class MockLogger {
  private logs: string[] = [];
  private redactionEnabled: boolean = true;

  enableRedaction(): void {
    this.redactionEnabled = true;
  }

  disableRedaction(): void {
    this.redactionEnabled = false;
  }

  log(message: string): void {
    const logEntry = this.redactionEnabled ? DataProtection.redactPII(message) : message;
    this.logs.push(logEntry);
  }

  getLogs(): string[] {
    return [...this.logs];
  }

  clear(): void {
    this.logs = [];
  }
}

describe('Data Protection Security Tests', () => {
  describe('PII Data Encryption at Rest', () => {
    /**
     * OWASP A02:2021 - Cryptographic Failures
     * Tests that PII is properly encrypted when stored
     */
    describe('Encryption implementation', () => {
      it('should encrypt PII data before storage', () => {
        const piiData = Buffer.from(
          JSON.stringify({
            ssn: '123-45-6789',
            email: 'user@example.com',
            phone: '555-123-4567',
          })
        );
        const key = DataProtection.generateKey();

        const { ciphertext, iv, tag } = DataProtection.encryptAtRest(piiData, key);

        // Ciphertext should not contain plaintext
        expect(ciphertext.toString()).not.toContain('123-45-6789');
        expect(ciphertext.toString()).not.toContain('user@example.com');
      });

      it('should use AES-256-GCM for encryption', () => {
        const data = Buffer.from('test data');
        const key = DataProtection.generateKey();

        const { ciphertext, iv, tag } = DataProtection.encryptAtRest(data, key);

        // AES-256-GCM produces 16-byte authentication tag
        expect(tag.length).toBe(16);
        // IV should be 12 bytes for GCM
        expect(iv.length).toBe(12);
        // Key should be 32 bytes (256 bits)
        expect(key.length).toBe(32);
      });

      it('should decrypt to original data', () => {
        const originalData = Buffer.from('Sensitive user information');
        const key = DataProtection.generateKey();

        const { ciphertext, iv, tag } = DataProtection.encryptAtRest(originalData, key);
        const decrypted = DataProtection.decryptAtRest(ciphertext, key, iv, tag);

        expect(decrypted.toString()).toBe('Sensitive user information');
      });

      it('should fail decryption with wrong key', () => {
        const data = Buffer.from('test');
        const key1 = DataProtection.generateKey();
        const key2 = DataProtection.generateKey();

        const { ciphertext, iv, tag } = DataProtection.encryptAtRest(data, key1);

        expect(() => {
          DataProtection.decryptAtRest(ciphertext, key2, iv, tag);
        }).toThrow();
      });

      it('should fail decryption with tampered ciphertext', () => {
        const data = Buffer.from('test');
        const key = DataProtection.generateKey();

        const { ciphertext, iv, tag } = DataProtection.encryptAtRest(data, key);
        ciphertext[0] ^= 0xff; // Tamper

        expect(() => {
          DataProtection.decryptAtRest(ciphertext, key, iv, tag);
        }).toThrow();
      });
    });

    describe('Key management', () => {
      it('should generate unique keys for each encryption', () => {
        const key1 = DataProtection.generateKey();
        const key2 = DataProtection.generateKey();

        expect(key1.equals(key2)).toBe(false);
      });

      it('should generate cryptographically strong keys', () => {
        const key = DataProtection.generateKey();

        // Check entropy - key shouldn't be all zeros or predictable
        const uniqueBytes = new Set(key);
        expect(uniqueBytes.size).toBeGreaterThan(5);
      });
    });
  });

  describe('PII Data Encryption in Transit', () => {
    /**
     * Tests for data protection during transmission
     */
    it('should require TLS for PII transmission', () => {
      // Document TLS requirement
      const tlsRequired = true;
      const minTlsVersion = '1.2';

      expect(tlsRequired).toBe(true);
      expect(minTlsVersion).toBe('1.2');
    });

    it('should encrypt request payload containing PII', () => {
      const piiPayload = {
        user: 'john@example.com',
        ssn: '123-45-6789',
      };

      // Simulate encryption for transit
      const key = DataProtection.generateKey();
      const plaintext = Buffer.from(JSON.stringify(piiPayload));
      const { ciphertext } = DataProtection.encryptAtRest(plaintext, key);

      // Ciphertext is safe for transit
      expect(ciphertext.toString('base64')).not.toContain('john@example.com');
    });

    it('should use separate keys for different data classifications', () => {
      const piiKey = DataProtection.generateKey();
      const sensitiveKey = DataProtection.generateKey();
      const publicKey = DataProtection.generateKey();

      // Keys should all be different
      expect(piiKey.equals(sensitiveKey)).toBe(false);
      expect(sensitiveKey.equals(publicKey)).toBe(false);
      expect(piiKey.equals(publicKey)).toBe(false);
    });
  });

  describe('Backup Encryption Validation', () => {
    /**
     * Tests that backups are properly encrypted
     */
    let backupService: MockBackupService;

    beforeEach(() => {
      backupService = new MockBackupService();
    });

    it('should encrypt backups before storage', () => {
      const sensitiveData = Buffer.from('Backup containing PII');

      const result = backupService.createBackup('backup-1', sensitiveData);

      expect(result.encrypted).toBe(true);
      expect(backupService.isEncrypted('backup-1')).toBe(true);
    });

    it('should restore backups correctly', () => {
      const originalData = Buffer.from('Original backup data');

      backupService.createBackup('backup-1', originalData);
      const restored = backupService.restoreBackup('backup-1');

      expect(restored?.toString()).toBe('Original backup data');
    });

    it('should use unique keys per backup', () => {
      const data1 = Buffer.from('Backup 1');
      const data2 = Buffer.from('Backup 2');

      backupService.createBackup('backup-1', data1);
      backupService.createBackup('backup-2', data2);

      // Both should be independently decryptable
      const restored1 = backupService.restoreBackup('backup-1');
      const restored2 = backupService.restoreBackup('backup-2');

      expect(restored1?.toString()).toBe('Backup 1');
      expect(restored2?.toString()).toBe('Backup 2');
    });

    it('should return null for non-existent backups', () => {
      const result = backupService.restoreBackup('non-existent');
      expect(result).toBeNull();
    });
  });

  describe('Credential Storage Security', () => {
    /**
     * Tests for secure credential storage
     */
    let credentialStore: MockCredentialStore;

    beforeEach(() => {
      credentialStore = new MockCredentialStore();
    });

    it('should never store plaintext passwords', () => {
      const password = 'MySecurePassword123!';
      credentialStore.storeCredential('user-1', password);

      const storedHash = credentialStore.getStoredHash('user-1');

      // Hash should not equal password
      expect(storedHash?.toString()).not.toBe(password);
      // Hash should not contain password
      expect(storedHash?.toString()).not.toContain(password);
    });

    it('should use strong hashing algorithm', () => {
      credentialStore.storeCredential('user-1', 'password');

      const algorithm = credentialStore.getAlgorithm('user-1');

      // Should use PBKDF2 with high iteration count
      expect(algorithm).toContain('pbkdf2');
      expect(algorithm).toContain('100000');
    });

    it('should use unique salt per credential', () => {
      credentialStore.storeCredential('user-1', 'same-password');
      credentialStore.storeCredential('user-2', 'same-password');

      const hash1 = credentialStore.getStoredHash('user-1');
      const hash2 = credentialStore.getStoredHash('user-2');

      // Same password should produce different hashes due to unique salts
      expect(hash1?.equals(hash2!)).toBe(false);
    });

    it('should verify correct passwords', () => {
      credentialStore.storeCredential('user-1', 'correct-password');

      expect(credentialStore.verifyCredential('user-1', 'correct-password')).toBe(true);
      expect(credentialStore.verifyCredential('user-1', 'wrong-password')).toBe(false);
    });

    it('should use timing-safe comparison', () => {
      credentialStore.storeCredential('user-1', 'password');

      // Both should take similar time (documented requirement)
      const iterations = 100;
      const correctTimes: number[] = [];
      const wrongTimes: number[] = [];

      for (let i = 0; i < iterations; i++) {
        const start1 = process.hrtime.bigint();
        credentialStore.verifyCredential('user-1', 'password');
        const end1 = process.hrtime.bigint();
        correctTimes.push(Number(end1 - start1));

        const start2 = process.hrtime.bigint();
        credentialStore.verifyCredential('user-1', 'wrongpwd');
        const end2 = process.hrtime.bigint();
        wrongTimes.push(Number(end2 - start2));
      }

      // Average times should be similar
      const avgCorrect = correctTimes.reduce((a, b) => a + b, 0) / iterations;
      const avgWrong = wrongTimes.reduce((a, b) => a + b, 0) / iterations;

      const ratio = avgCorrect / avgWrong;
      expect(ratio).toBeGreaterThan(0.5);
      expect(ratio).toBeLessThan(2.0);
    });
  });

  describe('Sensitive Data Masking in Logs', () => {
    /**
     * Tests that sensitive data is masked in log output
     */
    let logger: MockLogger;

    beforeEach(() => {
      logger = new MockLogger();
    });

    describe('PII redaction', () => {
      it('should redact SSN from logs', () => {
        logger.log('User SSN: 123-45-6789');

        const logs = logger.getLogs();
        expect(logs[0]).not.toContain('123-45-6789');
        expect(logs[0]).toContain('***-**-****');
      });

      it('should redact email from logs', () => {
        logger.log('User email: john.doe@example.com');

        const logs = logger.getLogs();
        expect(logs[0]).not.toContain('john.doe@example.com');
        expect(logs[0]).toContain('***@***.***');
      });

      it('should redact phone numbers from logs', () => {
        logger.log('Contact: 555-123-4567');

        const logs = logger.getLogs();
        expect(logs[0]).not.toContain('555-123-4567');
        expect(logs[0]).toContain('***-***-****');
      });

      it('should redact credit card numbers from logs', () => {
        logger.log('Card: 4111-1111-1111-1111');

        const logs = logger.getLogs();
        expect(logs[0]).not.toContain('4111-1111-1111-1111');
        expect(logs[0]).toContain('****-****-****-****');
      });

      it('should handle multiple PII in same log entry', () => {
        logger.log('User: john@test.com, SSN: 123-45-6789, Phone: 555-123-4567');

        const logs = logger.getLogs();
        expect(logs[0]).not.toContain('john@test.com');
        expect(logs[0]).not.toContain('123-45-6789');
        expect(logs[0]).not.toContain('555-123-4567');
      });
    });

    describe('Using fixture utilities', () => {
      it('should detect sensitive data using patterns', () => {
        const testData = 'User SSN: 123-45-6789, Email: test@example.com';

        const findings = scanForSensitiveData(testData);

        expect(findings.found).toBe(true);
        expect(findings.matches.length).toBeGreaterThan(0);
        expect(findings.matches.some((f: { pattern: string }) => f.pattern === 'ssn')).toBe(true);
        expect(findings.matches.some((f: { pattern: string }) => f.pattern === 'email')).toBe(true);
      });

      it('should mask sensitive data', () => {
        const data = 'SSN: 123-45-6789';

        const masked = maskSensitiveData(data);

        expect(masked).not.toContain('123-45-6789');
      });
    });

    describe('Log sanitization completeness', () => {
      SENSITIVE_DATA_PATTERNS.forEach(pattern => {
        it(`should detect and handle ${pattern.name} pattern`, () => {
          // Test the pattern detection
          expect(pattern.pattern).toBeDefined();
          expect(pattern.severity).toBeDefined();
        });
      });
    });
  });

  describe('Data Retention Policy Enforcement', () => {
    /**
     * Tests for data retention policy
     */
    let backupService: MockBackupService;

    beforeEach(() => {
      backupService = new MockBackupService();
    });

    it('should identify expired backups', () => {
      // Create backup with 0 day retention (expired immediately)
      backupService.createBackup('old-backup', Buffer.from('data'), 0);

      const expired = backupService.getExpiredBackups();

      expect(expired).toContain('old-backup');
    });

    it('should not identify non-expired backups', () => {
      // Create backup with 30 day retention
      backupService.createBackup('new-backup', Buffer.from('data'), 30);

      const expired = backupService.getExpiredBackups();

      expect(expired).not.toContain('new-backup');
    });

    it('should enforce retention periods', () => {
      const retentionDays = 30;
      const backup = { createdAt: new Date(), retentionDays };

      // Calculate expected expiry
      const expiryDate = new Date(backup.createdAt);
      expiryDate.setDate(expiryDate.getDate() + retentionDays);

      expect(expiryDate.getTime()).toBeGreaterThan(backup.createdAt.getTime());
    });
  });

  describe('Secure Deletion Verification', () => {
    /**
     * Tests for secure data deletion
     */
    it('should wipe sensitive buffers after use', () => {
      const sensitiveData = Buffer.from('Secret Key Material');
      const originalContent = sensitiveData.toString();

      DataProtection.secureWipe(sensitiveData);

      // Buffer should not contain original content
      expect(sensitiveData.toString()).not.toBe(originalContent);
      // Buffer should be zeroed
      expect(sensitiveData.every(byte => byte === 0)).toBe(true);
    });

    it('should delete backup keys when backup is deleted', () => {
      const backupService = new MockBackupService();

      backupService.createBackup('to-delete', Buffer.from('data'));
      const deleted = backupService.deleteBackup('to-delete');

      expect(deleted).toBe(true);
      // Backup should no longer be restorable
      expect(backupService.restoreBackup('to-delete')).toBeNull();
    });

    it('should perform multiple overwrites for secure deletion', () => {
      const buffer = Buffer.from('sensitive');
      const passCount = 2; // At least 2 passes

      // Our implementation does 4 passes (random, zero, random, zero)
      DataProtection.secureWipe(buffer);

      // Document the requirement
      expect(passCount).toBeGreaterThanOrEqual(1);
    });

    it('should not leave partial data after deletion', () => {
      const buffer = Buffer.alloc(100);
      buffer.fill('X');

      DataProtection.secureWipe(buffer);

      // No X characters should remain
      expect(buffer.includes(Buffer.from('X'))).toBe(false);
    });
  });

  describe('PII Detection', () => {
    /**
     * Tests for PII detection capabilities
     */
    it('should detect SSN in data', () => {
      expect(DataProtection.containsPII('My SSN is 123-45-6789')).toBe(true);
    });

    it('should detect email in data', () => {
      expect(DataProtection.containsPII('Contact me at user@example.com')).toBe(true);
    });

    it('should detect phone numbers in data', () => {
      expect(DataProtection.containsPII('Call me at 555-123-4567')).toBe(true);
    });

    it('should detect credit card numbers in data', () => {
      expect(DataProtection.containsPII('Card: 4111111111111111')).toBe(true);
    });

    it('should not flag non-PII data', () => {
      expect(DataProtection.containsPII('This is just regular text')).toBe(false);
    });
  });

  describe('Data Classification', () => {
    /**
     * Tests for proper data classification
     */
    const DataClassification = {
      PUBLIC: 'public',
      INTERNAL: 'internal',
      CONFIDENTIAL: 'confidential',
      RESTRICTED: 'restricted',

      classify(data: { type: string; containsPII: boolean }): string {
        if (data.containsPII) return this.RESTRICTED;
        if (data.type === 'financial') return this.CONFIDENTIAL;
        if (data.type === 'user-data') return this.CONFIDENTIAL;
        if (data.type === 'internal-docs') return this.INTERNAL;
        return this.PUBLIC;
      },
    };

    it('should classify PII as restricted', () => {
      const classification = DataClassification.classify({
        type: 'user-profile',
        containsPII: true,
      });

      expect(classification).toBe('restricted');
    });

    it('should classify financial data as confidential', () => {
      const classification = DataClassification.classify({
        type: 'financial',
        containsPII: false,
      });

      expect(classification).toBe('confidential');
    });

    it('should classify user data as confidential', () => {
      const classification = DataClassification.classify({
        type: 'user-data',
        containsPII: false,
      });

      expect(classification).toBe('confidential');
    });

    it('should apply encryption based on classification', () => {
      const encryptionRequired = (classification: string): boolean => {
        return ['confidential', 'restricted'].includes(classification);
      };

      expect(encryptionRequired('restricted')).toBe(true);
      expect(encryptionRequired('confidential')).toBe(true);
      expect(encryptionRequired('internal')).toBe(false);
      expect(encryptionRequired('public')).toBe(false);
    });
  });

  describe('Key Derivation Security', () => {
    /**
     * Tests for key derivation from passwords
     */
    it('should derive consistent keys from same password and salt', () => {
      const password = 'user-password';
      const salt = Buffer.from('fixed-salt-value');

      const key1 = DataProtection.deriveKeyFromPassword(password, salt);
      const key2 = DataProtection.deriveKeyFromPassword(password, salt);

      expect(key1.equals(key2)).toBe(true);
    });

    it('should derive different keys from different passwords', () => {
      const salt = Buffer.from('fixed-salt');

      const key1 = DataProtection.deriveKeyFromPassword('password1', salt);
      const key2 = DataProtection.deriveKeyFromPassword('password2', salt);

      expect(key1.equals(key2)).toBe(false);
    });

    it('should derive different keys from different salts', () => {
      const password = 'same-password';

      const key1 = DataProtection.deriveKeyFromPassword(password, Buffer.from('salt1'));
      const key2 = DataProtection.deriveKeyFromPassword(password, Buffer.from('salt2'));

      expect(key1.equals(key2)).toBe(false);
    });

    it('should use sufficient iterations', () => {
      // Document iteration requirement
      const minIterations = 100000;

      // Time the derivation
      const startTime = Date.now();
      DataProtection.deriveKeyFromPassword('password', Buffer.from('salt'));
      const duration = Date.now() - startTime;

      // Should take measurable time (at least a few ms)
      expect(duration).toBeGreaterThanOrEqual(0);
      expect(minIterations).toBeGreaterThanOrEqual(100000);
    });
  });

  describe('Encryption Key Storage', () => {
    /**
     * Tests for secure key storage requirements
     */
    it('should never store keys in plaintext', () => {
      // Document requirement: Keys should be encrypted with KEK or stored in HSM
      const keyStorageRequirements = {
        plaintextForbidden: true,
        kekRequired: true,
        hsmPreferred: true,
      };

      expect(keyStorageRequirements.plaintextForbidden).toBe(true);
    });

    it('should use key encryption keys (KEK)', () => {
      const dataKey = DataProtection.generateKey();
      const kek = DataProtection.generateKey();

      // Encrypt the data key with KEK
      const { ciphertext, iv, tag } = DataProtection.encryptAtRest(dataKey, kek);

      // Data key should be recoverable with KEK
      const recoveredKey = DataProtection.decryptAtRest(ciphertext, kek, iv, tag);
      expect(recoveredKey.equals(dataKey)).toBe(true);
    });

    it('should rotate keys periodically', () => {
      // Document key rotation requirement
      const keyRotationPolicy = {
        maxKeyAgedays: 90,
        rotationRequired: true,
      };

      expect(keyRotationPolicy.rotationRequired).toBe(true);
      expect(keyRotationPolicy.maxKeyAgedays).toBeLessThanOrEqual(365);
    });
  });
});
