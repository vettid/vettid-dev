/**
 * Integration Tests: Credential Backup
 *
 * Tests credential backup functionality:
 * - Backup creation
 * - Recovery phrase generation (BIP-39)
 * - Backup encryption (Argon2id + XChaCha20-Poly1305)
 * - Backup status
 *
 * @see lambda/handlers/vault/credentialBackup.ts (pending implementation)
 */

import {
  MockBackupService,
  MockS3Storage,
  createTestMemberKey,
  generateRecoveryPhrase,
  validateRecoveryPhrase,
  deriveKeyFromPhrase,
  getBip39WordList,
  getWordIndex,
} from '../../fixtures/backup/mockBackup';
import * as crypto from 'crypto';

// ============================================
// Tests
// ============================================

describe('Credential Backup', () => {
  let backupService: MockBackupService;
  let storage: MockS3Storage;
  const testMemberId = 'member-test-123';
  let memberKey: Buffer;

  beforeEach(() => {
    storage = new MockS3Storage();
    backupService = new MockBackupService(storage);
    memberKey = createTestMemberKey();
    backupService.setMemberKey(testMemberId, memberKey);
  });

  afterEach(() => {
    backupService.clear();
  });

  describe('Backup Creation', () => {
    it('should generate 24-word recovery phrase', async () => {
      const result = await backupService.createCredentialBackup(testMemberId);

      expect(result.success).toBe(true);
      expect(result.recoveryPhrase).toBeDefined();
      expect(result.recoveryPhrase).toHaveLength(24);
    });

    it('should derive backup key from phrase', async () => {
      const result = await backupService.createCredentialBackup(testMemberId);

      expect(result.success).toBe(true);
      expect(result.backup?.encryption_metadata.key_derivation).toBe('Argon2id');
      expect(result.backup?.encryption_metadata.salt).toBeDefined();
    });

    it('should encrypt credential blob', async () => {
      const result = await backupService.createCredentialBackup(testMemberId);

      expect(result.success).toBe(true);
      expect(result.backup?.encrypted_credentials).toBeDefined();
      expect(result.backup?.encrypted_credentials.length).toBeGreaterThan(0);

      // Encrypted data should not contain raw key
      expect(result.backup?.encrypted_credentials).not.toContain(
        memberKey.toString('base64')
      );
    });

    it('should store encrypted backup in S3', async () => {
      const result = await backupService.createCredentialBackup(testMemberId);

      expect(result.success).toBe(true);

      // Verify stored in S3
      const s3Key = `${testMemberId}/credentials.backup`;
      const stored = await storage.getObject('vettid-credential-backups', s3Key);
      expect(stored).toBeDefined();
      expect(stored?.data.length).toBeGreaterThan(0);
    });

    it('should require authenticated user', async () => {
      const result = await backupService.createCredentialBackup('unknown-member');

      expect(result.success).toBe(false);
      expect(result.error).toContain('Member key not found');
    });

    it('should generate unique backup ID', async () => {
      const result1 = await backupService.createCredentialBackup(testMemberId);

      // Create another member to test uniqueness
      const member2 = 'member-test-456';
      backupService.setMemberKey(member2, createTestMemberKey());
      const result2 = await backupService.createCredentialBackup(member2);

      expect(result1.backup?.backup_id).not.toBe(result2.backup?.backup_id);
    });

    it('should include checksum for integrity', async () => {
      const result = await backupService.createCredentialBackup(testMemberId);

      expect(result.success).toBe(true);
      expect(result.backup?.checksum).toBeDefined();
      expect(result.backup?.checksum).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should include creation timestamp', async () => {
      const before = new Date();
      const result = await backupService.createCredentialBackup(testMemberId);
      const after = new Date();

      expect(result.success).toBe(true);
      const createdAt = new Date(result.backup!.created_at);
      expect(createdAt.getTime()).toBeGreaterThanOrEqual(before.getTime());
      expect(createdAt.getTime()).toBeLessThanOrEqual(after.getTime());
    });
  });

  describe('Recovery Phrase', () => {
    it('should use BIP-39 word list', () => {
      const phrase = generateRecoveryPhrase();
      const wordList = getBip39WordList();

      // All words should be in BIP-39 list
      for (const word of phrase) {
        expect(wordList).toContain(word);
      }
    });

    it('should include checksum word', () => {
      // BIP-39 phrases include checksum in the last few bits
      // which are encoded in the final word(s)
      const phrase = generateRecoveryPhrase();

      expect(phrase).toHaveLength(24);
      // All words should be valid BIP-39 words
      const validation = validateRecoveryPhrase(phrase);
      expect(validation.valid).toBe(true);
    });

    it('should be unique per backup', async () => {
      const result1 = await backupService.createCredentialBackup(testMemberId);

      // Reset and create another
      backupService.clear();
      storage.clear();
      backupService = new MockBackupService(storage);
      backupService.setMemberKey(testMemberId, memberKey);

      const result2 = await backupService.createCredentialBackup(testMemberId);

      expect(result1.recoveryPhrase).not.toEqual(result2.recoveryPhrase);
    });

    it('should not be stored on server', async () => {
      const result = await backupService.createCredentialBackup(testMemberId);
      const phrase = result.recoveryPhrase;

      // Check S3 doesn't contain the phrase
      const s3Key = `${testMemberId}/credentials.backup`;
      const stored = await storage.getObject('vettid-credential-backups', s3Key);
      const storedString = stored?.data.toString('utf8');

      // The phrase should not appear in storage
      for (const word of phrase!) {
        // Check the full phrase isn't stored as-is
        expect(storedString).not.toContain(phrase!.join(' '));
      }
    });

    it('should generate valid 24-word phrases consistently', () => {
      // Generate multiple phrases and verify all are valid
      for (let i = 0; i < 10; i++) {
        const phrase = generateRecoveryPhrase();
        expect(phrase).toHaveLength(24);

        const validation = validateRecoveryPhrase(phrase);
        expect(validation.valid).toBe(true);
      }
    });

    it('should use lowercase words', () => {
      const phrase = generateRecoveryPhrase();

      for (const word of phrase) {
        expect(word).toBe(word.toLowerCase());
      }
    });
  });

  describe('Backup Encryption', () => {
    it('should use Argon2id for key derivation', async () => {
      const result = await backupService.createCredentialBackup(testMemberId);

      expect(result.backup?.encryption_metadata.key_derivation).toBe('Argon2id');
    });

    it('should use unique salt per backup', async () => {
      const result1 = await backupService.createCredentialBackup(testMemberId);

      // Create for different member
      const member2 = 'member-test-456';
      backupService.setMemberKey(member2, createTestMemberKey());
      const result2 = await backupService.createCredentialBackup(member2);

      expect(result1.backup?.encryption_metadata.salt).not.toBe(
        result2.backup?.encryption_metadata.salt
      );
    });

    it('should encrypt with XChaCha20-Poly1305', async () => {
      const result = await backupService.createCredentialBackup(testMemberId);

      expect(result.backup?.encryption_metadata.algorithm).toBe('XChaCha20-Poly1305');
    });

    it('should include Argon2id parameters', async () => {
      const result = await backupService.createCredentialBackup(testMemberId);

      expect(result.backup?.encryption_metadata.iterations).toBeDefined();
      expect(result.backup?.encryption_metadata.memory_cost).toBeDefined();
      expect(result.backup?.encryption_metadata.parallelism).toBeDefined();
    });

    it('should use secure Argon2id parameters', async () => {
      const result = await backupService.createCredentialBackup(testMemberId);

      // OWASP recommended minimums
      expect(result.backup?.encryption_metadata.iterations).toBeGreaterThanOrEqual(2);
      expect(result.backup?.encryption_metadata.memory_cost).toBeGreaterThanOrEqual(15000); // 15 MB
      expect(result.backup?.encryption_metadata.parallelism).toBeGreaterThanOrEqual(1);
    });

    it('should produce different ciphertext for same key with different salt', () => {
      const phrase = generateRecoveryPhrase();
      const salt1 = crypto.randomBytes(16);
      const salt2 = crypto.randomBytes(16);

      const key1 = deriveKeyFromPhrase(phrase, salt1);
      const key2 = deriveKeyFromPhrase(phrase, salt2);

      expect(key1.toString('hex')).not.toBe(key2.toString('hex'));
    });

    it('should derive same key from same phrase and salt', () => {
      const phrase = generateRecoveryPhrase();
      const salt = crypto.randomBytes(16);

      const key1 = deriveKeyFromPhrase(phrase, salt);
      const key2 = deriveKeyFromPhrase(phrase, salt);

      expect(key1.toString('hex')).toBe(key2.toString('hex'));
    });
  });

  describe('Backup Status', () => {
    it('should track backup existence', async () => {
      // Before backup
      const statusBefore = await backupService.getCredentialBackupStatus(testMemberId);
      expect(statusBefore.exists).toBe(false);

      // Create backup
      await backupService.createCredentialBackup(testMemberId);

      // After backup
      const statusAfter = await backupService.getCredentialBackupStatus(testMemberId);
      expect(statusAfter.exists).toBe(true);
    });

    it('should track last backup date', async () => {
      const before = new Date();
      await backupService.createCredentialBackup(testMemberId);
      const after = new Date();

      const status = await backupService.getCredentialBackupStatus(testMemberId);

      expect(status.exists).toBe(true);
      expect(status.lastBackup).toBeDefined();

      const lastBackup = new Date(status.lastBackup!);
      expect(lastBackup.getTime()).toBeGreaterThanOrEqual(before.getTime());
      expect(lastBackup.getTime()).toBeLessThanOrEqual(after.getTime());
    });

    it('should not expose backup contents', async () => {
      await backupService.createCredentialBackup(testMemberId);

      const status = await backupService.getCredentialBackupStatus(testMemberId);

      // Status should only contain existence and date info
      expect(Object.keys(status)).toEqual(['exists', 'lastBackup']);
    });

    it('should return false for non-existent member', async () => {
      const status = await backupService.getCredentialBackupStatus('non-existent-member');

      expect(status.exists).toBe(false);
      expect(status.lastBackup).toBeUndefined();
    });
  });

  describe('Recovery Phrase Validation', () => {
    it('should validate word count (24)', () => {
      const tooFew = generateRecoveryPhrase().slice(0, 12);
      const result = validateRecoveryPhrase(tooFew);

      expect(result.valid).toBe(false);
      expect(result.error).toContain('24');
    });

    it('should validate words in BIP-39 list', () => {
      const phrase = generateRecoveryPhrase();
      phrase[0] = 'notaword';

      const result = validateRecoveryPhrase(phrase);

      expect(result.valid).toBe(false);
      expect(result.error).toContain('BIP-39');
    });

    it('should accept valid phrases', () => {
      const phrase = generateRecoveryPhrase();
      const result = validateRecoveryPhrase(phrase);

      expect(result.valid).toBe(true);
      expect(result.error).toBeUndefined();
    });

    it('should reject invalid phrases', () => {
      const invalid = Array(24).fill('invalid');
      const result = validateRecoveryPhrase(invalid);

      expect(result.valid).toBe(false);
    });

    it('should be case-insensitive', () => {
      const phrase = generateRecoveryPhrase();
      const upperPhrase = phrase.map(w => w.toUpperCase());

      const result = validateRecoveryPhrase(upperPhrase);

      expect(result.valid).toBe(true);
    });

    it('should reject empty phrases', () => {
      const result = validateRecoveryPhrase([]);

      expect(result.valid).toBe(false);
      expect(result.error).toContain('24');
    });
  });

  describe('Key Derivation', () => {
    it('should derive 32-byte key from phrase', () => {
      const phrase = generateRecoveryPhrase();
      const salt = crypto.randomBytes(16);
      const key = deriveKeyFromPhrase(phrase, salt);

      expect(key).toBeInstanceOf(Buffer);
      expect(key.length).toBe(32); // 256 bits
    });

    it('should be deterministic', () => {
      const phrase = generateRecoveryPhrase();
      const salt = crypto.randomBytes(16);

      const key1 = deriveKeyFromPhrase(phrase, salt);
      const key2 = deriveKeyFromPhrase(phrase, salt);

      expect(key1.equals(key2)).toBe(true);
    });

    it('should differ with different phrases', () => {
      const phrase1 = generateRecoveryPhrase();
      const phrase2 = generateRecoveryPhrase();
      const salt = crypto.randomBytes(16);

      const key1 = deriveKeyFromPhrase(phrase1, salt);
      const key2 = deriveKeyFromPhrase(phrase2, salt);

      expect(key1.equals(key2)).toBe(false);
    });

    it('should support custom iteration count', () => {
      const phrase = generateRecoveryPhrase();
      const salt = crypto.randomBytes(16);

      const key1 = deriveKeyFromPhrase(phrase, salt, { iterations: 1 });
      const key2 = deriveKeyFromPhrase(phrase, salt, { iterations: 5 });

      // Different iterations produce different keys
      expect(key1.equals(key2)).toBe(false);
    });
  });

  describe('Word List', () => {
    it('should have at least 256 words for testing', () => {
      const wordList = getBip39WordList();
      expect(wordList.length).toBeGreaterThanOrEqual(256);
    });

    it('should return correct word index', () => {
      const wordList = getBip39WordList();
      const index = getWordIndex(wordList[0]);
      expect(index).toBe(0);

      const index100 = getWordIndex(wordList[100]);
      expect(index100).toBe(100);
    });

    it('should return -1 for unknown word', () => {
      const index = getWordIndex('notavalidword');
      expect(index).toBe(-1);
    });

    it('should contain only lowercase words', () => {
      const wordList = getBip39WordList();
      for (const word of wordList) {
        expect(word).toBe(word.toLowerCase());
      }
    });
  });
});
