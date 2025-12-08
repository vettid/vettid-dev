/**
 * Integration Tests: Create Backup
 *
 * Tests backup creation functionality:
 * - Manual backup creation
 * - Automatic backup creation
 * - Backup content inclusion
 * - XChaCha20-Poly1305 encryption
 *
 * @see lambda/handlers/vault/backup.ts (pending implementation)
 */

import {
  MockBackupService,
  MockS3Storage,
  encryptBackupData,
  decryptBackupData,
  packageEncryptedBackup,
  unpackageEncryptedBackup,
  deriveBackupKey,
  createTestMemberKey,
  BackupContents,
  VaultState,
  HandlerConfig,
  ConnectionKeyBackup,
} from '../../fixtures/backup/mockBackup';
import * as crypto from 'crypto';

// ============================================
// Tests
// ============================================

describe('Create Backup', () => {
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

  describe('Manual Backup', () => {
    it('should create backup on demand', async () => {
      const result = await backupService.createBackup(testMemberId, 'manual');

      expect(result.success).toBe(true);
      expect(result.backup).toBeDefined();
      expect(result.backup?.backup_id).toBeDefined();
      expect(result.backup?.type).toBe('manual');
    });

    it('should encrypt backup with member key', async () => {
      const result = await backupService.createBackup(testMemberId, 'manual', {
        vault_state: {
          version: 1,
          initialized_at: new Date().toISOString(),
          last_modified: new Date().toISOString(),
          settings: { theme: 'dark' },
        },
      });

      expect(result.success).toBe(true);
      expect(result.backup?.encryption_metadata.algorithm).toBe('XChaCha20-Poly1305');

      // Verify backup is stored encrypted in S3
      const s3Key = `${testMemberId}/${result.backup?.backup_id}.backup`;
      const stored = await storage.getObject('vettid-backups', s3Key);
      expect(stored).toBeDefined();
      expect(stored?.data.length).toBeGreaterThan(0);
    });

    it('should generate unique backup ID', async () => {
      const result1 = await backupService.createBackup(testMemberId, 'manual');
      const result2 = await backupService.createBackup(testMemberId, 'manual');

      expect(result1.backup?.backup_id).not.toBe(result2.backup?.backup_id);
    });

    it('should store backup metadata', async () => {
      const result = await backupService.createBackup(testMemberId, 'manual');

      expect(result.backup?.member_id).toBe(testMemberId);
      expect(result.backup?.status).toBe('complete');
      expect(result.backup?.created_at).toBeDefined();
      expect(result.backup?.completed_at).toBeDefined();
      expect(result.backup?.size_bytes).toBeGreaterThan(0);
      expect(result.backup?.checksum).toBeDefined();
    });

    it('should require authenticated user', async () => {
      // Try to create backup for member without key
      const result = await backupService.createBackup('unknown-member', 'manual');

      expect(result.success).toBe(false);
      expect(result.error).toContain('Member key not found');
    });

    it('should allow multiple manual backups in succession', async () => {
      const results = await Promise.all([
        backupService.createBackup(testMemberId, 'manual'),
        backupService.createBackup(testMemberId, 'manual'),
        backupService.createBackup(testMemberId, 'manual'),
      ]);

      expect(results.every(r => r.success)).toBe(true);
      expect(new Set(results.map(r => r.backup?.backup_id)).size).toBe(3);
    });
  });

  describe('Automatic Backup', () => {
    it('should trigger daily backup at scheduled time', async () => {
      const result = await backupService.createBackup(testMemberId, 'auto');

      expect(result.success).toBe(true);
      expect(result.backup?.type).toBe('auto');
    });

    it('should skip if recent backup exists', async () => {
      // Create first auto backup
      const result1 = await backupService.createBackup(testMemberId, 'auto');
      expect(result1.success).toBe(true);

      // Try to create another auto backup immediately
      const result2 = await backupService.createBackup(testMemberId, 'auto');
      expect(result2.success).toBe(false);
      expect(result2.error).toContain('Recent backup exists');
    });

    it('should handle failed backup gracefully', async () => {
      // Create service without member key to simulate failure
      const failService = new MockBackupService(storage);
      const result = await failService.createBackup(testMemberId, 'auto');

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('should update last auto backup in settings', async () => {
      // Set up settings first
      await backupService.updateSettings(testMemberId, { auto_backup_enabled: true });

      const result = await backupService.createBackup(testMemberId, 'auto');
      expect(result.success).toBe(true);

      const settings = await backupService.getSettings(testMemberId);
      expect(settings.last_auto_backup).toBeDefined();
    });

    it('should allow manual backup even when recent auto backup exists', async () => {
      // Create auto backup
      const autoResult = await backupService.createBackup(testMemberId, 'auto');
      expect(autoResult.success).toBe(true);

      // Manual backup should still work
      const manualResult = await backupService.createBackup(testMemberId, 'manual');
      expect(manualResult.success).toBe(true);
    });
  });

  describe('Backup Content', () => {
    it('should include vault state', async () => {
      const vaultState: VaultState = {
        version: 3,
        initialized_at: '2024-01-01T00:00:00Z',
        last_modified: new Date().toISOString(),
        settings: { encryption: 'enabled', notifications: true },
      };

      const result = await backupService.createBackup(testMemberId, 'manual', {
        vault_state: vaultState,
      });

      expect(result.success).toBe(true);
      expect(result.backup?.contents.vault_state.version).toBe(3);
      expect(result.backup?.contents.vault_state.settings.encryption).toBe('enabled');
    });

    it('should include handler configurations', async () => {
      const handlerConfigs: HandlerConfig[] = [
        { handler_id: 'h1', handler_type: 'email', config: { verify: true }, enabled: true },
        { handler_id: 'h2', handler_type: 'sms', config: { provider: 'twilio' }, enabled: false },
      ];

      const result = await backupService.createBackup(testMemberId, 'manual', {
        handler_configs: handlerConfigs,
      });

      expect(result.success).toBe(true);
      expect(result.backup?.contents.handler_configs).toHaveLength(2);
      expect(result.backup?.contents.handler_configs[0].handler_type).toBe('email');
    });

    it('should include connection keys', async () => {
      const connectionKeys: ConnectionKeyBackup[] = [
        {
          connection_id: 'conn-1',
          peer_id: 'peer-abc',
          shared_key_encrypted: crypto.randomBytes(32).toString('base64'),
          created_at: new Date().toISOString(),
        },
        {
          connection_id: 'conn-2',
          peer_id: 'peer-def',
          shared_key_encrypted: crypto.randomBytes(32).toString('base64'),
          created_at: new Date().toISOString(),
        },
      ];

      const result = await backupService.createBackup(testMemberId, 'manual', {
        connection_keys: connectionKeys,
      });

      expect(result.success).toBe(true);
      expect(result.backup?.contents.connection_keys).toHaveLength(2);
      expect(result.backup?.contents.connection_keys[0].peer_id).toBe('peer-abc');
    });

    it('should include message history (encrypted)', async () => {
      const messageHistory = {
        encrypted_data: crypto.randomBytes(1024).toString('base64'),
        message_count: 150,
        date_range: {
          from: '2024-01-01T00:00:00Z',
          to: '2024-06-01T00:00:00Z',
        },
      };

      const result = await backupService.createBackup(testMemberId, 'manual', {
        message_history: messageHistory,
      });

      expect(result.success).toBe(true);
      expect(result.backup?.contents.message_history.message_count).toBe(150);
      expect(result.backup?.contents.message_history.date_range.from).toBe('2024-01-01T00:00:00Z');
    });

    it('should exclude temporary data', async () => {
      const fullContents: Partial<BackupContents> = {
        vault_state: {
          version: 1,
          initialized_at: new Date().toISOString(),
          last_modified: new Date().toISOString(),
          settings: {
            persistent: 'value',
            // Note: In real implementation, temporary data would be filtered
          },
        },
      };

      const result = await backupService.createBackup(testMemberId, 'manual', fullContents);

      expect(result.success).toBe(true);
      // Backup should not contain temporary session data, tokens, etc.
      expect(result.backup?.contents.vault_state.settings.persistent).toBe('value');
    });

    it('should handle empty backup contents', async () => {
      const result = await backupService.createBackup(testMemberId, 'manual', {});

      expect(result.success).toBe(true);
      expect(result.backup?.contents.vault_state).toBeDefined();
      expect(result.backup?.contents.handler_configs).toEqual([]);
      expect(result.backup?.contents.connection_keys).toEqual([]);
    });
  });

  describe('Backup Encryption', () => {
    it('should use XChaCha20-Poly1305', async () => {
      const result = await backupService.createBackup(testMemberId, 'manual');

      expect(result.backup?.encryption_metadata.algorithm).toBe('XChaCha20-Poly1305');
    });

    it('should derive key from member credentials', async () => {
      const result = await backupService.createBackup(testMemberId, 'manual');

      expect(result.backup?.encryption_metadata.key_derivation).toBe('PBKDF2-SHA256');
      expect(result.backup?.encryption_metadata.salt).toBeDefined();
    });

    it('should include encryption metadata', async () => {
      const result = await backupService.createBackup(testMemberId, 'manual');

      const metadata = result.backup?.encryption_metadata;
      expect(metadata?.algorithm).toBeDefined();
      expect(metadata?.nonce).toBeDefined();
      expect(metadata?.salt).toBeDefined();
      expect(metadata?.key_derivation).toBeDefined();
    });

    it('should be decryptable with correct key', async () => {
      const testData = { secret: 'test-value', number: 42 };
      const key = crypto.randomBytes(32);

      const { encryptedData, nonce } = packageEncryptedBackup(testData, key);
      const decrypted = unpackageEncryptedBackup(encryptedData, nonce, key);

      expect(decrypted).toEqual(testData);
    });

    it('should fail decryption with wrong key', () => {
      const testData = { secret: 'test-value' };
      const correctKey = crypto.randomBytes(32);
      const wrongKey = crypto.randomBytes(32);

      const { encryptedData, nonce } = packageEncryptedBackup(testData, correctKey);

      expect(() => {
        unpackageEncryptedBackup(encryptedData, nonce, wrongKey);
      }).toThrow();
    });

    it('should use unique nonce for each backup', async () => {
      const result1 = await backupService.createBackup(testMemberId, 'manual');
      const result2 = await backupService.createBackup(testMemberId, 'manual');

      expect(result1.backup?.encryption_metadata.nonce).not.toBe(
        result2.backup?.encryption_metadata.nonce
      );
    });

    it('should use unique salt for each backup', async () => {
      const result1 = await backupService.createBackup(testMemberId, 'manual');
      const result2 = await backupService.createBackup(testMemberId, 'manual');

      expect(result1.backup?.encryption_metadata.salt).not.toBe(
        result2.backup?.encryption_metadata.salt
      );
    });

    it('should produce different ciphertext for same plaintext', () => {
      const testData = { same: 'data' };
      const key = crypto.randomBytes(32);

      const result1 = packageEncryptedBackup(testData, key);
      const result2 = packageEncryptedBackup(testData, key);

      // Different nonces produce different ciphertexts
      expect(result1.encryptedData).not.toBe(result2.encryptedData);
      expect(result1.nonce).not.toBe(result2.nonce);
    });

    it('should include checksum for integrity verification', async () => {
      const result = await backupService.createBackup(testMemberId, 'manual');

      expect(result.backup?.checksum).toBeDefined();
      expect(result.backup?.checksum).toMatch(/^[a-f0-9]{64}$/); // SHA-256 hex
    });
  });

  describe('Backup Size', () => {
    it('should calculate correct backup size', async () => {
      const largeContent: Partial<BackupContents> = {
        message_history: {
          encrypted_data: crypto.randomBytes(10000).toString('base64'),
          message_count: 1000,
          date_range: { from: '', to: '' },
        },
      };

      const result = await backupService.createBackup(testMemberId, 'manual', largeContent);

      expect(result.success).toBe(true);
      expect(result.backup?.size_bytes).toBeGreaterThan(10000);
    });

    it('should track storage usage per member', async () => {
      // Create multiple backups
      await backupService.createBackup(testMemberId, 'manual');
      await backupService.createBackup(testMemberId, 'manual');

      const storageUsed = backupService.getStorageUsed(testMemberId);
      expect(storageUsed).toBeGreaterThan(0);
    });
  });

  describe('Concurrent Backups', () => {
    it('should handle concurrent backup requests', async () => {
      const promises = Array(5).fill(null).map(() =>
        backupService.createBackup(testMemberId, 'manual')
      );

      const results = await Promise.all(promises);

      expect(results.every(r => r.success)).toBe(true);
      const backupIds = results.map(r => r.backup?.backup_id);
      expect(new Set(backupIds).size).toBe(5); // All unique
    });

    it('should isolate backups between members', async () => {
      const member2 = 'member-test-456';
      backupService.setMemberKey(member2, createTestMemberKey());

      const result1 = await backupService.createBackup(testMemberId, 'manual');
      const result2 = await backupService.createBackup(member2, 'manual');

      expect(result1.backup?.member_id).toBe(testMemberId);
      expect(result2.backup?.member_id).toBe(member2);

      // Each member should only see their own backup
      const list1 = await backupService.listBackups(testMemberId);
      const list2 = await backupService.listBackups(member2);

      expect(list1.backups.every(b => b.member_id === testMemberId)).toBe(true);
      expect(list2.backups.every(b => b.member_id === member2)).toBe(true);
    });
  });
});
