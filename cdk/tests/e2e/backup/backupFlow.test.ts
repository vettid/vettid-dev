/**
 * E2E Tests: Backup Flow
 *
 * End-to-end tests for complete backup scenarios:
 * - Create → list → verify → delete
 * - Create → corrupt → restore fails
 * - Create → restore → verify state
 * - Auto backup → retention cleanup
 * - Credential backup → recovery phrase → recover
 *
 * @see lambda/handlers/vault/backup.ts (pending implementation)
 */

import {
  MockBackupService,
  MockS3Storage,
  createTestMemberKey,
  corruptBackupData,
  generateRecoveryPhrase,
  BackupContents,
} from '../../fixtures/backup/mockBackup';
import * as crypto from 'crypto';

// ============================================
// Tests
// ============================================

describe('Backup Flow E2E', () => {
  let backupService: MockBackupService;
  let storage: MockS3Storage;

  beforeEach(() => {
    storage = new MockS3Storage();
    backupService = new MockBackupService(storage);
  });

  afterEach(() => {
    backupService.clear();
  });

  it('should complete: create backup → list → verify → delete', async () => {
    // Setup
    const memberId = 'member-flow-1';
    const memberKey = createTestMemberKey();
    backupService.setMemberKey(memberId, memberKey);

    // Step 1: Create backup
    const createResult = await backupService.createBackup(memberId, 'manual', {
      vault_state: {
        version: 1,
        initialized_at: new Date().toISOString(),
        last_modified: new Date().toISOString(),
        settings: { theme: 'dark', language: 'en' },
      },
      handler_configs: [
        { handler_id: 'h1', handler_type: 'email', config: {}, enabled: true },
      ],
    });

    expect(createResult.success).toBe(true);
    const backupId = createResult.backup!.backup_id;

    // Step 2: List backups
    const listResult = await backupService.listBackups(memberId);

    expect(listResult.total).toBe(1);
    expect(listResult.backups[0].backup_id).toBe(backupId);

    // Step 3: Verify backup metadata
    const backup = await backupService.getBackup(backupId, memberId);

    expect(backup).toBeDefined();
    expect(backup?.status).toBe('complete');
    expect(backup?.checksum).toBeDefined();
    expect(backup?.encryption_metadata.algorithm).toBe('XChaCha20-Poly1305');

    // Step 4: Create second backup (so we can delete first)
    await backupService.createBackup(memberId, 'manual');

    // Step 5: Delete first backup
    const deleteResult = await backupService.deleteBackup(memberId, backupId);

    expect(deleteResult.success).toBe(true);

    // Step 6: Verify deleted
    const listAfter = await backupService.listBackups(memberId);
    expect(listAfter.total).toBe(1);
    expect(listAfter.backups.map(b => b.backup_id)).not.toContain(backupId);
  });

  it('should complete: create backup → corrupt → restore fails', async () => {
    // Setup
    const memberId = 'member-flow-2';
    const memberKey = createTestMemberKey();
    backupService.setMemberKey(memberId, memberKey);

    // Step 1: Create backup
    const createResult = await backupService.createBackup(memberId, 'manual', {
      vault_state: {
        version: 5,
        initialized_at: new Date().toISOString(),
        last_modified: new Date().toISOString(),
        settings: { important: 'data' },
      },
    });

    expect(createResult.success).toBe(true);
    const backupId = createResult.backup!.backup_id;

    // Step 2: Corrupt the backup in S3
    const s3Key = `${memberId}/${backupId}.backup`;
    const stored = await storage.getObject('vettid-backups', s3Key);
    const corrupted = corruptBackupData(stored!.data);
    await storage.putObject('vettid-backups', s3Key, corrupted, stored!.metadata);

    // Step 3: Attempt restore
    const restoreResult = await backupService.restoreBackup(memberId, backupId);

    // Step 4: Verify restore fails
    expect(restoreResult.success).toBe(false);
    expect(restoreResult.error).toBeDefined();
  });

  it('should complete: create backup → restore → verify state', async () => {
    // Setup
    const memberId = 'member-flow-3';
    const memberKey = createTestMemberKey();
    backupService.setMemberKey(memberId, memberKey);

    const originalContents: Partial<BackupContents> = {
      vault_state: {
        version: 10,
        initialized_at: '2024-01-01T00:00:00Z',
        last_modified: '2024-06-15T12:00:00Z',
        settings: {
          theme: 'light',
          notifications: true,
          autoLock: 300,
        },
      },
      handler_configs: [
        { handler_id: 'email-handler', handler_type: 'email', config: { verified: true }, enabled: true },
        { handler_id: 'sms-handler', handler_type: 'sms', config: { phone: '+1234567890' }, enabled: false },
      ],
      connection_keys: [
        {
          connection_id: 'conn-abc123',
          peer_id: 'peer-xyz789',
          shared_key_encrypted: crypto.randomBytes(32).toString('base64'),
          created_at: '2024-03-01T00:00:00Z',
        },
      ],
      message_history: {
        encrypted_data: crypto.randomBytes(500).toString('base64'),
        message_count: 42,
        date_range: {
          from: '2024-01-01T00:00:00Z',
          to: '2024-06-15T00:00:00Z',
        },
      },
    };

    // Step 1: Create backup with specific content
    const createResult = await backupService.createBackup(memberId, 'manual', originalContents);

    expect(createResult.success).toBe(true);
    const backupId = createResult.backup!.backup_id;

    // Step 2: Restore backup
    const restoreResult = await backupService.restoreBackup(memberId, backupId);

    expect(restoreResult.success).toBe(true);

    // Step 3: Verify restored state
    expect(restoreResult.items_restored).toEqual({
      vault_state: true,
      handler_configs: 2,
      connection_keys: 1,
      messages: 42,
    });

    // Step 4: Verify backup still exists (restore doesn't delete)
    const backup = await backupService.getBackup(backupId, memberId);
    expect(backup).toBeDefined();
  });

  it('should complete: auto backup → retention cleanup', async () => {
    // Setup
    const memberId = 'member-flow-4';
    const memberKey = createTestMemberKey();
    backupService.setMemberKey(memberId, memberKey);

    // Step 1: Configure retention
    await backupService.updateSettings(memberId, {
      auto_backup_enabled: true,
      retention_daily: 2,
      retention_weekly: 0,
      retention_monthly: 0,
    });

    // Step 2: Create multiple manual backups (simulating auto backups over time)
    for (let i = 0; i < 5; i++) {
      await backupService.createBackup(memberId, 'manual');
    }

    // Verify we have 5 backups
    const listBefore = await backupService.listBackups(memberId);
    expect(listBefore.total).toBe(5);

    // Step 3: Apply retention policy
    const retentionResult = await backupService.applyRetentionPolicy(memberId);

    // Step 4: Verify cleanup
    expect(retentionResult.retained.length).toBe(2); // retention_daily = 2
    expect(retentionResult.deleted.length).toBe(3);

    // Step 5: Verify only 2 remain
    const listAfter = await backupService.listBackups(memberId);
    expect(listAfter.total).toBe(2);
  });

  it('should complete: credential backup → recovery phrase → recover', async () => {
    // Setup
    const memberId = 'member-flow-5';
    const memberKey = createTestMemberKey();
    backupService.setMemberKey(memberId, memberKey);

    // Step 1: Create credential backup
    const backupResult = await backupService.createCredentialBackup(memberId);

    expect(backupResult.success).toBe(true);
    expect(backupResult.recoveryPhrase).toHaveLength(24);

    const recoveryPhrase = backupResult.recoveryPhrase!;

    // Step 2: Verify backup status
    const status = await backupService.getCredentialBackupStatus(memberId);

    expect(status.exists).toBe(true);
    expect(status.lastBackup).toBeDefined();

    // Step 3: Recover using phrase
    const recoverResult = await backupService.recoverCredentials(memberId, recoveryPhrase);

    expect(recoverResult.success).toBe(true);
    expect(recoverResult.memberKey).toBeDefined();

    // Step 4: Verify recovered key matches original
    expect(recoverResult.memberKey!.equals(memberKey)).toBe(true);
  });

  describe('Complex Scenarios', () => {
    it('should handle multiple members with independent backups', async () => {
      const member1 = 'member-multi-1';
      const member2 = 'member-multi-2';
      const member3 = 'member-multi-3';

      backupService.setMemberKey(member1, createTestMemberKey());
      backupService.setMemberKey(member2, createTestMemberKey());
      backupService.setMemberKey(member3, createTestMemberKey());

      // Each member creates backups
      await backupService.createBackup(member1, 'manual');
      await backupService.createBackup(member1, 'manual');
      await backupService.createBackup(member2, 'manual');
      await backupService.createBackup(member3, 'manual');
      await backupService.createBackup(member3, 'manual');
      await backupService.createBackup(member3, 'manual');

      // Verify isolation
      const list1 = await backupService.listBackups(member1);
      const list2 = await backupService.listBackups(member2);
      const list3 = await backupService.listBackups(member3);

      expect(list1.total).toBe(2);
      expect(list2.total).toBe(1);
      expect(list3.total).toBe(3);

      // Retention for one doesn't affect others
      await backupService.updateSettings(member3, { retention_daily: 1 });
      await backupService.applyRetentionPolicy(member3);

      // member3 reduced to 1, others unchanged
      expect((await backupService.listBackups(member1)).total).toBe(2);
      expect((await backupService.listBackups(member2)).total).toBe(1);
      expect((await backupService.listBackups(member3)).total).toBe(1);
    });

    it('should handle backup and credential backup together', async () => {
      const memberId = 'member-combined';
      const memberKey = createTestMemberKey();
      backupService.setMemberKey(memberId, memberKey);

      // Create vault backup
      const vaultBackup = await backupService.createBackup(memberId, 'manual', {
        vault_state: {
          version: 1,
          initialized_at: new Date().toISOString(),
          last_modified: new Date().toISOString(),
          settings: { data: 'vault-data' },
        },
      });

      // Create credential backup
      const credBackup = await backupService.createCredentialBackup(memberId);

      expect(vaultBackup.success).toBe(true);
      expect(credBackup.success).toBe(true);

      // Both exist independently
      const vaultList = await backupService.listBackups(memberId);
      const credStatus = await backupService.getCredentialBackupStatus(memberId);

      expect(vaultList.total).toBe(1);
      expect(credStatus.exists).toBe(true);

      // Can restore vault backup
      const restoreResult = await backupService.restoreBackup(
        memberId,
        vaultBackup.backup!.backup_id
      );
      expect(restoreResult.success).toBe(true);

      // Can recover credentials
      const recoverResult = await backupService.recoverCredentials(
        memberId,
        credBackup.recoveryPhrase!
      );
      expect(recoverResult.success).toBe(true);
    });

    it('should handle backup → key change → restore with old key fails', async () => {
      const memberId = 'member-keychange';
      const originalKey = createTestMemberKey();
      backupService.setMemberKey(memberId, originalKey);

      // Create backup with original key
      const createResult = await backupService.createBackup(memberId, 'manual');
      const backupId = createResult.backup!.backup_id;

      // Simulate key rotation - new key
      const newKey = createTestMemberKey();
      backupService.setMemberKey(memberId, newKey);

      // Try to restore with new key
      const restoreResult = await backupService.restoreBackup(memberId, backupId);

      // Should fail because encryption key changed
      expect(restoreResult.success).toBe(false);
    });

    it('should handle full backup lifecycle: configure → backup → list → restore → delete', async () => {
      const memberId = 'member-lifecycle';
      const memberKey = createTestMemberKey();
      backupService.setMemberKey(memberId, memberKey);

      // Step 1: Configure settings
      await backupService.updateSettings(memberId, {
        auto_backup_enabled: true,
        backup_frequency: 'daily',
        backup_time: '03:00',
        retention_daily: 5,
      });

      // Step 2: Create backups
      const backup1 = await backupService.createBackup(memberId, 'manual');
      const backup2 = await backupService.createBackup(memberId, 'manual');

      // Step 3: List and verify
      const list = await backupService.listBackups(memberId);
      expect(list.total).toBe(2);

      // Step 4: Restore from backup1
      const restoreResult = await backupService.restoreBackup(
        memberId,
        backup1.backup!.backup_id
      );
      expect(restoreResult.success).toBe(true);

      // Step 5: Delete backup2
      const deleteResult = await backupService.deleteBackup(
        memberId,
        backup2.backup!.backup_id
      );
      expect(deleteResult.success).toBe(true);

      // Final state: 1 backup remaining
      const finalList = await backupService.listBackups(memberId);
      expect(finalList.total).toBe(1);
    });
  });

  describe('Error Recovery', () => {
    it('should handle S3 unavailable during backup', async () => {
      const memberId = 'member-s3fail';
      const memberKey = createTestMemberKey();
      backupService.setMemberKey(memberId, memberKey);

      // First backup succeeds
      const result1 = await backupService.createBackup(memberId, 'manual');
      expect(result1.success).toBe(true);

      // Clear storage to simulate S3 issues
      storage.clear('vettid-backups');

      // Restore should fail (data missing)
      const restoreResult = await backupService.restoreBackup(
        memberId,
        result1.backup!.backup_id
      );
      expect(restoreResult.success).toBe(false);
    });

    it('should handle concurrent operations gracefully', async () => {
      const memberId = 'member-concurrent';
      const memberKey = createTestMemberKey();
      backupService.setMemberKey(memberId, memberKey);

      // Concurrent backups
      const backupPromises = Array(5).fill(null).map(() =>
        backupService.createBackup(memberId, 'manual')
      );

      const backupResults = await Promise.all(backupPromises);
      expect(backupResults.every(r => r.success)).toBe(true);

      // Concurrent listings
      const listPromises = Array(5).fill(null).map(() =>
        backupService.listBackups(memberId)
      );

      const listResults = await Promise.all(listPromises);
      expect(listResults.every(r => r.total === 5)).toBe(true);
    });
  });
});
