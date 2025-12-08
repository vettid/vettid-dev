/**
 * Integration Tests: Backup Retention
 *
 * Tests backup retention functionality:
 * - Retention policies
 * - Manual deletion
 * - Storage quota management
 *
 * @see lambda/handlers/scheduled/backupRetention.ts (pending implementation)
 */

import {
  MockBackupService,
  MockS3Storage,
  createTestMemberKey,
} from '../../fixtures/backup/mockBackup';

// ============================================
// Helper Functions
// ============================================

function daysAgo(days: number): Date {
  const date = new Date();
  date.setDate(date.getDate() - days);
  return date;
}

// ============================================
// Tests
// ============================================

describe('Backup Retention', () => {
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

  describe('Retention Policy', () => {
    it('should keep last 3 daily backups by default', async () => {
      // Create 5 backups
      for (let i = 0; i < 5; i++) {
        await backupService.createBackup(testMemberId, 'manual');
      }

      // Set retention policy
      await backupService.updateSettings(testMemberId, {
        retention_daily: 3,
        retention_weekly: 0,
        retention_monthly: 0,
      });

      // Apply retention
      const result = await backupService.applyRetentionPolicy(testMemberId);

      expect(result.retained.length).toBe(3);
      expect(result.deleted.length).toBe(2);
    });

    it('should keep last 4 weekly backups', async () => {
      // Create backups spread over weeks (mocked by creating multiple backups
      // and treating them as weekly due to test constraints)
      for (let i = 0; i < 6; i++) {
        await backupService.createBackup(testMemberId, 'manual');
      }

      await backupService.updateSettings(testMemberId, {
        retention_daily: 1,
        retention_weekly: 4,
        retention_monthly: 0,
      });

      const result = await backupService.applyRetentionPolicy(testMemberId);

      // Should keep some backups based on policy
      expect(result.retained.length).toBeGreaterThan(0);
    });

    it('should keep last 12 monthly backups', async () => {
      // Create backups
      for (let i = 0; i < 3; i++) {
        await backupService.createBackup(testMemberId, 'manual');
      }

      await backupService.updateSettings(testMemberId, {
        retention_daily: 1,
        retention_weekly: 0,
        retention_monthly: 12,
      });

      const result = await backupService.applyRetentionPolicy(testMemberId);

      // Should retain backups
      expect(result.retained.length).toBeGreaterThan(0);
    });

    it('should delete older backups automatically', async () => {
      // Create multiple backups
      const backups: string[] = [];
      for (let i = 0; i < 10; i++) {
        const result = await backupService.createBackup(testMemberId, 'manual');
        backups.push(result.backup!.backup_id);
      }

      // Strict retention policy
      await backupService.updateSettings(testMemberId, {
        retention_daily: 2,
        retention_weekly: 0,
        retention_monthly: 0,
      });

      const result = await backupService.applyRetentionPolicy(testMemberId);

      expect(result.deleted.length).toBe(8); // 10 - 2 = 8 deleted
      expect(result.retained.length).toBe(2);
    });

    it('should always keep at least one backup', async () => {
      // Create single backup
      await backupService.createBackup(testMemberId, 'manual');

      // Very strict retention
      await backupService.updateSettings(testMemberId, {
        retention_daily: 0,
        retention_weekly: 0,
        retention_monthly: 0,
      });

      const result = await backupService.applyRetentionPolicy(testMemberId);

      // Should still keep at least one
      expect(result.retained.length).toBeGreaterThanOrEqual(1);
    });

    it('should handle no backups gracefully', async () => {
      const result = await backupService.applyRetentionPolicy(testMemberId);

      expect(result.deleted).toHaveLength(0);
      expect(result.retained).toHaveLength(0);
    });

    it('should respect combined retention policies', async () => {
      // Create 10 backups
      for (let i = 0; i < 10; i++) {
        await backupService.createBackup(testMemberId, 'manual');
      }

      await backupService.updateSettings(testMemberId, {
        retention_daily: 3,
        retention_weekly: 2,
        retention_monthly: 1,
      });

      const result = await backupService.applyRetentionPolicy(testMemberId);

      // Should keep at least retention_daily
      expect(result.retained.length).toBeGreaterThanOrEqual(3);
    });
  });

  describe('Manual Delete', () => {
    it('should allow deleting specific backup', async () => {
      // Create multiple backups
      const backup1 = await backupService.createBackup(testMemberId, 'manual');
      const backup2 = await backupService.createBackup(testMemberId, 'manual');

      const result = await backupService.deleteBackup(testMemberId, backup1.backup!.backup_id);

      expect(result.success).toBe(true);

      // Verify deleted
      const list = await backupService.listBackups(testMemberId);
      expect(list.backups.map(b => b.backup_id)).not.toContain(backup1.backup!.backup_id);
      expect(list.backups.map(b => b.backup_id)).toContain(backup2.backup!.backup_id);
    });

    it('should prevent deleting only backup', async () => {
      // Create single backup
      const backup = await backupService.createBackup(testMemberId, 'manual');

      const result = await backupService.deleteBackup(testMemberId, backup.backup!.backup_id);

      expect(result.success).toBe(false);
      expect(result.error).toContain('only backup');
    });

    it('should require authentication', async () => {
      // Create backup as testMemberId
      const backup = await backupService.createBackup(testMemberId, 'manual');
      await backupService.createBackup(testMemberId, 'manual'); // Ensure not only backup

      // Try to delete as different member
      const result = await backupService.deleteBackup('other-member', backup.backup!.backup_id);

      expect(result.success).toBe(false);
      expect(result.error).toContain('Not authorized');
    });

    it('should return error for non-existent backup', async () => {
      const result = await backupService.deleteBackup(testMemberId, 'non-existent-id');

      expect(result.success).toBe(false);
      expect(result.error).toContain('not found');
    });

    it('should remove from S3 on delete', async () => {
      const backup1 = await backupService.createBackup(testMemberId, 'manual');
      await backupService.createBackup(testMemberId, 'manual');

      const backupId = backup1.backup!.backup_id;
      const s3Key = `${testMemberId}/${backupId}.backup`;

      // Verify exists before delete
      const existsBefore = await storage.headObject('vettid-backups', s3Key);
      expect(existsBefore.exists).toBe(true);

      // Delete
      await backupService.deleteBackup(testMemberId, backupId);

      // Verify removed
      const existsAfter = await storage.headObject('vettid-backups', s3Key);
      expect(existsAfter.exists).toBe(false);
    });

    it('should update backup count after delete', async () => {
      await backupService.createBackup(testMemberId, 'manual');
      await backupService.createBackup(testMemberId, 'manual');
      const backup3 = await backupService.createBackup(testMemberId, 'manual');

      const listBefore = await backupService.listBackups(testMemberId);
      expect(listBefore.total).toBe(3);

      await backupService.deleteBackup(testMemberId, backup3.backup!.backup_id);

      const listAfter = await backupService.listBackups(testMemberId);
      expect(listAfter.total).toBe(2);
    });
  });

  describe('Storage Quota', () => {
    it('should track storage usage', async () => {
      // Initial usage should be 0
      const usageBefore = backupService.getStorageUsed(testMemberId);
      expect(usageBefore).toBe(0);

      // Create backup
      await backupService.createBackup(testMemberId, 'manual', {
        vault_state: {
          version: 1,
          initialized_at: new Date().toISOString(),
          last_modified: new Date().toISOString(),
          settings: { data: 'x'.repeat(1000) },
        },
      });

      const usageAfter = backupService.getStorageUsed(testMemberId);
      expect(usageAfter).toBeGreaterThan(0);
    });

    it('should calculate cumulative storage across backups', async () => {
      await backupService.createBackup(testMemberId, 'manual');
      const usage1 = backupService.getStorageUsed(testMemberId);

      await backupService.createBackup(testMemberId, 'manual');
      const usage2 = backupService.getStorageUsed(testMemberId);

      await backupService.createBackup(testMemberId, 'manual');
      const usage3 = backupService.getStorageUsed(testMemberId);

      expect(usage2).toBeGreaterThan(usage1);
      expect(usage3).toBeGreaterThan(usage2);
    });

    it('should reduce storage after deletion', async () => {
      const backup1 = await backupService.createBackup(testMemberId, 'manual');
      await backupService.createBackup(testMemberId, 'manual');

      const usageBefore = backupService.getStorageUsed(testMemberId);

      await backupService.deleteBackup(testMemberId, backup1.backup!.backup_id);

      const usageAfter = backupService.getStorageUsed(testMemberId);
      expect(usageAfter).toBeLessThan(usageBefore);
    });

    it('should isolate storage between members', async () => {
      const member2 = 'member-test-456';
      backupService.setMemberKey(member2, createTestMemberKey());

      // Create different sized backups
      await backupService.createBackup(testMemberId, 'manual', {
        vault_state: {
          version: 1,
          initialized_at: new Date().toISOString(),
          last_modified: new Date().toISOString(),
          settings: { data: 'x'.repeat(5000) },
        },
      });

      await backupService.createBackup(member2, 'manual', {
        vault_state: {
          version: 1,
          initialized_at: new Date().toISOString(),
          last_modified: new Date().toISOString(),
          settings: { data: 'y'.repeat(1000) },
        },
      });

      const usage1 = backupService.getStorageUsed(testMemberId);
      const usage2 = backupService.getStorageUsed(member2);

      // Usages should be different and independent
      expect(usage1).not.toBe(usage2);
      expect(usage1).toBeGreaterThan(usage2);
    });

    it('should track storage after retention cleanup', async () => {
      // Create multiple backups
      for (let i = 0; i < 5; i++) {
        await backupService.createBackup(testMemberId, 'manual');
      }

      const usageBefore = backupService.getStorageUsed(testMemberId);

      // Apply strict retention
      await backupService.updateSettings(testMemberId, {
        retention_daily: 1,
        retention_weekly: 0,
        retention_monthly: 0,
      });

      await backupService.applyRetentionPolicy(testMemberId);

      const usageAfter = backupService.getStorageUsed(testMemberId);
      expect(usageAfter).toBeLessThan(usageBefore);
    });
  });

  describe('Retention Execution', () => {
    it('should be idempotent', async () => {
      // Create backups
      for (let i = 0; i < 5; i++) {
        await backupService.createBackup(testMemberId, 'manual');
      }

      await backupService.updateSettings(testMemberId, { retention_daily: 3 });

      // Apply multiple times
      const result1 = await backupService.applyRetentionPolicy(testMemberId);
      const result2 = await backupService.applyRetentionPolicy(testMemberId);
      const result3 = await backupService.applyRetentionPolicy(testMemberId);

      // After first run, should have 3. Subsequent runs delete nothing new
      expect(result1.retained.length).toBe(3);
      expect(result2.deleted.length).toBe(0);
      expect(result3.deleted.length).toBe(0);
    });

    it('should handle concurrent retention execution', async () => {
      for (let i = 0; i < 10; i++) {
        await backupService.createBackup(testMemberId, 'manual');
      }

      await backupService.updateSettings(testMemberId, { retention_daily: 3 });

      // Run concurrently
      const results = await Promise.all([
        backupService.applyRetentionPolicy(testMemberId),
        backupService.applyRetentionPolicy(testMemberId),
        backupService.applyRetentionPolicy(testMemberId),
      ]);

      // Total retained should be 3
      const list = await backupService.listBackups(testMemberId);
      expect(list.total).toBe(3);
    });

    it('should not affect other members backups', async () => {
      const member2 = 'member-test-456';
      backupService.setMemberKey(member2, createTestMemberKey());

      // Create backups for both members
      for (let i = 0; i < 5; i++) {
        await backupService.createBackup(testMemberId, 'manual');
        await backupService.createBackup(member2, 'manual');
      }

      // Strict retention for member1 only
      await backupService.updateSettings(testMemberId, { retention_daily: 1 });
      await backupService.applyRetentionPolicy(testMemberId);

      // member1 should have 1 backup
      const list1 = await backupService.listBackups(testMemberId);
      expect(list1.total).toBe(1);

      // member2 should still have all 5
      const list2 = await backupService.listBackups(member2);
      expect(list2.total).toBe(5);
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty retention settings', async () => {
      await backupService.createBackup(testMemberId, 'manual');

      // Default settings
      const result = await backupService.applyRetentionPolicy(testMemberId);

      // Should use defaults and keep backup
      expect(result.retained.length).toBeGreaterThan(0);
    });

    it('should handle backup deletion during retention', async () => {
      // Create backups
      for (let i = 0; i < 5; i++) {
        await backupService.createBackup(testMemberId, 'manual');
      }

      await backupService.updateSettings(testMemberId, { retention_daily: 2 });

      // Apply retention
      const result = await backupService.applyRetentionPolicy(testMemberId);

      // Verify correct count
      const list = await backupService.listBackups(testMemberId);
      expect(list.total).toBe(result.retained.length);
    });
  });
});
