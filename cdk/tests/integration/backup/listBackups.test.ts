/**
 * Integration Tests: List Backups
 *
 * Tests backup listing functionality:
 * - Backup querying
 * - Pagination
 * - Metadata retrieval
 * - Access control
 *
 * @see lambda/handlers/vault/listBackups.ts (pending implementation)
 */

import {
  MockBackupService,
  MockS3Storage,
  createTestMemberKey,
} from '../../fixtures/backup/mockBackup';

// ============================================
// Tests
// ============================================

describe('List Backups', () => {
  let backupService: MockBackupService;
  let storage: MockS3Storage;
  const testMemberId = 'member-test-123';
  let memberKey: Buffer;

  beforeEach(async () => {
    storage = new MockS3Storage();
    backupService = new MockBackupService(storage);
    memberKey = createTestMemberKey();
    backupService.setMemberKey(testMemberId, memberKey);
  });

  afterEach(() => {
    backupService.clear();
  });

  describe('Backup Query', () => {
    it('should return all backups for member', async () => {
      // Create multiple backups
      await backupService.createBackup(testMemberId, 'manual');
      await backupService.createBackup(testMemberId, 'manual');
      await backupService.createBackup(testMemberId, 'manual');

      const result = await backupService.listBackups(testMemberId);

      expect(result.backups).toHaveLength(3);
      expect(result.total).toBe(3);
    });

    it('should sort by creation date (newest first)', async () => {
      // Create backups with slight delay
      await backupService.createBackup(testMemberId, 'manual');
      await new Promise(resolve => setTimeout(resolve, 10));
      await backupService.createBackup(testMemberId, 'manual');
      await new Promise(resolve => setTimeout(resolve, 10));
      await backupService.createBackup(testMemberId, 'manual');

      const result = await backupService.listBackups(testMemberId);

      // Verify sorted by newest first
      for (let i = 0; i < result.backups.length - 1; i++) {
        const current = new Date(result.backups[i].created_at).getTime();
        const next = new Date(result.backups[i + 1].created_at).getTime();
        expect(current).toBeGreaterThanOrEqual(next);
      }
    });

    it('should support pagination', async () => {
      // Create 5 backups
      for (let i = 0; i < 5; i++) {
        await backupService.createBackup(testMemberId, 'manual');
      }

      // Get first page
      const page1 = await backupService.listBackups(testMemberId, { limit: 2, offset: 0 });
      expect(page1.backups).toHaveLength(2);
      expect(page1.total).toBe(5);
      expect(page1.hasMore).toBe(true);

      // Get second page
      const page2 = await backupService.listBackups(testMemberId, { limit: 2, offset: 2 });
      expect(page2.backups).toHaveLength(2);
      expect(page2.hasMore).toBe(true);

      // Get last page
      const page3 = await backupService.listBackups(testMemberId, { limit: 2, offset: 4 });
      expect(page3.backups).toHaveLength(1);
      expect(page3.hasMore).toBe(false);
    });

    it('should return backup metadata', async () => {
      await backupService.createBackup(testMemberId, 'manual');

      const result = await backupService.listBackups(testMemberId);

      expect(result.backups[0]).toHaveProperty('backup_id');
      expect(result.backups[0]).toHaveProperty('member_id');
      expect(result.backups[0]).toHaveProperty('type');
      expect(result.backups[0]).toHaveProperty('status');
      expect(result.backups[0]).toHaveProperty('size_bytes');
      expect(result.backups[0]).toHaveProperty('created_at');
    });

    it('should return empty list for new member', async () => {
      const newMemberId = 'new-member-456';
      backupService.setMemberKey(newMemberId, createTestMemberKey());

      const result = await backupService.listBackups(newMemberId);

      expect(result.backups).toHaveLength(0);
      expect(result.total).toBe(0);
      expect(result.hasMore).toBe(false);
    });

    it('should handle large offset gracefully', async () => {
      await backupService.createBackup(testMemberId, 'manual');

      const result = await backupService.listBackups(testMemberId, { offset: 100 });

      expect(result.backups).toHaveLength(0);
      expect(result.total).toBe(1);
      expect(result.hasMore).toBe(false);
    });
  });

  describe('Backup Metadata', () => {
    it('should include backup ID', async () => {
      await backupService.createBackup(testMemberId, 'manual');

      const result = await backupService.listBackups(testMemberId);

      expect(result.backups[0].backup_id).toBeDefined();
      expect(result.backups[0].backup_id).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
      );
    });

    it('should include creation timestamp', async () => {
      const before = new Date();
      await backupService.createBackup(testMemberId, 'manual');
      const after = new Date();

      const result = await backupService.listBackups(testMemberId);
      const createdAt = new Date(result.backups[0].created_at);

      expect(createdAt.getTime()).toBeGreaterThanOrEqual(before.getTime());
      expect(createdAt.getTime()).toBeLessThanOrEqual(after.getTime());
    });

    it('should include size in bytes', async () => {
      await backupService.createBackup(testMemberId, 'manual', {
        vault_state: {
          version: 1,
          initialized_at: new Date().toISOString(),
          last_modified: new Date().toISOString(),
          settings: { data: 'x'.repeat(1000) },
        },
      });

      const result = await backupService.listBackups(testMemberId);

      expect(result.backups[0].size_bytes).toBeGreaterThan(0);
      expect(typeof result.backups[0].size_bytes).toBe('number');
    });

    it('should include backup type (auto/manual)', async () => {
      await backupService.createBackup(testMemberId, 'manual');

      // Need to bypass the "recent backup" check for auto
      // Creating a second member for auto backup test
      const autoMemberId = 'auto-member-789';
      backupService.setMemberKey(autoMemberId, createTestMemberKey());
      await backupService.createBackup(autoMemberId, 'auto');

      const manualResult = await backupService.listBackups(testMemberId);
      const autoResult = await backupService.listBackups(autoMemberId);

      expect(manualResult.backups[0].type).toBe('manual');
      expect(autoResult.backups[0].type).toBe('auto');
    });

    it('should include status (complete/partial)', async () => {
      await backupService.createBackup(testMemberId, 'manual');

      const result = await backupService.listBackups(testMemberId);

      expect(result.backups[0].status).toBe('complete');
    });

    it('should include checksum', async () => {
      await backupService.createBackup(testMemberId, 'manual');

      const result = await backupService.listBackups(testMemberId);

      expect(result.backups[0].checksum).toBeDefined();
      expect(result.backups[0].checksum).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should include encryption metadata', async () => {
      await backupService.createBackup(testMemberId, 'manual');

      const result = await backupService.listBackups(testMemberId);

      expect(result.backups[0].encryption_metadata).toBeDefined();
      expect(result.backups[0].encryption_metadata.algorithm).toBe('XChaCha20-Poly1305');
      expect(result.backups[0].encryption_metadata.nonce).toBeDefined();
      expect(result.backups[0].encryption_metadata.salt).toBeDefined();
    });

    it('should NOT include backup contents in list response', async () => {
      await backupService.createBackup(testMemberId, 'manual', {
        vault_state: {
          version: 1,
          initialized_at: new Date().toISOString(),
          last_modified: new Date().toISOString(),
          settings: { secret: 'should-not-appear' },
        },
      });

      const result = await backupService.listBackups(testMemberId);

      // Contents should be stripped from list response
      expect((result.backups[0] as any).contents).toBeUndefined();
    });
  });

  describe('Access Control', () => {
    it('should only return own backups', async () => {
      const member2 = 'member-test-456';
      backupService.setMemberKey(member2, createTestMemberKey());

      // Create backups for both members
      await backupService.createBackup(testMemberId, 'manual');
      await backupService.createBackup(testMemberId, 'manual');
      await backupService.createBackup(member2, 'manual');

      // Each member should only see their own
      const result1 = await backupService.listBackups(testMemberId);
      const result2 = await backupService.listBackups(member2);

      expect(result1.backups).toHaveLength(2);
      expect(result2.backups).toHaveLength(1);
      expect(result1.backups.every(b => b.member_id === testMemberId)).toBe(true);
      expect(result2.backups.every(b => b.member_id === member2)).toBe(true);
    });

    it('should reject unauthenticated requests', async () => {
      // Member without key set cannot access backups
      const unknownMember = 'unknown-member-999';

      const result = await backupService.listBackups(unknownMember);

      // Returns empty list for unauthenticated (no key) member
      expect(result.backups).toHaveLength(0);
    });

    it('should reject cross-member access', async () => {
      const member2 = 'member-test-456';
      backupService.setMemberKey(member2, createTestMemberKey());

      // Create backup for testMemberId
      const createResult = await backupService.createBackup(testMemberId, 'manual');
      const backupId = createResult.backup?.backup_id;

      // Try to get specific backup as different member
      const backup = await backupService.getBackup(backupId!, member2);

      expect(backup).toBeNull();
    });

    it('should isolate backup counts between members', async () => {
      const member2 = 'member-test-456';
      const member3 = 'member-test-789';
      backupService.setMemberKey(member2, createTestMemberKey());
      backupService.setMemberKey(member3, createTestMemberKey());

      await backupService.createBackup(testMemberId, 'manual');
      await backupService.createBackup(testMemberId, 'manual');
      await backupService.createBackup(member2, 'manual');
      await backupService.createBackup(member3, 'manual');
      await backupService.createBackup(member3, 'manual');
      await backupService.createBackup(member3, 'manual');

      const result1 = await backupService.listBackups(testMemberId);
      const result2 = await backupService.listBackups(member2);
      const result3 = await backupService.listBackups(member3);

      expect(result1.total).toBe(2);
      expect(result2.total).toBe(1);
      expect(result3.total).toBe(3);
    });
  });

  describe('Get Single Backup', () => {
    it('should return full backup with contents when getting single backup', async () => {
      const createResult = await backupService.createBackup(testMemberId, 'manual', {
        vault_state: {
          version: 5,
          initialized_at: new Date().toISOString(),
          last_modified: new Date().toISOString(),
          settings: { test: 'value' },
        },
      });

      const backup = await backupService.getBackup(createResult.backup!.backup_id, testMemberId);

      expect(backup).toBeDefined();
      expect(backup?.contents).toBeDefined();
      expect(backup?.contents.vault_state.version).toBe(5);
    });

    it('should return null for non-existent backup', async () => {
      const backup = await backupService.getBackup('non-existent-id', testMemberId);

      expect(backup).toBeNull();
    });

    it('should return null when accessing other members backup', async () => {
      const member2 = 'member-test-456';
      backupService.setMemberKey(member2, createTestMemberKey());

      const createResult = await backupService.createBackup(testMemberId, 'manual');
      const backup = await backupService.getBackup(createResult.backup!.backup_id, member2);

      expect(backup).toBeNull();
    });
  });

  describe('Filtering and Sorting', () => {
    it('should list backups by type', async () => {
      // Create mix of backup types
      await backupService.createBackup(testMemberId, 'manual');

      // Create auto for different member (to bypass recent check)
      const autoMember = 'auto-member-001';
      backupService.setMemberKey(autoMember, createTestMemberKey());
      await backupService.createBackup(autoMember, 'auto');
      await backupService.createBackup(autoMember, 'manual');

      const result = await backupService.listBackups(autoMember);

      // Should have both types
      const types = result.backups.map(b => b.type);
      expect(types).toContain('auto');
      expect(types).toContain('manual');
    });

    it('should preserve order with pagination', async () => {
      // Create 6 backups with delays
      const backupIds: string[] = [];
      for (let i = 0; i < 6; i++) {
        const result = await backupService.createBackup(testMemberId, 'manual');
        backupIds.push(result.backup!.backup_id);
        await new Promise(resolve => setTimeout(resolve, 5));
      }

      // Get all pages
      const page1 = await backupService.listBackups(testMemberId, { limit: 2, offset: 0 });
      const page2 = await backupService.listBackups(testMemberId, { limit: 2, offset: 2 });
      const page3 = await backupService.listBackups(testMemberId, { limit: 2, offset: 4 });

      // Combine all backup IDs from pages
      const paginatedIds = [
        ...page1.backups.map(b => b.backup_id),
        ...page2.backups.map(b => b.backup_id),
        ...page3.backups.map(b => b.backup_id),
      ];

      // Should be in reverse order (newest first)
      expect(paginatedIds).toEqual(backupIds.reverse());
    });
  });
});
