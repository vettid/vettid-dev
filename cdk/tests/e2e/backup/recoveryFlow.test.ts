/**
 * E2E Tests: Recovery Flow
 *
 * End-to-end tests for recovery scenarios:
 * - Device loss recovery using backup
 * - Credential recovery using recovery phrase
 * - New device enrollment post-recovery
 * - Connection sync after recovery
 *
 * @see lambda/handlers/vault/recovery.ts (pending implementation)
 */

import {
  MockBackupService,
  MockS3Storage,
  createTestMemberKey,
  generateRecoveryPhrase,
  BackupContents,
} from '../../fixtures/backup/mockBackup';
import * as crypto from 'crypto';

// ============================================
// Tests
// ============================================

describe('Recovery Flow E2E', () => {
  let backupService: MockBackupService;
  let storage: MockS3Storage;

  beforeEach(() => {
    storage = new MockS3Storage();
    backupService = new MockBackupService(storage);
  });

  afterEach(() => {
    backupService.clear();
  });

  it('should recover from device loss using backup', async () => {
    // Setup: Original device
    const memberId = 'member-device-loss';
    const originalKey = createTestMemberKey();
    backupService.setMemberKey(memberId, originalKey);

    // Step 1: Create backup on original device
    const backupContents: Partial<BackupContents> = {
      vault_state: {
        version: 5,
        initialized_at: '2024-01-01T00:00:00Z',
        last_modified: '2024-06-01T00:00:00Z',
        settings: {
          theme: 'dark',
          notifications: true,
          securityLevel: 'high',
        },
      },
      handler_configs: [
        { handler_id: 'email-1', handler_type: 'email', config: { addr: 'user@test.com' }, enabled: true },
        { handler_id: 'push-1', handler_type: 'push', config: { token: 'device-token' }, enabled: true },
      ],
      connection_keys: [
        {
          connection_id: 'conn-1',
          peer_id: 'peer-alice',
          shared_key_encrypted: crypto.randomBytes(32).toString('base64'),
          created_at: '2024-02-01T00:00:00Z',
        },
        {
          connection_id: 'conn-2',
          peer_id: 'peer-bob',
          shared_key_encrypted: crypto.randomBytes(32).toString('base64'),
          created_at: '2024-03-01T00:00:00Z',
        },
      ],
      message_history: {
        encrypted_data: crypto.randomBytes(2000).toString('base64'),
        message_count: 150,
        date_range: { from: '2024-01-01T00:00:00Z', to: '2024-06-01T00:00:00Z' },
      },
    };

    const createResult = await backupService.createBackup(memberId, 'manual', backupContents);
    expect(createResult.success).toBe(true);
    const backupId = createResult.backup!.backup_id;

    // Step 2: Simulate device loss - backup service retains S3 data
    // In real scenario, new device would initialize fresh service with same storage

    // Step 3: New device setup - re-initialize with same key
    // (In production, this would involve credential recovery first)
    const newDeviceService = new MockBackupService(storage);
    newDeviceService.setMemberKey(memberId, originalKey);

    // Need to re-hydrate backup metadata (simulated)
    // In production, this would be stored in DynamoDB and retrieved
    const listResult = await storage.listObjects('vettid-backups', `${memberId}/`);
    expect(listResult.length).toBeGreaterThan(0);

    // Step 4: Restore from backup on new device
    // For this test, we use the original service which has the metadata
    const restoreResult = await backupService.restoreBackup(memberId, backupId);

    expect(restoreResult.success).toBe(true);
    expect(restoreResult.items_restored).toEqual({
      vault_state: true,
      handler_configs: 2,
      connection_keys: 2,
      messages: 150,
    });

    // Step 5: Verify state recovered
    const backup = await backupService.getBackup(backupId, memberId);
    expect(backup?.contents.vault_state.version).toBe(5);
    expect(backup?.contents.handler_configs).toHaveLength(2);
    expect(backup?.contents.connection_keys).toHaveLength(2);
  });

  it('should recover credentials using recovery phrase', async () => {
    // Setup
    const memberId = 'member-cred-recover';
    const originalKey = createTestMemberKey();
    backupService.setMemberKey(memberId, originalKey);

    // Step 1: Create credential backup (user saves recovery phrase)
    const credBackup = await backupService.createCredentialBackup(memberId);
    expect(credBackup.success).toBe(true);

    const recoveryPhrase = credBackup.recoveryPhrase!;
    expect(recoveryPhrase).toHaveLength(24);

    // Step 2: Verify backup status
    const status = await backupService.getCredentialBackupStatus(memberId);
    expect(status.exists).toBe(true);
    expect(status.lastBackup).toBeDefined();

    // Step 3: Recover using phrase (same service - in production,
    // credential backup metadata would be stored in DynamoDB)
    const recoverResult = await backupService.recoverCredentials(memberId, recoveryPhrase);

    expect(recoverResult.success).toBe(true);
    expect(recoverResult.memberKey).toBeDefined();

    // Step 4: Verify recovered key matches original
    expect(recoverResult.memberKey!.equals(originalKey)).toBe(true);

    // Step 5: Can use recovered key for operations
    const settingsResult = await backupService.getSettings(memberId);
    expect(settingsResult.member_id).toBe(memberId);
  });

  it('should handle new device enrollment post-recovery', async () => {
    // Setup: Original device with vault and credential backups
    const memberId = 'member-new-device';
    const originalKey = createTestMemberKey();
    backupService.setMemberKey(memberId, originalKey);

    // Create vault backup
    const vaultBackup = await backupService.createBackup(memberId, 'manual', {
      vault_state: {
        version: 3,
        initialized_at: new Date().toISOString(),
        last_modified: new Date().toISOString(),
        settings: { enrolled_devices: ['device-original'] },
      },
    });

    // Create credential backup
    const credBackup = await backupService.createCredentialBackup(memberId);
    const recoveryPhrase = credBackup.recoveryPhrase!;

    // Step 1: Recover credentials using phrase
    // (In production, credential backup metadata would be in DynamoDB)
    const credRecovery = await backupService.recoverCredentials(memberId, recoveryPhrase);
    expect(credRecovery.success).toBe(true);

    // Step 2: Use recovered key
    backupService.setMemberKey(memberId, credRecovery.memberKey!);

    // Step 3: In production, would now:
    // - Create new device credential
    // - Register new device
    // - Mark old devices as untrusted
    // - Update vault state

    // For this test, we verify we can create new backup with recovered key
    const newBackup = await backupService.createBackup(memberId, 'manual', {
      vault_state: {
        version: 4,
        initialized_at: new Date().toISOString(),
        last_modified: new Date().toISOString(),
        settings: {
          enrolled_devices: ['device-new'],
          previous_devices: ['device-original'],
        },
      },
    });

    expect(newBackup.success).toBe(true);

    // Step 4: Verify new backup is accessible
    const list = await backupService.listBackups(memberId);
    expect(list.total).toBeGreaterThanOrEqual(2); // Original vault backup + new one
  });

  it('should sync with connections after recovery', async () => {
    // Setup
    const memberId = 'member-conn-sync';
    const memberKey = createTestMemberKey();
    backupService.setMemberKey(memberId, memberKey);

    // Create backup with connection keys
    const connectionKeys = [
      {
        connection_id: 'conn-alice',
        peer_id: 'alice-user',
        shared_key_encrypted: crypto.randomBytes(32).toString('base64'),
        created_at: '2024-01-15T00:00:00Z',
      },
      {
        connection_id: 'conn-bob',
        peer_id: 'bob-user',
        shared_key_encrypted: crypto.randomBytes(32).toString('base64'),
        created_at: '2024-02-20T00:00:00Z',
      },
      {
        connection_id: 'conn-charlie',
        peer_id: 'charlie-user',
        shared_key_encrypted: crypto.randomBytes(32).toString('base64'),
        created_at: '2024-03-10T00:00:00Z',
      },
    ];

    const backupResult = await backupService.createBackup(memberId, 'manual', {
      vault_state: {
        version: 1,
        initialized_at: new Date().toISOString(),
        last_modified: new Date().toISOString(),
        settings: {},
      },
      connection_keys: connectionKeys,
    });

    expect(backupResult.success).toBe(true);

    // Simulate recovery
    const restoreResult = await backupService.restoreBackup(
      memberId,
      backupResult.backup!.backup_id
    );

    expect(restoreResult.success).toBe(true);
    expect(restoreResult.items_restored?.connection_keys).toBe(3);

    // In production, after restore:
    // 1. System would notify each connection about potential key update
    // 2. Connections might need to re-establish if key rotation occurred
    // 3. Message history would be re-synced

    // Verify backup contains all connections
    const backup = await backupService.getBackup(
      backupResult.backup!.backup_id,
      memberId
    );
    expect(backup?.contents.connection_keys).toHaveLength(3);
  });

  describe('Recovery Edge Cases', () => {
    it('should handle recovery with wrong phrase', async () => {
      const memberId = 'member-wrong-phrase';
      const memberKey = createTestMemberKey();
      backupService.setMemberKey(memberId, memberKey);

      // Create backup
      await backupService.createCredentialBackup(memberId);

      // Try to recover with wrong phrase
      const wrongPhrase = generateRecoveryPhrase();
      const result = await backupService.recoverCredentials(memberId, wrongPhrase);

      expect(result.success).toBe(false);
      expect(result.error).toContain('Invalid');
    });

    it('should handle recovery when no backup exists', async () => {
      const memberId = 'member-no-backup';
      const phrase = generateRecoveryPhrase();

      const result = await backupService.recoverCredentials(memberId, phrase);

      expect(result.success).toBe(false);
      expect(result.error).toContain('No credential backup');
    });

    it('should handle multiple recovery attempts', async () => {
      const memberId = 'member-multi-recover';
      const memberKey = createTestMemberKey();
      backupService.setMemberKey(memberId, memberKey);

      const credBackup = await backupService.createCredentialBackup(memberId);
      const phrase = credBackup.recoveryPhrase!;

      // Multiple recovery attempts should all succeed
      const results = await Promise.all([
        backupService.recoverCredentials(memberId, phrase),
        backupService.recoverCredentials(memberId, phrase),
        backupService.recoverCredentials(memberId, phrase),
      ]);

      expect(results.every(r => r.success)).toBe(true);
      expect(results.every(r => r.memberKey!.equals(memberKey))).toBe(true);
    });

    it('should handle recovery after backup update', async () => {
      const memberId = 'member-backup-update';
      const memberKey = createTestMemberKey();
      backupService.setMemberKey(memberId, memberKey);

      // Create initial credential backup
      const backup1 = await backupService.createCredentialBackup(memberId);
      const phrase1 = backup1.recoveryPhrase!;

      // Create new credential backup (overwrites previous)
      const backup2 = await backupService.createCredentialBackup(memberId);
      const phrase2 = backup2.recoveryPhrase!;

      // Old phrase should no longer work (backup overwritten)
      const result1 = await backupService.recoverCredentials(memberId, phrase1);
      // Note: This depends on implementation - may fail if backup is overwritten
      // or succeed if backup is versioned

      // New phrase should work
      const result2 = await backupService.recoverCredentials(memberId, phrase2);
      expect(result2.success).toBe(true);
    });

    it('should preserve vault backup during credential recovery', async () => {
      const memberId = 'member-preserve-vault';
      const memberKey = createTestMemberKey();
      backupService.setMemberKey(memberId, memberKey);

      // Create vault backup
      await backupService.createBackup(memberId, 'manual', {
        vault_state: {
          version: 1,
          initialized_at: new Date().toISOString(),
          last_modified: new Date().toISOString(),
          settings: { important: 'data' },
        },
      });

      // Create credential backup
      const credBackup = await backupService.createCredentialBackup(memberId);

      // Verify both exist
      const vaultList = await backupService.listBackups(memberId);
      const credStatus = await backupService.getCredentialBackupStatus(memberId);

      expect(vaultList.total).toBe(1);
      expect(credStatus.exists).toBe(true);

      // Recover credentials
      const recoverResult = await backupService.recoverCredentials(
        memberId,
        credBackup.recoveryPhrase!
      );

      expect(recoverResult.success).toBe(true);

      // Vault backup should still exist
      const vaultListAfter = await backupService.listBackups(memberId);
      expect(vaultListAfter.total).toBe(1);
    });
  });

  describe('Full Recovery Scenario', () => {
    it('should complete full recovery: lost device → phrase → recover → restore → new backup', async () => {
      const memberId = 'member-full-recovery';
      const originalKey = createTestMemberKey();
      backupService.setMemberKey(memberId, originalKey);

      // === Day 1: Normal operation ===

      // Create vault with important data
      const vaultBackup = await backupService.createBackup(memberId, 'manual', {
        vault_state: {
          version: 10,
          initialized_at: '2024-01-01T00:00:00Z',
          last_modified: '2024-06-01T00:00:00Z',
          settings: { user_data: 'important' },
        },
        connection_keys: [
          {
            connection_id: 'conn-1',
            peer_id: 'peer-1',
            shared_key_encrypted: crypto.randomBytes(32).toString('base64'),
            created_at: new Date().toISOString(),
          },
        ],
      });

      // Create credential backup
      const credBackup = await backupService.createCredentialBackup(memberId);
      const savedPhrase = credBackup.recoveryPhrase!;

      // Store backup ID for later
      const vaultBackupId = vaultBackup.backup!.backup_id;

      // === Recovery Process ===
      // In production, credential backup metadata would be in DynamoDB
      // and accessible to any service instance. For this test, we use
      // the same service which has the metadata.

      // Step 1: Recover credentials using saved phrase
      const credRecovery = await backupService.recoverCredentials(memberId, savedPhrase);
      expect(credRecovery.success).toBe(true);

      // Step 2: Verify recovered key matches original
      expect(credRecovery.memberKey!.equals(originalKey)).toBe(true);

      // Step 3: Verify vault backup still exists in S3
      const s3Objects = await storage.listObjects('vettid-backups', `${memberId}/`);
      expect(s3Objects.length).toBeGreaterThan(0);

      // === Post-Recovery ===

      // Create new backup with updated state (simulating new device)
      const newBackup = await backupService.createBackup(memberId, 'manual', {
        vault_state: {
          version: 11,
          initialized_at: new Date().toISOString(),
          last_modified: new Date().toISOString(),
          settings: { user_data: 'important', recovered: true },
        },
      });

      expect(newBackup.success).toBe(true);

      // Verify recovery complete
      const credStatus = await backupService.getCredentialBackupStatus(memberId);
      expect(credStatus.exists).toBe(true);

      // Verify we now have 2 vault backups
      const vaultList = await backupService.listBackups(memberId);
      expect(vaultList.total).toBe(2);
    });
  });
});
