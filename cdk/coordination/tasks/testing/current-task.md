# Task: Phase 8 - Backup System Testing

## Phase
Phase 8: Backup System

## Assigned To
Testing Instance

## Repository
`github.com/mesmerverse/vettid-dev` (cdk/tests/)

## Status
Phase 7 complete. Ready for Phase 8 backup system testing.

## Overview

Phase 8 implements the backup and recovery system. You need to create tests for:
1. Automated vault backup creation and encryption
2. Backup listing and management
3. Backup restoration
4. Credential backup service (recovery phrase)
5. Backup cleanup and retention policies

## New Backend Endpoints

### Backup Management
```
POST /vault/backup                # Trigger manual backup
GET  /vault/backups               # List available backups
POST /vault/restore               # Initiate restore from backup
DELETE /vault/backups/{id}        # Delete specific backup
```

### Credential Backup
```
POST /vault/credentials/backup    # Create credential backup
GET  /vault/credentials/backup    # Get credential backup status
POST /vault/credentials/recover   # Recover credentials from backup
```

### Backup Settings
```
GET  /vault/backup/settings       # Get backup settings
PUT  /vault/backup/settings       # Update backup settings
```

## Phase 8 Testing Tasks

### 1. Backup Creation Tests

Create backup creation tests:

```typescript
// tests/integration/backup/createBackup.test.ts

describe('Create Backup', () => {
  describe('Manual Backup', () => {
    it('should create backup on demand');
    it('should encrypt backup with member key');
    it('should generate unique backup ID');
    it('should store backup metadata');
    it('should require authenticated user');
  });

  describe('Automatic Backup', () => {
    it('should trigger daily backup at scheduled time');
    it('should skip if recent backup exists');
    it('should handle failed backup gracefully');
    it('should retry on transient failures');
  });

  describe('Backup Content', () => {
    it('should include vault state');
    it('should include handler configurations');
    it('should include connection keys');
    it('should include message history (encrypted)');
    it('should exclude temporary data');
  });

  describe('Backup Encryption', () => {
    it('should use XChaCha20-Poly1305');
    it('should derive key from member credentials');
    it('should include encryption metadata');
    it('should be decryptable with correct key');
  });
});
```

### 2. Backup Listing Tests

Create backup listing tests:

```typescript
// tests/integration/backup/listBackups.test.ts

describe('List Backups', () => {
  describe('Backup Query', () => {
    it('should return all backups for member');
    it('should sort by creation date (newest first)');
    it('should support pagination');
    it('should return backup metadata');
  });

  describe('Backup Metadata', () => {
    it('should include backup ID');
    it('should include creation timestamp');
    it('should include size in bytes');
    it('should include backup type (auto/manual)');
    it('should include status (complete/partial)');
  });

  describe('Access Control', () => {
    it('should only return own backups');
    it('should reject unauthenticated requests');
    it('should reject cross-member access');
  });
});
```

### 3. Backup Restoration Tests

Create backup restoration tests:

```typescript
// tests/integration/backup/restoreBackup.test.ts

describe('Restore Backup', () => {
  describe('Restore Validation', () => {
    it('should validate backup exists');
    it('should validate backup integrity');
    it('should validate backup is decryptable');
    it('should reject corrupted backups');
  });

  describe('Restore Process', () => {
    it('should decrypt backup with member key');
    it('should restore vault state');
    it('should restore handler configurations');
    it('should restore connection keys');
    it('should trigger vault reinitialize');
  });

  describe('Restore Conflicts', () => {
    it('should handle version conflicts');
    it('should preserve newer local data option');
    it('should overwrite with backup data option');
    it('should merge option with conflict resolution');
  });

  describe('Restore Notification', () => {
    it('should notify user of restore progress');
    it('should notify connections of potential key update');
    it('should log restore event for audit');
  });
});
```

### 4. Credential Backup Tests

Create credential backup tests:

```typescript
// tests/integration/backup/credentialBackup.test.ts

describe('Credential Backup', () => {
  describe('Backup Creation', () => {
    it('should generate 24-word recovery phrase');
    it('should derive backup key from phrase');
    it('should encrypt credential blob');
    it('should store encrypted backup in S3');
  });

  describe('Recovery Phrase', () => {
    it('should use BIP-39 word list');
    it('should include checksum word');
    it('should be unique per backup');
    it('should not be stored on server');
  });

  describe('Backup Encryption', () => {
    it('should use Argon2id for key derivation');
    it('should use unique salt per backup');
    it('should encrypt with XChaCha20-Poly1305');
  });

  describe('Backup Status', () => {
    it('should track backup existence');
    it('should track last backup date');
    it('should not expose backup contents');
  });
});
```

### 5. Credential Recovery Tests

Create credential recovery tests:

```typescript
// tests/integration/backup/credentialRecovery.test.ts

describe('Credential Recovery', () => {
  describe('Recovery Process', () => {
    it('should validate recovery phrase');
    it('should derive key from phrase');
    it('should download encrypted backup');
    it('should decrypt credential blob');
  });

  describe('Phrase Validation', () => {
    it('should validate word count (24)');
    it('should validate words in BIP-39 list');
    it('should validate checksum');
    it('should reject invalid phrases');
  });

  describe('Recovery States', () => {
    it('should handle no backup exists');
    it('should handle wrong recovery phrase');
    it('should handle corrupted backup');
    it('should handle successful recovery');
  });

  describe('Post-Recovery', () => {
    it('should create new device credential');
    it('should mark old devices as untrusted');
    it('should require re-authentication');
    it('should notify user of recovery');
  });
});
```

### 6. Backup Retention Tests

Create backup retention tests:

```typescript
// tests/integration/backup/backupRetention.test.ts

describe('Backup Retention', () => {
  describe('Retention Policy', () => {
    it('should keep last 3 daily backups');
    it('should keep last 4 weekly backups');
    it('should keep last 12 monthly backups');
    it('should delete older backups automatically');
  });

  describe('Manual Delete', () => {
    it('should allow deleting specific backup');
    it('should prevent deleting only backup');
    it('should require authentication');
    it('should log deletion event');
  });

  describe('Storage Quota', () => {
    it('should enforce storage limits');
    it('should warn when approaching limit');
    it('should delete oldest on limit exceeded');
  });
});
```

### 7. Backup Settings Tests

Create backup settings tests:

```typescript
// tests/integration/backup/backupSettings.test.ts

describe('Backup Settings', () => {
  describe('Get Settings', () => {
    it('should return current backup settings');
    it('should return default settings if not set');
  });

  describe('Update Settings', () => {
    it('should update auto-backup enabled');
    it('should update backup time');
    it('should update retention policy');
    it('should validate settings values');
  });

  describe('Settings Options', () => {
    it('should support enable/disable auto-backup');
    it('should support backup frequency (daily/weekly)');
    it('should support backup time of day');
    it('should support retention count');
  });
});
```

### 8. E2E Backup Flow Tests

Create end-to-end tests:

```typescript
// tests/e2e/backup/backupFlow.test.ts

describe('Backup Flow E2E', () => {
  it('should complete: create backup → list → verify → delete');
  it('should complete: create backup → corrupt → restore fails');
  it('should complete: create backup → restore → verify state');
  it('should complete: auto backup → retention cleanup');
  it('should complete: credential backup → recovery phrase → recover');
});

// tests/e2e/backup/recoveryFlow.test.ts

describe('Recovery Flow E2E', () => {
  it('should recover from device loss using backup');
  it('should recover credentials using recovery phrase');
  it('should handle new device enrollment post-recovery');
  it('should sync with connections after recovery');
});
```

## Test Utilities

Create backup test utilities:

```typescript
// tests/fixtures/backup/mockBackup.ts

export function createMockBackup(options: {
  memberId: string;
  type?: 'auto' | 'manual';
  size?: number;
}): Backup;

export function createMockCredentialBackup(options: {
  memberId: string;
  recoveryPhrase?: string[];
}): CredentialBackup;

export function encryptTestBackup(
  data: any,
  key: Buffer
): { ciphertext: Buffer; nonce: Buffer };

export function decryptTestBackup(
  ciphertext: Buffer,
  nonce: Buffer,
  key: Buffer
): any;

export function generateTestRecoveryPhrase(): string[];

export function deriveKeyFromPhrase(
  phrase: string[],
  salt: Buffer
): Buffer;
```

## Deliverables

- [ ] createBackup.test.ts (backup creation)
- [ ] listBackups.test.ts (backup listing)
- [ ] restoreBackup.test.ts (backup restoration)
- [ ] credentialBackup.test.ts (credential backup)
- [ ] credentialRecovery.test.ts (credential recovery)
- [ ] backupRetention.test.ts (retention policies)
- [ ] backupSettings.test.ts (settings management)
- [ ] backupFlow.test.ts (E2E backup tests)
- [ ] recoveryFlow.test.ts (E2E recovery tests)
- [ ] Mock backup fixtures

## Acceptance Criteria

- [ ] Backup creation tests cover encryption and storage
- [ ] Backup listing tests cover pagination and metadata
- [ ] Restoration tests cover decryption and state recovery
- [ ] Credential backup tests cover recovery phrase generation
- [ ] Recovery tests cover phrase validation and decryption
- [ ] Retention tests cover automatic cleanup
- [ ] E2E tests cover complete backup/restore flows

## Notes

- Use mock S3 for storage testing
- Test encryption with known test vectors
- Verify backup integrity with checksums
- Test concurrent backup operations
- Consider large backup file handling

## Status Update

```bash
cd /path/to/vettid-dev/cdk
git pull
# Create backup system tests
npm run test:unit  # Verify tests pass
git add tests/
git commit -m "Phase 8: Add backup system tests"
git push

# Update status
# Edit cdk/coordination/status/testing.json
git add cdk/coordination/status/testing.json
git commit -m "Update Testing status: Phase 8 backup testing complete"
git push
```
