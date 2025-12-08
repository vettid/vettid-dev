/**
 * Mock Backup Fixtures
 *
 * Provides mock implementations for backup system testing:
 * - Backup creation and encryption (XChaCha20-Poly1305)
 * - BIP-39 recovery phrase generation
 * - Argon2id key derivation simulation
 * - Mock S3 storage
 * - Backup retention management
 */

import * as crypto from 'crypto';

// ============================================
// Types
// ============================================

export interface Backup {
  backup_id: string;
  member_id: string;
  type: 'auto' | 'manual';
  status: 'pending' | 'complete' | 'partial' | 'failed';
  size_bytes: number;
  created_at: string;
  completed_at?: string;
  checksum: string;
  encryption_metadata: {
    algorithm: string;
    nonce: string;
    salt: string;
    key_derivation: string;
  };
  contents: BackupContents;
}

export interface BackupContents {
  vault_state: VaultState;
  handler_configs: HandlerConfig[];
  connection_keys: ConnectionKeyBackup[];
  message_history: EncryptedMessageHistory;
}

export interface VaultState {
  version: number;
  initialized_at: string;
  last_modified: string;
  settings: Record<string, any>;
}

export interface HandlerConfig {
  handler_id: string;
  handler_type: string;
  config: Record<string, any>;
  enabled: boolean;
}

export interface ConnectionKeyBackup {
  connection_id: string;
  peer_id: string;
  shared_key_encrypted: string;
  created_at: string;
}

export interface EncryptedMessageHistory {
  encrypted_data: string;
  message_count: number;
  date_range: {
    from: string;
    to: string;
  };
}

export interface CredentialBackup {
  backup_id: string;
  member_id: string;
  created_at: string;
  encryption_metadata: {
    algorithm: string;
    nonce: string;
    salt: string;
    key_derivation: string;
    iterations: number;
    memory_cost: number;
    parallelism: number;
  };
  encrypted_credentials: string;
  checksum: string;
}

export interface BackupSettings {
  member_id: string;
  auto_backup_enabled: boolean;
  backup_frequency: 'daily' | 'weekly';
  backup_time: string; // HH:MM format
  retention_daily: number;
  retention_weekly: number;
  retention_monthly: number;
  last_auto_backup?: string;
  next_scheduled_backup?: string;
}

export interface RestoreResult {
  success: boolean;
  backup_id?: string;
  restored_at?: string;
  items_restored?: {
    vault_state: boolean;
    handler_configs: number;
    connection_keys: number;
    messages: number;
  };
  error?: string;
  conflicts?: RestoreConflict[];
}

export interface RestoreConflict {
  type: 'version' | 'data' | 'key';
  item_id: string;
  local_version?: number;
  backup_version?: number;
  resolution?: 'keep_local' | 'use_backup' | 'merge';
}

// ============================================
// BIP-39 Word List (first 100 words for testing)
// Full list has 2048 words
// ============================================

const BIP39_WORDLIST = [
  'abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb', 'abstract',
  'absurd', 'abuse', 'access', 'accident', 'account', 'accuse', 'achieve', 'acid',
  'acoustic', 'acquire', 'across', 'act', 'action', 'actor', 'actress', 'actual',
  'adapt', 'add', 'addict', 'address', 'adjust', 'admit', 'adult', 'advance',
  'advice', 'aerobic', 'affair', 'afford', 'afraid', 'again', 'age', 'agent',
  'agree', 'ahead', 'aim', 'air', 'airport', 'aisle', 'alarm', 'album',
  'alcohol', 'alert', 'alien', 'all', 'alley', 'allow', 'almost', 'alone',
  'alpha', 'already', 'also', 'alter', 'always', 'amateur', 'amazing', 'among',
  'amount', 'amused', 'analyst', 'anchor', 'ancient', 'anger', 'angle', 'angry',
  'animal', 'ankle', 'announce', 'annual', 'another', 'answer', 'antenna', 'antique',
  'anxiety', 'any', 'apart', 'apology', 'appear', 'apple', 'approve', 'april',
  'arch', 'arctic', 'area', 'arena', 'argue', 'arm', 'armed', 'armor',
  'army', 'around', 'arrange', 'arrest', 'arrive', 'arrow', 'art', 'artefact',
  'artist', 'artwork', 'ask', 'aspect', 'assault', 'asset', 'assist', 'assume',
  'asthma', 'athlete', 'atom', 'attack', 'attend', 'attitude', 'attract', 'auction',
  'audit', 'august', 'aunt', 'author', 'auto', 'autumn', 'average', 'avocado',
  'avoid', 'awake', 'aware', 'away', 'awesome', 'awful', 'awkward', 'axis',
  'baby', 'bachelor', 'bacon', 'badge', 'bag', 'balance', 'balcony', 'ball',
  'bamboo', 'banana', 'banner', 'bar', 'barely', 'bargain', 'barrel', 'base',
  'basic', 'basket', 'battle', 'beach', 'bean', 'beauty', 'because', 'become',
  'beef', 'before', 'begin', 'behave', 'behind', 'believe', 'below', 'belt',
  'bench', 'benefit', 'best', 'betray', 'better', 'between', 'beyond', 'bicycle',
  'bid', 'bike', 'bind', 'biology', 'bird', 'birth', 'bitter', 'black',
  'blade', 'blame', 'blanket', 'blast', 'bleak', 'bless', 'blind', 'blood',
  'blossom', 'blouse', 'blue', 'blur', 'blush', 'board', 'boat', 'body',
  'boil', 'bomb', 'bone', 'bonus', 'book', 'boost', 'border', 'boring',
  'borrow', 'boss', 'bottom', 'bounce', 'box', 'boy', 'bracket', 'brain',
  'brand', 'brass', 'brave', 'bread', 'breeze', 'brick', 'bridge', 'brief',
  'bright', 'bring', 'brisk', 'broccoli', 'broken', 'bronze', 'broom', 'brother',
  'brown', 'brush', 'bubble', 'buddy', 'budget', 'buffalo', 'build', 'bulb',
  'bulk', 'bullet', 'bundle', 'bunker', 'burden', 'burger', 'burst', 'bus',
  'business', 'busy', 'butter', 'buyer', 'buzz', 'cabbage', 'cabin', 'cable',
  // Extended list for 24-word phrases
  'cactus', 'cage', 'cake', 'call', 'calm', 'camera', 'camp', 'can',
  'canal', 'cancel', 'candy', 'cannon', 'canoe', 'canvas', 'canyon', 'capable',
  'capital', 'captain', 'car', 'carbon', 'card', 'cargo', 'carpet', 'carry',
  'cart', 'case', 'cash', 'casino', 'castle', 'casual', 'cat', 'catalog',
  'catch', 'category', 'cattle', 'caught', 'cause', 'caution', 'cave', 'ceiling',
  'celery', 'cement', 'census', 'century', 'cereal', 'certain', 'chair', 'chalk',
  'champion', 'change', 'chaos', 'chapter', 'charge', 'chase', 'chat', 'cheap',
  'check', 'cheese', 'chef', 'cherry', 'chest', 'chicken', 'chief', 'child',
  'chimney', 'choice', 'choose', 'chronic', 'chuckle', 'chunk', 'churn', 'cigar',
  'cinnamon', 'circle', 'citizen', 'city', 'civil', 'claim', 'clap', 'clarify',
  'claw', 'clay', 'clean', 'clerk', 'clever', 'click', 'client', 'cliff',
  'climb', 'clinic', 'clip', 'clock', 'clog', 'close', 'cloth', 'cloud',
  'clown', 'club', 'clump', 'cluster', 'clutch', 'coach', 'coast', 'coconut',
  'code', 'coffee', 'coil', 'coin', 'collect', 'color', 'column', 'combine',
  'come', 'comfort', 'comic', 'common', 'company', 'concert', 'conduct', 'confirm',
  'congress', 'connect', 'consider', 'control', 'convince', 'cook', 'cool', 'copper',
  'copy', 'coral', 'core', 'corn', 'correct', 'cost', 'cotton', 'couch',
  'country', 'couple', 'course', 'cousin', 'cover', 'coyote', 'crack', 'cradle',
  'craft', 'cram', 'crane', 'crash', 'crater', 'crawl', 'crazy', 'cream',
  'credit', 'creek', 'crew', 'cricket', 'crime', 'crisp', 'critic', 'crop',
  'cross', 'crouch', 'crowd', 'crucial', 'cruel', 'cruise', 'crumble', 'crunch',
  'crush', 'cry', 'crystal', 'cube', 'culture', 'cup', 'cupboard', 'curious',
  'current', 'curtain', 'curve', 'cushion', 'custom', 'cute', 'cycle', 'dad',
  'damage', 'damp', 'dance', 'danger', 'daring', 'dash', 'daughter', 'dawn',
  'day', 'deal', 'debate', 'debris', 'decade', 'december', 'decide', 'decline',
  'decorate', 'decrease', 'deer', 'defense', 'define', 'defy', 'degree', 'delay',
  'deliver', 'demand', 'demise', 'denial', 'dentist', 'deny', 'depart', 'depend',
  'deposit', 'depth', 'deputy', 'derive', 'describe', 'desert', 'design', 'desk',
];

// ============================================
// Encryption Utilities
// ============================================

/**
 * Simulates XChaCha20-Poly1305 encryption using ChaCha20-Poly1305
 * In production, use libsodium for proper XChaCha20-Poly1305
 */
export function encryptBackupData(
  data: any,
  key: Buffer
): { ciphertext: Buffer; nonce: Buffer; authTag: Buffer } {
  // Generate 24-byte nonce (XChaCha20 uses 24-byte nonces)
  const nonce = crypto.randomBytes(24);

  // For testing, we simulate XChaCha20-Poly1305 with ChaCha20-Poly1305
  // Using first 12 bytes of nonce for ChaCha20 (production would use HChaCha20 subkey derivation)
  const chacha20Nonce = nonce.slice(0, 12);

  const plaintext = Buffer.from(JSON.stringify(data), 'utf8');

  const cipher = crypto.createCipheriv('chacha20-poly1305', key, chacha20Nonce, {
    authTagLength: 16,
  });

  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return { ciphertext, nonce, authTag };
}

/**
 * Decrypts XChaCha20-Poly1305 encrypted data
 */
export function decryptBackupData(
  ciphertext: Buffer,
  nonce: Buffer,
  authTag: Buffer,
  key: Buffer
): any {
  const chacha20Nonce = nonce.slice(0, 12);

  const decipher = crypto.createDecipheriv('chacha20-poly1305', key, chacha20Nonce, {
    authTagLength: 16,
  });
  decipher.setAuthTag(authTag);

  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(plaintext.toString('utf8'));
}

/**
 * Package encrypted backup with metadata (base64 encoded)
 */
export function packageEncryptedBackup(
  data: any,
  key: Buffer
): { encryptedData: string; nonce: string; checksum: string } {
  const { ciphertext, nonce, authTag } = encryptBackupData(data, key);

  // Combine ciphertext and auth tag
  const combined = Buffer.concat([ciphertext, authTag]);

  // Calculate checksum of encrypted data
  const checksum = crypto.createHash('sha256').update(combined).digest('hex');

  return {
    encryptedData: combined.toString('base64'),
    nonce: nonce.toString('base64'),
    checksum,
  };
}

/**
 * Unpackage and decrypt backup
 */
export function unpackageEncryptedBackup(
  encryptedData: string,
  nonce: string,
  key: Buffer
): any {
  const combined = Buffer.from(encryptedData, 'base64');
  const nonceBuffer = Buffer.from(nonce, 'base64');

  // Split ciphertext and auth tag
  const ciphertext = combined.slice(0, -16);
  const authTag = combined.slice(-16);

  return decryptBackupData(ciphertext, nonceBuffer, authTag, key);
}

// ============================================
// BIP-39 Recovery Phrase
// ============================================

/**
 * Generate a 24-word recovery phrase using BIP-39 word list
 */
export function generateRecoveryPhrase(): string[] {
  // 24 words = 256 bits of entropy + 8 bit checksum
  const entropy = crypto.randomBytes(32); // 256 bits

  // Calculate checksum (first byte of SHA256 hash)
  const hash = crypto.createHash('sha256').update(entropy).digest();
  const checksumBits = hash[0];

  // Convert entropy + checksum to word indices
  const words: string[] = [];

  // Each word represents 11 bits
  // 24 words = 264 bits = 256 entropy + 8 checksum
  let bitBuffer = BigInt('0x' + entropy.toString('hex')) << BigInt(8);
  bitBuffer |= BigInt(checksumBits);

  for (let i = 0; i < 24; i++) {
    const shift = BigInt((23 - i) * 11);
    const index = Number((bitBuffer >> shift) & BigInt(0x7ff));
    words.push(BIP39_WORDLIST[index % BIP39_WORDLIST.length]);
  }

  return words;
}

/**
 * Validate a recovery phrase
 */
export function validateRecoveryPhrase(phrase: string[]): {
  valid: boolean;
  error?: string;
} {
  // Check word count
  if (phrase.length !== 24) {
    return { valid: false, error: `Invalid word count: expected 24, got ${phrase.length}` };
  }

  // Check all words are in the BIP-39 word list
  for (const word of phrase) {
    if (!BIP39_WORDLIST.includes(word.toLowerCase())) {
      return { valid: false, error: `Invalid word: "${word}" not in BIP-39 word list` };
    }
  }

  // In production, would also validate checksum
  // For testing, we accept any valid words
  return { valid: true };
}

/**
 * Get word index in BIP-39 list
 */
export function getWordIndex(word: string): number {
  return BIP39_WORDLIST.indexOf(word.toLowerCase());
}

/**
 * Get BIP-39 word list for testing
 */
export function getBip39WordList(): string[] {
  return [...BIP39_WORDLIST];
}

// ============================================
// Key Derivation (Argon2id simulation)
// ============================================

/**
 * Derive a key from recovery phrase using Argon2id
 * For testing, we simulate with PBKDF2 (production would use actual Argon2id)
 */
export function deriveKeyFromPhrase(
  phrase: string[],
  salt: Buffer,
  options: {
    iterations?: number;
    memoryCost?: number;
    parallelism?: number;
  } = {}
): Buffer {
  const {
    iterations = 3,
    memoryCost = 65536, // 64 MB
    parallelism = 4,
  } = options;

  // Convert phrase to seed
  const phraseSeed = phrase.join(' ').normalize('NFKD');

  // Simulate Argon2id with PBKDF2 for testing
  // In production, use actual Argon2id implementation
  const key = crypto.pbkdf2Sync(
    phraseSeed,
    salt,
    iterations * 10000, // Simulate memory-hard iterations
    32, // 256-bit key
    'sha512'
  );

  return key;
}

/**
 * Derive backup encryption key from member credentials
 */
export function deriveBackupKey(
  memberKey: Buffer,
  salt: Buffer
): Buffer {
  return crypto.pbkdf2Sync(memberKey, salt, 100000, 32, 'sha256');
}

// ============================================
// Mock S3 Storage
// ============================================

export class MockS3Storage {
  private buckets: Map<string, Map<string, { data: Buffer; metadata: Record<string, string> }>> =
    new Map();

  constructor() {
    // Initialize default backup bucket
    this.buckets.set('vettid-backups', new Map());
    this.buckets.set('vettid-credential-backups', new Map());
  }

  async putObject(
    bucket: string,
    key: string,
    data: Buffer,
    metadata: Record<string, string> = {}
  ): Promise<{ success: boolean; etag: string }> {
    if (!this.buckets.has(bucket)) {
      this.buckets.set(bucket, new Map());
    }

    const etag = crypto.createHash('md5').update(data).digest('hex');
    this.buckets.get(bucket)!.set(key, { data, metadata });

    return { success: true, etag };
  }

  async getObject(
    bucket: string,
    key: string
  ): Promise<{ data: Buffer; metadata: Record<string, string> } | null> {
    const bucketData = this.buckets.get(bucket);
    if (!bucketData) return null;
    return bucketData.get(key) || null;
  }

  async deleteObject(bucket: string, key: string): Promise<boolean> {
    const bucketData = this.buckets.get(bucket);
    if (!bucketData) return false;
    return bucketData.delete(key);
  }

  async listObjects(
    bucket: string,
    prefix?: string
  ): Promise<{ key: string; size: number; lastModified: string }[]> {
    const bucketData = this.buckets.get(bucket);
    if (!bucketData) return [];

    const objects: { key: string; size: number; lastModified: string }[] = [];

    for (const [key, value] of bucketData.entries()) {
      if (!prefix || key.startsWith(prefix)) {
        objects.push({
          key,
          size: value.data.length,
          lastModified: value.metadata['last-modified'] || new Date().toISOString(),
        });
      }
    }

    return objects.sort((a, b) => b.lastModified.localeCompare(a.lastModified));
  }

  async headObject(
    bucket: string,
    key: string
  ): Promise<{ exists: boolean; size?: number; metadata?: Record<string, string> }> {
    const obj = await this.getObject(bucket, key);
    if (!obj) return { exists: false };
    return { exists: true, size: obj.data.length, metadata: obj.metadata };
  }

  clear(bucket?: string): void {
    if (bucket) {
      this.buckets.get(bucket)?.clear();
    } else {
      for (const bucketData of this.buckets.values()) {
        bucketData.clear();
      }
    }
  }

  getStorageUsed(bucket: string, prefix?: string): number {
    const bucketData = this.buckets.get(bucket);
    if (!bucketData) return 0;

    let total = 0;
    for (const [key, value] of bucketData.entries()) {
      if (!prefix || key.startsWith(prefix)) {
        total += value.data.length;
      }
    }
    return total;
  }
}

// ============================================
// Mock Backup Service
// ============================================

export class MockBackupService {
  private backups: Map<string, Backup> = new Map();
  private credentialBackups: Map<string, CredentialBackup> = new Map();
  private settings: Map<string, BackupSettings> = new Map();
  private storage: MockS3Storage;
  private memberKeys: Map<string, Buffer> = new Map();

  constructor(storage?: MockS3Storage) {
    this.storage = storage || new MockS3Storage();
  }

  setMemberKey(memberId: string, key: Buffer): void {
    this.memberKeys.set(memberId, key);
  }

  getMemberKey(memberId: string): Buffer | undefined {
    return this.memberKeys.get(memberId);
  }

  // ============================================
  // Backup Creation
  // ============================================

  async createBackup(
    memberId: string,
    type: 'auto' | 'manual',
    contents: Partial<BackupContents> = {}
  ): Promise<{ success: boolean; backup?: Backup; error?: string }> {
    const memberKey = this.memberKeys.get(memberId);
    if (!memberKey) {
      return { success: false, error: 'Member key not found' };
    }

    // Check for recent backup if auto
    if (type === 'auto') {
      const recentBackup = await this.getRecentBackup(memberId, 24 * 60 * 60 * 1000); // 24 hours
      if (recentBackup) {
        return { success: false, error: 'Recent backup exists, skipping auto backup' };
      }
    }

    const backupId = crypto.randomUUID();
    const salt = crypto.randomBytes(16);
    const backupKey = deriveBackupKey(memberKey, salt);

    // Build backup contents
    const fullContents: BackupContents = {
      vault_state: contents.vault_state || {
        version: 1,
        initialized_at: new Date().toISOString(),
        last_modified: new Date().toISOString(),
        settings: {},
      },
      handler_configs: contents.handler_configs || [],
      connection_keys: contents.connection_keys || [],
      message_history: contents.message_history || {
        encrypted_data: '',
        message_count: 0,
        date_range: { from: '', to: '' },
      },
    };

    // Encrypt backup
    const { encryptedData, nonce, checksum } = packageEncryptedBackup(fullContents, backupKey);

    // Store in S3
    const s3Key = `${memberId}/${backupId}.backup`;
    await this.storage.putObject(
      'vettid-backups',
      s3Key,
      Buffer.from(encryptedData, 'base64'),
      {
        'member-id': memberId,
        'backup-type': type,
        'created-at': new Date().toISOString(),
        'last-modified': new Date().toISOString(),
      }
    );

    const backup: Backup = {
      backup_id: backupId,
      member_id: memberId,
      type,
      status: 'complete',
      size_bytes: Buffer.from(encryptedData, 'base64').length,
      created_at: new Date().toISOString(),
      completed_at: new Date().toISOString(),
      checksum,
      encryption_metadata: {
        algorithm: 'XChaCha20-Poly1305',
        nonce,
        salt: salt.toString('base64'),
        key_derivation: 'PBKDF2-SHA256',
      },
      contents: fullContents,
    };

    this.backups.set(backupId, backup);

    // Update settings
    if (type === 'auto') {
      const memberSettings = this.settings.get(memberId);
      if (memberSettings) {
        memberSettings.last_auto_backup = backup.created_at;
        this.settings.set(memberId, memberSettings);
      }
    }

    return { success: true, backup };
  }

  async getRecentBackup(memberId: string, withinMs: number): Promise<Backup | null> {
    const memberBackups = Array.from(this.backups.values())
      .filter((b) => b.member_id === memberId && b.status === 'complete')
      .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());

    if (memberBackups.length === 0) return null;

    const latestBackup = memberBackups[0];
    const backupAge = Date.now() - new Date(latestBackup.created_at).getTime();

    return backupAge <= withinMs ? latestBackup : null;
  }

  // ============================================
  // Backup Listing
  // ============================================

  async listBackups(
    memberId: string,
    options: { limit?: number; offset?: number } = {}
  ): Promise<{
    backups: Omit<Backup, 'contents'>[];
    total: number;
    hasMore: boolean;
  }> {
    const { limit = 10, offset = 0 } = options;

    const memberBackups = Array.from(this.backups.values())
      .filter((b) => b.member_id === memberId)
      .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());

    const total = memberBackups.length;
    const paginatedBackups = memberBackups.slice(offset, offset + limit);

    // Remove contents from response
    const sanitizedBackups = paginatedBackups.map(({ contents, ...rest }) => rest);

    return {
      backups: sanitizedBackups,
      total,
      hasMore: offset + limit < total,
    };
  }

  async getBackup(backupId: string, memberId: string): Promise<Backup | null> {
    const backup = this.backups.get(backupId);
    if (!backup || backup.member_id !== memberId) return null;
    return backup;
  }

  // ============================================
  // Backup Restoration
  // ============================================

  async restoreBackup(
    memberId: string,
    backupId: string,
    options: {
      conflictResolution?: 'keep_local' | 'use_backup' | 'merge';
    } = {}
  ): Promise<RestoreResult> {
    const { conflictResolution = 'use_backup' } = options;

    const backup = this.backups.get(backupId);
    if (!backup) {
      return { success: false, error: 'Backup not found' };
    }

    if (backup.member_id !== memberId) {
      return { success: false, error: 'Not authorized to restore this backup' };
    }

    if (backup.status !== 'complete') {
      return { success: false, error: 'Cannot restore incomplete backup' };
    }

    const memberKey = this.memberKeys.get(memberId);
    if (!memberKey) {
      return { success: false, error: 'Member key not found' };
    }

    // Verify backup integrity
    const s3Key = `${memberId}/${backupId}.backup`;
    const stored = await this.storage.getObject('vettid-backups', s3Key);
    if (!stored) {
      return { success: false, error: 'Backup data not found in storage' };
    }

    // Verify checksum
    const storedChecksum = crypto.createHash('sha256').update(stored.data).digest('hex');
    if (storedChecksum !== backup.checksum) {
      return { success: false, error: 'Backup integrity check failed' };
    }

    // Decrypt and restore
    try {
      const salt = Buffer.from(backup.encryption_metadata.salt, 'base64');
      const backupKey = deriveBackupKey(memberKey, salt);
      const decryptedContents = unpackageEncryptedBackup(
        stored.data.toString('base64'),
        backup.encryption_metadata.nonce,
        backupKey
      );

      // Detect conflicts (simplified)
      const conflicts: RestoreConflict[] = [];
      if (conflictResolution === 'merge') {
        // In real implementation, would compare versions and detect conflicts
      }

      return {
        success: true,
        backup_id: backupId,
        restored_at: new Date().toISOString(),
        items_restored: {
          vault_state: true,
          handler_configs: decryptedContents.handler_configs?.length || 0,
          connection_keys: decryptedContents.connection_keys?.length || 0,
          messages: decryptedContents.message_history?.message_count || 0,
        },
        conflicts: conflicts.length > 0 ? conflicts : undefined,
      };
    } catch (error) {
      return { success: false, error: 'Failed to decrypt backup' };
    }
  }

  async deleteBackup(memberId: string, backupId: string): Promise<{ success: boolean; error?: string }> {
    const backup = this.backups.get(backupId);
    if (!backup) {
      return { success: false, error: 'Backup not found' };
    }

    if (backup.member_id !== memberId) {
      return { success: false, error: 'Not authorized to delete this backup' };
    }

    // Check if it's the only backup
    const memberBackups = Array.from(this.backups.values()).filter(
      (b) => b.member_id === memberId
    );
    if (memberBackups.length === 1) {
      return { success: false, error: 'Cannot delete the only backup' };
    }

    // Delete from S3
    const s3Key = `${memberId}/${backupId}.backup`;
    await this.storage.deleteObject('vettid-backups', s3Key);

    // Delete from memory
    this.backups.delete(backupId);

    return { success: true };
  }

  // ============================================
  // Credential Backup
  // ============================================

  async createCredentialBackup(
    memberId: string
  ): Promise<{
    success: boolean;
    recoveryPhrase?: string[];
    backup?: CredentialBackup;
    error?: string;
  }> {
    const memberKey = this.memberKeys.get(memberId);
    if (!memberKey) {
      return { success: false, error: 'Member key not found' };
    }

    // Generate recovery phrase
    const recoveryPhrase = generateRecoveryPhrase();

    // Derive key from phrase
    const salt = crypto.randomBytes(16);
    const backupKey = deriveKeyFromPhrase(recoveryPhrase, salt);

    // Encrypt credentials
    const credentials = {
      member_key: memberKey.toString('base64'),
      created_at: new Date().toISOString(),
    };

    const { encryptedData, nonce, checksum } = packageEncryptedBackup(credentials, backupKey);

    const backupId = crypto.randomUUID();

    // Store in S3
    const s3Key = `${memberId}/credentials.backup`;
    await this.storage.putObject(
      'vettid-credential-backups',
      s3Key,
      Buffer.from(encryptedData, 'base64'),
      {
        'member-id': memberId,
        'created-at': new Date().toISOString(),
        'last-modified': new Date().toISOString(),
      }
    );

    const credentialBackup: CredentialBackup = {
      backup_id: backupId,
      member_id: memberId,
      created_at: new Date().toISOString(),
      encryption_metadata: {
        algorithm: 'XChaCha20-Poly1305',
        nonce,
        salt: salt.toString('base64'),
        key_derivation: 'Argon2id',
        iterations: 3,
        memory_cost: 65536,
        parallelism: 4,
      },
      encrypted_credentials: encryptedData,
      checksum,
    };

    this.credentialBackups.set(memberId, credentialBackup);

    // Don't store recovery phrase - return only once
    return {
      success: true,
      recoveryPhrase, // User must save this
      backup: credentialBackup,
    };
  }

  async getCredentialBackupStatus(
    memberId: string
  ): Promise<{ exists: boolean; lastBackup?: string }> {
    const backup = this.credentialBackups.get(memberId);
    if (!backup) {
      return { exists: false };
    }
    return { exists: true, lastBackup: backup.created_at };
  }

  async recoverCredentials(
    memberId: string,
    recoveryPhrase: string[]
  ): Promise<{
    success: boolean;
    memberKey?: Buffer;
    error?: string;
  }> {
    // Validate phrase
    const validation = validateRecoveryPhrase(recoveryPhrase);
    if (!validation.valid) {
      return { success: false, error: validation.error };
    }

    const backup = this.credentialBackups.get(memberId);
    if (!backup) {
      return { success: false, error: 'No credential backup found' };
    }

    // Retrieve from S3
    const s3Key = `${memberId}/credentials.backup`;
    const stored = await this.storage.getObject('vettid-credential-backups', s3Key);
    if (!stored) {
      return { success: false, error: 'Credential backup data not found' };
    }

    // Derive key and decrypt
    try {
      const salt = Buffer.from(backup.encryption_metadata.salt, 'base64');
      const backupKey = deriveKeyFromPhrase(recoveryPhrase, salt);

      const decrypted = unpackageEncryptedBackup(
        stored.data.toString('base64'),
        backup.encryption_metadata.nonce,
        backupKey
      );

      const memberKey = Buffer.from(decrypted.member_key, 'base64');

      return { success: true, memberKey };
    } catch (error) {
      return { success: false, error: 'Invalid recovery phrase' };
    }
  }

  // ============================================
  // Backup Settings
  // ============================================

  async getSettings(memberId: string): Promise<BackupSettings> {
    const existing = this.settings.get(memberId);
    if (existing) return existing;

    // Return defaults
    const defaults: BackupSettings = {
      member_id: memberId,
      auto_backup_enabled: true,
      backup_frequency: 'daily',
      backup_time: '03:00',
      retention_daily: 3,
      retention_weekly: 4,
      retention_monthly: 12,
    };

    this.settings.set(memberId, defaults);
    return defaults;
  }

  async updateSettings(
    memberId: string,
    updates: Partial<Omit<BackupSettings, 'member_id'>>
  ): Promise<{ success: boolean; settings?: BackupSettings; error?: string }> {
    const current = await this.getSettings(memberId);

    // Validate updates
    if (updates.backup_frequency && !['daily', 'weekly'].includes(updates.backup_frequency)) {
      return { success: false, error: 'Invalid backup frequency' };
    }

    if (updates.backup_time !== undefined) {
      const timeMatch = /^(\d{2}):(\d{2})$/.exec(updates.backup_time);
      if (!timeMatch) {
        return { success: false, error: 'Invalid backup time format (use HH:MM)' };
      }
      const hours = parseInt(timeMatch[1], 10);
      const minutes = parseInt(timeMatch[2], 10);
      if (hours < 0 || hours > 23 || minutes < 0 || minutes > 59) {
        return { success: false, error: 'Invalid backup time format (use HH:MM)' };
      }
    }

    if (updates.retention_daily !== undefined && (updates.retention_daily < 1 || updates.retention_daily > 30)) {
      return { success: false, error: 'Daily retention must be between 1 and 30' };
    }

    const updated: BackupSettings = {
      ...current,
      ...updates,
      member_id: memberId,
    };

    // Calculate next scheduled backup
    if (updated.auto_backup_enabled) {
      const now = new Date();
      const [hours, minutes] = updated.backup_time.split(':').map(Number);
      const next = new Date(now);
      next.setHours(hours, minutes, 0, 0);

      if (next <= now) {
        next.setDate(next.getDate() + (updated.backup_frequency === 'daily' ? 1 : 7));
      }

      updated.next_scheduled_backup = next.toISOString();
    }

    this.settings.set(memberId, updated);
    return { success: true, settings: updated };
  }

  // ============================================
  // Retention Management
  // ============================================

  async applyRetentionPolicy(memberId: string): Promise<{
    deleted: string[];
    retained: string[];
  }> {
    const settings = await this.getSettings(memberId);
    const memberBackups = Array.from(this.backups.values())
      .filter((b) => b.member_id === memberId && b.status === 'complete')
      .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());

    const now = new Date();
    const deleted: string[] = [];
    const retained: string[] = [];

    // Categorize backups by age
    const daily: Backup[] = [];
    const weekly: Backup[] = [];
    const monthly: Backup[] = [];
    const older: Backup[] = [];

    for (const backup of memberBackups) {
      const age = now.getTime() - new Date(backup.created_at).getTime();
      const days = age / (24 * 60 * 60 * 1000);

      if (days <= 7) {
        daily.push(backup);
      } else if (days <= 30) {
        weekly.push(backup);
      } else if (days <= 365) {
        monthly.push(backup);
      } else {
        older.push(backup);
      }
    }

    // Apply retention limits
    const toKeep = new Set<string>();

    // Keep last N daily
    daily.slice(0, settings.retention_daily).forEach((b) => toKeep.add(b.backup_id));

    // Keep last N weekly (one per week)
    const weeklyToKeep = weekly.slice(0, settings.retention_weekly);
    weeklyToKeep.forEach((b) => toKeep.add(b.backup_id));

    // Keep last N monthly (one per month)
    const monthlyToKeep = monthly.slice(0, settings.retention_monthly);
    monthlyToKeep.forEach((b) => toKeep.add(b.backup_id));

    // Always keep at least one backup
    if (toKeep.size === 0 && memberBackups.length > 0) {
      toKeep.add(memberBackups[0].backup_id);
    }

    // Delete others
    for (const backup of memberBackups) {
      if (toKeep.has(backup.backup_id)) {
        retained.push(backup.backup_id);
      } else {
        await this.deleteBackupInternal(backup);
        deleted.push(backup.backup_id);
      }
    }

    return { deleted, retained };
  }

  private async deleteBackupInternal(backup: Backup): Promise<void> {
    const s3Key = `${backup.member_id}/${backup.backup_id}.backup`;
    await this.storage.deleteObject('vettid-backups', s3Key);
    this.backups.delete(backup.backup_id);
  }

  getStorageUsed(memberId: string): number {
    return this.storage.getStorageUsed('vettid-backups', `${memberId}/`);
  }

  // ============================================
  // Utilities
  // ============================================

  clear(): void {
    this.backups.clear();
    this.credentialBackups.clear();
    this.settings.clear();
    this.memberKeys.clear();
    this.storage.clear();
  }

  getStorage(): MockS3Storage {
    return this.storage;
  }
}

// ============================================
// Test Helpers
// ============================================

export function createMockBackup(options: {
  memberId: string;
  type?: 'auto' | 'manual';
  status?: 'pending' | 'complete' | 'partial' | 'failed';
  size?: number;
  contents?: Partial<BackupContents>;
}): Backup {
  const {
    memberId,
    type = 'manual',
    status = 'complete',
    size = 1024,
    contents = {},
  } = options;

  const backupId = crypto.randomUUID();
  const nonce = crypto.randomBytes(24).toString('base64');
  const salt = crypto.randomBytes(16).toString('base64');

  const fullContents: BackupContents = {
    vault_state: contents.vault_state || {
      version: 1,
      initialized_at: new Date().toISOString(),
      last_modified: new Date().toISOString(),
      settings: {},
    },
    handler_configs: contents.handler_configs || [],
    connection_keys: contents.connection_keys || [],
    message_history: contents.message_history || {
      encrypted_data: '',
      message_count: 0,
      date_range: { from: '', to: '' },
    },
  };

  return {
    backup_id: backupId,
    member_id: memberId,
    type,
    status,
    size_bytes: size,
    created_at: new Date().toISOString(),
    completed_at: status === 'complete' ? new Date().toISOString() : undefined,
    checksum: crypto.randomBytes(32).toString('hex'),
    encryption_metadata: {
      algorithm: 'XChaCha20-Poly1305',
      nonce,
      salt,
      key_derivation: 'PBKDF2-SHA256',
    },
    contents: fullContents,
  };
}

export function createMockCredentialBackup(options: {
  memberId: string;
}): { backup: CredentialBackup; recoveryPhrase: string[] } {
  const { memberId } = options;

  const recoveryPhrase = generateRecoveryPhrase();
  const backupId = crypto.randomUUID();
  const nonce = crypto.randomBytes(24).toString('base64');
  const salt = crypto.randomBytes(16).toString('base64');

  const backup: CredentialBackup = {
    backup_id: backupId,
    member_id: memberId,
    created_at: new Date().toISOString(),
    encryption_metadata: {
      algorithm: 'XChaCha20-Poly1305',
      nonce,
      salt,
      key_derivation: 'Argon2id',
      iterations: 3,
      memory_cost: 65536,
      parallelism: 4,
    },
    encrypted_credentials: crypto.randomBytes(128).toString('base64'),
    checksum: crypto.randomBytes(32).toString('hex'),
  };

  return { backup, recoveryPhrase };
}

export function createTestMemberKey(): Buffer {
  return crypto.randomBytes(32);
}

export function corruptBackupData(data: Buffer): Buffer {
  const corrupted = Buffer.from(data);
  corrupted[Math.floor(corrupted.length / 2)] ^= 0xff;
  return corrupted;
}
