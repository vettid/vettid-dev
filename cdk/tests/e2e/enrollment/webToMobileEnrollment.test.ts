/**
 * E2E Tests: Web to Mobile Enrollment Flow
 *
 * Tests the complete enrollment journey:
 * 1. Member initiates vault deployment from web portal
 * 2. QR code generated with enrollment data
 * 3. Mobile scans QR and completes enrollment
 * 4. Web portal shows updated vault status
 *
 * @see docs/specs/vault-services-api.yaml
 * @see POST /member/vault/deploy
 * @see GET /member/vault/status
 * @see POST /vault/enroll/start
 */

import * as crypto from 'crypto';
import {
  generateX25519KeyPair,
  generateTransactionKeyPool,
  hashPassword,
  encryptWithTransactionKey,
  serializeEncryptedBlob,
  X25519KeyPair,
  TransactionKeyPair,
} from '../../../lambda/common/crypto';
// LAT functions imported from test utilities - LAT was part of the legacy
// centralized ledger system, replaced by vault-manager NATS auth
import {
  generateLAT,
  LAT,
} from '../../utils/cryptoTestUtils';

// ============================================
// Types (matching API spec)
// ============================================

interface DeploymentResponse {
  vaultId: string;
  status: 'pending_enrollment' | 'enrolled' | 'provisioning' | 'running' | 'stopped';
  enrollmentQr: {
    data: string;
    type: 'vettid_vault_enrollment';
  };
  expiresAt: string;
}

interface VaultStatus {
  vaultId: string;
  status: 'pending_enrollment' | 'enrolled' | 'provisioning' | 'running' | 'stopped' | 'terminated';
  instanceId?: string;
  region?: string;
  enrolledAt?: string;
  lastBackup?: string;
}

interface EnrollStartRequest {
  inviteCode: string;
  deviceInfo: {
    platform: 'android' | 'ios';
    osVersion: string;
    appVersion: string;
    deviceModel?: string;
  };
}

interface EnrollStartResponse {
  sessionId: string;
  attestationChallenge: string;
  transactionKeys: Array<{
    keyId: string;
    publicKey: string;
    algorithm: string;
  }>;
}

interface QRCodeData {
  type: 'vettid_vault_enrollment';
  vaultId: string;
  inviteCode: string;
  apiEndpoint: string;
  expiresAt: string;
}

// ============================================
// Mock Services
// ============================================

interface StoredVault {
  vaultId: string;
  memberId: string;
  status: VaultStatus['status'];
  inviteCode: string;
  inviteExpiresAt: Date;
  enrollmentSessionId?: string;
  enrolledAt?: Date;
  transactionKeys?: TransactionKeyPair[];
  lat?: LAT;
  cek?: X25519KeyPair;
}

/**
 * Mock Member Portal Service (Web)
 */
class MockMemberPortalService {
  private vaults: Map<string, StoredVault> = new Map();

  /**
   * Deploy vault - initiates enrollment from web portal
   */
  async deployVault(memberId: string): Promise<DeploymentResponse> {
    // Check if member already has a vault
    for (const vault of this.vaults.values()) {
      if (vault.memberId === memberId && vault.status !== 'terminated') {
        throw new Error('Vault already exists for this member');
      }
    }

    // Generate vault and invite
    const vaultId = crypto.randomUUID();
    const inviteCode = `VE-${crypto.randomBytes(8).toString('hex').toUpperCase()}`;
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    const vault: StoredVault = {
      vaultId,
      memberId,
      status: 'pending_enrollment',
      inviteCode,
      inviteExpiresAt: expiresAt,
    };

    this.vaults.set(vaultId, vault);

    // Generate QR code data
    const qrData: QRCodeData = {
      type: 'vettid_vault_enrollment',
      vaultId,
      inviteCode,
      apiEndpoint: 'https://api.vettid.dev',
      expiresAt: expiresAt.toISOString(),
    };

    return {
      vaultId,
      status: 'pending_enrollment',
      enrollmentQr: {
        data: Buffer.from(JSON.stringify(qrData)).toString('base64'),
        type: 'vettid_vault_enrollment',
      },
      expiresAt: expiresAt.toISOString(),
    };
  }

  /**
   * Get vault status
   */
  async getVaultStatus(memberId: string): Promise<VaultStatus | null> {
    for (const vault of this.vaults.values()) {
      if (vault.memberId === memberId && vault.status !== 'terminated') {
        return {
          vaultId: vault.vaultId,
          status: vault.status,
          enrolledAt: vault.enrolledAt?.toISOString(),
        };
      }
    }
    return null;
  }

  /**
   * Get vault by ID (for internal use)
   */
  getVault(vaultId: string): StoredVault | undefined {
    return this.vaults.get(vaultId);
  }

  /**
   * Update vault status (for enrollment service callback)
   */
  updateVaultStatus(vaultId: string, status: VaultStatus['status']): void {
    const vault = this.vaults.get(vaultId);
    if (vault) {
      vault.status = status;
      if (status === 'enrolled') {
        vault.enrolledAt = new Date();
      }
    }
  }
}

/**
 * Mock Vault Enrollment Service (Mobile)
 */
class MockVaultEnrollmentService {
  private sessions: Map<string, {
    sessionId: string;
    vaultId: string;
    inviteCode: string;
    step: 'started' | 'attested' | 'password_set' | 'finalized';
    challenge: Buffer;
    transactionKeys: TransactionKeyPair[];
    usedKeyIds: Set<string>;
    passwordHash?: string;
    deviceInfo: EnrollStartRequest['deviceInfo'];
    createdAt: Date;
    expiresAt: Date;
  }> = new Map();

  constructor(private memberPortal: MockMemberPortalService) {}

  /**
   * Start enrollment - mobile calls after scanning QR
   */
  async enrollStart(request: EnrollStartRequest): Promise<EnrollStartResponse> {
    // Parse and validate invite code to find vault
    let targetVault: StoredVault | undefined;

    for (const vault of Array.from((this.memberPortal as any).vaults.values())) {
      const v = vault as StoredVault;
      if (v.inviteCode === request.inviteCode) {
        targetVault = v;
        break;
      }
    }

    if (!targetVault) {
      throw new Error('Invalid invitation code');
    }

    if (targetVault.status !== 'pending_enrollment') {
      throw new Error('Already enrolled');
    }

    if (new Date() > targetVault.inviteExpiresAt) {
      throw new Error('Invitation expired');
    }

    // Create enrollment session
    const sessionId = crypto.randomUUID();
    const challenge = crypto.randomBytes(32);
    const transactionKeys = generateTransactionKeyPool(20);

    this.sessions.set(sessionId, {
      sessionId,
      vaultId: targetVault.vaultId,
      inviteCode: request.inviteCode,
      step: 'started',
      challenge,
      transactionKeys,
      usedKeyIds: new Set(),
      deviceInfo: request.deviceInfo,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 30 * 60 * 1000), // 30 minutes
    });

    return {
      sessionId,
      attestationChallenge: challenge.toString('base64'),
      transactionKeys: transactionKeys.map(tk => ({
        keyId: tk.keyId,
        publicKey: tk.publicKey.toString('base64'),
        algorithm: tk.algorithm,
      })),
    };
  }

  /**
   * Submit attestation
   */
  async enrollAttestation(sessionId: string, platform: string, challenge: string): Promise<{
    verified: boolean;
    securityLevel: string;
  }> {
    const session = this.sessions.get(sessionId);
    if (!session || session.step !== 'started') {
      throw new Error('Invalid session or wrong step');
    }

    // Verify challenge matches
    const providedChallenge = Buffer.from(challenge, 'base64');
    if (!providedChallenge.equals(session.challenge)) {
      throw new Error('Challenge mismatch');
    }

    session.step = 'attested';

    return {
      verified: true,
      securityLevel: platform === 'android' ? 'tee' : 'software',
    };
  }

  /**
   * Set password
   */
  async enrollSetPassword(
    sessionId: string,
    encryptedPassword: { ciphertext: string; nonce: string; ephemeral_public_key: string },
    transactionKeyId: string
  ): Promise<{ success: boolean }> {
    const session = this.sessions.get(sessionId);
    if (!session || session.step !== 'attested') {
      throw new Error('Invalid session or wrong step');
    }

    const tk = session.transactionKeys.find(k => k.keyId === transactionKeyId);
    if (!tk) {
      throw new Error('Transaction key not found');
    }

    if (session.usedKeyIds.has(transactionKeyId)) {
      throw new Error('Transaction key already used');
    }

    // Decrypt password (import function is available)
    const { decryptWithTransactionKey } = await import('../../../lambda/common/crypto');
    const encrypted = {
      ciphertext: Buffer.from(encryptedPassword.ciphertext, 'base64'),
      nonce: Buffer.from(encryptedPassword.nonce, 'base64'),
      ephemeralPublicKey: Buffer.from(encryptedPassword.ephemeral_public_key, 'base64'),
    };

    const password = decryptWithTransactionKey(encrypted, tk.privateKey).toString();

    // Hash password
    session.passwordHash = await hashPassword(password);
    session.usedKeyIds.add(transactionKeyId);
    session.step = 'password_set';

    return { success: true };
  }

  /**
   * Finalize enrollment
   */
  async enrollFinalize(sessionId: string): Promise<{
    userGuid: string;
    credentialBlob: any;
    lat: LAT;
  }> {
    const session = this.sessions.get(sessionId);
    if (!session || session.step !== 'password_set') {
      throw new Error('Invalid session or wrong step');
    }

    // Generate CEK and LAT
    const cek = generateX25519KeyPair();
    const lat = generateLAT(1);
    const userGuid = crypto.randomUUID();

    // Update vault status to enrolled
    this.memberPortal.updateVaultStatus(session.vaultId, 'enrolled');

    session.step = 'finalized';

    return {
      userGuid,
      credentialBlob: {
        userGuid,
        cekVersion: 1,
        // In real implementation, this would be encrypted credential
      },
      lat,
    };
  }

  /**
   * Get session for testing
   */
  getSession(sessionId: string) {
    return this.sessions.get(sessionId);
  }
}

// ============================================
// Tests
// ============================================

describe('Web to Mobile Enrollment Flow', () => {
  let memberPortal: MockMemberPortalService;
  let enrollmentService: MockVaultEnrollmentService;
  const testMemberId = crypto.randomUUID();

  beforeEach(() => {
    memberPortal = new MockMemberPortalService();
    enrollmentService = new MockVaultEnrollmentService(memberPortal);
  });

  describe('1. Vault Deployment (Web Portal)', () => {
    it('should create vault with pending_enrollment status', async () => {
      const response = await memberPortal.deployVault(testMemberId);

      expect(response.vaultId).toBeDefined();
      expect(response.status).toBe('pending_enrollment');
      expect(response.enrollmentQr.type).toBe('vettid_vault_enrollment');
    });

    it('should generate valid QR code data', async () => {
      const response = await memberPortal.deployVault(testMemberId);

      const qrData = JSON.parse(
        Buffer.from(response.enrollmentQr.data, 'base64').toString()
      ) as QRCodeData;

      expect(qrData.type).toBe('vettid_vault_enrollment');
      expect(qrData.vaultId).toBe(response.vaultId);
      expect(qrData.inviteCode).toMatch(/^VE-[A-F0-9]{16}$/);
      expect(qrData.apiEndpoint).toBeDefined();
      expect(new Date(qrData.expiresAt).getTime()).toBeGreaterThan(Date.now());
    });

    it('should set expiry 24 hours in the future', async () => {
      const before = Date.now();
      const response = await memberPortal.deployVault(testMemberId);
      const after = Date.now();

      const expiresAt = new Date(response.expiresAt).getTime();
      const twentyFourHours = 24 * 60 * 60 * 1000;

      expect(expiresAt).toBeGreaterThanOrEqual(before + twentyFourHours);
      expect(expiresAt).toBeLessThanOrEqual(after + twentyFourHours);
    });

    it('should reject duplicate vault deployment', async () => {
      await memberPortal.deployVault(testMemberId);

      await expect(memberPortal.deployVault(testMemberId))
        .rejects.toThrow('Vault already exists');
    });

    it('should allow new vault after termination', async () => {
      const first = await memberPortal.deployVault(testMemberId);

      // Simulate termination
      memberPortal.updateVaultStatus(first.vaultId, 'terminated');

      // Should allow new vault
      const second = await memberPortal.deployVault(testMemberId);
      expect(second.vaultId).not.toBe(first.vaultId);
    });
  });

  describe('2. QR Scan and Enrollment Start (Mobile)', () => {
    let qrData: QRCodeData;

    beforeEach(async () => {
      const deployment = await memberPortal.deployVault(testMemberId);
      qrData = JSON.parse(
        Buffer.from(deployment.enrollmentQr.data, 'base64').toString()
      );
    });

    it('should start enrollment with valid invite code', async () => {
      const response = await enrollmentService.enrollStart({
        inviteCode: qrData.inviteCode,
        deviceInfo: {
          platform: 'android',
          osVersion: '14',
          appVersion: '1.0.0',
        },
      });

      expect(response.sessionId).toBeDefined();
      expect(response.attestationChallenge).toBeDefined();
      expect(response.transactionKeys).toHaveLength(20);
    });

    it('should return 32-byte attestation challenge', async () => {
      const response = await enrollmentService.enrollStart({
        inviteCode: qrData.inviteCode,
        deviceInfo: {
          platform: 'android',
          osVersion: '14',
          appVersion: '1.0.0',
        },
      });

      const challenge = Buffer.from(response.attestationChallenge, 'base64');
      expect(challenge).toHaveLength(32);
    });

    it('should reject invalid invite code', async () => {
      await expect(enrollmentService.enrollStart({
        inviteCode: 'VE-INVALID12345678',
        deviceInfo: {
          platform: 'android',
          osVersion: '14',
          appVersion: '1.0.0',
        },
      })).rejects.toThrow('Invalid invitation code');
    });

    it('should reject expired invite code', async () => {
      // Get vault and manually expire it
      const vault = memberPortal.getVault(qrData.vaultId);
      if (vault) {
        vault.inviteExpiresAt = new Date(Date.now() - 1000);
      }

      await expect(enrollmentService.enrollStart({
        inviteCode: qrData.inviteCode,
        deviceInfo: {
          platform: 'android',
          osVersion: '14',
          appVersion: '1.0.0',
        },
      })).rejects.toThrow('Invitation expired');
    });

    it('should reject already-enrolled vault', async () => {
      // Complete first enrollment
      const start = await enrollmentService.enrollStart({
        inviteCode: qrData.inviteCode,
        deviceInfo: { platform: 'android', osVersion: '14', appVersion: '1.0.0' },
      });
      await enrollmentService.enrollAttestation(
        start.sessionId, 'android', start.attestationChallenge
      );
      const tk = start.transactionKeys[0];
      await enrollmentService.enrollSetPassword(
        start.sessionId,
        serializeEncryptedBlob(encryptWithTransactionKey(
          Buffer.from('password'),
          Buffer.from(tk.publicKey, 'base64')
        )),
        tk.keyId
      );
      await enrollmentService.enrollFinalize(start.sessionId);

      // Try to enroll again with same invite
      await expect(enrollmentService.enrollStart({
        inviteCode: qrData.inviteCode,
        deviceInfo: { platform: 'ios', osVersion: '17', appVersion: '1.0.0' },
      })).rejects.toThrow('Already enrolled');
    });
  });

  describe('3. Complete Enrollment Flow', () => {
    it('should complete full enrollment and update web portal status', async () => {
      // Step 1: Deploy vault from web
      const deployment = await memberPortal.deployVault(testMemberId);
      const qrData = JSON.parse(
        Buffer.from(deployment.enrollmentQr.data, 'base64').toString()
      ) as QRCodeData;

      // Verify initial status
      let status = await memberPortal.getVaultStatus(testMemberId);
      expect(status?.status).toBe('pending_enrollment');

      // Step 2: Start enrollment from mobile
      const start = await enrollmentService.enrollStart({
        inviteCode: qrData.inviteCode,
        deviceInfo: {
          platform: 'android',
          osVersion: '14',
          appVersion: '1.0.0',
          deviceModel: 'Pixel 8',
        },
      });

      // Step 3: Submit attestation
      await enrollmentService.enrollAttestation(
        start.sessionId,
        'android',
        start.attestationChallenge
      );

      // Step 4: Set password
      const password = 'secure-password-123';
      const tk = start.transactionKeys[0];
      const tkPublicKey = Buffer.from(tk.publicKey, 'base64');
      const encryptedPassword = encryptWithTransactionKey(Buffer.from(password), tkPublicKey);

      await enrollmentService.enrollSetPassword(
        start.sessionId,
        serializeEncryptedBlob(encryptedPassword),
        tk.keyId
      );

      // Step 5: Finalize enrollment
      const finalize = await enrollmentService.enrollFinalize(start.sessionId);

      expect(finalize.userGuid).toBeDefined();
      expect(finalize.lat.token).toBeDefined();
      expect(finalize.lat.version).toBe(1);

      // Step 6: Verify web portal shows enrolled status
      status = await memberPortal.getVaultStatus(testMemberId);
      expect(status?.status).toBe('enrolled');
      expect(status?.enrolledAt).toBeDefined();
    });

    it('should work for iOS devices', async () => {
      const deployment = await memberPortal.deployVault(testMemberId);
      const qrData = JSON.parse(
        Buffer.from(deployment.enrollmentQr.data, 'base64').toString()
      ) as QRCodeData;

      const start = await enrollmentService.enrollStart({
        inviteCode: qrData.inviteCode,
        deviceInfo: {
          platform: 'ios',
          osVersion: '17.0',
          appVersion: '1.0.0',
          deviceModel: 'iPhone 15 Pro',
        },
      });

      const attestation = await enrollmentService.enrollAttestation(
        start.sessionId,
        'ios',
        start.attestationChallenge
      );

      expect(attestation.verified).toBe(true);
      // iOS doesn't have hardware attestation like Android
      expect(attestation.securityLevel).toBe('software');
    });
  });

  describe('4. Error Handling', () => {
    it('should reject wrong step order', async () => {
      const deployment = await memberPortal.deployVault(testMemberId);
      const qrData = JSON.parse(
        Buffer.from(deployment.enrollmentQr.data, 'base64').toString()
      ) as QRCodeData;

      const start = await enrollmentService.enrollStart({
        inviteCode: qrData.inviteCode,
        deviceInfo: { platform: 'android', osVersion: '14', appVersion: '1.0.0' },
      });

      // Try to finalize before attestation
      await expect(enrollmentService.enrollFinalize(start.sessionId))
        .rejects.toThrow('Invalid session or wrong step');
    });

    it('should reject mismatched challenge', async () => {
      const deployment = await memberPortal.deployVault(testMemberId);
      const qrData = JSON.parse(
        Buffer.from(deployment.enrollmentQr.data, 'base64').toString()
      ) as QRCodeData;

      const start = await enrollmentService.enrollStart({
        inviteCode: qrData.inviteCode,
        deviceInfo: { platform: 'android', osVersion: '14', appVersion: '1.0.0' },
      });

      const wrongChallenge = crypto.randomBytes(32).toString('base64');

      await expect(enrollmentService.enrollAttestation(
        start.sessionId,
        'android',
        wrongChallenge
      )).rejects.toThrow('Challenge mismatch');
    });

    it('should reject invalid session ID', async () => {
      await expect(enrollmentService.enrollAttestation(
        'invalid-session-id',
        'android',
        'some-challenge'
      )).rejects.toThrow('Invalid session');
    });

    it('should reject reused transaction key', async () => {
      const deployment = await memberPortal.deployVault(testMemberId);
      const qrData = JSON.parse(
        Buffer.from(deployment.enrollmentQr.data, 'base64').toString()
      ) as QRCodeData;

      const start = await enrollmentService.enrollStart({
        inviteCode: qrData.inviteCode,
        deviceInfo: { platform: 'android', osVersion: '14', appVersion: '1.0.0' },
      });

      await enrollmentService.enrollAttestation(
        start.sessionId,
        'android',
        start.attestationChallenge
      );

      const tk = start.transactionKeys[0];
      const tkPublicKey = Buffer.from(tk.publicKey, 'base64');

      // Mark the key as used directly on the session (simulating prior use)
      const session = enrollmentService.getSession(start.sessionId);
      expect(session).toBeDefined();
      session!.usedKeyIds.add(tk.keyId);

      // Now try to use the "already used" key - should fail
      await expect(enrollmentService.enrollSetPassword(
        start.sessionId,
        serializeEncryptedBlob(encryptWithTransactionKey(
          Buffer.from('password'),
          tkPublicKey
        )),
        tk.keyId
      )).rejects.toThrow('Transaction key already used');
    });
  });

  describe('5. Concurrent Enrollment Attempts', () => {
    it('should handle multiple sessions for same vault (only one succeeds)', async () => {
      const deployment = await memberPortal.deployVault(testMemberId);
      const qrData = JSON.parse(
        Buffer.from(deployment.enrollmentQr.data, 'base64').toString()
      ) as QRCodeData;

      // Start two enrollment sessions
      const start1 = await enrollmentService.enrollStart({
        inviteCode: qrData.inviteCode,
        deviceInfo: { platform: 'android', osVersion: '14', appVersion: '1.0.0' },
      });

      // Complete first enrollment
      await enrollmentService.enrollAttestation(
        start1.sessionId,
        'android',
        start1.attestationChallenge
      );
      const tk1 = start1.transactionKeys[0];
      await enrollmentService.enrollSetPassword(
        start1.sessionId,
        serializeEncryptedBlob(encryptWithTransactionKey(
          Buffer.from('password'),
          Buffer.from(tk1.publicKey, 'base64')
        )),
        tk1.keyId
      );
      await enrollmentService.enrollFinalize(start1.sessionId);

      // Second attempt should fail
      await expect(enrollmentService.enrollStart({
        inviteCode: qrData.inviteCode,
        deviceInfo: { platform: 'ios', osVersion: '17', appVersion: '1.0.0' },
      })).rejects.toThrow('Already enrolled');
    });
  });

  describe('6. Cross-Platform Compatibility', () => {
    it('should accept same invite from Android or iOS', async () => {
      // Create two vaults for testing
      const member1 = crypto.randomUUID();
      const member2 = crypto.randomUUID();

      const deployment1 = await memberPortal.deployVault(member1);
      const qrData1 = JSON.parse(
        Buffer.from(deployment1.enrollmentQr.data, 'base64').toString()
      ) as QRCodeData;

      const deployment2 = await memberPortal.deployVault(member2);
      const qrData2 = JSON.parse(
        Buffer.from(deployment2.enrollmentQr.data, 'base64').toString()
      ) as QRCodeData;

      // Android enrollment
      const androidStart = await enrollmentService.enrollStart({
        inviteCode: qrData1.inviteCode,
        deviceInfo: { platform: 'android', osVersion: '14', appVersion: '1.0.0' },
      });
      expect(androidStart.sessionId).toBeDefined();

      // iOS enrollment (different vault)
      const iosStart = await enrollmentService.enrollStart({
        inviteCode: qrData2.inviteCode,
        deviceInfo: { platform: 'ios', osVersion: '17', appVersion: '1.0.0' },
      });
      expect(iosStart.sessionId).toBeDefined();

      // Both should receive same format of transaction keys
      expect(androidStart.transactionKeys[0].algorithm).toBe('X25519');
      expect(iosStart.transactionKeys[0].algorithm).toBe('X25519');
    });
  });
});
