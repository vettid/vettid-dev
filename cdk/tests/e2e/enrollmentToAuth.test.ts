/**
 * End-to-End Tests: Complete Enrollment to Authentication Flow
 *
 * Tests the full user journey from initial enrollment through authentication:
 * 1. Enrollment start → device attestation → password setup → finalize
 * 2. Action request → auth execute → LAT rotation
 * 3. Re-authentication with rotated LAT
 *
 * This test simulates the complete Protean credential lifecycle.
 *
 * @see cdk/coordination/specs/vault-services-api.yaml
 * @see cdk/coordination/specs/credential-format.md
 */

import * as crypto from 'crypto';
import {
  generateX25519KeyPair,
  deriveSharedSecret,
  hkdf,
  encryptWithPublicKey,
  decryptWithPrivateKey,
  encryptWithTransactionKey,
  decryptWithTransactionKey,
  hashPassword,
  verifyPassword,
  generateTransactionKeyPool,
  serializeEncryptedBlob,
  deserializeEncryptedBlob,
  X25519KeyPair,
  EncryptedBlob,
  TransactionKeyPair,
} from '../../lambda/common/crypto';
// LAT functions imported from test utilities - LAT was part of the legacy
// centralized ledger system, replaced by vault-manager NATS auth
import {
  generateLAT,
  hashLATToken,
  verifyLATToken,
  LAT,
} from '../utils/cryptoTestUtils';

// ============================================
// Mock Services (Simulating Backend)
// ============================================

interface EnrollmentSession {
  sessionId: string;
  inviteCode: string;
  step: 'started' | 'attested' | 'password_set' | 'finalized';
  attestationChallenge: Buffer;
  transactionKeys: TransactionKeyPair[];
  usedTransactionKeyIds: Set<string>;
  passwordHash?: string;
  cek?: X25519KeyPair;
  lat?: LAT;
  userGuid?: string;
  createdAt: Date;
  expiresAt: Date;
}

interface StoredCredential {
  userGuid: string;
  latTokenHash: string;
  latVersion: number;
  cekKeyId: string;
  cekPublicKey: Buffer;
  cekPrivateKeyEncrypted: Buffer;
  passwordHash: string;
  transactionKeys: TransactionKeyPair[];
  usedTransactionKeyIds: Set<string>;
  failedAttempts: number;
  status: 'active' | 'locked' | 'expired';
  createdAt: Date;
  lastAuthAt?: Date;
}

interface AuthSession {
  sessionId: string;
  userGuid: string;
  challenge: Buffer;
  transactionKeyIds: string[];
  createdAt: Date;
  expiresAt: Date;
}

/**
 * Mock Vault Service - Simulates the complete backend
 */
class MockVaultService {
  private enrollmentSessions: Map<string, EnrollmentSession> = new Map();
  private authSessions: Map<string, AuthSession> = new Map();
  private credentials: Map<string, StoredCredential> = new Map();
  private invites: Map<string, { code: string; used: boolean }> = new Map();

  constructor() {
    // Pre-populate a valid invite
    this.invites.set('VALID-INVITE-123', { code: 'VALID-INVITE-123', used: false });
  }

  // --- Enrollment Flow ---

  async enrollStart(inviteCode: string, deviceInfo: { platform: string; appVersion: string }): Promise<{
    sessionId: string;
    attestationChallenge: string;
    transactionKeys: { keyId: string; publicKey: string; algorithm: string }[];
  }> {
    // Validate invite
    const invite = this.invites.get(inviteCode);
    if (!invite || invite.used) {
      throw new Error('Invalid or already used invite code');
    }

    // Generate session
    const sessionId = crypto.randomUUID();
    const attestationChallenge = crypto.randomBytes(32);
    const transactionKeys = generateTransactionKeyPool(20);

    const session: EnrollmentSession = {
      sessionId,
      inviteCode,
      step: 'started',
      attestationChallenge,
      transactionKeys,
      usedTransactionKeyIds: new Set(),
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 30 * 60 * 1000), // 30 minutes
    };

    this.enrollmentSessions.set(sessionId, session);

    return {
      sessionId,
      attestationChallenge: attestationChallenge.toString('base64'),
      transactionKeys: transactionKeys.map(tk => ({
        keyId: tk.keyId,
        publicKey: tk.publicKey.toString('base64'),
        algorithm: tk.algorithm,
      })),
    };
  }

  async enrollAttestation(sessionId: string, attestationData: {
    platform: string;
    attestationObject: string;
    challenge: string;
  }): Promise<{ verified: boolean; securityLevel: string }> {
    const session = this.enrollmentSessions.get(sessionId);
    if (!session || session.step !== 'started') {
      throw new Error('Invalid session or wrong step');
    }

    // Mock attestation verification
    // In production, this would verify Android/iOS attestation certificates
    const providedChallenge = Buffer.from(attestationData.challenge, 'base64');
    if (!providedChallenge.equals(session.attestationChallenge)) {
      throw new Error('Challenge mismatch');
    }

    session.step = 'attested';

    return {
      verified: true,
      securityLevel: 'tee', // or 'strongbox' for StrongBox
    };
  }

  async enrollSetPassword(sessionId: string, encryptedPassword: {
    ciphertext: string;
    nonce: string;
    ephemeral_public_key: string;
  }, transactionKeyId: string): Promise<{ success: boolean }> {
    const session = this.enrollmentSessions.get(sessionId);
    if (!session || session.step !== 'attested') {
      throw new Error('Invalid session or wrong step');
    }

    // Find and use transaction key
    const tk = session.transactionKeys.find(k => k.keyId === transactionKeyId);
    if (!tk) {
      throw new Error('Transaction key not found');
    }

    if (session.usedTransactionKeyIds.has(transactionKeyId)) {
      throw new Error('Transaction key already used');
    }

    // Decrypt password
    const encrypted: EncryptedBlob = {
      ciphertext: Buffer.from(encryptedPassword.ciphertext, 'base64'),
      nonce: Buffer.from(encryptedPassword.nonce, 'base64'),
      ephemeralPublicKey: Buffer.from(encryptedPassword.ephemeral_public_key, 'base64'),
    };

    const password = decryptWithTransactionKey(encrypted, tk.privateKey).toString();

    // Hash password
    const passwordHash = await hashPassword(password);

    session.passwordHash = passwordHash;
    session.usedTransactionKeyIds.add(transactionKeyId);
    session.step = 'password_set';

    return { success: true };
  }

  async enrollFinalize(sessionId: string): Promise<{
    userGuid: string;
    credentialBlob: {
      ciphertext: string;
      nonce: string;
      ephemeral_public_key: string;
    };
    lat: { token: string; version: number };
  }> {
    const session = this.enrollmentSessions.get(sessionId);
    if (!session || session.step !== 'password_set') {
      throw new Error('Invalid session or wrong step');
    }

    // Generate CEK
    const cek = generateX25519KeyPair();

    // Generate LAT
    const lat = generateLAT(1);

    // Generate user GUID
    const userGuid = crypto.randomUUID();

    // Create credential blob (contains password hash and policies)
    const credentialData = {
      guid: userGuid,
      passwordHash: session.passwordHash,
      hashAlgorithm: 'pbkdf2-sha256',
      hashVersion: '1.0',
      policies: {
        ttlHours: 24,
        maxFailedAttempts: 3,
      },
    };

    const encryptedCredential = encryptWithPublicKey(
      Buffer.from(JSON.stringify(credentialData)),
      cek.publicKey,
      'credential-encryption-v1'
    );

    // Store credential
    const credential: StoredCredential = {
      userGuid,
      latTokenHash: hashLATToken(lat.token),
      latVersion: lat.version,
      cekKeyId: `cek_${crypto.randomBytes(8).toString('hex')}`,
      cekPublicKey: cek.publicKey,
      cekPrivateKeyEncrypted: cek.privateKey, // In production, encrypt with HSM
      passwordHash: session.passwordHash!,
      transactionKeys: session.transactionKeys.filter(tk => !session.usedTransactionKeyIds.has(tk.keyId)),
      usedTransactionKeyIds: new Set(session.usedTransactionKeyIds),
      failedAttempts: 0,
      status: 'active',
      createdAt: new Date(),
    };

    this.credentials.set(userGuid, credential);

    // Mark invite as used
    const invite = this.invites.get(session.inviteCode);
    if (invite) invite.used = true;

    // Store session info for reference
    session.cek = cek;
    session.lat = lat;
    session.userGuid = userGuid;
    session.step = 'finalized';

    return {
      userGuid,
      credentialBlob: serializeEncryptedBlob(encryptedCredential),
      lat: { token: lat.token, version: lat.version },
    };
  }

  // --- Authentication Flow ---

  async actionRequest(userGuid: string, actionType: string): Promise<{
    sessionId: string;
    challenge: string;
    transactionKeys: { keyId: string; publicKey: string; algorithm: string }[];
    credentialStatus: string;
    failedAttempts: number;
    maxAttempts: number;
  }> {
    const credential = this.credentials.get(userGuid);
    if (!credential) {
      throw new Error('Credential not found');
    }

    if (credential.status === 'locked') {
      throw new Error('Credential locked');
    }

    // Create auth session
    const sessionId = crypto.randomUUID();
    const challenge = crypto.randomBytes(32);

    // Get available transaction keys
    const availableKeys = credential.transactionKeys
      .filter(tk => !credential.usedTransactionKeyIds.has(tk.keyId))
      .slice(0, 5);

    const authSession: AuthSession = {
      sessionId,
      userGuid,
      challenge,
      transactionKeyIds: availableKeys.map(k => k.keyId),
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 5 * 60 * 1000), // 5 minutes
    };

    this.authSessions.set(sessionId, authSession);

    return {
      sessionId,
      challenge: challenge.toString('base64'),
      transactionKeys: availableKeys.map(tk => ({
        keyId: tk.keyId,
        publicKey: tk.publicKey.toString('base64'),
        algorithm: tk.algorithm,
      })),
      credentialStatus: credential.status,
      failedAttempts: credential.failedAttempts,
      maxAttempts: 3,
    };
  }

  async authExecute(sessionId: string, payload: {
    encryptedPassword: { ciphertext: string; nonce: string; ephemeral_public_key: string };
    lat: { token: string; version: number };
    transactionKeyId: string;
    challengeResponse: string;
  }): Promise<{
    success: boolean;
    newLat?: { token: string; version: number };
    failedAttempts?: number;
    error?: string;
  }> {
    const authSession = this.authSessions.get(sessionId);
    if (!authSession) {
      return { success: false, error: 'Invalid session' };
    }

    if (new Date() > authSession.expiresAt) {
      return { success: false, error: 'Session expired' };
    }

    const credential = this.credentials.get(authSession.userGuid);
    if (!credential) {
      return { success: false, error: 'Credential not found' };
    }

    // Verify transaction key
    if (!authSession.transactionKeyIds.includes(payload.transactionKeyId)) {
      return { success: false, error: 'Invalid transaction key' };
    }

    if (credential.usedTransactionKeyIds.has(payload.transactionKeyId)) {
      return { success: false, error: 'Transaction key already used' };
    }

    const tk = credential.transactionKeys.find(k => k.keyId === payload.transactionKeyId);
    if (!tk) {
      return { success: false, error: 'Transaction key not found' };
    }

    // Verify LAT
    if (!verifyLATToken(payload.lat.token, credential.latTokenHash)) {
      credential.failedAttempts++;
      if (credential.failedAttempts >= 3) {
        credential.status = 'locked';
      }
      return {
        success: false,
        error: 'Invalid LAT',
        failedAttempts: credential.failedAttempts,
      };
    }

    if (payload.lat.version !== credential.latVersion) {
      credential.failedAttempts++;
      if (credential.failedAttempts >= 3) {
        credential.status = 'locked';
      }
      return {
        success: false,
        error: 'LAT version mismatch',
        failedAttempts: credential.failedAttempts,
      };
    }

    // Decrypt and verify password
    const encrypted: EncryptedBlob = {
      ciphertext: Buffer.from(payload.encryptedPassword.ciphertext, 'base64'),
      nonce: Buffer.from(payload.encryptedPassword.nonce, 'base64'),
      ephemeralPublicKey: Buffer.from(payload.encryptedPassword.ephemeral_public_key, 'base64'),
    };

    let password: string;
    try {
      password = decryptWithTransactionKey(encrypted, tk.privateKey).toString();
    } catch {
      credential.failedAttempts++;
      if (credential.failedAttempts >= 3) {
        credential.status = 'locked';
      }
      return {
        success: false,
        error: 'Failed to decrypt password',
        failedAttempts: credential.failedAttempts,
      };
    }

    const passwordValid = await verifyPassword(credential.passwordHash, password);
    if (!passwordValid) {
      credential.failedAttempts++;
      if (credential.failedAttempts >= 3) {
        credential.status = 'locked';
      }
      return {
        success: false,
        error: 'Invalid password',
        failedAttempts: credential.failedAttempts,
      };
    }

    // Success! Rotate LAT
    const newLat = generateLAT(credential.latVersion + 1);
    credential.latTokenHash = hashLATToken(newLat.token);
    credential.latVersion = newLat.version;
    credential.failedAttempts = 0;
    credential.usedTransactionKeyIds.add(payload.transactionKeyId);
    credential.lastAuthAt = new Date();

    // Cleanup session
    this.authSessions.delete(sessionId);

    return {
      success: true,
      newLat: { token: newLat.token, version: newLat.version },
    };
  }

  // --- Helper methods for testing ---

  getCredential(userGuid: string): StoredCredential | undefined {
    return this.credentials.get(userGuid);
  }

  getEnrollmentSession(sessionId: string): EnrollmentSession | undefined {
    return this.enrollmentSessions.get(sessionId);
  }

  replenishTransactionKeys(userGuid: string, count: number = 20): void {
    const credential = this.credentials.get(userGuid);
    if (credential) {
      const newKeys = generateTransactionKeyPool(count);
      credential.transactionKeys.push(...newKeys);
    }
  }
}

// ============================================
// End-to-End Tests
// ============================================

describe('End-to-End: Enrollment to Authentication', () => {
  let vault: MockVaultService;

  beforeEach(() => {
    vault = new MockVaultService();
  });

  describe('1. Complete Enrollment Flow', () => {
    it('should complete full enrollment from invite to credential', async () => {
      // Step 1: Start enrollment
      const startResponse = await vault.enrollStart('VALID-INVITE-123', {
        platform: 'android',
        appVersion: '1.0.0',
      });

      expect(startResponse.sessionId).toBeDefined();
      expect(startResponse.attestationChallenge).toBeDefined();
      expect(startResponse.transactionKeys.length).toBe(20);

      // Step 2: Submit attestation
      const attestResponse = await vault.enrollAttestation(startResponse.sessionId, {
        platform: 'android',
        attestationObject: 'mock-attestation-data',
        challenge: startResponse.attestationChallenge,
      });

      expect(attestResponse.verified).toBe(true);
      expect(attestResponse.securityLevel).toBe('tee');

      // Step 3: Set password (encrypted with transaction key)
      const password = 'my-secure-password-123';
      const tkPublicKey = Buffer.from(startResponse.transactionKeys[0].publicKey, 'base64');
      const encryptedPassword = encryptWithTransactionKey(Buffer.from(password), tkPublicKey);

      const passwordResponse = await vault.enrollSetPassword(
        startResponse.sessionId,
        serializeEncryptedBlob(encryptedPassword),
        startResponse.transactionKeys[0].keyId
      );

      expect(passwordResponse.success).toBe(true);

      // Step 4: Finalize enrollment
      const finalizeResponse = await vault.enrollFinalize(startResponse.sessionId);

      expect(finalizeResponse.userGuid).toBeDefined();
      expect(finalizeResponse.credentialBlob).toBeDefined();
      expect(finalizeResponse.lat.token).toBeDefined();
      expect(finalizeResponse.lat.version).toBe(1);

      // Verify credential was stored
      const credential = vault.getCredential(finalizeResponse.userGuid);
      expect(credential).toBeDefined();
      expect(credential!.status).toBe('active');
    });

    it('should reject invalid invite code', async () => {
      await expect(vault.enrollStart('INVALID-CODE', {
        platform: 'android',
        appVersion: '1.0.0',
      })).rejects.toThrow('Invalid or already used invite code');
    });

    it('should reject reused invite code', async () => {
      // First enrollment
      const start1 = await vault.enrollStart('VALID-INVITE-123', {
        platform: 'android',
        appVersion: '1.0.0',
      });
      await vault.enrollAttestation(start1.sessionId, {
        platform: 'android',
        attestationObject: 'mock',
        challenge: start1.attestationChallenge,
      });
      const tk = start1.transactionKeys[0];
      await vault.enrollSetPassword(
        start1.sessionId,
        serializeEncryptedBlob(encryptWithTransactionKey(
          Buffer.from('password'),
          Buffer.from(tk.publicKey, 'base64')
        )),
        tk.keyId
      );
      await vault.enrollFinalize(start1.sessionId);

      // Second enrollment with same invite should fail
      await expect(vault.enrollStart('VALID-INVITE-123', {
        platform: 'android',
        appVersion: '1.0.0',
      })).rejects.toThrow('Invalid or already used invite code');
    });
  });

  describe('2. Complete Authentication Flow', () => {
    let userGuid: string;
    let currentLat: LAT;
    const password = 'test-password-456';

    beforeEach(async () => {
      // Set up enrolled user
      const start = await vault.enrollStart('VALID-INVITE-123', {
        platform: 'android',
        appVersion: '1.0.0',
      });
      await vault.enrollAttestation(start.sessionId, {
        platform: 'android',
        attestationObject: 'mock',
        challenge: start.attestationChallenge,
      });
      const tk = start.transactionKeys[0];
      await vault.enrollSetPassword(
        start.sessionId,
        serializeEncryptedBlob(encryptWithTransactionKey(
          Buffer.from(password),
          Buffer.from(tk.publicKey, 'base64')
        )),
        tk.keyId
      );
      const finalize = await vault.enrollFinalize(start.sessionId);
      userGuid = finalize.userGuid;
      currentLat = { token: finalize.lat.token, version: finalize.lat.version };
    });

    it('should authenticate successfully and rotate LAT', async () => {
      // Step 1: Request action
      const actionResponse = await vault.actionRequest(userGuid, 'authenticate');

      expect(actionResponse.sessionId).toBeDefined();
      expect(actionResponse.challenge).toBeDefined();
      expect(actionResponse.transactionKeys.length).toBeGreaterThan(0);
      expect(actionResponse.credentialStatus).toBe('active');
      expect(actionResponse.failedAttempts).toBe(0);

      // Step 2: Execute auth
      const tk = actionResponse.transactionKeys[0];
      const encryptedPassword = encryptWithTransactionKey(
        Buffer.from(password),
        Buffer.from(tk.publicKey, 'base64')
      );

      const authResponse = await vault.authExecute(actionResponse.sessionId, {
        encryptedPassword: serializeEncryptedBlob(encryptedPassword),
        lat: currentLat,
        transactionKeyId: tk.keyId,
        challengeResponse: actionResponse.challenge,
      });

      expect(authResponse.success).toBe(true);
      expect(authResponse.newLat).toBeDefined();
      expect(authResponse.newLat!.version).toBe(currentLat.version + 1);
    });

    it('should reject wrong password', async () => {
      const actionResponse = await vault.actionRequest(userGuid, 'authenticate');
      const tk = actionResponse.transactionKeys[0];
      const encryptedPassword = encryptWithTransactionKey(
        Buffer.from('wrong-password'),
        Buffer.from(tk.publicKey, 'base64')
      );

      const authResponse = await vault.authExecute(actionResponse.sessionId, {
        encryptedPassword: serializeEncryptedBlob(encryptedPassword),
        lat: currentLat,
        transactionKeyId: tk.keyId,
        challengeResponse: actionResponse.challenge,
      });

      expect(authResponse.success).toBe(false);
      expect(authResponse.error).toBe('Invalid password');
      expect(authResponse.failedAttempts).toBe(1);
    });

    it('should reject invalid LAT', async () => {
      const actionResponse = await vault.actionRequest(userGuid, 'authenticate');
      const tk = actionResponse.transactionKeys[0];
      const encryptedPassword = encryptWithTransactionKey(
        Buffer.from(password),
        Buffer.from(tk.publicKey, 'base64')
      );

      const authResponse = await vault.authExecute(actionResponse.sessionId, {
        encryptedPassword: serializeEncryptedBlob(encryptedPassword),
        lat: { token: 'invalid-token', version: currentLat.version },
        transactionKeyId: tk.keyId,
        challengeResponse: actionResponse.challenge,
      });

      expect(authResponse.success).toBe(false);
      expect(authResponse.error).toBe('Invalid LAT');
    });

    it('should reject old LAT version', async () => {
      // First successful auth to increment LAT version
      const action1 = await vault.actionRequest(userGuid, 'authenticate');
      const tk1 = action1.transactionKeys[0];
      await vault.authExecute(action1.sessionId, {
        encryptedPassword: serializeEncryptedBlob(encryptWithTransactionKey(
          Buffer.from(password),
          Buffer.from(tk1.publicKey, 'base64')
        )),
        lat: currentLat,
        transactionKeyId: tk1.keyId,
        challengeResponse: action1.challenge,
      });

      // Try to auth with old LAT
      const action2 = await vault.actionRequest(userGuid, 'authenticate');
      const tk2 = action2.transactionKeys[0];
      const authResponse = await vault.authExecute(action2.sessionId, {
        encryptedPassword: serializeEncryptedBlob(encryptWithTransactionKey(
          Buffer.from(password),
          Buffer.from(tk2.publicKey, 'base64')
        )),
        lat: currentLat, // Old LAT
        transactionKeyId: tk2.keyId,
        challengeResponse: action2.challenge,
      });

      expect(authResponse.success).toBe(false);
      // Either "Invalid LAT" (token mismatch) or "LAT version mismatch" is acceptable
      // since the old LAT has a different token than the rotated one
      expect(authResponse.error).toMatch(/Invalid LAT|LAT version mismatch/);
    });

    it('should reject reused transaction key', async () => {
      // First auth with transaction key
      const action1 = await vault.actionRequest(userGuid, 'authenticate');
      const tk = action1.transactionKeys[0];
      const auth1 = await vault.authExecute(action1.sessionId, {
        encryptedPassword: serializeEncryptedBlob(encryptWithTransactionKey(
          Buffer.from(password),
          Buffer.from(tk.publicKey, 'base64')
        )),
        lat: currentLat,
        transactionKeyId: tk.keyId,
        challengeResponse: action1.challenge,
      });
      expect(auth1.success).toBe(true);

      // Try to reuse same transaction key
      const action2 = await vault.actionRequest(userGuid, 'authenticate');
      const auth2 = await vault.authExecute(action2.sessionId, {
        encryptedPassword: serializeEncryptedBlob(encryptWithTransactionKey(
          Buffer.from(password),
          Buffer.from(tk.publicKey, 'base64')
        )),
        lat: auth1.newLat!,
        transactionKeyId: tk.keyId, // Reusing same key
        challengeResponse: action2.challenge,
      });

      expect(auth2.success).toBe(false);
      // The error could be "Invalid transaction key" (not in session) or
      // "Transaction key already used" depending on implementation
      expect(auth2.error).toMatch(/transaction key/i);
    });
  });

  describe('3. Multiple Authentication Cycles', () => {
    let userGuid: string;
    let currentLat: LAT;
    const password = 'multi-auth-password';

    beforeEach(async () => {
      // Set up enrolled user
      const start = await vault.enrollStart('VALID-INVITE-123', {
        platform: 'android',
        appVersion: '1.0.0',
      });
      await vault.enrollAttestation(start.sessionId, {
        platform: 'android',
        attestationObject: 'mock',
        challenge: start.attestationChallenge,
      });
      const tk = start.transactionKeys[0];
      await vault.enrollSetPassword(
        start.sessionId,
        serializeEncryptedBlob(encryptWithTransactionKey(
          Buffer.from(password),
          Buffer.from(tk.publicKey, 'base64')
        )),
        tk.keyId
      );
      const finalize = await vault.enrollFinalize(start.sessionId);
      userGuid = finalize.userGuid;
      currentLat = { token: finalize.lat.token, version: finalize.lat.version };
    });

    it('should handle 10 consecutive authentication cycles', async () => {
      for (let i = 0; i < 10; i++) {
        const action = await vault.actionRequest(userGuid, 'authenticate');
        const tk = action.transactionKeys[0];

        const auth = await vault.authExecute(action.sessionId, {
          encryptedPassword: serializeEncryptedBlob(encryptWithTransactionKey(
            Buffer.from(password),
            Buffer.from(tk.publicKey, 'base64')
          )),
          lat: currentLat,
          transactionKeyId: tk.keyId,
          challengeResponse: action.challenge,
        });

        expect(auth.success).toBe(true);
        expect(auth.newLat!.version).toBe(currentLat.version + 1);

        currentLat = auth.newLat!;
      }

      expect(currentLat.version).toBe(11); // 1 initial + 10 rotations
    });

    it('should track LAT version correctly through rotations', async () => {
      const versions: number[] = [currentLat.version];

      for (let i = 0; i < 5; i++) {
        const action = await vault.actionRequest(userGuid, 'authenticate');
        const tk = action.transactionKeys[0];

        const auth = await vault.authExecute(action.sessionId, {
          encryptedPassword: serializeEncryptedBlob(encryptWithTransactionKey(
            Buffer.from(password),
            Buffer.from(tk.publicKey, 'base64')
          )),
          lat: currentLat,
          transactionKeyId: tk.keyId,
          challengeResponse: action.challenge,
        });

        currentLat = auth.newLat!;
        versions.push(currentLat.version);
      }

      // Versions should be strictly increasing
      for (let i = 1; i < versions.length; i++) {
        expect(versions[i]).toBe(versions[i - 1] + 1);
      }
    });
  });

  describe('4. Credential Lockout', () => {
    let userGuid: string;
    let currentLat: LAT;
    const password = 'lockout-password';

    beforeEach(async () => {
      // Set up enrolled user
      const start = await vault.enrollStart('VALID-INVITE-123', {
        platform: 'android',
        appVersion: '1.0.0',
      });
      await vault.enrollAttestation(start.sessionId, {
        platform: 'android',
        attestationObject: 'mock',
        challenge: start.attestationChallenge,
      });
      const tk = start.transactionKeys[0];
      await vault.enrollSetPassword(
        start.sessionId,
        serializeEncryptedBlob(encryptWithTransactionKey(
          Buffer.from(password),
          Buffer.from(tk.publicKey, 'base64')
        )),
        tk.keyId
      );
      const finalize = await vault.enrollFinalize(start.sessionId);
      userGuid = finalize.userGuid;
      currentLat = { token: finalize.lat.token, version: finalize.lat.version };
    });

    it('should lock credential after 3 failed attempts', async () => {
      for (let i = 0; i < 3; i++) {
        const action = await vault.actionRequest(userGuid, 'authenticate');
        const tk = action.transactionKeys[0];

        const auth = await vault.authExecute(action.sessionId, {
          encryptedPassword: serializeEncryptedBlob(encryptWithTransactionKey(
            Buffer.from('wrong-password'),
            Buffer.from(tk.publicKey, 'base64')
          )),
          lat: currentLat,
          transactionKeyId: tk.keyId,
          challengeResponse: action.challenge,
        });

        expect(auth.success).toBe(false);
        expect(auth.failedAttempts).toBe(i + 1);
      }

      // Credential should now be locked
      const credential = vault.getCredential(userGuid);
      expect(credential!.status).toBe('locked');

      // Further action requests should fail
      await expect(vault.actionRequest(userGuid, 'authenticate'))
        .rejects.toThrow('Credential locked');
    });

    it('should reset failed attempts after successful auth', async () => {
      // Two failed attempts
      for (let i = 0; i < 2; i++) {
        const action = await vault.actionRequest(userGuid, 'authenticate');
        const tk = action.transactionKeys[0];

        await vault.authExecute(action.sessionId, {
          encryptedPassword: serializeEncryptedBlob(encryptWithTransactionKey(
            Buffer.from('wrong'),
            Buffer.from(tk.publicKey, 'base64')
          )),
          lat: currentLat,
          transactionKeyId: tk.keyId,
          challengeResponse: action.challenge,
        });
      }

      // Successful auth
      const action = await vault.actionRequest(userGuid, 'authenticate');
      const tk = action.transactionKeys[0];

      const auth = await vault.authExecute(action.sessionId, {
        encryptedPassword: serializeEncryptedBlob(encryptWithTransactionKey(
          Buffer.from(password),
          Buffer.from(tk.publicKey, 'base64')
        )),
        lat: currentLat,
        transactionKeyId: tk.keyId,
        challengeResponse: action.challenge,
      });

      expect(auth.success).toBe(true);

      // Failed attempts should be reset
      const credential = vault.getCredential(userGuid);
      expect(credential!.failedAttempts).toBe(0);
    });
  });

  describe('5. Transaction Key Pool Management', () => {
    let userGuid: string;
    let currentLat: LAT;
    const password = 'pool-test-password';

    beforeEach(async () => {
      // Set up enrolled user
      const start = await vault.enrollStart('VALID-INVITE-123', {
        platform: 'android',
        appVersion: '1.0.0',
      });
      await vault.enrollAttestation(start.sessionId, {
        platform: 'android',
        attestationObject: 'mock',
        challenge: start.attestationChallenge,
      });
      const tk = start.transactionKeys[0];
      await vault.enrollSetPassword(
        start.sessionId,
        serializeEncryptedBlob(encryptWithTransactionKey(
          Buffer.from(password),
          Buffer.from(tk.publicKey, 'base64')
        )),
        tk.keyId
      );
      const finalize = await vault.enrollFinalize(start.sessionId);
      userGuid = finalize.userGuid;
      currentLat = { token: finalize.lat.token, version: finalize.lat.version };
    });

    it('should consume transaction keys with each auth', async () => {
      const initialCredential = vault.getCredential(userGuid);
      const initialAvailable = initialCredential!.transactionKeys.length -
        initialCredential!.usedTransactionKeyIds.size;

      // Perform 3 authentications
      for (let i = 0; i < 3; i++) {
        const action = await vault.actionRequest(userGuid, 'authenticate');
        const tk = action.transactionKeys[0];

        const auth = await vault.authExecute(action.sessionId, {
          encryptedPassword: serializeEncryptedBlob(encryptWithTransactionKey(
            Buffer.from(password),
            Buffer.from(tk.publicKey, 'base64')
          )),
          lat: currentLat,
          transactionKeyId: tk.keyId,
          challengeResponse: action.challenge,
        });

        currentLat = auth.newLat!;
      }

      const finalCredential = vault.getCredential(userGuid);
      const finalAvailable = finalCredential!.transactionKeys.length -
        finalCredential!.usedTransactionKeyIds.size;

      expect(finalAvailable).toBe(initialAvailable - 3);
    });

    it('should support transaction key pool replenishment', async () => {
      // Use most transaction keys
      const credential = vault.getCredential(userGuid);
      const initialCount = credential!.transactionKeys.length;

      // Replenish pool
      vault.replenishTransactionKeys(userGuid, 10);

      const replenished = vault.getCredential(userGuid);
      expect(replenished!.transactionKeys.length).toBe(initialCount + 10);
    });
  });
});

// ============================================
// Cross-Platform Simulation Tests
// ============================================

describe('Cross-Platform Simulation', () => {
  let vault: MockVaultService;

  beforeEach(() => {
    vault = new MockVaultService();
  });

  it('should support Android enrollment and auth', async () => {
    // Android enrollment
    const start = await vault.enrollStart('VALID-INVITE-123', {
      platform: 'android',
      appVersion: '2.0.0',
    });

    expect(start.transactionKeys.length).toBe(20);

    await vault.enrollAttestation(start.sessionId, {
      platform: 'android',
      attestationObject: 'android-tee-attestation',
      challenge: start.attestationChallenge,
    });

    const tk = start.transactionKeys[0];
    await vault.enrollSetPassword(
      start.sessionId,
      serializeEncryptedBlob(encryptWithTransactionKey(
        Buffer.from('android-password'),
        Buffer.from(tk.publicKey, 'base64')
      )),
      tk.keyId
    );

    const finalize = await vault.enrollFinalize(start.sessionId);
    expect(finalize.userGuid).toBeDefined();

    // Android auth
    const action = await vault.actionRequest(finalize.userGuid, 'authenticate');
    const authTk = action.transactionKeys[0];

    const auth = await vault.authExecute(action.sessionId, {
      encryptedPassword: serializeEncryptedBlob(encryptWithTransactionKey(
        Buffer.from('android-password'),
        Buffer.from(authTk.publicKey, 'base64')
      )),
      lat: finalize.lat,
      transactionKeyId: authTk.keyId,
      challengeResponse: action.challenge,
    });

    expect(auth.success).toBe(true);
  });

  it.todo('should support iOS enrollment and auth');
  it.todo('should allow credential migration between platforms');
  it.todo('should maintain consistent LAT across platform changes');
});
