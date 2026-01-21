/**
 * Integration Tests: Auth Execute Flow
 *
 * Tests the authentication execution phase:
 * 1. Client submits encrypted password + LAT
 * 2. Server decrypts password using transaction key
 * 3. Server verifies password hash
 * 4. Server verifies LAT token and version
 * 5. Server rotates LAT on success
 *
 * @see docs/specs/vault-services-api.yaml
 * @see POST /vault/auth/execute
 */

import * as crypto from 'crypto';
import {
  generateX25519KeyPair,
  generateTransactionKeyPool,
  hashPassword,
  verifyPassword,
  encryptWithTransactionKey,
  decryptWithTransactionKey,
  type X25519KeyPair,
  type TransactionKeyPair,
  type EncryptedBlob,
} from '../../../lambda/common/crypto';
// LAT functions imported from test utilities - LAT was part of the legacy
// centralized ledger system, replaced by vault-manager NATS auth
import {
  generateLAT,
  hashLATToken,
  verifyLATToken,
  type LAT,
} from '../../utils/cryptoTestUtils';

// ============================================
// Mock Types
// ============================================

interface AuthExecutePayload {
  session_id: string;
  encrypted_password: {
    ciphertext: string;  // base64
    nonce: string;       // base64
    ephemeral_public_key: string;  // base64
  };
  lat: {
    token: string;   // hex
    version: number;
  };
  transaction_key_id: string;
}

interface AuthExecuteResponse {
  success: boolean;
  new_lat?: {
    token: string;
    version: number;
  };
  credential_blob?: string;  // base64 encoded
  error?: string;
}

interface MockSession {
  sessionId: string;
  userGuid: string;
  challenge: Buffer;
  createdAt: Date;
  expiresAt: Date;
  transactionKeyId?: string;
}

interface MockCredentialStore {
  userGuid: string;
  passwordHash: string;
  latTokenHash: string;
  latVersion: number;
  cekKeyPair: X25519KeyPair;
  status: 'active' | 'locked' | 'expired';
  failedAttempts: number;
  transactionKeys: Map<string, { key: TransactionKeyPair; used: boolean }>;
}

// ============================================
// Mock Service
// ============================================

class MockAuthExecuteService {
  private credentials: Map<string, MockCredentialStore> = new Map();
  private sessions: Map<string, MockSession> = new Map();

  /**
   * Register a credential with password for testing
   */
  async registerCredential(
    userGuid: string,
    password: string,
    transactionKeyCount: number = 20
  ): Promise<{ lat: LAT; cekKeyId: string }> {
    const passwordHash = await hashPassword(password);
    const lat = generateLAT(1);
    const cekKeyPair = generateX25519KeyPair();
    const transactionKeys = generateTransactionKeyPool(transactionKeyCount);

    const keyMap = new Map<string, { key: TransactionKeyPair; used: boolean }>();
    transactionKeys.forEach(k => keyMap.set(k.keyId, { key: k, used: false }));

    this.credentials.set(userGuid, {
      userGuid,
      passwordHash,
      latTokenHash: hashLATToken(lat.token),
      latVersion: lat.version,
      cekKeyPair,
      status: 'active',
      failedAttempts: 0,
      transactionKeys: keyMap,
    });

    return { lat, cekKeyId: `cek_${crypto.randomBytes(8).toString('hex')}` };
  }

  /**
   * Create a session for testing
   */
  createSession(userGuid: string): MockSession {
    const session: MockSession = {
      sessionId: crypto.randomUUID(),
      userGuid,
      challenge: crypto.randomBytes(32),
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 5 * 60 * 1000),
    };
    this.sessions.set(session.sessionId, session);
    return session;
  }

  /**
   * Get transaction key for client to use
   */
  getTransactionKey(userGuid: string): TransactionKeyPair | null {
    const credential = this.credentials.get(userGuid);
    if (!credential) return null;

    for (const [keyId, entry] of credential.transactionKeys) {
      if (!entry.used) {
        return entry.key;
      }
    }
    return null;
  }

  /**
   * Process auth execute request
   */
  async processAuthExecute(payload: AuthExecutePayload): Promise<AuthExecuteResponse> {
    // Get session
    const session = this.sessions.get(payload.session_id);
    if (!session) {
      return { success: false, error: 'Invalid session' };
    }

    // Check session expiry
    if (session.expiresAt < new Date()) {
      return { success: false, error: 'Session expired' };
    }

    // Get credential
    const credential = this.credentials.get(session.userGuid);
    if (!credential) {
      return { success: false, error: 'Authentication failed' };
    }

    // Check credential status
    if (credential.status !== 'active') {
      return { success: false, error: `Credential ${credential.status}` };
    }

    // Get and validate transaction key
    const tkEntry = credential.transactionKeys.get(payload.transaction_key_id);
    if (!tkEntry) {
      return { success: false, error: 'Invalid transaction key' };
    }

    if (tkEntry.used) {
      // Potential replay attack
      credential.failedAttempts++;
      if (credential.failedAttempts >= 3) {
        credential.status = 'locked';
      }
      return { success: false, error: 'Transaction key already used' };
    }

    // Mark transaction key as used immediately (before decryption)
    tkEntry.used = true;

    // Decrypt password
    let decryptedPassword: string;
    try {
      const encryptedBlob: EncryptedBlob = {
        ciphertext: Buffer.from(payload.encrypted_password.ciphertext, 'base64'),
        nonce: Buffer.from(payload.encrypted_password.nonce, 'base64'),
        ephemeralPublicKey: Buffer.from(payload.encrypted_password.ephemeral_public_key, 'base64'),
      };
      const decrypted = decryptWithTransactionKey(encryptedBlob, tkEntry.key.privateKey);
      decryptedPassword = decrypted.toString('utf8');
    } catch (error) {
      credential.failedAttempts++;
      if (credential.failedAttempts >= 3) {
        credential.status = 'locked';
      }
      return { success: false, error: 'Decryption failed' };
    }

    // Verify password
    const passwordValid = await verifyPassword(credential.passwordHash, decryptedPassword);
    if (!passwordValid) {
      credential.failedAttempts++;
      if (credential.failedAttempts >= 3) {
        credential.status = 'locked';
      }
      return { success: false, error: 'Authentication failed' };
    }

    // Verify LAT
    if (payload.lat.version !== credential.latVersion) {
      credential.failedAttempts++;
      if (credential.failedAttempts >= 3) {
        credential.status = 'locked';
      }
      return { success: false, error: 'LAT version mismatch' };
    }

    const latValid = verifyLATToken(payload.lat.token, credential.latTokenHash);
    if (!latValid) {
      credential.failedAttempts++;
      if (credential.failedAttempts >= 3) {
        credential.status = 'locked';
      }
      return { success: false, error: 'LAT verification failed' };
    }

    // Success! Reset failed attempts and rotate LAT
    credential.failedAttempts = 0;
    const newLAT = generateLAT(credential.latVersion + 1);
    credential.latTokenHash = hashLATToken(newLAT.token);
    credential.latVersion = newLAT.version;

    // Invalidate session
    this.sessions.delete(payload.session_id);

    return {
      success: true,
      new_lat: newLAT,
    };
  }

  /**
   * Get credential for testing assertions
   */
  getCredential(userGuid: string) {
    return this.credentials.get(userGuid);
  }
}

// ============================================
// Tests
// ============================================

describe('Auth Execute Flow', () => {
  let service: MockAuthExecuteService;
  let testUserGuid: string;
  let testPassword: string;
  let testLAT: LAT;

  beforeEach(async () => {
    service = new MockAuthExecuteService();
    testUserGuid = crypto.randomUUID();
    testPassword = 'test-password-123!';
    const result = await service.registerCredential(testUserGuid, testPassword);
    testLAT = result.lat;
  });

  describe('1. Password Decryption', () => {
    it('should decrypt password using transaction key', async () => {
      const session = service.createSession(testUserGuid);
      const tk = service.getTransactionKey(testUserGuid)!;

      // Client encrypts password with transaction key
      const encryptedPassword = encryptWithTransactionKey(
        Buffer.from(testPassword, 'utf8'),
        tk.publicKey
      );

      const response = await service.processAuthExecute({
        session_id: session.sessionId,
        encrypted_password: {
          ciphertext: encryptedPassword.ciphertext.toString('base64'),
          nonce: encryptedPassword.nonce.toString('base64'),
          ephemeral_public_key: encryptedPassword.ephemeralPublicKey.toString('base64'),
        },
        lat: testLAT,
        transaction_key_id: tk.keyId,
      });

      expect(response.success).toBe(true);
    });

    it('should fail with wrong password', async () => {
      const session = service.createSession(testUserGuid);
      const tk = service.getTransactionKey(testUserGuid)!;

      const encryptedPassword = encryptWithTransactionKey(
        Buffer.from('wrong-password', 'utf8'),
        tk.publicKey
      );

      const response = await service.processAuthExecute({
        session_id: session.sessionId,
        encrypted_password: {
          ciphertext: encryptedPassword.ciphertext.toString('base64'),
          nonce: encryptedPassword.nonce.toString('base64'),
          ephemeral_public_key: encryptedPassword.ephemeralPublicKey.toString('base64'),
        },
        lat: testLAT,
        transaction_key_id: tk.keyId,
      });

      expect(response.success).toBe(false);
      expect(response.error).toBe('Authentication failed');
    });

    it('should fail with corrupted ciphertext', async () => {
      const session = service.createSession(testUserGuid);
      const tk = service.getTransactionKey(testUserGuid)!;

      const encryptedPassword = encryptWithTransactionKey(
        Buffer.from(testPassword, 'utf8'),
        tk.publicKey
      );

      // Corrupt the ciphertext
      encryptedPassword.ciphertext[0] ^= 0xff;

      const response = await service.processAuthExecute({
        session_id: session.sessionId,
        encrypted_password: {
          ciphertext: encryptedPassword.ciphertext.toString('base64'),
          nonce: encryptedPassword.nonce.toString('base64'),
          ephemeral_public_key: encryptedPassword.ephemeralPublicKey.toString('base64'),
        },
        lat: testLAT,
        transaction_key_id: tk.keyId,
      });

      expect(response.success).toBe(false);
      expect(response.error).toBe('Decryption failed');
    });
  });

  describe('2. LAT Verification', () => {
    it('should verify correct LAT token and version', async () => {
      const session = service.createSession(testUserGuid);
      const tk = service.getTransactionKey(testUserGuid)!;

      const encryptedPassword = encryptWithTransactionKey(
        Buffer.from(testPassword, 'utf8'),
        tk.publicKey
      );

      const response = await service.processAuthExecute({
        session_id: session.sessionId,
        encrypted_password: {
          ciphertext: encryptedPassword.ciphertext.toString('base64'),
          nonce: encryptedPassword.nonce.toString('base64'),
          ephemeral_public_key: encryptedPassword.ephemeralPublicKey.toString('base64'),
        },
        lat: testLAT,
        transaction_key_id: tk.keyId,
      });

      expect(response.success).toBe(true);
    });

    it('should fail with wrong LAT token', async () => {
      const session = service.createSession(testUserGuid);
      const tk = service.getTransactionKey(testUserGuid)!;

      const encryptedPassword = encryptWithTransactionKey(
        Buffer.from(testPassword, 'utf8'),
        tk.publicKey
      );

      const wrongLAT = generateLAT(testLAT.version);

      const response = await service.processAuthExecute({
        session_id: session.sessionId,
        encrypted_password: {
          ciphertext: encryptedPassword.ciphertext.toString('base64'),
          nonce: encryptedPassword.nonce.toString('base64'),
          ephemeral_public_key: encryptedPassword.ephemeralPublicKey.toString('base64'),
        },
        lat: wrongLAT,
        transaction_key_id: tk.keyId,
      });

      expect(response.success).toBe(false);
      expect(response.error).toBe('LAT verification failed');
    });

    it('should fail with wrong LAT version', async () => {
      const session = service.createSession(testUserGuid);
      const tk = service.getTransactionKey(testUserGuid)!;

      const encryptedPassword = encryptWithTransactionKey(
        Buffer.from(testPassword, 'utf8'),
        tk.publicKey
      );

      const wrongVersionLAT = { token: testLAT.token, version: testLAT.version + 1 };

      const response = await service.processAuthExecute({
        session_id: session.sessionId,
        encrypted_password: {
          ciphertext: encryptedPassword.ciphertext.toString('base64'),
          nonce: encryptedPassword.nonce.toString('base64'),
          ephemeral_public_key: encryptedPassword.ephemeralPublicKey.toString('base64'),
        },
        lat: wrongVersionLAT,
        transaction_key_id: tk.keyId,
      });

      expect(response.success).toBe(false);
      expect(response.error).toBe('LAT version mismatch');
    });
  });

  describe('3. LAT Rotation', () => {
    it('should rotate LAT on successful auth', async () => {
      const session = service.createSession(testUserGuid);
      const tk = service.getTransactionKey(testUserGuid)!;

      const encryptedPassword = encryptWithTransactionKey(
        Buffer.from(testPassword, 'utf8'),
        tk.publicKey
      );

      const response = await service.processAuthExecute({
        session_id: session.sessionId,
        encrypted_password: {
          ciphertext: encryptedPassword.ciphertext.toString('base64'),
          nonce: encryptedPassword.nonce.toString('base64'),
          ephemeral_public_key: encryptedPassword.ephemeralPublicKey.toString('base64'),
        },
        lat: testLAT,
        transaction_key_id: tk.keyId,
      });

      expect(response.success).toBe(true);
      expect(response.new_lat).toBeDefined();
      expect(response.new_lat?.version).toBe(testLAT.version + 1);
      expect(response.new_lat?.token).not.toBe(testLAT.token);
    });

    it('should update stored LAT after rotation', async () => {
      const session = service.createSession(testUserGuid);
      const tk = service.getTransactionKey(testUserGuid)!;

      const encryptedPassword = encryptWithTransactionKey(
        Buffer.from(testPassword, 'utf8'),
        tk.publicKey
      );

      const response = await service.processAuthExecute({
        session_id: session.sessionId,
        encrypted_password: {
          ciphertext: encryptedPassword.ciphertext.toString('base64'),
          nonce: encryptedPassword.nonce.toString('base64'),
          ephemeral_public_key: encryptedPassword.ephemeralPublicKey.toString('base64'),
        },
        lat: testLAT,
        transaction_key_id: tk.keyId,
      });

      const credential = service.getCredential(testUserGuid);
      expect(credential?.latVersion).toBe(testLAT.version + 1);
    });

    it('should invalidate old LAT after rotation', async () => {
      const session1 = service.createSession(testUserGuid);
      const tk1 = service.getTransactionKey(testUserGuid)!;

      const encryptedPassword1 = encryptWithTransactionKey(
        Buffer.from(testPassword, 'utf8'),
        tk1.publicKey
      );

      // First auth succeeds and rotates LAT
      await service.processAuthExecute({
        session_id: session1.sessionId,
        encrypted_password: {
          ciphertext: encryptedPassword1.ciphertext.toString('base64'),
          nonce: encryptedPassword1.nonce.toString('base64'),
          ephemeral_public_key: encryptedPassword1.ephemeralPublicKey.toString('base64'),
        },
        lat: testLAT,
        transaction_key_id: tk1.keyId,
      });

      // Try to use old LAT again
      const session2 = service.createSession(testUserGuid);
      const tk2 = service.getTransactionKey(testUserGuid)!;

      const encryptedPassword2 = encryptWithTransactionKey(
        Buffer.from(testPassword, 'utf8'),
        tk2.publicKey
      );

      const response = await service.processAuthExecute({
        session_id: session2.sessionId,
        encrypted_password: {
          ciphertext: encryptedPassword2.ciphertext.toString('base64'),
          nonce: encryptedPassword2.nonce.toString('base64'),
          ephemeral_public_key: encryptedPassword2.ephemeralPublicKey.toString('base64'),
        },
        lat: testLAT, // Old LAT
        transaction_key_id: tk2.keyId,
      });

      expect(response.success).toBe(false);
    });
  });

  describe('4. Transaction Key Enforcement', () => {
    it('should mark transaction key as used', async () => {
      const session = service.createSession(testUserGuid);
      const tk = service.getTransactionKey(testUserGuid)!;

      const encryptedPassword = encryptWithTransactionKey(
        Buffer.from(testPassword, 'utf8'),
        tk.publicKey
      );

      await service.processAuthExecute({
        session_id: session.sessionId,
        encrypted_password: {
          ciphertext: encryptedPassword.ciphertext.toString('base64'),
          nonce: encryptedPassword.nonce.toString('base64'),
          ephemeral_public_key: encryptedPassword.ephemeralPublicKey.toString('base64'),
        },
        lat: testLAT,
        transaction_key_id: tk.keyId,
      });

      // Transaction key should not be returned again
      const newTk = service.getTransactionKey(testUserGuid);
      expect(newTk?.keyId).not.toBe(tk.keyId);
    });

    it('should reject reused transaction key', async () => {
      const session1 = service.createSession(testUserGuid);
      const tk = service.getTransactionKey(testUserGuid)!;

      const encryptedPassword1 = encryptWithTransactionKey(
        Buffer.from(testPassword, 'utf8'),
        tk.publicKey
      );

      // First auth
      await service.processAuthExecute({
        session_id: session1.sessionId,
        encrypted_password: {
          ciphertext: encryptedPassword1.ciphertext.toString('base64'),
          nonce: encryptedPassword1.nonce.toString('base64'),
          ephemeral_public_key: encryptedPassword1.ephemeralPublicKey.toString('base64'),
        },
        lat: testLAT,
        transaction_key_id: tk.keyId,
      });

      // Try to reuse same transaction key
      const session2 = service.createSession(testUserGuid);
      const newLAT = service.getCredential(testUserGuid);
      const fakeNewLAT = generateLAT(newLAT!.latVersion);

      const encryptedPassword2 = encryptWithTransactionKey(
        Buffer.from(testPassword, 'utf8'),
        tk.publicKey
      );

      const response = await service.processAuthExecute({
        session_id: session2.sessionId,
        encrypted_password: {
          ciphertext: encryptedPassword2.ciphertext.toString('base64'),
          nonce: encryptedPassword2.nonce.toString('base64'),
          ephemeral_public_key: encryptedPassword2.ephemeralPublicKey.toString('base64'),
        },
        lat: fakeNewLAT,
        transaction_key_id: tk.keyId, // Reused key ID
      });

      expect(response.success).toBe(false);
      expect(response.error).toBe('Transaction key already used');
    });

    it.todo('should reject invalid transaction key ID');
  });

  describe('5. Failed Attempt Tracking', () => {
    it('should increment failed attempts on wrong password', async () => {
      const session = service.createSession(testUserGuid);
      const tk = service.getTransactionKey(testUserGuid)!;

      const encryptedPassword = encryptWithTransactionKey(
        Buffer.from('wrong-password', 'utf8'),
        tk.publicKey
      );

      await service.processAuthExecute({
        session_id: session.sessionId,
        encrypted_password: {
          ciphertext: encryptedPassword.ciphertext.toString('base64'),
          nonce: encryptedPassword.nonce.toString('base64'),
          ephemeral_public_key: encryptedPassword.ephemeralPublicKey.toString('base64'),
        },
        lat: testLAT,
        transaction_key_id: tk.keyId,
      });

      const credential = service.getCredential(testUserGuid);
      expect(credential?.failedAttempts).toBe(1);
    });

    it('should lock credential after 3 failed attempts', async () => {
      for (let i = 0; i < 3; i++) {
        const session = service.createSession(testUserGuid);
        const tk = service.getTransactionKey(testUserGuid)!;

        const encryptedPassword = encryptWithTransactionKey(
          Buffer.from('wrong-password', 'utf8'),
          tk.publicKey
        );

        await service.processAuthExecute({
          session_id: session.sessionId,
          encrypted_password: {
            ciphertext: encryptedPassword.ciphertext.toString('base64'),
            nonce: encryptedPassword.nonce.toString('base64'),
            ephemeral_public_key: encryptedPassword.ephemeralPublicKey.toString('base64'),
          },
          lat: testLAT,
          transaction_key_id: tk.keyId,
        });
      }

      const credential = service.getCredential(testUserGuid);
      expect(credential?.status).toBe('locked');
    });

    it('should reset failed attempts on success', async () => {
      // One failed attempt first
      const session1 = service.createSession(testUserGuid);
      const tk1 = service.getTransactionKey(testUserGuid)!;

      const encryptedWrong = encryptWithTransactionKey(
        Buffer.from('wrong-password', 'utf8'),
        tk1.publicKey
      );

      await service.processAuthExecute({
        session_id: session1.sessionId,
        encrypted_password: {
          ciphertext: encryptedWrong.ciphertext.toString('base64'),
          nonce: encryptedWrong.nonce.toString('base64'),
          ephemeral_public_key: encryptedWrong.ephemeralPublicKey.toString('base64'),
        },
        lat: testLAT,
        transaction_key_id: tk1.keyId,
      });

      expect(service.getCredential(testUserGuid)?.failedAttempts).toBe(1);

      // Successful attempt
      const session2 = service.createSession(testUserGuid);
      const tk2 = service.getTransactionKey(testUserGuid)!;

      const encryptedCorrect = encryptWithTransactionKey(
        Buffer.from(testPassword, 'utf8'),
        tk2.publicKey
      );

      await service.processAuthExecute({
        session_id: session2.sessionId,
        encrypted_password: {
          ciphertext: encryptedCorrect.ciphertext.toString('base64'),
          nonce: encryptedCorrect.nonce.toString('base64'),
          ephemeral_public_key: encryptedCorrect.ephemeralPublicKey.toString('base64'),
        },
        lat: testLAT,
        transaction_key_id: tk2.keyId,
      });

      expect(service.getCredential(testUserGuid)?.failedAttempts).toBe(0);
    });
  });

  describe('6. Session Validation', () => {
    it('should reject invalid session', async () => {
      const tk = service.getTransactionKey(testUserGuid)!;

      const encryptedPassword = encryptWithTransactionKey(
        Buffer.from(testPassword, 'utf8'),
        tk.publicKey
      );

      const response = await service.processAuthExecute({
        session_id: 'invalid-session-id',
        encrypted_password: {
          ciphertext: encryptedPassword.ciphertext.toString('base64'),
          nonce: encryptedPassword.nonce.toString('base64'),
          ephemeral_public_key: encryptedPassword.ephemeralPublicKey.toString('base64'),
        },
        lat: testLAT,
        transaction_key_id: tk.keyId,
      });

      expect(response.success).toBe(false);
      expect(response.error).toBe('Invalid session');
    });

    it('should invalidate session after successful auth', async () => {
      const session = service.createSession(testUserGuid);
      const tk = service.getTransactionKey(testUserGuid)!;

      const encryptedPassword = encryptWithTransactionKey(
        Buffer.from(testPassword, 'utf8'),
        tk.publicKey
      );

      // First auth
      await service.processAuthExecute({
        session_id: session.sessionId,
        encrypted_password: {
          ciphertext: encryptedPassword.ciphertext.toString('base64'),
          nonce: encryptedPassword.nonce.toString('base64'),
          ephemeral_public_key: encryptedPassword.ephemeralPublicKey.toString('base64'),
        },
        lat: testLAT,
        transaction_key_id: tk.keyId,
      });

      // Try to use same session again
      const tk2 = service.getTransactionKey(testUserGuid)!;
      const newLAT = service.getCredential(testUserGuid);
      const fakeNewLAT = generateLAT(newLAT!.latVersion);

      const encryptedPassword2 = encryptWithTransactionKey(
        Buffer.from(testPassword, 'utf8'),
        tk2.publicKey
      );

      const response = await service.processAuthExecute({
        session_id: session.sessionId,
        encrypted_password: {
          ciphertext: encryptedPassword2.ciphertext.toString('base64'),
          nonce: encryptedPassword2.nonce.toString('base64'),
          ephemeral_public_key: encryptedPassword2.ephemeralPublicKey.toString('base64'),
        },
        lat: fakeNewLAT,
        transaction_key_id: tk2.keyId,
      });

      expect(response.success).toBe(false);
      expect(response.error).toBe('Invalid session');
    });

    it.todo('should reject expired session');
  });

  describe('7. Audit Logging', () => {
    it.todo('should log successful authentication');
    it.todo('should log failed authentication');
    it.todo('should log LAT rotation');
  });
});
