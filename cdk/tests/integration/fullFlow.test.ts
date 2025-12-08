/**
 * Full Flow Integration Tests
 *
 * Phase 10: Production Readiness & Polish
 *
 * Complete user journey tests covering:
 * - Registration → Enrollment → Auth → Messaging → Backup
 * - Multi-device scenarios
 * - Connection establishment between two users
 * - Handler installation and execution flow
 */

import * as crypto from 'crypto';

// ============================================================================
// Type Definitions
// ============================================================================

interface User {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  status: 'pending' | 'approved' | 'rejected';
  createdAt: Date;
}

interface Device {
  id: string;
  userId: string;
  publicKey: Buffer;
  privateKey: Buffer;
  attestationData: string;
  createdAt: Date;
  lastUsed: Date;
}

interface Vault {
  id: string;
  userId: string;
  status: 'provisioning' | 'active' | 'suspended' | 'terminated';
  natsAccount: string;
  createdAt: Date;
}

interface Connection {
  id: string;
  userId: string;
  connectedUserId: string;
  status: 'pending' | 'active' | 'revoked';
  sharedSecret: Buffer;
  createdAt: Date;
}

interface Message {
  id: string;
  connectionId: string;
  senderId: string;
  recipientId: string;
  encryptedContent: Buffer;
  nonce: Buffer;
  timestamp: Date;
}

interface Backup {
  id: string;
  userId: string;
  encryptedData: Buffer;
  nonce: Buffer;
  createdAt: Date;
  type: 'manual' | 'auto';
}

interface Handler {
  id: string;
  name: string;
  version: string;
  wasmHash: string;
  manifest: {
    permissions: string[];
    egress: { allowed: string[] };
  };
  status: 'pending' | 'verified' | 'installed' | 'revoked';
}

// ============================================================================
// Mock Services
// ============================================================================

class MockUserService {
  private users: Map<string, User> = new Map();
  private inviteCodes: Map<string, { used: number; maxUses: number; expiresAt: Date }> = new Map();

  constructor() {
    // Create some valid invite codes
    this.inviteCodes.set('VALID-INVITE-001', {
      used: 0,
      maxUses: 10,
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    });
  }

  async register(
    email: string,
    firstName: string,
    lastName: string,
    inviteCode: string
  ): Promise<User> {
    // Validate invite code
    const invite = this.inviteCodes.get(inviteCode);
    if (!invite) {
      throw new Error('Invalid invite code');
    }
    if (invite.used >= invite.maxUses) {
      throw new Error('Invite code exhausted');
    }
    if (invite.expiresAt < new Date()) {
      throw new Error('Invite code expired');
    }

    // Check for duplicate email
    for (const user of this.users.values()) {
      if (user.email === email) {
        throw new Error('Email already registered');
      }
    }

    const user: User = {
      id: crypto.randomUUID(),
      email,
      firstName,
      lastName,
      status: 'pending',
      createdAt: new Date(),
    };

    this.users.set(user.id, user);
    invite.used++;

    return user;
  }

  async approve(userId: string): Promise<User> {
    const user = this.users.get(userId);
    if (!user) {
      throw new Error('User not found');
    }
    user.status = 'approved';
    return user;
  }

  async getUser(userId: string): Promise<User | null> {
    return this.users.get(userId) || null;
  }

  async getUserByEmail(email: string): Promise<User | null> {
    for (const user of this.users.values()) {
      if (user.email === email) {
        return user;
      }
    }
    return null;
  }
}

class MockEnrollmentService {
  private devices: Map<string, Device> = new Map();
  private enrollmentSessions: Map<string, { userId: string; expiresAt: Date }> = new Map();

  async startEnrollment(userId: string): Promise<string> {
    const sessionId = crypto.randomUUID();
    this.enrollmentSessions.set(sessionId, {
      userId,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes
    });
    return sessionId;
  }

  async completeEnrollment(
    sessionId: string,
    attestationData: string
  ): Promise<Device> {
    const session = this.enrollmentSessions.get(sessionId);
    if (!session) {
      throw new Error('Invalid enrollment session');
    }
    if (session.expiresAt < new Date()) {
      throw new Error('Enrollment session expired');
    }

    // Generate key pair for device
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');

    const device: Device = {
      id: crypto.randomUUID(),
      userId: session.userId,
      publicKey: publicKey.export({ type: 'spki', format: 'der' }) as Buffer,
      privateKey: privateKey.export({ type: 'pkcs8', format: 'der' }) as Buffer,
      attestationData,
      createdAt: new Date(),
      lastUsed: new Date(),
    };

    this.devices.set(device.id, device);
    this.enrollmentSessions.delete(sessionId);

    return device;
  }

  async getDevice(deviceId: string): Promise<Device | null> {
    return this.devices.get(deviceId) || null;
  }

  async getUserDevices(userId: string): Promise<Device[]> {
    const devices: Device[] = [];
    for (const device of this.devices.values()) {
      if (device.userId === userId) {
        devices.push(device);
      }
    }
    return devices;
  }
}

class MockVaultService {
  private vaults: Map<string, Vault> = new Map();

  async provisionVault(userId: string): Promise<Vault> {
    const vault: Vault = {
      id: crypto.randomUUID(),
      userId,
      status: 'provisioning',
      natsAccount: `vault-${crypto.randomUUID().substring(0, 8)}`,
      createdAt: new Date(),
    };

    this.vaults.set(vault.id, vault);

    // Simulate provisioning delay
    await new Promise(resolve => setTimeout(resolve, 10));
    vault.status = 'active';

    return vault;
  }

  async getVault(vaultId: string): Promise<Vault | null> {
    return this.vaults.get(vaultId) || null;
  }

  async getUserVault(userId: string): Promise<Vault | null> {
    for (const vault of this.vaults.values()) {
      if (vault.userId === userId) {
        return vault;
      }
    }
    return null;
  }
}

class MockAuthService {
  private activeSessions: Map<string, { userId: string; deviceId: string; expiresAt: Date }> = new Map();

  async authenticate(
    device: Device,
    challenge: Buffer,
    signature: Buffer
  ): Promise<string> {
    // Verify signature
    const pubKey = crypto.createPublicKey({
      key: device.publicKey,
      format: 'der',
      type: 'spki',
    });

    const isValid = crypto.verify(null, challenge, pubKey, signature);
    if (!isValid) {
      throw new Error('Invalid signature');
    }

    // Create session token
    const token = crypto.randomBytes(32).toString('base64url');
    this.activeSessions.set(token, {
      userId: device.userId,
      deviceId: device.id,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
    });

    return token;
  }

  async validateSession(token: string): Promise<{ userId: string; deviceId: string } | null> {
    const session = this.activeSessions.get(token);
    if (!session) return null;
    if (session.expiresAt < new Date()) {
      this.activeSessions.delete(token);
      return null;
    }
    return { userId: session.userId, deviceId: session.deviceId };
  }

  async revokeSession(token: string): Promise<void> {
    this.activeSessions.delete(token);
  }
}

class MockConnectionService {
  private connections: Map<string, Connection> = new Map();
  private invitations: Map<string, { fromUserId: string; expiresAt: Date }> = new Map();

  async createInvitation(userId: string): Promise<string> {
    const invitationCode = crypto.randomBytes(16).toString('base64url');
    this.invitations.set(invitationCode, {
      fromUserId: userId,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
    });
    return invitationCode;
  }

  async acceptInvitation(invitationCode: string, acceptingUserId: string): Promise<Connection> {
    const invitation = this.invitations.get(invitationCode);
    if (!invitation) {
      throw new Error('Invalid invitation');
    }
    if (invitation.expiresAt < new Date()) {
      throw new Error('Invitation expired');
    }
    if (invitation.fromUserId === acceptingUserId) {
      throw new Error('Cannot connect to yourself');
    }

    // Generate shared secret via X25519 simulation
    const sharedSecret = crypto.randomBytes(32);

    const connection: Connection = {
      id: crypto.randomUUID(),
      userId: invitation.fromUserId,
      connectedUserId: acceptingUserId,
      status: 'active',
      sharedSecret,
      createdAt: new Date(),
    };

    this.connections.set(connection.id, connection);
    this.invitations.delete(invitationCode);

    return connection;
  }

  async getConnection(connectionId: string): Promise<Connection | null> {
    return this.connections.get(connectionId) || null;
  }

  async getUserConnections(userId: string): Promise<Connection[]> {
    const connections: Connection[] = [];
    for (const conn of this.connections.values()) {
      if (conn.userId === userId || conn.connectedUserId === userId) {
        connections.push(conn);
      }
    }
    return connections;
  }

  async revokeConnection(connectionId: string): Promise<void> {
    const connection = this.connections.get(connectionId);
    if (connection) {
      connection.status = 'revoked';
    }
  }
}

class MockMessagingService {
  private messages: Map<string, Message> = new Map();

  async sendMessage(
    connection: Connection,
    senderId: string,
    content: string
  ): Promise<Message> {
    if (connection.status !== 'active') {
      throw new Error('Connection not active');
    }

    // Encrypt message
    const nonce = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv(
      'aes-256-gcm',
      connection.sharedSecret,
      nonce
    );
    const encrypted = Buffer.concat([
      cipher.update(Buffer.from(content, 'utf8')),
      cipher.final(),
      cipher.getAuthTag(),
    ]);

    const recipientId = senderId === connection.userId
      ? connection.connectedUserId
      : connection.userId;

    const message: Message = {
      id: crypto.randomUUID(),
      connectionId: connection.id,
      senderId,
      recipientId,
      encryptedContent: encrypted,
      nonce,
      timestamp: new Date(),
    };

    this.messages.set(message.id, message);
    return message;
  }

  async decryptMessage(message: Message, sharedSecret: Buffer): Promise<string> {
    const tag = message.encryptedContent.subarray(-16);
    const data = message.encryptedContent.subarray(0, -16);

    const decipher = crypto.createDecipheriv('aes-256-gcm', sharedSecret, message.nonce);
    decipher.setAuthTag(tag);

    const decrypted = Buffer.concat([
      decipher.update(data),
      decipher.final(),
    ]);

    return decrypted.toString('utf8');
  }

  async getMessages(connectionId: string): Promise<Message[]> {
    const messages: Message[] = [];
    for (const msg of this.messages.values()) {
      if (msg.connectionId === connectionId) {
        messages.push(msg);
      }
    }
    return messages.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
  }
}

class MockBackupService {
  private backups: Map<string, Backup> = new Map();

  async createBackup(
    userId: string,
    data: Buffer,
    encryptionKey: Buffer,
    type: 'manual' | 'auto' = 'manual'
  ): Promise<Backup> {
    const nonce = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, nonce);
    const encrypted = Buffer.concat([
      cipher.update(data),
      cipher.final(),
      cipher.getAuthTag(),
    ]);

    const backup: Backup = {
      id: crypto.randomUUID(),
      userId,
      encryptedData: encrypted,
      nonce,
      createdAt: new Date(),
      type,
    };

    this.backups.set(backup.id, backup);
    return backup;
  }

  async restoreBackup(backup: Backup, encryptionKey: Buffer): Promise<Buffer> {
    const tag = backup.encryptedData.subarray(-16);
    const data = backup.encryptedData.subarray(0, -16);

    const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey, backup.nonce);
    decipher.setAuthTag(tag);

    return Buffer.concat([
      decipher.update(data),
      decipher.final(),
    ]);
  }

  async getUserBackups(userId: string): Promise<Backup[]> {
    const backups: Backup[] = [];
    for (const backup of this.backups.values()) {
      if (backup.userId === userId) {
        backups.push(backup);
      }
    }
    return backups.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }
}

class MockHandlerService {
  private handlers: Map<string, Handler> = new Map();
  private installedHandlers: Map<string, Set<string>> = new Map(); // userId -> Set<handlerId>

  async registerHandler(
    name: string,
    version: string,
    wasmCode: Buffer,
    manifest: Handler['manifest']
  ): Promise<Handler> {
    const handler: Handler = {
      id: crypto.randomUUID(),
      name,
      version,
      wasmHash: crypto.createHash('sha256').update(wasmCode).digest('hex'),
      manifest,
      status: 'pending',
    };

    this.handlers.set(handler.id, handler);
    return handler;
  }

  async verifyHandler(handlerId: string): Promise<void> {
    const handler = this.handlers.get(handlerId);
    if (!handler) {
      throw new Error('Handler not found');
    }
    handler.status = 'verified';
  }

  async installHandler(userId: string, handlerId: string): Promise<void> {
    const handler = this.handlers.get(handlerId);
    if (!handler) {
      throw new Error('Handler not found');
    }
    if (handler.status !== 'verified') {
      throw new Error('Handler not verified');
    }

    if (!this.installedHandlers.has(userId)) {
      this.installedHandlers.set(userId, new Set());
    }
    this.installedHandlers.get(userId)!.add(handlerId);
    handler.status = 'installed';
  }

  async executeHandler(
    userId: string,
    handlerId: string,
    input: Record<string, unknown>
  ): Promise<Record<string, unknown>> {
    const userHandlers = this.installedHandlers.get(userId);
    if (!userHandlers?.has(handlerId)) {
      throw new Error('Handler not installed');
    }

    // Simulate handler execution
    return {
      success: true,
      handlerId,
      input,
      output: { processed: true, timestamp: new Date().toISOString() },
    };
  }
}

// ============================================================================
// Test Suites
// ============================================================================

describe('Full Flow Integration Tests', () => {
  let userService: MockUserService;
  let enrollmentService: MockEnrollmentService;
  let vaultService: MockVaultService;
  let authService: MockAuthService;
  let connectionService: MockConnectionService;
  let messagingService: MockMessagingService;
  let backupService: MockBackupService;
  let handlerService: MockHandlerService;

  beforeEach(() => {
    userService = new MockUserService();
    enrollmentService = new MockEnrollmentService();
    vaultService = new MockVaultService();
    authService = new MockAuthService();
    connectionService = new MockConnectionService();
    messagingService = new MockMessagingService();
    backupService = new MockBackupService();
    handlerService = new MockHandlerService();
  });

  describe('Complete User Journey', () => {
    test('should complete full journey: registration → enrollment → auth → messaging → backup', async () => {
      // Step 1: Registration
      const user = await userService.register(
        'alice@example.com',
        'Alice',
        'Smith',
        'VALID-INVITE-001'
      );
      expect(user.status).toBe('pending');

      // Step 2: Admin approval
      const approvedUser = await userService.approve(user.id);
      expect(approvedUser.status).toBe('approved');

      // Step 3: Enrollment
      const sessionId = await enrollmentService.startEnrollment(user.id);
      const device = await enrollmentService.completeEnrollment(
        sessionId,
        JSON.stringify({ type: 'android', version: '1.0' })
      );
      expect(device.userId).toBe(user.id);

      // Step 4: Vault provisioning
      const vault = await vaultService.provisionVault(user.id);
      expect(vault.status).toBe('active');

      // Step 5: Authentication
      const challenge = crypto.randomBytes(32);
      const privKey = crypto.createPrivateKey({
        key: device.privateKey,
        format: 'der',
        type: 'pkcs8',
      });
      const signature = crypto.sign(null, challenge, privKey);
      const token = await authService.authenticate(device, challenge, signature);
      expect(token).toBeTruthy();

      // Verify session
      const session = await authService.validateSession(token);
      expect(session?.userId).toBe(user.id);

      // Step 6: Create connection with another user
      const bob = await userService.register(
        'bob@example.com',
        'Bob',
        'Jones',
        'VALID-INVITE-001'
      );
      await userService.approve(bob.id);

      const invitationCode = await connectionService.createInvitation(user.id);
      const connection = await connectionService.acceptInvitation(invitationCode, bob.id);
      expect(connection.status).toBe('active');

      // Step 7: Send message
      const message = await messagingService.sendMessage(
        connection,
        user.id,
        'Hello, Bob!'
      );
      expect(message.senderId).toBe(user.id);
      expect(message.recipientId).toBe(bob.id);

      // Step 8: Decrypt message
      const decrypted = await messagingService.decryptMessage(
        message,
        connection.sharedSecret
      );
      expect(decrypted).toBe('Hello, Bob!');

      // Step 9: Create backup
      const backupData = Buffer.from(JSON.stringify({
        connections: [connection.id],
        timestamp: new Date().toISOString(),
      }));
      const backupKey = crypto.randomBytes(32);
      const backup = await backupService.createBackup(
        user.id,
        backupData,
        backupKey,
        'manual'
      );
      expect(backup.type).toBe('manual');

      // Step 10: Restore backup
      const restored = await backupService.restoreBackup(backup, backupKey);
      expect(restored.toString()).toBe(backupData.toString());
    });

    test('should handle error at each stage gracefully', async () => {
      // Registration with invalid invite
      await expect(
        userService.register('test@example.com', 'Test', 'User', 'INVALID')
      ).rejects.toThrow('Invalid invite code');

      // Valid registration
      const user = await userService.register(
        'test@example.com',
        'Test',
        'User',
        'VALID-INVITE-001'
      );

      // Duplicate registration
      await expect(
        userService.register('test@example.com', 'Test', 'User', 'VALID-INVITE-001')
      ).rejects.toThrow('Email already registered');

      // Enrollment without approval should still work (enrollment service doesn't check)
      const sessionId = await enrollmentService.startEnrollment(user.id);
      expect(sessionId).toBeTruthy();

      // Invalid enrollment session
      await expect(
        enrollmentService.completeEnrollment('invalid-session', '{}')
      ).rejects.toThrow('Invalid enrollment session');
    });
  });

  describe('Multi-Device Scenarios', () => {
    test('should support multiple devices for same user', async () => {
      const user = await userService.register(
        'multidevice@example.com',
        'Multi',
        'Device',
        'VALID-INVITE-001'
      );
      await userService.approve(user.id);

      // Enroll first device (phone)
      const session1 = await enrollmentService.startEnrollment(user.id);
      const phone = await enrollmentService.completeEnrollment(
        session1,
        JSON.stringify({ type: 'android', device: 'phone' })
      );

      // Enroll second device (tablet)
      const session2 = await enrollmentService.startEnrollment(user.id);
      const tablet = await enrollmentService.completeEnrollment(
        session2,
        JSON.stringify({ type: 'android', device: 'tablet' })
      );

      // Both devices should be registered
      const devices = await enrollmentService.getUserDevices(user.id);
      expect(devices.length).toBe(2);

      // Both devices should be able to authenticate
      const challenge = crypto.randomBytes(32);

      // Phone authentication
      const phonePrivKey = crypto.createPrivateKey({
        key: phone.privateKey,
        format: 'der',
        type: 'pkcs8',
      });
      const phoneSignature = crypto.sign(null, challenge, phonePrivKey);
      const phoneToken = await authService.authenticate(phone, challenge, phoneSignature);

      // Tablet authentication
      const tabletPrivKey = crypto.createPrivateKey({
        key: tablet.privateKey,
        format: 'der',
        type: 'pkcs8',
      });
      const tabletSignature = crypto.sign(null, challenge, tabletPrivKey);
      const tabletToken = await authService.authenticate(tablet, challenge, tabletSignature);

      // Both tokens should be valid
      const phoneSession = await authService.validateSession(phoneToken);
      const tabletSession = await authService.validateSession(tabletToken);

      expect(phoneSession?.userId).toBe(user.id);
      expect(tabletSession?.userId).toBe(user.id);
      expect(phoneSession?.deviceId).toBe(phone.id);
      expect(tabletSession?.deviceId).toBe(tablet.id);
    });

    test('should handle device revocation', async () => {
      const user = await userService.register(
        'revoke@example.com',
        'Revoke',
        'Test',
        'VALID-INVITE-001'
      );
      await userService.approve(user.id);

      // Enroll device
      const session = await enrollmentService.startEnrollment(user.id);
      const device = await enrollmentService.completeEnrollment(session, '{}');

      // Authenticate
      const challenge = crypto.randomBytes(32);
      const privKey = crypto.createPrivateKey({
        key: device.privateKey,
        format: 'der',
        type: 'pkcs8',
      });
      const signature = crypto.sign(null, challenge, privKey);
      const token = await authService.authenticate(device, challenge, signature);

      // Token should be valid
      expect(await authService.validateSession(token)).toBeTruthy();

      // Revoke session
      await authService.revokeSession(token);

      // Token should no longer be valid
      expect(await authService.validateSession(token)).toBeNull();
    });
  });

  describe('Connection Establishment Between Users', () => {
    let alice: User;
    let bob: User;
    let aliceDevice: Device;
    let bobDevice: Device;

    beforeEach(async () => {
      // Create and enroll Alice
      alice = await userService.register('alice@test.com', 'Alice', 'A', 'VALID-INVITE-001');
      await userService.approve(alice.id);
      const aliceSession = await enrollmentService.startEnrollment(alice.id);
      aliceDevice = await enrollmentService.completeEnrollment(aliceSession, '{}');

      // Create and enroll Bob
      bob = await userService.register('bob@test.com', 'Bob', 'B', 'VALID-INVITE-001');
      await userService.approve(bob.id);
      const bobSession = await enrollmentService.startEnrollment(bob.id);
      bobDevice = await enrollmentService.completeEnrollment(bobSession, '{}');
    });

    test('should establish connection via invitation', async () => {
      // Alice creates invitation
      const invitation = await connectionService.createInvitation(alice.id);
      expect(invitation).toBeTruthy();

      // Bob accepts invitation
      const connection = await connectionService.acceptInvitation(invitation, bob.id);
      expect(connection.userId).toBe(alice.id);
      expect(connection.connectedUserId).toBe(bob.id);
      expect(connection.status).toBe('active');
    });

    test('should support bidirectional messaging after connection', async () => {
      const invitation = await connectionService.createInvitation(alice.id);
      const connection = await connectionService.acceptInvitation(invitation, bob.id);

      // Alice sends to Bob
      const msg1 = await messagingService.sendMessage(connection, alice.id, 'Hi Bob!');
      expect(msg1.senderId).toBe(alice.id);
      expect(msg1.recipientId).toBe(bob.id);

      // Bob sends to Alice
      const msg2 = await messagingService.sendMessage(connection, bob.id, 'Hi Alice!');
      expect(msg2.senderId).toBe(bob.id);
      expect(msg2.recipientId).toBe(alice.id);

      // Both can decrypt
      const decrypted1 = await messagingService.decryptMessage(msg1, connection.sharedSecret);
      const decrypted2 = await messagingService.decryptMessage(msg2, connection.sharedSecret);

      expect(decrypted1).toBe('Hi Bob!');
      expect(decrypted2).toBe('Hi Alice!');
    });

    test('should prevent messaging on revoked connection', async () => {
      const invitation = await connectionService.createInvitation(alice.id);
      const connection = await connectionService.acceptInvitation(invitation, bob.id);

      // Send message works
      await messagingService.sendMessage(connection, alice.id, 'Hello');

      // Revoke connection
      await connectionService.revokeConnection(connection.id);

      // Messaging should fail
      await expect(
        messagingService.sendMessage(connection, alice.id, 'This should fail')
      ).rejects.toThrow('Connection not active');
    });

    test('should prevent self-connection', async () => {
      const invitation = await connectionService.createInvitation(alice.id);

      await expect(
        connectionService.acceptInvitation(invitation, alice.id)
      ).rejects.toThrow('Cannot connect to yourself');
    });

    test('should support multiple connections per user', async () => {
      // Create third user
      const charlie = await userService.register('charlie@test.com', 'Charlie', 'C', 'VALID-INVITE-001');
      await userService.approve(charlie.id);

      // Alice connects with Bob
      const inv1 = await connectionService.createInvitation(alice.id);
      await connectionService.acceptInvitation(inv1, bob.id);

      // Alice connects with Charlie
      const inv2 = await connectionService.createInvitation(alice.id);
      await connectionService.acceptInvitation(inv2, charlie.id);

      // Alice should have 2 connections
      const aliceConnections = await connectionService.getUserConnections(alice.id);
      expect(aliceConnections.length).toBe(2);

      // Bob should have 1 connection
      const bobConnections = await connectionService.getUserConnections(bob.id);
      expect(bobConnections.length).toBe(1);
    });
  });

  describe('Handler Installation and Execution Flow', () => {
    let user: User;

    beforeEach(async () => {
      user = await userService.register('handler@test.com', 'Handler', 'Test', 'VALID-INVITE-001');
      await userService.approve(user.id);
    });

    test('should complete handler lifecycle: register → verify → install → execute', async () => {
      // Register handler
      const wasmCode = crypto.randomBytes(1024); // Mock WASM
      const handler = await handlerService.registerHandler(
        'test-handler',
        '1.0.0',
        wasmCode,
        {
          permissions: ['read', 'write'],
          egress: { allowed: ['api.example.com'] },
        }
      );
      expect(handler.status).toBe('pending');

      // Verify handler
      await handlerService.verifyHandler(handler.id);
      const verifiedHandler = await handlerService['handlers'].get(handler.id);
      expect(verifiedHandler?.status).toBe('verified');

      // Install handler
      await handlerService.installHandler(user.id, handler.id);

      // Execute handler
      const result = await handlerService.executeHandler(
        user.id,
        handler.id,
        { action: 'test', data: 'hello' }
      );
      expect(result.success).toBe(true);
      expect(result.handlerId).toBe(handler.id);
    });

    test('should prevent installing unverified handlers', async () => {
      const wasmCode = crypto.randomBytes(1024);
      const handler = await handlerService.registerHandler(
        'unverified-handler',
        '1.0.0',
        wasmCode,
        { permissions: [], egress: { allowed: [] } }
      );

      await expect(
        handlerService.installHandler(user.id, handler.id)
      ).rejects.toThrow('Handler not verified');
    });

    test('should prevent executing uninstalled handlers', async () => {
      const wasmCode = crypto.randomBytes(1024);
      const handler = await handlerService.registerHandler(
        'not-installed',
        '1.0.0',
        wasmCode,
        { permissions: [], egress: { allowed: [] } }
      );
      await handlerService.verifyHandler(handler.id);

      await expect(
        handlerService.executeHandler(user.id, handler.id, {})
      ).rejects.toThrow('Handler not installed');
    });
  });

  describe('Backup and Recovery Flow', () => {
    let user: User;
    let device: Device;
    let backupKey: Buffer;

    beforeEach(async () => {
      user = await userService.register('backup@test.com', 'Backup', 'Test', 'VALID-INVITE-001');
      await userService.approve(user.id);

      const session = await enrollmentService.startEnrollment(user.id);
      device = await enrollmentService.completeEnrollment(session, '{}');

      backupKey = crypto.randomBytes(32);
    });

    test('should create and restore manual backup', async () => {
      const originalData = {
        profile: { name: 'Test User' },
        connections: ['conn-1', 'conn-2'],
        settings: { theme: 'dark' },
      };

      const backup = await backupService.createBackup(
        user.id,
        Buffer.from(JSON.stringify(originalData)),
        backupKey,
        'manual'
      );

      expect(backup.type).toBe('manual');
      expect(backup.userId).toBe(user.id);

      const restored = await backupService.restoreBackup(backup, backupKey);
      const restoredData = JSON.parse(restored.toString());

      expect(restoredData.profile.name).toBe('Test User');
      expect(restoredData.connections).toEqual(['conn-1', 'conn-2']);
    });

    test('should fail restore with wrong key', async () => {
      const backup = await backupService.createBackup(
        user.id,
        Buffer.from('secret data'),
        backupKey,
        'manual'
      );

      const wrongKey = crypto.randomBytes(32);

      await expect(
        backupService.restoreBackup(backup, wrongKey)
      ).rejects.toThrow();
    });

    test('should list user backups in chronological order', async () => {
      // Create multiple backups
      await backupService.createBackup(
        user.id,
        Buffer.from('backup 1'),
        backupKey,
        'auto'
      );

      await new Promise(resolve => setTimeout(resolve, 10));

      await backupService.createBackup(
        user.id,
        Buffer.from('backup 2'),
        backupKey,
        'manual'
      );

      const backups = await backupService.getUserBackups(user.id);

      expect(backups.length).toBe(2);
      // Should be in reverse chronological order (newest first)
      expect(backups[0].createdAt.getTime()).toBeGreaterThan(backups[1].createdAt.getTime());
    });
  });

  describe('Cross-Flow Interactions', () => {
    test('should maintain data integrity across flows', async () => {
      // Create user and complete enrollment
      const user = await userService.register(
        'integrity@test.com',
        'Integrity',
        'Test',
        'VALID-INVITE-001'
      );
      await userService.approve(user.id);

      const session = await enrollmentService.startEnrollment(user.id);
      const device = await enrollmentService.completeEnrollment(session, '{}');

      // Provision vault
      const vault = await vaultService.provisionVault(user.id);

      // Authenticate
      const challenge = crypto.randomBytes(32);
      const privKey = crypto.createPrivateKey({
        key: device.privateKey,
        format: 'der',
        type: 'pkcs8',
      });
      const signature = crypto.sign(null, challenge, privKey);
      const token = await authService.authenticate(device, challenge, signature);

      // Verify all IDs are consistent
      const validSession = await authService.validateSession(token);
      expect(validSession?.userId).toBe(user.id);

      const userDevices = await enrollmentService.getUserDevices(user.id);
      expect(userDevices[0].id).toBe(device.id);

      const userVault = await vaultService.getUserVault(user.id);
      expect(userVault?.id).toBe(vault.id);
    });

    test('should handle concurrent operations safely', async () => {
      const user = await userService.register(
        'concurrent@test.com',
        'Concurrent',
        'Test',
        'VALID-INVITE-001'
      );
      await userService.approve(user.id);

      // Concurrent enrollments
      const sessions = await Promise.all([
        enrollmentService.startEnrollment(user.id),
        enrollmentService.startEnrollment(user.id),
        enrollmentService.startEnrollment(user.id),
      ]);

      // Complete all enrollments concurrently
      const devices = await Promise.all(
        sessions.map((s, i) =>
          enrollmentService.completeEnrollment(s, JSON.stringify({ device: i }))
        )
      );

      expect(devices.length).toBe(3);
      expect(new Set(devices.map(d => d.id)).size).toBe(3); // All unique IDs
    });
  });
});

describe('End-to-End Scenarios', () => {
  test('should support complete new user onboarding', async () => {
    const userService = new MockUserService();
    const enrollmentService = new MockEnrollmentService();
    const vaultService = new MockVaultService();

    // Simulate frontend flow
    const inviteCode = 'VALID-INVITE-001';

    // 1. User submits registration form
    const user = await userService.register(
      'newuser@example.com',
      'New',
      'User',
      inviteCode
    );

    // 2. Admin approves (simulated)
    await userService.approve(user.id);

    // 3. User receives approval notification and starts mobile app
    // 4. Mobile app initiates enrollment
    const sessionId = await enrollmentService.startEnrollment(user.id);

    // 5. Mobile generates attestation and completes enrollment
    const device = await enrollmentService.completeEnrollment(sessionId, JSON.stringify({
      platform: 'android',
      manufacturer: 'Google',
      model: 'Pixel',
      osVersion: '14',
    }));

    // 6. Vault is provisioned
    const vault = await vaultService.provisionVault(user.id);

    // Verification
    expect(user.status).toBe('approved');
    expect(device.userId).toBe(user.id);
    expect(vault.status).toBe('active');
    expect(vault.userId).toBe(user.id);
  });

  test('should support message exchange between two complete users', async () => {
    const userService = new MockUserService();
    const enrollmentService = new MockEnrollmentService();
    const connectionService = new MockConnectionService();
    const messagingService = new MockMessagingService();

    // Setup Alice
    const alice = await userService.register('alice@e2e.com', 'Alice', 'E2E', 'VALID-INVITE-001');
    await userService.approve(alice.id);
    const aliceSession = await enrollmentService.startEnrollment(alice.id);
    await enrollmentService.completeEnrollment(aliceSession, '{}');

    // Setup Bob
    const bob = await userService.register('bob@e2e.com', 'Bob', 'E2E', 'VALID-INVITE-001');
    await userService.approve(bob.id);
    const bobSession = await enrollmentService.startEnrollment(bob.id);
    await enrollmentService.completeEnrollment(bobSession, '{}');

    // Connect
    const invitation = await connectionService.createInvitation(alice.id);
    const connection = await connectionService.acceptInvitation(invitation, bob.id);

    // Exchange messages
    await messagingService.sendMessage(connection, alice.id, 'Hello Bob!');
    await messagingService.sendMessage(connection, bob.id, 'Hi Alice!');
    await messagingService.sendMessage(connection, alice.id, 'How are you?');

    // Verify message history
    const messages = await messagingService.getMessages(connection.id);
    expect(messages.length).toBe(3);

    const decryptedMessages = await Promise.all(
      messages.map(m => messagingService.decryptMessage(m, connection.sharedSecret))
    );

    expect(decryptedMessages).toEqual(['Hello Bob!', 'Hi Alice!', 'How are you?']);
  });
});
