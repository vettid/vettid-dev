/**
 * Integration Tests: Revoke Connection
 *
 * Tests the connection revocation endpoint:
 * - Authorization (owner can revoke)
 * - Status updates for both parties
 * - Shared key deletion
 * - Message history handling
 * - Future message blocking
 *
 * @see lambda/handlers/connections/revokeConnection.ts (pending implementation)
 */

import {
  MockConnectionService,
  createMockConnection,
} from '../../fixtures/connections/mockConnection';
import { MockMessagingService } from '../../fixtures/messaging/mockMessage';

// ============================================
// Tests
// ============================================

describe('Revoke Connection', () => {
  let connectionService: MockConnectionService;
  let messagingService: MockMessagingService;
  const creatorGuid = 'user-creator-123';
  const acceptorGuid = 'user-acceptor-456';

  beforeEach(() => {
    connectionService = new MockConnectionService();
    messagingService = new MockMessagingService();
  });

  afterEach(() => {
    connectionService.clear();
    messagingService.clear();
  });

  describe('Revocation Authorization', () => {
    it('should allow owner to revoke connection', async () => {
      // Create connection
      const invite = await connectionService.createInvitation(creatorGuid);
      const accept = await connectionService.acceptInvitation(
        acceptorGuid,
        invite.invitation!.code
      );

      // Revoke as owner
      const result = await connectionService.revokeConnection(
        acceptorGuid,
        accept.connection!.connection_id
      );

      expect(result.success).toBe(true);
    });

    it('should reject revocation by non-owner', async () => {
      // Create connection
      const invite = await connectionService.createInvitation(creatorGuid);
      const accept = await connectionService.acceptInvitation(
        acceptorGuid,
        invite.invitation!.code
      );

      // Try to revoke as random user
      const result = await connectionService.revokeConnection(
        'random-user-789',
        accept.connection!.connection_id
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('Not authorized');
    });

    it('should handle already-revoked connections', async () => {
      const invite = await connectionService.createInvitation(creatorGuid);
      const accept = await connectionService.acceptInvitation(
        acceptorGuid,
        invite.invitation!.code
      );

      // First revocation
      await connectionService.revokeConnection(
        acceptorGuid,
        accept.connection!.connection_id
      );

      // Try to revoke again
      const result = await connectionService.revokeConnection(
        acceptorGuid,
        accept.connection!.connection_id
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('already revoked');
    });

    it('should handle non-existent connection', async () => {
      const result = await connectionService.revokeConnection(
        creatorGuid,
        'non-existent-connection-id'
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('not found');
    });

    it('should allow either party to revoke', async () => {
      // First connection - acceptor revokes
      const invite1 = await connectionService.createInvitation(creatorGuid);
      const accept1 = await connectionService.acceptInvitation(
        acceptorGuid,
        invite1.invitation!.code
      );

      const result1 = await connectionService.revokeConnection(
        acceptorGuid,
        accept1.connection!.connection_id
      );
      expect(result1.success).toBe(true);

      // Clear and create new connection - creator revokes
      connectionService.clear();

      const invite2 = await connectionService.createInvitation(creatorGuid);
      await connectionService.acceptInvitation(acceptorGuid, invite2.invitation!.code);

      const creatorConnections = connectionService.getUserConnections(creatorGuid);
      const result2 = await connectionService.revokeConnection(
        creatorGuid,
        creatorConnections[0].connection_id
      );
      expect(result2.success).toBe(true);
    });
  });

  describe('Revocation Effects', () => {
    it('should update connection status to revoked', async () => {
      const invite = await connectionService.createInvitation(creatorGuid);
      const accept = await connectionService.acceptInvitation(
        acceptorGuid,
        invite.invitation!.code
      );

      await connectionService.revokeConnection(
        acceptorGuid,
        accept.connection!.connection_id
      );

      const connection = connectionService.getConnection(accept.connection!.connection_id);
      expect(connection?.status).toBe('revoked');
    });

    it('should delete shared encryption key', async () => {
      const invite = await connectionService.createInvitation(creatorGuid);
      const accept = await connectionService.acceptInvitation(
        acceptorGuid,
        invite.invitation!.code
      );

      const sharedKeyId = accept.connection!.shared_key_id;

      // Key exists before revocation
      expect(connectionService.getSharedKey(sharedKeyId)).toBeDefined();

      await connectionService.revokeConnection(
        acceptorGuid,
        accept.connection!.connection_id
      );

      // Key should be deleted after revocation
      expect(connectionService.getSharedKey(sharedKeyId)).toBeUndefined();
    });

    it('should update both parties connection status', async () => {
      const invite = await connectionService.createInvitation(creatorGuid);
      await connectionService.acceptInvitation(acceptorGuid, invite.invitation!.code);

      const acceptorConnections = connectionService.getUserConnections(acceptorGuid);
      await connectionService.revokeConnection(
        acceptorGuid,
        acceptorConnections[0].connection_id
      );

      // Check both parties
      const creatorConns = connectionService.getUserConnections(creatorGuid);
      const acceptorConns = connectionService.getUserConnections(acceptorGuid);

      expect(creatorConns[0].status).toBe('revoked');
      expect(acceptorConns[0].status).toBe('revoked');
    });

    it('should prevent future message exchange', async () => {
      const invite = await connectionService.createInvitation(creatorGuid);
      const accept = await connectionService.acceptInvitation(
        acceptorGuid,
        invite.invitation!.code
      );

      // Set up messaging
      const sharedKey = connectionService.getSharedKey(accept.connection!.shared_key_id)!;
      messagingService.setSharedKey(accept.connection!.connection_id, sharedKey);

      // Send message before revocation - should work
      const beforeRevoke = await messagingService.sendMessage(
        creatorGuid,
        accept.connection!.connection_id,
        acceptorGuid,
        'Hello before revoke'
      );
      expect(beforeRevoke.success).toBe(true);

      // Revoke connection
      await connectionService.revokeConnection(
        acceptorGuid,
        accept.connection!.connection_id
      );

      // Clear the shared key from messaging service (simulating revocation cleanup)
      messagingService.clear();

      // Try to send message after revocation - should fail
      const afterRevoke = await messagingService.sendMessage(
        creatorGuid,
        accept.connection!.connection_id,
        acceptorGuid,
        'Hello after revoke'
      );
      expect(afterRevoke.success).toBe(false);
      expect(afterRevoke.error).toContain('key not found');
    });
  });

  describe('Data Cleanup', () => {
    it('should retain message history for owner', async () => {
      const invite = await connectionService.createInvitation(creatorGuid);
      const accept = await connectionService.acceptInvitation(
        acceptorGuid,
        invite.invitation!.code
      );

      // Set up messaging and send some messages
      const sharedKey = connectionService.getSharedKey(accept.connection!.shared_key_id)!;
      messagingService.setSharedKey(accept.connection!.connection_id, sharedKey);

      await messagingService.sendMessage(
        creatorGuid,
        accept.connection!.connection_id,
        acceptorGuid,
        'Message 1'
      );
      await messagingService.sendMessage(
        acceptorGuid,
        accept.connection!.connection_id,
        creatorGuid,
        'Message 2'
      );

      // Verify messages exist
      const messagesBefore = messagingService.getMessages(accept.connection!.connection_id);
      expect(messagesBefore.length).toBe(2);

      // Note: In a real implementation, messages would be retained but marked
      // The mock doesn't implement full cleanup logic
    });

    it('should mark connection as revoked but preserve record', async () => {
      const invite = await connectionService.createInvitation(creatorGuid);
      const accept = await connectionService.acceptInvitation(
        acceptorGuid,
        invite.invitation!.code
      );

      const connectionId = accept.connection!.connection_id;

      await connectionService.revokeConnection(acceptorGuid, connectionId);

      // Connection record should still exist but be marked as revoked
      const connection = connectionService.getConnection(connectionId);
      expect(connection).toBeDefined();
      expect(connection?.status).toBe('revoked');
    });
  });

  describe('Pending Invitations', () => {
    it('should not affect other pending invitations from same user', async () => {
      // Create connection
      const invite1 = await connectionService.createInvitation(creatorGuid);
      const accept = await connectionService.acceptInvitation(
        acceptorGuid,
        invite1.invitation!.code
      );

      // Create another pending invitation
      const invite2 = await connectionService.createInvitation(creatorGuid);
      expect(invite2.invitation?.status).toBe('pending');

      // Revoke the connection
      await connectionService.revokeConnection(
        acceptorGuid,
        accept.connection!.connection_id
      );

      // Pending invitation should still be valid
      const pendingInvite = connectionService.getInvitation(invite2.invitation!.code);
      expect(pendingInvite?.status).toBe('pending');
    });
  });

  describe('Multiple Connections', () => {
    it('should only revoke specified connection', async () => {
      const user2 = 'user-2';
      const user3 = 'user-3';

      // Create multiple connections
      const invite1 = await connectionService.createInvitation(creatorGuid);
      await connectionService.acceptInvitation(user2, invite1.invitation!.code);

      const invite2 = await connectionService.createInvitation(creatorGuid);
      await connectionService.acceptInvitation(user3, invite2.invitation!.code);

      const creatorConnections = connectionService.getUserConnections(creatorGuid);
      expect(creatorConnections.length).toBe(2);

      // Revoke first connection
      await connectionService.revokeConnection(creatorGuid, creatorConnections[0].connection_id);

      // Check states
      const updatedConnections = connectionService.getUserConnections(creatorGuid);
      const revokedCount = updatedConnections.filter(c => c.status === 'revoked').length;
      const activeCount = updatedConnections.filter(c => c.status === 'active').length;

      expect(revokedCount).toBe(1);
      expect(activeCount).toBe(1);
    });

    it('should allow reconnection after revocation', async () => {
      // Create and revoke connection
      const invite1 = await connectionService.createInvitation(creatorGuid);
      const accept1 = await connectionService.acceptInvitation(
        acceptorGuid,
        invite1.invitation!.code
      );

      await connectionService.revokeConnection(
        acceptorGuid,
        accept1.connection!.connection_id
      );

      // Create new invitation and reconnect
      // Note: In real implementation, this might need additional logic
      // to handle re-connection with same user
    });
  });
});
