# Task: Phase 7 - Connections & Messaging Testing

## Phase
Phase 7: Connections & Messaging

## Assigned To
Testing Instance

## Repository
`github.com/mesmerverse/vettid-dev` (cdk/tests/)

## Status
Phase 6 complete. Ready for Phase 7 connections & messaging testing.

## Overview

Phase 7 implements the connection and messaging system. You need to create tests for:
1. Connection invitation generation and acceptance
2. Per-connection key exchange (X25519)
3. Profile publishing and sharing
4. End-to-end encrypted messaging

## New Backend Endpoints

### Connections
```
POST /connections/invite          # Generate connection invitation
POST /connections/accept          # Accept connection invitation
POST /connections/revoke          # Revoke connection
GET  /connections                 # List connections
GET  /connections/{id}            # Get connection details
GET  /connections/{id}/profile    # Get connection's profile
```

### Profiles
```
GET  /profile                     # Get own profile
PUT  /profile                     # Update own profile
POST /profile/publish             # Publish profile to connections
```

### Messaging
```
POST /messages/send               # Send encrypted message
GET  /messages/{connectionId}     # Get message history
GET  /messages/unread             # Get unread message count
POST /messages/{id}/read          # Mark message as read
```

## Phase 7 Testing Tasks

### 1. Connection Invitation Tests

Create connection invitation flow tests:

```typescript
// tests/integration/connections/createInvitation.test.ts

describe('Create Connection Invitation', () => {
  describe('Invitation Generation', () => {
    it('should generate unique invitation code');
    it('should include owner public key in invitation');
    it('should set configurable expiration time');
    it('should enforce max pending invitations limit');
    it('should require authenticated user');
  });

  describe('Invitation Payload', () => {
    it('should include invitation ID');
    it('should include creator display name');
    it('should include creator avatar URL if set');
    it('should include QR code data');
    it('should include deep link URL');
  });

  describe('Invitation Storage', () => {
    it('should store invitation in DynamoDB');
    it('should set TTL for automatic cleanup');
    it('should track invitation status (pending/accepted/expired/revoked)');
  });
});
```

### 2. Connection Acceptance Tests

Create connection acceptance tests:

```typescript
// tests/integration/connections/acceptInvitation.test.ts

describe('Accept Connection Invitation', () => {
  describe('Invitation Validation', () => {
    it('should validate invitation code exists');
    it('should reject expired invitations');
    it('should reject already-accepted invitations');
    it('should reject revoked invitations');
    it('should reject self-connection attempts');
  });

  describe('Key Exchange', () => {
    it('should perform X25519 key exchange');
    it('should derive shared secret using HKDF');
    it('should generate per-connection encryption key');
    it('should store key securely in vault');
  });

  describe('Connection Establishment', () => {
    it('should create connection record for both parties');
    it('should set connection status to active');
    it('should exchange initial profiles');
    it('should notify inviter of acceptance via NATS');
  });
});
```

### 3. Connection Revocation Tests

Create connection revocation tests:

```typescript
// tests/integration/connections/revokeConnection.test.ts

describe('Revoke Connection', () => {
  describe('Revocation Authorization', () => {
    it('should allow owner to revoke connection');
    it('should reject revocation by non-owner');
    it('should handle already-revoked connections');
  });

  describe('Revocation Effects', () => {
    it('should update connection status to revoked');
    it('should delete shared encryption key');
    it('should remove from both parties connection list');
    it('should notify other party via NATS');
    it('should prevent future message exchange');
  });

  describe('Data Cleanup', () => {
    it('should retain message history for owner');
    it('should mark messages as from-revoked-connection');
    it('should clean up pending invitations');
  });
});
```

### 4. Profile Management Tests

Create profile management tests:

```typescript
// tests/integration/profile/profileManagement.test.ts

describe('Profile Management', () => {
  describe('Profile Schema', () => {
    it('should validate required fields (display_name)');
    it('should validate optional fields (avatar_url, bio, location)');
    it('should enforce field length limits');
    it('should sanitize input for XSS prevention');
  });

  describe('Profile Updates', () => {
    it('should update profile fields');
    it('should version profile updates');
    it('should track last_updated timestamp');
    it('should publish update to connections');
  });

  describe('Profile Publishing', () => {
    it('should encrypt profile for each connection');
    it('should send via MessageSpace');
    it('should handle offline connections (queue)');
    it('should respect connection visibility settings');
  });

  describe('Profile Retrieval', () => {
    it('should return own profile');
    it('should return connection profile');
    it('should reject non-connection profile requests');
    it('should return cached profile if connection offline');
  });
});
```

### 5. Encrypted Messaging Tests

Create end-to-end messaging tests:

```typescript
// tests/integration/messaging/sendMessage.test.ts

describe('Send Message', () => {
  describe('Message Encryption', () => {
    it('should encrypt message with connection key');
    it('should use XChaCha20-Poly1305 AEAD');
    it('should include unique nonce per message');
    it('should authenticate sender');
  });

  describe('Message Delivery', () => {
    it('should send via OwnerSpace topic');
    it('should queue for offline recipient');
    it('should return delivery receipt');
    it('should handle large messages (chunking)');
  });

  describe('Message Validation', () => {
    it('should enforce message size limit');
    it('should validate connection is active');
    it('should reject messages to revoked connections');
    it('should validate message content type');
  });
});

// tests/integration/messaging/receiveMessage.test.ts

describe('Receive Message', () => {
  describe('Message Decryption', () => {
    it('should decrypt message with connection key');
    it('should verify message authenticity');
    it('should reject tampered messages');
    it('should handle decryption failures gracefully');
  });

  describe('Message Storage', () => {
    it('should store decrypted message locally');
    it('should index by connection and timestamp');
    it('should support message search');
    it('should handle duplicate message IDs');
  });

  describe('Message Status', () => {
    it('should track unread count');
    it('should mark messages as read');
    it('should send read receipts');
  });
});
```

### 6. Message History Tests

Create message history tests:

```typescript
// tests/integration/messaging/messageHistory.test.ts

describe('Message History', () => {
  describe('History Retrieval', () => {
    it('should return messages in chronological order');
    it('should support pagination');
    it('should filter by connection');
    it('should filter by date range');
  });

  describe('History Sync', () => {
    it('should sync history across devices');
    it('should handle conflicts');
    it('should respect message retention settings');
  });

  describe('History Search', () => {
    it('should search message content');
    it('should return matching messages with context');
    it('should respect search result limits');
  });
});
```

### 7. E2E Connection Flow Tests

Create end-to-end tests:

```typescript
// tests/e2e/connectionFlow.test.ts

describe('Connection Flow E2E', () => {
  it('should complete: invite → accept → exchange profiles → send message → receive message');
  it('should complete: invite → accept → send messages → revoke → verify blocked');
  it('should handle: offline connection → queue messages → deliver on reconnect');
  it('should handle: key rotation → re-encrypt pending messages');
  it('should handle: profile update → propagate to all connections');
});

// tests/e2e/messagingFlow.test.ts

describe('Messaging Flow E2E', () => {
  it('should deliver message within 500ms (online recipient)');
  it('should queue and deliver message (offline recipient)');
  it('should handle concurrent message exchange');
  it('should maintain message order');
  it('should handle message deletion');
});
```

## Test Utilities

Create connection and messaging test utilities:

```typescript
// tests/fixtures/connections/mockConnection.ts

export function createMockInvitation(options: {
  creatorGuid: string;
  expiresIn?: number;
}): ConnectionInvitation;

export function createMockConnection(options: {
  ownerGuid: string;
  peerGuid: string;
  status?: 'active' | 'revoked';
}): Connection;

export function createMockKeyPair(): {
  publicKey: Buffer;
  privateKey: Buffer;
};

export function deriveSharedKey(
  privateKey: Buffer,
  peerPublicKey: Buffer
): Buffer;

// tests/fixtures/messaging/mockMessage.ts

export function createMockMessage(options: {
  senderId: string;
  connectionId: string;
  content: string;
}): EncryptedMessage;

export function encryptMessage(
  content: string,
  sharedKey: Buffer
): { ciphertext: Buffer; nonce: Buffer };

export function decryptMessage(
  ciphertext: Buffer,
  nonce: Buffer,
  sharedKey: Buffer
): string;
```

## Deliverables

- [ ] createInvitation.test.ts (invitation generation)
- [ ] acceptInvitation.test.ts (connection acceptance)
- [ ] revokeConnection.test.ts (connection revocation)
- [ ] profileManagement.test.ts (profile CRUD)
- [ ] sendMessage.test.ts (message sending)
- [ ] receiveMessage.test.ts (message receiving)
- [ ] messageHistory.test.ts (history and search)
- [ ] connectionFlow.test.ts (E2E connection tests)
- [ ] messagingFlow.test.ts (E2E messaging tests)
- [ ] Mock connection and messaging fixtures

## Acceptance Criteria

- [ ] Connection invitation tests cover generation, validation, expiration
- [ ] Key exchange tests verify X25519 ECDH flow
- [ ] Profile tests cover schema, updates, publishing
- [ ] Messaging tests verify E2E encryption
- [ ] Message history tests cover pagination and search
- [ ] E2E tests cover complete connection and messaging flows

## Notes

- Use mock NATS for pub/sub testing
- Test both online and offline scenarios
- Verify encryption with known test vectors
- Test concurrent operations for race conditions
- Consider message size limits and chunking

## Status Update

```bash
cd /path/to/vettid-dev/cdk
git pull
# Create connection and messaging tests
npm run test:unit  # Verify tests pass
git add tests/
git commit -m "Phase 7: Add connections and messaging tests"
git push

# Update status
# Edit cdk/coordination/status/testing.json
git add cdk/coordination/status/testing.json
git commit -m "Update Testing status: Phase 7 connections & messaging tests complete"
git push
```
