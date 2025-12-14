# E2EE Calling Implementation Plan (Vault-Centric)

## Overview

This plan describes the implementation of end-to-end encrypted WebRTC calls using a **vault-centric architecture**. Call state and signaling are handled entirely within user vaults using NATS JetStream for storage, with WASM handlers for logic.

**Key Principles:**
- Call state is stored in each user's own JetStream KV bucket (decentralized)
- WASM handlers in vaults process call events
- NATS handles both messaging AND data storage
- AWS only provides TURN credentials (single Lambda)
- All E2EE is handled client-side

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    VAULT-CENTRIC CALL ARCHITECTURE                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌────────────┐                                          ┌────────────┐   │
│   │  Alice's   │                                          │   Bob's    │   │
│   │    App     │                                          │    App     │   │
│   └─────┬──────┘                                          └─────┬──────┘   │
│         │ OwnerSpace                                  OwnerSpace │         │
│         │                                                        │         │
│   ┌─────▼──────┐                                          ┌─────▼──────┐   │
│   │  Alice's   │         MessageSpace.call.>              │   Bob's    │   │
│   │   Vault    │◄────────────────────────────────────────►│   Vault    │   │
│   │   (WASM)   │                                          │   (WASM)   │   │
│   └─────┬──────┘                                          └─────┬──────┘   │
│         │                                                        │         │
│         │ JetStream KV                              JetStream KV │         │
│         ▼                                                        ▼         │
│   ┌───────────────────────────────────────────────────────────────────┐   │
│   │                      NATS + JetStream                              │   │
│   │                                                                    │   │
│   │  ┌─────────────────────┐          ┌─────────────────────┐         │   │
│   │  │  Alice's KV Buckets │          │  Bob's KV Buckets   │         │   │
│   │  │                     │          │                     │         │   │
│   │  │  • calls            │          │  • calls            │         │   │
│   │  │  • connections      │          │  • connections      │         │   │
│   │  │  • messages         │          │  • messages         │         │   │
│   │  │  • profile          │          │  • profile          │         │   │
│   │  └─────────────────────┘          └─────────────────────┘         │   │
│   │                                                                    │   │
│   │  ┌─────────────────────────────────────────────────────────────┐  │   │
│   │  │                    Pub/Sub Topics                            │  │   │
│   │  │                                                              │  │   │
│   │  │  OwnerSpace.{guid}.forVault.>    (app → vault)              │  │   │
│   │  │  OwnerSpace.{guid}.forApp.>      (vault → app)              │  │   │
│   │  │  MessageSpace.{guid}.call.>      (vault ↔ vault signaling)  │  │   │
│   │  └─────────────────────────────────────────────────────────────┘  │   │
│   └───────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│   ┌───────────────────────────────────────────────────────────────────┐   │
│   │                         AWS (Minimal)                              │   │
│   │                                                                    │   │
│   │  ┌─────────────────────┐                                          │   │
│   │  │ GET /calls/turn     │  ← Only AWS Lambda needed                │   │
│   │  │ (TURN credentials)  │     (Cloudflare secrets)                 │   │
│   │  └─────────────────────┘                                          │   │
│   └───────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Call Flow

### Initiating a Call

```
Alice's App                Alice's Vault              NATS                Bob's Vault               Bob's App
    │                           │                      │                       │                       │
    │  1. call.initiate         │                      │                       │                       │
    │  {peer_guid, call_type}   │                      │                       │                       │
    │──────────────────────────►│                      │                       │                       │
    │                           │                      │                       │                       │
    │                           │  2. Store call in KV │                       │                       │
    │                           │  status: "outgoing"  │                       │                       │
    │                           │─────────────────────►│                       │                       │
    │                           │                      │                       │                       │
    │                           │  3. Publish call.incoming                    │                       │
    │                           │  to Bob's MessageSpace                       │                       │
    │                           │─────────────────────────────────────────────►│                       │
    │                           │                      │                       │                       │
    │                           │                      │                       │  4. Store call in KV  │
    │                           │                      │                       │  status: "incoming"   │
    │                           │                      │                       │─────────────────────► │
    │                           │                      │                       │                       │
    │                           │                      │                       │  5. Notify app        │
    │                           │                      │                       │  call.incoming        │
    │                           │                      │                       │──────────────────────►│
    │                           │                      │                       │                       │
    │  6. call.ringing          │                      │                       │                       │
    │◄──────────────────────────│◄─────────────────────────────────────────────│                       │
    │                           │                      │                       │                       │
```

### Accepting a Call

```
Bob's App                  Bob's Vault               NATS               Alice's Vault             Alice's App
    │                           │                      │                       │                       │
    │  1. call.accept           │                      │                       │                       │
    │  {call_id, public_key}    │                      │                       │                       │
    │──────────────────────────►│                      │                       │                       │
    │                           │                      │                       │                       │
    │                           │  2. Update KV        │                       │                       │
    │                           │  status: "active"    │                       │                       │
    │                           │─────────────────────►│                       │                       │
    │                           │                      │                       │                       │
    │                           │  3. Publish call.accept                      │                       │
    │                           │  to Alice's MessageSpace                     │                       │
    │                           │─────────────────────────────────────────────►│                       │
    │                           │                      │                       │                       │
    │                           │                      │                       │  4. Update KV         │
    │                           │                      │                       │  status: "active"     │
    │                           │                      │                       │─────────────────────► │
    │                           │                      │                       │                       │
    │                           │                      │                       │  5. Notify app        │
    │                           │                      │                       │  call.accepted        │
    │                           │                      │                       │  {public_key}         │
    │                           │                      │                       │──────────────────────►│
    │                           │                      │                       │                       │
    │                    [E2EE Key Exchange & WebRTC Signaling via NATS]       │                       │
    │                           │                      │                       │                       │
```

## Phase 1: JetStream KV Buckets

### Bucket Provisioning

When a NATS account is created (during enrollment), provision these KV buckets:

```typescript
// Bucket names follow pattern: {user_guid}_{bucket_type}
// Created by vault services or during NATS account setup

interface KVBucketConfig {
  name: string;
  ttl?: number;        // Optional TTL in seconds
  maxBytes?: number;   // Storage limit
  history?: number;    // Number of historical values to keep
}

const userBuckets: KVBucketConfig[] = [
  {
    name: '{user_guid}_calls',
    ttl: 30 * 24 * 60 * 60,  // 30 days
    history: 1,
  },
  {
    name: '{user_guid}_connections',
    history: 1,
  },
  {
    name: '{user_guid}_messages',
    ttl: 90 * 24 * 60 * 60,  // 90 days (configurable)
    history: 1,
  },
  {
    name: '{user_guid}_profile',
    history: 1,
  },
];
```

### Call Record Schema

```typescript
// Stored in KV bucket: {user_guid}_calls
// Key: {call_id}

interface CallRecord {
  call_id: string;
  peer_guid: string;           // The other party
  direction: 'incoming' | 'outgoing';
  call_type: 'audio' | 'video';
  status: 'initiating' | 'ringing' | 'active' | 'ended' | 'missed' | 'rejected';

  // Timestamps
  created_at: string;          // ISO8601
  answered_at?: string;        // When call connected
  ended_at?: string;           // When call ended

  // Call details
  duration_seconds?: number;
  end_reason?: 'caller' | 'callee' | 'timeout' | 'error' | 'rejected';

  // E2EE metadata (no keys stored)
  key_exchange_complete: boolean;
}
```

## Phase 2: NATS Message Types

### Topic Structure

```
# App ↔ Vault (OwnerSpace)
OwnerSpace.{user_guid}.forVault.call.initiate    # App requests call
OwnerSpace.{user_guid}.forVault.call.accept      # App accepts call
OwnerSpace.{user_guid}.forVault.call.reject      # App rejects call
OwnerSpace.{user_guid}.forVault.call.end         # App ends call
OwnerSpace.{user_guid}.forVault.call.signal      # App sends WebRTC signal

OwnerSpace.{user_guid}.forApp.call.incoming      # Vault notifies incoming call
OwnerSpace.{user_guid}.forApp.call.accepted      # Vault notifies call accepted
OwnerSpace.{user_guid}.forApp.call.rejected      # Vault notifies call rejected
OwnerSpace.{user_guid}.forApp.call.ended         # Vault notifies call ended
OwnerSpace.{user_guid}.forApp.call.signal        # Vault forwards WebRTC signal
OwnerSpace.{user_guid}.forApp.call.ringing       # Vault notifies peer is ringing

# Vault ↔ Vault (MessageSpace)
MessageSpace.{user_guid}.call.incoming           # Incoming call from peer
MessageSpace.{user_guid}.call.accept             # Peer accepted call
MessageSpace.{user_guid}.call.reject             # Peer rejected call
MessageSpace.{user_guid}.call.end                # Peer ended call
MessageSpace.{user_guid}.call.ringing            # Peer's phone is ringing
MessageSpace.{user_guid}.call.signal             # WebRTC signaling (SDP/ICE)
```

### Message Schemas

```typescript
// Base message
interface CallMessageBase {
  message_id: string;
  call_id: string;
  timestamp: string;
}

// App → Vault: Initiate call
interface CallInitiateRequest extends CallMessageBase {
  type: 'call.initiate';
  peer_guid: string;
  call_type: 'audio' | 'video';
}

// Vault → App: Incoming call notification
interface CallIncomingNotification extends CallMessageBase {
  type: 'call.incoming';
  peer_guid: string;
  call_type: 'audio' | 'video';
  peer_profile: {
    display_name: string;
    avatar_url?: string;
  };
}

// App → Vault: Accept call
interface CallAcceptRequest extends CallMessageBase {
  type: 'call.accept';
  public_key: string;      // Base64 ECDH public key for E2EE
  key_id: string;
}

// Vault → Vault: Call accepted
interface CallAcceptedSignal extends CallMessageBase {
  type: 'call.accept';
  from_guid: string;
  public_key: string;
  key_id: string;
}

// WebRTC Signaling
interface CallSignal extends CallMessageBase {
  type: 'call.signal';
  signal_type: 'offer' | 'answer' | 'ice' | 'key_exchange';
  payload: string;         // JSON-encoded SDP, ICE candidate, or public key
}

// Call ended
interface CallEndedSignal extends CallMessageBase {
  type: 'call.end';
  reason: 'caller' | 'callee' | 'timeout' | 'error';
  duration_seconds?: number;
}
```

## Phase 3: WASM Handlers

### Handler Directory Structure

```
vault/handlers/
├── call/
│   ├── initiate.wasm      # Handle call initiation
│   ├── incoming.wasm      # Handle incoming call from peer
│   ├── accept.wasm        # Handle call acceptance
│   ├── reject.wasm        # Handle call rejection
│   ├── end.wasm           # Handle call ending
│   ├── signal.wasm        # Relay WebRTC signals
│   └── timeout.wasm       # Handle call timeouts
```

### Handler Specifications

#### 1. `initiate.wasm`

```
Trigger: OwnerSpace.{user_guid}.forVault.call.initiate
Input:   CallInitiateRequest

Logic:
1. Validate peer_guid is in connections KV bucket
2. Generate call_id (UUID)
3. Store CallRecord in calls KV bucket (status: 'initiating')
4. Publish call.incoming to peer's MessageSpace
5. Notify app via OwnerSpace.forApp (call initiated)

Output: call_id, status
```

#### 2. `incoming.wasm`

```
Trigger: MessageSpace.{user_guid}.call.incoming
Input:   CallIncomingSignal from peer vault

Logic:
1. Validate from_guid is in connections KV bucket
2. Lookup peer profile from connections
3. Store CallRecord in calls KV bucket (status: 'incoming', direction: 'incoming')
4. Publish call.ringing back to caller's MessageSpace
5. Notify app via OwnerSpace.forApp.call.incoming

Output: Notification to app with peer profile
```

#### 3. `accept.wasm`

```
Trigger: OwnerSpace.{user_guid}.forVault.call.accept
Input:   CallAcceptRequest (includes E2EE public key)

Logic:
1. Lookup call in KV bucket
2. Validate call status is 'incoming'
3. Update CallRecord: status='active', answered_at=now
4. Publish call.accept to peer's MessageSpace (include public key)
5. Notify app: call connected

Output: Call connected confirmation
```

#### 4. `reject.wasm`

```
Trigger: OwnerSpace.{user_guid}.forVault.call.reject
Input:   { call_id, reason? }

Logic:
1. Lookup call in KV bucket
2. Update CallRecord: status='rejected', ended_at=now
3. Publish call.reject to peer's MessageSpace
4. Notify app: call rejected

Output: Call rejected confirmation
```

#### 5. `end.wasm`

```
Trigger: OwnerSpace.{user_guid}.forVault.call.end
Input:   { call_id }

Logic:
1. Lookup call in KV bucket
2. Calculate duration if call was active
3. Update CallRecord: status='ended', ended_at=now, duration_seconds
4. Publish call.end to peer's MessageSpace
5. Notify app: call ended

Output: Call ended with duration
```

#### 6. `signal.wasm`

```
Trigger:
  - OwnerSpace.{user_guid}.forVault.call.signal (from app)
  - MessageSpace.{user_guid}.call.signal (from peer vault)

Logic:
If from app:
  1. Lookup call in KV, get peer_guid
  2. Forward signal to peer's MessageSpace

If from peer:
  1. Validate call exists and is active
  2. Forward signal to app via OwnerSpace.forApp.call.signal

Output: Signal forwarded
```

#### 7. `timeout.wasm`

```
Trigger: Scheduled (every 30 seconds) or via NATS timer

Logic:
1. Query calls KV for status='ringing' older than 60 seconds
2. Update each to status='missed', ended_at=now
3. Publish call.end (reason: timeout) to peer's MessageSpace
4. Notify app: call missed

Output: Stale calls cleaned up
```

## Phase 4: NATS Permission Updates

Update `generateMemberJwt.ts` to include call signaling permissions:

```typescript
// App permissions
if (body.client_type === 'app') {
  publishPerms = [
    `${ownerSpace}.forVault.>`,           // Existing
    // No direct MessageSpace publish for apps
  ];
  subscribePerms = [
    `${ownerSpace}.forApp.>`,             // Existing
    `${ownerSpace}.eventTypes`,           // Existing
  ];
}

// Vault permissions
if (body.client_type === 'vault') {
  publishPerms = [
    `${ownerSpace}.forApp.>`,             // Existing
    `${messageSpace}.call.>`,             // NEW: Vault can send call signals to peers
    `${messageSpace}.forOwner.>`,         // Existing
    `${messageSpace}.ownerProfile`,       // Existing
  ];
  subscribePerms = [
    `${ownerSpace}.forVault.>`,           // Existing
    `${ownerSpace}.control`,              // Existing
    `${ownerSpace}.eventTypes`,           // Existing
    `${messageSpace}.call.>`,             // NEW: Vault receives call signals
    `${messageSpace}.forOwner.>`,         // Existing
  ];
}
```

## Phase 5: KV Bucket Provisioning

Update `createMemberAccount.ts` to provision KV buckets:

```typescript
// After creating NATS account, create KV buckets
async function provisionKVBuckets(js: JetStreamClient, userGuid: string) {
  const buckets = [
    {
      bucket: `${userGuid}_calls`,
      ttl: 30 * 24 * 60 * 60 * 1000, // 30 days in ms
      history: 1,
      maxBytes: 10 * 1024 * 1024,    // 10MB
    },
    {
      bucket: `${userGuid}_connections`,
      history: 1,
      maxBytes: 1 * 1024 * 1024,     // 1MB
    },
    {
      bucket: `${userGuid}_messages`,
      ttl: 90 * 24 * 60 * 60 * 1000, // 90 days in ms
      history: 1,
      maxBytes: 100 * 1024 * 1024,   // 100MB
    },
    {
      bucket: `${userGuid}_profile`,
      history: 1,
      maxBytes: 100 * 1024,          // 100KB
    },
  ];

  for (const config of buckets) {
    await js.views.kv(config.bucket, {
      ttl: config.ttl,
      history: config.history,
      max_bytes: config.maxBytes,
    });
  }
}
```

## Phase 6: AWS Lambda (TURN Credentials Only)

### Single Lambda Handler

```typescript
// lambda/handlers/calls/getTurnCredentials.ts

/**
 * Generate Cloudflare TURN credentials
 *
 * GET /calls/turn-credentials
 *
 * This is the ONLY AWS Lambda needed for calling.
 * Everything else runs in user vaults.
 */

import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import * as crypto from 'crypto';
import { ok, forbidden, requireUserClaims } from '../../common/util';

const TURN_SECRET = process.env.CLOUDFLARE_TURN_SECRET!;
const TURN_TTL_SECONDS = 86400; // 24 hours

interface TurnCredentials {
  ice_servers: IceServer[];
  expires_at: string;
}

interface IceServer {
  urls: string[];
  username?: string;
  credential?: string;
}

export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const origin = event.headers?.origin;

  // Require authenticated member
  const claimsResult = requireUserClaims(event, origin);
  if ('error' in claimsResult) {
    return claimsResult.error;
  }
  const { claims } = claimsResult;
  const userGuid = claims.user_guid;

  // Generate time-limited credentials
  const expiry = Math.floor(Date.now() / 1000) + TURN_TTL_SECONDS;
  const username = `${expiry}:${userGuid}`;

  const credential = crypto
    .createHmac('sha1', TURN_SECRET)
    .update(username)
    .digest('base64');

  const response: TurnCredentials = {
    ice_servers: [
      {
        urls: ['stun:stun.cloudflare.com:3478'],
      },
      {
        urls: [
          'turn:turn.cloudflare.com:3478?transport=udp',
          'turn:turn.cloudflare.com:3478?transport=tcp',
          'turns:turn.cloudflare.com:5349?transport=tcp',
        ],
        username,
        credential,
      },
    ],
    expires_at: new Date(expiry * 1000).toISOString(),
  };

  return ok(response, origin);
};
```

### Stack Wiring

Add to `vettid-stack.ts`:

```typescript
// TURN credentials Lambda (only AWS resource for calling)
const getTurnCredentialsFn = new lambdaNode.NodejsFunction(this, 'GetTurnCredentials', {
  entry: 'lambda/handlers/calls/getTurnCredentials.ts',
  handler: 'handler',
  runtime: lambda.Runtime.NODEJS_20_X,
  environment: {
    CLOUDFLARE_TURN_SECRET: '{{resolve:secretsmanager:cloudflare-turn:SecretString:secret}}',
  },
});

httpApi.addRoutes({
  path: '/calls/turn-credentials',
  methods: [apigw.HttpMethod.GET],
  integration: new integrations.HttpLambdaIntegration('GetTurnCredentialsIntegration', getTurnCredentialsFn),
  authorizer: memberAuthorizer,
});
```

## Phase 7: Mobile App Integration

### Call Flow from App Perspective

```typescript
// Initiating a call
async function initiateCall(peerGuid: string, callType: 'audio' | 'video') {
  // 1. Get TURN credentials from AWS
  const turnCreds = await apiClient.get('/calls/turn-credentials');

  // 2. Generate E2EE key pair
  const { publicKey, privateKey } = await generateECDHKeyPair();

  // 3. Send initiate request to own vault via NATS
  await natsClient.publish(`${ownerSpace}.forVault.call.initiate`, {
    type: 'call.initiate',
    message_id: uuid(),
    call_id: uuid(),
    peer_guid: peerGuid,
    call_type: callType,
    timestamp: new Date().toISOString(),
  });

  // 4. Wait for peer's acceptance with their public key
  // (via OwnerSpace.forApp.call.accepted subscription)

  // 5. Derive shared secret, start WebRTC with E2EE
}

// Receiving a call
natsClient.subscribe(`${ownerSpace}.forApp.call.incoming`, (msg) => {
  const call = JSON.parse(msg.data);
  // Show incoming call UI
  // User can accept or reject
});

// Accepting a call
async function acceptCall(callId: string) {
  const { publicKey, privateKey } = await generateECDHKeyPair();
  const turnCreds = await apiClient.get('/calls/turn-credentials');

  await natsClient.publish(`${ownerSpace}.forVault.call.accept`, {
    type: 'call.accept',
    message_id: uuid(),
    call_id: callId,
    public_key: publicKey,
    key_id: uuid(),
    timestamp: new Date().toISOString(),
  });

  // Wait for peer's key, derive shared secret, start WebRTC
}
```

## Implementation Order

### Step 1: NATS Infrastructure
1. [ ] Update `createMemberAccount.ts` to provision KV buckets
2. [ ] Update `generateMemberJwt.ts` with call signaling permissions
3. [ ] Test KV bucket creation and access

### Step 2: WASM Handlers
4. [ ] Create `call/initiate.wasm` handler
5. [ ] Create `call/incoming.wasm` handler
6. [ ] Create `call/accept.wasm` handler
7. [ ] Create `call/reject.wasm` handler
8. [ ] Create `call/end.wasm` handler
9. [ ] Create `call/signal.wasm` handler
10. [ ] Create `call/timeout.wasm` handler

### Step 3: AWS (Minimal)
11. [ ] Create `getTurnCredentials.ts` Lambda
12. [ ] Add Cloudflare TURN secret to Secrets Manager
13. [ ] Add API route to stack

### Step 4: Mobile Integration
14. [ ] Update Android app with call UI and NATS handlers
15. [ ] Update iOS app with call UI and NATS handlers
16. [ ] Implement E2EE key exchange on both platforms
17. [ ] Implement WebRTC with Insertable Streams

## Security Considerations

1. **Connection Validation**: Vaults only process calls from connected peers
2. **No Central State**: Call records exist only in participant vaults
3. **E2EE Keys Never Leave Device**: Backend only relays encrypted signals
4. **TURN Credentials**: Short-lived (24h), tied to user_guid
5. **KV Bucket Isolation**: Each user's buckets are only accessible by their vault
6. **TTL Cleanup**: Call records auto-expire after 30 days

## Comparison: Vault-Centric vs AWS-Centric

| Aspect | Vault-Centric | AWS-Centric |
|--------|--------------|-------------|
| Call State Storage | User's JetStream KV | DynamoDB |
| Call Logic | WASM handlers | Lambda functions |
| Data Location | Decentralized (user vaults) | Centralized (AWS) |
| Privacy | Higher (user controls data) | Lower (AWS sees metadata) |
| AWS Cost | Minimal (1 Lambda) | Higher (7+ Lambdas + DynamoDB) |
| Complexity | Higher (WASM dev) | Lower (familiar Lambda) |
| Latency | Lower (no Lambda cold start) | Variable |

## Estimated Effort

- **NATS Updates**: 4 hours
- **WASM Handlers**: 16 hours (7 handlers)
- **AWS Lambda**: 2 hours (1 handler)
- **Mobile Integration**: 24 hours (both platforms)
- **Testing**: 8 hours
- **Documentation**: 4 hours

**Total**: ~58 hours
