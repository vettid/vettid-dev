/**
 * NATS Publisher Utility
 *
 * Provides functions to publish messages to NATS from Lambda functions.
 * Uses the system account credentials from Secrets Manager for publishing
 * system-wide broadcasts and control messages.
 *
 * The NATS cluster is accessible via TLS on port 443 through the NLB.
 */

import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import { connect, NatsConnection, StringCodec, credsAuthenticator } from 'nats';
import * as nkeys from 'nkeys.js';
import { createHash, randomUUID } from 'crypto';

const OPERATOR_SECRET_ID = process.env.NATS_OPERATOR_SECRET_ARN || 'vettid/nats/operator-key';
const NATS_DOMAIN = process.env.NATS_DOMAIN || 'nats.vettid.dev';

const secretsClient = new SecretsManagerClient({});
const sc = StringCodec();

// Cache system credentials for Lambda reuse
let cachedSystemCreds: string | null = null;
let cacheTime = 0;
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

interface SystemCredentials {
  jwt: string;
  seed: string;
  creds: string;
}

interface NatsAccountClaims {
  jti: string;
  iat: number;
  exp?: number;
  iss: string;
  sub: string;
  name: string;
  nats: {
    limits?: object;
    type?: string;
    version?: number;
  };
}

interface NatsUserClaims {
  jti: string;
  iat: number;
  exp: number;
  iss: string;
  sub: string;
  name: string;
  nats: {
    pub?: { allow?: string[]; deny?: string[] };
    sub?: { allow?: string[]; deny?: string[] };
    subs?: number;
    data?: number;
    payload?: number;
    type?: string;
    version?: number;
  };
}

/**
 * Encode a JWT without external libraries
 */
function encodeJwt(header: object, payload: object, signingKey: nkeys.KeyPair): string {
  const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');

  const dataToSign = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const signature = signingKey.sign(dataToSign);
  const signatureB64 = Buffer.from(signature).toString('base64url');

  return `${headerB64}.${payloadB64}.${signatureB64}`;
}

/**
 * Format credentials as NATS creds file content
 */
function formatCredsFile(jwt: string, seed: string): string {
  return `-----BEGIN NATS USER JWT-----
${jwt}
------END NATS USER JWT-----

************************* IMPORTANT *************************
NKEY Seed printed below can be used to sign and prove identity.
NKEYs are sensitive and should be treated as secrets.

-----BEGIN USER NKEY SEED-----
${seed}
------END USER NKEY SEED-----
`;
}

/**
 * Get system credentials for publishing broadcasts
 * The system account has permissions to publish to Broadcast.* subjects
 */
async function getSystemCredentials(): Promise<SystemCredentials> {
  const now = Date.now();

  // Return cached credentials if still valid
  if (cachedSystemCreds && (now - cacheTime) < CACHE_TTL_MS) {
    const lines = cachedSystemCreds.split('\n');
    const jwtStart = lines.findIndex(l => l.includes('BEGIN NATS USER JWT'));
    const jwtEnd = lines.findIndex(l => l.includes('END NATS USER JWT'));
    const seedStart = lines.findIndex(l => l.includes('BEGIN USER NKEY SEED'));
    const seedEnd = lines.findIndex(l => l.includes('END USER NKEY SEED'));

    const jwt = lines.slice(jwtStart + 1, jwtEnd).join('').trim();
    const seed = lines.slice(seedStart + 1, seedEnd).join('').trim();

    return { jwt, seed, creds: cachedSystemCreds };
  }

  // Fetch operator secret
  const response = await secretsClient.send(new GetSecretValueCommand({
    SecretId: OPERATOR_SECRET_ID,
  }));

  if (!response.SecretString) {
    throw new Error('NATS operator secret is empty');
  }

  const secret = JSON.parse(response.SecretString);

  if (!secret.system_account_seed || !secret.system_account_public_key) {
    throw new Error('NATS operator secret missing system account keys');
  }

  // Generate a system user for publishing broadcasts
  const systemAccountSeed = secret.system_account_seed;
  const systemAccountKeyPair = nkeys.fromSeed(new TextEncoder().encode(systemAccountSeed));
  const systemAccountPublicKey = systemAccountKeyPair.getPublicKey();

  // Create a user key pair for this session
  const userKeyPair = nkeys.createUser();
  const userSeed = new TextDecoder().decode(userKeyPair.getSeed());
  const userPublicKey = userKeyPair.getPublicKey();

  const nowSec = Math.floor(Date.now() / 1000);
  const exp = nowSec + 3600; // 1 hour expiry

  // SECURITY: JTI includes randomness to prevent collisions
  const jti = createHash('sha256')
    .update(`${userPublicKey}:${nowSec}:${randomUUID()}`)
    .digest('hex')
    .substring(0, 22);

  // System user permissions - can publish to Broadcast.*, Control.*, and OwnerSpace.* subjects
  // OwnerSpace access is needed for publishing security events to users
  const userClaims: NatsUserClaims = {
    jti,
    iat: nowSec,
    exp,
    iss: systemAccountPublicKey,
    sub: userPublicKey,
    name: 'system-broadcast-publisher',
    nats: {
      pub: { allow: ['Broadcast.>', 'Control.>', 'OwnerSpace.>'] },
      sub: { allow: [] },
      subs: 0,
      data: -1,
      payload: -1,
      type: 'user',
      version: 2,
    },
  };

  const header = {
    typ: 'JWT',
    alg: 'ed25519-nkey',
  };

  const jwt = encodeJwt(header, userClaims, systemAccountKeyPair);
  const creds = formatCredsFile(jwt, userSeed);

  // Cache the credentials
  cachedSystemCreds = creds;
  cacheTime = now;

  return { jwt, seed: userSeed, creds };
}

/**
 * Publish a message to NATS
 *
 * @param subject - The NATS subject to publish to
 * @param payload - The message payload (will be JSON encoded)
 * @returns Promise<boolean> - true if published successfully
 */
export async function publishToNats(
  subject: string,
  payload: object
): Promise<{ success: boolean; error?: string }> {
  let nc: NatsConnection | null = null;

  try {
    // Get system credentials
    const { creds } = await getSystemCredentials();

    // Connect to NATS
    nc = await connect({
      servers: [`tls://${NATS_DOMAIN}:443`],
      authenticator: credsAuthenticator(new TextEncoder().encode(creds)),
      reconnect: false,
      maxReconnectAttempts: 0,
      timeout: 10000, // 10 second connection timeout
    });

    // Publish the message
    const data = sc.encode(JSON.stringify(payload));
    nc.publish(subject, data);

    // Flush to ensure the message is sent
    await nc.flush();

    console.log(`Published message to NATS subject: ${subject}`);
    return { success: true };
  } catch (error: any) {
    console.error('Failed to publish to NATS:', error.message);
    return { success: false, error: error.message };
  } finally {
    // Clean up connection
    if (nc) {
      try {
        await nc.drain();
      } catch {
        // Ignore drain errors
      }
    }
  }
}

/**
 * Publish a vault broadcast message
 *
 * @param broadcastType - Type of broadcast (system_announcement, security_alert, admin_message)
 * @param payload - The broadcast payload
 */
export async function publishVaultBroadcast(
  broadcastType: string,
  payload: {
    broadcast_id: string;
    type: string;
    priority: string;
    title: string;
    message: string;
    sent_at: string;
    sent_by: string;
  }
): Promise<{ success: boolean; error?: string }> {
  // Map broadcast type to NATS subject
  const BROADCAST_SUBJECTS: Record<string, string> = {
    system_announcement: 'Broadcast.system.announcement',
    security_alert: 'Broadcast.security.alert',
    admin_message: 'Broadcast.admin.message',
  };

  const subject = BROADCAST_SUBJECTS[broadcastType];
  if (!subject) {
    return { success: false, error: `Unknown broadcast type: ${broadcastType}` };
  }

  return publishToNats(subject, payload);
}

/**
 * Publish a signed control command to NATS
 *
 * SECURITY: All control commands are signed with Ed25519 to prevent
 * unauthorized execution if backend credentials are compromised.
 *
 * @param command - Command type (e.g., 'handlers.reload', 'health.request')
 * @param target - Target specifier (global, enclave, or user)
 * @param params - Command parameters
 * @param issuedBy - Admin email or system identifier
 */
export async function publishSignedControlCommand(
  command: string,
  target: { type: 'global' | 'enclave' | 'user'; id?: string },
  params: Record<string, any>,
  issuedBy: string
): Promise<{ success: boolean; command_id?: string; error?: string }> {
  // Import signing module
  const { signControlCommand } = await import('./control-signing');

  try {
    // Sign the command
    const signedCommand = await signControlCommand({
      command,
      target,
      params,
      issued_by: issuedBy,
    });

    // Determine NATS subject based on target
    let subject: string;
    switch (target.type) {
      case 'global':
        subject = `Control.global.${command}`;
        break;
      case 'enclave':
        if (!target.id) {
          return { success: false, error: 'enclave target requires id' };
        }
        subject = `Control.enclave.${target.id}.${command}`;
        break;
      case 'user':
        if (!target.id) {
          return { success: false, error: 'user target requires id' };
        }
        subject = `Control.user.${target.id}.${command}`;
        break;
      default:
        return { success: false, error: `Unknown target type: ${target.type}` };
    }

    // Publish signed command
    const result = await publishToNats(subject, signedCommand);

    if (result.success) {
      return { success: true, command_id: signedCommand.command_id };
    }
    return result;
  } catch (error: any) {
    console.error('Failed to publish signed control command:', error);
    return { success: false, error: error.message };
  }
}

// ============================================================================
// Security Event Publishing
// ============================================================================

/**
 * Standard security event payload structure
 */
export interface SecurityEvent {
  event_id: string;
  type: string;
  timestamp: string;
  payload: Record<string, any>;
}

/**
 * Recovery event types
 */
export type RecoveryEventType =
  | 'recovery_requested'
  | 'recovery_cancelled'
  | 'recovery_completed';

/**
 * Transfer event types
 */
export type TransferEventType =
  | 'transfer_requested'
  | 'transfer_approved'
  | 'transfer_denied'
  | 'transfer_completed'
  | 'transfer_expired';

/**
 * Security event types
 */
export type SecurityAlertType =
  | 'recovery_fraud_detected';

/**
 * Publish a security event to a user's OwnerSpace
 *
 * Events are published to OwnerSpace.{guid}.forApp.{topic}
 * where topic is determined by the event type.
 *
 * @param userGuid - The user's GUID
 * @param eventType - The type of event
 * @param payload - Event-specific payload data
 * @returns Promise with success status
 */
export async function publishUserSecurityEvent(
  userGuid: string,
  eventType: RecoveryEventType | TransferEventType | SecurityAlertType,
  payload: Record<string, any>
): Promise<{ success: boolean; event_id?: string; error?: string }> {
  const eventId = randomUUID();

  // Map event type to NATS topic
  const topicMap: Record<string, string> = {
    // Recovery events
    recovery_requested: 'forApp.recovery.requested',
    recovery_cancelled: 'forApp.recovery.cancelled',
    recovery_completed: 'forApp.recovery.completed',
    // Transfer events
    transfer_requested: 'forApp.transfer.requested',
    transfer_approved: 'forApp.transfer.approved',
    transfer_denied: 'forApp.transfer.denied',
    transfer_completed: 'forApp.transfer.completed',
    transfer_expired: 'forApp.transfer.expired',
    // Security alerts
    recovery_fraud_detected: 'forApp.security.fraud_detected',
  };

  const topic = topicMap[eventType];
  if (!topic) {
    return { success: false, error: `Unknown event type: ${eventType}` };
  }

  const subject = `OwnerSpace.${userGuid}.${topic}`;

  const event: SecurityEvent = {
    event_id: eventId,
    type: eventType,
    timestamp: new Date().toISOString(),
    payload,
  };

  const result = await publishToNats(subject, event);

  if (result.success) {
    console.log(`Published security event ${eventType} to user ${userGuid.substring(0, 8)}...`);
    return { success: true, event_id: eventId };
  }

  return result;
}

/**
 * Publish a recovery requested event
 */
export async function publishRecoveryRequested(
  userGuid: string,
  recoveryId: string,
  requestedAt: string,
  availableAt: string
): Promise<{ success: boolean; event_id?: string; error?: string }> {
  return publishUserSecurityEvent(userGuid, 'recovery_requested', {
    recovery_id: recoveryId,
    requested_at: requestedAt,
    available_at: availableAt,
  });
}

/**
 * Publish a recovery cancelled event
 */
export async function publishRecoveryCancelled(
  userGuid: string,
  recoveryId: string,
  reason: 'user_cancelled' | 'admin_cancelled' | 'credential_used_during_recovery',
  cancelledAt: string
): Promise<{ success: boolean; event_id?: string; error?: string }> {
  return publishUserSecurityEvent(userGuid, 'recovery_cancelled', {
    recovery_id: recoveryId,
    reason,
    cancelled_at: cancelledAt,
  });
}

/**
 * Publish a recovery completed event
 */
export async function publishRecoveryCompleted(
  userGuid: string,
  recoveryId: string,
  completedAt: string
): Promise<{ success: boolean; event_id?: string; error?: string }> {
  return publishUserSecurityEvent(userGuid, 'recovery_completed', {
    recovery_id: recoveryId,
    completed_at: completedAt,
  });
}

/**
 * Publish a recovery fraud detected event
 */
export async function publishRecoveryFraudDetected(
  userGuid: string,
  recoveryId: string,
  reason: string,
  detectedAt: string
): Promise<{ success: boolean; event_id?: string; error?: string }> {
  return publishUserSecurityEvent(userGuid, 'recovery_fraud_detected', {
    recovery_id: recoveryId,
    reason,
    detected_at: detectedAt,
  });
}

/**
 * Device info for transfer events
 */
export interface DeviceInfo {
  device_id: string;
  model?: string;
  os_version?: string;
  location?: string;
}

/**
 * Publish a transfer requested event
 */
export async function publishTransferRequested(
  userGuid: string,
  transferId: string,
  sourceDeviceId: string,
  targetDeviceInfo: DeviceInfo,
  expiresAt: string
): Promise<{ success: boolean; event_id?: string; error?: string }> {
  return publishUserSecurityEvent(userGuid, 'transfer_requested', {
    transfer_id: transferId,
    source_device_id: sourceDeviceId,
    target_device_info: targetDeviceInfo,
    expires_at: expiresAt,
  });
}

/**
 * Publish a transfer approved event
 */
export async function publishTransferApproved(
  userGuid: string,
  transferId: string
): Promise<{ success: boolean; event_id?: string; error?: string }> {
  return publishUserSecurityEvent(userGuid, 'transfer_approved', {
    transfer_id: transferId,
  });
}

/**
 * Publish a transfer denied event
 */
export async function publishTransferDenied(
  userGuid: string,
  transferId: string,
  reason?: string
): Promise<{ success: boolean; event_id?: string; error?: string }> {
  return publishUserSecurityEvent(userGuid, 'transfer_denied', {
    transfer_id: transferId,
    reason: reason || 'user_denied',
  });
}

/**
 * Publish a transfer completed event
 */
export async function publishTransferCompleted(
  userGuid: string,
  transferId: string,
  completedAt: string
): Promise<{ success: boolean; event_id?: string; error?: string }> {
  return publishUserSecurityEvent(userGuid, 'transfer_completed', {
    transfer_id: transferId,
    completed_at: completedAt,
  });
}

/**
 * Publish a transfer expired event
 */
export async function publishTransferExpired(
  userGuid: string,
  transferId: string
): Promise<{ success: boolean; event_id?: string; error?: string }> {
  return publishUserSecurityEvent(userGuid, 'transfer_expired', {
    transfer_id: transferId,
  });
}
