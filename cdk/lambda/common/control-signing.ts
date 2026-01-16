/**
 * Control Command Signing Module
 *
 * Provides Ed25519 signing for control commands to ensure:
 * 1. Authenticity - Commands are from authorized admin services
 * 2. Integrity - Commands haven't been tampered with
 * 3. Non-repudiation - Signed commands can be audited
 * 4. Replay prevention - Commands expire and have idempotency keys
 *
 * Key Management:
 * - Private key stored in AWS Secrets Manager
 * - Public key distributed to enclave parent processes
 * - Keys should be rotated periodically (see docs/CONTROL-COMMAND-SIGNING.md)
 */

import * as crypto from 'crypto';
import {
  SecretsManagerClient,
  GetSecretValueCommand,
} from '@aws-sdk/client-secrets-manager';
import { DynamoDBClient, PutItemCommand, GetItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall } from '@aws-sdk/util-dynamodb';
import { randomUUID } from 'crypto';

const secretsManager = new SecretsManagerClient({});
const ddb = new DynamoDBClient({});

// Environment variables
const CONTROL_SIGNING_KEY_SECRET = process.env.CONTROL_SIGNING_KEY_SECRET || 'vettid/control-signing-key';
const TABLE_COMMAND_IDEMPOTENCY = process.env.TABLE_COMMAND_IDEMPOTENCY;

// Command expiry (5 minutes)
const COMMAND_TTL_SECONDS = 300;

// Cache the private key in memory (Lambda warm start optimization)
let cachedPrivateKey: crypto.KeyObject | null = null;
let cacheTimestamp = 0;
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Target types for control commands
 */
export type CommandTargetType = 'global' | 'enclave' | 'user';

/**
 * Target specification for a control command
 */
export interface CommandTarget {
  type: CommandTargetType;
  id?: string; // Required for 'enclave' and 'user' targets
}

/**
 * Signed control command structure
 */
export interface SignedControlCommand {
  command_id: string;
  command: string;
  target: CommandTarget;
  params: Record<string, unknown>;
  issued_at: string;
  issued_by: string;
  expires_at: string;
  signature: string; // Base64-encoded Ed25519 signature
}

/**
 * Unsigned command (before signing)
 */
export interface UnsignedControlCommand {
  command: string;
  target: CommandTarget;
  params: Record<string, unknown>;
  issued_by: string;
}

/**
 * Retrieves the Ed25519 private key from Secrets Manager
 * Uses in-memory caching to reduce API calls
 */
async function getPrivateKey(): Promise<crypto.KeyObject> {
  const now = Date.now();

  // Return cached key if still valid
  if (cachedPrivateKey && now - cacheTimestamp < CACHE_TTL_MS) {
    return cachedPrivateKey;
  }

  try {
    const response = await secretsManager.send(
      new GetSecretValueCommand({
        SecretId: CONTROL_SIGNING_KEY_SECRET,
      })
    );

    if (!response.SecretString) {
      throw new Error('Control signing key secret is empty');
    }

    const secret = JSON.parse(response.SecretString);

    if (!secret.private_key) {
      throw new Error('Control signing key secret missing private_key field');
    }

    // Import the PEM-encoded private key
    cachedPrivateKey = crypto.createPrivateKey({
      key: secret.private_key,
      format: 'pem',
    });

    cacheTimestamp = now;

    return cachedPrivateKey;
  } catch (error) {
    console.error('Failed to retrieve control signing key:', error);
    throw new Error('Control signing key unavailable');
  }
}

/**
 * Creates the canonical payload string for signing
 * Order matters - must match verification in enclave
 */
function createSigningPayload(command: Omit<SignedControlCommand, 'signature'>): string {
  const payload = {
    command_id: command.command_id,
    command: command.command,
    target: command.target,
    params: command.params,
    issued_at: command.issued_at,
    issued_by: command.issued_by,
    expires_at: command.expires_at,
  };

  // Use sorted keys for deterministic serialization
  return JSON.stringify(payload, Object.keys(payload).sort());
}

/**
 * Signs a control command with Ed25519
 *
 * @param command - The unsigned command to sign
 * @returns Signed command with signature and metadata
 */
export async function signControlCommand(
  command: UnsignedControlCommand
): Promise<SignedControlCommand> {
  const privateKey = await getPrivateKey();

  const commandId = `cmd-${randomUUID()}`;
  const issuedAt = new Date().toISOString();
  const expiresAt = new Date(Date.now() + COMMAND_TTL_SECONDS * 1000).toISOString();

  const unsignedCommand: Omit<SignedControlCommand, 'signature'> = {
    command_id: commandId,
    command: command.command,
    target: command.target,
    params: command.params,
    issued_at: issuedAt,
    issued_by: command.issued_by,
    expires_at: expiresAt,
  };

  const payload = createSigningPayload(unsignedCommand);
  const signature = crypto.sign(null, Buffer.from(payload), privateKey);

  return {
    ...unsignedCommand,
    signature: signature.toString('base64'),
  };
}

/**
 * Verifies a signed control command (for testing/debugging)
 * In production, verification happens in the enclave parent process
 *
 * @param command - The signed command to verify
 * @param publicKeyPem - PEM-encoded Ed25519 public key
 * @returns true if signature is valid
 */
export function verifyControlCommand(
  command: SignedControlCommand,
  publicKeyPem: string
): boolean {
  try {
    const publicKey = crypto.createPublicKey({
      key: publicKeyPem,
      format: 'pem',
    });

    const { signature, ...unsignedCommand } = command;
    const payload = createSigningPayload(unsignedCommand);

    return crypto.verify(
      null,
      Buffer.from(payload),
      publicKey,
      Buffer.from(signature, 'base64')
    );
  } catch (error) {
    console.error('Signature verification failed:', error);
    return false;
  }
}

/**
 * Checks if a command has expired
 */
export function isCommandExpired(command: SignedControlCommand): boolean {
  const expiresAt = new Date(command.expires_at).getTime();
  return Date.now() > expiresAt;
}

/**
 * Checks if a command ID has already been processed (idempotency)
 * Stores processed command IDs in DynamoDB with TTL
 *
 * @param commandId - The command ID to check
 * @returns true if command was already processed
 */
export async function isCommandProcessed(commandId: string): Promise<boolean> {
  if (!TABLE_COMMAND_IDEMPOTENCY) {
    console.warn('TABLE_COMMAND_IDEMPOTENCY not set, skipping idempotency check');
    return false;
  }

  try {
    const result = await ddb.send(
      new GetItemCommand({
        TableName: TABLE_COMMAND_IDEMPOTENCY,
        Key: marshall({ command_id: commandId }),
      })
    );

    return !!result.Item;
  } catch (error) {
    console.error('Error checking command idempotency:', error);
    // Fail open to avoid blocking commands on DDB issues
    return false;
  }
}

/**
 * Marks a command as processed for idempotency
 *
 * @param commandId - The command ID to mark
 * @param command - The command name (for audit)
 * @param issuedBy - Who issued the command
 */
export async function markCommandProcessed(
  commandId: string,
  command: string,
  issuedBy: string
): Promise<void> {
  if (!TABLE_COMMAND_IDEMPOTENCY) {
    console.warn('TABLE_COMMAND_IDEMPOTENCY not set, skipping idempotency record');
    return;
  }

  try {
    // TTL: 24 hours from now (commands expire in 5 min, but keep record longer for audit)
    const ttl = Math.floor(Date.now() / 1000) + 86400;

    await ddb.send(
      new PutItemCommand({
        TableName: TABLE_COMMAND_IDEMPOTENCY,
        Item: marshall({
          command_id: commandId,
          command,
          issued_by: issuedBy,
          processed_at: new Date().toISOString(),
          ttl,
        }),
      })
    );
  } catch (error) {
    console.error('Error recording command idempotency:', error);
    // Don't fail the command if we can't record idempotency
  }
}

/**
 * Helper to generate a new Ed25519 keypair for initial setup
 * Run this once to generate keys, then store in Secrets Manager
 *
 * Usage:
 * const { publicKey, privateKey } = generateSigningKeyPair();
 * // Store privateKey in Secrets Manager
 * // Distribute publicKey to enclave instances
 */
export function generateSigningKeyPair(): { publicKey: string; privateKey: string } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');

  return {
    publicKey: publicKey.export({ type: 'spki', format: 'pem' }) as string,
    privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }) as string,
  };
}
