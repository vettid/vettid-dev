/**
 * Control Command Signing Utility
 *
 * SECURITY: All control commands must be signed to prevent unauthorized execution
 * if backend credentials are compromised.
 *
 * Signature covers: command_id, command, target, params, issued_at, issued_by, expires_at
 * Algorithm: Ed25519 (same as NATS JWTs)
 */

import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import { createHash, randomUUID, sign, verify, generateKeyPairSync } from 'crypto';

const secretsClient = new SecretsManagerClient({});

// Cache the signing key for Lambda reuse
let cachedSigningKey: { privateKey: Buffer; publicKey: Buffer } | null = null;
let cacheTime = 0;
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

const CONTROL_SIGNING_SECRET_ID = process.env.CONTROL_SIGNING_SECRET_ARN || 'vettid/control-signing-key';

// Command expiration time (5 minutes)
const COMMAND_TTL_MS = 5 * 60 * 1000;

/**
 * Control command target types
 */
export type ControlTargetType = 'global' | 'enclave' | 'user';

/**
 * Control command target
 */
export interface ControlTarget {
  type: ControlTargetType;
  id?: string;  // Required for 'enclave' and 'user' types
}

/**
 * Signed control command structure
 */
export interface SignedControlCommand {
  command_id: string;
  command: string;
  target: ControlTarget;
  params: Record<string, any>;
  issued_at: string;
  issued_by: string;
  expires_at: string;
  signature: string;
}

/**
 * Unsigned control command (before signing)
 */
export interface UnsignedControlCommand {
  command: string;
  target: ControlTarget;
  params?: Record<string, any>;
  issued_by: string;
}

/**
 * Get or generate signing keys
 *
 * In production, keys are stored in Secrets Manager.
 * In development, generates ephemeral keys.
 */
async function getSigningKeys(): Promise<{ privateKey: Buffer; publicKey: Buffer }> {
  const now = Date.now();

  // Return cached keys if still valid
  if (cachedSigningKey && (now - cacheTime) < CACHE_TTL_MS) {
    return cachedSigningKey;
  }

  try {
    // Try to get keys from Secrets Manager
    const response = await secretsClient.send(new GetSecretValueCommand({
      SecretId: CONTROL_SIGNING_SECRET_ID,
    }));

    if (response.SecretString) {
      const secret = JSON.parse(response.SecretString);

      if (secret.private_key && secret.public_key) {
        cachedSigningKey = {
          privateKey: Buffer.from(secret.private_key, 'base64'),
          publicKey: Buffer.from(secret.public_key, 'base64'),
        };
        cacheTime = now;
        return cachedSigningKey;
      }
    }
  } catch (error: any) {
    // In development, fall through to generate ephemeral keys
    if (process.env.NODE_ENV === 'production') {
      throw new Error(`Failed to get control signing keys: ${error.message}`);
    }
    console.warn('Control signing secret not found, using development keys');
  }

  // Development mode: generate ephemeral keys
  // WARNING: These keys change on each Lambda cold start!
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  cachedSigningKey = {
    privateKey: privateKey.export({ type: 'pkcs8', format: 'der' }) as Buffer,
    publicKey: publicKey.export({ type: 'spki', format: 'der' }) as Buffer,
  };
  cacheTime = now;

  console.warn('Using ephemeral control signing keys (development mode)');
  return cachedSigningKey;
}

/**
 * Create the canonical payload for signing
 *
 * SECURITY: Order of fields matters for consistent signatures
 */
function createSigningPayload(cmd: Omit<SignedControlCommand, 'signature'>): string {
  return JSON.stringify({
    command_id: cmd.command_id,
    command: cmd.command,
    target: cmd.target,
    params: cmd.params,
    issued_at: cmd.issued_at,
    issued_by: cmd.issued_by,
    expires_at: cmd.expires_at,
  });
}

/**
 * Sign a control command
 *
 * @param command - The unsigned command to sign
 * @returns Signed control command with all fields populated
 */
export async function signControlCommand(command: UnsignedControlCommand): Promise<SignedControlCommand> {
  const keys = await getSigningKeys();

  const now = new Date();
  const expiresAt = new Date(now.getTime() + COMMAND_TTL_MS);

  const unsignedCmd: Omit<SignedControlCommand, 'signature'> = {
    command_id: randomUUID(),
    command: command.command,
    target: command.target,
    params: command.params || {},
    issued_at: now.toISOString(),
    issued_by: command.issued_by,
    expires_at: expiresAt.toISOString(),
  };

  // Create canonical payload and sign
  const payload = createSigningPayload(unsignedCmd);
  const signature = sign(null, Buffer.from(payload), {
    key: keys.privateKey,
    format: 'der',
    type: 'pkcs8',
  });

  return {
    ...unsignedCmd,
    signature: signature.toString('base64'),
  };
}

/**
 * Verify a signed control command
 *
 * SECURITY: Verifies signature, timestamp freshness, and expiration
 *
 * @param command - The signed command to verify
 * @returns true if valid, throws on invalid
 */
export async function verifyControlCommand(command: SignedControlCommand): Promise<boolean> {
  const keys = await getSigningKeys();

  // 1. Check expiration
  const expiresAt = new Date(command.expires_at);
  if (expiresAt.getTime() < Date.now()) {
    throw new Error('Control command has expired');
  }

  // 2. Check freshness (issued within last 5 minutes)
  const issuedAt = new Date(command.issued_at);
  const age = Date.now() - issuedAt.getTime();
  if (age > COMMAND_TTL_MS) {
    throw new Error('Control command is too old');
  }
  if (age < -60000) {
    // Allow 1 minute clock skew into the future
    throw new Error('Control command issued in the future');
  }

  // 3. Verify signature
  const payload = createSigningPayload({
    command_id: command.command_id,
    command: command.command,
    target: command.target,
    params: command.params,
    issued_at: command.issued_at,
    issued_by: command.issued_by,
    expires_at: command.expires_at,
  });

  const isValid = verify(
    null,
    Buffer.from(payload),
    { key: keys.publicKey, format: 'der', type: 'spki' },
    Buffer.from(command.signature, 'base64')
  );

  if (!isValid) {
    throw new Error('Invalid control command signature');
  }

  return true;
}

/**
 * Get the public key for distribution to enclaves
 *
 * This should be called during deployment to get the public key
 * that enclaves need for verification.
 */
export async function getControlSigningPublicKey(): Promise<string> {
  const keys = await getSigningKeys();
  return keys.publicKey.toString('base64');
}

/**
 * Generate a new signing keypair and store in Secrets Manager
 *
 * This is a one-time operation to initialize the signing keys.
 * Should be run via a script, not during normal operation.
 */
export async function initializeControlSigningKeys(): Promise<{ publicKey: string }> {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');

  const privateKeyDer = privateKey.export({ type: 'pkcs8', format: 'der' }) as Buffer;
  const publicKeyDer = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;

  // Store in Secrets Manager
  const { SecretsManagerClient, CreateSecretCommand, UpdateSecretCommand } = await import('@aws-sdk/client-secrets-manager');
  const client = new SecretsManagerClient({});

  const secretValue = JSON.stringify({
    private_key: privateKeyDer.toString('base64'),
    public_key: publicKeyDer.toString('base64'),
    created_at: new Date().toISOString(),
  });

  try {
    await client.send(new CreateSecretCommand({
      Name: CONTROL_SIGNING_SECRET_ID,
      Description: 'Ed25519 keypair for signing control commands',
      SecretString: secretValue,
      Tags: [
        { Key: 'Application', Value: 'vettid' },
        { Key: 'Component', Value: 'control-signing' },
      ],
    }));
  } catch (error: any) {
    if (error.name === 'ResourceExistsException') {
      // Update existing secret
      await client.send(new UpdateSecretCommand({
        SecretId: CONTROL_SIGNING_SECRET_ID,
        SecretString: secretValue,
      }));
    } else {
      throw error;
    }
  }

  // Invalidate cache
  cachedSigningKey = null;
  cacheTime = 0;

  return {
    publicKey: publicKeyDer.toString('base64'),
  };
}
