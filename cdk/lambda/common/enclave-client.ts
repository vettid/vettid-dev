/**
 * Nitro Enclave Client
 *
 * Provides communication with the Nitro Enclave via NATS.
 * Lambdas send requests to the enclave through the parent process,
 * which forwards them over vsock.
 *
 * Communication flow:
 *   Lambda → NATS → Parent Process → vsock → Enclave
 *   Enclave → vsock → Parent Process → NATS → Lambda
 */

import { connect, NatsConnection, StringCodec, JSONCodec, credsAuthenticator } from 'nats';
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import { SSMClient, GetParameterCommand } from '@aws-sdk/client-ssm';

const secretsClient = new SecretsManagerClient({});
const ssmClient = new SSMClient({});

// Cache for NATS connection
let natsConnection: NatsConnection | null = null;
let natsCredentials: string | null = null;

const NATS_URL = process.env.NATS_URL || 'nats://nats.internal.vettid.dev:4222';
const BACKEND_CREDS_PARAM = '/vettid/nitro/parent-nats-creds';

// Request timeout (10 seconds for enclave operations)
const REQUEST_TIMEOUT_MS = 10000;

// ============================================
// Types
// ============================================

export interface EnclaveAttestationRequest {
  nonce: string;  // Base64-encoded 32-byte nonce
}

export interface EnclaveAttestationResponse {
  attestation: string;       // Base64-encoded CBOR attestation document
  public_key: string;        // Base64-encoded enclave ephemeral public key
  timestamp: number;
}

export interface EnclaveHealthResponse {
  healthy: boolean;
  active_vaults: number;
  total_vaults: number;
  memory_used_mb: number;
  memory_total_mb: number;
  uptime_seconds: number;
  version: string;
}

// ============================================
// NATS Connection Management
// ============================================

/**
 * Get NATS credentials for backend services
 * Uses the same credentials as the parent process
 */
async function getNatsCredentials(): Promise<string> {
  if (natsCredentials) {
    return natsCredentials;
  }

  try {
    const result = await ssmClient.send(new GetParameterCommand({
      Name: BACKEND_CREDS_PARAM,
      WithDecryption: true,
    }));

    if (!result.Parameter?.Value) {
      throw new Error('NATS credentials parameter is empty');
    }

    natsCredentials = result.Parameter.Value;
    return natsCredentials;
  } catch (error: any) {
    console.error('Failed to get NATS credentials:', error.message);
    throw new Error('Failed to get NATS credentials for enclave communication');
  }
}

/**
 * Get or create NATS connection
 */
async function getNatsConnection(): Promise<NatsConnection> {
  if (natsConnection && !natsConnection.isClosed()) {
    return natsConnection;
  }

  const creds = await getNatsCredentials();

  // Use credsAuthenticator which handles parsing and signing automatically
  const encoder = new TextEncoder();

  natsConnection = await connect({
    servers: NATS_URL,
    authenticator: credsAuthenticator(encoder.encode(creds)),
    maxReconnectAttempts: 3,
    reconnectTimeWait: 1000,
  });

  console.log('Connected to NATS for enclave communication');
  return natsConnection;
}

/**
 * Close NATS connection (call during Lambda shutdown if needed)
 */
export async function closeNatsConnection(): Promise<void> {
  if (natsConnection && !natsConnection.isClosed()) {
    await natsConnection.drain();
    natsConnection = null;
  }
}

// ============================================
// Enclave Communication
// ============================================

const jc = JSONCodec();

/**
 * Send a request to the enclave and wait for response
 * Uses NATS request-reply pattern
 */
async function enclaveRequest<TReq, TRes>(
  subject: string,
  request: TReq,
  timeoutMs: number = REQUEST_TIMEOUT_MS
): Promise<TRes> {
  const nc = await getNatsConnection();

  try {
    const response = await nc.request(subject, jc.encode(request), {
      timeout: timeoutMs,
    });

    const decoded = jc.decode(response.data) as any;

    if (decoded.error) {
      throw new Error(`Enclave error: ${decoded.error}`);
    }

    return decoded as TRes;
  } catch (error: any) {
    if (error.code === 'TIMEOUT') {
      throw new Error(`Enclave request timeout after ${timeoutMs}ms`);
    }
    throw error;
  }
}

// ============================================
// Enclave API Functions
// ============================================

/**
 * Request attestation document from the enclave
 * The attestation proves the enclave is genuine and includes its public key
 */
export async function requestEnclaveAttestation(
  nonce: Buffer
): Promise<EnclaveAttestationResponse> {
  const request: EnclaveAttestationRequest = {
    nonce: nonce.toString('base64'),
  };

  // Attestation requests go to a special enclave control topic
  // This doesn't require a user context
  return enclaveRequest<EnclaveAttestationRequest, EnclaveAttestationResponse>(
    'enclave.attestation.request',
    request
  );
}

/**
 * Get enclave health status
 */
export async function getEnclaveHealth(): Promise<EnclaveHealthResponse> {
  return enclaveRequest<{}, EnclaveHealthResponse>(
    'enclave.health.check',
    {}
  );
}

/**
 * Check if enclave is available and healthy
 */
export async function isEnclaveAvailable(): Promise<boolean> {
  try {
    const health = await getEnclaveHealth();
    return health.healthy;
  } catch (error) {
    console.warn('Enclave health check failed:', error);
    return false;
  }
}
