/**
 * GET /vault/pcrs/current - Return current PCR values for Nitro Enclave attestation
 *
 * This public endpoint returns the expected PCR values for the current VettID
 * enclave build, signed with VettID's Ed25519 key so mobile apps can verify
 * the authenticity of PCR updates.
 *
 * PCR (Platform Configuration Register) values are SHA-384 hashes that identify:
 * - PCR0: Enclave image file (EIF)
 * - PCR1: Linux kernel and bootstrap
 * - PCR2: Application code
 *
 * Mobile apps use these values to verify Nitro attestation documents.
 */

import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import * as crypto from 'crypto';

const secretsManager = new SecretsManagerClient({});

// Current PCR values from the latest enclave build
// These are updated when a new enclave image is deployed
// AMI: ami-0df4c8d00aefbcded (2026-01-04)
const CURRENT_PCRS = {
  PCR0: 'dba58cf585cb2bfcfe71d6985dc3960d176b12375bdba05f1147cb080e63c6d7e49a5cecfe6a01118dfc916d99b1f1f4',
  PCR1: '4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493',
  PCR2: 'a9cd3622a33cc26a19100d021e0b0460dcd51f37d39679a81570ab8c585f820bf816a7cf0cf8a34d3ad5f5279cea9161',
  // PCR3 is optional - hash of IAM role ARN if KMS attestation is used
  PCR3: null as string | null,
};

// Version identifier for this PCR configuration
const PCR_VERSION = '2026-01-04-v2';
const PUBLISHED_AT = '2026-01-04T02:00:00Z';

// CORS headers
const corsHeaders = {
  'Access-Control-Allow-Origin': '*', // Public endpoint
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Allow-Methods': 'OPTIONS,GET',
  'Content-Type': 'application/json',
  'Cache-Control': 'public, max-age=3600', // Cache for 1 hour
};

interface PcrResponse {
  pcrs: {
    PCR0: string;
    PCR1: string;
    PCR2: string;
    PCR3: string | null;
  };
  version: string;
  published_at: string;
  signature: string;
  key_id: string;
}

/**
 * Sign the PCR payload with Ed25519
 */
async function signPcrs(payload: object): Promise<string> {
  const secretName = process.env.PCR_SIGNING_KEY_SECRET;
  if (!secretName) {
    throw new Error('PCR_SIGNING_KEY_SECRET not configured');
  }

  // Get the private key from Secrets Manager
  const command = new GetSecretValueCommand({ SecretId: secretName });
  const response = await secretsManager.send(command);

  if (!response.SecretString) {
    throw new Error('PCR signing key not found');
  }

  // The secret is stored as Base64-encoded DER
  const privateKeyDer = Buffer.from(response.SecretString, 'base64');

  // Create the private key object
  const privateKey = crypto.createPrivateKey({
    key: privateKeyDer,
    format: 'der',
    type: 'pkcs8',
  });

  // Sign the canonical JSON representation
  const message = JSON.stringify(payload);
  const signature = crypto.sign(null, Buffer.from(message), privateKey);

  return signature.toString('base64');
}

export const handler = async (
  event: APIGatewayProxyEventV2
): Promise<APIGatewayProxyResultV2> => {
  console.log('GET /vault/pcrs/current');

  // Handle CORS preflight
  if (event.requestContext.http.method === 'OPTIONS') {
    return {
      statusCode: 204,
      headers: corsHeaders,
      body: '',
    };
  }

  try {
    // Build the PCR payload
    const pcrPayload = {
      PCR0: CURRENT_PCRS.PCR0,
      PCR1: CURRENT_PCRS.PCR1,
      PCR2: CURRENT_PCRS.PCR2,
      ...(CURRENT_PCRS.PCR3 && { PCR3: CURRENT_PCRS.PCR3 }),
    };

    // Sign the payload
    const signature = await signPcrs(pcrPayload);

    const response: PcrResponse = {
      pcrs: {
        PCR0: CURRENT_PCRS.PCR0,
        PCR1: CURRENT_PCRS.PCR1,
        PCR2: CURRENT_PCRS.PCR2,
        PCR3: CURRENT_PCRS.PCR3,
      },
      version: PCR_VERSION,
      published_at: PUBLISHED_AT,
      signature: signature,
      key_id: 'vettid-pcr-signing-key-v1',
    };

    return {
      statusCode: 200,
      headers: corsHeaders,
      body: JSON.stringify(response),
    };
  } catch (error) {
    console.error('Error getting PCR config:', error);

    return {
      statusCode: 500,
      headers: corsHeaders,
      body: JSON.stringify({
        error: 'Failed to get PCR configuration',
        message: error instanceof Error ? error.message : 'Unknown error',
      }),
    };
  }
};
