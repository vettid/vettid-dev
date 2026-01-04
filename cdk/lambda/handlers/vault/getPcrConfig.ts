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
 *
 * PCR values are stored in SSM Parameter Store and updated automatically
 * during AMI builds by Packer.
 */

import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import { SSMClient, GetParameterCommand } from '@aws-sdk/client-ssm';
import * as crypto from 'crypto';

const secretsManager = new SecretsManagerClient({});
const ssm = new SSMClient({});

// SSM parameter path for PCR values
const PCR_PARAMETER_NAME = '/vettid/enclave/pcr/current';

// Cache for PCR values (refresh every 5 minutes)
let cachedPcrs: PcrData | null = null;
let cacheExpiry = 0;
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

interface PcrData {
  PCR0: string;
  PCR1: string;
  PCR2: string;
  PCR3?: string | null;
  version: string;
  published_at: string;
}

// CORS headers
const corsHeaders = {
  'Access-Control-Allow-Origin': '*', // Public endpoint
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Allow-Methods': 'OPTIONS,GET',
  'Content-Type': 'application/json',
  'Cache-Control': 'public, max-age=300', // Cache for 5 minutes (matches Lambda cache)
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
 * Fetch PCR values from SSM Parameter Store with caching
 */
async function getPcrValues(): Promise<PcrData> {
  const now = Date.now();

  // Return cached value if still valid
  if (cachedPcrs && now < cacheExpiry) {
    console.log('Using cached PCR values');
    return cachedPcrs;
  }

  console.log('Fetching PCR values from SSM Parameter Store');

  const command = new GetParameterCommand({
    Name: PCR_PARAMETER_NAME,
    WithDecryption: false,
  });

  const response = await ssm.send(command);

  if (!response.Parameter?.Value) {
    throw new Error('PCR values not found in SSM Parameter Store');
  }

  const pcrData = JSON.parse(response.Parameter.Value) as PcrData;

  // Update cache
  cachedPcrs = pcrData;
  cacheExpiry = now + CACHE_TTL_MS;

  console.log(`Loaded PCR values version: ${pcrData.version}`);

  return pcrData;
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
    // Get PCR values from SSM
    const pcrData = await getPcrValues();

    // Build the PCR payload for signing
    const pcrPayload = {
      PCR0: pcrData.PCR0,
      PCR1: pcrData.PCR1,
      PCR2: pcrData.PCR2,
      ...(pcrData.PCR3 && { PCR3: pcrData.PCR3 }),
    };

    // Sign the payload
    const signature = await signPcrs(pcrPayload);

    const response: PcrResponse = {
      pcrs: {
        PCR0: pcrData.PCR0,
        PCR1: pcrData.PCR1,
        PCR2: pcrData.PCR2,
        PCR3: pcrData.PCR3 || null,
      },
      version: pcrData.version,
      published_at: pcrData.published_at,
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
