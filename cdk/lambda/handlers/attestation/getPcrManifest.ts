import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { S3Client, GetObjectCommand } from '@aws-sdk/client-s3';
import { KMSClient, VerifyCommand } from '@aws-sdk/client-kms';
import { createHash } from 'crypto';
import { canonicalize } from '../../../lib/canonical-json';

const s3 = new S3Client({});
const kms = new KMSClient({});
const BUCKET = process.env.PCR_MANIFEST_BUCKET!;
const MANIFEST_KEY = 'pcr-manifest.json';
// KMS key (alias or ARN) used to sign the manifest. Required — if
// unset the Lambda fails closed rather than ship an unverified blob.
const SIGNING_KEY_ID = process.env.PCR_SIGNING_KEY_ID || '';

/**
 * GET /attestation/pcr-manifest
 *
 * Returns the signed PCR manifest containing all valid PCR sets.
 * This endpoint is PUBLIC - no authentication required.
 *
 * Mobile apps fetch this manifest and verify the signature against
 * the embedded VettID signing public key before trusting the PCR values.
 *
 * Response format:
 * {
 *   "version": 2,
 *   "timestamp": "2026-01-06T00:00:00Z",
 *   "pcr_sets": [
 *     {
 *       "id": "production-v1",
 *       "pcr0": "...",
 *       "pcr1": "...",
 *       "pcr2": "...",
 *       "valid_from": "2026-01-03T00:00:00Z",
 *       "valid_until": null,
 *       "is_current": true,
 *       "description": "Initial production enclave"
 *     }
 *   ],
 *   "signature": "base64-encoded-ecdsa-signature"
 * }
 */
/**
 * Verifies the manifest's embedded signature against the configured
 * KMS key. Hashes the canonical (RFC 8785-sorted) form of
 * {version, timestamp, pcr_sets} — must match what publish-pcr-set.ts
 * canonicalized at sign time.
 *
 * Returns null on success, or a string describing the failure.
 */
async function verifyManifestSignature(manifestJson: string): Promise<string | null> {
  let parsed: any;
  try {
    parsed = JSON.parse(manifestJson);
  } catch (e: any) {
    return `manifest is not valid JSON: ${e.message || e}`;
  }
  const sig: string | undefined = parsed?.signature;
  if (!sig) return 'manifest has no signature field';
  if (!Array.isArray(parsed.pcr_sets) || typeof parsed.version !== 'number' || typeof parsed.timestamp !== 'string') {
    return 'manifest missing required fields (version, timestamp, pcr_sets)';
  }

  const dataToVerify = canonicalize({
    version: parsed.version,
    timestamp: parsed.timestamp,
    pcr_sets: parsed.pcr_sets,
  });
  const messageHash = createHash('sha256').update(dataToVerify).digest();

  let signatureBytes: Buffer;
  try {
    signatureBytes = Buffer.from(sig, 'base64');
  } catch (e: any) {
    return `signature is not valid base64: ${e.message || e}`;
  }

  try {
    const result = await kms.send(new VerifyCommand({
      KeyId: SIGNING_KEY_ID,
      Message: messageHash,
      MessageType: 'DIGEST',
      Signature: signatureBytes,
      SigningAlgorithm: 'ECDSA_SHA_256',
    }));
    if (!result.SignatureValid) {
      return 'KMS reported SignatureValid=false';
    }
    return null;
  } catch (e: any) {
    return `KMS Verify failed: ${e.message || e}`;
  }
}

export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Cache-Control': 'public, max-age=300', // Cache for 5 minutes
  };

  // Handle CORS preflight
  if (event.requestContext.http.method === 'OPTIONS') {
    return {
      statusCode: 204,
      headers: corsHeaders,
      body: '',
    };
  }

  try {
    // Fetch manifest from S3
    const response = await s3.send(new GetObjectCommand({
      Bucket: BUCKET,
      Key: MANIFEST_KEY,
    }));

    const manifest = await response.Body?.transformToString();

    if (!manifest) {
      console.error('PCR manifest not found or empty');
      return {
        statusCode: 503,
        headers: {
          ...corsHeaders,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          error: 'PCR manifest not available',
          message: 'The attestation configuration is being updated. Please retry.',
        }),
      };
    }

    // Defense in depth: verify the signature on every fetch. The
    // S3 bucket access is restricted to the publisher role, but a
    // compromised CI / IAM mistake / S3 misconfig would let an
    // attacker swap the manifest. Mobile clients verify too — but
    // verifying here means a hostile blob never leaves the API
    // surface. Audit finding F2.
    if (!SIGNING_KEY_ID) {
      console.error('PCR_SIGNING_KEY_ID env var unset — refusing to ship unverified manifest');
      return {
        statusCode: 503,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          error: 'PCR manifest verification unavailable',
          message: 'Signing key not configured.',
        }),
      };
    }
    const verifyErr = await verifyManifestSignature(manifest);
    if (verifyErr) {
      console.error('PCR manifest signature verification failed:', verifyErr);
      return {
        statusCode: 503,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          error: 'PCR manifest verification failed',
          message: 'Manifest signature invalid — refusing to serve.',
        }),
      };
    }

    // Return the manifest (already signed, includes signature field)
    return {
      statusCode: 200,
      headers: {
        ...corsHeaders,
        'Content-Type': 'application/json',
        'ETag': response.ETag || '',
      },
      body: manifest,
    };

  } catch (error: any) {
    console.error('Error fetching PCR manifest:', error);

    if (error.name === 'NoSuchKey') {
      return {
        statusCode: 503,
        headers: {
          ...corsHeaders,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          error: 'PCR manifest not configured',
          message: 'Contact administrator to initialize PCR manifest.',
        }),
      };
    }

    return {
      statusCode: 500,
      headers: {
        ...corsHeaders,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        error: 'Internal error',
        message: 'Failed to retrieve PCR manifest.',
      }),
    };
  }
};
