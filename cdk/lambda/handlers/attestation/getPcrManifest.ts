import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { S3Client, GetObjectCommand } from '@aws-sdk/client-s3';

const s3 = new S3Client({});
const BUCKET = process.env.PCR_MANIFEST_BUCKET!;
const MANIFEST_KEY = 'pcr-manifest.json';

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
