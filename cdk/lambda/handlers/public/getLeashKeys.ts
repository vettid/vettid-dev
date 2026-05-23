import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, QueryCommand } from '@aws-sdk/client-dynamodb';
import { unmarshall } from '@aws-sdk/util-dynamodb';

const ddb = new DynamoDBClient({});
const TABLE_LEASH_ATTEST_KEYS = process.env.TABLE_LEASH_ATTEST_KEYS!;

/**
 * GET /v1/public/leash/keys/{user_guid}
 *
 * Returns the published Ed25519 attestation pubkey(s) for a user, so
 * external LEASH verifiers can fetch them by kid to verify JWT
 * signatures. See docs/LEASH-TOKEN-FORMAT.md §"Key publishing".
 *
 * Response (200):
 *   {
 *     "user_guid": "...",
 *     "keys": [
 *       { "kid": "leash-attest-...-v1", "alg": "EdDSA",
 *         "pubkey": "<base64url ed25519 pubkey>", "created_at": 1716000000 },
 *       ...
 *     ]
 *   }
 *
 * Response (404): user has never issued a leash.
 *
 * Public endpoint — no PII exposed (just an Ed25519 pubkey + opaque kid).
 * Verifiers SHOULD cache responses for ~1h; pubkeys rotate rarely.
 */

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Content-Type': 'application/json',
};

export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  if (event.requestContext.http.method === 'OPTIONS') {
    return { statusCode: 200, headers: corsHeaders, body: '' };
  }

  const userGuid = event.pathParameters?.user_guid;
  if (!userGuid) {
    return {
      statusCode: 400,
      headers: corsHeaders,
      body: JSON.stringify({ error: 'missing user_guid in path' }),
    };
  }

  try {
    // Query by partition key (user_guid). Returns all rows across the
    // sortkey (kid) — covers key rotation grace periods where multiple
    // kids are live simultaneously.
    const result = await ddb.send(
      new QueryCommand({
        TableName: TABLE_LEASH_ATTEST_KEYS,
        KeyConditionExpression: 'user_guid = :pk',
        ExpressionAttributeValues: {
          ':pk': { S: userGuid },
        },
      }),
    );

    const items = (result.Items ?? []).map((it) => unmarshall(it));
    if (items.length === 0) {
      return {
        statusCode: 404,
        headers: corsHeaders,
        body: JSON.stringify({
          error: 'no attestation keys published for this user',
          user_guid: userGuid,
        }),
      };
    }

    // Shape the response: drop DDB-internal fields (none right now
    // beyond what the vault publishes, but be defensive for the future).
    const keys = items.map((row) => ({
      kid: row.kid,
      alg: row.alg,
      pubkey: row.pubkey,
      created_at: row.created_at,
      rotated_at: row.rotated_at ?? null,
    }));

    return {
      statusCode: 200,
      headers: {
        ...corsHeaders,
        // Cache for 1 hour as recommended in the spec. Rotation
        // procedure (v2) will overlap keys for longer than this TTL
        // so caches don't miss the new key.
        'Cache-Control': 'public, max-age=3600',
      },
      body: JSON.stringify({ user_guid: userGuid, keys }),
    };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'unknown error';
    console.error('getLeashKeys query failed', { user_guid: userGuid, error: message });
    return {
      statusCode: 500,
      headers: corsHeaders,
      body: JSON.stringify({ error: 'lookup failed' }),
    };
  }
};
