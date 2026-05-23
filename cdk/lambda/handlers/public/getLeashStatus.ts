import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand } from '@aws-sdk/client-dynamodb';
import { unmarshall } from '@aws-sdk/util-dynamodb';

const ddb = new DynamoDBClient({});
const TABLE_LEASH_ISSUED = process.env.TABLE_LEASH_ISSUED!;

/**
 * GET /v1/public/leash/status/{jti}
 *
 * Returns the current revocation status of one LEASH by jti. See
 * docs/LEASH-TOKEN-FORMAT.md §"Revocation endpoint".
 *
 * Response (200):
 *   {
 *     "jti": "leash-...",
 *     "revoked": false,
 *     "revoked_at": null,         // unix sec when revoked, else null
 *     "reason": null,
 *     "checked_at": 1716483800
 *   }
 *
 * Response (404):
 *   { "jti": "...", "revoked": true, "reason": "unknown jti" }
 *   Verifiers MUST treat 404 as revoked — a leash not in the issuer's
 *   records is not one a relying party should honor.
 *
 * Public endpoint — jti is opaque, scope/timestamps are not secret.
 * Verifiers SHOULD cache responses for ≤30s.
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

  const jti = event.pathParameters?.jti;
  if (!jti) {
    return {
      statusCode: 400,
      headers: corsHeaders,
      body: JSON.stringify({ error: 'missing jti in path' }),
    };
  }

  const now = Math.floor(Date.now() / 1000);

  try {
    const result = await ddb.send(
      new GetItemCommand({
        TableName: TABLE_LEASH_ISSUED,
        Key: { jti: { S: jti } },
      }),
    );

    if (!result.Item) {
      // Per spec: 404 means "unknown jti" and verifiers MUST treat
      // it as revoked. We return the structured body with
      // revoked=true so a careless verifier that only checks the
      // body shape (not status) still does the right thing.
      return {
        statusCode: 404,
        headers: { ...corsHeaders, 'Cache-Control': 'public, max-age=30' },
        body: JSON.stringify({
          jti,
          revoked: true,
          revoked_at: null,
          reason: 'unknown jti',
          checked_at: now,
        }),
      };
    }

    const row = unmarshall(result.Item);
    return {
      statusCode: 200,
      headers: { ...corsHeaders, 'Cache-Control': 'public, max-age=30' },
      body: JSON.stringify({
        jti: row.jti,
        revoked: row.revoked === true,
        revoked_at: row.revoked_at ?? null,
        reason: row.reason ?? null,
        checked_at: now,
      }),
    };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'unknown error';
    console.error('getLeashStatus lookup failed', { jti, error: message });
    return {
      statusCode: 500,
      headers: corsHeaders,
      body: JSON.stringify({ error: 'lookup failed' }),
    };
  }
};
