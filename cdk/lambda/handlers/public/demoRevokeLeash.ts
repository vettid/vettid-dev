import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, UpdateItemCommand, GetItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import { isDemoIssuer } from './_demoFixtures';

/**
 * POST /v1/public/leash/demo/revoke
 *
 * Marks a Demo Alice LEASH as revoked so the gamified page can show
 * "replay after revoke" attacks. ONLY revokes LEASHes whose iss is
 * Demo Alice — real-user LEASHes can never be revoked through this
 * endpoint (defends against the public revoke being used to nuke
 * production agents).
 *
 * Body:
 *   { "jti": "leash-demo-..." }
 *
 * Response:
 *   { "jti": "...", "revoked": true, "revoked_at": ..., "reason": "demo-test" }
 *   400 if jti doesn't exist or isn't a demo leash.
 */

const ddb = new DynamoDBClient({});
const TABLE_LEASH_ISSUED = process.env.TABLE_LEASH_ISSUED!;

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Content-Type': 'application/json',
};

export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  if (event.requestContext.http.method === 'OPTIONS') {
    return { statusCode: 200, headers: corsHeaders, body: '' };
  }

  let body: { jti?: unknown };
  try {
    body = JSON.parse(event.body ?? '');
  } catch {
    return { statusCode: 400, headers: corsHeaders, body: JSON.stringify({ error: 'malformed JSON' }) };
  }

  const jti = typeof body.jti === 'string' ? body.jti : null;
  if (!jti) {
    return { statusCode: 400, headers: corsHeaders, body: JSON.stringify({ error: 'jti is required' }) };
  }

  try {
    // Load + verify it's a demo leash before touching it.
    const get = await ddb.send(new GetItemCommand({
      TableName: TABLE_LEASH_ISSUED,
      Key: { jti: { S: jti } },
    }));
    if (!get.Item) {
      return { statusCode: 404, headers: corsHeaders, body: JSON.stringify({ error: 'jti not found' }) };
    }
    const row = unmarshall(get.Item);
    if (!isDemoIssuer(row.iss)) {
      // Hard refusal — never revoke real-user leashes through the
      // demo endpoint, even if the caller knows a real jti.
      return {
        statusCode: 403,
        headers: corsHeaders,
        body: JSON.stringify({ error: 'this endpoint only revokes Demo Alice LEASHes' }),
      };
    }

    const now = Math.floor(Date.now() / 1000);
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_LEASH_ISSUED,
      Key: { jti: { S: jti } },
      UpdateExpression: 'SET revoked = :true, revoked_at = :now, #r = :reason',
      ExpressionAttributeNames: { '#r': 'reason' },
      ExpressionAttributeValues: marshall({
        ':true': true,
        ':now': now,
        ':reason': 'demo-revoke',
      }),
    }));

    return {
      statusCode: 200,
      headers: { ...corsHeaders, 'Cache-Control': 'no-store' },
      body: JSON.stringify({ jti, revoked: true, revoked_at: now, reason: 'demo-revoke' }),
    };
  } catch (err: unknown) {
    const m = err instanceof Error ? err.message : 'unknown';
    console.error('demoRevokeLeash failed', { jti, error: m });
    return { statusCode: 500, headers: corsHeaders, body: JSON.stringify({ error: 'revoke failed' }) };
  }
};
