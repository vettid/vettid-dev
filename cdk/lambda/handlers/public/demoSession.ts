import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, PutItemCommand, GetItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import { randomBytes } from 'crypto';

/**
 * Two handlers for the live-tester mode of the gamified LEASH demo:
 *
 *   POST /v1/public/leash/demo/session
 *     → { session_token, expires_at, poll_url }
 *     The page spins one of these so a tester can run
 *     `vettid-agent demo validate --session <token> ...` and watch
 *     the result appear in the page.
 *
 *   GET /v1/public/leash/demo/session/{token}
 *     → { session_token, results: [...], expires_at }
 *     Polled by the page every couple seconds while waiting on
 *     the agent's verify request.
 *
 * Results are appended by `verifyLeash.ts` when it sees an
 * `X-Demo-Session` request header — see that handler for the
 * insertion logic.
 *
 * No PII: sessions hold opaque tokens and verifier output only.
 */

const ddb = new DynamoDBClient({});
const TABLE = process.env.TABLE_LEASH_DEMO_SESSIONS!;
const SESSION_TTL_SECS = 30 * 60; // 30 minutes

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Content-Type': 'application/json',
};

export const createHandler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  if (event.requestContext.http.method === 'OPTIONS') {
    return { statusCode: 200, headers: corsHeaders, body: '' };
  }

  // Token: 16 bytes of randomness, base64url. ~22 chars; easy to
  // copy/paste into a CLI flag.
  const token = randomBytes(16).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const sessionToken = `ses_${token}`;
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + SESSION_TTL_SECS;

  try {
    await ddb.send(new PutItemCommand({
      TableName: TABLE,
      Item: marshall({
        session_token: sessionToken,
        created_at: now,
        expires_at: expiresAt,
        expires_at_ttl: expiresAt,
        results: [], // appended by verifyLeash.ts on each verify
      }, { removeUndefinedValues: true }),
    }));
  } catch (err: unknown) {
    const m = err instanceof Error ? err.message : 'unknown';
    console.error('createDemoSession failed', { error: m });
    return { statusCode: 500, headers: corsHeaders, body: JSON.stringify({ error: 'create failed' }) };
  }

  return {
    statusCode: 200,
    headers: { ...corsHeaders, 'Cache-Control': 'no-store' },
    body: JSON.stringify({
      session_token: sessionToken,
      expires_at: expiresAt,
      poll_url: `https://api.vettid.dev/v1/public/leash/demo/session/${sessionToken}`,
      cli_hint:
        `vettid-agent demo validate --session ${sessionToken} ` +
        `--validator https://api.vettid.dev --leash <jwt> --action <scope-token>`,
    }),
  };
};

export const getHandler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  if (event.requestContext.http.method === 'OPTIONS') {
    return { statusCode: 200, headers: corsHeaders, body: '' };
  }

  const token = event.pathParameters?.token;
  if (!token) {
    return { statusCode: 400, headers: corsHeaders, body: JSON.stringify({ error: 'missing token' }) };
  }

  try {
    const r = await ddb.send(new GetItemCommand({
      TableName: TABLE,
      Key: { session_token: { S: token } },
    }));
    if (!r.Item) {
      return { statusCode: 404, headers: corsHeaders, body: JSON.stringify({ error: 'session expired or not found' }) };
    }
    const row = unmarshall(r.Item);
    return {
      statusCode: 200,
      headers: { ...corsHeaders, 'Cache-Control': 'no-store' },
      body: JSON.stringify({
        session_token: row.session_token,
        created_at: row.created_at,
        expires_at: row.expires_at,
        results: row.results || [],
      }),
    };
  } catch (err: unknown) {
    const m = err instanceof Error ? err.message : 'unknown';
    console.error('getDemoSession failed', { token, error: m });
    return { statusCode: 500, headers: corsHeaders, body: JSON.stringify({ error: 'lookup failed' }) };
  }
};
