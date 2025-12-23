/**
 * NATS Account JWT Lookup
 *
 * This endpoint is called by the NATS server's URL resolver to fetch account JWTs.
 * When a user connects with credentials, NATS needs to verify their account exists.
 *
 * GET /nats/jwt/v1/accounts/{account_public_key}
 *
 * Returns: Raw account JWT (text/plain) or 404 if not found
 *
 * Security: This endpoint is called by NATS servers only (no user auth required).
 * The JWT itself is cryptographically signed by the operator.
 */

import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, QueryCommand } from '@aws-sdk/client-dynamodb';
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import { unmarshall } from '@aws-sdk/util-dynamodb';

const ddb = new DynamoDBClient({});
const secretsClient = new SecretsManagerClient({});

const TABLE_NATS_ACCOUNTS = process.env.TABLE_NATS_ACCOUNTS!;
const NATS_OPERATOR_SECRET_ARN = process.env.NATS_OPERATOR_SECRET_ARN || 'vettid/nats/operator-key';

// Cache for system account info (to avoid repeated Secrets Manager calls)
let cachedSystemAccountKey: string | null = null;
let cachedSystemAccountJwt: string | null = null;
let cacheTime = 0;
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

async function getSystemAccountInfo(): Promise<{ publicKey: string; jwt: string } | null> {
  const now = Date.now();
  if (cachedSystemAccountKey && cachedSystemAccountJwt && (now - cacheTime) < CACHE_TTL_MS) {
    return { publicKey: cachedSystemAccountKey, jwt: cachedSystemAccountJwt };
  }

  try {
    const response = await secretsClient.send(new GetSecretValueCommand({
      SecretId: NATS_OPERATOR_SECRET_ARN,
    }));

    if (!response.SecretString) {
      return null;
    }

    const secret = JSON.parse(response.SecretString);
    if (secret.system_account_public_key && secret.system_account_jwt) {
      cachedSystemAccountKey = secret.system_account_public_key;
      cachedSystemAccountJwt = secret.system_account_jwt;
      cacheTime = now;
      return { publicKey: secret.system_account_public_key, jwt: secret.system_account_jwt };
    }
  } catch (error) {
    console.error('Error fetching system account from Secrets Manager:', error);
  }
  return null;
}

export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  try {
    // Extract account public key from path
    // Path format: /nats/jwt/v1/accounts/{account_public_key}
    const accountPublicKey = event.pathParameters?.account_public_key;

    // Handle base URL request (NATS server validation on startup)
    // When no account key is provided, return 200 OK to indicate the resolver is operational
    if (!accountPublicKey) {
      return {
        statusCode: 200,
        headers: { 'Content-Type': 'text/plain' },
        body: 'ok',
      };
    }

    // Check if this is a request for the system account (stored in Secrets Manager)
    const systemAccount = await getSystemAccountInfo();
    if (systemAccount && accountPublicKey === systemAccount.publicKey) {
      console.log('Returning system account JWT');
      return {
        statusCode: 200,
        headers: {
          'Content-Type': 'text/plain',
          'Cache-Control': 'public, max-age=3600', // Cache for 1 hour
        },
        body: systemAccount.jwt,
      };
    }

    // Query by account public key using GSI
    const result = await ddb.send(new QueryCommand({
      TableName: TABLE_NATS_ACCOUNTS,
      IndexName: 'account-key-index',
      KeyConditionExpression: 'account_public_key = :pk',
      ExpressionAttributeValues: {
        ':pk': { S: accountPublicKey },
      },
      Limit: 1,
    }));

    if (!result.Items || result.Items.length === 0) {
      console.log(`Account not found: ${accountPublicKey.substring(0, 10)}...`);
      return {
        statusCode: 404,
        headers: { 'Content-Type': 'text/plain' },
        body: 'Account not found',
      };
    }

    const account = unmarshall(result.Items[0]);

    // Check account status
    if (account.status !== 'active') {
      console.log(`Account ${accountPublicKey.substring(0, 10)}... is ${account.status}`);
      return {
        statusCode: 403,
        headers: { 'Content-Type': 'text/plain' },
        body: 'Account is not active',
      };
    }

    // Return the raw JWT
    return {
      statusCode: 200,
      headers: {
        'Content-Type': 'text/plain',
        'Cache-Control': 'public, max-age=3600', // Cache for 1 hour
      },
      body: account.account_jwt,
    };
  } catch (error: any) {
    console.error('Error looking up account JWT:', error);
    return {
      statusCode: 500,
      headers: { 'Content-Type': 'text/plain' },
      body: 'Internal server error',
    };
  }
};
