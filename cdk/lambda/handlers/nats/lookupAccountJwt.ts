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
import { unmarshall } from '@aws-sdk/util-dynamodb';

const ddb = new DynamoDBClient({});

const TABLE_NATS_ACCOUNTS = process.env.TABLE_NATS_ACCOUNTS!;

export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  try {
    // Extract account public key from path
    // Path format: /nats/jwt/v1/accounts/{account_public_key}
    const accountPublicKey = event.pathParameters?.account_public_key;

    if (!accountPublicKey) {
      return {
        statusCode: 400,
        headers: { 'Content-Type': 'text/plain' },
        body: 'Missing account public key',
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
