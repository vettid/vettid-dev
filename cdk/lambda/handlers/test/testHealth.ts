/**
 * GET /test/health
 *
 * Test environment health check endpoint.
 * Returns the status of test infrastructure components.
 *
 * SECURITY: This endpoint requires a valid test API key.
 * Only deployed in non-production environments.
 */
import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, DescribeTableCommand } from '@aws-sdk/client-dynamodb';
import { ok, forbidden, internalError } from '../../common/util';

const ddb = new DynamoDBClient({});

// Environment configuration
const TEST_API_KEY = process.env.TEST_API_KEY;
const TABLE_ENROLLMENT_SESSIONS = process.env.TABLE_ENROLLMENT_SESSIONS!;
const TABLE_TRANSACTION_KEYS = process.env.TABLE_TRANSACTION_KEYS!;
const TABLE_INVITES = process.env.TABLE_INVITES!;

/**
 * Validate test API key from request headers
 */
function validateTestApiKey(event: APIGatewayProxyEventV2): boolean {
  if (!TEST_API_KEY) {
    console.error('TEST_API_KEY not configured - test endpoints disabled');
    return false;
  }

  const apiKey = event.headers['x-test-api-key'] || event.headers['X-Test-Api-Key'];
  return apiKey === TEST_API_KEY;
}

export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const origin = event.headers?.origin;

  try {
    // Validate test API key
    if (!validateTestApiKey(event)) {
      return forbidden('Invalid or missing test API key', origin);
    }

    // Check table health
    const tableChecks: Record<string, { status: string; itemCount?: number }> = {};

    const tablesToCheck = [
      { name: 'enrollment_sessions', tableName: TABLE_ENROLLMENT_SESSIONS },
      { name: 'transaction_keys', tableName: TABLE_TRANSACTION_KEYS },
      { name: 'invites', tableName: TABLE_INVITES },
    ];

    for (const table of tablesToCheck) {
      try {
        const result = await ddb.send(new DescribeTableCommand({
          TableName: table.tableName,
        }));
        tableChecks[table.name] = {
          status: 'healthy',
          itemCount: result.Table?.ItemCount,
        };
      } catch (error) {
        tableChecks[table.name] = {
          status: 'unhealthy',
        };
      }
    }

    return ok({
      status: 'healthy',
      environment: 'test',
      timestamp: new Date().toISOString(),
      features: {
        mock_attestation_enabled: true,
        skip_attestation_available: true,
        test_user_prefix: 'test_android_',
      },
      tables: tableChecks,
    }, origin);

  } catch (error: any) {
    console.error('Health check error:', error);
    return internalError('Health check failed', origin);
  }
};
