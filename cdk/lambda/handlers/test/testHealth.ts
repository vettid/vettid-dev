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
import { ok, forbidden, internalError, secureCompare } from '../../common/util';
import { loadTestApiKey } from '../../common/testApiKey';

const ddb = new DynamoDBClient({});

const TABLE_ENROLLMENT_SESSIONS = process.env.TABLE_ENROLLMENT_SESSIONS!;
const TABLE_NATS_ACCOUNTS = process.env.TABLE_NATS_ACCOUNTS!;
const TABLE_INVITES = process.env.TABLE_INVITES!;

/**
 * Validate test API key from request headers. The expected value is
 * loaded lazily from Secrets Manager on first call (cached per
 * container) — env var TEST_API_KEY_SECRET_ARN points at the secret.
 */
async function validateTestApiKey(event: APIGatewayProxyEventV2): Promise<boolean> {
  const expected = await loadTestApiKey();
  if (!expected) {
    console.error('test api key not configured or unreadable - test endpoints disabled');
    return false;
  }

  const apiKey = event.headers['x-test-api-key'] || event.headers['X-Test-Api-Key'];
  if (!apiKey) return false;
  // SECURITY: constant-time compare prevents an attacker from
  // inferring the test API key one byte at a time via timing.
  return secureCompare(apiKey, expected);
}

export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const origin = event.headers?.origin;

  try {
    // Validate test API key
    if (!(await validateTestApiKey(event))) {
      return forbidden('Invalid or missing test API key', origin);
    }

    // Check table health
    const tableChecks: Record<string, { status: string; itemCount?: number }> = {};

    const tablesToCheck = [
      { name: 'enrollment_sessions', tableName: TABLE_ENROLLMENT_SESSIONS },
      { name: 'nats_accounts', tableName: TABLE_NATS_ACCOUNTS },
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
        nitro_model: true,  // Using Nitro enclave architecture
      },
      tables: tableChecks,
    }, origin);

  } catch (error: any) {
    console.error('Health check error:', error);
    return internalError('Health check failed', origin);
  }
};
