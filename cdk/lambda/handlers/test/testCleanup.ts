/**
 * POST /test/cleanup
 *
 * Cleans up test user data.
 * Deletes all data associated with a test user.
 *
 * SECURITY: This endpoint requires a valid test API key.
 * Only deployed in non-production environments.
 */
import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import {
  DynamoDBClient,
  DeleteItemCommand,
  QueryCommand,
  ScanCommand,
} from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  forbidden,
  internalError,
  parseJsonBody,
  getRequestId,
  putAudit,
} from '../../common/util';

const ddb = new DynamoDBClient({});

// Environment configuration
const TEST_API_KEY = process.env.TEST_API_KEY;
const TABLE_INVITES = process.env.TABLE_INVITES!;
const TABLE_ENROLLMENT_SESSIONS = process.env.TABLE_ENROLLMENT_SESSIONS!;
const TABLE_NATS_ACCOUNTS = process.env.TABLE_NATS_ACCOUNTS!;
const TABLE_ACTION_TOKENS = process.env.TABLE_ACTION_TOKENS!;

// Test user prefix
const TEST_USER_PREFIX = 'test_android_';

interface CleanupRequest {
  test_user_id: string;
  cleanup_all_test_data?: boolean;
}

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

/**
 * Delete test invitations by scanning for test prefix
 */
async function deleteTestInvitations(testUserId?: string): Promise<number> {
  let deletedCount = 0;
  let lastEvaluatedKey: any = undefined;

  do {
    // Scan for test invitations
    const filterExpression = testUserId
      ? 'test_user_id = :userId OR begins_with(code, :testPrefix)'
      : 'is_test_invitation = :isTest OR begins_with(code, :testPrefix)';

    const expressionValues = testUserId
      ? { ':userId': testUserId, ':testPrefix': 'TEST-' }
      : { ':isTest': true, ':testPrefix': 'TEST-' };

    const scanResult = await ddb.send(new ScanCommand({
      TableName: TABLE_INVITES,
      FilterExpression: filterExpression,
      ExpressionAttributeValues: marshall(expressionValues),
      ExclusiveStartKey: lastEvaluatedKey,
    }));

    if (scanResult.Items && scanResult.Items.length > 0) {
      const items = scanResult.Items.map(item => unmarshall(item));

      for (const item of items) {
        await ddb.send(new DeleteItemCommand({
          TableName: TABLE_INVITES,
          Key: marshall({ code: item.code }),
        }));
        deletedCount++;
      }
    }

    lastEvaluatedKey = scanResult.LastEvaluatedKey;
  } while (lastEvaluatedKey);

  return deletedCount;
}

/**
 * Delete enrollment sessions for a user
 */
async function deleteEnrollmentSessions(userGuid: string): Promise<number> {
  let deletedCount = 0;
  let lastEvaluatedKey: any = undefined;

  do {
    // Scan for enrollment sessions (no GSI on user_guid for this table)
    const scanResult = await ddb.send(new ScanCommand({
      TableName: TABLE_ENROLLMENT_SESSIONS,
      FilterExpression: 'user_guid = :guid',
      ExpressionAttributeValues: marshall({ ':guid': userGuid }),
      ExclusiveStartKey: lastEvaluatedKey,
    }));

    if (scanResult.Items && scanResult.Items.length > 0) {
      const items = scanResult.Items.map(item => unmarshall(item));

      for (const item of items) {
        await ddb.send(new DeleteItemCommand({
          TableName: TABLE_ENROLLMENT_SESSIONS,
          Key: marshall({ session_id: item.session_id }),
        }));
        deletedCount++;
      }
    }

    lastEvaluatedKey = scanResult.LastEvaluatedKey;
  } while (lastEvaluatedKey);

  return deletedCount;
}

/**
 * Delete NATS account for a user (Nitro model)
 */
async function deleteNatsAccount(userGuid: string): Promise<number> {
  try {
    await ddb.send(new DeleteItemCommand({
      TableName: TABLE_NATS_ACCOUNTS,
      Key: marshall({ user_guid: userGuid }),
    }));
    return 1;
  } catch (e) {
    console.log('No NATS account to delete or error:', e);
    return 0;
  }
}

export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);
  const origin = event.headers?.origin;

  try {
    // Validate test API key
    if (!validateTestApiKey(event)) {
      return forbidden('Invalid or missing test API key', origin);
    }

    // Parse request body
    const body = parseJsonBody<CleanupRequest>(event);

    if (!body.test_user_id && !body.cleanup_all_test_data) {
      return badRequest('test_user_id is required (or set cleanup_all_test_data: true)', origin);
    }

    // Ensure test user ID has correct prefix (if provided)
    const testUserId = body.test_user_id
      ? (body.test_user_id.startsWith(TEST_USER_PREFIX)
        ? body.test_user_id
        : `${TEST_USER_PREFIX}${body.test_user_id}`)
      : undefined;

    // Validate test user ID format (must be test user)
    if (testUserId && !testUserId.startsWith(TEST_USER_PREFIX)) {
      return badRequest('Can only cleanup test users (prefix: test_android_)', origin);
    }

    const cleanupResults: Record<string, number> = {};

    if (body.cleanup_all_test_data) {
      // Cleanup ALL test data (dangerous but useful for test reset)
      cleanupResults.invitations = await deleteTestInvitations();
      // Note: Would need to scan all tables for test_ prefix - expensive operation
      console.log('Cleaned up all test invitations');
    } else if (testUserId) {
      // Cleanup specific test user
      cleanupResults.invitations = await deleteTestInvitations(testUserId);
      cleanupResults.enrollment_sessions = await deleteEnrollmentSessions(testUserId);

      // Delete NATS account (Nitro model - replaces legacy credential tables)
      cleanupResults.nats_accounts = await deleteNatsAccount(testUserId);
    }

    // Audit log
    await putAudit({
      type: 'test_cleanup',
      test_user_id: testUserId || 'all_test_data',
      cleanup_results: cleanupResults,
    }, requestId);

    return ok({
      status: 'cleaned',
      test_user_id: testUserId || 'all_test_data',
      deleted_items: cleanupResults,
    }, origin);

  } catch (error: any) {
    console.error('Cleanup error:', error);
    return internalError('Failed to cleanup test data', origin);
  }
};
