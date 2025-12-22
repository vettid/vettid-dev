/**
 * POST /test/create-invitation
 *
 * Creates a test enrollment invitation programmatically.
 * Returns full QR data payload for direct use by Android tests.
 *
 * SECURITY: This endpoint requires a valid test API key.
 * Only deployed in non-production environments.
 */
import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, PutItemCommand, DeleteItemCommand, QueryCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import { randomBytes, randomUUID } from 'crypto';
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
const API_URL = process.env.API_URL || 'https://tiqpij5mue.execute-api.us-east-1.amazonaws.com';

// Test user prefix to identify test data
const TEST_USER_PREFIX = 'test_android_';

interface CreateInvitationRequest {
  test_user_id: string;
  expires_in_seconds?: number;
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
 * Generate a random invitation code
 */
function generateInvitationCode(): string {
  // Format: TEST-XXXX-XXXX-XXXX (easy to identify as test)
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // No confusing chars
  let code = 'TEST-';
  for (let i = 0; i < 12; i++) {
    if (i > 0 && i % 4 === 0) code += '-';
    code += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return code;
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
    const body = parseJsonBody<CreateInvitationRequest>(event);

    if (!body.test_user_id) {
      return badRequest('test_user_id is required', origin);
    }

    // Ensure test user ID has correct prefix
    const testUserId = body.test_user_id.startsWith(TEST_USER_PREFIX)
      ? body.test_user_id
      : `${TEST_USER_PREFIX}${body.test_user_id}`;

    // Validate test user ID format
    if (!/^test_android_[a-zA-Z0-9_-]+$/.test(testUserId)) {
      return badRequest('Invalid test_user_id format. Must be alphanumeric with underscores/hyphens.', origin);
    }

    const expiresInSeconds = body.expires_in_seconds || 3600; // Default 1 hour
    const now = new Date();
    const expiresAt = new Date(now.getTime() + expiresInSeconds * 1000);

    // Generate invitation code
    const invitationCode = generateInvitationCode();

    // Store invitation in DynamoDB
    await ddb.send(new PutItemCommand({
      TableName: TABLE_INVITES,
      Item: marshall({
        code: invitationCode,
        status: 'active',
        test_user_id: testUserId,
        is_test_invitation: true,
        created_at: now.toISOString(),
        expires_at: expiresAt.toISOString(),
        expires_at_ttl: Math.floor(expiresAt.getTime() / 1000),
        max_uses: 1,
        used: 0,
      }),
    }));

    // Build QR data payload (what would normally be in a QR code)
    const qrData = {
      type: 'vettid_enrollment',
      version: 1,
      invitation_code: invitationCode,
      api_url: API_URL,
      skip_attestation: true, // Test invitations always skip attestation
    };

    // Audit log
    await putAudit({
      type: 'test_invitation_created',
      test_user_id: testUserId,
      invitation_code: invitationCode.substring(0, 8) + '...',
      expires_in_seconds: expiresInSeconds,
    }, requestId);

    return ok({
      invitation_code: invitationCode,
      test_user_id: testUserId,
      qr_data: qrData,
      expires_at: expiresAt.toISOString(),
      api_url: API_URL,
      notes: {
        skip_attestation: 'Set skip_attestation: true in enroll/start request',
        device_type: 'Set device_type: "android" in enroll/start request',
        device_id: 'Can use any unique identifier for device_id',
      },
    }, origin);

  } catch (error: any) {
    console.error('Create invitation error:', error);
    return internalError('Failed to create test invitation', origin);
  }
};
