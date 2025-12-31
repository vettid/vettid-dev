/**
 * POST /test/create-invitation
 *
 * Creates a test enrollment invitation programmatically.
 * Returns full QR data payload for direct use by Android tests.
 *
 * This endpoint creates BOTH:
 * 1. An invitation code (for backwards compatibility)
 * 2. A proper enrollment session with session_token (for Android app compatibility)
 *
 * Request body:
 * - test_user_id (required): Identifier for the test user
 * - expires_in_seconds (optional): Invitation expiry, default 3600 (1 hour)
 * - user_guid (optional): Reuse an existing user_guid that has a vault provisioned.
 *   This enables full end-to-end testing without provisioning new EC2 instances.
 *
 * The Android app can use the standard flow:
 * 1. Parse QR data with session_token
 * 2. Call /vault/enroll/authenticate
 * 3. Get enrollment JWT
 * 4. Continue with normal enrollment flow
 *
 * For full bootstrap flow testing, pass user_guid of an existing vault user:
 * {
 *   "test_user_id": "my_test",
 *   "user_guid": "user-29680995BC4D4AE19F5B8F046D140005"
 * }
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
  generateSecureId,
} from '../../common/util';

const ddb = new DynamoDBClient({});

// Environment configuration
const TEST_API_KEY = process.env.TEST_API_KEY;
const TABLE_INVITES = process.env.TABLE_INVITES!;
const TABLE_ENROLLMENT_SESSIONS = process.env.TABLE_ENROLLMENT_SESSIONS!;
const API_URL = process.env.API_URL || 'https://tiqpij5mue.execute-api.us-east-1.amazonaws.com';

// Test user prefix to identify test data
const TEST_USER_PREFIX = 'test_android_';

interface CreateInvitationRequest {
  test_user_id: string;
  expires_in_seconds?: number;
  // Optional: reuse an existing user_guid that has a vault provisioned
  // This enables testing the full bootstrap flow without provisioning new vaults
  user_guid?: string;
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

    // Use provided user_guid or generate a new one
    // When reusing an existing user_guid with a provisioned vault, this enables
    // full end-to-end testing without needing to provision new EC2 instances
    const userGuid = body.user_guid || generateSecureId('user', 32);
    const isReusingVault = !!body.user_guid;
    const sessionId = generateSecureId('enroll', 32);
    const sessionToken = generateSecureId('est', 48); // Enrollment Session Token
    const nowMs = now.getTime();
    const expiresAtMs = expiresAt.getTime();

    // Store invitation in DynamoDB
    await ddb.send(new PutItemCommand({
      TableName: TABLE_INVITES,
      Item: marshall({
        code: invitationCode,
        status: 'active',
        test_user_id: testUserId,
        user_guid: userGuid,  // Link invitation to generated user
        is_test_invitation: true,
        created_at: now.toISOString(),
        expires_at: expiresAt.toISOString(),
        expires_at_ttl: Math.floor(expiresAtMs / 1000),
        max_uses: 1,
        used: 0,
      }),
    }));

    // Create enrollment session (mimics createEnrollmentSession.ts)
    // This allows Android to use the standard session_token → authenticate → JWT flow
    await ddb.send(new PutItemCommand({
      TableName: TABLE_ENROLLMENT_SESSIONS,
      Item: marshall({
        session_id: sessionId,
        session_token: sessionToken,
        user_guid: userGuid,
        user_email: `${testUserId}@test.vettid.dev`,
        status: 'WEB_INITIATED',  // Same status as web-initiated enrollment
        step: 'awaiting_mobile',
        is_test_session: true,
        test_user_id: testUserId,
        invitation_code: invitationCode,
        skip_attestation: true,  // Test sessions skip attestation
        created_at: nowMs,  // Number for GSI compatibility
        created_at_iso: now.toISOString(),
        expires_at: expiresAtMs,  // Number for GSI compatibility
        expires_at_iso: expiresAt.toISOString(),
        ttl: Math.floor(expiresAtMs / 1000),
      }),
    }));

    // Build QR data payload (matches what Android expects)
    // Includes BOTH session_token (for standard flow) and invitation_code (for direct flow)
    const qrData = {
      type: 'vettid_enrollment',
      version: 1,
      api_url: API_URL,
      // Standard Android flow fields:
      session_token: sessionToken,
      user_guid: userGuid,
      // Direct flow field (for backwards compatibility):
      invitation_code: invitationCode,
      // Test-specific flag:
      skip_attestation: true,
    };

    // Audit log
    await putAudit({
      type: 'test_invitation_created',
      test_user_id: testUserId,
      user_guid: userGuid,
      session_id: sessionId,
      invitation_code: invitationCode.substring(0, 8) + '...',
      expires_in_seconds: expiresInSeconds,
      reusing_vault: isReusingVault,
    }, requestId);

    return ok({
      // Primary fields for Android:
      session_token: sessionToken,
      user_guid: userGuid,
      enrollment_session_id: sessionId,
      // Also include invitation_code for direct flow:
      invitation_code: invitationCode,
      test_user_id: testUserId,
      // QR data (what would be in a scanned QR code):
      qr_data: qrData,
      expires_at: expiresAt.toISOString(),
      api_url: API_URL,
      // Vault reuse info:
      reusing_existing_vault: isReusingVault,
      notes: {
        android_flow: 'Use session_token with /vault/enroll/authenticate to get JWT',
        direct_flow: 'Use invitation_code with /vault/enroll/start-direct (no auth needed)',
        skip_attestation: 'Test sessions automatically skip attestation verification',
        vault_reuse: isReusingVault
          ? 'Using existing vault - full bootstrap flow will work'
          : 'New user_guid - vault must be provisioned separately for bootstrap to work',
      },
    }, origin);

  } catch (error: any) {
    console.error('Create invitation error:', error);
    return internalError('Failed to create test invitation', origin);
  }
};
