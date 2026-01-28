import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, PutItemCommand, UpdateItemCommand, QueryCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  notFound,
  conflict,
  internalError,
  getRequestId,
  putAudit,
  checkRateLimit,
  hashIdentifier,
  tooManyRequests,
} from '../../common/util';
// Note: generateBootstrapCredentials removed - app uses credentials from enrollNatsBootstrap

const ddb = new DynamoDBClient({});

const TABLE_ENROLLMENT_SESSIONS = process.env.TABLE_ENROLLMENT_SESSIONS!;
const TABLE_INVITES = process.env.TABLE_INVITES!;
const TABLE_NATS_ACCOUNTS = process.env.TABLE_NATS_ACCOUNTS!;
const TABLE_REGISTRATIONS = process.env.TABLE_REGISTRATIONS!;

// SECURITY: Require device attestation before finalization
// Set to 'true' in production to enforce hardware-backed attestation
const REQUIRE_DEVICE_ATTESTATION = process.env.REQUIRE_DEVICE_ATTESTATION === 'true';

// Rate limiting: 3 finalize attempts per session per 15 minutes
const RATE_LIMIT_MAX_REQUESTS = 3;
const RATE_LIMIT_WINDOW_MINUTES = 15;

interface FinalizeRequest {
  enrollment_session_id?: string;  // Optional if using authorizer context
}

/**
 * POST /vault/enroll/finalize
 *
 * Finalize enrollment and set up vault access.
 * Creates NATS account and returns bootstrap credentials.
 *
 * The actual Protean Credential is created by the vault-manager when
 * the mobile app calls app.bootstrap on its vault via NATS.
 *
 * Supports two flows:
 * 1. QR Code Flow: session_id comes from enrollment JWT (authorizer context)
 * 2. Direct Flow: enrollment_session_id in request body
 *
 * Returns:
 * - status: 'enrolled'
 * - vault_bootstrap: NATS credentials and topics for app to connect to vault
 * - vault_status: 'ENCLAVE_READY'
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);
  const origin = event.headers?.origin;

  try {
    // Check for authorizer context (QR code flow)
    // The authorizer property exists but isn't in the base type definition
    const authContext = (event.requestContext as any)?.authorizer?.lambda as {
      userGuid?: string;
      sessionId?: string;
    } | undefined;

    // Parse body - may be empty for QR code flow where session comes from authorizer
    let body: FinalizeRequest = {};
    if (event.body) {
      try {
        body = JSON.parse(event.body) as FinalizeRequest;
      } catch {
        return badRequest('Invalid JSON in request body', origin);
      }
    }

    // Get session_id from authorizer context or request body
    const sessionId = authContext?.sessionId || body.enrollment_session_id;

    if (!sessionId) {
      return badRequest('enrollment_session_id is required', origin);
    }

    // Rate limiting by session ID (prevents replay attacks)
    const sessionHash = hashIdentifier(sessionId);
    const isAllowed = await checkRateLimit(sessionHash, 'enroll_finalize', RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_MINUTES);
    if (!isAllowed) {
      return tooManyRequests('Too many finalize attempts. Please try again later.', origin);
    }

    // Get enrollment session
    const sessionResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_ENROLLMENT_SESSIONS,
      Key: marshall({ session_id: sessionId }),
    }));

    if (!sessionResult.Item) {
      return notFound('Enrollment session not found', origin);
    }

    const session = unmarshall(sessionResult.Item);

    // If using authorizer context, verify user_guid matches
    if (authContext?.userGuid && session.user_guid !== authContext.userGuid) {
      return badRequest('Session does not belong to authenticated user', origin);
    }

    // Validate session state - must have completed NATS-based enrollment phases
    // PASSWORD_SET means vault-manager has confirmed credential creation via NATS
    // STARTED is also accepted for backwards compatibility
    // AUTHENTICATED is accepted for NATS-based flow where enrollment happens entirely via NATS
    const validStates = ['PASSWORD_SET', 'STARTED', 'AUTHENTICATED'];
    if (!validStates.includes(session.status)) {
      // Provide helpful error message based on current state
      const stateMessages: Record<string, string> = {
        'WEB_INITIATED': 'Mobile app has not scanned the QR code yet',
        'DEVICE_ATTESTED': 'Device attested but enrollment not started',
        'NATS_CONNECTED': 'Waiting for enclave attestation verification',
        'ATTESTATION_VERIFIED': 'Waiting for PIN setup',
        'PIN_SET': 'Waiting for credential password setup',
        'COMPLETED': 'Enrollment already completed',
        'CANCELLED': 'Enrollment was cancelled',
      };
      const message = stateMessages[session.status] || `Invalid session status: ${session.status}`;
      return conflict(message, origin);
    }

    // SECURITY: Verify device attestation was completed (if required)
    // This prevents enrollment token exfiltration - even if an attacker steals
    // the enrollment JWT, they cannot complete enrollment without passing
    // device attestation from the same device
    if (REQUIRE_DEVICE_ATTESTATION) {
      if (!session.device_attestation_verified) {
        await putAudit({
          type: 'enrollment_finalize_failed',
          reason: 'device_attestation_required',
          session_id: sessionId,
          user_guid: session.user_guid,
        }, requestId);
        return conflict('Device attestation required. Call /vault/enroll/device-attestation first.', origin);
      }

      // Log the attestation binding for audit trail
      console.log('Enrollment finalize with attestation binding:', {
        session_id: sessionId,
        attestation_hash: session.device_attestation_hash?.substring(0, 16) + '...',
        attestation_type: session.device_attestation_type,
      });
    }

    // Check session expiry
    if (new Date(session.expires_at) < new Date()) {
      return badRequest('Enrollment session has expired', origin);
    }

    const now = new Date();
    const userGuid = session.user_guid;

    // === FETCH REGISTRATION PROFILE ===
    // Get user's registration data (firstName, lastName, email) to include in response
    // This allows the mobile app to populate the profile during enrollment
    let registrationProfile: { firstName: string; lastName: string; email: string } | null = null;
    try {
      const registrationResult = await ddb.send(new QueryCommand({
        TableName: TABLE_REGISTRATIONS,
        IndexName: 'user-guid-index',
        KeyConditionExpression: 'user_guid = :user_guid',
        ExpressionAttributeValues: marshall({
          ':user_guid': userGuid,
        }),
        Limit: 1,
      }));

      if (registrationResult.Items && registrationResult.Items.length > 0) {
        const registration = unmarshall(registrationResult.Items[0]);
        registrationProfile = {
          firstName: registration.first_name || '',
          lastName: registration.last_name || '',
          email: registration.email || '',
        };
        console.log(`Fetched registration profile for user ${userGuid}`);
      } else {
        console.log(`No registration found for user ${userGuid}`);
      }
    } catch (error) {
      // Log but don't fail enrollment if profile fetch fails
      console.warn('Failed to fetch registration profile:', error);
    }

    // === NATS ACCOUNT ACTIVATION ===
    // The NATS account should already exist (created by enrollNatsBootstrap)
    // with status='enrolling'. We transition it to 'active' here.
    //
    // SECURITY: This is the only place where accounts become 'active'.
    // This ensures enrollment must complete fully before the account is usable.
    const vaultStatus = 'ENCLAVE_READY';

    const existingAccountResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_NATS_ACCOUNTS,
      Key: marshall({ user_guid: userGuid }),
    }));

    if (!existingAccountResult.Item) {
      // NATS account should have been created by enrollNatsBootstrap
      return badRequest('Enrollment not properly initialized. Please restart enrollment.', origin);
    }

    const existingAccount = unmarshall(existingAccountResult.Item);
    const ownerSpaceId = existingAccount.owner_space_id;
    const messageSpaceId = existingAccount.message_space_id;

    // Validate account status
    if (existingAccount.status === 'active') {
      // Already active - this is a re-finalize (idempotent)
      console.log(`Account already active for user ${userGuid}`);
    } else if (existingAccount.status === 'enrolling') {
      // Transition from 'enrolling' to 'active' and remove TTL
      await ddb.send(new UpdateItemCommand({
        TableName: TABLE_NATS_ACCOUNTS,
        Key: marshall({ user_guid: userGuid }),
        UpdateExpression: 'SET #status = :active, activated_at = :now REMOVE enrollment_ttl',
        ExpressionAttributeNames: {
          '#status': 'status',
        },
        ExpressionAttributeValues: marshall({
          ':active': 'active',
          ':now': now.toISOString(),
        }),
      }));
      console.log(`Activated NATS account for user ${userGuid}`);
    } else {
      // Unexpected status
      return conflict(`Cannot finalize enrollment: account status is '${existingAccount.status}'`, origin);
    }

    // NOTE: App already has NATS credentials from enrollNatsBootstrap.
    // Those credentials include permissions for forVault.> and forApp.> topics,
    // which is sufficient for the bootstrap call.
    // No separate bootstrap credentials are generated here.

    // Mark session as completed
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_ENROLLMENT_SESSIONS,
      Key: marshall({ session_id: sessionId }),
      UpdateExpression: 'SET #status = :status, completed_at = :completed_at',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':status': 'COMPLETED',
        ':completed_at': now.toISOString(),
      }),
    }));

    // Mark invitation as used (only if there is one - QR code flow may not have invitation)
    if (session.invitation_code) {
      await ddb.send(new UpdateItemCommand({
        TableName: TABLE_INVITES,
        Key: marshall({ code: session.invitation_code }),
        UpdateExpression: 'SET #status = :status, used_at = :used_at, used_by_guid = :user_guid',
        ExpressionAttributeNames: {
          '#status': 'status',
        },
        ExpressionAttributeValues: marshall({
          ':status': 'used',
          ':used_at': now.toISOString(),
          ':user_guid': userGuid,
        }),
      }));
    }

    // Update registration vault_status to indicate enrollment is complete
    // This is used by the account portal to show the correct status
    if (registrationProfile) {
      try {
        // Find and update the registration by user_guid
        const regResult = await ddb.send(new QueryCommand({
          TableName: TABLE_REGISTRATIONS,
          IndexName: 'user-guid-index',
          KeyConditionExpression: 'user_guid = :user_guid',
          ExpressionAttributeValues: marshall({ ':user_guid': userGuid }),
          ProjectionExpression: 'registration_id',
          Limit: 1,
        }));

        if (regResult.Items && regResult.Items.length > 0) {
          const registration = unmarshall(regResult.Items[0]);
          await ddb.send(new UpdateItemCommand({
            TableName: TABLE_REGISTRATIONS,
            Key: marshall({ registration_id: registration.registration_id }),
            UpdateExpression: 'SET vault_status = :vault_status, enrollment_completed_at = :completed_at',
            ExpressionAttributeValues: marshall({
              ':vault_status': vaultStatus,
              ':completed_at': now.toISOString(),
            }),
          }));
          console.log(`Updated registration vault_status to ${vaultStatus} for user ${userGuid}`);
        }
      } catch (regError) {
        // Log but don't fail enrollment if registration update fails
        console.warn('Failed to update registration vault_status:', regError);
      }
    }

    // Audit log
    await putAudit({
      type: 'enrollment_completed',
      user_guid: userGuid,
      session_id: sessionId,
      storage_type: 'enclave',
      nats_account_created: !existingAccountResult.Item,
    }, requestId);

    return ok({
      status: 'enrolled',
      vault_status: vaultStatus,
      // Registration profile data for mobile app to store locally
      // Contains the system fields from registration (read-only in profile)
      registration_profile: registrationProfile,
      // Vault bootstrap info - app uses credentials from enrollNatsBootstrap to call app.bootstrap
      // on the vault and receive:
      // 1. Full NATS credentials for vault communication
      // 2. The Protean Credential (created by vault-manager, stored in vault's JetStream)
      // Enclave is immediately available - no EC2 startup delay.
      vault_bootstrap: {
        // NOTE: credentials removed - app uses credentials from enrollNatsBootstrap
        owner_space: ownerSpaceId,
        message_space: messageSpaceId,
        nats_endpoint: `tls://${process.env.NATS_ENDPOINT || 'nats.vettid.dev:443'}`,
        bootstrap_topic: `${ownerSpaceId}.forVault.app.bootstrap`,
        response_topic: `${ownerSpaceId}.forApp.app.bootstrap.>`,
        estimated_ready_at: new Date().toISOString(),  // Enclave is immediately ready
      },
    }, origin);

  } catch (error: any) {
    console.error('Finalize enrollment error:', error);
    return internalError('Failed to finalize enrollment', origin);
  }
};
