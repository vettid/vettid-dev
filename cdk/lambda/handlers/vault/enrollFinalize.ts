import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, PutItemCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
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
import { generateAccountCredentials, generateBootstrapCredentials, formatCredsFile } from '../../common/nats-jwt';

const ddb = new DynamoDBClient({});

const TABLE_ENROLLMENT_SESSIONS = process.env.TABLE_ENROLLMENT_SESSIONS!;
const TABLE_INVITES = process.env.TABLE_INVITES!;
const TABLE_NATS_ACCOUNTS = process.env.TABLE_NATS_ACCOUNTS!;

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
    const validStates = ['PASSWORD_SET', 'STARTED'];
    if (!validStates.includes(session.status)) {
      // Provide helpful error message based on current state
      const stateMessages: Record<string, string> = {
        'WEB_INITIATED': 'Mobile app has not scanned the QR code yet',
        'AUTHENTICATED': 'App connected but enrollment not started',
        'NATS_CONNECTED': 'Waiting for enclave attestation verification',
        'ATTESTATION_VERIFIED': 'Waiting for PIN setup',
        'PIN_SET': 'Waiting for credential password setup',
        'COMPLETED': 'Enrollment already completed',
        'CANCELLED': 'Enrollment was cancelled',
      };
      const message = stateMessages[session.status] || `Invalid session status: ${session.status}`;
      return conflict(message, origin);
    }

    // Check session expiry
    if (new Date(session.expires_at) < new Date()) {
      return badRequest('Enrollment session has expired', origin);
    }

    const now = new Date();
    const userGuid = session.user_guid;

    // === NATS ACCOUNT SETUP ===
    // Create NATS account for mobile app communication with the vault.
    // The Nitro enclave is already running - no EC2 provisioning needed.
    // The vault-manager will create the Protean Credential when the app
    // calls app.bootstrap on its vault via NATS.
    const vaultStatus = 'ENCLAVE_READY';
    const ownerSpaceId = `OwnerSpace.${userGuid.replace(/-/g, '')}`;
    const messageSpaceId = `MessageSpace.${userGuid.replace(/-/g, '')}`;
    let bootstrapCredentials = '';
    let accountSeed: string;

    // Check if this user already has a NATS account (e.g., re-enrollment)
    const existingAccountResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_NATS_ACCOUNTS,
      Key: marshall({ user_guid: userGuid }),
    }));

    if (existingAccountResult.Item) {
      // Reusing existing account - use the existing seed for bootstrap credentials
      const existingAccount = unmarshall(existingAccountResult.Item);
      accountSeed = existingAccount.account_seed;
      console.log(`Re-enrollment with existing NATS account for user ${userGuid}`);
    } else {
      // New user - create NATS account
      const accountCredentials = await generateAccountCredentials(userGuid);
      accountSeed = accountCredentials.seed;

      await ddb.send(new PutItemCommand({
        TableName: TABLE_NATS_ACCOUNTS,
        Item: marshall({
          user_guid: userGuid,
          account_public_key: accountCredentials.publicKey,
          account_seed: accountCredentials.seed,
          account_jwt: accountCredentials.accountJwt,
          owner_space_id: ownerSpaceId,
          message_space_id: messageSpaceId,
          status: 'active',
          storage_type: 'enclave',
          created_at: now.toISOString(),
        }, { removeUndefinedValues: true }),
      }));

      console.log(`Created NATS account for user ${userGuid}`);
    }

    // Generate temporary bootstrap credentials for initial app connection
    // These have minimal permissions - just enough to call app.bootstrap
    // The vault-manager will generate full credentials after bootstrap
    const bootstrapCreds = await generateBootstrapCredentials(
      userGuid,
      accountSeed,
      ownerSpaceId
    );

    bootstrapCredentials = formatCredsFile(bootstrapCreds.jwt, bootstrapCreds.seed);

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
      // Vault bootstrap info - app uses these temporary credentials to call app.bootstrap
      // on the vault and receive:
      // 1. Full NATS credentials for vault communication
      // 2. The Protean Credential (created by vault-manager, stored in vault's JetStream)
      // Enclave is immediately available - no EC2 startup delay.
      vault_bootstrap: {
        credentials: bootstrapCredentials,
        owner_space: ownerSpaceId,
        message_space: messageSpaceId,
        nats_endpoint: `tls://${process.env.NATS_ENDPOINT || 'nats.vettid.dev:443'}`,
        bootstrap_topic: `${ownerSpaceId}.forVault.app.bootstrap`,
        response_topic: `${ownerSpaceId}.forApp.app.bootstrap.>`,
        credentials_ttl_seconds: 3600,
        estimated_ready_at: new Date().toISOString(),  // Enclave is immediately ready
      },
    }, origin);

  } catch (error: any) {
    console.error('Finalize enrollment error:', error);
    return internalError('Failed to finalize enrollment', origin);
  }
};
