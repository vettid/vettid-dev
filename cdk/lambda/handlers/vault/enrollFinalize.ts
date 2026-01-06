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
  generateSecureId,
  checkRateLimit,
  hashIdentifier,
  tooManyRequests,
} from '../../common/util';
import { generateAccountCredentials, generateBootstrapCredentials, formatCredsFile } from '../../common/nats-jwt';
import { generateLAT, hashLATToken } from '../../common/crypto-keys';
import { requestCredentialCreate } from '../../common/enclave-client';

const ddb = new DynamoDBClient({});

const TABLE_ENROLLMENT_SESSIONS = process.env.TABLE_ENROLLMENT_SESSIONS!;
const TABLE_INVITES = process.env.TABLE_INVITES!;
const TABLE_CREDENTIALS = process.env.TABLE_CREDENTIALS!;
const TABLE_CREDENTIAL_KEYS = process.env.TABLE_CREDENTIAL_KEYS!;
const TABLE_LEDGER_AUTH_TOKENS = process.env.TABLE_LEDGER_AUTH_TOKENS!;
const TABLE_TRANSACTION_KEYS = process.env.TABLE_TRANSACTION_KEYS!;
const TABLE_NATS_ACCOUNTS = process.env.TABLE_NATS_ACCOUNTS!;
// NATS_CA_SECRET_ARN no longer needed - NLB terminates TLS with ACM (publicly trusted)

// Rate limiting: 3 finalize attempts per session per 15 minutes
const RATE_LIMIT_MAX_REQUESTS = 3;
const RATE_LIMIT_WINDOW_MINUTES = 15;

interface FinalizeRequest {
  enrollment_session_id?: string;  // Optional if using authorizer context
}

/**
 * POST /vault/enroll/finalize
 *
 * Finalize enrollment and create the credential.
 * Generates CEK, encrypts credential blob, creates LAT.
 *
 * Supports two flows:
 * 1. QR Code Flow: session_id comes from enrollment JWT (authorizer context)
 * 2. Direct Flow: enrollment_session_id in request body
 *
 * Returns:
 * - status: 'enrolled'
 * - credential_package with encrypted_blob, cek_version, lat, and remaining transaction_keys
 * - vault_status
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

    // Validate session state
    if (session.status !== 'STARTED') {
      return conflict(`Invalid session status: ${session.status}`, origin);
    }

    if (session.step !== 'password_set') {
      return conflict('Password must be set before finalizing enrollment', origin);
    }

    // Check session expiry
    if (new Date(session.expires_at) < new Date()) {
      return badRequest('Enrollment session has expired', origin);
    }

    const now = new Date();
    const userGuid = session.user_guid;

    // Generate LAT (Ledger Auth Token)
    console.log('DEBUG: Starting LAT generation');
    const lat = generateLAT(1);
    const latTokenHash = hashLATToken(lat.token);
    console.log('DEBUG: LAT generated, storing to DynamoDB');

    await ddb.send(new PutItemCommand({
      TableName: TABLE_LEDGER_AUTH_TOKENS,
      Item: marshall({
        token: latTokenHash,  // Primary key - store hash as the key
        user_guid: userGuid,
        version: lat.version,
        status: 'ACTIVE',
        created_at: now.toISOString(),
      }, { removeUndefinedValues: true }),
    }));
    console.log('DEBUG: LAT stored successfully');

    // Get remaining unused transaction keys
    const unusedKeysResult = await ddb.send(new QueryCommand({
      TableName: TABLE_TRANSACTION_KEYS,
      IndexName: 'user-index',
      KeyConditionExpression: 'user_guid = :user_guid',
      FilterExpression: '#status = :status',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':user_guid': userGuid,
        ':status': 'UNUSED',
      }),
    }));

    const remainingKeys = (unusedKeysResult.Items || []).map(item => {
      const key = unmarshall(item);
      return {
        key_id: key.key_id,
        public_key: key.public_key,
        algorithm: key.algorithm,
      };
    });

    // ============================================
    // ENCLAVE CREDENTIAL CREATION
    // ============================================
    // The enclave creates a sealed credential that only it can unseal.
    // Mobile encrypted auth data to the enclave's public key during set-password step.

    const credentialId = generateSecureId('cred', 16);

    // Get the encrypted auth data from the session
    const encryptedAuth = Buffer.from(session.encrypted_password_hash, 'base64');

    // Determine auth type from session
    const authType = session.auth_type || 'password';

    // Request credential creation from enclave
    const enclaveResult = await requestCredentialCreate(
      userGuid,
      encryptedAuth,
      authType as 'pin' | 'password' | 'pattern'
    );

    // Store credential metadata (enclave manages the actual keys)
    const credentialItem: Record<string, any> = {
      user_guid: userGuid,
      credential_id: credentialId,
      status: 'ACTIVE',
      storage_type: 'enclave',
      lat_version: lat.version,
      created_at: now.toISOString(),
      last_action_at: now.toISOString(),
      failed_auth_count: 0,
    };

    // Add optional fields only if they exist
    if (session.device_id) {
      credentialItem.device_id = session.device_id;
    }
    if (enclaveResult.public_key) {
      credentialItem.enclave_public_key = enclaveResult.public_key;
    }
    if (session.invitation_code) {
      credentialItem.invitation_code = session.invitation_code;
    }

    console.log('DEBUG: Storing credential to DynamoDB, item:', JSON.stringify(credentialItem));
    await ddb.send(new PutItemCommand({
      TableName: TABLE_CREDENTIALS,
      Item: marshall(credentialItem, { removeUndefinedValues: true }),
    }));
    console.log('DEBUG: Credential stored successfully');

    // Build credential package
    const credentialPackage: Record<string, any> = {
      user_guid: userGuid,
      credential_id: credentialId,
      sealed_credential: enclaveResult.sealed_credential,
      ledger_auth_token: {
        token: lat.token,
        version: lat.version,
      },
      transaction_keys: remainingKeys,
    };

    // Add optional enclave fields if present
    if (enclaveResult.public_key) {
      credentialPackage.enclave_public_key = enclaveResult.public_key;
    }
    if (enclaveResult.backup_key) {
      credentialPackage.backup_key = enclaveResult.backup_key;
    }

    console.log(`Created enclave credential for user ${userGuid}`);

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
      lat_version: lat.version,
      transaction_keys_remaining: remainingKeys.length,
    }, requestId);

    // === NATS ACCOUNT SETUP ===
    // Create NATS account for mobile app communication with the enclave.
    // The Nitro enclave is already running - no EC2 provisioning needed.
    const vaultStatus = 'ENCLAVE_READY';
    let ownerSpaceId = '';
    let messageSpaceId = '';
    let bootstrapCredentials = '';

    try {
      ownerSpaceId = `OwnerSpace.${userGuid.replace(/-/g, '')}`;
      messageSpaceId = `MessageSpace.${userGuid.replace(/-/g, '')}`;

      // Check if this user already has a NATS account (e.g., re-enrollment)
      const existingAccountResult = await ddb.send(new GetItemCommand({
        TableName: TABLE_NATS_ACCOUNTS,
        Key: marshall({ user_guid: userGuid }),
      }));

      let accountSeed: string;

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
      const bootstrapCreds = await generateBootstrapCredentials(
        userGuid,
        accountSeed,
        ownerSpaceId
      );

      bootstrapCredentials = formatCredsFile(bootstrapCreds.jwt, bootstrapCreds.seed);

    } catch (provisionError: any) {
      // Non-fatal: enrollment succeeded, but NATS account creation failed
      console.warn('NATS account setup failed (non-fatal):', provisionError.message);
    }

    return ok({
      status: 'enrolled',
      credential_package: credentialPackage,
      vault_status: vaultStatus,
      // Vault bootstrap info - app uses these temporary credentials to call app.bootstrap
      // on the vault and receive full NATS credentials generated by the vault.
      // Enclave is immediately available - no EC2 startup delay.
      vault_bootstrap: bootstrapCredentials ? {
        credentials: bootstrapCredentials,
        owner_space: ownerSpaceId,
        message_space: messageSpaceId,
        nats_endpoint: `tls://${process.env.NATS_ENDPOINT || 'nats.vettid.dev:443'}`,
        bootstrap_topic: `${ownerSpaceId}.forVault.app.bootstrap`,
        response_topic: `${ownerSpaceId}.forApp.app.bootstrap.>`,
        credentials_ttl_seconds: 3600,
        estimated_ready_at: new Date().toISOString(),  // Enclave is immediately ready
      } : undefined,
    }, origin);

  } catch (error: any) {
    console.error('Finalize enrollment error:', error);
    return internalError('Failed to finalize enrollment', origin);
  }
};
