import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, PutItemCommand, UpdateItemCommand, QueryCommand } from '@aws-sdk/client-dynamodb';
// SecretsManagerClient no longer needed - NLB terminates TLS with ACM (publicly trusted)
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
// crypto module imported via common/crypto
import {
  ok,
  badRequest,
  notFound,
  conflict,
  internalError,
  getRequestId,
  putAudit,
  generateSecureId,
  addMinutesIso,
} from '../../common/util';
import { generateAccountCredentials, generateBootstrapCredentials, formatCredsFile } from '../../common/nats-jwt';
import { triggerVaultProvisioning } from '../../common/vault-provisioner';
import {
  generateX25519KeyPair,
  encryptCredentialBlob,
  decryptWithTransactionKey,
  deserializeEncryptedBlob,
  serializeEncryptedBlob,
  generateLAT,
  hashLATToken,
} from '../../common/crypto-keys';

const ddb = new DynamoDBClient({});

const TABLE_ENROLLMENT_SESSIONS = process.env.TABLE_ENROLLMENT_SESSIONS!;
const TABLE_INVITES = process.env.TABLE_INVITES!;
const TABLE_CREDENTIALS = process.env.TABLE_CREDENTIALS!;
const TABLE_CREDENTIAL_KEYS = process.env.TABLE_CREDENTIAL_KEYS!;
const TABLE_LEDGER_AUTH_TOKENS = process.env.TABLE_LEDGER_AUTH_TOKENS!;
const TABLE_TRANSACTION_KEYS = process.env.TABLE_TRANSACTION_KEYS!;
const TABLE_NATS_ACCOUNTS = process.env.TABLE_NATS_ACCOUNTS!;
// NATS_CA_SECRET_ARN no longer needed - NLB terminates TLS with ACM (publicly trusted)

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

    // Generate CEK (Credential Encryption Key)
    const cekKeyPair = generateX25519KeyPair();
    const cekVersion = 1;
    const credentialKeyId = generateSecureId('cek', 16);

    // Store CEK private key (encrypted at rest by DynamoDB)
    await ddb.send(new PutItemCommand({
      TableName: TABLE_CREDENTIAL_KEYS,
      Item: marshall({
        credential_id: credentialKeyId,  // Primary key
        user_guid: userGuid,
        version: cekVersion,
        private_key: cekKeyPair.privateKey.toString('base64'),
        public_key: cekKeyPair.publicKey.toString('base64'),
        algorithm: 'X25519',
        status: 'ACTIVE',
        created_at: now.toISOString(),
      }),
    }));

    // Generate LAT (Ledger Auth Token) using crypto utilities
    const lat = generateLAT(1);
    const latTokenHash = hashLATToken(lat.token);

    await ddb.send(new PutItemCommand({
      TableName: TABLE_LEDGER_AUTH_TOKENS,
      Item: marshall({
        token: latTokenHash,  // Primary key - store hash as the key
        user_guid: userGuid,
        version: lat.version,
        status: 'ACTIVE',
        created_at: now.toISOString(),
      }),
    }));

    // Decrypt password hash from session using the transaction key
    // The mobile app encrypted the password with a UTK during set-password step
    let decryptedPasswordHash: string;
    try {
      // Get the LTK (Ledger Transaction Key - private key) that was used
      // Note: table uses transaction_id as PK (same value as key_id)
      const ltkResult = await ddb.send(new GetItemCommand({
        TableName: TABLE_TRANSACTION_KEYS,
        Key: marshall({
          transaction_id: session.password_key_id,
        }),
      }));

      if (!ltkResult.Item) {
        return badRequest('Transaction key not found for password decryption', origin);
      }

      const ltk = unmarshall(ltkResult.Item);
      const ltkPrivateKey = Buffer.from(ltk.private_key, 'base64');

      // Deserialize and decrypt the password hash
      const encryptedPassword = deserializeEncryptedBlob({
        ciphertext: session.encrypted_password_hash,
        nonce: session.password_nonce,
        ephemeral_public_key: session.password_ephemeral_key || session.ephemeral_public_key,
      });

      const decryptedBuffer = decryptWithTransactionKey(encryptedPassword, ltkPrivateKey);
      decryptedPasswordHash = decryptedBuffer.toString('utf-8');
    } catch (decryptError) {
      console.error('Failed to decrypt password hash:', decryptError);
      // Fall back to storing as-is if decryption fails (legacy format)
      decryptedPasswordHash = session.encrypted_password_hash;
    }

    // Create credential data structure
    const credentialData = {
      guid: userGuid,
      version: 1,
      created_at: now.toISOString(),
      password_hash: decryptedPasswordHash,  // Decrypted hash from enrollment
      hash_algorithm: 'pbkdf2-sha256',  // Or 'argon2id' in production
      policies: {
        cache_period: 3600,
        require_biometric: false,
        max_attempts: 3,
      },
      secrets: {},
    };

    // Encrypt credential blob with CEK using proper ECIES
    const credentialJson = JSON.stringify(credentialData);
    const encryptedBlobData = encryptCredentialBlob(
      Buffer.from(credentialJson, 'utf-8'),
      cekKeyPair.publicKey  // Use PUBLIC key for encryption
    );

    // Serialize the encrypted blob for transmission
    const serializedBlob = serializeEncryptedBlob(encryptedBlobData);

    // Store credential metadata
    const credentialId = generateSecureId('cred', 16);
    const credentialItem: Record<string, any> = {
      user_guid: userGuid,
      credential_id: credentialId,
      status: 'ACTIVE',
      cek_version: cekVersion,
      lat_version: lat.version,
      device_id: session.device_id,
      created_at: now.toISOString(),
      last_action_at: now.toISOString(),
      failed_auth_count: 0,
    };
    // Only add invitation_code if it exists (QR code flow may not have one)
    if (session.invitation_code) {
      credentialItem.invitation_code = session.invitation_code;
    }
    await ddb.send(new PutItemCommand({
      TableName: TABLE_CREDENTIALS,
      Item: marshall(credentialItem),
    }));

    // Get remaining unused transaction keys using the user-index GSI
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
      cek_version: cekVersion,
      lat_version: lat.version,
      transaction_keys_remaining: remainingKeys.length,
    }, requestId);

    // === AUTO-PROVISIONING ===
    // After enrollment completes, automatically provision the vault EC2 instance.
    // This is non-blocking for enrollment - if provisioning fails, user can manually
    // trigger via POST /vault/provision later.
    //
    // NOTE: The vault-manager generates its own NATS credentials from the account seed
    // on first boot. It also generates mobile app credentials when the app calls
    // the app.bootstrap handler. This is the intended architecture where vault is
    // the authority for all credential generation.
    let vaultStatus = 'PENDING_PROVISION';
    let vaultInstanceId: string | undefined;
    let ownerSpaceId = '';
    let messageSpaceId = '';
    let bootstrapCredentials = '';
    // natsCaCertificate no longer needed - NLB terminates TLS with ACM (publicly trusted)

    try {
      // 1. Create NATS account for this user
      const accountCredentials = await generateAccountCredentials(userGuid);
      ownerSpaceId = `OwnerSpace.${userGuid.replace(/-/g, '')}`;
      messageSpaceId = `MessageSpace.${userGuid.replace(/-/g, '')}`;

      await ddb.send(new PutItemCommand({
        TableName: TABLE_NATS_ACCOUNTS,
        Item: marshall({
          user_guid: userGuid,
          account_public_key: accountCredentials.publicKey,
          account_seed: accountCredentials.seed,
          account_jwt: accountCredentials.accountJwt,  // For NATS resolver
          owner_space_id: ownerSpaceId,
          message_space_id: messageSpaceId,
          status: 'active',  // Required for lookupAccountJwt
          created_at: now.toISOString(),
        }),
        ConditionExpression: 'attribute_not_exists(user_guid)',
      }));

      // 2. Trigger EC2 provisioning (vault generates its own credentials on startup)
      const provisionResult = await triggerVaultProvisioning({
        userGuid,
        ownerSpaceId,
        messageSpaceId,
        accountSeed: accountCredentials.seed,
      });

      vaultStatus = 'PROVISIONING';
      vaultInstanceId = provisionResult.instanceId;

      console.log(`Auto-provisioned vault for user ${userGuid}: instance ${vaultInstanceId}`);

      // 3. Generate temporary bootstrap credentials for initial app connection
      // These have minimal permissions - just enough to call app.bootstrap
      // and receive full credentials from the vault
      const bootstrapCreds = await generateBootstrapCredentials(
        userGuid,
        accountCredentials.seed,
        ownerSpaceId
      );

      // Store bootstrap credentials for response
      bootstrapCredentials = formatCredsFile(bootstrapCreds.jwt, bootstrapCreds.seed);

      // Note: NATS CA certificate no longer needed - NLB terminates TLS with ACM (publicly trusted)

    } catch (provisionError: any) {
      // Non-fatal: enrollment succeeded, but vault provisioning failed
      // User can manually provision later via POST /vault/provision
      console.warn('Auto-provisioning failed (non-fatal):', provisionError.message);
      vaultStatus = 'PENDING_PROVISION';
    }

    return ok({
      status: 'enrolled',
      credential_package: {
        user_guid: userGuid,
        credential_id: credentialId,
        encrypted_blob: serializedBlob.ciphertext,
        ephemeral_public_key: serializedBlob.ephemeral_public_key,
        nonce: serializedBlob.nonce,
        cek_version: cekVersion,
        ledger_auth_token: {
          token: lat.token,  // Send raw token to mobile (will be stored for verification)
          version: lat.version,
        },
        transaction_keys: remainingKeys,
      },
      vault_status: vaultStatus,
      vault_instance_id: vaultInstanceId,
      // Vault bootstrap info - app uses these temporary credentials to call app.bootstrap
      // on the vault and receive full NATS credentials generated by the vault.
      // Bootstrap credentials have minimal permissions (1 hour TTL, only app.bootstrap topic).
      vault_bootstrap: vaultStatus === 'PROVISIONING' && bootstrapCredentials ? {
        credentials: bootstrapCredentials,  // Temporary credentials for bootstrap only
        owner_space: ownerSpaceId,
        message_space: messageSpaceId,
        nats_endpoint: `tls://${process.env.NATS_ENDPOINT || 'nats.vettid.dev:4222'}`,
        bootstrap_topic: `${ownerSpaceId}.forVault.app.bootstrap`,
        response_topic: `${ownerSpaceId}.forApp.bootstrap.>`,
        credentials_ttl_seconds: 3600,  // 1 hour
        estimated_ready_at: new Date(Date.now() + 2 * 60 * 1000).toISOString(),
        // Note: ca_certificate no longer needed - NLB terminates TLS with ACM (publicly trusted)
      } : undefined,
    }, origin);

  } catch (error: any) {
    console.error('Finalize enrollment error:', error);
    return internalError('Failed to finalize enrollment', origin);
  }
};
