import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, PutItemCommand, GetItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  conflict,
  internalError,
  getRequestId,
  putAudit,
} from '../../common/util';

const ddb = new DynamoDBClient({});

const TABLE_VAULT_INSTANCES = process.env.TABLE_VAULT_INSTANCES!;
const TABLE_REGISTRATIONS = process.env.TABLE_REGISTRATIONS!;

interface RegisterNitroEnrollmentRequest {
  user_guid: string;
  credential_guid?: string;
  pcr_version?: string;
}

/**
 * POST /vault/nitro/register
 *
 * Register a completed Nitro Enclave enrollment.
 * Called by mobile app after successful enrollment via NATS.
 * Creates a VaultInstances record so the portal shows correct status.
 *
 * This endpoint is authenticated via Cognito and validates
 * that the user_guid matches the authenticated user.
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);
  const origin = event.headers?.origin;

  try {
    // Get authenticated user from authorizer
    const authContext = (event.requestContext as any)?.authorizer?.jwt?.claims;
    const authenticatedUserGuid = authContext?.sub || authContext?.['custom:user_guid'];

    if (!authenticatedUserGuid) {
      return badRequest('Authentication required', origin);
    }

    // Parse request body
    if (!event.body) {
      return badRequest('Request body required', origin);
    }

    let body: RegisterNitroEnrollmentRequest;
    try {
      body = JSON.parse(event.body);
    } catch {
      return badRequest('Invalid JSON in request body', origin);
    }

    const { user_guid, credential_guid, pcr_version } = body;

    if (!user_guid) {
      return badRequest('user_guid is required', origin);
    }

    // Security: Ensure user can only register their own vault
    if (user_guid !== authenticatedUserGuid) {
      return badRequest('user_guid does not match authenticated user', origin);
    }

    // Check if vault already registered
    const existingVault = await ddb.send(new GetItemCommand({
      TableName: TABLE_VAULT_INSTANCES,
      Key: marshall({ user_guid }),
    }));

    if (existingVault.Item) {
      // Already registered - update status to active
      const existing = unmarshall(existingVault.Item);
      if (existing.status === 'active') {
        return ok({
          status: 'already_registered',
          vault_type: existing.vault_type,
          created_at: existing.created_at,
        }, origin);
      }
    }

    // Create VaultInstances record
    const now = new Date().toISOString();
    await ddb.send(new PutItemCommand({
      TableName: TABLE_VAULT_INSTANCES,
      Item: marshall({
        user_guid,
        vault_type: 'nitro',
        status: 'active',
        created_at: now,
        updated_at: now,
        enrollment_method: 'nitro_enclave',
        credential_guid: credential_guid || null,
        pcr_version: pcr_version || null,
      }),
    }));

    // Audit log
    await putAudit({
      type: 'nitro_enrollment_registered',
      user_guid,
      request_id: requestId,
      timestamp: now,
      details: {
        credential_guid,
        pcr_version,
      },
    });

    console.log(`Registered Nitro enrollment for user ${user_guid}`);

    return ok({
      status: 'registered',
      vault_type: 'nitro',
      created_at: now,
    }, origin);

  } catch (error) {
    console.error('Error registering Nitro enrollment:', error);
    await putAudit({
      type: 'nitro_enrollment_register_error',
      request_id: requestId,
      error: error instanceof Error ? error.message : 'Unknown error',
    });
    return internalError('Failed to register enrollment', origin);
  }
};
