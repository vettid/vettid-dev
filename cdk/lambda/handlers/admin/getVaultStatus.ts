import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ok, badRequest, internalError, requireAdminGroup, putAudit } from "../../common/util";
import { DynamoDBClient, BatchGetItemCommand, QueryCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";

const ddb = new DynamoDBClient({});

const TABLE_VAULT_INSTANCES = process.env.TABLE_VAULT_INSTANCES!;
const TABLE_ENROLLMENT_SESSIONS = process.env.TABLE_ENROLLMENT_SESSIONS!;

/**
 * Get vault enrollment status for one or more users
 *
 * Query params:
 * - user_guids: Comma-separated list of user GUIDs (max 100)
 *
 * Returns vault status for each user:
 * - not_enrolled: No enrollment session exists
 * - enrolling: Enrollment in progress
 * - enrolled: Vault instance exists
 * - active: Vault is currently active/connected
 */
export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Validate admin group membership
  const authError = requireAdminGroup(event);
  if (authError) {
    await putAudit({
      type: 'auth_failure_admin_access_denied',
      reason: 'insufficient_group_membership',
      path: event.rawPath
    });
    return authError;
  }

  try {
    const userGuidsParam = event.queryStringParameters?.user_guids;

    if (!userGuidsParam) {
      return badRequest('user_guids query parameter is required');
    }

    const userGuids = userGuidsParam.split(',').map(g => g.trim()).filter(g => g.length > 0);

    if (userGuids.length === 0) {
      return badRequest('At least one user_guid is required');
    }

    if (userGuids.length > 100) {
      return badRequest('Maximum 100 user_guids allowed per request');
    }

    // Batch get vault instances for all users
    const vaultStatuses: Record<string, {
      status: 'not_enrolled' | 'enrolling' | 'enrolled' | 'active';
      instance_id?: string;
      created_at?: string;
      last_seen_at?: string;
    }> = {};

    // Initialize all users as not_enrolled
    for (const userGuid of userGuids) {
      vaultStatuses[userGuid] = { status: 'not_enrolled' };
    }

    // Check VaultInstances table for enrolled/active vaults
    if (userGuids.length > 0) {
      try {
        const batchResult = await ddb.send(new BatchGetItemCommand({
          RequestItems: {
            [TABLE_VAULT_INSTANCES]: {
              Keys: userGuids.map(guid => marshall({ user_guid: guid })),
              ProjectionExpression: 'user_guid, instance_id, #s, created_at, last_seen_at',
              ExpressionAttributeNames: { '#s': 'status' }
            }
          }
        }));
        const vaultItems = (batchResult.Responses?.[TABLE_VAULT_INSTANCES] || []).map(item => unmarshall(item));

        for (const item of vaultItems) {
          const userGuid = item.user_guid as string;
          const instanceStatus = item.status as string;

          // Map vault instance status to display status
          let displayStatus: 'enrolled' | 'active' = 'enrolled';
          if (instanceStatus === 'active' || instanceStatus === 'connected') {
            displayStatus = 'active';
          }

          vaultStatuses[userGuid] = {
            status: displayStatus,
            instance_id: item.instance_id as string,
            created_at: item.created_at as string,
            last_seen_at: item.last_seen_at as string,
          };
        }
      } catch (batchError) {
        console.error('Error batch getting vault instances:', batchError);
        // Continue - we'll check enrollment sessions next
      }
    }

    // For users without vault instances, check if they have enrollment sessions in progress
    const notEnrolledUsers = userGuids.filter(guid =>
      vaultStatuses[guid].status === 'not_enrolled'
    );

    if (notEnrolledUsers.length > 0) {
      // Query enrollment sessions for each not-enrolled user
      // Check for sessions in pending or in_progress status
      await Promise.all(notEnrolledUsers.map(async (userGuid) => {
        try {
          const queryResult = await ddb.send(new QueryCommand({
            TableName: TABLE_ENROLLMENT_SESSIONS,
            IndexName: 'user-index',
            KeyConditionExpression: 'user_guid = :guid',
            FilterExpression: '#s IN (:pending, :in_progress)',
            ExpressionAttributeNames: { '#s': 'status' },
            ExpressionAttributeValues: marshall({
              ':guid': userGuid,
              ':pending': 'pending',
              ':in_progress': 'in_progress',
            }),
            Limit: 1,
            ScanIndexForward: false, // Most recent first
          }));

          if (queryResult.Items && queryResult.Items.length > 0) {
            vaultStatuses[userGuid] = { status: 'enrolling' };
          }
        } catch (queryError) {
          console.error(`Error querying enrollment sessions for ${userGuid}:`, queryError);
          // Keep as not_enrolled
        }
      }));
    }

    return ok({
      vault_statuses: vaultStatuses
    });
  } catch (error) {
    console.error('Error fetching vault statuses:', error);

    await putAudit({
      type: 'admin_get_vault_status_error',
      error: error instanceof Error ? error.message : String(error)
    });

    return internalError('Failed to fetch vault statuses');
  }
};
