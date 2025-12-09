import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, DeleteItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  notFound,
  internalError,
  getRequestId,
  requireUserClaims,
  putAudit,
} from '../../common/util';

const ddb = new DynamoDBClient({});

const TABLE_VAULT_INSTANCES = process.env.TABLE_VAULT_INSTANCES!;

/**
 * DELETE /vault/byov
 *
 * Remove a registered BYOV vault.
 *
 * Requires member JWT authentication.
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);
  const origin = event.headers?.origin;

  try {
    // Validate member authentication and get claims
    const claimsResult = requireUserClaims(event, origin);
    if ('error' in claimsResult) {
      return claimsResult.error;
    }
    const { claims } = claimsResult;
    const userGuid = claims.user_guid;

    // Get existing vault
    const result = await ddb.send(new GetItemCommand({
      TableName: TABLE_VAULT_INSTANCES,
      Key: marshall({ user_guid: userGuid }),
    }));

    if (!result.Item) {
      return notFound('No vault registered', origin);
    }

    const vault = unmarshall(result.Item);

    if (vault.type !== 'BYOV') {
      return badRequest('This endpoint is only for BYOV vaults. Use /vault/terminate for managed vaults.', origin);
    }

    // Delete the vault record
    await ddb.send(new DeleteItemCommand({
      TableName: TABLE_VAULT_INSTANCES,
      Key: marshall({ user_guid: userGuid }),
    }));

    // Audit log
    await putAudit({
      type: 'byov_vault_deleted',
      user_guid: userGuid,
      vault_id: vault.vault_id,
      vault_url: new URL(vault.vault_url).host,
    }, requestId);

    return ok({
      message: 'Vault registration removed',
      vault_id: vault.vault_id,
    }, origin);

  } catch (error: any) {
    console.error('Delete BYOV vault error:', error);
    return internalError('Failed to delete vault', origin);
  }
};
