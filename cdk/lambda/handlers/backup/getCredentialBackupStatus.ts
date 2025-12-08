import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { DynamoDBClient, GetItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import {
  ok,
  badRequest,
  internalError,
  requireUserClaims,
  ValidationError,
} from "../../common/util";

const ddb = new DynamoDBClient({});
const TABLE_CREDENTIAL_BACKUPS = process.env.TABLE_CREDENTIAL_BACKUPS!;

export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const origin = event.headers?.origin;

  try {
    // Validate user claims
    const claimsResult = requireUserClaims(event, origin);
    if ("error" in claimsResult) {
      return claimsResult.error;
    }
    const { claims } = claimsResult;

    // Get credential backup metadata
    const result = await ddb.send(new GetItemCommand({
      TableName: TABLE_CREDENTIAL_BACKUPS,
      Key: marshall({ member_guid: claims.user_guid }),
    }));

    if (!result.Item) {
      return ok({
        exists: false,
        created_at: null,
        last_verified_at: null,
      }, origin);
    }

    const backup = unmarshall(result.Item);

    return ok({
      exists: true,
      created_at: backup.created_at,
      updated_at: backup.updated_at,
      last_verified_at: backup.last_verified_at || null,
      size_bytes: backup.size_bytes,
      encryption_method: backup.encryption_method,
      key_derivation: backup.key_derivation,
    }, origin);

  } catch (error) {
    console.error("Error getting credential backup status:", error);
    if (error instanceof ValidationError) {
      return badRequest(error.message, origin);
    }
    return internalError("Failed to get credential backup status", origin);
  }
};
