import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ddb, TABLES, ok, putAudit, requireAdminGroup, badRequest } from "../../common/util";
import { DeleteItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall } from "@aws-sdk/util-dynamodb";

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Validate admin group membership
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  const code = event.pathParameters?.code;
  if (!code) {
    return badRequest("Missing invite code");
  }
  const adminEmail = (event.requestContext as any)?.authorizer?.jwt?.claims?.email || "unknown@vettid.dev";

  await ddb.send(new DeleteItemCommand({
    TableName: TABLES.invites,
    Key: marshall({ code })
  }));

  await putAudit({ type: "invite_deleted", email: adminEmail, code, deleted_by: adminEmail });
  return ok({ message: "Invite deleted", code });
};
