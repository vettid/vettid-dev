import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ddb, TABLES, ok, badRequest, putAudit, requireAdminGroup } from "../../common/util";
import { UpdateItemCommand, GetItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Validate admin group membership
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  const code = event.pathParameters?.code;
  if (!code) return badRequest("code required");

  const inviteRes = await ddb.send(new GetItemCommand({
    TableName: TABLES.invites,
    Key: marshall({ code })
  }));

  if (!inviteRes.Item) return badRequest("invite not found");
  const invite = unmarshall(inviteRes.Item) as any;

  if (invite.status !== "active") return badRequest("invite is not active");

  const adminEmail = (event.requestContext as any)?.authorizer?.jwt?.claims?.email || "unknown@vettid.dev";
  const now = new Date().toISOString();

  // Update invite status to expired
  await ddb.send(new UpdateItemCommand({
    TableName: TABLES.invites,
    Key: marshall({ code }),
    UpdateExpression: "SET #s = :expired, expired_at = :now, expired_by = :by",
    ExpressionAttributeNames: { "#s": "status" },
    ExpressionAttributeValues: marshall({
      ":expired": "expired",
      ":now": now,
      ":by": adminEmail
    })
  }));

  await putAudit({
    type: "invite_expired",
    code,
    expired_by: adminEmail
  });

  return ok({ message: "invite expired successfully" });
};
