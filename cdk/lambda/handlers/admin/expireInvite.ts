import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ddb, TABLES, ok, badRequest, putAudit, requireAdminGroup, notFound, internalError } from "../../common/util";
import { UpdateItemCommand, GetItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  const origin = event.headers?.origin;

  try {
    // Validate admin group membership
    const authError = requireAdminGroup(event, origin);
    if (authError) return authError;

    const code = event.pathParameters?.code;
    if (!code) return badRequest("code required", origin);

    const inviteRes = await ddb.send(new GetItemCommand({
      TableName: TABLES.invites,
      Key: marshall({ code })
    }));

    if (!inviteRes.Item) return notFound("invite not found", origin);
    const invite = unmarshall(inviteRes.Item) as any;

    if (invite.status !== "active") return badRequest("invite is not active", origin);

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
      email: adminEmail,
      code,
      expired_by: adminEmail
    });

    return ok({ message: "invite expired successfully" }, origin);
  } catch (error) {
    console.error("Error expiring invite:", error);
    return internalError("Failed to expire invite", origin);
  }
};
