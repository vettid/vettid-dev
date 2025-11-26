import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import {
  ok,
  badRequest,
  notFound,
  internalError,
  putAudit,
  getAdminEmail,
  getRegistration,
  cognito,
  USER_POOL_ID,
  ddb,
  TABLES,
  NotFoundError,
  requireAdminGroup
} from "../../common/util";
import { UpdateItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall } from "@aws-sdk/util-dynamodb";
import { AdminAddUserToGroupCommand } from "@aws-sdk/client-cognito-identity-provider";

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Validate admin group membership
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  const id = event.pathParameters?.id;
  if (!id) return badRequest("id required");

  const requestId = (event.requestContext as any).requestId;

  try {
    const reg = await getRegistration(id);

    if (reg.membership_status === "approved") {
      return ok({ message: "Membership already approved" });
    }

    if (reg.membership_status !== "pending") {
      return badRequest("No pending membership request found");
    }

    const adminEmail = getAdminEmail(event);
    const now = new Date().toISOString();

    // Add to member group in Cognito
    await cognito.send(new AdminAddUserToGroupCommand({
      UserPoolId: USER_POOL_ID,
      Username: reg.email,
      GroupName: 'member'
    }));

    // Update membership status
    await ddb.send(new UpdateItemCommand({
      TableName: TABLES.registrations,
      Key: marshall({ registration_id: id }),
      UpdateExpression: "SET membership_status = :approved, membership_approved_at = :now, membership_approved_by = :by",
      ExpressionAttributeValues: marshall({
        ":approved": "approved",
        ":now": now,
        ":by": adminEmail
      })
    }));

    await putAudit({
      type: "membership_approved",
      registration_id: id,
      email: reg.email,
      approved_by: adminEmail,
      approved_at: now
    }, requestId);

    return ok({ message: "Membership approved successfully" });
  } catch (error) {
    if (error instanceof NotFoundError) {
      return notFound(error.message);
    }
    console.error('Failed to approve membership:', error);
    return internalError("Failed to approve membership");
  }
};
