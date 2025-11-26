import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import {
  ok,
  badRequest,
  notFound,
  internalError,
  putAudit,
  getAdminEmail,
  getRegistration,
  ddb,
  TABLES,
  NotFoundError,
  requireAdminGroup,
  parseJsonBody,
  ValidationError
} from "../../common/util";
import { UpdateItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall } from "@aws-sdk/util-dynamodb";

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Validate admin group membership
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  const id = event.pathParameters?.id;
  if (!id) return badRequest("id required");

  const requestId = (event.requestContext as any).requestId;

  try {
    const body = parseJsonBody(event);
    const reason = body.reason || "No reason provided";

    const reg = await getRegistration(id);

    if (reg.membership_status === "denied") {
      return ok({ message: "Membership already denied" });
    }

    if (reg.membership_status !== "pending") {
      return badRequest("No pending membership request found");
    }

    const adminEmail = getAdminEmail(event);
    const now = new Date().toISOString();

    // Update membership status to denied
    await ddb.send(new UpdateItemCommand({
      TableName: TABLES.registrations,
      Key: marshall({ registration_id: id }),
      UpdateExpression: "SET membership_status = :denied, membership_denied_at = :now, membership_denied_by = :by, membership_denial_reason = :reason",
      ExpressionAttributeValues: marshall({
        ":denied": "denied",
        ":now": now,
        ":by": adminEmail,
        ":reason": reason
      })
    }));

    await putAudit({
      type: "membership_denied",
      registration_id: id,
      email: reg.email,
      denied_by: adminEmail,
      denied_at: now,
      reason: reason
    }, requestId);

    return ok({ message: "Membership denied" });
  } catch (error) {
    if (error instanceof NotFoundError) {
      return notFound(error.message);
    }
    if (error instanceof ValidationError) {
      return badRequest(error.message);
    }
    console.error('Failed to deny membership:', error);
    return internalError("Failed to deny membership");
  }
};
