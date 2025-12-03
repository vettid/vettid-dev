import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ok, badRequest, putAudit, requireAdminGroup, validateOrigin, getAdminEmail, internalError, ddb } from "../../common/util";
import { GetItemCommand, DeleteItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import { SESClient, DeleteIdentityCommand } from "@aws-sdk/client-ses";

const ses = new SESClient({});
const PENDING_ADMINS_TABLE = process.env.PENDING_ADMINS_TABLE!;

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  const requestOrigin = event.headers?.origin || event.headers?.Origin;

  // Validate admin group membership
  const authError = requireAdminGroup(event, requestOrigin);
  if (authError) return authError;

  // CSRF protection
  const csrfError = validateOrigin(event);
  if (csrfError) return csrfError;

  const email = event.pathParameters?.email;
  if (!email) {
    return badRequest("Email is required", requestOrigin);
  }

  const decodedEmail = decodeURIComponent(email).toLowerCase();
  const cancelledBy = getAdminEmail(event);

  try {
    // Get the pending admin record to verify it exists
    const pendingResult = await ddb.send(new GetItemCommand({
      TableName: PENDING_ADMINS_TABLE,
      Key: marshall({ email: decodedEmail })
    }));

    if (!pendingResult.Item) {
      return badRequest("No pending invitation found for this email", requestOrigin);
    }

    const pendingAdmin = unmarshall(pendingResult.Item);

    // Delete the pending admin record
    await ddb.send(new DeleteItemCommand({
      TableName: PENDING_ADMINS_TABLE,
      Key: marshall({ email: decodedEmail })
    }));

    // Optionally remove the SES identity (clean up)
    try {
      await ses.send(new DeleteIdentityCommand({
        Identity: decodedEmail
      }));
    } catch (sesError) {
      // Non-fatal - just log it
      console.error('Error removing SES identity (non-fatal):', sesError);
    }

    await putAudit({
      type: "admin_invitation_cancelled",
      email: decodedEmail,
      first_name: pendingAdmin.first_name,
      last_name: pendingAdmin.last_name,
      admin_type: pendingAdmin.admin_type,
      cancelled_by: cancelledBy,
      originally_invited_by: pendingAdmin.invited_by,
    });

    return ok({
      message: "Admin invitation cancelled successfully.",
      email: decodedEmail,
    }, requestOrigin);

  } catch (error: any) {
    console.error('Error cancelling admin invitation:', error);
    return internalError('Failed to cancel admin invitation', requestOrigin);
  }
};
