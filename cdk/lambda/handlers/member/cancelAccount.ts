import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import {
  ddb,
  TABLES,
  ok,
  badRequest,
  notFound,
  forbidden,
  internalError,
  putAudit,
  userExistsInCognito,
  cognito,
  USER_POOL_ID,
  NotFoundError,
  requireRegisteredOrMemberGroup,
  extractUserClaims
} from "../../common/util";
import { UpdateItemCommand, QueryCommand, DeleteItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import { AdminDisableUserCommand } from "@aws-sdk/client-cognito-identity-provider";

const TABLE_SUBSCRIPTIONS = process.env.TABLE_SUBSCRIPTIONS!;

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Validate registered or member group membership
  const authError = requireRegisteredOrMemberGroup(event);
  if (authError) return authError;

  const requestId = (event.requestContext as any).requestId;

  try {
    // Get user claims from JWT token
    const userClaims = extractUserClaims(event);
    if (!userClaims) {
      return badRequest("Unable to identify user");
    }
    const userEmail = userClaims.email;
    const userGuid = userClaims.user_guid;

    // Find the user's registration by email using Query on status-index
    // Note: Remove Limit when using FilterExpression - Limit applies BEFORE filtering
    const queryResult = await ddb.send(new QueryCommand({
      TableName: TABLES.registrations,
      IndexName: 'status-index',
      KeyConditionExpression: "#s = :approved",
      FilterExpression: "email = :email",
      ExpressionAttributeNames: {
        "#s": "status"
      },
      ExpressionAttributeValues: marshall({
        ":email": userEmail,
        ":approved": "approved"
      })
    }));

    if (!queryResult.Items || queryResult.Items.length === 0) {
      return notFound("No active registration found for your account");
    }

    const reg = unmarshall(queryResult.Items[0]) as any;

    // SECURITY: Verify the registration belongs to the authenticated user
    // This prevents IDOR where modified JWT claims could cancel another user's account
    if (reg.user_guid && userGuid && reg.user_guid !== userGuid) {
      await putAudit({
        type: 'cancel_account_idor_attempt',
        claimed_user_guid: userGuid,
        registration_user_guid: reg.user_guid,
        email: userEmail
      }, requestId);
      return forbidden("You can only cancel your own account");
    }

    const now = new Date().toISOString();

    // Calculate scheduled deletion date (7 days from now)
    const scheduledDeletionDate = new Date();
    scheduledDeletionDate.setDate(scheduledDeletionDate.getDate() + 7);
    const scheduledDeletionIso = scheduledDeletionDate.toISOString();

    // Disable user in Cognito if they exist
    const exists = await userExistsInCognito(userEmail);
    if (exists) {
      await cognito.send(new AdminDisableUserCommand({
        UserPoolId: USER_POOL_ID,
        Username: userEmail
      }));
    }

    // Update registration status to canceled with scheduled deletion date
    await ddb.send(new UpdateItemCommand({
      TableName: TABLES.registrations,
      Key: marshall({ registration_id: reg.registration_id }),
      UpdateExpression: "SET #s = :canceled, canceled_at = :now, canceled_by = :by, scheduled_deletion_date = :deletion_date",
      ExpressionAttributeNames: { "#s": "status" },
      ExpressionAttributeValues: marshall({
        ":canceled": "canceled",
        ":now": now,
        ":by": userEmail,
        ":deletion_date": scheduledDeletionIso
      })
    }));

    // Delete user's subscription if it exists
    if (userGuid && TABLE_SUBSCRIPTIONS) {
      try {
        await ddb.send(new DeleteItemCommand({
          TableName: TABLE_SUBSCRIPTIONS,
          Key: marshall({ user_guid: userGuid })
        }));
      } catch {
        // Ignore - subscription may not exist
      }
    }

    await putAudit({
      type: "account_canceled",
      registration_id: reg.registration_id,
      email: userEmail,
      canceled_by: userEmail,
      canceled_at: now,
      scheduled_deletion_date: scheduledDeletionIso
    }, requestId);

    return ok({
      message: "Your account has been canceled. Your data will be held for 7 days before being permanently deleted. Contact restore@vettid.dev to restore your account or request immediate deletion."
    });
  } catch (error) {
    if (error instanceof NotFoundError) {
      return notFound(error.message);
    }
    console.error('Failed to cancel account:', error);
    return internalError("Failed to cancel account");
  }
};
