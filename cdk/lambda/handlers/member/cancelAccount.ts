import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import {
  ddb,
  TABLES,
  ok,
  badRequest,
  notFound,
  internalError,
  putAudit,
  userExistsInCognito,
  cognito,
  USER_POOL_ID,
  NotFoundError,
  requireRegisteredOrMemberGroup
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
    // Get user's email from JWT claims
    const userEmail = (event.requestContext as any)?.authorizer?.jwt?.claims?.email;
    if (!userEmail) {
      return badRequest("Unable to identify user");
    }

    // Find the user's registration by email using GSI
    const queryResult = await ddb.send(new QueryCommand({
      TableName: TABLES.registrations,
      IndexName: 'email-index',
      KeyConditionExpression: "email = :email",
      FilterExpression: "#s = :approved",
      ExpressionAttributeNames: {
        "#s": "status"
      },
      ExpressionAttributeValues: marshall({
        ":email": userEmail,
        ":approved": "approved"
      }),
      Limit: 1
    }));

    if (!queryResult.Items || queryResult.Items.length === 0) {
      return notFound("No active registration found for your account");
    }

    const reg = unmarshall(queryResult.Items[0]) as any;
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
    const userGuid = (event.requestContext as any)?.authorizer?.jwt?.claims?.['custom:user_guid'];
    if (userGuid && TABLE_SUBSCRIPTIONS) {
      try {
        await ddb.send(new DeleteItemCommand({
          TableName: TABLE_SUBSCRIPTIONS,
          Key: marshall({ user_guid: userGuid })
        }));
      } catch (subError) {
        // Log but don't fail - subscription may not exist
        console.log('No subscription to delete or delete failed:', subError);
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
