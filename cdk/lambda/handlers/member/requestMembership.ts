import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import {
  ddb,
  TABLES,
  ok,
  badRequest,
  notFound,
  internalError,
  putAudit,
  requireRegisteredOrMemberGroup,
  getRequestId,
  cognito,
  USER_POOL_ID,
  requireUserClaims
} from "../../common/util";
import { UpdateItemCommand, QueryCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import { AdminAddUserToGroupCommand } from "@aws-sdk/client-cognito-identity-provider";

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Validate registered or member group membership
  const authError = requireRegisteredOrMemberGroup(event);
  if (authError) return authError;

  const requestId = getRequestId(event);

  // Parse request body for terms acceptance
  let termsVersionId: string | undefined;
  if (event.body) {
    try {
      const body = JSON.parse(event.body);
      termsVersionId = body.terms_version_id;
    } catch (e) {
      // Body is optional but if provided must be valid JSON
    }
  }

  if (!termsVersionId) {
    return badRequest("You must accept the membership terms before requesting membership");
  }

  try {
    // Get user claims from JWT token using standardized utility
    const claimsResult = requireUserClaims(event);
    if ('error' in claimsResult) return claimsResult.error;
    const { email: userEmail } = claimsResult.claims;

    // Find the user's registration by email using GSI (efficient query instead of scan)
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
      })
    }));

    if (!queryResult.Items || queryResult.Items.length === 0) {
      return notFound("No active registration found for your account");
    }

    const reg = unmarshall(queryResult.Items[0]) as any;

    // Check current membership status
    if (reg.membership_status === 'approved') {
      return badRequest("You are already a member");
    }

    const now = new Date().toISOString();

    // RACE CONDITION FIX: Update DynamoDB FIRST with conditional expression
    // This ensures atomicity - only one request can succeed in updating the status
    try {
      await ddb.send(new UpdateItemCommand({
        TableName: TABLES.registrations,
        Key: marshall({ registration_id: reg.registration_id }),
        UpdateExpression: "SET membership_status = :status, membership_approved_at = :now, terms_version_id = :termsVersion, terms_accepted_at = :now",
        // Conditional expression: only update if membership_status is NOT already 'approved'
        ConditionExpression: "attribute_not_exists(membership_status) OR membership_status <> :status",
        ExpressionAttributeValues: marshall({
          ":status": "approved",
          ":now": now,
          ":termsVersion": termsVersionId
        })
      }));
    } catch (conditionError: any) {
      if (conditionError.name === 'ConditionalCheckFailedException') {
        // Another request already approved the membership
        return badRequest("You are already a member");
      }
      throw conditionError;
    }

    // DynamoDB updated successfully - now add to Cognito group
    // If this fails, we need to rollback the DynamoDB change
    try {
      await cognito.send(new AdminAddUserToGroupCommand({
        UserPoolId: USER_POOL_ID,
        Username: userEmail,
        GroupName: 'member'
      }));
    } catch (cognitoError) {
      // Cognito failed - rollback DynamoDB change
      console.error('Cognito group add failed, rolling back DynamoDB:', cognitoError);
      try {
        await ddb.send(new UpdateItemCommand({
          TableName: TABLES.registrations,
          Key: marshall({ registration_id: reg.registration_id }),
          UpdateExpression: "SET membership_status = :status REMOVE membership_approved_at, terms_version_id, terms_accepted_at",
          ExpressionAttributeValues: marshall({
            ":status": "pending"
          })
        }));
      } catch (rollbackError) {
        // Log rollback failure for manual intervention
        console.error('CRITICAL: Failed to rollback DynamoDB after Cognito failure:', rollbackError);
        await putAudit({
          type: "membership_rollback_failed",
          registration_id: reg.registration_id,
          email: userEmail,
          cognito_error: String(cognitoError),
          rollback_error: String(rollbackError)
        }, requestId);
      }
      throw cognitoError;
    }

    await putAudit({
      type: "membership_approved_auto",
      registration_id: reg.registration_id,
      email: userEmail,
      approved_at: now
    }, requestId);

    return ok({
      message: "Membership approved! Please sign in again to access member features.",
      requires_signin: true
    });
  } catch (error) {
    console.error('Failed to request membership:', error);
    return internalError("Failed to request membership");
  }
};
