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
  USER_POOL_ID
} from "../../common/util";
import { UpdateItemCommand, QueryCommand, ScanCommand } from "@aws-sdk/client-dynamodb";
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
    // Get user's email from JWT claims
    const userEmail = (event.requestContext as any)?.authorizer?.jwt?.claims?.email;
    if (!userEmail) {
      return badRequest("Unable to identify user");
    }

    // Find the user's registration by email using Scan
    // NOTE: Do NOT use Limit with FilterExpression - Limit applies BEFORE filtering
    const queryResult = await ddb.send(new ScanCommand({
      TableName: TABLES.registrations,
      FilterExpression: "email = :email AND #s = :approved",
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

    // Add user to member group in Cognito
    await cognito.send(new AdminAddUserToGroupCommand({
      UserPoolId: USER_POOL_ID,
      Username: userEmail,
      GroupName: 'member'
    }));

    // Update membership status to approved and record terms acceptance
    await ddb.send(new UpdateItemCommand({
      TableName: TABLES.registrations,
      Key: marshall({ registration_id: reg.registration_id }),
      UpdateExpression: "SET membership_status = :status, membership_approved_at = :now, terms_version_id = :termsVersion, terms_accepted_at = :now",
      ExpressionAttributeValues: marshall({
        ":status": "approved",
        ":now": now,
        ":termsVersion": termsVersionId
      })
    }));

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
