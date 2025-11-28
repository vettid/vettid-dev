import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import {
  ddb,
  TABLES,
  ok,
  badRequest,
  notFound,
  internalError,
  requireRegisteredOrMemberGroup
} from "../../common/util";
import { QueryCommand, ScanCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Validate registered or member group membership
  const authError = requireRegisteredOrMemberGroup(event);
  if (authError) return authError;

  try {
    // Get user's email from JWT claims
    const userEmail = (event.requestContext as any)?.authorizer?.jwt?.claims?.email;
    if (!userEmail) {
      return badRequest("Unable to identify user");
    }

    // Find the user's registration by email using Scan
    const queryResult = await ddb.send(new ScanCommand({
      TableName: TABLES.registrations,
      FilterExpression: "email = :email",
      ExpressionAttributeValues: marshall({
        ":email": userEmail
      }),
      Limit: 1
    }));

    // If no registration found, return default status
    if (!queryResult.Items || queryResult.Items.length === 0) {
      return ok({
        membership_status: 'none',
        membership_requested_at: null,
        membership_approved_at: null,
        membership_denied_at: null,
        membership_denial_reason: null,
        terms_version_id: null,
        terms_accepted_at: null,
        registration_status: 'not_found'
      });
    }

    const reg = unmarshall(queryResult.Items[0]) as any;

    // Check if registration is approved - if not, user shouldn't be accessing this
    if (reg.status !== 'approved') {
      return ok({
        membership_status: 'none',
        membership_requested_at: null,
        membership_approved_at: null,
        membership_denied_at: null,
        membership_denial_reason: null,
        terms_version_id: null,
        terms_accepted_at: null,
        registration_status: reg.status
      });
    }

    return ok({
      membership_status: reg.membership_status || 'none',
      membership_requested_at: reg.membership_requested_at || null,
      membership_approved_at: reg.membership_approved_at || null,
      membership_denied_at: reg.membership_denied_at || null,
      membership_denial_reason: reg.membership_denial_reason || null,
      terms_version_id: reg.terms_version_id || null,
      terms_accepted_at: reg.terms_accepted_at || null,
      registration_status: 'approved'
    });
  } catch (error) {
    console.error('Failed to get membership status:', error);
    return internalError("Failed to get membership status");
  }
};
