import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import {
  ddb,
  TABLES,
  ok,
  badRequest,
  internalError,
  requireAdminGroup
} from "../../common/util";
import { ScanCommand } from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";

// Valid membership status values
const VALID_MEMBERSHIP_STATUSES = ['none', 'pending', 'approved', 'denied'];

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Validate admin group membership
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  // Get optional membership_status filter from query params
  const membershipStatusFilter = event.queryStringParameters?.membership_status;

  // Get optional pagination params
  const limitParam = event.queryStringParameters?.limit;
  const offsetParam = event.queryStringParameters?.offset;
  const limit = limitParam ? Math.min(Math.max(parseInt(limitParam, 10) || 100, 1), 100) : 100;
  const offset = offsetParam ? Math.max(parseInt(offsetParam, 10) || 0, 0) : 0;

  // Validate membership_status filter if provided
  if (membershipStatusFilter && !VALID_MEMBERSHIP_STATUSES.includes(membershipStatusFilter)) {
    return badRequest(`Invalid membership_status filter. Must be one of: ${VALID_MEMBERSHIP_STATUSES.join(', ')}`);
  }

  try {
    // Scan for all approved registrations (could be optimized with GSI if needed)
    const result = await ddb.send(new ScanCommand({
      TableName: TABLES.registrations,
      FilterExpression: "#s = :approved",
      ExpressionAttributeNames: {
        "#s": "status"
      },
      ExpressionAttributeValues: {
        ":approved": { S: "approved" }
      }
    }));

    let registrations = (result.Items || [])
      .map(item => unmarshall(item))
      .map((reg: any) => ({
        registration_id: reg.registration_id,
        email: reg.email,
        first_name: reg.first_name,
        last_name: reg.last_name,
        membership_status: reg.membership_status || 'none',
        membership_requested_at: reg.membership_requested_at || null,
        membership_approved_at: reg.membership_approved_at || null,
        membership_denied_at: reg.membership_denied_at || null,
        membership_denial_reason: reg.membership_denial_reason || null,
        membership_approved_by: reg.membership_approved_by || null,
        membership_denied_by: reg.membership_denied_by || null
      }));

    // Apply membership_status filter if provided
    if (membershipStatusFilter) {
      registrations = registrations.filter(reg => reg.membership_status === membershipStatusFilter);
    }

    // Sort by requested_at if pending
    registrations.sort((a, b) => {
      if (a.membership_requested_at && b.membership_requested_at) {
        return new Date(b.membership_requested_at).getTime() - new Date(a.membership_requested_at).getTime();
      }
      return 0;
    });

    // Get total count before pagination
    const total = registrations.length;

    // Apply pagination
    registrations = registrations.slice(offset, offset + limit);

    return ok({ registrations, total, limit, offset });
  } catch (error) {
    console.error('Failed to list membership requests:', error);
    return internalError("Failed to list membership requests");
  }
};
