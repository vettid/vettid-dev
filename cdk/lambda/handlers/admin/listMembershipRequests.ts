import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import {
  ddb,
  TABLES,
  ok,
  internalError,
  requireAdminGroup
} from "../../common/util";
import { ScanCommand } from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Validate admin group membership
  const authError = requireAdminGroup(event);
  if (authError) return authError;

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

    const registrations = (result.Items || [])
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
      }))
      .sort((a, b) => {
        // Sort by requested_at if pending
        if (a.membership_requested_at && b.membership_requested_at) {
          return new Date(b.membership_requested_at).getTime() - new Date(a.membership_requested_at).getTime();
        }
        return 0;
      });

    return ok({ registrations });
  } catch (error) {
    console.error('Failed to list membership requests:', error);
    return internalError("Failed to list membership requests");
  }
};
