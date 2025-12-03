import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ok, internalError, requireAdminGroup, ddb } from "../../common/util";
import { ScanCommand } from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";
import { SESClient, GetIdentityVerificationAttributesCommand } from "@aws-sdk/client-ses";

const ses = new SESClient({});
const PENDING_ADMINS_TABLE = process.env.PENDING_ADMINS_TABLE!;

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  const requestOrigin = event.headers?.origin || event.headers?.Origin;

  // Validate admin group membership
  const authError = requireAdminGroup(event, requestOrigin);
  if (authError) return authError;

  try {
    // Scan all pending admins
    const result = await ddb.send(new ScanCommand({
      TableName: PENDING_ADMINS_TABLE,
    }));

    const pendingAdmins = (result.Items || []).map(item => unmarshall(item));

    // If there are pending admins, check their current SES verification status
    if (pendingAdmins.length > 0) {
      const emails = pendingAdmins.map(item => item.email);

      try {
        const verificationStatus = await ses.send(new GetIdentityVerificationAttributesCommand({
          Identities: emails
        }));

        // Update each pending admin with current SES status
        for (const admin of pendingAdmins) {
          const status = verificationStatus.VerificationAttributes?.[admin.email]?.VerificationStatus;
          admin.ses_status = status || 'NotStarted';
          admin.ses_verified = status === 'Success';
        }
      } catch (sesError) {
        console.error('Error checking SES verification status:', sesError);
        // Continue without updated status
      }
    }

    // Sort by invited_at descending (most recent first)
    pendingAdmins.sort((a, b) => {
      const dateA = new Date(a.invited_at || 0).getTime();
      const dateB = new Date(b.invited_at || 0).getTime();
      return dateB - dateA;
    });

    return ok({
      pending_admins: pendingAdmins,
      count: pendingAdmins.length
    }, requestOrigin);

  } catch (error) {
    console.error('Error listing pending admins:', error);
    return internalError('Failed to list pending admins', requestOrigin);
  }
};
