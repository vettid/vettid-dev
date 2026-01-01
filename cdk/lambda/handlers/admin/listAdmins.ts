import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ok, internalError, requireAdminGroup, putAudit, getAdminEmail, getRequestId } from "../../common/util";
import { CognitoIdentityProviderClient, ListUsersInGroupCommand } from "@aws-sdk/client-cognito-identity-provider";

const cognito = new CognitoIdentityProviderClient({});
const USER_POOL_ID = process.env.ADMIN_USER_POOL_ID!;
const ADMIN_GROUP = process.env.ADMIN_GROUP || "admin";

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  const requestOrigin = event.headers?.origin || event.headers?.Origin;

  // Validate admin group membership
  const authError = requireAdminGroup(event, requestOrigin);
  if (authError) return authError;

  const requestId = getRequestId(event);
  const accessingAdmin = getAdminEmail(event);

  try {
    const result = await cognito.send(new ListUsersInGroupCommand({
      UserPoolId: USER_POOL_ID,
      GroupName: ADMIN_GROUP
    }));

    const admins = (result.Users || []).map(user => {
      const email = user.Attributes?.find(a => a.Name === 'email')?.Value || '';
      const givenName = user.Attributes?.find(a => a.Name === 'given_name')?.Value || '';
      const familyName = user.Attributes?.find(a => a.Name === 'family_name')?.Value || '';
      const adminType = user.Attributes?.find(a => a.Name === 'custom:admin_type')?.Value || 'admin';
      const lastLoginAt = user.Attributes?.find(a => a.Name === 'custom:last_login_at')?.Value;

      return {
        email,
        given_name: givenName,
        family_name: familyName,
        admin_type: adminType,
        enabled: user.Enabled,
        created_at: user.UserCreateDate?.toISOString(),
        last_login_at: lastLoginAt,  // Will be undefined until user logs in after this update
        status: user.UserStatus
      };
    });

    // SECURITY: Audit log for admin enumeration (helps detect reconnaissance)
    await putAudit({
      type: 'admin_list_accessed',
      accessed_by: accessingAdmin,
      admin_count: admins.length
    }, requestId);

    return ok({ admins }, requestOrigin);
  } catch (error) {
    console.error('Error listing admin users:', error);
    return internalError('Failed to list admin users', requestOrigin);
  }
};
