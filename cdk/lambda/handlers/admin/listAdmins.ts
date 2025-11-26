import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ok, requireAdminGroup } from "../../common/util";
import { CognitoIdentityProviderClient, ListUsersInGroupCommand } from "@aws-sdk/client-cognito-identity-provider";

const cognito = new CognitoIdentityProviderClient({});
const USER_POOL_ID = process.env.USER_POOL_ID!;
const ADMIN_GROUP = process.env.ADMIN_GROUP || "admin";

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Validate admin group membership
  const authError = requireAdminGroup(event);
  if (authError) return authError;

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

      return {
        email,
        given_name: givenName,
        family_name: familyName,
        admin_type: adminType,
        enabled: user.Enabled,
        created_at: user.UserCreateDate?.toISOString(),
        status: user.UserStatus
      };
    });

    return ok(admins);
  } catch (error) {
    console.error('Error listing admin users:', error);
    throw error;
  }
};
