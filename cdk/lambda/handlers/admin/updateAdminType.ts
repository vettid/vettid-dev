import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ok, badRequest, putAudit, requireAdminGroup, validateOrigin } from "../../common/util";
import { CognitoIdentityProviderClient, AdminUpdateUserAttributesCommand, AdminGetUserCommand } from "@aws-sdk/client-cognito-identity-provider";

const cognito = new CognitoIdentityProviderClient({});
const USER_POOL_ID = process.env.ADMIN_USER_POOL_ID!;

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Validate admin group membership
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  // CSRF protection: Validate request origin
  const csrfError = validateOrigin(event);
  if (csrfError) return csrfError;

  const username = event.pathParameters?.username;

  if (!username) {
    return badRequest("Username is required");
  }

  const email = decodeURIComponent(username).toLowerCase();
  const adminEmail = (event.requestContext as any)?.authorizer?.jwt?.claims?.email || "unknown@vettid.dev";

  let adminType: string;

  try {
    const body = event.body ? JSON.parse(event.body) : {};
    adminType = body.admin_type;

    // Validate admin_type
    const validAdminTypes = ['admin', 'user_admin', 'subscriber_admin', 'vote_admin'];
    if (!adminType || !validAdminTypes.includes(adminType)) {
      return badRequest('Invalid admin type. Must be one of: admin, user_admin, subscriber_admin, vote_admin');
    }
  } catch (error: any) {
    return badRequest(error.message || 'Invalid input');
  }

  try {
    // Check if user exists
    try {
      await cognito.send(new AdminGetUserCommand({
        UserPoolId: USER_POOL_ID,
        Username: email
      }));
    } catch (error: any) {
      if (error.name === 'UserNotFoundException') {
        return badRequest("User not found");
      }
      throw error;
    }

    // Update admin type
    await cognito.send(new AdminUpdateUserAttributesCommand({
      UserPoolId: USER_POOL_ID,
      Username: email,
      UserAttributes: [
        { Name: 'custom:admin_type', Value: adminType }
      ]
    }));

    await putAudit({
      type: "admin_type_updated",
      email: email,
      new_admin_type: adminType,
      updated_by: adminEmail
    });

    return ok({
      message: "Admin type updated successfully",
      email: email,
      admin_type: adminType
    });
  } catch (error: any) {
    console.error('Error updating admin type:', error);
    throw error;
  }
};
