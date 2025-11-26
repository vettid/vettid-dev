import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ok, badRequest, putAudit, requireAdminGroup, validateOrigin } from "../../common/util";
import { CognitoIdentityProviderClient, AdminRemoveUserFromGroupCommand, AdminGetUserCommand, AdminDeleteUserCommand } from "@aws-sdk/client-cognito-identity-provider";

const cognito = new CognitoIdentityProviderClient({});
const USER_POOL_ID = process.env.USER_POOL_ID!;
const ADMIN_GROUP = process.env.ADMIN_GROUP || "admin";

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Validate admin group membership
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  // CSRF protection: Validate request origin
  const csrfError = validateOrigin(event);
  if (csrfError) return csrfError;

  const email = event.pathParameters?.email;

  if (!email) {
    return badRequest("Email is required");
  }

  const decodedEmail = decodeURIComponent(email).toLowerCase();
  const adminEmail = (event.requestContext as any)?.authorizer?.jwt?.claims?.email || "unknown@vettid.dev";

  // Prevent removing yourself
  if (decodedEmail === adminEmail.toLowerCase()) {
    return badRequest("You cannot remove your own admin privileges");
  }

  try {
    // Check if user exists
    try {
      await cognito.send(new AdminGetUserCommand({
        UserPoolId: USER_POOL_ID,
        Username: decodedEmail
      }));
    } catch (error: any) {
      if (error.name === 'UserNotFoundException') {
        return badRequest("User not found");
      }
      throw error;
    }

    // Remove user from admin group
    await cognito.send(new AdminRemoveUserFromGroupCommand({
      UserPoolId: USER_POOL_ID,
      Username: decodedEmail,
      GroupName: ADMIN_GROUP
    }));

    // Delete the Cognito user account entirely
    await cognito.send(new AdminDeleteUserCommand({
      UserPoolId: USER_POOL_ID,
      Username: decodedEmail
    }));

    await putAudit({
      type: "admin_removed",
      email: decodedEmail,
      removed_by: adminEmail
    });

    return ok({
      message: "Admin user deleted successfully",
      email: decodedEmail
    });
  } catch (error: any) {
    console.error('Error removing admin user:', error);
    throw error;
  }
};
