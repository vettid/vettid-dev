import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ok, badRequest, putAudit, requireAdminGroup, validateOrigin } from "../../common/util";
import { CognitoIdentityProviderClient, AdminEnableUserCommand, AdminGetUserCommand } from "@aws-sdk/client-cognito-identity-provider";

const cognito = new CognitoIdentityProviderClient({});
const USER_POOL_ID = process.env.USER_POOL_ID!;

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

  try {
    // Check if user exists and get their status
    let userEnabled = false;
    try {
      const userResult = await cognito.send(new AdminGetUserCommand({
        UserPoolId: USER_POOL_ID,
        Username: decodedEmail
      }));
      userEnabled = userResult.Enabled || false;
    } catch (error: any) {
      if (error.name === 'UserNotFoundException') {
        return badRequest("User not found");
      }
      throw error;
    }

    // Check if already enabled
    if (userEnabled) {
      return badRequest("User is already enabled");
    }

    // Enable the admin user in Cognito
    await cognito.send(new AdminEnableUserCommand({
      UserPoolId: USER_POOL_ID,
      Username: decodedEmail
    }));

    await putAudit({
      type: "admin_enabled",
      email: decodedEmail,
      enabled_by: adminEmail
    });

    return ok({
      message: "Admin user enabled successfully",
      email: decodedEmail
    });
  } catch (error: any) {
    console.error('Error enabling admin user:', error);
    throw error;
  }
};
