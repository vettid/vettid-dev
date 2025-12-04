import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ok, badRequest, internalError, requireAdminGroup, validateOrigin, putAudit, parseJsonBody, checkRateLimit, hashIdentifier, tooManyRequests } from "../../common/util";
import { CognitoIdentityProviderClient, ChangePasswordCommand } from "@aws-sdk/client-cognito-identity-provider";

const cognito = new CognitoIdentityProviderClient({});

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Validate admin group membership
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  // CSRF protection: Validate request origin
  const csrfError = validateOrigin(event);
  if (csrfError) return csrfError;

  const adminEmail = (event.requestContext as any)?.authorizer?.jwt?.claims?.email || "unknown@vettid.dev";

  // Rate limiting: Max 5 password changes per admin per hour
  const adminHash = hashIdentifier(adminEmail);
  const isAllowed = await checkRateLimit(adminHash, 'change_password', 5, 60);
  if (!isAllowed) {
    return tooManyRequests("Too many password change attempts. Please try again later.");
  }

  // Parse request body
  const body = parseJsonBody(event);
  const { currentPassword, newPassword } = body;

  if (!currentPassword || typeof currentPassword !== 'string') {
    return badRequest("Current password is required");
  }

  if (!newPassword || typeof newPassword !== 'string') {
    return badRequest("New password is required");
  }

  // Validate new password strength
  if (newPassword.length < 8) {
    return badRequest("New password must be at least 8 characters long");
  }

  // Get access token from Authorization header
  const authHeader = event.headers?.authorization || event.headers?.Authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return badRequest("Missing or invalid authorization header");
  }

  const accessToken = authHeader.substring(7); // Remove 'Bearer ' prefix

  try {
    // Change password using Cognito API
    await cognito.send(new ChangePasswordCommand({
      AccessToken: accessToken,
      PreviousPassword: currentPassword,
      ProposedPassword: newPassword
    }));

    // Log password change in audit trail
    await putAudit({
      type: "admin_password_changed",
      email: adminEmail,
      changed_at: new Date().toISOString()
    });

    return ok({
      message: "Password changed successfully"
    });
  } catch (error: any) {
    console.error('Error changing password:', error);

    // Handle specific Cognito errors
    if (error.name === 'NotAuthorizedException') {
      return badRequest("Current password is incorrect");
    }

    if (error.name === 'InvalidPasswordException') {
      return badRequest("New password does not meet security requirements");
    }

    if (error.name === 'LimitExceededException') {
      return badRequest("Too many attempts. Please try again later.");
    }

    return internalError("Failed to change password");
  }
};
