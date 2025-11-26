import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ok, badRequest, requireAdminGroup, validateOrigin } from "../../common/util";
import {
  CognitoIdentityProviderClient,
  AdminInitiateAuthCommand,
  ChangePasswordCommand,
  AuthFlowType
} from "@aws-sdk/client-cognito-identity-provider";

const cognito = new CognitoIdentityProviderClient({});
const USER_POOL_ID = process.env.USER_POOL_ID!;
const CLIENT_ID = process.env.CLIENT_ID!;

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Validate admin group membership (or any authenticated user)
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  // CSRF protection: Validate request origin
  const csrfError = validateOrigin(event);
  if (csrfError) return csrfError;

  // Get user email from JWT claims
  const claims = (event.requestContext as any)?.authorizer?.jwt?.claims;
  const email = claims?.email;

  if (!email) {
    return badRequest('Unable to identify user from authentication token');
  }

  let currentPassword: string;
  let newPassword: string;

  try {
    const body = event.body ? JSON.parse(event.body) : {};
    currentPassword = body.currentPassword;
    newPassword = body.newPassword;

    if (!currentPassword || !newPassword) {
      return badRequest('Current password and new password are required');
    }

    // Validate password strength
    if (newPassword.length < 8) {
      return badRequest('Password must be at least 8 characters long');
    }

  } catch (error: any) {
    return badRequest(error.message || 'Invalid input');
  }

  try {
    // Step 1: Re-authenticate with current password to get fresh access token
    // This provides defense in depth - even if existing token is compromised,
    // attacker cannot change password without knowing current password
    const authResponse = await cognito.send(new AdminInitiateAuthCommand({
      UserPoolId: USER_POOL_ID,
      ClientId: CLIENT_ID,
      AuthFlow: AuthFlowType.ADMIN_NO_SRP_AUTH,
      AuthParameters: {
        USERNAME: email,
        PASSWORD: currentPassword
      }
    }));

    const freshAccessToken = authResponse.AuthenticationResult?.AccessToken;

    if (!freshAccessToken) {
      return badRequest('Authentication failed - unable to verify current password');
    }

    // Step 2: Use the fresh access token to change password
    await cognito.send(new ChangePasswordCommand({
      AccessToken: freshAccessToken,
      PreviousPassword: currentPassword,
      ProposedPassword: newPassword
    }));

    return ok({
      message: "Password changed successfully"
    });
  } catch (error: any) {
    console.error('Error changing password:', error);

    // Return user-friendly error messages
    if (error.name === 'NotAuthorizedException') {
      return badRequest('Current password is incorrect');
    } else if (error.name === 'InvalidPasswordException') {
      return badRequest('New password does not meet requirements');
    } else if (error.name === 'LimitExceededException') {
      return badRequest('Too many password change attempts. Please try again later');
    } else if (error.name === 'UserNotFoundException') {
      return badRequest('User not found');
    }

    throw error;
  }
};
