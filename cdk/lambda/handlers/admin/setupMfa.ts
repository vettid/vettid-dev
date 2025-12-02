import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import {
  ok,
  badRequest,
  internalError,
  requireAdminGroup,
  getAdminEmail
} from "../../common/util";
import {
  CognitoIdentityProviderClient,
  AdminGetUserCommand
} from "@aws-sdk/client-cognito-identity-provider";

const cognito = new CognitoIdentityProviderClient({});
const USER_POOL_ID = process.env.ADMIN_USER_POOL_ID!;

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Validate admin group membership
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  const method = event.requestContext.http.method;

  // Get the admin's email from JWT claims
  const adminEmail = getAdminEmail(event);
  if (!adminEmail || adminEmail === 'unknown@vettid.dev') {
    return badRequest("Could not determine admin email from token");
  }

  try {
    if (method === "GET") {
      // Check current MFA status using admin API
      const userResponse = await cognito.send(new AdminGetUserCommand({
        UserPoolId: USER_POOL_ID,
        Username: adminEmail
      }));

      const mfaEnabled = userResponse.UserMFASettingList?.includes('SOFTWARE_TOKEN_MFA') || false;

      return ok({
        mfa_enabled: mfaEnabled,
        mfa_type: mfaEnabled ? 'TOTP' : null
      });

    } else if (method === "POST") {
      // MFA setup via the hosted UI is required
      // When MFA is set to REQUIRED on the user pool, users will be prompted during sign-in
      return ok({
        message: "To set up MFA, please sign out and sign back in. You will be prompted to configure your authenticator app during the sign-in process.",
        setup_required: true
      });
    }

    return badRequest("Method not allowed");

  } catch (error: any) {
    console.error("MFA status check error:", error);

    if (error.name === 'UserNotFoundException') {
      return badRequest("User not found.");
    }

    return internalError("Failed to check MFA status");
  }
};
