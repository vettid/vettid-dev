import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ok, badRequest, requireAdminGroup, validateOrigin, putAudit, ses, checkRateLimit, hashIdentifier, tooManyRequests } from "../../common/util";
import { CognitoIdentityProviderClient, AdminGetUserCommand } from "@aws-sdk/client-cognito-identity-provider";
import { SendEmailCommand } from "@aws-sdk/client-ses";

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
  const adminEmail = (event.requestContext as any)?.authorizer?.jwt?.claims?.email || "unknown@vettid.dev";

  if (!email) {
    return badRequest("Email is required");
  }

  // Rate limiting: Max 5 password resets per admin per hour
  const adminHash = hashIdentifier(adminEmail);
  const isAllowed = await checkRateLimit(adminHash, 'password_reset', 5, 60);
  if (!isAllowed) {
    return tooManyRequests("Too many password reset requests. Please try again later.");
  }

  const decodedEmail = decodeURIComponent(email).toLowerCase();

  try {
    // Check if user exists
    const userResponse = await cognito.send(new AdminGetUserCommand({
      UserPoolId: USER_POOL_ID,
      Username: decodedEmail
    }));

    const givenName = userResponse.UserAttributes?.find(a => a.Name === 'given_name')?.Value || '';
    const familyName = userResponse.UserAttributes?.find(a => a.Name === 'family_name')?.Value || '';
    const fullName = `${givenName} ${familyName}`.trim() || decodedEmail;

    // SECURITY: Instead of sending temporary password via email, send a magic link
    // Admin users use the same magic link authentication flow as regular users
    // The magic link will be generated when they click "Sign in" on the admin portal

    // Send email notifying user to use magic link
    await ses.send(new SendEmailCommand({
      Source: 'VettID Admin <noreply@vettid.dev>',
      Destination: {
        ToAddresses: [decodedEmail]
      },
      Message: {
        Subject: {
          Data: 'Your VettID Admin Access - Sign In Required'
        },
        Body: {
          Html: {
            Data: `
              <html>
                <body style="font-family: Arial, sans-serif; color: #333; line-height: 1.6;">
                  <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #ffc125;">VettID Admin Access</h2>
                    <p>Hello ${fullName},</p>
                    <p>An administrator has requested that you sign in to VettID Admin.</p>
                    <p>To sign in:</p>
                    <ol>
                      <li>Go to <a href="https://admin.vettid.dev" style="color: #ffc125;">https://admin.vettid.dev</a></li>
                      <li>Click "Sign in"</li>
                      <li>Enter your email address: <strong>${decodedEmail}</strong></li>
                      <li>You will receive a magic link to complete sign-in securely</li>
                    </ol>
                    <div style="background: #f5f5f5; padding: 15px; border-left: 4px solid #ffc125; margin: 20px 0;">
                      <p style="margin: 0;"><strong>No password required!</strong></p>
                      <p style="margin: 10px 0 0 0; color: #666;">VettID uses secure magic links for authentication. You'll receive a one-time sign-in link via email.</p>
                    </div>
                    <p style="color: #666; font-size: 0.9em; margin-top: 30px; border-top: 1px solid #ddd; padding-top: 15px;">
                      If you did not expect this email or have concerns, please contact your system administrator.
                    </p>
                  </div>
                </body>
              </html>
            `
          },
          Text: {
            Data: `
VettID Admin Access

Hello ${fullName},

An administrator has requested that you sign in to VettID Admin.

To sign in:
1. Go to https://admin.vettid.dev
2. Click "Sign in"
3. Enter your email address: ${decodedEmail}
4. You will receive a magic link to complete sign-in securely

No password required! VettID uses secure magic links for authentication.
You'll receive a one-time sign-in link via email.

If you did not expect this email or have concerns, please contact your system administrator.
            `
          }
        }
      }
    }));

    await putAudit({
      type: "admin_access_notification",
      email: decodedEmail,
      requested_by: adminEmail
    });

    return ok({
      message: "Sign-in notification sent. User will receive magic link when they sign in.",
      email: decodedEmail
    });
  } catch (error: any) {
    console.error('Error resetting admin password:', error);

    if (error.name === 'UserNotFoundException') {
      return badRequest("User not found");
    }

    throw error;
  }
};
