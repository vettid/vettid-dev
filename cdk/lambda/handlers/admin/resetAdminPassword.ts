import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ok, badRequest, requireAdminGroup, validateOrigin, putAudit, ses, checkRateLimit, hashIdentifier, tooManyRequests } from "../../common/util";
import { CognitoIdentityProviderClient, AdminGetUserCommand, AdminSetUserPasswordCommand } from "@aws-sdk/client-cognito-identity-provider";
import { SendEmailCommand } from "@aws-sdk/client-ses";
import { randomBytes } from "crypto";

const cognito = new CognitoIdentityProviderClient({});
const USER_POOL_ID = process.env.ADMIN_USER_POOL_ID!;

// Generate a secure temporary password
function generateTemporaryPassword(): string {
  // Generate 16 random bytes and convert to base64, then clean up for password requirements
  const password = randomBytes(16).toString('base64')
    .replace(/\+/g, 'A')
    .replace(/\//g, 'b')
    .replace(/=/g, '');

  // Ensure it meets Cognito password requirements (uppercase, lowercase, number, special char)
  return `Temp${password}!`;
}

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Validate admin group membership
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  // CSRF protection: Validate request origin
  const csrfError = validateOrigin(event);
  if (csrfError) return csrfError;

  const email = event.pathParameters?.username;
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

    // Generate a secure temporary password
    const temporaryPassword = generateTemporaryPassword();

    // Set the temporary password in Cognito (user will be forced to change it on first login)
    await cognito.send(new AdminSetUserPasswordCommand({
      UserPoolId: USER_POOL_ID,
      Username: decodedEmail,
      Password: temporaryPassword,
      Permanent: false // This forces password change on next login
    }));

    // Send email with temporary password
    await ses.send(new SendEmailCommand({
      Source: 'VettID Admin <noreply@vettid.dev>',
      Destination: {
        ToAddresses: [decodedEmail]
      },
      Message: {
        Subject: {
          Data: 'VettID Admin - Password Reset'
        },
        Body: {
          Html: {
            Data: `
              <html>
                <body style="font-family: Arial, sans-serif; color: #333; line-height: 1.6;">
                  <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #ffc125;">Password Reset Request</h2>
                    <p>Hello ${fullName},</p>
                    <p>An administrator has reset your VettID Admin password.</p>
                    <div style="background: #f5f5f5; padding: 15px; border-left: 4px solid #ffc125; margin: 20px 0;">
                      <p style="margin: 0;"><strong>Temporary Password:</strong></p>
                      <p style="margin: 10px 0 0 0; font-family: monospace; font-size: 1.1em; color: #000;">${temporaryPassword}</p>
                    </div>
                    <p>To sign in:</p>
                    <ol>
                      <li>Go to <a href="https://admin.vettid.dev" style="color: #ffc125;">https://admin.vettid.dev</a></li>
                      <li>Enter your email: <strong>${decodedEmail}</strong></li>
                      <li>Enter the temporary password above</li>
                      <li>You will be prompted to create a new password</li>
                    </ol>
                    <div style="background: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin: 20px 0;">
                      <p style="margin: 0; color: #856404;"><strong>⚠️ Security Notice:</strong></p>
                      <p style="margin: 10px 0 0 0; color: #856404;">This is a temporary password. You will be required to create a new password when you sign in.</p>
                    </div>
                    <p style="color: #666; font-size: 0.9em; margin-top: 30px; border-top: 1px solid #ddd; padding-top: 15px;">
                      If you did not request this password reset, please contact your system administrator immediately.
                    </p>
                  </div>
                </body>
              </html>
            `
          },
          Text: {
            Data: `
VettID Admin - Password Reset

Hello ${fullName},

An administrator has reset your VettID Admin password.

Temporary Password: ${temporaryPassword}

To sign in:
1. Go to https://admin.vettid.dev
2. Enter your email: ${decodedEmail}
3. Enter the temporary password above
4. You will be prompted to create a new password

⚠️ SECURITY NOTICE: This is a temporary password. You will be required to create a new password when you sign in.

If you did not request this password reset, please contact your system administrator immediately.
            `
          }
        }
      }
    }));

    await putAudit({
      type: "admin_password_reset",
      email: decodedEmail,
      reset_by: adminEmail,
      reset_at: new Date().toISOString()
    });

    return ok({
      message: "Temporary password sent. User must change password on first login.",
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
