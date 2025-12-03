import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ok, badRequest, putAudit, requireAdminGroup, validateOrigin, checkRateLimit, hashIdentifier, tooManyRequests, getAdminEmail, internalError, ddb, ses, escapeHtml } from "../../common/util";
import { SESClient, GetIdentityVerificationAttributesCommand, SendEmailCommand } from "@aws-sdk/client-ses";
import { GetItemCommand, DeleteItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import { CognitoIdentityProviderClient, AdminCreateUserCommand, AdminAddUserToGroupCommand, AdminSetUserPasswordCommand } from "@aws-sdk/client-cognito-identity-provider";
import { randomBytes } from "crypto";

const sesClient = new SESClient({});
const cognito = new CognitoIdentityProviderClient({});
const PENDING_ADMINS_TABLE = process.env.PENDING_ADMINS_TABLE!;
const USER_POOL_ID = process.env.ADMIN_USER_POOL_ID!;
const ADMIN_GROUP = process.env.ADMIN_GROUP || "admin";

// Generate a secure temporary password
function generateTemporaryPassword(): string {
  const password = randomBytes(16).toString('base64')
    .replace(/\+/g, 'A')
    .replace(/\//g, 'b')
    .replace(/=/g, '');
  return `Temp${password}!`;
}

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  const requestOrigin = event.headers?.origin || event.headers?.Origin;

  // Validate admin group membership
  const authError = requireAdminGroup(event, requestOrigin);
  if (authError) return authError;

  // CSRF protection
  const csrfError = validateOrigin(event);
  if (csrfError) return csrfError;

  // Rate limiting
  const callerEmail = getAdminEmail(event);
  const callerHash = hashIdentifier(callerEmail);
  const isAllowed = await checkRateLimit(callerHash, 'activate_admin', 10, 60);
  if (!isAllowed) {
    return tooManyRequests("Too many activation requests. Please try again later.", requestOrigin);
  }

  const email = event.pathParameters?.email;
  if (!email) {
    return badRequest("Email is required", requestOrigin);
  }

  const decodedEmail = decodeURIComponent(email).toLowerCase();
  const activatedBy = getAdminEmail(event);

  try {
    // Get the pending admin record
    const pendingResult = await ddb.send(new GetItemCommand({
      TableName: PENDING_ADMINS_TABLE,
      Key: marshall({ email: decodedEmail })
    }));

    if (!pendingResult.Item) {
      return badRequest("No pending invitation found for this email", requestOrigin);
    }

    const pendingAdmin = unmarshall(pendingResult.Item);

    // Check SES verification status
    const verificationStatus = await sesClient.send(new GetIdentityVerificationAttributesCommand({
      Identities: [decodedEmail]
    }));

    const sesStatus = verificationStatus.VerificationAttributes?.[decodedEmail]?.VerificationStatus;

    if (sesStatus !== 'Success') {
      return badRequest(
        `Email not yet verified in SES. Current status: ${sesStatus || 'Not started'}. ` +
        "The recipient must click the verification link in their email before you can activate their account.",
        requestOrigin
      );
    }

    // Create the Cognito user
    await cognito.send(new AdminCreateUserCommand({
      UserPoolId: USER_POOL_ID,
      Username: decodedEmail,
      MessageAction: 'SUPPRESS', // We'll send our own email with temp password
      UserAttributes: [
        { Name: 'email', Value: decodedEmail },
        { Name: 'email_verified', Value: 'true' },
        { Name: 'given_name', Value: pendingAdmin.first_name },
        { Name: 'family_name', Value: pendingAdmin.last_name },
        { Name: 'custom:admin_type', Value: pendingAdmin.admin_type }
      ]
    }));

    // Add user to admin group
    await cognito.send(new AdminAddUserToGroupCommand({
      UserPoolId: USER_POOL_ID,
      Username: decodedEmail,
      GroupName: ADMIN_GROUP
    }));

    // Generate and set temporary password
    const temporaryPassword = generateTemporaryPassword();
    await cognito.send(new AdminSetUserPasswordCommand({
      UserPoolId: USER_POOL_ID,
      Username: decodedEmail,
      Password: temporaryPassword,
      Permanent: false // Forces password change on first login
    }));

    // Send welcome email with temporary password
    const fullName = `${pendingAdmin.first_name} ${pendingAdmin.last_name}`.trim();
    await ses.send(new SendEmailCommand({
      Source: 'VettID Admin <noreply@vettid.dev>',
      Destination: {
        ToAddresses: [decodedEmail]
      },
      Message: {
        Subject: {
          Data: 'Welcome to VettID Admin Portal'
        },
        Body: {
          Html: {
            Data: `
              <html>
                <body style="font-family: Arial, sans-serif; color: #333; line-height: 1.6;">
                  <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #ffc125;">Welcome to VettID Admin</h2>
                    <p>Hello ${escapeHtml(fullName)},</p>
                    <p>Your VettID Admin account has been activated. You can now sign in to the admin portal.</p>
                    <div style="background: #f5f5f5; padding: 15px; border-left: 4px solid #ffc125; margin: 20px 0;">
                      <p style="margin: 0;"><strong>Your Temporary Password:</strong></p>
                      <p style="margin: 10px 0 0 0; font-family: monospace; font-size: 1.1em; color: #000;">${escapeHtml(temporaryPassword)}</p>
                    </div>
                    <p>To sign in:</p>
                    <ol>
                      <li>Go to <a href="https://admin.vettid.dev" style="color: #ffc125;">https://admin.vettid.dev</a></li>
                      <li>Enter your email: <strong>${escapeHtml(decodedEmail)}</strong></li>
                      <li>Enter the temporary password above</li>
                      <li>You will be prompted to create a new password</li>
                    </ol>
                    <div style="background: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin: 20px 0;">
                      <p style="margin: 0; color: #856404;"><strong>Security Notice:</strong></p>
                      <p style="margin: 10px 0 0 0; color: #856404;">This is a temporary password. You will be required to create a new password when you first sign in.</p>
                    </div>
                    <p style="color: #666; font-size: 0.9em; margin-top: 30px; border-top: 1px solid #ddd; padding-top: 15px;">
                      If you did not expect this email, please contact your system administrator.
                    </p>
                  </div>
                </body>
              </html>
            `
          },
          Text: {
            Data: `
Welcome to VettID Admin

Hello ${fullName},

Your VettID Admin account has been activated. You can now sign in to the admin portal.

Your Temporary Password: ${temporaryPassword}

To sign in:
1. Go to https://admin.vettid.dev
2. Enter your email: ${decodedEmail}
3. Enter the temporary password above
4. You will be prompted to create a new password

SECURITY NOTICE: This is a temporary password. You will be required to create a new password when you first sign in.

If you did not expect this email, please contact your system administrator.
            `
          }
        }
      }
    }));

    // Delete the pending admin record
    await ddb.send(new DeleteItemCommand({
      TableName: PENDING_ADMINS_TABLE,
      Key: marshall({ email: decodedEmail })
    }));

    await putAudit({
      type: "admin_activated",
      email: decodedEmail,
      first_name: pendingAdmin.first_name,
      last_name: pendingAdmin.last_name,
      admin_type: pendingAdmin.admin_type,
      activated_by: activatedBy,
      invited_by: pendingAdmin.invited_by,
    });

    return ok({
      message: "Admin account activated successfully. Welcome email with temporary password has been sent.",
      email: decodedEmail,
    }, requestOrigin);

  } catch (error: any) {
    console.error('Error activating admin:', error);

    if (error.name === 'UsernameExistsException') {
      // Clean up the pending record since user already exists
      await ddb.send(new DeleteItemCommand({
        TableName: PENDING_ADMINS_TABLE,
        Key: marshall({ email: decodedEmail })
      }));
      return badRequest("This user already exists in the system.", requestOrigin);
    }

    return internalError('Failed to activate admin user', requestOrigin);
  }
};
