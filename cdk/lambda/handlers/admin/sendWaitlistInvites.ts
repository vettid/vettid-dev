import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, ScanCommand, PutItemCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { SESClient, SendEmailCommand, GetIdentityVerificationAttributesCommand, VerifyEmailIdentityCommand } from '@aws-sdk/client-ses';
import { CognitoIdentityProviderClient, AdminCreateUserCommand, AdminAddUserToGroupCommand, AdminGetUserCommand } from '@aws-sdk/client-cognito-identity-provider';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import { randomBytes, randomUUID } from 'crypto';
import { ok, forbidden, badRequest, internalError, getRequestId, putAudit, validateOrigin, requireAdminGroup, sanitizeErrorForClient } from '../../common/util';

const ddb = new DynamoDBClient({});
const ses = new SESClient({});
const cognito = new CognitoIdentityProviderClient({});

const TABLE_WAITLIST = process.env.TABLE_WAITLIST!;
const TABLE_INVITES = process.env.TABLE_INVITES!;
const TABLE_REGISTRATIONS = process.env.TABLE_REGISTRATIONS!;
const USER_POOL_ID = process.env.USER_POOL_ID!;
const REGISTERED_GROUP = process.env.REGISTERED_GROUP || 'registered';
const SES_FROM_EMAIL = process.env.SES_FROM_EMAIL || 'noreply@vettid.dev';

/**
 * Check if email is verified in SES sandbox mode
 * Returns: 'Success' | 'Pending' | 'NotStarted' | 'Failed' | 'TemporaryFailure'
 */
async function checkSESVerificationStatus(email: string): Promise<string> {
  try {
    const result = await ses.send(new GetIdentityVerificationAttributesCommand({
      Identities: [email]
    }));
    return result.VerificationAttributes?.[email]?.VerificationStatus || 'NotStarted';
  } catch {
    return 'NotStarted';
  }
}

/**
 * Trigger SES email verification (for sandbox mode)
 * Only useful if account is in SES sandbox
 */
async function triggerSESVerification(email: string): Promise<boolean> {
  try {
    await ses.send(new VerifyEmailIdentityCommand({ EmailAddress: email }));
    return true;
  } catch (error) {
    console.error(`Failed to trigger SES verification for ${email}:`, error);
    return false;
  }
}

type SendInvitesRequest = {
  waitlist_ids: string[];
  custom_message?: string; // Optional custom message to include in email
};

/**
 * Send invite codes to selected waitlist users (admin only)
 * POST /admin/waitlist/send-invites
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  // Require admin group membership
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  const requestId = getRequestId(event);

  // CSRF protection
  const csrfError = validateOrigin(event);
  if (csrfError) return csrfError;

  try {
    // Verify admin group membership
    const claims = (event.requestContext as any)?.authorizer?.jwt?.claims;
    const groups = claims?.['cognito:groups'] || [];
    const adminEmail = claims?.email;

    if (!groups.includes('admin')) {
      return forbidden('Admin access required');
    }

    if (!event.body) {
      return badRequest('Missing request body');
    }

    let payload: SendInvitesRequest;
    try {
      payload = JSON.parse(event.body);
    } catch {
      return badRequest('Invalid JSON');
    }

    if (!payload.waitlist_ids || !Array.isArray(payload.waitlist_ids) || payload.waitlist_ids.length === 0) {
      return badRequest('waitlist_ids must be a non-empty array');
    }

    const results = {
      sent: [] as string[],
      failed: [] as { waitlist_id: string; email: string; error: string }[],
    };

    // Process each waitlist entry
    for (const waitlistId of payload.waitlist_ids) {
      let email = 'unknown';
      try {
        // Get waitlist entry by scanning for waitlist_id (since email is the partition key)
        const waitlistResult = await ddb.send(new ScanCommand({
          TableName: TABLE_WAITLIST,
          FilterExpression: 'waitlist_id = :wid',
          ExpressionAttributeValues: marshall({
            ':wid': waitlistId,
          }),
        }));

        if (!waitlistResult.Items || waitlistResult.Items.length === 0) {
          results.failed.push({
            waitlist_id: waitlistId,
            email: 'unknown',
            error: 'Waitlist entry not found',
          });
          continue;
        }

        const waitlistEntry = unmarshall(waitlistResult.Items[0]);
        email = waitlistEntry.email || 'unknown';
        const first_name = waitlistEntry.first_name || '';
        const last_name = waitlistEntry.last_name || '';
        const email_consent = waitlistEntry.email_consent || false;

        // Get custom message from request payload
        const customMessage = payload.custom_message?.trim() || '';

        const now = new Date();
        const nowIso = now.toISOString();

        // Check SES verification status - MUST be verified to proceed
        const sesStatus = await checkSESVerificationStatus(email);
        if (sesStatus !== 'Success') {
          // Email not verified - send/resend verification and fail
          await triggerSESVerification(email);
          const statusMessage = sesStatus === 'Pending'
            ? 'Email verification pending. Verification email re-sent.'
            : sesStatus === 'NotStarted'
            ? 'Email not verified. Verification email sent.'
            : `Email verification ${sesStatus}. New verification email sent.`;
          results.failed.push({
            waitlist_id: waitlistId,
            email,
            error: `${statusMessage} User must click the verification link before they can be approved.`,
          });
          continue;
        }

        // Check if user already exists in Cognito
        let cognitoUserExists = false;
        try {
          await cognito.send(new AdminGetUserCommand({
            UserPoolId: USER_POOL_ID,
            Username: email
          }));
          cognitoUserExists = true;
        } catch (error: any) {
          if (error.name !== 'UserNotFoundException') {
            throw error;
          }
        }

        if (cognitoUserExists) {
          results.failed.push({
            waitlist_id: waitlistId,
            email,
            error: 'User already exists in Cognito. They may already be registered.',
          });
          continue;
        }

        // Check for existing registration
        const existingRegs = await ddb.send(new ScanCommand({
          TableName: TABLE_REGISTRATIONS,
          FilterExpression: 'email = :email AND #s <> :deleted AND #s <> :rejected',
          ExpressionAttributeNames: {
            '#s': 'status',
          },
          ExpressionAttributeValues: marshall({
            ':email': email,
            ':deleted': 'deleted',
            ':rejected': 'rejected',
          }),
          Limit: 1,
        }));

        if (existingRegs.Items && existingRegs.Items.length > 0) {
          results.failed.push({
            waitlist_id: waitlistId,
            email,
            error: 'User already has an active registration.',
          });
          continue;
        }

        // ============================================
        // AUTO-REGISTRATION: Create registration and Cognito user directly
        // ============================================

        const registrationId = randomUUID();
        const userGuid = randomUUID();

        // Create registration record (already approved)
        const registrationItem = {
          registration_id: registrationId,
          first_name,
          last_name,
          email,
          invite_code: `WAITLIST-${waitlistId.substring(0, 8)}`, // Synthetic code for tracking
          status: 'approved',
          membership_status: 'none',
          user_guid: userGuid,
          email_consent,
          created_at: nowIso,
          updated_at: nowIso,
          approved_at: nowIso,
          approved_by: adminEmail || 'waitlist-auto',
          waitlist_id: waitlistId, // Link back to waitlist entry
        };

        await ddb.send(new PutItemCommand({
          TableName: TABLE_REGISTRATIONS,
          Item: marshall(registrationItem),
        }));

        // Create Cognito user
        await cognito.send(new AdminCreateUserCommand({
          UserPoolId: USER_POOL_ID,
          Username: email,
          UserAttributes: [
            { Name: 'email', Value: email },
            { Name: 'email_verified', Value: 'true' },
            { Name: 'given_name', Value: first_name },
            { Name: 'family_name', Value: last_name },
            { Name: 'custom:user_guid', Value: userGuid },
          ],
          MessageAction: 'SUPPRESS', // Don't send Cognito welcome email
        }));

        // Add user to 'registered' group
        await cognito.send(new AdminAddUserToGroupCommand({
          UserPoolId: USER_POOL_ID,
          Username: email,
          GroupName: REGISTERED_GROUP,
        }));

        // HTML escape for email
        const escapeHtml = (str: string) => {
          return str
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
        };

        const customMessageHtml = customMessage
          ? `<div style="background:#f0f9ff;border-left:4px solid #0ea5e9;padding:16px;margin:20px 0;border-radius:4px;">
               <p style="margin:0;color:#0c4a6e;font-style:italic;">${escapeHtml(customMessage)}</p>
             </div>`
          : '';

        // Send "You're approved!" email (no invite code needed)
        const accountUrl = `https://vettid.dev/account`;

        const emailParams = {
          Source: SES_FROM_EMAIL,
          Destination: {
            ToAddresses: [email],
          },
          Message: {
            Subject: {
              Data: 'Welcome to VettID - Your Account is Ready!',
            },
            Body: {
              Html: {
                Data: `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; margin: 0; padding: 0; }
    .container { max-width: 600px; margin: 20px auto; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
    .header { background: linear-gradient(135deg, #ffd940 0%, #ffc125 100%); padding: 30px; text-align: center; }
    .header h1 { margin: 0; color: #000; font-size: 28px; }
    .content { padding: 30px; }
    .success-box { background: #f0fdf4; border: 2px solid #22c55e; border-radius: 8px; padding: 20px; margin: 20px 0; text-align: center; }
    .success-icon { font-size: 48px; margin-bottom: 10px; }
    .btn { display: inline-block; background: linear-gradient(135deg, #ffd940 0%, #ffc125 100%); color: #000; text-decoration: none; padding: 14px 28px; border-radius: 6px; font-weight: bold; margin: 20px 0; }
    .footer { background: #f8f9fa; padding: 20px; text-align: center; font-size: 12px; color: #666; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Welcome to VettID!</h1>
    </div>
    <div class="content">
      <p>Hi ${escapeHtml(first_name)} ${escapeHtml(last_name)},</p>
      <p>Great news! Your VettID account has been approved and is ready to use.</p>
      ${customMessageHtml}
      <div class="success-box">
        <div class="success-icon">&#10003;</div>
        <p style="margin:0;font-weight:bold;color:#166534;">Your account is active!</p>
      </div>
      <p>You can now sign in to VettID using your email address. We use passwordless authentication, so you'll receive a magic link each time you sign in.</p>
      <p style="text-align: center;">
        <a href="${accountUrl}" class="btn">Sign In Now</a>
      </p>
      <p><strong>What's next?</strong></p>
      <ol>
        <li>Click "Sign In Now" above (or visit ${accountUrl})</li>
        <li>Enter your email address: <strong>${escapeHtml(email)}</strong></li>
        <li>Check your inbox for a magic link</li>
        <li>Click the link to sign in securely</li>
      </ol>
      <p>If you have any questions, feel free to reach out to our support team.</p>
      <p>Welcome aboard!</p>
    </div>
    <div class="footer">
      <p>&copy; ${new Date().getFullYear()} VettID. All rights reserved.</p>
    </div>
  </div>
</body>
</html>
                `,
              },
              Text: {
                Data: `Hi ${first_name} ${last_name},\n\nGreat news! Your VettID account has been approved and is ready to use.\n${customMessage ? `\n${customMessage}\n` : ''}\nYou can now sign in at: ${accountUrl}\n\nUse your email address (${email}) to sign in. We'll send you a magic link - no password needed!\n\nWelcome to VettID!`,
              },
            },
          },
        };

        await ses.send(new SendEmailCommand(emailParams));

        // Mark waitlist entry as approved (using email as partition key)
        await ddb.send(new UpdateItemCommand({
          TableName: TABLE_WAITLIST,
          Key: marshall({ email }),
          UpdateExpression: 'SET approved_at = :approved_at, #st = :status, approved_by = :approved_by, registration_id = :reg_id',
          ExpressionAttributeNames: {
            '#st': 'status',
          },
          ExpressionAttributeValues: marshall({
            ':approved_at': nowIso,
            ':status': 'approved',
            ':approved_by': adminEmail || 'unknown',
            ':reg_id': registrationId,
          }),
        }));

        // Log to audit
        await putAudit({
          type: 'waitlist_auto_approved',
          email: adminEmail,
          admin_email: adminEmail,
          waitlist_id: waitlistId,
          recipient_email: email,
          registration_id: registrationId,
          user_guid: userGuid,
        }, requestId);

        results.sent.push(email);

      } catch (error: any) {
        console.error(`Error processing waitlist ID ${waitlistId}:`, error);
        results.failed.push({
          waitlist_id: waitlistId,
          email,
          error: error.message || 'Unknown error',
        });
      }
    }

    return ok({
      message: `Sent ${results.sent.length} invites, ${results.failed.length} failed`,
      sent: results.sent,
      failed: results.failed,
    });

  } catch (error: any) {
    console.error('Error sending waitlist invites:', error);
    return internalError(sanitizeErrorForClient(error, 'Failed to send invites'));
  }
};
