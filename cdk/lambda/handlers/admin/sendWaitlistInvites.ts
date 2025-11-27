import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, PutItemCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { SESClient, SendEmailCommand, GetIdentityVerificationAttributesCommand, VerifyEmailIdentityCommand } from '@aws-sdk/client-ses';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import { randomBytes } from 'crypto';
import { ok, forbidden, badRequest, internalError, getRequestId, putAudit, validateOrigin, requireAdminGroup } from '../../common/util';

const ddb = new DynamoDBClient({});
const ses = new SESClient({});

const TABLE_WAITLIST = process.env.TABLE_WAITLIST!;
const TABLE_INVITES = process.env.TABLE_INVITES!;
const TABLE_AUDIT = process.env.TABLE_AUDIT!;
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
        // Get waitlist entry
        const waitlistResult = await ddb.send(new GetItemCommand({
          TableName: TABLE_WAITLIST,
          Key: marshall({ waitlist_id: waitlistId }),
        }));

        if (!waitlistResult.Item) {
          results.failed.push({
            waitlist_id: waitlistId,
            email: 'unknown',
            error: 'Waitlist entry not found',
          });
          continue;
        }

        const waitlistEntry = unmarshall(waitlistResult.Item);
        email = waitlistEntry.email || 'unknown';
        const first_name = waitlistEntry.first_name || '';
        const last_name = waitlistEntry.last_name || '';

        // Generate invite code (8 characters, alphanumeric)
        const inviteCode = randomBytes(4).toString('hex').toUpperCase();

        // Create invite in DynamoDB (expires in 7 days, max 1 use)
        const now = new Date();
        const expiresAt = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000); // 7 days from now

        await ddb.send(new PutItemCommand({
          TableName: TABLE_INVITES,
          Item: marshall({
            code: inviteCode,
            status: 'active',
            expires_at: Math.floor(expiresAt.getTime() / 1000), // Unix timestamp in seconds
            max_uses: 1,
            used: 0,
            created_by: adminEmail,
            created_at: now.toISOString(),
            waitlist_id: waitlistId,
            auto_approve: true, // Waitlist invitees are auto-approved
          }),
        }));

        // Check SES verification status in sandbox mode
        // If pending, trigger new verification and provide clear error
        const sesStatus = await checkSESVerificationStatus(email);
        if (sesStatus === 'Pending') {
          // Re-send verification email and fail with informative message
          await triggerSESVerification(email);
          results.failed.push({
            waitlist_id: waitlistId,
            email,
            error: 'Email verification pending. Verification email re-sent to recipient. They must click the verification link first.',
          });
          continue;
        } else if (sesStatus !== 'Success' && sesStatus !== 'NotStarted') {
          // Handle failed/temporary failure
          await triggerSESVerification(email);
          results.failed.push({
            waitlist_id: waitlistId,
            email,
            error: `SES verification ${sesStatus}. New verification email sent.`,
          });
          continue;
        }

        // Send email with invite code
        const registerUrl = `https://vettid.dev/register`;

        const emailParams = {
          Source: SES_FROM_EMAIL,
          Destination: {
            ToAddresses: [email],
          },
          Message: {
            Subject: {
              Data: 'Your VettID Invitation',
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
    .code-box { background: #f8f9fa; border: 2px dashed #ffc125; border-radius: 8px; padding: 20px; margin: 20px 0; text-align: center; }
    .code { font-size: 32px; font-weight: bold; color: #000; letter-spacing: 4px; font-family: 'Courier New', monospace; }
    .btn { display: inline-block; background: linear-gradient(135deg, #ffd940 0%, #ffc125 100%); color: #000; text-decoration: none; padding: 14px 28px; border-radius: 6px; font-weight: bold; margin: 20px 0; }
    .footer { background: #f8f9fa; padding: 20px; text-align: center; font-size: 12px; color: #666; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>You're Invited to VettID!</h1>
    </div>
    <div class="content">
      <p>Hi ${first_name} ${last_name},</p>
      <p>Great news! You've been selected from our waitlist to join VettID. We're excited to have you as part of our community.</p>
      <p>Here's your personal invitation code:</p>
      <div class="code-box">
        <div class="code">${inviteCode}</div>
      </div>
      <p>This code is valid for 7 days and can be used once to create your VettID account.</p>
      <p style="text-align: center;">
        <a href="${registerUrl}" class="btn">Register Now</a>
      </p>
      <p><strong>How to register:</strong></p>
      <ol>
        <li>Click the "Register Now" button above (or visit ${registerUrl})</li>
        <li>Enter your information</li>
        <li>Use the invitation code shown above</li>
        <li>Submit your registration</li>
      </ol>
      <p>If you have any questions, feel free to reply to this email.</p>
      <p>Welcome to VettID!</p>
    </div>
    <div class="footer">
      <p>&copy; ${new Date().getFullYear()} VettID. All rights reserved.</p>
      <p>This is an automated message. Please do not reply to this email address.</p>
    </div>
  </div>
</body>
</html>
                `,
              },
              Text: {
                Data: `Hi ${first_name} ${last_name},\n\nYou've been selected from our waitlist to join VettID!\n\nYour invitation code: ${inviteCode}\n\nThis code is valid for 7 days and can be used once.\n\nRegister at: ${registerUrl}\n\nWelcome to VettID!`,
              },
            },
          },
        };

        await ses.send(new SendEmailCommand(emailParams));

        // Mark waitlist entry as invited
        await ddb.send(new UpdateItemCommand({
          TableName: TABLE_WAITLIST,
          Key: marshall({ waitlist_id: waitlistId }),
          UpdateExpression: 'SET invited_at = :invited_at, invite_code = :code, #st = :status, invited_by = :invited_by',
          ExpressionAttributeNames: {
            '#st': 'status',
          },
          ExpressionAttributeValues: marshall({
            ':invited_at': now.toISOString(),
            ':code': inviteCode,
            ':status': 'invited',
            ':invited_by': adminEmail || 'unknown',
          }),
        }));

        // Log to audit
        await putAudit({
          action: 'waitlist_invite_sent',
          admin_email: adminEmail,
          waitlist_id: waitlistId,
          recipient_email: email,
          invite_code: inviteCode,
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
    return internalError(error.message || 'Failed to send invites');
  }
};
