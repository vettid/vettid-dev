import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, PutItemCommand, QueryCommand } from '@aws-sdk/client-dynamodb';
import { SESClient, VerifyEmailIdentityCommand, SendEmailCommand } from '@aws-sdk/client-ses';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import { randomUUID } from 'crypto';
import { validateEmail, validateName, checkRateLimit, hashIdentifier, getClientIp, escapeHtml } from '../../common/util';

const ddb = new DynamoDBClient({});
const ses = new SESClient({});

// Rate limit: 5 waitlist submissions per IP per hour
const RATE_LIMIT_MAX_REQUESTS = 5;
const RATE_LIMIT_WINDOW_MINUTES = 60;

const TABLE_WAITLIST = process.env.TABLE_WAITLIST!;
const TABLE_NOTIFICATION_PREFERENCES = process.env.TABLE_NOTIFICATION_PREFERENCES!;
const SES_FROM = process.env.SES_FROM || 'no-reply@vettid.dev';
// SECURITY: Remove wildcard default - CORS_ORIGIN must be explicitly set or use allowed list
const CORS_ORIGIN = process.env.CORS_ORIGIN || '';

type WaitlistRequest = {
  first_name?: string;
  last_name?: string;
  email?: string;
  email_consent?: boolean;
};

// SECURITY: Strict CORS - only allow specific origins
const ALLOWED_ORIGINS = [
  'https://register.vettid.dev',
  'https://vettid.dev',
  'https://www.vettid.dev',
  'https://admin.vettid.dev',
  'http://localhost:3000',
  'http://localhost:5173',
];

function corsHeaders(origin?: string): Record<string, string> {
  // Use env var if set (and not wildcard), otherwise use allowed list
  const envOrigins = CORS_ORIGIN && CORS_ORIGIN !== '*'
    ? CORS_ORIGIN.split(',').map(o => o.trim())
    : ALLOWED_ORIGINS;

  // SECURITY: Only allow explicitly listed origins
  let allowedOrigin: string;
  if (origin && envOrigins.includes(origin)) {
    allowedOrigin = origin;
  } else {
    // Default to primary domain - will cause CORS errors for unknown origins
    allowedOrigin = envOrigins.find(o => o !== '*') || 'https://register.vettid.dev';
  }

  return {
    'Access-Control-Allow-Origin': allowedOrigin,
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    'Access-Control-Allow-Methods': 'OPTIONS,POST',
    // SECURITY: Additional headers to prevent MIME type sniffing and other attacks
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-Permitted-Cross-Domain-Policies': 'none',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Content-Language': 'en',
    // SECURITY: Additional security headers for compliance
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Cache-Control': 'no-store, no-cache, must-revalidate',
  };
}

function jsonResponse(
  statusCode: number,
  body: unknown,
  origin?: string
): APIGatewayProxyResultV2 {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders(origin),
    },
    body: JSON.stringify(body),
  };
}

function badRequest(message: string, origin?: string): APIGatewayProxyResultV2 {
  return jsonResponse(400, { message }, origin);
}

async function sendWelcomeEmail(firstName: string, email: string): Promise<void> {
  try {
    await ses.send(
      new SendEmailCommand({
        Source: SES_FROM,
        Destination: {
          ToAddresses: [email],
        },
        Message: {
          Subject: {
            Data: 'Welcome to the VettID Waitlist!',
            Charset: 'UTF-8',
          },
          Body: {
            Html: {
              Data: `
                <!DOCTYPE html>
                <html>
                <head>
                  <meta charset="UTF-8">
                  <meta name="viewport" content="width=device-width, initial-scale=1.0">
                </head>
                <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
                  <div style="background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); padding: 30px; border-radius: 12px 12px 0 0; text-align: center;">
                    <h1 style="color: #ffc125; margin: 0; font-size: 28px;">Welcome to VettID!</h1>
                  </div>
                  <div style="background: #f8f9fa; padding: 30px; border-radius: 0 0 12px 12px; border: 1px solid #e9ecef; border-top: none;">
                    <p style="font-size: 16px; margin-top: 0;">Hi ${escapeHtml(firstName)},</p>
                    <p style="font-size: 16px;">Thank you for joining the VettID waitlist! We're excited to have you on board.</p>
                    <p style="font-size: 16px;">VettID is building the future of verified digital identity. As a waitlist member, you'll be among the first to know when we launch and may receive early access to our platform.</p>
                    <div style="background: #fff; border-left: 4px solid #ffc125; padding: 15px 20px; margin: 20px 0; border-radius: 0 8px 8px 0;">
                      <p style="margin: 0; font-size: 14px; color: #666;"><strong>What happens next?</strong></p>
                      <ul style="margin: 10px 0 0 0; padding-left: 20px; color: #666; font-size: 14px;">
                        <li>We'll notify you when invites become available</li>
                        <li>Early waitlist members get priority access</li>
                        <li>Stay tuned for updates and announcements</li>
                      </ul>
                    </div>
                    <p style="font-size: 16px; margin-bottom: 0;">Best regards,<br><strong>The VettID Team</strong></p>
                  </div>
                  <div style="text-align: center; padding: 20px; color: #999; font-size: 12px;">
                    <p style="margin: 0;">© ${new Date().getFullYear()} VettID. All rights reserved.</p>
                    <p style="margin: 5px 0 0 0;">You received this email because you joined the VettID waitlist.</p>
                  </div>
                </body>
                </html>
              `,
              Charset: 'UTF-8',
            },
            Text: {
              Data: `Hi ${firstName},

Thank you for joining the VettID waitlist! We're excited to have you on board.

VettID is building the future of verified digital identity. As a waitlist member, you'll be among the first to know when we launch and may receive early access to our platform.

What happens next?
- We'll notify you when invites become available
- Early waitlist members get priority access
- Stay tuned for updates and announcements

Best regards,
The VettID Team

© ${new Date().getFullYear()} VettID. All rights reserved.
You received this email because you joined the VettID waitlist.`,
              Charset: 'UTF-8',
            },
          },
        },
      })
    );
  } catch (error) {
    console.error('Failed to send welcome email:', error);
    // Don't fail the request if welcome email fails
  }
}

async function sendAdminNotifications(firstName: string, lastName: string, email: string): Promise<void> {
  try {
    // Query admin emails subscribed to waitlist notifications
    const result = await ddb.send(
      new QueryCommand({
        TableName: TABLE_NOTIFICATION_PREFERENCES,
        KeyConditionExpression: 'notification_type = :type',
        ExpressionAttributeValues: marshall({
          ':type': 'waitlist',
        }),
      })
    );

    if (!result.Items || result.Items.length === 0) {
      return;
    }

    const adminEmails = result.Items.map(item => unmarshall(item).admin_email as string);

    // Send email to each subscribed admin
    for (const adminEmail of adminEmails) {
      try {
        await ses.send(
          new SendEmailCommand({
            Source: SES_FROM,
            Destination: {
              ToAddresses: [adminEmail],
            },
            Message: {
              Subject: {
                Data: 'New Waitlist Signup - VettID',
                Charset: 'UTF-8',
              },
              Body: {
                Html: {
                  Data: `
                    <h2>New Waitlist Signup</h2>
                    <p>A new user has joined the VettID waitlist:</p>
                    <ul>
                      <li><strong>Name:</strong> ${escapeHtml(firstName)} ${escapeHtml(lastName)}</li>
                      <li><strong>Email:</strong> ${escapeHtml(email)}</li>
                      <li><strong>Time:</strong> ${new Date().toISOString()}</li>
                    </ul>
                    <p>You can manage waitlist entries in the <a href="https://admin.vettid.dev">Admin Portal</a>.</p>
                  `,
                  Charset: 'UTF-8',
                },
                Text: {
                  Data: `New Waitlist Signup\n\nA new user has joined the VettID waitlist:\n\nName: ${firstName} ${lastName}\nEmail: ${email}\nTime: ${new Date().toISOString()}\n\nManage waitlist entries at https://admin.vettid.dev`,
                  Charset: 'UTF-8',
                },
              },
            },
          })
        );
      } catch (emailError) {
        console.error(`Failed to send notification to ${adminEmail}:`, emailError);
      }
    }
  } catch (error) {
    console.error('Failed to send admin notifications:', error);
  }
}

export const handler = async (
  event: APIGatewayProxyEventV2
): Promise<APIGatewayProxyResultV2> => {
  const origin =
    event.headers?.origin || event.headers?.Origin || CORS_ORIGIN || '*';

  // Preflight
  if (event.requestContext.http.method === 'OPTIONS') {
    return {
      statusCode: 204,
      headers: corsHeaders(origin),
    };
  }

  if (!event.body) {
    return badRequest('Missing request body', origin);
  }

  let payload: WaitlistRequest;
  try {
    payload = JSON.parse(event.body);
  } catch {
    return badRequest('Request body must be valid JSON', origin);
  }

  // Validate and sanitize inputs
  let first: string, last: string, email: string;
  const emailConsent = payload.email_consent === true;

  try {
    first = validateName(payload.first_name || '', 'First name');
    last = validateName(payload.last_name || '', 'Last name');
    email = validateEmail(payload.email || '');
  } catch (error: any) {
    return badRequest(error.message || 'Invalid input', origin);
  }

  // Rate limiting by IP address (test emails bypass rate limiting)
  const clientIp = getClientIp(event);
  const ipHash = hashIdentifier(clientIp);
  const isAllowed = await checkRateLimit(ipHash, 'waitlist', RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_MINUTES, email);
  if (!isAllowed) {
    return jsonResponse(429, { message: 'Too many requests. Please try again later.' }, origin);
  }

  // Check for duplicate email (email is the partition key)
  const existingEntries = await ddb.send(
    new QueryCommand({
      TableName: TABLE_WAITLIST,
      KeyConditionExpression: 'email = :email',
      ExpressionAttributeValues: marshall({
        ':email': email,
      }),
      Limit: 1,
    })
  );

  if (existingEntries.Items && existingEntries.Items.length > 0) {
    return badRequest('This email address is already on the waitlist.', origin);
  }

  // Create waitlist entry
  const waitlistId = randomUUID();
  const nowIso = new Date().toISOString();

  const waitlistItem = {
    waitlist_id: waitlistId,
    first_name: first,
    last_name: last,
    email,
    email_consent: emailConsent,
    created_at: nowIso,
  };

  await ddb.send(
    new PutItemCommand({
      TableName: TABLE_WAITLIST,
      Item: marshall(waitlistItem),
    })
  );

  // Send admin notifications
  await sendAdminNotifications(first, last, email);

  // Send welcome email to user (may fail in SES sandbox mode if recipient not verified)
  await sendWelcomeEmail(first, email);

  // If email consent is given, trigger SES email verification
  let sesVerificationSent = false;
  if (emailConsent) {
    try {
      await ses.send(new VerifyEmailIdentityCommand({ EmailAddress: email }));
      sesVerificationSent = true;
    } catch (error) {
      // Log but don't fail the request if SES verification fails
      console.warn('Failed to send SES verification email:', error);
    }
  }

  const baseMessage = 'Successfully joined the wait list! We\'ll notify you when new invites are available.';
  const verificationMessage = sesVerificationSent
    ? ' Please check your inbox for a verification email from AWS and click the link to confirm your email address.'
    : '';

  return jsonResponse(
    200,
    {
      message: baseMessage + verificationMessage,
      waitlist_id: waitlistId,
      email_verification_sent: sesVerificationSent,
    },
    origin
  );
};
