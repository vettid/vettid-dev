// lambda/handlers/auth/createAuthChallenge.ts
import { CreateAuthChallengeTriggerHandler } from 'aws-lambda';
import { DynamoDBClient, PutItemCommand, QueryCommand, ScanCommand } from '@aws-sdk/client-dynamodb';
import { SESClient, SendEmailCommand } from '@aws-sdk/client-ses';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import { randomBytes, createHash } from 'crypto';

/**
 * Hash identifier for safe logging (no PII in logs)
 */
function hashForLog(value: string): string {
  return createHash('sha256').update(value.toLowerCase().trim()).digest('hex').substring(0, 12);
}

const ddb = new DynamoDBClient({});
const ses = new SESClient({});

const MAGIC_LINK_TABLE = process.env.MAGIC_LINK_TABLE!;
const REGISTRATIONS_TABLE = process.env.REGISTRATIONS_TABLE!;
const MAGIC_LINK_URL = process.env.MAGIC_LINK_URL || 'https://account.vettid.dev/auth';
const SES_FROM = process.env.SES_FROM || 'no-reply@auth.vettid.dev';
const TOKEN_EXPIRY_MINUTES = 15;

/**
 * Generate a secure random token
 */
function generateToken(): string {
  return randomBytes(32).toString('base64url');
}

/**
 * Cognito CreateAuthChallenge trigger
 * Generates magic link and sends email
 *
 * IMPORTANT: This Lambda is called TWICE during magic link authentication:
 * 1. When user requests a magic link on /signin → should send email
 * 2. When user clicks magic link and /auth calls initiateAuth → should NOT send email
 *
 * To prevent duplicate emails, we check if a valid unexpired token already exists
 * and reuse it without sending another email.
 */
export const handler: CreateAuthChallengeTriggerHandler = async (event) => {
  // SECURITY: Only log user hash, not full event with PII
  const userEmail = event.request.userAttributes?.email;
  console.log('CreateAuthChallenge: user_hash=%s',
    userEmail ? hashForLog(userEmail) : 'unknown'
  );

  const { userAttributes } = event.request;
  const email = userAttributes.email;
  const sub = userAttributes.sub;

  if (!email) {
    throw new Error('User email not found');
  }

  // Check if user has PIN enabled FIRST (needed for all code paths)
  let pinRequired = false;
  try {
    const regQuery = await ddb.send(new ScanCommand({
      TableName: REGISTRATIONS_TABLE,
      FilterExpression: "email = :email AND #s = :approved",
      ExpressionAttributeNames: {
        "#s": "status"
      },
      ExpressionAttributeValues: marshall({
        ":email": email,
        ":approved": "approved"
      }),
      Limit: 1
    }));

    if (regQuery.Items && regQuery.Items.length > 0) {
      const reg = unmarshall(regQuery.Items[0]) as any;
      pinRequired = reg.pin_enabled === true;
      console.log(`PIN required for user ${hashForLog(email)}: ${pinRequired}`);
    }
  } catch (error) {
    console.error('Error checking PIN status:', error);
    // Continue with pinRequired = false
  }

  // Check if a valid unexpired token already exists for this user
  // Rate limiting: Query recent tokens for this email to prevent abuse
  const now = Math.floor(Date.now() / 1000);
  const ONE_HOUR_AGO = now - 3600;
  const RATE_LIMIT_MAX_REQUESTS = 5; // Max 5 magic link requests per hour

  try {
    const { unmarshall } = await import('@aws-sdk/util-dynamodb');

    // Scan MagicLink table to get all tokens for this email within the last hour
    const queryResult = await ddb.send(new ScanCommand({
      TableName: MAGIC_LINK_TABLE,
      FilterExpression: 'email = :email AND createdAtTimestamp > :oneHourAgo',
      ExpressionAttributeValues: {
        ':email': { S: email },
        ':oneHourAgo': { N: ONE_HOUR_AGO.toString() }
      },
    }));

    const recentTokens = (queryResult.Items || []).map(item => unmarshall(item));

    // Rate limiting check
    if (recentTokens.length >= RATE_LIMIT_MAX_REQUESTS) {
      console.log(`Rate limit exceeded for user ${hashForLog(email)}: ${recentTokens.length} requests in last hour`);
      // Still return a challenge but log the abuse
      // Don't send email to prevent abuse
      // Return the most recent valid token if it exists
      const validTokens = recentTokens.filter(t => t.expiresAt > now);
      if (validTokens.length > 0) {
        const mostRecent = validTokens[0];
        event.response.publicChallengeParameters = { email, pinRequired: pinRequired.toString() };
        event.response.privateChallengeParameters = { token: mostRecent.token };
        event.response.challengeMetadata = 'MAGIC_LINK';
        return event;
      }
    }

    // Check for ANY valid unexpired token to reuse
    // This prevents sending duplicate emails when:
    // 1. User clicks magic link (auth page calls initiateAuth)
    // 2. User requests a new link before the old one expires
    // Only create a new token if no valid token exists
    const validTokens = recentTokens.filter(t => t.expiresAt > now);

    if (validTokens.length > 0) {
      const existingToken = validTokens[0].token;
      const ageSeconds = now - validTokens[0].createdAtTimestamp;
      const minutesRemaining = Math.round((validTokens[0].expiresAt - now) / 60);

      console.log(`Found existing valid token for user ${hashForLog(email)}, age: ${ageSeconds}s, expires in ${minutesRemaining}m, reusing without sending email`);
      event.response.publicChallengeParameters = { email, pinRequired: pinRequired.toString() };
      event.response.privateChallengeParameters = { token: existingToken };
      event.response.challengeMetadata = 'MAGIC_LINK';
      return event;
    }

  } catch (error) {
    console.error('Error checking for existing tokens:', error);
    // Continue with normal flow if check fails
  }

  console.log(`Creating new token for user ${hashForLog(email)} and sending email`);

  // Generate magic link token
  const token = generateToken();
  const expiresAt = Math.floor(Date.now() / 1000) + (TOKEN_EXPIRY_MINUTES * 60);

  // Store token in DynamoDB
  await ddb.send(new PutItemCommand({
    TableName: MAGIC_LINK_TABLE,
    Item: marshall({
      token,
      email,
      sub: userAttributes.sub,
      expiresAt,
      createdAt: new Date().toISOString(),
      createdAtTimestamp: now, // Unix timestamp for easy comparison
    }),
  }));

  console.log(`Generated magic link token for user ${hashForLog(email)}, expires in ${TOKEN_EXPIRY_MINUTES} minutes`);

  // Build magic link using URL fragment for security
  // Fragments are not sent to server or logged in access logs
  const magicLink = `${MAGIC_LINK_URL}#token=${encodeURIComponent(token)}&email=${encodeURIComponent(email)}`;

  // Send email with magic link
  const emailParams = {
    Source: SES_FROM,
    Destination: {
      ToAddresses: [email],
    },
    Message: {
      Subject: {
        Data: 'Your VettID Login Link',
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
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif; margin: 0; padding: 0; background-color: #f5f5f5;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f5f5f5; padding: 40px 20px;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
          <tr>
            <td style="padding: 40px 40px 20px 40px; text-align: center;">
              <h1 style="color: #ffc125; margin: 0; font-size: 28px;">VettID</h1>
            </td>
          </tr>
          <tr>
            <td style="padding: 0 40px 20px 40px;">
              <h2 style="color: #333; margin: 0 0 20px 0; font-size: 22px;">Your Login Link</h2>
              <p style="color: #666; font-size: 16px; line-height: 24px; margin: 0 0 30px 0;">
                Click the button below to securely log in to your VettID account. This link will expire in ${TOKEN_EXPIRY_MINUTES} minutes.
              </p>
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td align="center" style="padding: 20px 0;">
                    <a href="${magicLink}" style="display: inline-block; background-color: #ffc125; color: #000; text-decoration: none; padding: 14px 40px; border-radius: 6px; font-weight: 600; font-size: 16px;">
                      Log In to VettID
                    </a>
                  </td>
                </tr>
              </table>
              <p style="color: #999; font-size: 14px; line-height: 20px; margin: 30px 0 0 0;">
                If you didn't request this login link, you can safely ignore this email.
              </p>
            </td>
          </tr>
          <tr>
            <td style="padding: 20px 40px 40px 40px; text-align: center; border-top: 1px solid #eee;">
              <p style="color: #999; font-size: 12px; margin: 0;">
                © ${new Date().getFullYear()} VettID. All rights reserved.
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
          `,
        },
        Text: {
          Data: `
Your VettID Login Link

Click the link below to log in to your VettID account:

${magicLink}

This link will expire in ${TOKEN_EXPIRY_MINUTES} minutes.

If you didn't request this login link, you can safely ignore this email.

© ${new Date().getFullYear()} VettID
          `,
        },
      },
    },
  };

  try {
    await ses.send(new SendEmailCommand(emailParams));
    console.log(`Magic link email sent to user ${hashForLog(email)}`);
  } catch (error) {
    console.error('Failed to send magic link email:', error);
    throw error;
  }

  // Set the challenge metadata (not sent to client)
  event.response.publicChallengeParameters = {
    email,
    pinRequired: pinRequired.toString(), // Pass as string for Cognito compatibility
  };
  event.response.privateChallengeParameters = {
    token,
  };
  event.response.challengeMetadata = 'MAGIC_LINK';

  return event;
};
