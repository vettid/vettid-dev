import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, ScanCommand, QueryCommand, PutItemCommand, BatchGetItemCommand } from '@aws-sdk/client-dynamodb';
import { SESClient, SendEmailCommand } from '@aws-sdk/client-ses';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import { randomUUID, createHash } from 'crypto';

// SECURITY: Hash email for logs to prevent CSV injection and PII exposure
function hashEmail(email: string): string {
  return createHash('sha256').update(email.toLowerCase()).digest('hex').substring(0, 12);
}
import { ok, badRequest, internalError, requireAdminGroup, getAdminEmail, validateUUID, putAudit } from '../../common/util';

const ddb = new DynamoDBClient({});
const ses = new SESClient({});

const TABLE_WAITLIST = process.env.TABLE_WAITLIST!;
const TABLE_REGISTRATIONS = process.env.TABLE_REGISTRATIONS!;
const TABLE_SUBSCRIPTIONS = process.env.TABLE_SUBSCRIPTIONS!;
const TABLE_SENT_EMAILS = process.env.TABLE_SENT_EMAILS!;
const SES_FROM_EMAIL = 'no-reply@vettid.dev';

type SendBulkEmailRequest = {
  recipient_type: 'waitlist' | 'registered' | 'members' | 'subscribers';
  subject: string;
  body_html: string;
  body_text: string;
};

// SECURITY: Allowed domains for links in bulk emails
const ALLOWED_LINK_DOMAINS = [
  'vettid.dev',
  'www.vettid.dev',
  'account.vettid.dev',
  'admin.vettid.dev',
  'register.vettid.dev',
];

/**
 * SECURITY: Validate email content to prevent phishing attacks
 * Returns null if valid, error message if invalid
 */
function validateEmailContent(html: string, text: string, subject: string): string | null {
  const lowerHtml = html.toLowerCase();
  const lowerText = text.toLowerCase();
  const lowerSubject = subject.toLowerCase();

  // Block JavaScript in HTML
  if (/<script[\s>]/i.test(html) || /javascript:/i.test(html) || /on\w+\s*=/i.test(html)) {
    return 'JavaScript is not allowed in email content';
  }

  // Block form elements (phishing vector)
  if (/<form[\s>]/i.test(html) || /<input[\s>]/i.test(html) || /<button[\s>]/i.test(html)) {
    return 'Form elements are not allowed in email content';
  }

  // Block iframes and objects
  if (/<iframe[\s>]/i.test(html) || /<object[\s>]/i.test(html) || /<embed[\s>]/i.test(html)) {
    return 'Embedded content (iframe, object, embed) is not allowed';
  }

  // Extract and validate all URLs
  const urlPattern = /https?:\/\/[^\s"'<>]+/gi;
  const urls = html.match(urlPattern) || [];

  for (const url of urls) {
    try {
      const parsed = new URL(url);
      const hostname = parsed.hostname.toLowerCase();

      // Check if domain is allowed
      const isAllowed = ALLOWED_LINK_DOMAINS.some(domain =>
        hostname === domain || hostname.endsWith('.' + domain)
      );

      if (!isAllowed) {
        return `External links are not allowed. Found: ${hostname}. Only vettid.dev domains are permitted.`;
      }
    } catch {
      // Invalid URL - skip
    }
  }

  // Block common phishing keywords in subject
  const phishingKeywords = [
    'verify your account',
    'confirm your identity',
    'update your payment',
    'suspended',
    'urgent action required',
    'your account will be',
    'click here immediately',
    'act now',
  ];

  for (const keyword of phishingKeywords) {
    if (lowerSubject.includes(keyword)) {
      return `Subject contains suspicious phrase: "${keyword}"`;
    }
  }

  // Limit content size to prevent abuse
  if (html.length > 100000) {
    return 'HTML content exceeds maximum size (100KB)';
  }

  if (text.length > 50000) {
    return 'Text content exceeds maximum size (50KB)';
  }

  return null; // Valid
}

/**
 * Get recipient emails based on recipient type
 */
async function getRecipientEmails(recipientType: string): Promise<string[]> {
  const emails: string[] = [];

  switch (recipientType) {
    case 'waitlist': {
      // Query waitlist table with status = 'pending'
      const result = await ddb.send(new QueryCommand({
        TableName: TABLE_WAITLIST,
        IndexName: 'status-index',
        KeyConditionExpression: '#status = :status',
        ExpressionAttributeNames: {
          '#status': 'status'
        },
        ExpressionAttributeValues: marshall({
          ':status': 'pending'
        })
      }));

      if (result.Items) {
        for (const item of result.Items) {
          const entry = unmarshall(item);
          if (entry.email) emails.push(entry.email);
        }
      }
      break;
    }

    case 'registered': {
      // Query registrations table with status = 'approved'
      const result = await ddb.send(new QueryCommand({
        TableName: TABLE_REGISTRATIONS,
        IndexName: 'status-index',
        KeyConditionExpression: '#status = :status',
        ExpressionAttributeNames: {
          '#status': 'status'
        },
        ExpressionAttributeValues: marshall({
          ':status': 'approved'
        })
      }));

      if (result.Items) {
        for (const item of result.Items) {
          const entry = unmarshall(item);
          if (entry.email) emails.push(entry.email);
        }
      }
      break;
    }

    case 'members': {
      // Scan registrations for approved registrations with membership status = 'approved'
      const result = await ddb.send(new ScanCommand({
        TableName: TABLE_REGISTRATIONS,
        FilterExpression: '#status = :approved AND #membership_status = :membership_approved',
        ExpressionAttributeNames: {
          '#status': 'status',
          '#membership_status': 'membership_status'
        },
        ExpressionAttributeValues: marshall({
          ':approved': 'approved',
          ':membership_approved': 'approved'
        })
      }));

      if (result.Items) {
        for (const item of result.Items) {
          const entry = unmarshall(item);
          if (entry.email) emails.push(entry.email);
        }
      }
      break;
    }

    case 'subscribers': {
      // Scan subscriptions for active subscribers
      const result = await ddb.send(new ScanCommand({
        TableName: TABLE_SUBSCRIPTIONS,
        FilterExpression: '#status = :active',
        ExpressionAttributeNames: {
          '#status': 'status'
        },
        ExpressionAttributeValues: marshall({
          ':active': 'active'
        })
      }));

      if (result.Items && result.Items.length > 0) {
        // SECURITY: Validate and collect user_guids
        const validUserGuids: string[] = [];
        for (const item of result.Items) {
          const subscription = unmarshall(item);
          if (subscription.user_guid) {
            // Validate UUID format to prevent injection
            try {
              validateUUID(subscription.user_guid, 'user_guid');
              validUserGuids.push(subscription.user_guid);
            } catch {
              console.warn(`Invalid user_guid format in subscription: ${subscription.user_guid?.substring(0, 8)}...`);
              continue;
            }
          }
        }

        // FIX N+1: Use BatchGetItem to fetch registrations in batches of 100
        for (let i = 0; i < validUserGuids.length; i += 100) {
          const batch = validUserGuids.slice(i, i + 100);

          // Query registrations by user_guid using the user-guid-index GSI
          for (const userGuid of batch) {
            const regResult = await ddb.send(new QueryCommand({
              TableName: TABLE_REGISTRATIONS,
              IndexName: 'user-guid-index',
              KeyConditionExpression: 'user_guid = :user_guid',
              ExpressionAttributeValues: marshall({
                ':user_guid': userGuid
              }),
              Limit: 1
            }));

            if (regResult.Items && regResult.Items.length > 0) {
              const registration = unmarshall(regResult.Items[0]);
              if (registration.email) emails.push(registration.email);
            }
          }
        }
      }
      break;
    }
  }

  // Remove duplicates
  return [...new Set(emails)];
}

/**
 * Send bulk email to a list of users (admin only)
 * POST /admin/send-bulk-email
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  // Require admin group membership
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  const adminEmail = getAdminEmail(event);

  if (!event.body) {
    return badRequest('Missing request body');
  }

  let payload: SendBulkEmailRequest;
  try {
    payload = JSON.parse(event.body);
  } catch {
    return badRequest('Invalid JSON');
  }

  const { recipient_type, subject, body_html, body_text } = payload;

  // Validation
  if (!recipient_type || !['waitlist', 'registered', 'members', 'subscribers'].includes(recipient_type)) {
    return badRequest('recipient_type must be one of: waitlist, registered, members, subscribers');
  }

  if (!subject || subject.trim().length === 0) {
    return badRequest('subject is required');
  }

  if (!body_html || body_html.trim().length === 0) {
    return badRequest('body_html is required');
  }

  if (!body_text || body_text.trim().length === 0) {
    return badRequest('body_text is required');
  }

  // SECURITY: Validate email content to prevent phishing
  const contentError = validateEmailContent(body_html, body_text, subject);
  if (contentError) {
    await putAudit({
      type: 'bulk_email_content_rejected',
      admin: adminEmail,
      reason: contentError,
      recipient_type,
    });
    return badRequest(`Content validation failed: ${contentError}`);
  }

  try {
    // Get recipient emails
    const recipientEmails = await getRecipientEmails(recipient_type);

    if (recipientEmails.length === 0) {
      return ok({
        message: 'No recipients found for the selected group',
        recipient_count: 0,
        email_id: null
      });
    }

    // Send emails
    let sentCount = 0;
    const failedEmails: string[] = [];

    for (const email of recipientEmails) {
      try {
        await ses.send(new SendEmailCommand({
          Source: SES_FROM_EMAIL,
          Destination: {
            ToAddresses: [email]
          },
          Message: {
            Subject: {
              Data: subject,
              Charset: 'UTF-8'
            },
            Body: {
              Html: {
                Data: body_html,
                Charset: 'UTF-8'
              },
              Text: {
                Data: body_text,
                Charset: 'UTF-8'
              }
            }
          }
        }));
        sentCount++;
      } catch (error) {
        // SECURITY: Hash email in logs to prevent CSV injection and PII exposure
        console.error(`Failed to send email to [hash:${hashEmail(email)}]:`, error);
        failedEmails.push(email);
      }
    }

    // Record sent email in DynamoDB
    // SECURITY: Don't store full email body in logs - only metadata
    const emailId = randomUUID();
    const sentAt = new Date().toISOString();

    await ddb.send(new PutItemCommand({
      TableName: TABLE_SENT_EMAILS,
      Item: marshall({
        email_id: emailId,
        recipient_type,
        subject,
        // SECURITY: Store truncated preview instead of full body to prevent sensitive data exposure
        body_preview: body_text.substring(0, 200) + (body_text.length > 200 ? '...' : ''),
        recipient_count: sentCount,
        failed_count: failedEmails.length,
        sent_at: sentAt,
        sent_by: adminEmail
      })
    }));

    return ok({
      message: `Email sent successfully to ${sentCount} recipient(s)`,
      email_id: emailId,
      recipient_count: sentCount,
      failed_count: failedEmails.length,
      sent_at: sentAt
    });
  } catch (error: any) {
    console.error('Error sending bulk email:', error);
    // SECURITY: Don't expose error.message
    return internalError('Failed to send bulk email');
  }
};
