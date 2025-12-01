import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, ScanCommand, QueryCommand, PutItemCommand } from '@aws-sdk/client-dynamodb';
import { SESClient, SendEmailCommand } from '@aws-sdk/client-ses';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import { randomUUID } from 'crypto';
import { ok, badRequest, internalError, requireAdminGroup, getAdminEmail } from '../../common/util';

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

      if (result.Items) {
        // For subscriptions, we need to look up email from registrations
        for (const item of result.Items) {
          const subscription = unmarshall(item);
          if (subscription.user_guid) {
            // Look up email from registrations table
            const regResult = await ddb.send(new ScanCommand({
              TableName: TABLE_REGISTRATIONS,
              FilterExpression: 'user_guid = :user_guid',
              ExpressionAttributeValues: marshall({
                ':user_guid': subscription.user_guid
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
        console.error(`Failed to send email to ${email}:`, error);
        failedEmails.push(email);
      }
    }

    // Record sent email in DynamoDB
    const emailId = randomUUID();
    const sentAt = new Date().toISOString();

    await ddb.send(new PutItemCommand({
      TableName: TABLE_SENT_EMAILS,
      Item: marshall({
        email_id: emailId,
        recipient_type,
        subject,
        body_html,
        body_text,
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
    return internalError(error.message || 'Failed to send bulk email');
  }
};
