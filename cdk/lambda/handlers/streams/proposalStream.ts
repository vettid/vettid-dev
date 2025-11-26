import { DynamoDBStreamEvent, DynamoDBRecord } from 'aws-lambda';
import { DynamoDBClient, ScanCommand, GetItemCommand } from '@aws-sdk/client-dynamodb';
import { SESClient, SendTemplatedEmailCommand } from '@aws-sdk/client-ses';
import { unmarshall, marshall } from '@aws-sdk/util-dynamodb';
import { createHash } from 'crypto';

/**
 * Hash identifier for safe logging (no PII in logs)
 */
function hashForLog(value: string): string {
  return createHash('sha256').update(value.toLowerCase().trim()).digest('hex').substring(0, 12);
}

const ddb = new DynamoDBClient({});
const ses = new SESClient({});

const TABLE_SUBSCRIPTIONS = process.env.TABLE_SUBSCRIPTIONS!;
const TABLE_AUDIT = process.env.TABLE_AUDIT!;
const TABLE_REGISTRATIONS = process.env.TABLE_REGISTRATIONS!;
const SES_FROM = process.env.SES_FROM || 'no-reply@vettid.dev';

interface ProposalRecord {
  proposal_id: string;
  proposal_title: string;
  proposal_description?: string;
  status: string;
  opens_at: string;
  closes_at: string;
}

/**
 * Process DynamoDB Stream events for proposals table
 * Sends email notifications when proposals become active
 */
export const handler = async (event: DynamoDBStreamEvent): Promise<void> => {
  console.log(`Processing ${event.Records.length} stream records`);

  for (const record of event.Records) {
    try {
      await processRecord(record);
    } catch (error) {
      console.error('Error processing record:', error);
      // Continue processing other records
    }
  }
};

async function processRecord(record: DynamoDBRecord): Promise<void> {
  const eventName = record.eventName;

  if (eventName === 'INSERT' || eventName === 'MODIFY') {
    const newImage = record.dynamodb?.NewImage;
    const oldImage = record.dynamodb?.OldImage;

    if (!newImage) {
      return;
    }

    const proposal = unmarshall(newImage as any) as ProposalRecord;

    // Check if proposal is now active and open for voting
    const isNowActive = proposal.status === 'active';
    const wasActive = oldImage ? (unmarshall(oldImage as any) as ProposalRecord).status === 'active' : false;

    // Only send notifications if:
    // 1. This is a new proposal (INSERT) that is active
    // 2. OR status changed from non-active to active (MODIFY)
    const shouldNotify = (eventName === 'INSERT' && isNowActive) ||
                         (eventName === 'MODIFY' && isNowActive && !wasActive);

    if (!shouldNotify) {
      console.log(`Skipping notification for proposal ${proposal.proposal_id} (status: ${proposal.status}, event: ${eventName})`);
      return;
    }

    // Check if proposal is currently open for voting
    const now = new Date();
    const opensAt = new Date(proposal.opens_at);
    const closesAt = new Date(proposal.closes_at);

    if (now < opensAt) {
      console.log(`Proposal ${proposal.proposal_id} not yet open (opens at ${proposal.opens_at})`);
      return;
    }

    if (now > closesAt) {
      console.log(`Proposal ${proposal.proposal_id} already closed (closed at ${proposal.closes_at})`);
      return;
    }

    console.log(`Sending notifications for proposal: ${proposal.proposal_title}`);
    await sendNotifications(proposal);
  }
}

async function sendNotifications(proposal: ProposalRecord): Promise<void> {
  // Get all active subscriptions
  const subscriptionsResult = await ddb.send(new ScanCommand({
    TableName: TABLE_SUBSCRIPTIONS,
    FilterExpression: '#status = :status',
    ExpressionAttributeNames: {
      '#status': 'status',
    },
    ExpressionAttributeValues: marshall({
      ':status': 'active',
    }),
  }));

  if (!subscriptionsResult.Items || subscriptionsResult.Items.length === 0) {
    console.log('No active subscriptions found');
    return;
  }

  console.log(`Found ${subscriptionsResult.Items.length} active subscriptions`);

  let sentCount = 0;
  let skippedCount = 0;

  // Process each subscription
  for (const item of subscriptionsResult.Items) {
    try {
      const subscription = unmarshall(item);
      const userGuid = subscription.user_guid;

      // Check if user has system emails enabled
      const hasSystemEmailsEnabled = await checkSystemEmailsEnabled(userGuid);

      if (!hasSystemEmailsEnabled) {
        console.log(`Skipping user ${userGuid} - system emails disabled`);
        skippedCount++;
        continue;
      }

      // Get user's email from registrations table
      const email = await getUserEmail(userGuid);

      if (!email) {
        console.log(`Skipping user ${userGuid} - no email found`);
        skippedCount++;
        continue;
      }

      // Send notification email
      await sendProposalNotificationEmail(email, proposal);
      sentCount++;
      console.log(`Sent notification to user ${hashForLog(email)}`);

    } catch (error) {
      console.error('Error processing subscription:', error);
      skippedCount++;
    }
  }

  console.log(`Notifications sent: ${sentCount}, skipped: ${skippedCount}`);
}

async function checkSystemEmailsEnabled(userGuid: string): Promise<boolean> {
  try {
    const result = await ddb.send(new GetItemCommand({
      TableName: TABLE_AUDIT,
      Key: {
        id: { S: `email-prefs:${userGuid}` },
      },
    }));

    if (!result.Item) {
      // Default to enabled if no preferences set
      return true;
    }

    const prefs = unmarshall(result.Item);
    // Check if system_emails exists and is explicitly disabled
    return prefs.system_emails !== false;

  } catch (error) {
    console.error(`Error checking email preferences for ${userGuid}:`, error);
    // Default to enabled on error
    return true;
  }
}

async function getUserEmail(userGuid: string): Promise<string | null> {
  try {
    const result = await ddb.send(new ScanCommand({
      TableName: TABLE_REGISTRATIONS,
      FilterExpression: 'user_guid = :user_guid',
      ExpressionAttributeValues: marshall({
        ':user_guid': userGuid,
      }),
      Limit: 1,
    }));

    if (!result.Items || result.Items.length === 0) {
      return null;
    }

    const registration = unmarshall(result.Items[0]);
    return registration.email || null;

  } catch (error) {
    console.error(`Error getting email for ${userGuid}:`, error);
    return null;
  }
}

async function sendProposalNotificationEmail(
  to: string,
  proposal: ProposalRecord
): Promise<void> {
  const templateData = {
    proposal_title: proposal.proposal_title,
    proposal_description: proposal.proposal_description || 'No description provided.',
    opens_at: new Date(proposal.opens_at).toLocaleString('en-US', {
      dateStyle: 'full',
      timeStyle: 'short',
      timeZone: 'UTC',
    }),
    closes_at: new Date(proposal.closes_at).toLocaleString('en-US', {
      dateStyle: 'full',
      timeStyle: 'short',
      timeZone: 'UTC',
    }),
  };

  await ses.send(new SendTemplatedEmailCommand({
    Source: SES_FROM,
    Destination: {
      ToAddresses: [to],
    },
    Template: 'NewProposalNotification',
    TemplateData: JSON.stringify(templateData),
  }));
}
