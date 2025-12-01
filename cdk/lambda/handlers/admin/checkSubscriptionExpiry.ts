import { DynamoDBClient, ScanCommand, GetItemCommand, UpdateItemCommand, PutItemCommand } from '@aws-sdk/client-dynamodb';
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
const TABLE_REGISTRATIONS = process.env.TABLE_REGISTRATIONS!;
const TABLE_AUDIT = process.env.TABLE_AUDIT!;
const SES_FROM = process.env.SES_FROM || 'no-reply@vettid.dev';

interface Subscription {
  subscription_id: string;
  user_guid: string;
  subscription_type: string;
  status: string;
  expires_at: string;
  notification_sent_48h?: boolean;
}

/**
 * Scheduled Lambda to check for subscriptions expiring in 48 hours
 * and send notification emails to users with system emails enabled
 */
export const handler = async (): Promise<void> => {
  console.log('Starting subscription expiry check...');

  try {
    // Calculate the time window (48 hours from now, with a 1 hour buffer)
    const now = new Date();
    const expiryStart = new Date(now.getTime() + (47 * 60 * 60 * 1000)); // 47 hours from now
    const expiryEnd = new Date(now.getTime() + (49 * 60 * 60 * 1000)); // 49 hours from now

    // Scan for active subscriptions
    const scanResult = await ddb.send(new ScanCommand({
      TableName: TABLE_SUBSCRIPTIONS,
      FilterExpression: '#status = :status',
      ExpressionAttributeNames: {
        '#status': 'status'
      },
      ExpressionAttributeValues: marshall({
        ':status': 'active'
      })
    }));

    if (!scanResult.Items || scanResult.Items.length === 0) {
      console.log('No active subscriptions found');
      return;
    }

    const subscriptions = scanResult.Items.map(item => unmarshall(item) as Subscription);
    console.log(`Found ${subscriptions.length} active subscriptions`);

    let notificationsSent = 0;
    let notificationsSkipped = 0;

    for (const subscription of subscriptions) {
      try {
        // Parse expiry date
        const expiresAt = new Date(subscription.expires_at);

        // Check if subscription expires within our 48-hour window
        if (expiresAt < expiryStart || expiresAt > expiryEnd) {
          continue;
        }

        // Check if we've already sent a 48-hour notification for this subscription
        if (subscription.notification_sent_48h) {
          console.log(`Already sent 48h notification for subscription ${subscription.subscription_id}`);
          notificationsSkipped++;
          continue;
        }

        // Check if user has system emails enabled
        const hasSystemEmailsEnabled = await checkSystemEmailsEnabled(subscription.user_guid);
        if (!hasSystemEmailsEnabled) {
          console.log(`User ${subscription.user_guid} has system emails disabled`);
          notificationsSkipped++;
          continue;
        }

        // Get user details
        const userDetails = await getUserDetails(subscription.user_guid);
        if (!userDetails) {
          console.log(`Could not find user details for ${subscription.user_guid}`);
          notificationsSkipped++;
          continue;
        }

        // Send notification email
        await sendExpiryNotification(userDetails, subscription, expiresAt);

        // Mark notification as sent to avoid duplicates
        await markNotificationSent(subscription.subscription_id);

        notificationsSent++;
        console.log(`Sent expiry notification to user ${hashForLog(userDetails.email)} for subscription ${subscription.subscription_id}`);

        // Log to audit table (use hashed email for privacy)
        await logAuditEntry({
          id: `sub-expiry-notification:${subscription.subscription_id}:${Date.now()}`,
          user_guid: subscription.user_guid,
          email_hash: hashForLog(userDetails.email),
          subscription_id: subscription.subscription_id,
          notification_type: '48_hour_expiry',
          expires_at: subscription.expires_at,
          sent_at: new Date().toISOString()
        });

      } catch (error) {
        console.error(`Error processing subscription ${subscription.subscription_id}:`, error);
        notificationsSkipped++;
      }
    }

    console.log(`Expiry check complete. Sent: ${notificationsSent}, Skipped: ${notificationsSkipped}`);

  } catch (error) {
    console.error('Error in subscription expiry check:', error);
    throw error;
  }
};

async function checkSystemEmailsEnabled(userGuid: string): Promise<boolean> {
  try {
    const result = await ddb.send(new GetItemCommand({
      TableName: TABLE_AUDIT,
      Key: marshall({ id: `email-prefs:${userGuid}` })
    }));

    if (!result.Item) {
      // Default to enabled if no preferences set
      return true;
    }

    const prefs = unmarshall(result.Item);
    // Check if system_emails is explicitly disabled
    return prefs.system_emails !== false;

  } catch (error) {
    console.error(`Error checking email preferences for ${userGuid}:`, error);
    // Default to enabled on error
    return true;
  }
}

async function getUserDetails(userGuid: string): Promise<{ email: string; first_name: string; last_name: string } | null> {
  try {
    // Get user details from registrations table
    const scanResult = await ddb.send(new ScanCommand({
      TableName: TABLE_REGISTRATIONS,
      FilterExpression: 'user_guid = :user_guid',
      ExpressionAttributeValues: marshall({
        ':user_guid': userGuid
      })
    }));

    if (!scanResult.Items || scanResult.Items.length === 0) {
      return null;
    }

    const registration = unmarshall(scanResult.Items[0]);
    return {
      email: registration.email,
      first_name: registration.first_name || 'Member',
      last_name: registration.last_name || ''
    };

  } catch (error) {
    console.error(`Error getting user details for ${userGuid}:`, error);
    return null;
  }
}

async function sendExpiryNotification(
  userDetails: { email: string; first_name: string; last_name: string },
  subscription: Subscription,
  expiresAt: Date
): Promise<void> {
  const templateData = {
    first_name: userDetails.first_name,
    last_name: userDetails.last_name,
    subscription_type: subscription.subscription_type.replace(/_/g, ' '),
    expires_at: expiresAt.toLocaleString('en-US', {
      dateStyle: 'full',
      timeStyle: 'short',
      timeZone: 'UTC'
    }),
    hours_remaining: '48',
    renewal_link: 'https://account.vettid.dev' // Link to account page where they can renew
  };

  await ses.send(new SendTemplatedEmailCommand({
    Source: SES_FROM,
    Destination: {
      ToAddresses: [userDetails.email]
    },
    Template: 'SubscriptionExpiryWarning',
    TemplateData: JSON.stringify(templateData)
  }));
}

async function markNotificationSent(subscriptionId: string): Promise<void> {
  try {
    // Find the subscription first to get the primary key
    const scanResult = await ddb.send(new ScanCommand({
      TableName: TABLE_SUBSCRIPTIONS,
      FilterExpression: 'subscription_id = :id',
      ExpressionAttributeValues: marshall({
        ':id': subscriptionId
      })
    }));

    if (scanResult.Items && scanResult.Items.length > 0) {
      const item = unmarshall(scanResult.Items[0]);

      // Update the item to mark notification as sent
      await ddb.send(new UpdateItemCommand({
        TableName: TABLE_SUBSCRIPTIONS,
        Key: marshall({
          subscription_id: subscriptionId,
          user_guid: item.user_guid
        }),
        UpdateExpression: 'SET notification_sent_48h = :val',
        ExpressionAttributeValues: marshall({
          ':val': true
        })
      }));
    }
  } catch (error) {
    console.error(`Error marking notification sent for ${subscriptionId}:`, error);
    // Don't throw - we still want to continue processing other subscriptions
  }
}

async function logAuditEntry(entry: any): Promise<void> {
  try {
    await ddb.send(new PutItemCommand({
      TableName: TABLE_AUDIT,
      Item: marshall(entry)
    }));
  } catch (error) {
    console.error('Error logging audit entry:', error);
    // Don't throw - this is not critical
  }
}