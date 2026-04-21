import { DynamoDBClient, GetItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';

const ddb = new DynamoDBClient({});

/**
 * Returns true iff the user has a subscription row whose status is
 * "active" AND expires_at is in the future. Mirrors the logic in
 * getSubscriptionStatus.ts so the member portal and backend gates
 * agree.
 *
 * Caller is responsible for passing TABLE_SUBSCRIPTIONS (so each
 * handler's env binding stays explicit). Returns false on any fetch
 * error — callers should treat that as "no active subscription"
 * rather than surface DynamoDB faults to the client.
 */
export async function hasActiveSubscription(
  userGuid: string,
  tableSubscriptions: string,
): Promise<boolean> {
  if (!userGuid || !tableSubscriptions) return false;
  try {
    const result = await ddb.send(new GetItemCommand({
      TableName: tableSubscriptions,
      Key: marshall({ user_guid: userGuid }),
    }));
    if (!result.Item) return false;

    const sub = unmarshall(result.Item);
    if (sub.status !== 'active') return false;
    const expiresAt = sub.expires_at ? new Date(sub.expires_at) : null;
    if (!expiresAt || isNaN(expiresAt.getTime())) return false;
    return expiresAt > new Date();
  } catch (err) {
    console.error('subscription check failed', err);
    return false;
  }
}
