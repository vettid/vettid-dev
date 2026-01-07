// lambda/handlers/auth/verifyAuthChallenge.ts
import { VerifyAuthChallengeResponseTriggerHandler } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, DeleteItemCommand, QueryCommand } from '@aws-sdk/client-dynamodb';
import { CloudWatchClient, PutMetricDataCommand } from '@aws-sdk/client-cloudwatch';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import { createHash, timingSafeEqual } from 'crypto';
import { recordFailedAttempt, isBlockedByBruteForce, clearFailedAttempts } from '../../common/rateLimit';

const ddb = new DynamoDBClient({});
const cloudwatch = new CloudWatchClient({});
const MAGIC_LINK_TABLE = process.env.MAGIC_LINK_TABLE!;
const REGISTRATIONS_TABLE = process.env.REGISTRATIONS_TABLE!;

/**
 * PIN brute force protection configuration
 * 5 failed attempts in 15 minutes = 30 minute block
 */
const PIN_BRUTE_FORCE_CONFIG = {
  maxFailedAttempts: 5,
  windowSeconds: 900,        // 15 minutes
  blockDurationSeconds: 1800, // 30 minutes
};

/**
 * Hash PIN using SHA-256
 */
function hashPin(pin: string): string {
  return createHash('sha256').update(pin).digest('hex');
}

/**
 * Timing-safe string comparison to prevent timing attacks
 * SECURITY: Use this for comparing hashes to prevent attackers
 * from inferring information via response time differences
 */
function secureCompare(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) {
    timingSafeEqual(bufA, bufA); // Constant time operation
    return false;
  }
  return timingSafeEqual(bufA, bufB);
}

/**
 * Publish CloudWatch metric for failed login attempts
 */
async function publishFailedLoginMetric(reason: string): Promise<void> {
  try {
    await cloudwatch.send(new PutMetricDataCommand({
      Namespace: 'VettID/Authentication',
      MetricData: [
        {
          MetricName: 'FailedLoginAttempts',
          Value: 1,
          Unit: 'Count',
          Dimensions: [
            {
              Name: 'FailureReason',
              Value: reason
            }
          ],
          Timestamp: new Date()
        }
      ]
    }));
  } catch (error) {
    console.error('Failed to publish CloudWatch metric:', error);
  }
}

/**
 * Hash identifier for safe logging (no PII in logs)
 */
function hashForLog(value: string): string {
  return createHash('sha256').update(value.toLowerCase().trim()).digest('hex').substring(0, 12);
}

/**
 * Cognito VerifyAuthChallenge trigger
 * Validates the magic link token
 */
export const handler: VerifyAuthChallengeResponseTriggerHandler = async (event) => {
  // SECURITY: Only log user hash, not full event with PII or token
  const userEmail = event.request.userAttributes?.email;
  console.log('VerifyAuthChallenge: user_hash=%s, has_answer=%s',
    userEmail ? hashForLog(userEmail) : 'unknown',
    !!event.request.challengeAnswer
  );

  const { challengeAnswer } = event.request;

  if (!challengeAnswer) {
    await publishFailedLoginMetric('MissingToken');
    event.response.answerCorrect = false;
    return event;
  }

  // Parse challenge answer - could be "token" or "token:pin"
  const parts = challengeAnswer.split(':');
  const token = parts[0];
  const providedPin = parts.length > 1 ? parts[1] : null;

  try {
    // First, check if user has PIN enabled
    const email = event.request.userAttributes.email;
    // SECURITY: Use email-index GSI instead of table scan for O(1) lookup
    // This prevents DDoS via expensive scan operations
    const regQuery = await ddb.send(new QueryCommand({
      TableName: REGISTRATIONS_TABLE,
      IndexName: 'email-index',
      KeyConditionExpression: 'email = :email',
      FilterExpression: '#s = :approved',
      ExpressionAttributeNames: {
        '#s': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':email': email,
        ':approved': 'approved',
      }),
      Limit: 1, // Only need one result
    }));

    let pinRequired = false;
    let storedPinHash: string | null = null;

    if (regQuery.Items && regQuery.Items.length > 0) {
      const reg = unmarshall(regQuery.Items[0]) as any;
      pinRequired = reg.pin_enabled === true;
      storedPinHash = reg.pin_hash || null;
    }

    // If PIN is required but not provided, reject
    if (pinRequired && !providedPin) {
      await publishFailedLoginMetric('PinRequired');
      event.response.answerCorrect = false;
      return event;
    }

    // If PIN is provided, validate it with brute force protection
    if (pinRequired && providedPin) {
      if (!storedPinHash) {
        await publishFailedLoginMetric('PinHashMissing');
        event.response.answerCorrect = false;
        return event;
      }

      // SECURITY: Check if user is blocked due to too many failed PIN attempts
      const isBlocked = await isBlockedByBruteForce(email, 'pin', PIN_BRUTE_FORCE_CONFIG);
      if (isBlocked) {
        console.warn('PIN auth blocked due to brute force protection: user_hash=%s', hashForLog(email));
        await publishFailedLoginMetric('PinBlocked');
        event.response.answerCorrect = false;
        return event;
      }

      const providedPinHash = hashPin(providedPin);
      // SECURITY: Use timing-safe comparison to prevent timing attacks
      if (!secureCompare(providedPinHash, storedPinHash)) {
        // SECURITY: Record failed attempt for brute force detection
        const { blocked, attemptsRemaining } = await recordFailedAttempt(
          email,
          'pin',
          PIN_BRUTE_FORCE_CONFIG
        );
        console.warn('Invalid PIN: user_hash=%s, attempts_remaining=%d, blocked=%s',
          hashForLog(email), attemptsRemaining, blocked);
        await publishFailedLoginMetric('InvalidPin');
        event.response.answerCorrect = false;
        return event;
      }

      // SECURITY: Clear failed attempts on successful PIN validation
      await clearFailedAttempts(email, 'pin');
    }

    // Retrieve token from DynamoDB to verify it exists and hasn't expired
    // Note: We accept any valid token for this user, not just the one from privateChallengeParameters
    // This allows magic links to work across sessions (user clicks link in email)
    const result = await ddb.send(new GetItemCommand({
      TableName: MAGIC_LINK_TABLE,
      Key: marshall({ token }),
    }));

    if (!result.Item) {
      await publishFailedLoginMetric('TokenNotFound');
      event.response.answerCorrect = false;
      return event;
    }

    const tokenData = unmarshall(result.Item);
    const now = Math.floor(Date.now() / 1000);

    // Check if token has expired
    if (tokenData.expiresAt && tokenData.expiresAt < now) {
      await publishFailedLoginMetric('TokenExpired');
      event.response.answerCorrect = false;
      return event;
    }

    // Check if token belongs to the correct user
    if (tokenData.email !== email) {
      await publishFailedLoginMetric('EmailMismatch');
      event.response.answerCorrect = false;
      return event;
    }

    event.response.answerCorrect = true;

    // Delete the token so it can't be reused
    await ddb.send(new DeleteItemCommand({
      TableName: MAGIC_LINK_TABLE,
      Key: marshall({ token }),
    }));

  } catch (error) {
    console.error('Error verifying token:', error);
    event.response.answerCorrect = false;
  }

  return event;
};
