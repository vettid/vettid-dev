// lambda/handlers/auth/verifyAuthChallenge.ts
import { VerifyAuthChallengeResponseTriggerHandler } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, DeleteItemCommand, QueryCommand, ScanCommand } from '@aws-sdk/client-dynamodb';
import { CloudWatchClient, PutMetricDataCommand } from '@aws-sdk/client-cloudwatch';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import { createHash, timingSafeEqual } from 'crypto';

const ddb = new DynamoDBClient({});
const cloudwatch = new CloudWatchClient({});
const MAGIC_LINK_TABLE = process.env.MAGIC_LINK_TABLE!;
const REGISTRATIONS_TABLE = process.env.REGISTRATIONS_TABLE!;

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
    console.log('Missing challenge answer');
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
    const userEmail = event.request.userAttributes.email;
    const regQuery = await ddb.send(new ScanCommand({
      TableName: REGISTRATIONS_TABLE,
      FilterExpression: "email = :email AND #s = :approved",
      ExpressionAttributeNames: {
        "#s": "status"
      },
      ExpressionAttributeValues: marshall({
        ":email": userEmail,
        ":approved": "approved"
      }),
      Limit: 1
    }));

    let pinRequired = false;
    let storedPinHash: string | null = null;

    if (regQuery.Items && regQuery.Items.length > 0) {
      const reg = unmarshall(regQuery.Items[0]) as any;
      pinRequired = reg.pin_enabled === true;
      storedPinHash = reg.pin_hash || null;
      console.log('PIN required:', pinRequired);
    }

    // If PIN is required but not provided, reject
    if (pinRequired && !providedPin) {
      console.log('PIN required but not provided');
      await publishFailedLoginMetric('PinRequired');
      event.response.answerCorrect = false;
      return event;
    }

    // If PIN is provided, validate it
    if (pinRequired && providedPin) {
      if (!storedPinHash) {
        console.log('PIN enabled but no hash stored');
        await publishFailedLoginMetric('PinHashMissing');
        event.response.answerCorrect = false;
        return event;
      }

      const providedPinHash = hashPin(providedPin);
      // SECURITY: Use timing-safe comparison to prevent timing attacks
      if (!secureCompare(providedPinHash, storedPinHash)) {
        console.log('PIN hash mismatch');
        await publishFailedLoginMetric('InvalidPin');
        event.response.answerCorrect = false;
        return event;
      }

      console.log('PIN verified successfully');
    }

    // Retrieve token from DynamoDB to verify it exists and hasn't expired
    // Note: We accept any valid token for this user, not just the one from privateChallengeParameters
    // This allows magic links to work across sessions (user clicks link in email)
    const result = await ddb.send(new GetItemCommand({
      TableName: MAGIC_LINK_TABLE,
      Key: marshall({ token }),
    }));

    if (!result.Item) {
      console.log('Token not found in database');
      await publishFailedLoginMetric('TokenNotFound');
      event.response.answerCorrect = false;
      return event;
    }

    const tokenData = unmarshall(result.Item);
    const now = Math.floor(Date.now() / 1000);

    // Check if token has expired
    if (tokenData.expiresAt && tokenData.expiresAt < now) {
      console.log('Token has expired');
      await publishFailedLoginMetric('TokenExpired');
      event.response.answerCorrect = false;
      return event;
    }

    // Check if token belongs to the correct user
    if (tokenData.email !== userEmail) {
      console.log('Token email mismatch');
      await publishFailedLoginMetric('EmailMismatch');
      event.response.answerCorrect = false;
      return event;
    }

    console.log('Token verified successfully');
    event.response.answerCorrect = true;

    // Delete the token so it can't be reused
    await ddb.send(new DeleteItemCommand({
      TableName: MAGIC_LINK_TABLE,
      Key: marshall({ token }),
    }));

    console.log('Token deleted after successful verification');

  } catch (error) {
    console.error('Error verifying token:', error);
    event.response.answerCorrect = false;
  }

  return event;
};
