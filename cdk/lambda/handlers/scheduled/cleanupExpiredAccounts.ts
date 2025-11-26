import { EventBridgeEvent } from "aws-lambda";
import {
  ddb,
  TABLES,
  cognito,
  USER_POOL_ID,
  putAudit
} from "../../common/util";
import { ScanCommand, DeleteItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import { AdminDeleteUserCommand } from "@aws-sdk/client-cognito-identity-provider";
import { createHash } from "crypto";

/**
 * Hash identifier for safe logging (no PII in logs)
 */
function hashForLog(value: string): string {
  return createHash('sha256').update(value.toLowerCase().trim()).digest('hex').substring(0, 12);
}

/**
 * Scheduled Lambda that runs daily to permanently delete accounts
 * that have passed their scheduled_deletion_date (7 days after cancellation)
 */
export const handler = async (event: EventBridgeEvent<string, any>) => {
  console.log('Starting cleanup of expired canceled accounts');
  const now = new Date().toISOString();
  let deletedCount = 0;
  let errorCount = 0;

  try {
    // Scan for canceled accounts with scheduled_deletion_date <= now
    const scanResult = await ddb.send(new ScanCommand({
      TableName: TABLES.registrations,
      FilterExpression: "#s = :canceled AND scheduled_deletion_date <= :now",
      ExpressionAttributeNames: {
        "#s": "status"
      },
      ExpressionAttributeValues: marshall({
        ":canceled": "canceled",
        ":now": now
      })
    }));

    if (!scanResult.Items || scanResult.Items.length === 0) {
      console.log('No expired accounts found for deletion');
      return {
        statusCode: 200,
        body: JSON.stringify({
          message: 'No expired accounts to delete',
          deleted: 0
        })
      };
    }

    console.log(`Found ${scanResult.Items.length} expired accounts to delete`);

    // Process each expired account
    for (const item of scanResult.Items) {
      const reg = unmarshall(item) as any;

      try {
        console.log(`Deleting account: ${hashForLog(reg.email)} (registration_id: ${reg.registration_id})`);

        // Delete Cognito user if exists
        try {
          await cognito.send(new AdminDeleteUserCommand({
            UserPoolId: USER_POOL_ID,
            Username: reg.email
          }));
          console.log(`Deleted Cognito user: ${hashForLog(reg.email)}`);
        } catch (cognitoError: any) {
          // User might already be deleted, log but continue
          if (cognitoError.name !== 'UserNotFoundException') {
            console.warn(`Failed to delete Cognito user ${hashForLog(reg.email)}:`, cognitoError);
          }
        }

        // Delete registration record from DynamoDB
        await ddb.send(new DeleteItemCommand({
          TableName: TABLES.registrations,
          Key: marshall({ registration_id: reg.registration_id })
        }));
        console.log(`Deleted registration record: ${reg.registration_id}`);

        // Audit log (use hashed email for privacy)
        await putAudit({
          type: "account_auto_deleted",
          registration_id: reg.registration_id,
          email_hash: hashForLog(reg.email),
          deleted_at: now,
          canceled_at: reg.canceled_at,
          scheduled_deletion_date: reg.scheduled_deletion_date,
          reason: "7-day retention period expired"
        });

        deletedCount++;
      } catch (error) {
        console.error(`Failed to delete account ${hashForLog(reg.email)}:`, error);
        errorCount++;

        // Audit the failure (use hashed email for privacy)
        await putAudit({
          type: "account_auto_deletion_failed",
          registration_id: reg.registration_id,
          email_hash: hashForLog(reg.email),
          error: error instanceof Error ? error.message : 'Unknown error',
          attempted_at: now
        });
      }
    }

    console.log(`Cleanup completed. Deleted: ${deletedCount}, Errors: ${errorCount}`);

    return {
      statusCode: 200,
      body: JSON.stringify({
        message: 'Cleanup completed',
        deleted: deletedCount,
        errors: errorCount
      })
    };
  } catch (error) {
    console.error('Failed to run cleanup:', error);
    throw error;
  }
};
