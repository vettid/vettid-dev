import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ddb, ok, badRequest, putAudit, requireAdminGroup } from "../../common/util";
import { DeleteItemCommand, ScanCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";

const TABLE_WAITLIST = process.env.TABLE_WAITLIST!;

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Validate admin group membership
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  const body = JSON.parse(event.body || "{}");
  const { waitlist_ids } = body;

  if (!waitlist_ids || !Array.isArray(waitlist_ids) || waitlist_ids.length === 0) {
    return badRequest("waitlist_ids array required");
  }

  if (waitlist_ids.length > 25) {
    return badRequest("Maximum 25 entries can be deleted at once");
  }

  const adminEmail = (event.requestContext as any)?.authorizer?.jwt?.claims?.email || "unknown@vettid.dev";

  const deleted: string[] = [];
  const failed: { id: string; error: string }[] = [];

  // Delete items one by one (scan for waitlist_id to get email, then delete by email).
  // No GSI on waitlist_id today, so we scan with a filter expression. Earlier this
  // had `Limit: 1` which is a Scan-level cap, applied BEFORE the filter — so if the
  // matching item wasn't the first record DynamoDB happened to scan, the filter
  // returned nothing and the entry was silently skipped. We now page through the
  // table until we find the match (or exhaust the table). For a waitlist of any
  // realistic size this is fine; if it grows, add a waitlist_id GSI.
  for (const id of waitlist_ids) {
    try {
      let email: string | undefined;
      let exclusiveStartKey: Record<string, any> | undefined;
      do {
        const scanResult = await ddb.send(new ScanCommand({
          TableName: TABLE_WAITLIST,
          FilterExpression: 'waitlist_id = :wid',
          ExpressionAttributeValues: marshall({ ':wid': id }),
          ExclusiveStartKey: exclusiveStartKey,
        }));
        if (scanResult.Items && scanResult.Items.length > 0) {
          email = unmarshall(scanResult.Items[0]).email;
          break;
        }
        exclusiveStartKey = scanResult.LastEvaluatedKey;
      } while (exclusiveStartKey);

      if (!email) {
        failed.push({ id, error: "Waitlist entry not found" });
        continue;
      }

      // Delete using email as partition key
      await ddb.send(new DeleteItemCommand({
        TableName: TABLE_WAITLIST,
        Key: marshall({ email })
      }));
      deleted.push(id);
    } catch (error: any) {
      failed.push({ id, error: error.message || "Unknown error" });
    }
  }

  // Audit log (email field is indexed in GSI for lookups)
  await putAudit({
    type: "waitlist_entries_deleted",
    email: adminEmail, // For GSI lookup by admin email
    deleted_count: deleted.length,
    failed_count: failed.length,
    deleted_by: adminEmail,
    waitlist_ids: deleted
  });

  return ok({
    message: `Deleted ${deleted.length} waitlist ${deleted.length === 1 ? 'entry' : 'entries'}`,
    deleted,
    failed
  });
};
