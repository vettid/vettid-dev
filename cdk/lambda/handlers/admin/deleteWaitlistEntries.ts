import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ddb, ok, badRequest, putAudit, requireAdminGroup } from "../../common/util";
import { DeleteItemCommand, BatchWriteItemCommand, ScanCommand } from "@aws-sdk/client-dynamodb";
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

  // Delete items one by one (scan for waitlist_id to get email, then delete by email)
  for (const id of waitlist_ids) {
    try {
      // Find the waitlist entry by waitlist_id to get the email (partition key)
      const scanResult = await ddb.send(new ScanCommand({
        TableName: TABLE_WAITLIST,
        FilterExpression: 'waitlist_id = :wid',
        ExpressionAttributeValues: marshall({ ':wid': id }),
        Limit: 1,
      }));

      if (!scanResult.Items || scanResult.Items.length === 0) {
        failed.push({ id, error: "Waitlist entry not found" });
        continue;
      }

      const entry = unmarshall(scanResult.Items[0]);
      const email = entry.email;

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

  // Audit log
  await putAudit({
    type: "waitlist_entries_deleted",
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
