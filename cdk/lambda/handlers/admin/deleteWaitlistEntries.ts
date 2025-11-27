import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ddb, ok, badRequest, putAudit, requireAdminGroup } from "../../common/util";
import { DeleteItemCommand, BatchWriteItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall } from "@aws-sdk/util-dynamodb";

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

  // Delete items one by one (could use BatchWriteItem for better performance)
  for (const id of waitlist_ids) {
    try {
      await ddb.send(new DeleteItemCommand({
        TableName: TABLE_WAITLIST,
        Key: marshall({ waitlist_id: id })
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
