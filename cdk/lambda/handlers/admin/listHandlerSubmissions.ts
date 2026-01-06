import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ok, internalError, requireAdminGroup, putAudit } from "../../common/util";
import { DynamoDBClient, QueryCommand, ScanCommand } from "@aws-sdk/client-dynamodb";
import { unmarshall, marshall } from "@aws-sdk/util-dynamodb";

const ddb = new DynamoDBClient({});

const TABLE_HANDLER_SUBMISSIONS = process.env.TABLE_HANDLER_SUBMISSIONS!;

/**
 * List handler submissions for admin review
 *
 * Query params:
 * - status: Filter by status (pending, approved, rejected, deployed) - defaults to 'pending'
 */
export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Validate admin group membership
  const authError = requireAdminGroup(event);
  if (authError) {
    await putAudit({
      type: 'auth_failure_admin_access_denied',
      reason: 'insufficient_group_membership',
      path: event.rawPath
    });
    return authError;
  }

  try {
    const statusFilter = event.queryStringParameters?.status || 'pending';
    const validStatuses = ['pending', 'approved', 'rejected', 'deployed', 'uploading'];

    if (!validStatuses.includes(statusFilter)) {
      return ok({
        submissions: [],
        count: 0,
        message: `Invalid status filter. Valid values: ${validStatuses.join(', ')}`
      });
    }

    // Query using status-index GSI
    const result = await ddb.send(new QueryCommand({
      TableName: TABLE_HANDLER_SUBMISSIONS,
      IndexName: 'status-index',
      KeyConditionExpression: '#s = :status',
      ExpressionAttributeNames: { '#s': 'status', '#n': 'name' },
      ExpressionAttributeValues: marshall({
        ':status': statusFilter
      }),
      ProjectionExpression: 'submission_id, handler_id, #n, version, description, submitter_email, submitted_at, s3_key, wasm_hash, rejection_reason',
      ScanIndexForward: false // Most recent first
    }));

    const submissions = (result.Items || []).map(item => {
      const s = unmarshall(item);
      return {
        submission_id: s.submission_id,
        handler_id: s.handler_id,
        name: s.name,
        version: s.version,
        description: s.description,
        submitter_email: s.submitter_email,
        submitted_at: s.submitted_at,
        s3_key: s.s3_key,
        wasm_hash: s.wasm_hash,
        rejection_reason: s.rejection_reason
      };
    });

    return ok({
      submissions,
      count: submissions.length,
      status_filter: statusFilter
    });
  } catch (error) {
    console.error('Error listing handler submissions:', error);

    await putAudit({
      type: 'admin_list_handler_submissions_error',
      error: error instanceof Error ? error.message : String(error)
    });

    return internalError('Failed to list handler submissions');
  }
};
