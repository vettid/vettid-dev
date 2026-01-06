import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ok, badRequest, notFound, internalError, requireAdminGroup, putAudit, getAdminEmail } from "../../common/util";
import { DynamoDBClient, GetItemCommand, UpdateItemCommand } from "@aws-sdk/client-dynamodb";
import { S3Client, DeleteObjectCommand } from "@aws-sdk/client-s3";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";

const ddb = new DynamoDBClient({});
const s3 = new S3Client({});

const TABLE_HANDLER_SUBMISSIONS = process.env.TABLE_HANDLER_SUBMISSIONS!;
const HANDLER_BUCKET = process.env.HANDLER_BUCKET!;

/**
 * Reject a handler submission
 *
 * Path params:
 * - submission_id: ID of the submission to reject
 *
 * Body:
 * - reason: Reason for rejection (required)
 *
 * This endpoint:
 * 1. Verifies the submission is in 'pending' status
 * 2. Deletes the uploaded WASM file from S3
 * 3. Updates status to 'rejected' with reason
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
    const submissionId = event.pathParameters?.submission_id;
    const adminEmail = getAdminEmail(event);

    if (!submissionId) {
      return badRequest('submission_id path parameter is required');
    }

    if (!event.body) {
      return badRequest('Request body with rejection reason is required');
    }

    const body = JSON.parse(event.body);
    const { reason } = body;

    if (!reason || typeof reason !== 'string' || reason.trim().length < 10) {
      return badRequest('reason is required and must be at least 10 characters');
    }

    // Get the submission record
    const getResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_HANDLER_SUBMISSIONS,
      Key: marshall({ submission_id: submissionId })
    }));

    if (!getResult.Item) {
      return notFound('Submission not found');
    }

    const submission = unmarshall(getResult.Item);

    if (submission.status !== 'pending') {
      return badRequest(`Cannot reject submission with status '${submission.status}'. Expected 'pending'.`);
    }

    // Delete the uploaded WASM file
    try {
      await s3.send(new DeleteObjectCommand({
        Bucket: HANDLER_BUCKET,
        Key: submission.s3_key
      }));
    } catch (s3Error) {
      console.warn('Failed to delete S3 object (may not exist):', s3Error);
      // Continue with rejection even if delete fails
    }

    const now = new Date().toISOString();

    // Update submission to rejected status
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_HANDLER_SUBMISSIONS,
      Key: marshall({ submission_id: submissionId }),
      UpdateExpression: 'SET #s = :rejected, rejected_at = :now, rejected_by = :admin, rejection_reason = :reason',
      ExpressionAttributeNames: { '#s': 'status' },
      ExpressionAttributeValues: marshall({
        ':rejected': 'rejected',
        ':now': now,
        ':admin': adminEmail || 'unknown',
        ':reason': reason.trim()
      })
    }));

    await putAudit({
      type: 'admin_handler_submission_rejected',
      details: {
        submission_id: submissionId,
        handler_id: submission.handler_id,
        version: submission.version,
        rejected_by: adminEmail,
        rejection_reason: reason.trim()
      }
    });

    return ok({
      submission_id: submissionId,
      status: 'rejected',
      handler_id: submission.handler_id,
      version: submission.version,
      rejected_at: now,
      rejected_by: adminEmail,
      rejection_reason: reason.trim(),
      message: 'Handler submission rejected'
    });
  } catch (error) {
    console.error('Error rejecting handler submission:', error);

    await putAudit({
      type: 'admin_handler_submission_reject_error',
      error: error instanceof Error ? error.message : String(error)
    });

    return internalError('Failed to reject handler submission');
  }
};
