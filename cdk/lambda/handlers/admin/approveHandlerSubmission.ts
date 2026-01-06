import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ok, badRequest, notFound, internalError, requireAdminGroup, putAudit, getAdminEmail } from "../../common/util";
import { DynamoDBClient, GetItemCommand, UpdateItemCommand } from "@aws-sdk/client-dynamodb";
import { S3Client, CopyObjectCommand } from "@aws-sdk/client-s3";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";

const ddb = new DynamoDBClient({});
const s3 = new S3Client({});

const TABLE_HANDLER_SUBMISSIONS = process.env.TABLE_HANDLER_SUBMISSIONS!;
const HANDLER_BUCKET = process.env.HANDLER_BUCKET!;

/**
 * Approve a handler submission and deploy it
 *
 * Path params:
 * - submission_id: ID of the submission to approve
 *
 * This endpoint:
 * 1. Verifies the submission is in 'pending' status
 * 2. Copies the WASM file to the deployed handlers directory
 * 3. Updates status to 'deployed'
 * 4. Note: Actual signing would be done by a separate secure process
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
      return badRequest(`Cannot approve submission with status '${submission.status}'. Expected 'pending'.`);
    }

    // Copy WASM file to deployed handlers directory
    const deployedKey = `deployed/${submission.handler_id}/${submission.version}/${submission.handler_id}.wasm`;

    await s3.send(new CopyObjectCommand({
      Bucket: HANDLER_BUCKET,
      CopySource: `${HANDLER_BUCKET}/${submission.s3_key}`,
      Key: deployedKey,
      ContentType: 'application/wasm',
      Metadata: {
        'handler-id': submission.handler_id,
        'version': submission.version,
        'submission-id': submissionId,
        'approved-by': adminEmail || 'unknown'
      },
      MetadataDirective: 'REPLACE'
    }));

    const now = new Date().toISOString();

    // Update submission to deployed status
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_HANDLER_SUBMISSIONS,
      Key: marshall({ submission_id: submissionId }),
      UpdateExpression: 'SET #s = :deployed, deployed_at = :now, deployed_by = :admin, deployed_s3_key = :key',
      ExpressionAttributeNames: { '#s': 'status' },
      ExpressionAttributeValues: marshall({
        ':deployed': 'deployed',
        ':now': now,
        ':admin': adminEmail || 'unknown',
        ':key': deployedKey
      })
    }));

    await putAudit({
      type: 'admin_handler_submission_approved',
      details: {
        submission_id: submissionId,
        handler_id: submission.handler_id,
        version: submission.version,
        deployed_by: adminEmail,
        deployed_s3_key: deployedKey
      }
    });

    return ok({
      submission_id: submissionId,
      status: 'deployed',
      handler_id: submission.handler_id,
      version: submission.version,
      deployed_at: now,
      deployed_by: adminEmail,
      deployed_s3_key: deployedKey,
      message: 'Handler approved and deployed. Use force-update to push to enclaves.'
    });
  } catch (error) {
    console.error('Error approving handler submission:', error);

    await putAudit({
      type: 'admin_handler_submission_approve_error',
      error: error instanceof Error ? error.message : String(error)
    });

    return internalError('Failed to approve handler submission');
  }
};
