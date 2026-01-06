import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ok, badRequest, notFound, internalError, requireAdminGroup, putAudit } from "../../common/util";
import { DynamoDBClient, GetItemCommand, UpdateItemCommand } from "@aws-sdk/client-dynamodb";
import { S3Client, HeadObjectCommand } from "@aws-sdk/client-s3";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import { createHash } from "crypto";

const ddb = new DynamoDBClient({});
const s3 = new S3Client({});

const TABLE_HANDLER_SUBMISSIONS = process.env.TABLE_HANDLER_SUBMISSIONS!;
const HANDLER_BUCKET = process.env.HANDLER_BUCKET!;

/**
 * Confirm a handler submission after upload
 *
 * Path params:
 * - submission_id: ID of the submission to confirm
 *
 * This endpoint:
 * 1. Verifies the WASM file was uploaded to S3
 * 2. Calculates the file hash
 * 3. Updates status from 'uploading' to 'pending'
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

    if (submission.status !== 'uploading') {
      return badRequest(`Cannot confirm submission with status '${submission.status}'. Expected 'uploading'.`);
    }

    // Verify the file exists in S3
    try {
      const headResult = await s3.send(new HeadObjectCommand({
        Bucket: HANDLER_BUCKET,
        Key: submission.s3_key
      }));

      // Get file metadata
      const fileSize = headResult.ContentLength || 0;
      const etag = headResult.ETag?.replace(/"/g, '') || '';

      // Update submission to pending status
      await ddb.send(new UpdateItemCommand({
        TableName: TABLE_HANDLER_SUBMISSIONS,
        Key: marshall({ submission_id: submissionId }),
        UpdateExpression: 'SET #s = :pending, wasm_hash = :hash, file_size = :size, confirmed_at = :now',
        ExpressionAttributeNames: { '#s': 'status' },
        ExpressionAttributeValues: marshall({
          ':pending': 'pending',
          ':hash': etag, // S3 ETag is MD5 hash for non-multipart uploads
          ':size': fileSize,
          ':now': new Date().toISOString()
        })
      }));

      await putAudit({
        type: 'admin_handler_submission_confirmed',
        details: {
          submission_id: submissionId,
          handler_id: submission.handler_id,
          version: submission.version,
          file_size: fileSize,
          wasm_hash: etag
        }
      });

      return ok({
        submission_id: submissionId,
        status: 'pending',
        handler_id: submission.handler_id,
        version: submission.version,
        file_size: fileSize,
        wasm_hash: etag,
        message: 'Submission confirmed and pending admin review'
      });
    } catch (s3Error: unknown) {
      if (s3Error && typeof s3Error === 'object' && 'name' in s3Error && s3Error.name === 'NotFound') {
        return badRequest('WASM file has not been uploaded yet');
      }
      throw s3Error;
    }
  } catch (error) {
    console.error('Error confirming handler submission:', error);

    await putAudit({
      type: 'admin_handler_submission_confirm_error',
      error: error instanceof Error ? error.message : String(error)
    });

    return internalError('Failed to confirm handler submission');
  }
};
