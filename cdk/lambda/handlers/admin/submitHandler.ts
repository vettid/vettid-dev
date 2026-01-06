import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ok, badRequest, internalError, requireAdminGroup, putAudit } from "../../common/util";
import { DynamoDBClient, PutItemCommand } from "@aws-sdk/client-dynamodb";
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { marshall } from "@aws-sdk/util-dynamodb";
import { randomUUID } from "crypto";

const ddb = new DynamoDBClient({});
const s3 = new S3Client({});

const TABLE_HANDLER_SUBMISSIONS = process.env.TABLE_HANDLER_SUBMISSIONS!;
const HANDLER_BUCKET = process.env.HANDLER_BUCKET!;

/**
 * Submit a new handler for review
 *
 * Body:
 * - handler_id: Unique identifier for the handler (e.g., 'credential-validator')
 * - name: Display name of the handler
 * - version: Semantic version (e.g., '1.0.0')
 * - description: Description of what the handler does
 * - submitter_email: Email of the person submitting
 *
 * Returns:
 * - submission_id: ID of the new submission
 * - upload_url: Presigned S3 URL for uploading the WASM file
 * - upload_expires_in: Seconds until the upload URL expires
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
    if (!event.body) {
      return badRequest('Request body is required');
    }

    const body = JSON.parse(event.body);
    const { handler_id, name, version, description, submitter_email } = body;

    // Validate required fields
    if (!handler_id || typeof handler_id !== 'string') {
      return badRequest('handler_id is required');
    }
    if (!name || typeof name !== 'string') {
      return badRequest('name is required');
    }
    if (!version || typeof version !== 'string') {
      return badRequest('version is required');
    }
    if (!description || typeof description !== 'string') {
      return badRequest('description is required');
    }
    if (!submitter_email || typeof submitter_email !== 'string') {
      return badRequest('submitter_email is required');
    }

    // Validate handler_id format (alphanumeric with hyphens)
    if (!/^[a-z0-9-]+$/.test(handler_id)) {
      return badRequest('handler_id must contain only lowercase letters, numbers, and hyphens');
    }

    // Validate version format (semver-like)
    if (!/^\d+\.\d+\.\d+(-[a-z0-9.]+)?$/.test(version)) {
      return badRequest('version must be in semver format (e.g., 1.0.0 or 1.0.0-beta.1)');
    }

    const submissionId = `sub-${randomUUID()}`;
    const s3Key = `submissions/${submissionId}/${handler_id}-${version}.wasm`;
    const now = new Date().toISOString();

    // Create submission record
    await ddb.send(new PutItemCommand({
      TableName: TABLE_HANDLER_SUBMISSIONS,
      Item: marshall({
        submission_id: submissionId,
        handler_id,
        name,
        version,
        description,
        submitter_email,
        status: 'uploading',
        s3_key: s3Key,
        submitted_at: now,
        created_at: now
      })
    }));

    // Generate presigned URL for upload
    const uploadUrl = await getSignedUrl(
      s3,
      new PutObjectCommand({
        Bucket: HANDLER_BUCKET,
        Key: s3Key,
        ContentType: 'application/wasm'
      }),
      { expiresIn: 3600 } // 1 hour
    );

    await putAudit({
      type: 'admin_handler_submission_created',
      details: {
        submission_id: submissionId,
        handler_id,
        name,
        version,
        submitter_email
      }
    });

    return ok({
      submission_id: submissionId,
      upload_url: uploadUrl,
      upload_expires_in: 3600,
      s3_key: s3Key,
      message: 'Upload your WASM file using the provided URL, then call confirm-submission'
    });
  } catch (error) {
    console.error('Error creating handler submission:', error);

    await putAudit({
      type: 'admin_handler_submission_error',
      error: error instanceof Error ? error.message : String(error)
    });

    return internalError('Failed to create handler submission');
  }
};
