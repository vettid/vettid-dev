import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ok, badRequest, notFound, internalError, requireAdminGroup, putAudit, getAdminEmail } from "../../common/util";
import { DynamoDBClient, GetItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import { publishSignedControlCommand } from "../../common/nats-publisher";

const ddb = new DynamoDBClient({});

const TABLE_HANDLER_SUBMISSIONS = process.env.TABLE_HANDLER_SUBMISSIONS!;

/**
 * Force all enclaves to reload a handler
 *
 * Path params:
 * - submission_id: ID of the deployed submission to force update
 *
 * This endpoint:
 * 1. Verifies the submission is in 'deployed' status
 * 2. Publishes a Control.global.handlers.reload message to NATS
 * 3. Records the force update in audit log
 *
 * Note: NATS publishing is done via HTTP API since Lambda cannot use raw TCP NATS
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

    if (submission.status !== 'deployed') {
      return badRequest(`Cannot force update handler with status '${submission.status}'. Expected 'deployed'.`);
    }

    // Build the reload message payload
    const reloadParams = {
      handler_id: submission.handler_id,
      version: submission.version,
      s3_key: submission.deployed_s3_key,
      wasm_hash: submission.wasm_hash,
    };

    // SECURITY: Publish signed control command to NATS
    // All control commands are Ed25519-signed to prevent unauthorized execution
    // even if NATS credentials are compromised
    const result = await publishSignedControlCommand(
      'handlers.reload',
      { type: 'global' },
      reloadParams,
      adminEmail || 'system'
    );

    if (!result.success) {
      console.error('Failed to publish control command:', result.error);

      await putAudit({
        type: 'admin_handler_force_update_failed',
        details: {
          submission_id: submissionId,
          handler_id: submission.handler_id,
          error: result.error,
          triggered_by: adminEmail
        }
      });

      return internalError('Failed to send reload command to enclaves');
    }

    // Log successful force update
    await putAudit({
      type: 'admin_handler_force_update',
      details: {
        submission_id: submissionId,
        handler_id: submission.handler_id,
        version: submission.version,
        command_id: result.command_id,
        nats_subject: 'Control.global.handlers.reload',
        triggered_by: adminEmail
      }
    });

    return ok({
      submission_id: submissionId,
      handler_id: submission.handler_id,
      version: submission.version,
      command_id: result.command_id,
      nats_subject: 'Control.global.handlers.reload',
      status: 'sent',
      message_text: 'Signed handler reload command sent to all enclaves'
    });
  } catch (error) {
    console.error('Error forcing handler update:', error);

    await putAudit({
      type: 'admin_handler_force_update_error',
      error: error instanceof Error ? error.message : String(error)
    });

    return internalError('Failed to force handler update');
  }
};
