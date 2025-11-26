import { DynamoDBStreamEvent, DynamoDBBatchResponse, DynamoDBBatchItemFailure } from "aws-lambda";
import { unmarshall } from "@aws-sdk/util-dynamodb";
import { sendTemplateEmail, putAudit } from "../../common/util";

// Transient errors that should be retried
const TRANSIENT_ERROR_CODES = [
  'ServiceUnavailable',
  'ServiceUnavailableException',
  'ThrottlingException',
  'Throttling',
  'ProvisionedThroughputExceededException',
  'InternalServerError',
  'RequestLimitExceeded'
];

function isTransientError(error: any): boolean {
  const errorCode = error.name || error.code || error.Code;
  return TRANSIENT_ERROR_CODES.some(code =>
    errorCode?.includes(code) || error.message?.includes(code)
  );
}

export const handler = async (event: DynamoDBStreamEvent): Promise<DynamoDBBatchResponse> => {
  const batchItemFailures: DynamoDBBatchItemFailure[] = [];

  for (const rec of event.Records) {
    try {
      if (rec.eventName !== "MODIFY" && rec.eventName !== "INSERT") continue;

      // Cast stream images to 'any' to satisfy util-dynamodb's expected type
      const oldImg = rec.dynamodb?.OldImage ? (unmarshall(rec.dynamodb.OldImage as any) as any) : null;
      const newImg = rec.dynamodb?.NewImage ? (unmarshall(rec.dynamodb.NewImage as any) as any) : null;
      if (!newImg || !newImg.email) continue;

      if (rec.eventName === "INSERT" && newImg.status === "pending") {
        await sendTemplateEmail(newImg.email, "RegistrationPending", {
          first_name: newImg.first_name,
          last_name: newImg.last_name,
          email: newImg.email,
          invite_code: newImg.invite_code
        });
        await putAudit({ type: "email_sent", template: "RegistrationPending", to: newImg.email });
        continue;
      }

      if (rec.eventName === "MODIFY" && oldImg && newImg.status !== oldImg.status) {
        if (newImg.status === "approved") {
          await sendTemplateEmail(newImg.email, "RegistrationApproved", {
            first_name: newImg.first_name,
            last_name: newImg.last_name,
            email: newImg.email
          });
          await putAudit({ type: "email_sent", template: "RegistrationApproved", to: newImg.email });
        } else if (newImg.status === "rejected") {
          await sendTemplateEmail(newImg.email, "RegistrationRejected", {
            first_name: newImg.first_name,
            last_name: newImg.last_name,
            email: newImg.email,
            reason: newImg.rejection_reason || ""
          });
          await putAudit({ type: "email_sent", template: "RegistrationRejected", to: newImg.email });
        }
      }
    } catch (err: any) {
      console.error("Stream processing error for record:", rec.eventID, err);

      // Log the error to audit (best effort - don't fail if audit fails)
      try {
        await putAudit({
          type: "stream_error",
          event_id: rec.eventID,
          message: err.message || String(err),
          error_code: err.name || err.code,
          is_transient: isTransientError(err)
        });
      } catch (auditErr) {
        console.warn("Failed to log stream error to audit:", auditErr);
      }

      // For transient errors, mark the record as failed so it will be retried
      // For permanent errors (e.g., invalid email, template not found), log and continue
      if (isTransientError(err)) {
        // Report this record as failed - Lambda will retry based on bisect/retry config
        if (rec.eventID) {
          batchItemFailures.push({ itemIdentifier: rec.eventID });
        }
      } else {
        // Permanent error - log but don't retry (would fail forever)
        console.error("Permanent error processing record, skipping:", rec.eventID, err.message);
      }
    }
  }

  // Return partial batch response - Lambda will retry only failed items
  return { batchItemFailures };
};

