import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { S3Client, HeadObjectCommand } from "@aws-sdk/client-s3";
import {
  ok,
  badRequest,
  internalError,
  requireUserClaims,
  ValidationError,
} from "../../common/util";

const s3 = new S3Client({});
const VAULT_DATA_BUCKET = process.env.VAULT_DATA_BUCKET || "vettid-vault-data-449757308783";

export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const origin = event.headers?.origin;

  try {
    // Validate user claims
    const claimsResult = requireUserClaims(event, origin);
    if ("error" in claimsResult) {
      return claimsResult.error;
    }
    const { claims } = claimsResult;

    // Check for vault state backup in S3
    const vaultStateKey = `vaults/${claims.user_guid}/vault_state.enc`;

    try {
      const head = await s3.send(new HeadObjectCommand({
        Bucket: VAULT_DATA_BUCKET,
        Key: vaultStateKey,
      }));

      return ok({
        exists: true,
        enabled: true,
        last_backup: head.LastModified?.toISOString() || null,
        size_bytes: head.ContentLength || 0,
      }, origin);

    } catch (s3Error: any) {
      if (s3Error.name === "NotFound" || s3Error.$metadata?.httpStatusCode === 404) {
        // No vault state backup exists
        return ok({
          exists: false,
          enabled: false,
          last_backup: null,
        }, origin);
      }
      throw s3Error;
    }

  } catch (error) {
    console.error("Error getting credential backup status:", error);
    if (error instanceof ValidationError) {
      return badRequest(error.message, origin);
    }
    return internalError("Failed to get credential backup status", origin);
  }
};
