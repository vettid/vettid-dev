import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ddb, ok, badRequest, notFound, requireAdminGroup } from "../../common/util";
import { GetItemCommand } from "@aws-sdk/client-dynamodb";
import { GetObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";

const s3 = new S3Client({});
const TABLE_MEMBERSHIP_TERMS = process.env.TABLE_MEMBERSHIP_TERMS!;
const TERMS_BUCKET = process.env.TERMS_BUCKET!;

/**
 * Generate a presigned download URL for a specific membership terms version
 * GET /admin/membership-terms/{version_id}/download
 */
export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Validate admin group membership
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  try {
    const versionId = event.pathParameters?.version_id;

    if (!versionId) {
      return badRequest("Version ID is required");
    }

    // Fetch the terms record to get the s3_key
    const res = await ddb.send(new GetItemCommand({
      TableName: TABLE_MEMBERSHIP_TERMS,
      Key: marshall({ version_id: versionId })
    }));

    if (!res.Item) {
      return notFound("Terms version not found");
    }

    const item = unmarshall(res.Item);

    // Generate presigned URL (valid for 1 hour)
    const downloadUrl = await getSignedUrl(
      s3,
      new GetObjectCommand({
        Bucket: TERMS_BUCKET,
        Key: item.s3_key
      }),
      { expiresIn: 3600 }
    );

    return ok({
      version_id: versionId,
      download_url: downloadUrl,
      expires_in: 3600
    });
  } catch (error) {
    console.error('Failed to generate download URL:', error);
    return badRequest("Failed to generate download URL");
  }
};
