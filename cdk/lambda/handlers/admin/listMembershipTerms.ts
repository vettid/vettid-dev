import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ddb, ok, requireAdminGroup } from "../../common/util";
import { ScanCommand } from "@aws-sdk/client-dynamodb";
import { GetObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { unmarshall } from "@aws-sdk/util-dynamodb";

const s3 = new S3Client({});
const TABLE_MEMBERSHIP_TERMS = process.env.TABLE_MEMBERSHIP_TERMS!;
const TERMS_BUCKET = process.env.TERMS_BUCKET!;

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Validate admin group membership
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  try {
    // Scan all terms (should be small table, so scan is acceptable)
    const res = await ddb.send(new ScanCommand({
      TableName: TABLE_MEMBERSHIP_TERMS
    }));

    const items = (res.Items || []).map((i) => unmarshall(i as any));

    // Sort by created_at descending (newest first)
    items.sort((a: any, b: any) => {
      return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
    });

    // Generate presigned URLs for each version
    const enrichedItems = await Promise.all(items.map(async (item: any) => {
      const downloadUrl = await getSignedUrl(
        s3,
        new GetObjectCommand({
          Bucket: TERMS_BUCKET,
          Key: item.s3_key
        }),
        { expiresIn: 3600 }
      );

      return {
        version_id: item.version_id,
        created_at: item.created_at,
        created_by: item.created_by,
        is_current: item.is_current === 'true',
        download_url: downloadUrl
      };
    }));

    return ok(enrichedItems);
  } catch (error) {
    console.error('Failed to list membership terms:', error);
    return ok([]);
  }
};
