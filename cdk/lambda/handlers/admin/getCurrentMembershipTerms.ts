import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ddb, ok, notFound, requireAdminGroup } from "../../common/util";
import { QueryCommand } from "@aws-sdk/client-dynamodb";
import { GetObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";

const s3 = new S3Client({});
const TABLE_MEMBERSHIP_TERMS = process.env.TABLE_MEMBERSHIP_TERMS!;
const TERMS_BUCKET = process.env.TERMS_BUCKET!;

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Validate admin group membership
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  try {
    // Query for current version using GSI
    const res = await ddb.send(new QueryCommand({
      TableName: TABLE_MEMBERSHIP_TERMS,
      IndexName: 'current-index',
      KeyConditionExpression: 'is_current = :true',
      ExpressionAttributeValues: marshall({ ':true': 'true' }),
      ScanIndexForward: false,
      Limit: 1
    }));

    if (!res.Items || res.Items.length === 0) {
      return notFound("No current membership terms found");
    }

    const currentTerms = unmarshall(res.Items[0]);

    // Generate presigned URL for PDF download (valid for 1 hour)
    const downloadUrl = await getSignedUrl(
      s3,
      new GetObjectCommand({
        Bucket: TERMS_BUCKET,
        Key: currentTerms.s3_key
      }),
      { expiresIn: 3600 }
    );

    return ok({
      version_id: currentTerms.version_id,
      created_at: currentTerms.created_at,
      created_by: currentTerms.created_by,
      terms_text: currentTerms.terms_text,
      download_url: downloadUrl
    });
  } catch (error) {
    console.error('Failed to get current membership terms:', error);
    return notFound("Failed to get current membership terms");
  }
};
