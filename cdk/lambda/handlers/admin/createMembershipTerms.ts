import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ddb, ok, badRequest, internalError, requireAdminGroup, getAdminEmail } from "../../common/util";
import { PutItemCommand, UpdateItemCommand, QueryCommand, ScanCommand } from "@aws-sdk/client-dynamodb";
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import PDFDocument from "pdfkit";
import * as path from "path";
import * as fs from "fs";

const s3 = new S3Client({});
const TABLE_MEMBERSHIP_TERMS = process.env.TABLE_MEMBERSHIP_TERMS!;
const TERMS_BUCKET = process.env.TERMS_BUCKET!;

type CreateTermsRequest = {
  terms_text: string;
};

// Generate PDF with VettID logo and terms text
async function generateTermsPDF(termsText: string, versionId: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({
      size: 'LETTER',
      margins: { top: 72, bottom: 72, left: 72, right: 72 }
    });

    const chunks: Buffer[] = [];
    doc.on('data', (chunk) => chunks.push(chunk));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);

    // First page: VettID logo and title
    // Path to logo in Lambda environment (bundled with function)
    const logoPath = path.join(__dirname, '../../assets/logo.jpg');

    // Check if logo exists and add it, otherwise fallback to text
    if (fs.existsSync(logoPath)) {
      // Center the logo (page width is 612 points for LETTER size, logo width ~150)
      const logoWidth = 150;
      const pageWidth = 612;
      const xPosition = (pageWidth - logoWidth) / 2;

      doc.image(logoPath, xPosition, doc.y, {
        width: logoWidth,
        align: 'center'
      });
      doc.moveDown(2);
    } else {
      // Fallback to text if logo not found
      doc.fontSize(32)
        .fillColor('#FFC125')
        .text('VettID', { align: 'center' });
      doc.moveDown(2);
    }

    doc.fontSize(24)
      .fillColor('#000000')
      .text('Membership Terms of Service', { align: 'center' });

    doc.moveDown(1);

    doc.fontSize(12)
      .fillColor('#666666')
      .text(`Version: ${versionId}`, { align: 'center' });

    doc.moveDown(1);

    doc.fontSize(12)
      .text(`Effective Date: ${new Date().toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric'
      })}`, { align: 'center' });

    doc.addPage();

    // Second page onwards: Terms text
    doc.fontSize(11)
      .fillColor('#000000')
      .text(termsText, {
        align: 'left',
        lineGap: 4
      });

    doc.end();
  });
}

// Get next sequential version number
async function getNextVersionNumber(): Promise<string> {
  try {
    const scanRes = await ddb.send(new ScanCommand({
      TableName: TABLE_MEMBERSHIP_TERMS,
      ProjectionExpression: 'version_id'
    }));

    if (!scanRes.Items || scanRes.Items.length === 0) {
      return "1.0";
    }

    // Parse existing versions and find max numeric version
    let maxVersion = 0;
    for (const item of scanRes.Items) {
      const unmarshalled = unmarshall(item);
      const versionStr = unmarshalled.version_id;

      // Try to parse as numeric version (e.g., "1.0", "2.0")
      const match = versionStr.match(/^(\d+)\.0$/);
      if (match) {
        const versionNum = parseInt(match[1], 10);
        if (versionNum > maxVersion) {
          maxVersion = versionNum;
        }
      }
      // Ignore UUID versions (backward compatibility)
    }

    return `${maxVersion + 1}.0`;
  } catch (error) {
    console.error('Failed to get next version number:', error);
    // Fallback to 1.0 if there's an error
    return "1.0";
  }
}

/**
 * Creates a new version of membership terms and marks it as current.
 *
 * IMPORTANT SAFEGUARDS:
 * - Membership terms are NEVER deleted - all versions are preserved
 * - When a new version is created, the previous current version is marked as not current
 * - The new version automatically becomes current
 * - A custom resource ensures at least one current version always exists on stack deployment
 * - There is NO delete endpoint - terms can only be created and superseded
 */
export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Validate admin group membership
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  if (!event.body) return badRequest("Missing request body");

  let payload: CreateTermsRequest;
  try {
    payload = JSON.parse(event.body);
  } catch {
    return badRequest("Invalid JSON");
  }

  const { terms_text } = payload;

  if (!terms_text || terms_text.trim().length === 0) {
    return badRequest("terms_text is required and cannot be empty");
  }

  const adminEmail = getAdminEmail(event);
  const now = new Date().toISOString();

  try {
    // Get next sequential version number
    const versionId = await getNextVersionNumber();

    // Generate PDF
    const pdfBuffer = await generateTermsPDF(terms_text, versionId);

    // Upload PDF to S3
    const s3Key = `membership-terms/${versionId}.pdf`;
    await s3.send(new PutObjectCommand({
      Bucket: TERMS_BUCKET,
      Key: s3Key,
      Body: pdfBuffer,
      ContentType: 'application/pdf',
      Metadata: {
        version_id: versionId,
        created_by: adminEmail,
        created_at: now
      }
    }));

    // Mark previous current version as not current
    const currentRes = await ddb.send(new QueryCommand({
      TableName: TABLE_MEMBERSHIP_TERMS,
      IndexName: 'current-index',
      KeyConditionExpression: 'is_current = :true',
      ExpressionAttributeValues: marshall({ ':true': 'true' }),
      Limit: 1
    }));

    if (currentRes.Items && currentRes.Items.length > 0) {
      const previousCurrent = unmarshall(currentRes.Items[0]);
      await ddb.send(new UpdateItemCommand({
        TableName: TABLE_MEMBERSHIP_TERMS,
        Key: marshall({ version_id: previousCurrent.version_id }),
        UpdateExpression: 'SET is_current = :false',
        ExpressionAttributeValues: marshall({ ':false': 'false' })
      }));
    }

    // Save new version to DynamoDB
    const termsItem = {
      version_id: versionId,
      terms_text,
      s3_key: s3Key,
      created_at: now,
      created_by: adminEmail,
      is_current: 'true'
    };

    await ddb.send(new PutItemCommand({
      TableName: TABLE_MEMBERSHIP_TERMS,
      Item: marshall(termsItem)
    }));

    return ok({
      message: "Membership terms created successfully",
      version_id: versionId,
      s3_key: s3Key,
      created_at: now
    });
  } catch (error) {
    console.error('Failed to create membership terms:', error);
    return internalError("Failed to create membership terms");
  }
};
