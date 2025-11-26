import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ddb, ok, badRequest, internalError, requireAdminGroup, getAdminEmail } from "../../common/util";
import { PutItemCommand, UpdateItemCommand, QueryCommand } from "@aws-sdk/client-dynamodb";
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import { randomUUID } from "crypto";
import PDFDocument from "pdfkit";
import { Readable } from "stream";

const s3 = new S3Client({});
const TABLE_MEMBERSHIP_TERMS = process.env.TABLE_MEMBERSHIP_TERMS!;
const TERMS_BUCKET = process.env.TERMS_BUCKET!;

type CreateTermsRequest = {
  terms_text: string;
};

// Helper to convert stream to buffer
async function streamToBuffer(stream: Readable): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    stream.on('data', (chunk) => chunks.push(chunk));
    stream.on('error', reject);
    stream.on('end', () => resolve(Buffer.concat(chunks)));
  });
}

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
    doc.fontSize(32)
      .fillColor('#FFC125')
      .text('VettID', { align: 'center' });

    doc.moveDown(2);

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
  const versionId = randomUUID();
  const now = new Date().toISOString();

  try {
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
