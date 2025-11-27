import { Handler } from "aws-lambda";
import { DynamoDBClient, PutItemCommand, QueryCommand } from "@aws-sdk/client-dynamodb";
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import { randomUUID } from "crypto";
import PDFDocument from "pdfkit";

const ddb = new DynamoDBClient({});
const s3 = new S3Client({});

const DEFAULT_TERMS_TEXT = `VettID Cooperative Membership Terms

Welcome to VettID, a member-owned cooperative dedicated to protecting your online security and privacy.

By accepting these terms, you agree to become a full member of the VettID Cooperative with voting rights and access to all member features.

1. MEMBERSHIP

   1.1 As a member, you have equal voting rights in cooperative governance decisions.
   1.2 Members are expected to uphold the cooperative's values of privacy, security, and community.
   1.3 Membership is non-transferable.

2. SERVICES

   2.1 VettID provides secure identity verification and privacy protection services.
   2.2 Services are subject to availability and may be updated from time to time.

3. PRIVACY

   3.1 We implement zero-knowledge architecture where possible.
   3.2 Your data belongs to you, and we cannot access it by design.
   3.3 We will never sell or share your personal information.

4. COOPERATIVE GOVERNANCE

   4.1 One member, one vote on major decisions.
   4.2 Members may propose changes to services or governance.
   4.3 Annual meetings will be held for member voting.

5. TERMINATION

   5.1 You may terminate your membership at any time.
   5.2 VettID reserves the right to terminate membership for violations of these terms.

6. UPDATES TO TERMS

   6.1 These terms may be updated from time to time.
   6.2 You will be notified of material changes.
   6.3 Continued membership constitutes acceptance of updated terms.

Last Updated: ${new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}
`;

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

/**
 * Lambda function to ensure default membership terms exist
 * Invoked manually after stack deployment
 */
export const handler: Handler = async () => {
  console.log('Checking for current membership terms...');

  const tableName = process.env.TABLE_MEMBERSHIP_TERMS!;
  const bucketName = process.env.TERMS_BUCKET!;

  try {
    // Check if any current membership terms exist
    const queryRes = await ddb.send(new QueryCommand({
      TableName: tableName,
      IndexName: 'current-index',
      KeyConditionExpression: 'is_current = :true',
      ExpressionAttributeValues: marshall({ ':true': 'true' }),
      Limit: 1
    }));

    if (queryRes.Items && queryRes.Items.length > 0) {
      console.log('✓ Current membership terms already exist, skipping creation');
      return {
        statusCode: 200,
        message: 'Current membership terms already exist',
        existing: true
      };
    }

    // No current terms found - create default terms
    console.log('No current membership terms found, creating default terms');

    const versionId = randomUUID();
    const now = new Date().toISOString();

    // Generate PDF
    const pdfBuffer = await generateTermsPDF(DEFAULT_TERMS_TEXT, versionId);

    // Upload PDF to S3
    const s3Key = `membership-terms/${versionId}.pdf`;
    await s3.send(new PutObjectCommand({
      Bucket: bucketName,
      Key: s3Key,
      Body: pdfBuffer,
      ContentType: 'application/pdf',
      Metadata: {
        version_id: versionId,
        created_by: 'system',
        created_at: now,
        is_default: 'true'
      }
    }));

    // Save to DynamoDB
    const termsItem = {
      version_id: versionId,
      terms_text: DEFAULT_TERMS_TEXT,
      s3_key: s3Key,
      created_at: now,
      created_by: 'system',
      is_current: 'true'
    };

    await ddb.send(new PutItemCommand({
      TableName: tableName,
      Item: marshall(termsItem)
    }));

    console.log('✓ Default membership terms created successfully:', versionId);

    return {
      statusCode: 200,
      message: 'Default membership terms created',
      versionId,
      s3Key,
      created: true
    };
  } catch (error) {
    console.error('Failed to ensure default membership terms:', error);
    throw error;
  }
};
