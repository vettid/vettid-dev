import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ddb, ok, badRequest, forbidden, notFound, internalError, requireAdminGroup, validateOrigin, getAdminEmail, putAudit } from "../../common/util";
import { GetItemCommand, UpdateItemCommand } from "@aws-sdk/client-dynamodb";
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import PDFDocument from "pdfkit";
import * as path from "path";
import * as fs from "fs";

const s3 = new S3Client({});
const TABLE_MEMBERSHIP_TERMS = process.env.TABLE_MEMBERSHIP_TERMS!;
const TERMS_BUCKET = process.env.TERMS_BUCKET!;

// Generate PDF with VettID logo and terms text (same as createMembershipTerms)
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
    const logoPath = path.join(__dirname, '../../assets/logo.jpg');

    if (fs.existsSync(logoPath)) {
      const logoWidth = 150;
      const pageWidth = 612;
      const xPosition = (pageWidth - logoWidth) / 2;

      doc.image(logoPath, xPosition, doc.y, {
        width: logoWidth,
        align: 'center'
      });
      doc.moveDown(2);
    } else {
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

/**
 * Regenerates the PDF for an existing membership terms version.
 * This is useful when the terms_text was updated but the PDF wasn't regenerated.
 *
 * POST /admin/membership-terms/{version_id}/regenerate-pdf
 */
export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Validate admin group membership
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  // CSRF protection
  const csrfError = validateOrigin(event);
  if (csrfError) return csrfError;

  // Only full admins can regenerate PDFs
  const adminType = (event.requestContext as any)?.authorizer?.jwt?.claims?.['custom:admin_type'];
  if (adminType !== 'admin') {
    const adminEmail = getAdminEmail(event);
    await putAudit({
      type: 'unauthorized_pdf_regeneration_attempt',
      admin_type: adminType,
      admin_email: adminEmail
    });
    return forbidden('Only full admins can regenerate membership terms PDFs');
  }

  const versionId = event.pathParameters?.version_id;
  if (!versionId) {
    return badRequest("Version ID is required");
  }

  const adminEmail = getAdminEmail(event);

  try {
    // Fetch the terms record
    const res = await ddb.send(new GetItemCommand({
      TableName: TABLE_MEMBERSHIP_TERMS,
      Key: marshall({ version_id: versionId })
    }));

    if (!res.Item) {
      return notFound("Terms version not found");
    }

    const item = unmarshall(res.Item);
    const termsText = item.terms_text;

    if (!termsText) {
      return badRequest("Terms version has no terms_text to generate PDF from");
    }

    // Generate new PDF
    const pdfBuffer = await generateTermsPDF(termsText, versionId);

    // Determine S3 key - use existing or create new standard one
    const s3Key = item.s3_key?.endsWith('.pdf')
      ? item.s3_key
      : `membership-terms/${versionId}.pdf`;

    // Upload PDF to S3
    await s3.send(new PutObjectCommand({
      Bucket: TERMS_BUCKET,
      Key: s3Key,
      Body: pdfBuffer,
      ContentType: 'application/pdf',
      Metadata: {
        version_id: versionId,
        regenerated_by: adminEmail,
        regenerated_at: new Date().toISOString()
      }
    }));

    // Update DynamoDB if s3_key changed
    if (item.s3_key !== s3Key) {
      await ddb.send(new UpdateItemCommand({
        TableName: TABLE_MEMBERSHIP_TERMS,
        Key: marshall({ version_id: versionId }),
        UpdateExpression: 'SET s3_key = :key',
        ExpressionAttributeValues: marshall({ ':key': s3Key })
      }));
    }

    // Audit log
    await putAudit({
      type: 'membership_terms_pdf_regenerated',
      version_id: versionId,
      s3_key: s3Key,
      admin_email: adminEmail
    });

    return ok({
      message: "PDF regenerated successfully",
      version_id: versionId,
      s3_key: s3Key
    });
  } catch (error) {
    console.error('Failed to regenerate PDF:', error);
    return internalError("Failed to regenerate PDF");
  }
};
