import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, PutItemCommand } from '@aws-sdk/client-dynamodb';
import { SESClient, SendEmailCommand } from '@aws-sdk/client-ses';
import { marshall } from '@aws-sdk/util-dynamodb';
import { randomUUID } from 'crypto';
import {
  validateEmail,
  validateName,
  validateStringInput,
  checkRateLimit,
  hashIdentifier,
  getClientIp,
  escapeHtml,
} from '../../common/util';

const ddb = new DynamoDBClient({});
const ses = new SESClient({});

// Rate limit: 3 help submissions per IP per hour
const RATE_LIMIT_MAX_REQUESTS = 3;
const RATE_LIMIT_WINDOW_MINUTES = 60;

const TABLE_HELP_REQUESTS = process.env.TABLE_HELP_REQUESTS!;
const SES_FROM = process.env.SES_FROM || 'no-reply@vettid.dev';
const ADMIN_NOTIFICATION_EMAIL = process.env.ADMIN_NOTIFICATION_EMAIL || 'admin@vettid.dev';

// Valid help types (must match frontend)
const VALID_HELP_TYPES = [
  'legal',
  'developer',
  'beta_tester',
  'donation',
  'marketing',
  'design',
  'community',
  'other',
] as const;

type HelpType = typeof VALID_HELP_TYPES[number];

type HelpRequest = {
  name?: string;
  email?: string;
  phone?: string;
  linkedin_url?: string;
  help_types?: string[];
  message?: string;
  // Honeypot field - should always be empty
  website?: string;
};

// CORS configuration
const ALLOWED_ORIGINS = [
  'https://vettid.dev',
  'https://www.vettid.dev',
  'http://localhost:3000',
  'http://localhost:5173',
];

function corsHeaders(origin?: string): Record<string, string> {
  let allowedOrigin = 'https://vettid.dev';
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    allowedOrigin = origin;
  }

  return {
    'Access-Control-Allow-Origin': allowedOrigin,
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'OPTIONS,POST',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-Permitted-Cross-Domain-Policies': 'none',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Cache-Control': 'no-store, no-cache, must-revalidate',
  };
}

function jsonResponse(
  statusCode: number,
  body: unknown,
  origin?: string
): APIGatewayProxyResultV2 {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders(origin),
    },
    body: JSON.stringify(body),
  };
}

function badRequest(message: string, origin?: string): APIGatewayProxyResultV2 {
  return jsonResponse(400, { message }, origin);
}

// Validate phone number format (basic validation)
function validatePhone(phone: string): string {
  const cleaned = phone.trim();
  if (cleaned.length < 10 || cleaned.length > 20) {
    throw new Error('Phone number must be between 10 and 20 characters');
  }
  // Allow digits, spaces, dashes, parentheses, and plus sign
  if (!/^[\d\s\-\(\)\+]+$/.test(cleaned)) {
    throw new Error('Phone number contains invalid characters');
  }
  return cleaned;
}

// Validate LinkedIn URL format (optional field)
function validateLinkedInUrl(url: string | undefined): string | undefined {
  if (!url || url.trim() === '') {
    return undefined;
  }
  const cleaned = url.trim();
  // Must be a valid LinkedIn profile URL
  const linkedInPattern = /^https?:\/\/(www\.)?linkedin\.com\/in\/[\w\-]+\/?$/i;
  if (!linkedInPattern.test(cleaned)) {
    throw new Error('LinkedIn URL must be a valid profile URL (e.g., https://linkedin.com/in/username)');
  }
  // Normalize to https
  return cleaned.replace(/^http:/, 'https:');
}

// Validate help types array
function validateHelpTypes(types: unknown): HelpType[] {
  if (!Array.isArray(types) || types.length === 0) {
    throw new Error('Please select at least one way you would like to help');
  }
  if (types.length > VALID_HELP_TYPES.length) {
    throw new Error('Invalid help type selection');
  }
  const validated: HelpType[] = [];
  for (const type of types) {
    if (typeof type !== 'string') {
      throw new Error('Invalid help type format');
    }
    const normalized = type.toLowerCase().trim();
    if (!VALID_HELP_TYPES.includes(normalized as HelpType)) {
      throw new Error(`Invalid help type: ${type}`);
    }
    validated.push(normalized as HelpType);
  }
  return validated;
}

// Send notification email to admin
async function sendAdminNotification(
  name: string,
  email: string,
  phone: string,
  linkedinUrl: string | undefined,
  helpTypes: HelpType[],
  message: string
): Promise<void> {
  const helpTypeLabels: Record<HelpType, string> = {
    legal: 'Legal',
    developer: 'Developer',
    beta_tester: 'Beta Tester',
    donation: 'Donation/Funding',
    marketing: 'Marketing/PR',
    design: 'Design/UX',
    community: 'Community/Advocacy',
    other: 'Other',
  };

  const helpTypesFormatted = helpTypes.map(t => helpTypeLabels[t]).join(', ');
  const linkedinHtml = linkedinUrl
    ? `<li><strong>LinkedIn:</strong> <a href="${escapeHtml(linkedinUrl)}">${escapeHtml(linkedinUrl)}</a></li>`
    : '';

  try {
    await ses.send(
      new SendEmailCommand({
        Source: SES_FROM,
        Destination: {
          ToAddresses: [ADMIN_NOTIFICATION_EMAIL],
        },
        Message: {
          Subject: {
            Data: `New Help Request - VettID (${helpTypesFormatted})`,
            Charset: 'UTF-8',
          },
          Body: {
            Html: {
              Data: `
                <!DOCTYPE html>
                <html>
                <head>
                  <meta charset="UTF-8">
                </head>
                <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
                  <div style="background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); padding: 20px 30px; border-radius: 12px 12px 0 0;">
                    <h2 style="color: #ffc125; margin: 0;">New Help Request</h2>
                  </div>
                  <div style="background: #f8f9fa; padding: 30px; border-radius: 0 0 12px 12px; border: 1px solid #e9ecef; border-top: none;">
                    <p style="margin-top: 0;">Someone wants to help VettID!</p>
                    <ul style="list-style: none; padding: 0;">
                      <li><strong>Name:</strong> ${escapeHtml(name)}</li>
                      <li><strong>Email:</strong> <a href="mailto:${escapeHtml(email)}">${escapeHtml(email)}</a></li>
                      <li><strong>Phone:</strong> ${escapeHtml(phone)}</li>
                      ${linkedinHtml}
                      <li><strong>Type of Help:</strong> ${escapeHtml(helpTypesFormatted)}</li>
                    </ul>
                    <div style="background: #fff; border-left: 4px solid #ffc125; padding: 15px 20px; margin: 20px 0; border-radius: 0 8px 8px 0;">
                      <p style="margin: 0 0 10px 0; font-weight: bold;">Their Message:</p>
                      <p style="margin: 0; white-space: pre-wrap;">${escapeHtml(message)}</p>
                    </div>
                    <p style="margin-bottom: 0;">
                      <a href="https://admin.vettid.dev" style="display: inline-block; background: #ffc125; color: #1a1a2e; padding: 10px 20px; text-decoration: none; border-radius: 6px; font-weight: bold;">View in Admin Portal</a>
                    </p>
                  </div>
                </body>
                </html>
              `,
              Charset: 'UTF-8',
            },
            Text: {
              Data: `New Help Request - VettID

Someone wants to help VettID!

Name: ${name}
Email: ${email}
Phone: ${phone}
${linkedinUrl ? `LinkedIn: ${linkedinUrl}\n` : ''}Type of Help: ${helpTypesFormatted}

Their Message:
${message}

View in Admin Portal: https://admin.vettid.dev`,
              Charset: 'UTF-8',
            },
          },
        },
      })
    );
  } catch (error) {
    console.error('Failed to send admin notification email:', error);
    // Don't fail the request if email fails
  }
}

export const handler = async (
  event: APIGatewayProxyEventV2
): Promise<APIGatewayProxyResultV2> => {
  const origin = event.headers?.origin || event.headers?.Origin;

  // Handle CORS preflight
  if (event.requestContext.http.method === 'OPTIONS') {
    return {
      statusCode: 204,
      headers: corsHeaders(origin),
    };
  }

  if (!event.body) {
    return badRequest('Missing request body', origin);
  }

  let payload: HelpRequest;
  try {
    payload = JSON.parse(event.body);
  } catch {
    return badRequest('Request body must be valid JSON', origin);
  }

  // SECURITY: Honeypot check - if 'website' field is filled, it's a bot
  if (payload.website && payload.website.trim() !== '') {
    // Silently accept to not reveal the honeypot, but don't store
    console.log('Honeypot triggered - likely bot submission');
    return jsonResponse(
      200,
      { message: 'Thank you for your interest! We\'ll be in touch soon.' },
      origin
    );
  }

  // Validate and sanitize all inputs
  let name: string;
  let email: string;
  let phone: string;
  let linkedinUrl: string | undefined;
  let helpTypes: HelpType[];
  let message: string;

  try {
    name = validateName(payload.name || '', 'Name');
    email = validateEmail(payload.email || '');
    phone = validatePhone(payload.phone || '');
    linkedinUrl = validateLinkedInUrl(payload.linkedin_url);
    helpTypes = validateHelpTypes(payload.help_types);
    message = validateStringInput(payload.message || '', 'Message', 10, 2000);
  } catch (error: any) {
    return badRequest(error.message || 'Invalid input', origin);
  }

  // Rate limiting by IP
  const clientIp = getClientIp(event);
  const ipHash = hashIdentifier(clientIp);
  const isAllowed = await checkRateLimit(
    ipHash,
    'help_request',
    RATE_LIMIT_MAX_REQUESTS,
    RATE_LIMIT_WINDOW_MINUTES,
    email
  );
  if (!isAllowed) {
    return jsonResponse(
      429,
      { message: 'Too many requests. Please try again later.' },
      origin
    );
  }

  // Create help request record
  const requestId = randomUUID();
  const nowIso = new Date().toISOString();

  const helpRequestItem = {
    request_id: requestId,
    name,
    email,
    phone,
    linkedin_url: linkedinUrl || null,
    help_types: helpTypes,
    message,
    status: 'new',
    admin_notes: null,
    created_at: nowIso,
    updated_at: nowIso,
  };

  await ddb.send(
    new PutItemCommand({
      TableName: TABLE_HELP_REQUESTS,
      Item: marshall(helpRequestItem, { removeUndefinedValues: true }),
    })
  );

  // Send admin notification email
  await sendAdminNotification(name, email, phone, linkedinUrl, helpTypes, message);

  return jsonResponse(
    200,
    {
      message: 'Thank you for your interest in helping VettID! We\'ll be in touch soon.',
      request_id: requestId,
    },
    origin
  );
};
