import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, PutItemCommand, QueryCommand } from '@aws-sdk/client-dynamodb';
import { SESClient, VerifyEmailIdentityCommand } from '@aws-sdk/client-ses';
import { marshall } from '@aws-sdk/util-dynamodb';
import { randomUUID } from 'crypto';
import { validateEmail, validateName, checkRateLimit, hashIdentifier, getClientIp } from '../../common/util';

const ddb = new DynamoDBClient({});
const ses = new SESClient({});

// Rate limit: 5 waitlist submissions per IP per hour
const RATE_LIMIT_MAX_REQUESTS = 5;
const RATE_LIMIT_WINDOW_MINUTES = 60;

const TABLE_WAITLIST = process.env.TABLE_WAITLIST!;
// SECURITY: Remove wildcard default - CORS_ORIGIN must be explicitly set or use allowed list
const CORS_ORIGIN = process.env.CORS_ORIGIN || '';

type WaitlistRequest = {
  first_name?: string;
  last_name?: string;
  email?: string;
  email_consent?: boolean;
};

// SECURITY: Strict CORS - only allow specific origins
const ALLOWED_ORIGINS = [
  'https://register.vettid.dev',
  'https://vettid.dev',
  'https://www.vettid.dev',
  'http://localhost:3000',
  'http://localhost:5173',
];

function corsHeaders(origin?: string): Record<string, string> {
  // Use env var if set (and not wildcard), otherwise use allowed list
  const envOrigins = CORS_ORIGIN && CORS_ORIGIN !== '*'
    ? CORS_ORIGIN.split(',').map(o => o.trim())
    : ALLOWED_ORIGINS;

  // SECURITY: Only allow explicitly listed origins
  let allowedOrigin: string;
  if (origin && envOrigins.includes(origin)) {
    allowedOrigin = origin;
  } else {
    // Default to primary domain - will cause CORS errors for unknown origins
    allowedOrigin = envOrigins.find(o => o !== '*') || 'https://register.vettid.dev';
  }

  return {
    'Access-Control-Allow-Origin': allowedOrigin,
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    'Access-Control-Allow-Methods': 'OPTIONS,POST',
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

export const handler = async (
  event: APIGatewayProxyEventV2
): Promise<APIGatewayProxyResultV2> => {
  const origin =
    event.headers?.origin || event.headers?.Origin || CORS_ORIGIN || '*';

  // Preflight
  if (event.requestContext.http.method === 'OPTIONS') {
    return {
      statusCode: 204,
      headers: corsHeaders(origin),
    };
  }

  if (!event.body) {
    return badRequest('Missing request body', origin);
  }

  // Rate limiting by IP address
  const clientIp = getClientIp(event);
  const ipHash = hashIdentifier(clientIp);
  const isAllowed = await checkRateLimit(ipHash, 'waitlist', RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_MINUTES);
  if (!isAllowed) {
    return jsonResponse(429, { message: 'Too many requests. Please try again later.' }, origin);
  }

  let payload: WaitlistRequest;
  try {
    payload = JSON.parse(event.body);
  } catch {
    return badRequest('Request body must be valid JSON', origin);
  }

  // Validate and sanitize inputs
  let first: string, last: string, email: string;
  const emailConsent = payload.email_consent === true;

  try {
    first = validateName(payload.first_name || '', 'First name');
    last = validateName(payload.last_name || '', 'Last name');
    email = validateEmail(payload.email || '');
  } catch (error: any) {
    return badRequest(error.message || 'Invalid input', origin);
  }

  // Check for duplicate email
  const existingEntries = await ddb.send(
    new QueryCommand({
      TableName: TABLE_WAITLIST,
      IndexName: 'email-index',
      KeyConditionExpression: 'email = :email',
      ExpressionAttributeValues: marshall({
        ':email': email,
      }),
      Limit: 1,
    })
  );

  if (existingEntries.Items && existingEntries.Items.length > 0) {
    return badRequest('This email address is already on the waitlist.', origin);
  }

  // Create waitlist entry
  const waitlistId = randomUUID();
  const nowIso = new Date().toISOString();

  const waitlistItem = {
    waitlist_id: waitlistId,
    first_name: first,
    last_name: last,
    email,
    email_consent: emailConsent,
    created_at: nowIso,
  };

  await ddb.send(
    new PutItemCommand({
      TableName: TABLE_WAITLIST,
      Item: marshall(waitlistItem),
    })
  );

  // If email consent is given, trigger SES email verification
  let sesVerificationSent = false;
  if (emailConsent) {
    try {
      await ses.send(new VerifyEmailIdentityCommand({ EmailAddress: email }));
      sesVerificationSent = true;
    } catch (error) {
      // Log but don't fail the request if SES verification fails
      console.warn('Failed to send SES verification email:', error);
    }
  }

  const baseMessage = 'Successfully joined the wait list! We\'ll notify you when new invites are available.';
  const verificationMessage = sesVerificationSent
    ? ' Please check your inbox for a verification email from AWS and click the link to confirm your email address.'
    : '';

  return jsonResponse(
    200,
    {
      message: baseMessage + verificationMessage,
      waitlist_id: waitlistId,
      email_verification_sent: sesVerificationSent,
    },
    origin
  );
};
