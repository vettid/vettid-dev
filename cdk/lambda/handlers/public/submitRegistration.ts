// lambda/handlers/public/submitRegistration.ts
// Updated to use case-preserving invite code validation

import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import {
  DynamoDBClient,
  GetItemCommand,
  PutItemCommand,
  UpdateItemCommand,
  ScanCommand,
} from '@aws-sdk/client-dynamodb';
import { SESClient, VerifyEmailIdentityCommand, GetIdentityVerificationAttributesCommand } from '@aws-sdk/client-ses';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import { randomUUID } from 'crypto';
import { CognitoIdentityProviderClient, AdminCreateUserCommand, AdminAddUserToGroupCommand, AdminGetUserCommand } from '@aws-sdk/client-cognito-identity-provider';
import { validateEmail, validateName, validateInviteCode, checkRateLimit, hashIdentifier, getClientIp } from '../../common/util';

// Rate limit: 10 registration attempts per IP per hour
const RATE_LIMIT_MAX_REQUESTS = 10;
const RATE_LIMIT_WINDOW_MINUTES = 60;

const ddb = new DynamoDBClient({});
const cognito = new CognitoIdentityProviderClient({});
const ses = new SESClient({});

const TABLE_INVITES = process.env.TABLE_INVITES!;
const TABLE_REGISTRATIONS = process.env.TABLE_REGISTRATIONS!;
const TABLE_AUDIT = process.env.TABLE_AUDIT;
const USER_POOL_ID = process.env.USER_POOL_ID!;
const REGISTERED_GROUP = process.env.REGISTERED_GROUP || 'registered';
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';

type RegistrationRequest = {
  first_name?: string;
  last_name?: string;
  email?: string;
  invite_code?: string;
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

function normalizeNumber(value: any | undefined): number | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value === 'number') return value;
  if (typeof value === 'string' && value.trim() !== '' && !isNaN(Number(value))) {
    return Number(value);
  }
  return undefined;
}

function isInviteExpired(invite: any): boolean {
  const nowMs = Date.now();

  const raw = invite.expires_at ?? invite.expiresAt ?? invite.expiry;
  const n = normalizeNumber(raw);
  if (n === undefined) return false;

  // Handle both seconds and milliseconds
  const expiresMs = n > 1e12 ? n : n * 1000;
  return expiresMs < nowMs;
}

function inviteUsage(invite: any): { maxUses: number; used: number } {
  const max =
    normalizeNumber(invite.max_uses ?? invite.maxUses ?? invite.limit) ?? 1;
  const used =
    normalizeNumber(invite.used ?? invite.uses ?? invite.used_count) ?? 0;

  return { maxUses: max, used };
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

  let payload: RegistrationRequest;
  try {
    payload = JSON.parse(event.body);
  } catch {
    return badRequest('Request body must be valid JSON', origin);
  }

  // Validate and sanitize inputs with proper error handling
  let first: string, last: string, email: string, code: string;
  const emailConsent = payload.email_consent === true;

  try {
    first = validateName(payload.first_name || '', 'First name');
    last = validateName(payload.last_name || '', 'Last name');
    email = validateEmail(payload.email || '');
    code = validateInviteCode(payload.invite_code || '');
  } catch (error: any) {
    return badRequest(error.message || 'Invalid input', origin);
  }

  // Rate limiting by IP address (test emails bypass rate limiting)
  const clientIp = getClientIp(event);
  const ipHash = hashIdentifier(clientIp);
  const isAllowed = await checkRateLimit(ipHash, 'register', RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_MINUTES, email);
  if (!isAllowed) {
    return jsonResponse(429, { message: 'Too many requests. Please try again later.' }, origin);
  }

  // 1) Look up invite
  const inviteRes = await ddb.send(
    new GetItemCommand({
      TableName: TABLE_INVITES,
      Key: marshall({ code }), // PK = code (case-sensitive)
      ConsistentRead: true,
    })
  );

  if (!inviteRes.Item) {
    return badRequest('Invite is invalid, expired, or exhausted.', origin);
  }

  const invite = unmarshall(inviteRes.Item);

  // Optional status check: allow undefined or "active"/"new"
  const status = (invite.status || invite.invite_status || '').toString().toLowerCase();
  if (status && status !== 'active' && status !== 'new') {
    return badRequest('Invite is invalid, expired, or exhausted.', origin);
  }

  // Expiry check (handles seconds vs ms)
  if (isInviteExpired(invite)) {
    return badRequest('Invite is invalid, expired, or exhausted.', origin);
  }

  // Usage check
  const { maxUses, used } = inviteUsage(invite);
  if (used >= maxUses) {
    return badRequest('Invite is invalid, expired, or exhausted.', origin);
  }

  // Check for duplicate email using Scan (exclude deleted and rejected registrations)
  const existingRegs = await ddb.send(
    new ScanCommand({
      TableName: TABLE_REGISTRATIONS,
      FilterExpression: 'email = :email AND #s <> :deleted AND #s <> :rejected',
      ExpressionAttributeNames: {
        '#s': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':email': email,
        ':deleted': 'deleted',
        ':rejected': 'rejected',
      }),
      Limit: 1,
    })
  );

  if (existingRegs.Items && existingRegs.Items.length > 0) {
    // Use generic message to prevent email enumeration
    return badRequest('Unable to complete registration. This email may already be registered or the invite code is invalid.', origin);
  }

  // Check if user already exists in Cognito
  let cognitoUserExists = false;
  try {
    await cognito.send(new AdminGetUserCommand({
      UserPoolId: USER_POOL_ID,
      Username: email
    }));
    cognitoUserExists = true;
  } catch (error: any) {
    // User doesn't exist, which is what we want for new registrations
    if (error.name !== 'UserNotFoundException') {
      // Some other error occurred
      console.error('Error checking Cognito user:', error);
      return jsonResponse(500, { message: 'An error occurred processing your registration.' }, origin);
    }
  }

  if (cognitoUserExists) {
    // Use same generic message to prevent email enumeration
    return badRequest('Unable to complete registration. This email may already be registered or the invite code is invalid.', origin);
  }

  // 2) Create registration record
  const registrationId = randomUUID();
  const nowIso = new Date().toISOString();
  const autoApprove = invite.auto_approve === true;

  // Generate user GUID upfront so it can be stored in both DynamoDB and Cognito
  const userGuid = randomUUID();

  const registrationItem: any = {
    registration_id: registrationId,
    first_name: first,
    last_name: last,
    email,
    invite_code: code,
    status: autoApprove ? 'approved' : 'pending',
    membership_status: 'none', // Initialize membership status
    user_guid: userGuid, // Store GUID in DynamoDB so it persists even if Cognito user is deleted
    email_consent: emailConsent, // Store email consent preference
    created_at: nowIso,
    updated_at: nowIso,
  };

  if (autoApprove) {
    registrationItem.approved_at = nowIso;
    registrationItem.approved_by = 'auto';
  }

  // 3) Atomically update invite usage with conditional check to prevent race conditions
  // This must happen BEFORE creating the registration to ensure invite is still valid
  try {
    await ddb.send(
      new UpdateItemCommand({
        TableName: TABLE_INVITES,
        Key: marshall({ code }),
        UpdateExpression: 'SET used = if_not_exists(used, :zero) + :one, #st = :newStatus, updated_at = :now',
        ConditionExpression: '(attribute_not_exists(used) OR used < :maxUses) AND (attribute_not_exists(#st) OR #st IN (:active, :new))',
        ExpressionAttributeNames: {
          '#st': 'status',
        },
        ExpressionAttributeValues: marshall({
          ':zero': 0,
          ':one': 1,
          ':maxUses': maxUses,
          ':newStatus': (used + 1) >= maxUses ? 'exhausted' : (status || 'active'),
          ':active': 'active',
          ':new': 'new',
          ':now': nowIso,
        }),
      })
    );
  } catch (error: any) {
    if (error.name === 'ConditionalCheckFailedException') {
      // Race condition: invite was used/exhausted by another request
      return badRequest('Invite is invalid, expired, or exhausted.', origin);
    }
    throw error;
  }

  // 4) Create registration record (after invite is successfully claimed)
  await ddb.send(
    new PutItemCommand({
      TableName: TABLE_REGISTRATIONS,
      Item: marshall(registrationItem),
    })
  );

  // For auto-approve, create the Cognito user immediately so they can sign in
  // The magic link flow requires the user to exist in Cognito before authentication
  if (autoApprove) {
    try {
      // Create Cognito user with email as username
      await cognito.send(new AdminCreateUserCommand({
        UserPoolId: USER_POOL_ID,
        Username: email,
        UserAttributes: [
          { Name: 'email', Value: email },
          { Name: 'email_verified', Value: 'true' },
          { Name: 'given_name', Value: first },
          { Name: 'family_name', Value: last },
          { Name: 'custom:user_guid', Value: userGuid },
        ],
        MessageAction: 'SUPPRESS', // Don't send welcome email - user will use magic link
      }));

      // Add user to 'registered' group so they can access account endpoints
      // NOTE: Do NOT add to 'member' group here - that happens after terms acceptance
      await cognito.send(new AdminAddUserToGroupCommand({
        UserPoolId: USER_POOL_ID,
        Username: email,
        GroupName: REGISTERED_GROUP,
      }));
    } catch (cognitoError: any) {
      // Log but don't fail - the registration record exists, admin can manually approve
      console.error('Failed to create auto-approved user in Cognito:', cognitoError);
    }
  }

  // 5) Optional audit
  if (TABLE_AUDIT) {
    const auditItem = {
      id: `registration:${registrationId}`,
      type: 'registration_submitted',
      created_at: nowIso,
      details: {
        registration_id: registrationId,
        email,
        invite_code: code,
      },
    };
    try {
      await ddb.send(
        new PutItemCommand({
          TableName: TABLE_AUDIT,
          Item: marshall(auditItem),
        })
      );
    } catch (e) {
      console.warn('Failed to write audit event', e);
    }
  }

  // If email consent is given, trigger SES email verification (only if not already verified)
  let sesVerificationSent = false;
  if (emailConsent) {
    try {
      // Check if email is already verified in SES (e.g., from waitlist)
      const verificationStatus = await ses.send(new GetIdentityVerificationAttributesCommand({
        Identities: [email]
      }));
      const status = verificationStatus.VerificationAttributes?.[email]?.VerificationStatus;

      // Only send verification if not already verified or pending
      if (status !== 'Success' && status !== 'Pending') {
        await ses.send(new VerifyEmailIdentityCommand({ EmailAddress: email }));
        sesVerificationSent = true;
      }
    } catch (error) {
      // Log but don't fail the request if SES verification fails
      console.warn('Failed to check/send SES verification email:', error);
    }
  }

  const baseMessage = autoApprove
    ? 'Registration approved! Visit https://vettid.dev/account to sign in with your email.'
    : 'Registration submitted. Your request is pending approval by a VettID admin.';
  const verificationMessage = sesVerificationSent
    ? ' Please also check your inbox for a verification email from AWS and click the link to confirm your email address.'
    : '';

  return jsonResponse(
    200,
    {
      message: baseMessage + verificationMessage,
      registration_id: registrationId,
      auto_approved: autoApprove,
      email_verification_sent: sesVerificationSent,
    },
    origin
  );
};
