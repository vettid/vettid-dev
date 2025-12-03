import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ok, badRequest, putAudit, requireAdminGroup, validateOrigin, validateEmail, validateName, checkRateLimit, hashIdentifier, tooManyRequests, getAdminEmail, internalError, ddb } from "../../common/util";
import { SESClient, VerifyEmailIdentityCommand, GetIdentityVerificationAttributesCommand } from "@aws-sdk/client-ses";
import { PutItemCommand, GetItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import { CognitoIdentityProviderClient, AdminGetUserCommand } from "@aws-sdk/client-cognito-identity-provider";

const ses = new SESClient({});
const cognito = new CognitoIdentityProviderClient({});
const PENDING_ADMINS_TABLE = process.env.PENDING_ADMINS_TABLE!;
const USER_POOL_ID = process.env.ADMIN_USER_POOL_ID!;

// Invitation expires after 7 days
const INVITATION_TTL_DAYS = 7;

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  const requestOrigin = event.headers?.origin || event.headers?.Origin;

  // Validate admin group membership
  const authError = requireAdminGroup(event, requestOrigin);
  if (authError) return authError;

  // CSRF protection: Validate request origin
  const csrfError = validateOrigin(event);
  if (csrfError) return csrfError;

  // Rate limiting: Max 10 admin invitations per admin per hour
  const callerEmail = getAdminEmail(event);
  const callerHash = hashIdentifier(callerEmail);
  const isAllowed = await checkRateLimit(callerHash, 'invite_admin', 10, 60);
  if (!isAllowed) {
    return tooManyRequests("Too many admin invitation requests. Please try again later.", requestOrigin);
  }

  // Validate and sanitize inputs
  let email: string, firstName: string, lastName: string, adminType: string;

  try {
    const body = event.body ? JSON.parse(event.body) : {};
    email = validateEmail(body.email || '');
    firstName = validateName(body.first_name || '', 'First name');
    lastName = validateName(body.last_name || '', 'Last name');

    // Validate admin_type
    adminType = body.admin_type || 'admin';
    const validAdminTypes = ['admin', 'user_admin', 'subscriber_admin', 'vote_admin'];
    if (!validAdminTypes.includes(adminType)) {
      throw new Error('Invalid admin type. Must be one of: admin, user_admin, subscriber_admin, vote_admin');
    }
  } catch (error: any) {
    return badRequest(error.message || 'Invalid input', requestOrigin);
  }

  const invitedBy = getAdminEmail(event);

  try {
    // Check if user already exists in Cognito
    try {
      await cognito.send(new AdminGetUserCommand({
        UserPoolId: USER_POOL_ID,
        Username: email
      }));
      // User exists - they're already an admin
      return badRequest("This email is already registered as an admin user.", requestOrigin);
    } catch (error: any) {
      if (error.name !== 'UserNotFoundException') {
        throw error;
      }
      // User doesn't exist - continue with invitation
    }

    // Check if there's already a pending invitation
    const existingInvite = await ddb.send(new GetItemCommand({
      TableName: PENDING_ADMINS_TABLE,
      Key: marshall({ email })
    }));

    if (existingInvite.Item) {
      return badRequest("An invitation is already pending for this email. Use 'Resend Verification' if needed.", requestOrigin);
    }

    // Check current SES verification status
    let sesStatus = 'Pending';
    try {
      const verificationStatus = await ses.send(new GetIdentityVerificationAttributesCommand({
        Identities: [email]
      }));
      sesStatus = verificationStatus.VerificationAttributes?.[email]?.VerificationStatus || 'NotStarted';
    } catch (sesError) {
      console.error('Error checking SES status:', sesError);
    }

    // Send SES verification email if not already verified
    if (sesStatus !== 'Success') {
      await ses.send(new VerifyEmailIdentityCommand({
        EmailAddress: email
      }));
      sesStatus = 'Pending';
    }

    // Calculate TTL (7 days from now)
    const expiresAt = Math.floor(Date.now() / 1000) + (INVITATION_TTL_DAYS * 24 * 60 * 60);

    // Store pending admin invitation
    await ddb.send(new PutItemCommand({
      TableName: PENDING_ADMINS_TABLE,
      Item: marshall({
        email,
        first_name: firstName,
        last_name: lastName,
        admin_type: adminType,
        invited_by: invitedBy,
        invited_at: new Date().toISOString(),
        ses_status: sesStatus,
        expires_at: expiresAt,
      })
    }));

    await putAudit({
      type: "admin_invited",
      email,
      first_name: firstName,
      last_name: lastName,
      admin_type: adminType,
      invited_by: invitedBy,
      ses_status: sesStatus,
    });

    const message = sesStatus === 'Success'
      ? "Admin invitation created. Email already verified - ready to activate."
      : "Admin invitation created. Verification email sent - waiting for recipient to click the verification link.";

    return ok({
      message,
      email,
      ses_status: sesStatus,
      expires_at: new Date(expiresAt * 1000).toISOString(),
    }, requestOrigin);

  } catch (error: any) {
    console.error('Error inviting admin user:', error);
    return internalError('Failed to invite admin user', requestOrigin);
  }
};
