import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ok, badRequest, forbidden, putAudit, requireAdminGroup, validateOrigin, validateEmail, validateName, checkRateLimit, hashIdentifier, tooManyRequests, getAdminEmail, internalError } from "../../common/util";
import { CognitoIdentityProviderClient, AdminCreateUserCommand, AdminAddUserToGroupCommand, AdminGetUserCommand, AdminUpdateUserAttributesCommand } from "@aws-sdk/client-cognito-identity-provider";
import { SESClient, VerifyEmailIdentityCommand, GetIdentityVerificationAttributesCommand } from "@aws-sdk/client-ses";

const cognito = new CognitoIdentityProviderClient({});
const ses = new SESClient({});
const USER_POOL_ID = process.env.ADMIN_USER_POOL_ID!;
const ADMIN_GROUP = process.env.ADMIN_GROUP || "admin";

// Admin type hierarchy: higher number = more privilege
// Only admins with equal or higher privilege can create admins of a given type
const ADMIN_TYPE_HIERARCHY: Record<string, number> = {
  'vote_admin': 1,
  'subscriber_admin': 2,
  'user_admin': 2,
  'admin': 4  // Full admin has highest privilege
};

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  const requestOrigin = event.headers?.origin || event.headers?.Origin;

  // Validate admin group membership
  const authError = requireAdminGroup(event, requestOrigin);
  if (authError) return authError;

  // CSRF protection: Validate request origin
  const csrfError = validateOrigin(event);
  if (csrfError) return csrfError;

  // Rate limiting: Max 10 admin creations per admin per hour
  const callerEmail = getAdminEmail(event);
  const callerHash = hashIdentifier(callerEmail);
  const isAllowed = await checkRateLimit(callerHash, 'add_admin', 10, 60);
  if (!isAllowed) {
    return tooManyRequests("Too many admin creation requests. Please try again later.", requestOrigin);
  }

  // Validate and sanitize inputs with proper error handling
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

  const adminEmail = (event.requestContext as any)?.authorizer?.jwt?.claims?.email || "unknown@vettid.dev";

  // SECURITY: Check admin type hierarchy - callers can only create admins at or below their privilege level
  const callerAdminType = (event.requestContext as any)?.authorizer?.jwt?.claims?.['custom:admin_type'] || 'admin';
  const callerPrivilege = ADMIN_TYPE_HIERARCHY[callerAdminType] || 0;
  const targetPrivilege = ADMIN_TYPE_HIERARCHY[adminType] || 0;

  if (targetPrivilege > callerPrivilege) {
    await putAudit({
      type: 'admin_creation_privilege_violation',
      caller_email: adminEmail,
      caller_admin_type: callerAdminType,
      attempted_admin_type: adminType,
      target_email: email
    });
    return forbidden(`You cannot create an admin with higher privileges than your own (${callerAdminType})`, requestOrigin);
  }

  try {
    // Check if user already exists
    let userExists = true;
    try {
      await cognito.send(new AdminGetUserCommand({
        UserPoolId: USER_POOL_ID,
        Username: email
      }));
    } catch (error: any) {
      if (error.name === 'UserNotFoundException') {
        userExists = false;
      } else {
        throw error;
      }
    }

    // If user doesn't exist, create them
    if (!userExists) {
      await cognito.send(new AdminCreateUserCommand({
        UserPoolId: USER_POOL_ID,
        Username: email,
        DesiredDeliveryMediums: ['EMAIL'],
        UserAttributes: [
          { Name: 'email', Value: email },
          { Name: 'email_verified', Value: 'true' },
          { Name: 'given_name', Value: firstName },
          { Name: 'family_name', Value: lastName },
          { Name: 'custom:admin_type', Value: adminType }
        ]
      }));
    } else {
      // If user exists, update their admin_type
      await cognito.send(new AdminUpdateUserAttributesCommand({
        UserPoolId: USER_POOL_ID,
        Username: email,
        UserAttributes: [
          { Name: 'custom:admin_type', Value: adminType }
        ]
      }));
    }

    // Add user to admin group
    await cognito.send(new AdminAddUserToGroupCommand({
      UserPoolId: USER_POOL_ID,
      Username: email,
      GroupName: ADMIN_GROUP
    }));

    // Check if email is already verified in SES, if not send verification
    let sesVerificationSent = false;
    let sesAlreadyVerified = false;
    try {
      const verificationStatus = await ses.send(new GetIdentityVerificationAttributesCommand({
        Identities: [email]
      }));

      const status = verificationStatus.VerificationAttributes?.[email]?.VerificationStatus;

      if (status === 'Success') {
        sesAlreadyVerified = true;
      } else {
        // Send verification email (also handles 'Pending' status by resending)
        await ses.send(new VerifyEmailIdentityCommand({
          EmailAddress: email
        }));
        sesVerificationSent = true;
      }
    } catch (sesError: any) {
      // Log but don't fail the admin creation if SES verification fails
      console.error('SES verification error (non-fatal):', sesError);
    }

    await putAudit({
      type: "admin_added",
      email,
      first_name: firstName,
      last_name: lastName,
      admin_type: adminType,
      added_by: adminEmail,
      ses_verification_sent: sesVerificationSent,
      ses_already_verified: sesAlreadyVerified
    });

    let message = userExists ? "User added to admin group" : "Admin user created successfully";
    if (sesVerificationSent) {
      message += ". SES verification email sent - they must click the link to receive notifications.";
    } else if (sesAlreadyVerified) {
      message += ". Email already verified for notifications.";
    }

    return ok({
      message,
      email,
      ses_verification_sent: sesVerificationSent,
      ses_already_verified: sesAlreadyVerified
    }, requestOrigin);
  } catch (error: any) {
    console.error('Error adding admin user:', error);
    if (error.name === 'UsernameExistsException') {
      return badRequest("User already exists", requestOrigin);
    }
    return internalError('Failed to add admin user', requestOrigin);
  }
};
