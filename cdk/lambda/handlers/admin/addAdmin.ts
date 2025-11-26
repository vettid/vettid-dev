import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ok, badRequest, putAudit, requireAdminGroup, validateOrigin, validateEmail, validateName, checkRateLimit, hashIdentifier, tooManyRequests, getAdminEmail } from "../../common/util";
import { CognitoIdentityProviderClient, AdminCreateUserCommand, AdminAddUserToGroupCommand, AdminGetUserCommand, AdminUpdateUserAttributesCommand } from "@aws-sdk/client-cognito-identity-provider";

const cognito = new CognitoIdentityProviderClient({});
const USER_POOL_ID = process.env.USER_POOL_ID!;
const ADMIN_GROUP = process.env.ADMIN_GROUP || "admin";

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Validate admin group membership
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  // CSRF protection: Validate request origin
  const csrfError = validateOrigin(event);
  if (csrfError) return csrfError;

  // Rate limiting: Max 10 admin creations per admin per hour
  const callerEmail = getAdminEmail(event);
  const callerHash = hashIdentifier(callerEmail);
  const isAllowed = await checkRateLimit(callerHash, 'add_admin', 10, 60);
  if (!isAllowed) {
    return tooManyRequests("Too many admin creation requests. Please try again later.");
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
    return badRequest(error.message || 'Invalid input');
  }

  const adminEmail = (event.requestContext as any)?.authorizer?.jwt?.claims?.email || "unknown@vettid.dev";

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

    await putAudit({
      type: "admin_added",
      email,
      first_name: firstName,
      last_name: lastName,
      admin_type: adminType,
      added_by: adminEmail
    });

    return ok({
      message: userExists ? "User added to admin group" : "Admin user created successfully",
      email
    });
  } catch (error: any) {
    console.error('Error adding admin user:', error);
    if (error.name === 'UsernameExistsException') {
      return badRequest("User already exists");
    }
    throw error;
  }
};
