import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import {
  ok,
  badRequest,
  notFound,
  internalError,
  putAudit,
  getAdminEmail,
  getRegistration,
  userExistsInCognito,
  cognito,
  USER_POOL_ID,
  ddb,
  TABLES,
  NotFoundError,
  requireAdminGroup,
  validateOrigin,
  checkRateLimit,
  hashIdentifier,
  tooManyRequests
} from "../../common/util";
import { UpdateItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall } from "@aws-sdk/util-dynamodb";
import { AdminCreateUserCommand, AdminAddUserToGroupCommand, AdminGetUserCommand } from "@aws-sdk/client-cognito-identity-provider";
import { randomUUID, randomBytes } from "crypto";

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Validate admin group membership
  const authError = requireAdminGroup(event);
  if (authError) {
    // SECURITY: Log authorization failures for monitoring
    await putAudit({
      type: 'auth_failure_admin_access_denied',
      reason: 'insufficient_group_membership',
      path: event.rawPath
    });
    return authError;
  }

  // CSRF protection: Validate request origin
  const csrfError = validateOrigin(event);
  if (csrfError) return csrfError;

  // Rate limiting: Max 50 approvals per admin per hour
  const adminEmail = getAdminEmail(event);
  const adminHash = hashIdentifier(adminEmail);
  const isAllowed = await checkRateLimit(adminHash, 'approve_registration', 50, 60);
  if (!isAllowed) {
    return tooManyRequests("Too many approval requests. Please try again later.");
  }

  const id = event.pathParameters?.registration_id;
  if (!id) return badRequest("registration_id required");

  const requestId = (event.requestContext as any).requestId;

  try {
    const reg = await getRegistration(id);

    if (reg.status === "approved") {
      return ok({ message: "already approved" });
    }

    const adminEmail = getAdminEmail(event);
    const now = new Date().toISOString();

    let userGuid: string;

    // Create Cognito user if they don't exist
    const exists = await userExistsInCognito(reg.email);
    if (!exists) {
      userGuid = randomUUID();
      await cognito.send(new AdminCreateUserCommand({
        UserPoolId: USER_POOL_ID,
        Username: reg.email,
        MessageAction: "SUPPRESS", // Don't send temporary password - users login via magic link
        UserAttributes: [
          { Name: "email", Value: reg.email },
          { Name: "email_verified", Value: "true" },
          { Name: "given_name", Value: reg.first_name },
          { Name: "family_name", Value: reg.last_name },
          { Name: "custom:user_guid", Value: userGuid }
        ]
      }));

      // Set permanent password to remove FORCE_CHANGE_PASSWORD status
      // This is required for magic link auth to work properly
      // SECURITY: Generate cryptographically secure random password (user won't use it - magic link auth)
      const { AdminSetUserPasswordCommand } = await import('@aws-sdk/client-cognito-identity-provider');
      const securePassword = randomBytes(32).toString('base64') + 'Aa1!'; // High entropy + required chars
      await cognito.send(new AdminSetUserPasswordCommand({
        UserPoolId: USER_POOL_ID,
        Username: reg.email,
        Password: securePassword,
        Permanent: true
      }));
    } else {
      // User already exists - fetch their GUID from Cognito
      const userResponse = await cognito.send(new AdminGetUserCommand({
        UserPoolId: USER_POOL_ID,
        Username: reg.email
      }));
      const guidAttr = userResponse.UserAttributes?.find(attr => attr.Name === 'custom:user_guid');
      userGuid = guidAttr?.Value || randomUUID(); // Fallback to new GUID if not found
    }

    // Add to registered group (not member - they need to request membership separately)
    await cognito.send(new AdminAddUserToGroupCommand({
      UserPoolId: USER_POOL_ID,
      Username: reg.email,
      GroupName: 'registered'
    }));

    // Update registration status, set membership_status and user_guid
    await ddb.send(new UpdateItemCommand({
      TableName: TABLES.registrations,
      Key: marshall({ registration_id: id }),
      UpdateExpression: "SET #s = :approved, approved_at = :now, approved_by = :by, membership_status = :membership_status, user_guid = :user_guid",
      ExpressionAttributeNames: { "#s": "status" },
      ExpressionAttributeValues: marshall({
        ":approved": "approved",
        ":now": now,
        ":by": adminEmail,
        ":membership_status": "pending",
        ":user_guid": userGuid
      })
    }));

    await putAudit({
      type: "registration_approved",
      id,
      email: reg.email,
      approved_by: adminEmail
    }, requestId);

    return ok({ message: "approved and user added to registered group" });
  } catch (error) {
    if (error instanceof NotFoundError) {
      return notFound(error.message);
    }
    console.error('Failed to approve registration:', error);
    return internalError("Failed to approve registration");
  }
};
