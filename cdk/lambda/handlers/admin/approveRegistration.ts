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
  tooManyRequests,
  validatePathParam,
  ValidationError
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

  let id: string;
  try {
    id = validatePathParam(event.pathParameters?.registration_id, "registration_id");
  } catch (error) {
    if (error instanceof ValidationError) {
      return badRequest(error.message);
    }
    return badRequest("registration_id required");
  }

  const requestId = (event.requestContext as any).requestId;

  try {
    const reg = await getRegistration(id);

    if (reg.status === "approved") {
      return ok({ message: "already approved" });
    }

    const adminEmail = getAdminEmail(event);
    const now = new Date().toISOString();

    let userGuid: string;
    let needsUserCreation = false;

    // SECURITY FIX: Check Cognito first, but update DynamoDB BEFORE creating Cognito user
    // This prevents orphaned Cognito users if DynamoDB update fails
    const exists = await userExistsInCognito(reg.email);
    if (!exists) {
      userGuid = randomUUID();
      needsUserCreation = true;
    } else {
      // User already exists - fetch their GUID from Cognito
      const userResponse = await cognito.send(new AdminGetUserCommand({
        UserPoolId: USER_POOL_ID,
        Username: reg.email
      }));
      const guidAttr = userResponse.UserAttributes?.find(attr => attr.Name === 'custom:user_guid');

      if (!guidAttr?.Value) {
        // CRITICAL: Existing user is missing custom:user_guid attribute
        console.error(`User ${reg.email} exists in Cognito but missing custom:user_guid attribute`);
        await putAudit({
          type: 'approval_error_missing_guid',
          email: reg.email,
          registration_id: id,
          error: 'Existing Cognito user missing custom:user_guid attribute - requires manual intervention'
        }, requestId);
        return internalError('User account requires administrative repair. Please contact support.');
      }

      userGuid = guidAttr.Value;
    }

    // STEP 1: Update DynamoDB FIRST (before Cognito mutation)
    // This ensures we don't create orphaned Cognito users
    try {
      await ddb.send(new UpdateItemCommand({
        TableName: TABLES.registrations,
        Key: marshall({ registration_id: id }),
        UpdateExpression: "SET #s = :approved, approved_at = :now, approved_by = :by, membership_status = :membership_status, user_guid = :user_guid",
        ConditionExpression: "#s = :pending",
        ExpressionAttributeNames: { "#s": "status" },
        ExpressionAttributeValues: marshall({
          ":approved": "approved",
          ":pending": "pending",
          ":now": now,
          ":by": adminEmail,
          ":membership_status": "pending",
          ":user_guid": userGuid
        })
      }));
    } catch (error: any) {
      if (error.name === 'ConditionalCheckFailedException') {
        return ok({ message: "already approved" });
      }
      throw error;
    }

    // STEP 2: Create Cognito user if needed (DynamoDB already updated)
    if (needsUserCreation) {
      try {
        await cognito.send(new AdminCreateUserCommand({
          UserPoolId: USER_POOL_ID,
          Username: reg.email,
          MessageAction: "SUPPRESS",
          UserAttributes: [
            { Name: "email", Value: reg.email },
            { Name: "email_verified", Value: "true" },
            { Name: "given_name", Value: reg.first_name },
            { Name: "family_name", Value: reg.last_name },
            { Name: "custom:user_guid", Value: userGuid }
          ]
        }));

        // Set permanent password for magic link auth
        const { AdminSetUserPasswordCommand } = await import('@aws-sdk/client-cognito-identity-provider');
        const securePassword = randomBytes(32).toString('base64') + 'Aa1!';
        await cognito.send(new AdminSetUserPasswordCommand({
          UserPoolId: USER_POOL_ID,
          Username: reg.email,
          Password: securePassword,
          Permanent: true
        }));
      } catch (cognitoError) {
        // Rollback DynamoDB on Cognito failure
        console.error('Cognito user creation failed, rolling back DynamoDB:', cognitoError);
        await ddb.send(new UpdateItemCommand({
          TableName: TABLES.registrations,
          Key: marshall({ registration_id: id }),
          UpdateExpression: "SET #s = :pending, approved_at = :null, approved_by = :null",
          ExpressionAttributeNames: { "#s": "status" },
          ExpressionAttributeValues: marshall({
            ":pending": "pending",
            ":null": null
          })
        }));
        throw cognitoError;
      }
    }

    // STEP 3: Add to registered group
    await cognito.send(new AdminAddUserToGroupCommand({
      UserPoolId: USER_POOL_ID,
      Username: reg.email,
      GroupName: 'registered'
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
