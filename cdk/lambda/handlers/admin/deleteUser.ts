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
import { AdminDisableUserCommand } from "@aws-sdk/client-cognito-identity-provider";

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

  // Rate limiting: Max 20 user deletions per admin per hour
  const adminEmail = getAdminEmail(event);
  const adminHash = hashIdentifier(adminEmail);
  const isAllowed = await checkRateLimit(adminHash, 'delete_user', 20, 60);
  if (!isAllowed) {
    return tooManyRequests("Too many delete requests. Please try again later.");
  }

  const id = event.pathParameters?.user_id;
  if (!id) return badRequest("user_id required");

  try {
    const reg = await getRegistration(id);
    const adminEmail = getAdminEmail(event);
    const now = new Date().toISOString();

    // Disable user in Cognito if they exist (don't delete - that's for permanent delete only)
    const exists = await userExistsInCognito(reg.email);
    if (exists) {
      try {
        await cognito.send(new AdminDisableUserCommand({
          UserPoolId: USER_POOL_ID,
          Username: reg.email
        }));
      } catch (err: any) {
        // User may already be disabled (from cancel), which is fine
        if (!err.name?.includes('AlreadyDisabled')) {
          throw err;
        }
      }
    }

    // Mark registration as deleted in DynamoDB
    await ddb.send(new UpdateItemCommand({
      TableName: TABLES.registrations,
      Key: marshall({ registration_id: id }),
      UpdateExpression: "SET #s = :deleted, deleted_at = :now, deleted_by = :by",
      ExpressionAttributeNames: { "#s": "status" },
      ExpressionAttributeValues: marshall({
        ":deleted": "deleted",
        ":now": now,
        ":by": adminEmail
      })
    }));

    await putAudit({
      type: "user_deleted",
      id,
      email: reg.email,
      deleted_by: adminEmail
    });

    return ok({ message: "user deleted successfully" });
  } catch (error) {
    if (error instanceof NotFoundError) {
      return notFound(error.message);
    }
    console.error('Failed to delete user:', error);
    return internalError("Failed to delete user");
  }
};
