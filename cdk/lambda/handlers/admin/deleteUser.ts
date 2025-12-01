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
import { UpdateItemCommand, QueryCommand, DeleteItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import { AdminDeleteUserCommand } from "@aws-sdk/client-cognito-identity-provider";

const TABLE_WAITLIST = process.env.TABLE_WAITLIST!;

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
    const deletedData = [];

    // 1. DELETE user from Cognito completely (not just disable)
    const exists = await userExistsInCognito(reg.email);
    if (exists) {
      try {
        await cognito.send(new AdminDeleteUserCommand({
          UserPoolId: USER_POOL_ID,
          Username: reg.email
        }));
        deletedData.push('cognito_user');
        console.log(`Deleted Cognito user: ${reg.email}`);
      } catch (err: any) {
        // If user doesn't exist, that's fine (already deleted)
        if (err.name !== 'UserNotFoundException') {
          console.error(`Error deleting Cognito user ${reg.email}:`, err);
          // CRITICAL: Do NOT continue with DynamoDB cleanup if Cognito deletion fails
          // This prevents orphaned Cognito users that can still login but have no registration record
          await putAudit({
            type: 'user_delete_failed',
            registration_id: id,
            email: reg.email,
            reason: 'cognito_deletion_failed',
            error: err.message,
            attempted_by: adminEmail
          });
          return internalError(`Failed to delete Cognito user. Please try again or contact support. Error: ${err.name}`);
        }
      }
    }

    // 2. DELETE all waitlist entries for this email
    try {
      const waitlistEntries = await ddb.send(new QueryCommand({
        TableName: TABLE_WAITLIST,
        KeyConditionExpression: 'email = :email',
        ExpressionAttributeValues: marshall({ ':email': reg.email }),
      }));

      if (waitlistEntries.Items && waitlistEntries.Items.length > 0) {
        // Delete all waitlist entries for this email
        for (const item of waitlistEntries.Items) {
          const entry = unmarshall(item);
          await ddb.send(new DeleteItemCommand({
            TableName: TABLE_WAITLIST,
            Key: marshall({
              email: reg.email,
              waitlist_id: entry.waitlist_id
            })
          }));
          deletedData.push('waitlist_entry');
        }
        console.log(`Deleted ${waitlistEntries.Items.length} waitlist entries for ${reg.email}`);
      }
    } catch (err: any) {
      console.error(`Error deleting waitlist entries for ${reg.email}:`, err);
      // Continue with other cleanup
    }

    // 3. DELETE the registration record completely (not just mark as deleted)
    await ddb.send(new DeleteItemCommand({
      TableName: TABLES.registrations,
      Key: marshall({ registration_id: id })
    }));
    deletedData.push('registration');
    console.log(`Deleted registration: ${id}`);

    // 4. Clean up user preferences and other data from audit table
    //    (getting_started, email_preferences, etc. use pattern: <type>_<email>)
    try {
      const auditPrefixesToCheck = [
        `getting_started_${reg.email}`,
        `email_preferences_${reg.email}`,
        `pin_${reg.email}`,
        `magic_link_${reg.email}`
      ];

      for (const prefixId of auditPrefixesToCheck) {
        try {
          await ddb.send(new DeleteItemCommand({
            TableName: TABLES.audit,
            Key: marshall({ id: prefixId })
          }));
          deletedData.push(`audit_${prefixId.split('_')[0]}`);
        } catch (err: any) {
          // Item may not exist, which is fine
          if (err.name !== 'ResourceNotFoundException') {
            console.warn(`Error deleting audit item ${prefixId}:`, err);
          }
        }
      }
    } catch (err: any) {
      console.error(`Error cleaning up audit data for ${reg.email}:`, err);
      // Continue - this is not critical
    }

    // 5. Write final audit log for the deletion itself
    await putAudit({
      type: "user_deleted",
      id,
      email: reg.email,
      deleted_by: adminEmail,
      deleted_data: deletedData,
      deleted_at: now
    });

    return ok({
      message: "User deleted successfully. All user data has been permanently removed.",
      deleted: deletedData
    });
  } catch (error) {
    if (error instanceof NotFoundError) {
      return notFound(error.message);
    }
    console.error('Failed to delete user:', error);
    return internalError("Failed to delete user");
  }
};
