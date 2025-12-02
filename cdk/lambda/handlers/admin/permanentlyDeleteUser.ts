import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ddb, TABLES, ok, badRequest, putAudit, requireAdminGroup, validatePathParam, ValidationError } from "../../common/util";
import { DeleteItemCommand, GetItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import { CognitoIdentityProviderClient, AdminDeleteUserCommand, AdminGetUserCommand } from "@aws-sdk/client-cognito-identity-provider";

const cognito = new CognitoIdentityProviderClient({});
const USER_POOL_ID = process.env.USER_POOL_ID!;
const TABLE_SUBSCRIPTIONS = process.env.TABLE_SUBSCRIPTIONS!;

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Validate admin group membership
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  let id: string;
  try {
    id = validatePathParam(event.pathParameters?.user_id, "user_id");
  } catch (error) {
    if (error instanceof ValidationError) {
      return badRequest(error.message);
    }
    return badRequest("user_id required");
  }

  const regRes = await ddb.send(new GetItemCommand({
    TableName: TABLES.registrations,
    Key: marshall({ registration_id: id })
  }));

  if (!regRes.Item) return badRequest("registration not found");
  const reg = unmarshall(regRes.Item) as any;

  const adminEmail = (event.requestContext as any)?.authorizer?.jwt?.claims?.email || "unknown@vettid.dev";

  // Check if user exists in Cognito and delete if found
  let userExists = true;
  let cognitoDeleteSuccess = false;
  try {
    await cognito.send(new AdminGetUserCommand({
      UserPoolId: USER_POOL_ID,
      Username: reg.email
    }));
  } catch (error: any) {
    if (error.name === 'UserNotFoundException') {
      userExists = false;
    } else {
      // Some other error checking user existence
      console.error('Error checking Cognito user existence:', error);
      throw error; // Re-throw unexpected errors
    }
  }

  if (userExists) {
    try {
      await cognito.send(new AdminDeleteUserCommand({
        UserPoolId: USER_POOL_ID,
        Username: reg.email
      }));
      cognitoDeleteSuccess = true;
      console.log(`Successfully deleted Cognito user: ${reg.email}`);
    } catch (error: any) {
      console.error(`CRITICAL: Failed to delete Cognito user ${reg.email}:`, error);
      // Don't throw - we still want to delete the DynamoDB record
      // But we'll include this in the response
    }
  } else {
    cognitoDeleteSuccess = true; // User didn't exist, so nothing to delete
  }

  // Permanently delete the registration record from DynamoDB
  await ddb.send(new DeleteItemCommand({
    TableName: TABLES.registrations,
    Key: marshall({ registration_id: id })
  }));

  // Delete user's subscription if it exists (using user_guid from registration)
  if (reg.user_guid && TABLE_SUBSCRIPTIONS) {
    try {
      await ddb.send(new DeleteItemCommand({
        TableName: TABLE_SUBSCRIPTIONS,
        Key: marshall({ user_guid: reg.user_guid })
      }));
    } catch {
      // Ignore - subscription may not exist
    }
  }

  await putAudit({
    type: "user_permanently_deleted",
    id,
    email: reg.email,
    deleted_by: adminEmail,
    previous_status: reg.status,
    cognito_deleted: cognitoDeleteSuccess
  });

  if (!cognitoDeleteSuccess) {
    return ok({
      message: "User record deleted, but FAILED to delete Cognito account. User may still be able to sign in.",
      warning: true,
      cognito_delete_failed: true
    });
  }

  return ok({ message: "User permanently deleted" });
};
