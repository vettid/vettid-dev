import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ddb, TABLES, ok, badRequest, putAudit, requireAdminGroup } from "../../common/util";
import { DeleteItemCommand, GetItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import { CognitoIdentityProviderClient, AdminDeleteUserCommand, AdminGetUserCommand } from "@aws-sdk/client-cognito-identity-provider";

const cognito = new CognitoIdentityProviderClient({});
const USER_POOL_ID = process.env.USER_POOL_ID!;

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Validate admin group membership
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  const id = event.pathParameters?.id;
  if (!id) return badRequest("id required");

  const regRes = await ddb.send(new GetItemCommand({
    TableName: TABLES.registrations,
    Key: marshall({ registration_id: id })
  }));

  if (!regRes.Item) return badRequest("registration not found");
  const reg = unmarshall(regRes.Item) as any;

  const adminEmail = (event.requestContext as any)?.authorizer?.jwt?.claims?.email || "unknown@vettid.dev";

  // Check if user exists in Cognito and delete if found
  let userExists = true;
  try {
    await cognito.send(new AdminGetUserCommand({
      UserPoolId: USER_POOL_ID,
      Username: reg.email
    }));
  } catch {
    userExists = false;
  }

  if (userExists) {
    await cognito.send(new AdminDeleteUserCommand({
      UserPoolId: USER_POOL_ID,
      Username: reg.email
    }));
  }

  // Permanently delete the registration record from DynamoDB
  await ddb.send(new DeleteItemCommand({
    TableName: TABLES.registrations,
    Key: marshall({ registration_id: id })
  }));

  await putAudit({
    type: "user_permanently_deleted",
    id,
    email: reg.email,
    deleted_by: adminEmail,
    previous_status: reg.status
  });

  return ok({ message: "user permanently deleted" });
};
