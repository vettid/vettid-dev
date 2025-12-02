import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ddb, TABLES, ok, badRequest, notFound, putAudit, requireAdminGroup } from "../../common/util";
import { UpdateItemCommand, GetItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import { CognitoIdentityProviderClient, AdminDisableUserCommand, AdminGetUserCommand } from "@aws-sdk/client-cognito-identity-provider";

const cognito = new CognitoIdentityProviderClient({});
const USER_POOL_ID = process.env.USER_POOL_ID!;

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Validate admin group membership
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  const id = event.pathParameters?.user_id;
  if (!id) return badRequest("user_id required");

  const regRes = await ddb.send(new GetItemCommand({
    TableName: TABLES.registrations,
    Key: marshall({ registration_id: id })
  }));

  if (!regRes.Item) return notFound("User not found");
  const reg = unmarshall(regRes.Item) as any;

  if (reg.status !== "approved") return badRequest("user is not approved");

  const adminEmail = (event.requestContext as any)?.authorizer?.jwt?.claims?.email || "unknown@vettid.dev";
  const now = new Date().toISOString();

  // Check if user exists in Cognito
  let userExists = true;
  try {
    await cognito.send(new AdminGetUserCommand({
      UserPoolId: USER_POOL_ID,
      Username: reg.email
    }));
  } catch {
    userExists = false;
  }

  // Disable user in Cognito if they exist
  if (userExists) {
    await cognito.send(new AdminDisableUserCommand({
      UserPoolId: USER_POOL_ID,
      Username: reg.email
    }));
  }

  // Update registration status to disabled
  await ddb.send(new UpdateItemCommand({
    TableName: TABLES.registrations,
    Key: marshall({ registration_id: id }),
    UpdateExpression: "SET #s = :disabled, disabled_at = :now, disabled_by = :by",
    ExpressionAttributeNames: { "#s": "status" },
    ExpressionAttributeValues: marshall({
      ":disabled": "disabled",
      ":now": now,
      ":by": adminEmail
    })
  }));

  await putAudit({
    type: "user_disabled",
    id,
    email: reg.email,
    disabled_by: adminEmail
  });

  return ok({ message: "user disabled successfully" });
};
