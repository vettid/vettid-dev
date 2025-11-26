import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ddb, TABLES, ok, badRequest, putAudit, requireAdminGroup } from "../../common/util";
import { UpdateItemCommand, GetItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import { CognitoIdentityProviderClient, AdminEnableUserCommand, AdminGetUserCommand } from "@aws-sdk/client-cognito-identity-provider";

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

  if (reg.status !== "disabled" && reg.status !== "canceled" && reg.status !== "deleted") {
    return badRequest("user is not disabled, canceled, or deleted");
  }

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

  // Enable user in Cognito if they exist
  if (userExists) {
    await cognito.send(new AdminEnableUserCommand({
      UserPoolId: USER_POOL_ID,
      Username: reg.email
    }));
  }

  // Update registration status back to approved and clear scheduled deletion
  await ddb.send(new UpdateItemCommand({
    TableName: TABLES.registrations,
    Key: marshall({ registration_id: id }),
    UpdateExpression: "SET #s = :approved, enabled_at = :now, enabled_by = :by REMOVE disabled_at, disabled_by, canceled_at, canceled_by, deleted_at, deleted_by, scheduled_deletion_date",
    ExpressionAttributeNames: { "#s": "status" },
    ExpressionAttributeValues: marshall({
      ":approved": "approved",
      ":now": now,
      ":by": adminEmail
    })
  }));

  await putAudit({
    type: "user_enabled",
    id,
    email: reg.email,
    enabled_by: adminEmail
  });

  return ok({ message: "user enabled successfully" });
};
