import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ddb, TABLES, ok, badRequest, putAudit, requireAdminGroup, validateOrigin, sanitizeInput, getRequestId } from "../../common/util";
import { UpdateItemCommand, GetItemCommand, QueryCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import { CognitoIdentityProviderClient, AdminRemoveUserFromGroupCommand, AdminGetUserCommand, AdminListGroupsForUserCommand } from "@aws-sdk/client-cognito-identity-provider";

const cognito = new CognitoIdentityProviderClient({});
const USER_POOL_ID = process.env.USER_POOL_ID!;

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Validate admin group membership
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  // CSRF protection: Validate request origin
  const csrfError = validateOrigin(event);
  if (csrfError) return csrfError;

  const id = event.pathParameters?.registration_id;
  if (!id) return badRequest("registration_id required");

  const requestId = getRequestId(event);

  // Safely parse JSON body with try-catch
  let body: any = {};
  if (event.body) {
    try {
      body = JSON.parse(event.body);
    } catch {
      return badRequest("Invalid JSON in request body");
    }
  }
  const reason: string = sanitizeInput(body.reason || "");

  const regRes = await ddb.send(new GetItemCommand({ TableName: TABLES.registrations, Key: marshall({ registration_id: id }) }));
  if (!regRes.Item) return badRequest("registration not found");
  const reg = unmarshall(regRes.Item) as any;

  if (reg.status === "rejected") return ok({ message: "already rejected" });
  if (reg.status === "approved") return badRequest("cannot reject an approved registration");

  const adminEmail = (event.requestContext as any)?.authorizer?.jwt?.claims?.email || "unknown@vettid.dev";

  await ddb.send(new UpdateItemCommand({
    TableName: TABLES.registrations,
    Key: marshall({ registration_id: id }),
    UpdateExpression: "SET #s = :rejected, rejection_reason = :reason, rejected_at = :now, rejected_by = :by",
    ExpressionAttributeNames: {"#s":"status"},
    ExpressionAttributeValues: marshall({ ":rejected":"rejected", ":reason": reason, ":now": new Date().toISOString(), ":by": adminEmail })
  }));

  // Check if user exists in Cognito and remove from groups if no other approved registrations exist
  if (reg.email) {
    try {
      // Check if user exists in Cognito
      await cognito.send(new AdminGetUserCommand({
        UserPoolId: USER_POOL_ID,
        Username: reg.email
      }));

      // User exists - check for other approved registrations with this email
      const otherApproved = await ddb.send(new QueryCommand({
        TableName: TABLES.registrations,
        IndexName: 'email-index',
        KeyConditionExpression: 'email = :email',
        FilterExpression: '#s = :approved AND registration_id <> :currentId',
        ExpressionAttributeNames: { '#s': 'status' },
        ExpressionAttributeValues: marshall({
          ':email': reg.email,
          ':approved': 'approved',
          ':currentId': id
        }),
        Limit: 1
      }));

      // If no other approved registrations, remove user from all groups
      if (!otherApproved.Items || otherApproved.Items.length === 0) {
        // Get user's current groups
        const groupsRes = await cognito.send(new AdminListGroupsForUserCommand({
          UserPoolId: USER_POOL_ID,
          Username: reg.email
        }));

        // Remove from each group
        for (const group of (groupsRes.Groups || [])) {
          if (group.GroupName) {
            await cognito.send(new AdminRemoveUserFromGroupCommand({
              UserPoolId: USER_POOL_ID,
              Username: reg.email,
              GroupName: group.GroupName
            }));
          }
        }

        await putAudit({
          type: "user_groups_removed",
          email: reg.email,
          reason: "registration_rejected",
          groups_removed: (groupsRes.Groups || []).map(g => g.GroupName)
        }, requestId);
      }
    } catch (error: any) {
      // User doesn't exist in Cognito - that's fine, nothing to remove
      if (error.name !== 'UserNotFoundException') {
        console.warn('Error checking/updating Cognito user during rejection:', error);
      }
    }
  }

  await putAudit({ type: "registration_rejected", id, email: reg.email, reason, rejected_by: adminEmail }, requestId);
  return ok({ message: "rejected" });
};
