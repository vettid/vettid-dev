import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ddb, TABLES, ok, requireAdminGroup, putAudit } from "../../common/util";
import { QueryCommand, ScanCommand } from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";
import { CognitoIdentityProviderClient, AdminGetUserCommand, AdminListGroupsForUserCommand } from "@aws-sdk/client-cognito-identity-provider";

const cognito = new CognitoIdentityProviderClient({});
const USER_POOL_ID = process.env.USER_POOL_ID!;

// SECURITY: Maximum items to return per request
const MAX_LIMIT = 100;
const DEFAULT_LIMIT = 20; // SECURITY: Reduced from 50 for better performance

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

  const status = event.queryStringParameters?.status;
  // SECURITY: Enforce reasonable limits to prevent abuse
  const requestedLimit = Number(event.queryStringParameters?.limit || DEFAULT_LIMIT);
  const limit = Math.min(Math.max(1, requestedLimit), MAX_LIMIT);
  const cursor = event.queryStringParameters?.cursor; // For pagination

  // Decode pagination cursor if provided
  let exclusiveStartKey: Record<string, any> | undefined;
  if (cursor) {
    try {
      exclusiveStartKey = JSON.parse(Buffer.from(cursor, 'base64').toString('utf-8'));
    } catch {
      // Invalid cursor, ignore
    }
  }

  let res;
  if (status) {
    // Query by specific status using the GSI
    res = await ddb.send(new QueryCommand({
      TableName: TABLES.registrations,
      IndexName: "status-index",
      KeyConditionExpression: "#s = :status",
      ExpressionAttributeNames: { "#s": "status" },
      ExpressionAttributeValues: { ":status": { S: status } },
      ScanIndexForward: false,
      Limit: limit,
      ExclusiveStartKey: exclusiveStartKey
    }));
  } else {
    // Scan to get all registrations
    res = await ddb.send(new ScanCommand({
      TableName: TABLES.registrations,
      Limit: limit,
      ExclusiveStartKey: exclusiveStartKey
    }));
  }

  const items = (res.Items || []).map((i) => unmarshall(i as any));

  // For approved users, fetch GUID and groups from Cognito
  const enrichedItems = await Promise.all(items.map(async (item:any) => {
    if (item.status === 'approved' && item.email) {
      try {
        const userRes = await cognito.send(new AdminGetUserCommand({
          UserPoolId: USER_POOL_ID,
          Username: item.email
        }));
        const guidAttr = userRes.UserAttributes?.find(attr => attr.Name === 'custom:user_guid');
        if (guidAttr) {
          item.user_guid = guidAttr.Value;
        }

        // Fetch user's groups
        const groupsRes = await cognito.send(new AdminListGroupsForUserCommand({
          UserPoolId: USER_POOL_ID,
          Username: item.email
        }));
        item.groups = (groupsRes.Groups || []).map(g => g.GroupName);
      } catch (error) {
        // User might not exist in Cognito yet, silently skip
      }
    }
    return item;
  }));

  // Build response with pagination cursor
  const response: any = {
    items: enrichedItems,
    count: enrichedItems.length,
    limit: limit
  };

  // Include next cursor if there are more results
  if (res.LastEvaluatedKey) {
    response.nextCursor = Buffer.from(JSON.stringify(res.LastEvaluatedKey)).toString('base64');
  }

  return ok(response);
};

