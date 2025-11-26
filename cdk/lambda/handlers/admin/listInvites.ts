import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ddb, TABLES, ok, requireAdminGroup } from "../../common/util";
import { ScanCommand } from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Validate admin group membership
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  const status = event.queryStringParameters?.status;
  const limit = Number(event.queryStringParameters?.limit || 1000);

  const params: any = {
    TableName: TABLES.invites,
    Limit: limit
  };

  // If status filter is provided, add FilterExpression
  if (status) {
    params.FilterExpression = "#s = :status";
    params.ExpressionAttributeNames = { "#s": "status" };
    params.ExpressionAttributeValues = { ":status": { S: status } };
  }

  const res = await ddb.send(new ScanCommand(params));
  const items = (res.Items || []).map((i) => unmarshall(i as any));

  // Sort by created_at descending
  items.sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''));

  return ok(items);
};
