import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { DynamoDBClient, QueryCommand } from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";
import {
  ok,
  badRequest,
  notFound,
  internalError,
  requireUserClaims,
  ValidationError,
} from "../../common/util";

const ddb = new DynamoDBClient({});
const TABLE_REGISTRATIONS = process.env.TABLE_REGISTRATIONS!;

/**
 * GET /profile/registration
 *
 * Returns read-only registration data for the authenticated user.
 * Used by mobile post-enrollment flow to populate profile with registration info.
 *
 * Response:
 * {
 *   "firstName": "string",
 *   "lastName": "string",
 *   "email": "string"
 * }
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const origin = event.headers?.origin;

  try {
    // Validate user claims - get email from JWT
    const claimsResult = requireUserClaims(event, origin);
    if ("error" in claimsResult) {
      return claimsResult.error;
    }
    const { claims } = claimsResult;

    // Query registrations table by email using GSI
    const result = await ddb.send(new QueryCommand({
      TableName: TABLE_REGISTRATIONS,
      IndexName: "email-index",
      KeyConditionExpression: "email = :email",
      ExpressionAttributeValues: {
        ":email": { S: claims.email },
        ":deleted": { S: "deleted" },
        ":rejected": { S: "rejected" },
      },
      // Only return active registrations (not deleted or rejected)
      FilterExpression: "#status <> :deleted AND #status <> :rejected",
      ExpressionAttributeNames: {
        "#status": "status",
      },
      Limit: 1,
    }));

    if (!result.Items || result.Items.length === 0) {
      return notFound("Registration not found", origin);
    }

    const registration = unmarshall(result.Items[0]);

    // Return read-only registration data
    return ok({
      firstName: registration.first_name || "",
      lastName: registration.last_name || "",
      email: registration.email || claims.email,
    }, origin);

  } catch (error: any) {
    console.error("Error getting registration:", error);

    if (error instanceof ValidationError) {
      return badRequest(error.message, origin);
    }
    return internalError("Failed to get registration", origin);
  }
};
