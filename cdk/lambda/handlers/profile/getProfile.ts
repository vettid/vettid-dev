import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { DynamoDBClient, GetItemCommand, PutItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import {
  ok,
  badRequest,
  internalError,
  requireUserClaims,
  ValidationError,
  nowIso,
} from "../../common/util";

const ddb = new DynamoDBClient({});
const TABLE_PROFILES = process.env.TABLE_PROFILES!;

export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const origin = event.headers?.origin;

  try {
    // Validate user claims
    const claimsResult = requireUserClaims(event, origin);
    if ("error" in claimsResult) {
      return claimsResult.error;
    }
    const { claims } = claimsResult;

    // Get user's profile
    const result = await ddb.send(new GetItemCommand({
      TableName: TABLE_PROFILES,
      Key: marshall({ user_guid: claims.user_guid }),
    }));

    if (!result.Item) {
      // Create default profile if none exists
      const now = nowIso();
      const defaultProfile = {
        user_guid: claims.user_guid,
        display_name: claims.email.split("@")[0], // Use email prefix as default name
        avatar_url: null,
        bio: null,
        location: null,
        created_at: now,
        updated_at: now,
        version: 1,
      };

      await ddb.send(new PutItemCommand({
        TableName: TABLE_PROFILES,
        Item: marshall(defaultProfile),
        ConditionExpression: "attribute_not_exists(user_guid)",
      }));

      return ok({
        guid: claims.user_guid,
        display_name: defaultProfile.display_name,
        avatar_url: null,
        bio: null,
        location: null,
        last_updated: now,
      }, origin);
    }

    const profile = unmarshall(result.Item);

    return ok({
      guid: profile.user_guid,
      display_name: profile.display_name,
      avatar_url: profile.avatar_url || null,
      bio: profile.bio || null,
      location: profile.location || null,
      last_updated: profile.updated_at || profile.created_at,
    }, origin);

  } catch (error: any) {
    console.error("Error getting profile:", error);

    // Handle race condition where profile was created between check and put
    if (error.name === "ConditionalCheckFailedException") {
      // Retry the get
      try {
        const claimsResult = requireUserClaims(event, event.headers?.origin);
        if ("error" in claimsResult) {
          return claimsResult.error;
        }
        const { claims } = claimsResult;

        const retryResult = await ddb.send(new GetItemCommand({
          TableName: TABLE_PROFILES,
          Key: marshall({ user_guid: claims.user_guid }),
        }));

        if (retryResult.Item) {
          const profile = unmarshall(retryResult.Item);
          return ok({
            guid: profile.user_guid,
            display_name: profile.display_name,
            avatar_url: profile.avatar_url || null,
            bio: profile.bio || null,
            location: profile.location || null,
            last_updated: profile.updated_at || profile.created_at,
          }, origin);
        }
      } catch (retryError) {
        console.error("Error retrying profile get:", retryError);
      }
    }

    if (error instanceof ValidationError) {
      return badRequest(error.message, origin);
    }
    return internalError("Failed to get profile", origin);
  }
};
