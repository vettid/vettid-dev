import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { DynamoDBClient, UpdateItemCommand, GetItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import {
  ok,
  badRequest,
  internalError,
  requireUserClaims,
  ValidationError,
  nowIso,
  parseJsonBody,
  sanitizeInput,
  validateStringInput,
} from "../../common/util";

const ddb = new DynamoDBClient({});
const TABLE_PROFILES = process.env.TABLE_PROFILES!;

interface UpdateProfileRequest {
  display_name?: string;
  avatar_url?: string;
  bio?: string;
  location?: string;
}

export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const origin = event.headers?.origin;

  try {
    // Validate user claims
    const claimsResult = requireUserClaims(event, origin);
    if ("error" in claimsResult) {
      return claimsResult.error;
    }
    const { claims } = claimsResult;

    // Parse request body
    const body = parseJsonBody<UpdateProfileRequest>(event);

    // Validate and sanitize fields
    const updates: Record<string, any> = {};
    const expressionParts: string[] = [];
    const expressionNames: Record<string, string> = {};
    const expressionValues: Record<string, any> = {};

    if (body.display_name !== undefined) {
      const displayName = validateStringInput(body.display_name, "display_name", 1, 100);
      updates.display_name = sanitizeInput(displayName, 100);
      expressionParts.push("#display_name = :display_name");
      expressionNames["#display_name"] = "display_name";
      expressionValues[":display_name"] = updates.display_name;
    }

    if (body.avatar_url !== undefined) {
      if (body.avatar_url === null || body.avatar_url === "") {
        updates.avatar_url = null;
      } else {
        // Validate URL format
        try {
          const url = new URL(body.avatar_url);
          if (!["http:", "https:"].includes(url.protocol)) {
            return badRequest("avatar_url must be http or https", origin);
          }
          if (body.avatar_url.length > 500) {
            return badRequest("avatar_url must be at most 500 characters", origin);
          }
          updates.avatar_url = body.avatar_url;
        } catch {
          return badRequest("avatar_url must be a valid URL", origin);
        }
      }
      expressionParts.push("avatar_url = :avatar_url");
      expressionValues[":avatar_url"] = updates.avatar_url;
    }

    if (body.bio !== undefined) {
      if (body.bio === null || body.bio === "") {
        updates.bio = null;
      } else {
        if (body.bio.length > 500) {
          return badRequest("bio must be at most 500 characters", origin);
        }
        updates.bio = sanitizeInput(body.bio, 500);
      }
      expressionParts.push("bio = :bio");
      expressionValues[":bio"] = updates.bio;
    }

    if (body.location !== undefined) {
      if (body.location === null || body.location === "") {
        updates.location = null;
      } else {
        if (body.location.length > 100) {
          return badRequest("location must be at most 100 characters", origin);
        }
        updates.location = sanitizeInput(body.location, 100);
      }
      expressionParts.push("#location = :location");
      expressionNames["#location"] = "location";
      expressionValues[":location"] = updates.location;
    }

    if (expressionParts.length === 0) {
      return badRequest("No fields to update", origin);
    }

    // Add updated_at and increment version
    const now = nowIso();
    expressionParts.push("updated_at = :updated_at");
    expressionValues[":updated_at"] = now;

    expressionParts.push("#version = if_not_exists(#version, :zero) + :one");
    expressionNames["#version"] = "version";
    expressionValues[":zero"] = 0;
    expressionValues[":one"] = 1;

    // Update profile
    const result = await ddb.send(new UpdateItemCommand({
      TableName: TABLE_PROFILES,
      Key: marshall({ user_guid: claims.user_guid }),
      UpdateExpression: `SET ${expressionParts.join(", ")}`,
      ExpressionAttributeNames: Object.keys(expressionNames).length > 0 ? expressionNames : undefined,
      ExpressionAttributeValues: marshall(expressionValues),
      ReturnValues: "ALL_NEW",
    }));

    const profile = result.Attributes ? unmarshall(result.Attributes) : null;

    if (!profile) {
      return internalError("Failed to update profile", origin);
    }

    return ok({
      guid: profile.user_guid,
      display_name: profile.display_name,
      avatar_url: profile.avatar_url || null,
      bio: profile.bio || null,
      location: profile.location || null,
      last_updated: profile.updated_at,
      version: profile.version,
    }, origin);

  } catch (error) {
    console.error("Error updating profile:", error);
    if (error instanceof ValidationError) {
      return badRequest(error.message, origin);
    }
    return internalError("Failed to update profile", origin);
  }
};
