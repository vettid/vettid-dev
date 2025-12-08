import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { DynamoDBClient, PutItemCommand, QueryCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import { randomBytes } from "crypto";
import {
  ok,
  badRequest,
  internalError,
  requireUserClaims,
  ValidationError,
  nowIso,
  addMinutesSeconds,
  generateSecureId,
} from "../../common/util";

const ddb = new DynamoDBClient({});
const TABLE_INVITATIONS = process.env.TABLE_INVITATIONS!;
const TABLE_PROFILES = process.env.TABLE_PROFILES!;
const MAX_PENDING_INVITATIONS = 5;
const DEFAULT_EXPIRATION_MINUTES = 60;

interface CreateInviteRequest {
  expires_in_minutes?: number;
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
    let expiresInMinutes = DEFAULT_EXPIRATION_MINUTES;
    if (event.body) {
      try {
        const body: CreateInviteRequest = JSON.parse(event.body);
        if (body.expires_in_minutes !== undefined) {
          if (typeof body.expires_in_minutes !== "number" || body.expires_in_minutes < 5 || body.expires_in_minutes > 1440) {
            return badRequest("expires_in_minutes must be between 5 and 1440 (24 hours)", origin);
          }
          expiresInMinutes = body.expires_in_minutes;
        }
      } catch {
        return badRequest("Invalid JSON in request body", origin);
      }
    }

    // Check pending invitations count
    const pendingInvitations = await ddb.send(new QueryCommand({
      TableName: TABLE_INVITATIONS,
      IndexName: "creator-index",
      KeyConditionExpression: "creator_guid = :guid",
      FilterExpression: "#status = :pending",
      ExpressionAttributeNames: { "#status": "status" },
      ExpressionAttributeValues: marshall({
        ":guid": claims.user_guid,
        ":pending": "pending",
      }),
    }));

    if ((pendingInvitations.Items?.length || 0) >= MAX_PENDING_INVITATIONS) {
      return badRequest(`Maximum of ${MAX_PENDING_INVITATIONS} pending invitations allowed`, origin);
    }

    // Get creator's profile for display name
    let creatorDisplayName = "VettID User";
    try {
      const profileResult = await ddb.send(new QueryCommand({
        TableName: TABLE_PROFILES,
        KeyConditionExpression: "user_guid = :guid",
        ExpressionAttributeValues: marshall({ ":guid": claims.user_guid }),
        Limit: 1,
      }));
      if (profileResult.Items?.[0]) {
        const profile = unmarshall(profileResult.Items[0]);
        creatorDisplayName = profile.display_name || creatorDisplayName;
      }
    } catch {
      // Use default display name if profile lookup fails
    }

    // Generate invitation
    const invitationId = generateSecureId("INV");
    const invitationCode = generateInvitationCode();
    const now = nowIso();
    const expiresAt = addMinutesSeconds(expiresInMinutes);

    // Create QR code data and deep link
    const qrCodeData = JSON.stringify({
      type: "vettid_connection_invite",
      code: invitationCode,
      creator: creatorDisplayName,
    });
    const deepLinkUrl = `vettid://connect/${invitationCode}`;

    const invitation = {
      invitation_id: invitationId,
      invitation_code: invitationCode,
      creator_guid: claims.user_guid,
      creator_display_name: creatorDisplayName,
      status: "pending",
      created_at: now,
      expires_at: expiresAt,
      ttl: expiresAt + 86400, // TTL 24 hours after expiration for cleanup
    };

    await ddb.send(new PutItemCommand({
      TableName: TABLE_INVITATIONS,
      Item: marshall(invitation),
      ConditionExpression: "attribute_not_exists(invitation_id)",
    }));

    return ok({
      invitation_id: invitationId,
      invitation_code: invitationCode,
      qr_code_data: qrCodeData,
      deep_link_url: deepLinkUrl,
      expires_at: expiresAt,
      creator_display_name: creatorDisplayName,
    }, origin);

  } catch (error) {
    console.error("Error creating invitation:", error);
    if (error instanceof ValidationError) {
      return badRequest(error.message, origin);
    }
    return internalError("Failed to create invitation", origin);
  }
};

/**
 * Generate a human-readable invitation code
 * Format: XXXX-XXXX-XXXX (12 chars, alphanumeric, no ambiguous chars)
 */
function generateInvitationCode(): string {
  // Exclude ambiguous characters: 0, O, I, l, 1
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = randomBytes(12);
  let code = "";

  for (let i = 0; i < 12; i++) {
    code += chars[bytes[i] % chars.length];
    if (i === 3 || i === 7) {
      code += "-";
    }
  }

  return code;
}
