import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { DynamoDBClient, GetItemCommand, PutItemCommand, UpdateItemCommand, TransactWriteItemsCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import {
  ok,
  badRequest,
  notFound,
  conflict,
  internalError,
  requireUserClaims,
  ValidationError,
  nowIso,
  nowSeconds,
  generateSecureId,
  parseJsonBody,
} from "../../common/util";

const ddb = new DynamoDBClient({});
const TABLE_INVITATIONS = process.env.TABLE_INVITATIONS!;
const TABLE_CONNECTIONS = process.env.TABLE_CONNECTIONS!;
const TABLE_PROFILES = process.env.TABLE_PROFILES!;

interface AcceptInviteRequest {
  invitation_code: string;
  public_key: string; // Base64-encoded X25519 public key
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
    const body = parseJsonBody<AcceptInviteRequest>(event);

    if (!body.invitation_code || typeof body.invitation_code !== "string") {
      return badRequest("invitation_code is required", origin);
    }

    if (!body.public_key || typeof body.public_key !== "string") {
      return badRequest("public_key is required", origin);
    }

    // Validate public key is valid Base64 and correct length (32 bytes for X25519)
    try {
      const keyBuffer = Buffer.from(body.public_key, "base64");
      if (keyBuffer.length !== 32) {
        return badRequest("public_key must be 32 bytes (X25519)", origin);
      }
    } catch {
      return badRequest("public_key must be valid Base64", origin);
    }

    // Normalize invitation code (remove dashes, uppercase)
    const normalizedCode = body.invitation_code.replace(/-/g, "").toUpperCase();

    // Look up invitation by code
    const invitationResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_INVITATIONS,
      Key: marshall({ invitation_code: normalizedCode }),
    }));

    if (!invitationResult.Item) {
      return notFound("Invitation not found or expired", origin);
    }

    const invitation = unmarshall(invitationResult.Item);

    // Validate invitation status
    if (invitation.status !== "pending") {
      if (invitation.status === "accepted") {
        return conflict("Invitation has already been accepted", origin);
      }
      if (invitation.status === "revoked") {
        return badRequest("Invitation has been revoked", origin);
      }
      return badRequest("Invitation is no longer valid", origin);
    }

    // Check expiration
    if (invitation.expires_at < nowSeconds()) {
      // Update status to expired
      await ddb.send(new UpdateItemCommand({
        TableName: TABLE_INVITATIONS,
        Key: marshall({ invitation_code: normalizedCode }),
        UpdateExpression: "SET #status = :expired",
        ExpressionAttributeNames: { "#status": "status" },
        ExpressionAttributeValues: marshall({ ":expired": "expired" }),
      }));
      return badRequest("Invitation has expired", origin);
    }

    // Prevent self-connection
    if (invitation.creator_guid === claims.user_guid) {
      return badRequest("Cannot accept your own invitation", origin);
    }

    // Check if connection already exists
    const existingConnection = await ddb.send(new GetItemCommand({
      TableName: TABLE_CONNECTIONS,
      Key: marshall({
        owner_guid: claims.user_guid,
        peer_guid: invitation.creator_guid,
      }),
    }));

    if (existingConnection.Item) {
      const existing = unmarshall(existingConnection.Item);
      if (existing.status === "active") {
        return conflict("You are already connected with this user", origin);
      }
    }

    // Get acceptor's profile
    let acceptorDisplayName = "VettID User";
    let acceptorAvatarUrl: string | undefined;
    try {
      const profileResult = await ddb.send(new GetItemCommand({
        TableName: TABLE_PROFILES,
        Key: marshall({ user_guid: claims.user_guid }),
      }));
      if (profileResult.Item) {
        const profile = unmarshall(profileResult.Item);
        acceptorDisplayName = profile.display_name || acceptorDisplayName;
        acceptorAvatarUrl = profile.avatar_url;
      }
    } catch {
      // Use default if profile lookup fails
    }

    // Generate connection IDs
    const connectionId = generateSecureId("CONN");
    const now = nowIso();

    // Create connection records for both parties using transaction
    await ddb.send(new TransactWriteItemsCommand({
      TransactItems: [
        // Update invitation status
        {
          Update: {
            TableName: TABLE_INVITATIONS,
            Key: marshall({ invitation_code: normalizedCode }),
            UpdateExpression: "SET #status = :accepted, accepted_at = :now, acceptor_guid = :acceptor, acceptor_public_key = :pubkey",
            ConditionExpression: "#status = :pending",
            ExpressionAttributeNames: { "#status": "status" },
            ExpressionAttributeValues: marshall({
              ":accepted": "accepted",
              ":pending": "pending",
              ":now": now,
              ":acceptor": claims.user_guid,
              ":pubkey": body.public_key,
            }),
          },
        },
        // Create connection for acceptor (owner)
        {
          Put: {
            TableName: TABLE_CONNECTIONS,
            Item: marshall({
              connection_id: connectionId,
              owner_guid: claims.user_guid,
              peer_guid: invitation.creator_guid,
              peer_display_name: invitation.creator_display_name,
              peer_avatar_url: invitation.creator_avatar_url || null,
              status: "active",
              created_at: now,
              last_message_at: null,
              unread_count: 0,
              invitation_id: invitation.invitation_id,
            }),
            ConditionExpression: "attribute_not_exists(owner_guid)",
          },
        },
        // Create connection for inviter (peer)
        {
          Put: {
            TableName: TABLE_CONNECTIONS,
            Item: marshall({
              connection_id: connectionId,
              owner_guid: invitation.creator_guid,
              peer_guid: claims.user_guid,
              peer_display_name: acceptorDisplayName,
              peer_avatar_url: acceptorAvatarUrl || null,
              status: "active",
              created_at: now,
              last_message_at: null,
              unread_count: 0,
              invitation_id: invitation.invitation_id,
              peer_public_key: body.public_key,
            }),
            ConditionExpression: "attribute_not_exists(owner_guid)",
          },
        },
      ],
    }));

    return ok({
      connection_id: connectionId,
      peer_guid: invitation.creator_guid,
      peer_display_name: invitation.creator_display_name,
      peer_avatar_url: invitation.creator_avatar_url || null,
      status: "active",
      created_at: now,
    }, origin);

  } catch (error: any) {
    console.error("Error accepting invitation:", error);

    if (error instanceof ValidationError) {
      return badRequest(error.message, origin);
    }

    if (error.name === "TransactionCanceledException") {
      // Check which condition failed
      const reasons = error.CancellationReasons || [];
      for (const reason of reasons) {
        if (reason.Code === "ConditionalCheckFailed") {
          return conflict("Invitation status changed or connection already exists", origin);
        }
      }
    }

    return internalError("Failed to accept invitation", origin);
  }
};
