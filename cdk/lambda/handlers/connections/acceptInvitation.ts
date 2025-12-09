import { APIGatewayProxyEventV2WithJWTAuthorizer, APIGatewayProxyResultV2 } from "aws-lambda";
import { DynamoDBClient, GetItemCommand, PutItemCommand, UpdateItemCommand, QueryCommand, ScanCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import { randomBytes, createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync } from "crypto";
import { ok, badRequest, forbidden, notFound, internalError, nowIso, requireMemberGroup, hashForLog } from "../../common/util";

const ddb = new DynamoDBClient({});
const TABLE_INVITATIONS = process.env.TABLE_CONNECTION_INVITATIONS!;
const TABLE_CONNECTIONS = process.env.TABLE_CONNECTIONS!;
const TABLE_PROFILES = process.env.TABLE_PROFILES!;

interface AcceptInvitationRequest {
  invite_code: string;
  display_name?: string;
  include_profile?: boolean;
}

/**
 * POST /member/connections/accept
 *
 * Accepts a connection invitation and establishes a bidirectional connection.
 * Performs X25519 key exchange to derive a shared secret for message encryption.
 */
export const handler = async (
  event: APIGatewayProxyEventV2WithJWTAuthorizer
): Promise<APIGatewayProxyResultV2> => {
  try {
    // Require member group
    const authError = requireMemberGroup(event);
    if (authError) return authError;

    const acceptorGuid = event.requestContext.authorizer.jwt.claims.sub as string;
    const acceptorEmail = event.requestContext.authorizer.jwt.claims.email as string;

    // Parse request body
    if (!event.body) {
      return badRequest("Request body is required");
    }

    let body: AcceptInvitationRequest;
    try {
      body = JSON.parse(event.body);
    } catch {
      return badRequest("Invalid JSON body");
    }

    if (!body.invite_code) {
      return badRequest("invite_code is required");
    }

    const inviteCode = body.invite_code.toUpperCase().trim();
    if (!/^[A-Z2-9]{6}$/.test(inviteCode)) {
      return badRequest("Invalid invite code format");
    }

    // Look up invitation by code
    const inviteResult = await ddb.send(new QueryCommand({
      TableName: TABLE_INVITATIONS,
      IndexName: "invite-code-index",
      KeyConditionExpression: "invite_code = :code",
      FilterExpression: "#status = :active",
      ExpressionAttributeNames: { "#status": "status" },
      ExpressionAttributeValues: marshall({
        ":code": inviteCode,
        ":active": "active",
      }),
    }));

    if (!inviteResult.Items || inviteResult.Items.length === 0) {
      return notFound("Invitation not found or expired");
    }

    const invitation = unmarshall(inviteResult.Items[0]);

    // Validate invitation
    if (new Date(invitation.expires_at) < new Date()) {
      return badRequest("Invitation has expired");
    }

    if (invitation.used_count >= invitation.max_uses) {
      return badRequest("Invitation has reached maximum uses");
    }

    // Prevent self-connection
    if (invitation.owner_guid === acceptorGuid) {
      return badRequest("Cannot accept your own invitation");
    }

    // Check if connection already exists (query by primary key)
    const existingConnection = await ddb.send(new GetItemCommand({
      TableName: TABLE_CONNECTIONS,
      Key: marshall({
        owner_guid: acceptorGuid,
        peer_guid: invitation.owner_guid,
      }),
    }));

    if (existingConnection.Item) {
      return badRequest("Connection already exists with this user");
    }

    // Generate acceptor's ephemeral key pair for key exchange
    const { publicKey: acceptorPublicKey, privateKey: acceptorPrivateKey } = generateKeyPairSync("x25519");
    const acceptorPublicKeyBase64 = acceptorPublicKey.export({ type: "spki", format: "der" }).toString("base64");

    // Perform key exchange to derive shared secret
    // Note: In production, this would be done more carefully with proper key derivation
    const inviterPublicKeyDer = Buffer.from(invitation.public_key, "base64");
    const inviterPublicKey = createPublicKey({ key: inviterPublicKeyDer, format: "der", type: "spki" });

    const sharedSecret = diffieHellman({
      privateKey: acceptorPrivateKey,
      publicKey: inviterPublicKey,
    });
    const sharedSecretBase64 = sharedSecret.toString("base64");

    // Generate connection ID
    const connectionId = generateConnectionId();
    const now = nowIso();

    // Get acceptor's display name and profile
    const acceptorDisplayName = body.display_name || acceptorEmail.split("@")[0];
    let acceptorProfile: any = undefined;
    if (body.include_profile !== false) {
      try {
        const profileResult = await ddb.send(new GetItemCommand({
          TableName: TABLE_PROFILES,
          Key: marshall({ user_guid: acceptorGuid }),
          ProjectionExpression: "display_name, avatar_url, bio",
        }));
        if (profileResult.Item) {
          acceptorProfile = unmarshall(profileResult.Item);
        }
      } catch {
        // Continue without profile
      }
    }

    // Create connection record for acceptor (points to inviter)
    // Table key: owner_guid (acceptor), peer_guid (inviter)
    const acceptorConnection = {
      connection_id: connectionId,
      owner_guid: acceptorGuid,
      peer_guid: invitation.owner_guid,
      peer_display_name: invitation.display_name,
      peer_profile: invitation.profile_snippet,
      shared_secret_encrypted: sharedSecretBase64, // TODO: Encrypt with user's key
      my_public_key: acceptorPublicKeyBase64,
      peer_public_key: invitation.public_key,
      status: "active",
      created_at: now,
      created_via: "invitation_accept",
      invitation_id: invitation.invitation_id,
    };

    // Create connection record for inviter (points to acceptor)
    // Table key: owner_guid (inviter), peer_guid (acceptor)
    const inviterConnection = {
      connection_id: connectionId,
      owner_guid: invitation.owner_guid,
      peer_guid: acceptorGuid,
      peer_display_name: acceptorDisplayName,
      peer_profile: acceptorProfile,
      shared_secret_encrypted: sharedSecretBase64, // TODO: Encrypt with user's key
      my_public_key: invitation.public_key,
      peer_public_key: acceptorPublicKeyBase64,
      status: "active",
      created_at: now,
      created_via: "invitation_create",
      invitation_id: invitation.invitation_id,
    };

    // Store both connection records
    await Promise.all([
      ddb.send(new PutItemCommand({
        TableName: TABLE_CONNECTIONS,
        Item: marshall(acceptorConnection, { removeUndefinedValues: true }),
      })),
      ddb.send(new PutItemCommand({
        TableName: TABLE_CONNECTIONS,
        Item: marshall(inviterConnection, { removeUndefinedValues: true }),
      })),
    ]);

    // Increment invitation usage
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_INVITATIONS,
      Key: marshall({ invitation_id: invitation.invitation_id }),
      UpdateExpression: "SET used_count = used_count + :one, #status = if_not_exists(#status, :active)",
      ConditionExpression: "used_count < max_uses",
      ExpressionAttributeNames: { "#status": "status" },
      ExpressionAttributeValues: marshall({ ":one": 1, ":active": "active" }),
    }));

    // If max uses reached, mark invitation as exhausted
    if (invitation.used_count + 1 >= invitation.max_uses) {
      await ddb.send(new UpdateItemCommand({
        TableName: TABLE_INVITATIONS,
        Key: marshall({ invitation_id: invitation.invitation_id }),
        UpdateExpression: "SET #status = :exhausted",
        ExpressionAttributeNames: { "#status": "status" },
        ExpressionAttributeValues: marshall({ ":exhausted": "exhausted" }),
      }));
    }

    console.log(`Connection established: ${connectionId} between ${hashForLog(acceptorGuid)} and ${hashForLog(invitation.owner_guid)}`);

    return ok({
      connection_id: connectionId,
      peer_guid: invitation.owner_guid,
      peer_display_name: invitation.display_name,
      peer_profile: invitation.profile_snippet,
      status: "active",
      created_at: now,
    });

  } catch (error) {
    console.error("Error accepting invitation:", error);
    return internalError("Failed to accept invitation");
  }
};

/**
 * Generate a unique connection ID
 */
function generateConnectionId(): string {
  return `conn_${randomBytes(16).toString("hex")}`;
}
