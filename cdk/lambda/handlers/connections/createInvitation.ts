import { APIGatewayProxyEventV2WithJWTAuthorizer, APIGatewayProxyResultV2 } from "aws-lambda";
import { DynamoDBClient, PutItemCommand, GetItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import { randomBytes, createPublicKey, generateKeyPairSync } from "crypto";
import { ok, badRequest, forbidden, internalError, nowIso, addMinutesIso, ValidationError, requireMemberGroup, hashForLog } from "../../common/util";

const ddb = new DynamoDBClient({});
const TABLE_INVITATIONS = process.env.TABLE_CONNECTION_INVITATIONS!;
const TABLE_PROFILES = process.env.TABLE_PROFILES!;

interface CreateInvitationRequest {
  display_name?: string;
  message?: string;
  expires_in_hours?: number;
  max_uses?: number;
  include_profile?: boolean;
}

interface ProfileSnippet {
  display_name?: string;
  avatar_url?: string;
  bio?: string;
}

/**
 * POST /member/connections/invitations
 *
 * Creates a new connection invitation that can be shared via QR code or link.
 * The invitation includes an ephemeral X25519 public key for key exchange.
 */
export const handler = async (
  event: APIGatewayProxyEventV2WithJWTAuthorizer
): Promise<APIGatewayProxyResultV2> => {
  try {
    // Require member group
    const authError = requireMemberGroup(event);
    if (authError) return authError;

    const userGuid = event.requestContext.authorizer.jwt.claims.sub as string;
    const userEmail = event.requestContext.authorizer.jwt.claims.email as string;

    // Parse request body
    let body: CreateInvitationRequest = {};
    if (event.body) {
      try {
        body = JSON.parse(event.body);
      } catch {
        return badRequest("Invalid JSON body");
      }
    }

    // Validate inputs
    const displayName = body.display_name || userEmail.split("@")[0];
    if (displayName.length > 100) {
      return badRequest("Display name must be 100 characters or less");
    }

    if (body.message && body.message.length > 500) {
      return badRequest("Message must be 500 characters or less");
    }

    const expiresInHours = body.expires_in_hours ?? 168; // Default: 7 days
    if (expiresInHours < 1 || expiresInHours > 720) { // Max 30 days
      return badRequest("Expiration must be between 1 and 720 hours");
    }

    const maxUses = body.max_uses ?? 1;
    if (maxUses < 1 || maxUses > 100) {
      return badRequest("Max uses must be between 1 and 100");
    }

    // Generate invitation ID and code
    const invitationId = generateInvitationId();
    const inviteCode = generateInviteCode();

    // Generate ephemeral X25519 key pair for this invitation
    // The private key is stored encrypted, public key is shared in invitation
    const { publicKey, privateKey } = generateKeyPairSync("x25519");
    const publicKeyBase64 = publicKey.export({ type: "spki", format: "der" }).toString("base64");
    const privateKeyBase64 = privateKey.export({ type: "pkcs8", format: "der" }).toString("base64");

    // Optionally fetch profile snippet
    let profileSnippet: ProfileSnippet | undefined;
    if (body.include_profile !== false) {
      try {
        const profileResult = await ddb.send(new GetItemCommand({
          TableName: TABLE_PROFILES,
          Key: marshall({ user_guid: userGuid }),
          ProjectionExpression: "display_name, avatar_url, bio",
        }));
        if (profileResult.Item) {
          const profile = unmarshall(profileResult.Item);
          profileSnippet = {
            display_name: profile.display_name || displayName,
            avatar_url: profile.avatar_url,
            bio: profile.bio,
          };
        }
      } catch {
        // Profile fetch failed, continue without it
      }
    }

    const now = nowIso();
    const expiresAt = addMinutesIso(expiresInHours * 60);

    // Store invitation in DynamoDB
    const invitation = {
      invitation_id: invitationId,
      invite_code: inviteCode,
      owner_guid: userGuid,
      display_name: displayName,
      message: body.message,
      public_key: publicKeyBase64,
      private_key_encrypted: privateKeyBase64, // TODO: Encrypt with owner's key
      profile_snippet: profileSnippet,
      max_uses: maxUses,
      used_count: 0,
      status: "active",
      created_at: now,
      expires_at: expiresAt,
      ttl: Math.floor(new Date(expiresAt).getTime() / 1000) + 86400, // Expires + 1 day for cleanup
    };

    await ddb.send(new PutItemCommand({
      TableName: TABLE_INVITATIONS,
      Item: marshall(invitation, { removeUndefinedValues: true }),
      ConditionExpression: "attribute_not_exists(invitation_id)",
    }));

    // Build QR code payload
    const qrPayload = {
      type: "vettid_connection_invite",
      version: 1,
      code: inviteCode,
      pk: publicKeyBase64,
      name: displayName,
      exp: expiresAt,
    };

    // Build share URL
    const shareUrl = `https://vettid.dev/connect/${inviteCode}`;

    console.log(`Connection invitation created: ${invitationId} by user ${hashForLog(userGuid)}`);

    return ok({
      invitation_id: invitationId,
      invite_code: inviteCode,
      public_key: publicKeyBase64,
      display_name: displayName,
      profile_snippet: profileSnippet,
      expires_at: expiresAt,
      max_uses: maxUses,
      share_url: shareUrl,
      qr_payload: JSON.stringify(qrPayload),
    });

  } catch (error) {
    console.error("Error creating invitation:", error);
    return internalError("Failed to create invitation");
  }
};

/**
 * Generate a unique invitation ID
 */
function generateInvitationId(): string {
  return `inv_${randomBytes(16).toString("hex")}`;
}

/**
 * Generate a short, human-readable invite code
 * Uses base32-like alphabet without ambiguous characters (I, O, 0, 1)
 */
function generateInviteCode(): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = randomBytes(6);
  let code = "";
  for (let i = 0; i < 6; i++) {
    code += alphabet[bytes[i] % alphabet.length];
  }
  return code;
}
