import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import {
  ddb,
  TABLES,
  ok,
  badRequest,
  putAudit,
  getAdminEmail,
  generateSecureId,
  parseJsonBody,
  ValidationError,
  requireAdminGroup,
  validateOrigin,
  sanitizeInput,
  getRequestId,
  checkRateLimit,
  hashIdentifier,
  tooManyRequests
} from "../../common/util";
import { PutItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall } from "@aws-sdk/util-dynamodb";

/**
 * Generate secure invite code with VET prefix
 */
function generateInviteCode(): string {
  return generateSecureId("VET");
}

/**
 * Validate custom invite code format
 * Must be alphanumeric with optional dashes/underscores, 4-50 chars
 */
function isValidInviteCode(code: string): boolean {
  return /^[A-Za-z0-9_-]{4,50}$/.test(code);
}

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Validate admin group membership
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  // CSRF protection: Validate request origin
  const csrfError = validateOrigin(event);
  if (csrfError) return csrfError;

  const requestId = getRequestId(event);
  const adminEmail = getAdminEmail(event);

  // Rate limiting: Max 100 invite creations per admin per hour
  const adminHash = hashIdentifier(adminEmail);
  const isAllowed = await checkRateLimit(adminHash, 'create_invite', 100, 60);
  if (!isAllowed) {
    return tooManyRequests("Too many invite creations. Please try again later.");
  }

  try {
    const body = parseJsonBody(event);

    const max_uses = Math.max(1, Number(body.max_uses || 1));
    const expires_at = body.expires_at || null;
    const auto_approve = body.auto_approve === true;

    // Use custom code if provided, otherwise generate secure code
    let code: string;
    if (body.code) {
      const sanitizedCode = sanitizeInput(body.code).trim();
      // SECURITY: Validate custom invite code format
      if (!isValidInviteCode(sanitizedCode)) {
        return badRequest("Invalid invite code format. Must be 4-50 alphanumeric characters (dashes and underscores allowed)");
      }
      code = sanitizedCode;
    } else {
      code = generateInviteCode();
    }

    const item: any = {
      code,
      max_uses,
      used: 0,
      status: "active",
      created_at: new Date().toISOString(),
      created_by: adminEmail
    };

    if (expires_at) item.expires_at = expires_at;
    if (auto_approve) item.auto_approve = true;

    await ddb.send(new PutItemCommand({
      TableName: TABLES.invites,
      Item: marshall(item)
    }));

    await putAudit({
      type: "invite_created",
      email: adminEmail,
      code,
      max_uses,
      expires_at,
      auto_approve
    }, requestId);

    return ok({ code, max_uses, expires_at, auto_approve });
  } catch (error) {
    if (error instanceof ValidationError) {
      return badRequest(error.message);
    }
    console.error('Failed to create invite:', error);
    return badRequest("Failed to create invite");
  }
};
