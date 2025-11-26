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
  getRequestId
} from "../../common/util";
import { PutItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall } from "@aws-sdk/util-dynamodb";

/**
 * Generate secure invite code with VET prefix
 */
function generateInviteCode(): string {
  return generateSecureId("VET");
}

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Validate admin group membership
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  // CSRF protection: Validate request origin
  const csrfError = validateOrigin(event);
  if (csrfError) return csrfError;

  const requestId = getRequestId(event);

  try {
    const body = parseJsonBody(event);

    const max_uses = Math.max(1, Number(body.max_uses || 1));
    const expires_at = body.expires_at || null;
    const auto_approve = body.auto_approve === true;
    // Use custom code if provided, otherwise generate secure code
    const code = body.code ? sanitizeInput(body.code).trim() : generateInviteCode();
    const adminEmail = getAdminEmail(event);

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
      code,
      max_uses,
      expires_at,
      auto_approve,
      created_by: adminEmail
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
