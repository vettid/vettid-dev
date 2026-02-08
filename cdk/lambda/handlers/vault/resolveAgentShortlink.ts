import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, DeleteItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  notFound,
  tooManyRequests,
  internalError,
  getRequestId,
  putAudit,
} from '../../common/util';
import { checkRateLimit } from '../../common/rateLimit';

const ddb = new DynamoDBClient({});

const TABLE_AGENT_SHORTLINKS = process.env.TABLE_AGENT_SHORTLINKS!;

// SECURITY: Strict code format validation — 6 chars, Base62 only
const CODE_PATTERN = /^[A-Za-z0-9]{6}$/;

/**
 * GET /vault/agent/shortlink/{code}
 *
 * Public endpoint (no auth, rate-limited) — called by agent connector binary
 * to resolve a shortlink code to invitation parameters.
 *
 * SECURITY: Single-use — uses atomic DeleteItem with ReturnValues to read
 * and delete in one operation. This prevents replay attacks.
 *
 * Returns fields matching the agent connector's ShortlinkPayload struct:
 * - messagespace_uri, invite_token, invitation_id
 * Plus: vault_public_key, owner_guid
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);
  const origin = event.headers?.origin;

  try {
    // SECURITY: Rate limit to prevent brute force code guessing
    const rateLimitResult = await checkRateLimit(event, 'agent:resolve_shortlink');
    if (!rateLimitResult.allowed) {
      return tooManyRequests('Too many requests. Please try again later.', origin);
    }

    // Extract code from path parameter
    const code = event.pathParameters?.code;
    if (!code || !CODE_PATTERN.test(code)) {
      return badRequest('Invalid shortlink code format', origin);
    }

    // SECURITY: Atomic single-use resolve — DeleteItem with ConditionExpression
    // reads the item and deletes it in one operation, preventing replay
    let item: Record<string, any>;
    try {
      const result = await ddb.send(new DeleteItemCommand({
        TableName: TABLE_AGENT_SHORTLINKS,
        Key: marshall({ code }),
        ConditionExpression: 'attribute_exists(code)',
        ReturnValues: 'ALL_OLD',
      }));

      if (!result.Attributes) {
        // Should not happen if condition passed, but handle defensively
        await putAudit({
          type: 'agent_shortlink_resolve_failed',
          reason: 'no_attributes_returned',
          code_prefix: code.substring(0, 2) + '****',
        }, requestId);
        return notFound('Shortlink not found, expired, or already used', origin);
      }

      item = unmarshall(result.Attributes);
    } catch (err: any) {
      if (err.name === 'ConditionalCheckFailedException') {
        // Code doesn't exist — either never created, expired (TTL), or already used
        await putAudit({
          type: 'agent_shortlink_resolve_failed',
          reason: 'not_found_or_used',
          code_prefix: code.substring(0, 2) + '****',
        }, requestId);
        return notFound('Shortlink not found, expired, or already used', origin);
      }
      throw err;
    }

    // SECURITY: Explicit TTL check — DynamoDB TTL deletion is eventually consistent
    // (items may linger up to 48 hours after TTL expiry)
    const now = Math.floor(Date.now() / 1000);
    if (item.ttl && item.ttl < now) {
      await putAudit({
        type: 'agent_shortlink_resolve_failed',
        reason: 'expired',
        code_prefix: code.substring(0, 2) + '****',
        owner_guid: item.owner_guid,
      }, requestId);
      return notFound('Shortlink not found, expired, or already used', origin);
    }

    // Audit log successful resolution
    await putAudit({
      type: 'agent_shortlink_resolved',
      owner_guid: item.owner_guid,
      invitation_id: item.invitation_id,
      code_prefix: code.substring(0, 2) + '****',
    }, requestId);

    // Return payload matching agent connector's ShortlinkPayload struct
    return ok({
      messagespace_uri: item.messagespace_uri,
      invite_token: item.invite_token,
      invitation_id: item.invitation_id,
      vault_public_key: item.vault_public_key,
      owner_guid: item.owner_guid,
    }, origin);

  } catch (error: any) {
    console.error('Resolve agent shortlink error:', error);
    return internalError('Failed to resolve agent shortlink', origin);
  }
};
