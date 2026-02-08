import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, PutItemCommand } from '@aws-sdk/client-dynamodb';
import { randomBytes } from 'crypto';
import { marshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  internalError,
  parseJsonBody,
  getRequestId,
  putAudit,
} from '../../common/util';

const ddb = new DynamoDBClient({});

const TABLE_AGENT_SHORTLINKS = process.env.TABLE_AGENT_SHORTLINKS!;
const API_URL = process.env.API_URL || 'https://api.vettid.dev';

// SECURITY: Base62 alphabet for short codes (no ambiguous characters needed — agents copy-paste)
const BASE62 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

/**
 * Generate a cryptographically random 6-character Base62 code.
 * 62^6 ≈ 56.8 billion combinations — sufficient for short-lived codes.
 */
function generateShortCode(): string {
  const bytes = randomBytes(6);
  return Array.from(bytes, (b) => BASE62[b % BASE62.length]).join('');
}

interface CreateShortlinkRequest {
  owner_guid: string;
  invitation_id: string;
  invite_token: string;
  messagespace_uri: string;
  vault_public_key: string;
}

/**
 * POST /vault/agent/shortlink
 *
 * Internal endpoint (no auth) — called by vault-manager via parent process
 * when a vault owner creates an agent invitation.
 *
 * Creates a short-lived (2-minute) shortlink code that an agent connector
 * can resolve to obtain invitation parameters for registration.
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);
  const origin = event.headers?.origin;

  try {
    const body = parseJsonBody<CreateShortlinkRequest>(event);

    // Validate required fields
    if (!body.owner_guid || typeof body.owner_guid !== 'string') {
      return badRequest('owner_guid is required', origin);
    }
    if (!body.invitation_id || typeof body.invitation_id !== 'string') {
      return badRequest('invitation_id is required', origin);
    }
    if (!body.invite_token || typeof body.invite_token !== 'string') {
      return badRequest('invite_token is required', origin);
    }
    if (!body.messagespace_uri || typeof body.messagespace_uri !== 'string') {
      return badRequest('messagespace_uri is required', origin);
    }
    if (!body.vault_public_key || typeof body.vault_public_key !== 'string') {
      return badRequest('vault_public_key is required', origin);
    }

    // SECURITY: 2-minute TTL — shortlinks are ephemeral
    const now = Date.now();
    const ttlSeconds = Math.floor(now / 1000) + 120;
    const expiresAt = new Date(now + 120 * 1000).toISOString();

    // Retry up to 3 times on code collision (extremely unlikely with 62^6 space)
    let code: string | null = null;
    for (let attempt = 0; attempt < 3; attempt++) {
      const candidateCode = generateShortCode();
      try {
        await ddb.send(new PutItemCommand({
          TableName: TABLE_AGENT_SHORTLINKS,
          Item: marshall({
            code: candidateCode,
            owner_guid: body.owner_guid,
            invitation_id: body.invitation_id,
            invite_token: body.invite_token,
            messagespace_uri: body.messagespace_uri,
            vault_public_key: body.vault_public_key,
            created_at: new Date(now).toISOString(),
            ttl: ttlSeconds,
          }),
          ConditionExpression: 'attribute_not_exists(code)',
        }));
        code = candidateCode;
        break;
      } catch (err: any) {
        if (err.name === 'ConditionalCheckFailedException') {
          console.warn(`Shortlink code collision on attempt ${attempt + 1}, retrying`);
          continue;
        }
        throw err;
      }
    }

    if (!code) {
      console.error('Failed to generate unique shortlink code after 3 attempts');
      return internalError('Failed to generate shortlink', origin);
    }

    const shortlinkUrl = `${API_URL}/vault/agent/shortlink/${code}`;

    // Audit log with redacted code prefix for traceability
    await putAudit({
      type: 'agent_shortlink_created',
      owner_guid: body.owner_guid,
      invitation_id: body.invitation_id,
      code_prefix: code.substring(0, 2) + '****',
      expires_at: expiresAt,
    }, requestId);

    return ok({
      code,
      url: shortlinkUrl,
      expires_at: expiresAt,
    }, origin);

  } catch (error: any) {
    console.error('Create agent shortlink error:', error);
    return internalError('Failed to create agent shortlink', origin);
  }
};
