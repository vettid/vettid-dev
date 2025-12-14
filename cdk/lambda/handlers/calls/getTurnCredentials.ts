/**
 * Get TURN Credentials
 *
 * Generates short-lived Cloudflare TURN credentials for WebRTC calls.
 * This is the only AWS Lambda needed for the calling feature - all other
 * call logic runs in user vaults via WASM handlers.
 *
 * GET /calls/turn-credentials
 *
 * Response:
 * {
 *   ice_servers: [
 *     { urls: ['stun:stun.cloudflare.com:3478'] },
 *     {
 *       urls: ['turn:turn.cloudflare.com:3478?transport=udp', ...],
 *       username: string,
 *       credential: string
 *     }
 *   ],
 *   expires_at: string
 * }
 *
 * Requires: Member JWT token
 */

import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import * as crypto from 'crypto';
import {
  ok,
  internalError,
  requireUserClaims,
  getRequestId,
  putAudit,
} from '../../common/util';

const secretsManager = new SecretsManagerClient({});

const SECRET_NAME = process.env.TURN_SECRET_NAME || 'vettid/cloudflare-turn';
const TURN_TTL_SECONDS = 86400; // 24 hours

// Cache the secret to avoid repeated calls to Secrets Manager
let cachedSecret: { tokenId: string; tokenSecret: string } | null = null;
let secretCacheExpiry = 0;
const SECRET_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

interface TurnCredentials {
  ice_servers: IceServer[];
  expires_at: string;
}

interface IceServer {
  urls: string[];
  username?: string;
  credential?: string;
}

async function getTurnSecret(): Promise<{ tokenId: string; tokenSecret: string }> {
  const now = Date.now();

  // Return cached secret if still valid
  if (cachedSecret && now < secretCacheExpiry) {
    return cachedSecret;
  }

  // Fetch from Secrets Manager
  const response = await secretsManager.send(new GetSecretValueCommand({
    SecretId: SECRET_NAME,
  }));

  if (!response.SecretString) {
    throw new Error('TURN secret not found or empty');
  }

  const secret = JSON.parse(response.SecretString);
  cachedSecret = {
    tokenId: secret.token_id,
    tokenSecret: secret.token_secret,
  };
  secretCacheExpiry = now + SECRET_CACHE_TTL_MS;

  return cachedSecret;
}

export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);
  const origin = event.headers?.origin;

  try {
    // Require authenticated member
    const claimsResult = requireUserClaims(event, origin);
    if ('error' in claimsResult) {
      return claimsResult.error;
    }
    const { claims } = claimsResult;
    const userGuid = claims.user_guid;

    if (!userGuid) {
      return internalError('Missing user_guid in token', origin);
    }

    // Get TURN secret from Secrets Manager
    const turnSecret = await getTurnSecret();

    // Generate time-limited credentials using TURN REST API format
    // Username format: timestamp:userGuid (timestamp is expiry time)
    const expiry = Math.floor(Date.now() / 1000) + TURN_TTL_SECONDS;
    const username = `${expiry}:${userGuid}`;

    // Credential is HMAC-SHA1 of username using the shared secret
    const credential = crypto
      .createHmac('sha1', turnSecret.tokenSecret)
      .update(username)
      .digest('base64');

    const response: TurnCredentials = {
      ice_servers: [
        // STUN server (free, for connection discovery)
        {
          urls: ['stun:stun.cloudflare.com:3478'],
        },
        // TURN servers (relayed, for NAT traversal when P2P fails)
        {
          urls: [
            'turn:turn.cloudflare.com:3478?transport=udp',
            'turn:turn.cloudflare.com:3478?transport=tcp',
            'turns:turn.cloudflare.com:5349?transport=tcp',
          ],
          username,
          credential,
        },
      ],
      expires_at: new Date(expiry * 1000).toISOString(),
    };

    // Audit log (don't log credentials)
    await putAudit({
      event: 'turn_credentials_generated',
      user_guid: userGuid,
      expires_at: response.expires_at,
    }, requestId);

    return ok(response, origin);
  } catch (error: any) {
    console.error('Error generating TURN credentials:', error);
    return internalError('Failed to generate TURN credentials', origin);
  }
};
