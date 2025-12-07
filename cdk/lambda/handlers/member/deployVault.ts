import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, QueryCommand, PutItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  conflict,
  internalError,
  getRequestId,
  requireUserClaims,
  putAudit,
  generateSecureId,
} from '../../common/util';

const ddb = new DynamoDBClient({});

const TABLE_INVITES = process.env.TABLE_INVITES!;
const TABLE_CREDENTIALS = process.env.TABLE_CREDENTIALS!;

// Invite expiration time (30 minutes)
const INVITE_TTL_MS = 30 * 60 * 1000;

/**
 * Deploy vault response structure
 */
interface DeployVaultResponse {
  invite_code: string;
  qr_data: string;
  expires_at: string;
  enrollment_endpoint: string;
}

/**
 * POST /member/vault/deploy
 *
 * Initiate vault deployment for a member.
 * Generates an invite code that can be scanned by the mobile app.
 *
 * The invite code is embedded in a QR code data structure:
 * {
 *   "type": "vettid_vault_enrollment",
 *   "code": "invite_code",
 *   "endpoint": "https://api.vettid.dev",
 *   "expires_at": "ISO timestamp"
 * }
 *
 * Requires member JWT authentication.
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);

  try {
    // Validate member authentication and get claims
    const claimsResult = requireUserClaims(event);
    if ('error' in claimsResult) {
      return claimsResult.error;
    }
    const { claims } = claimsResult;
    const userGuid = claims.user_guid;
    const email = claims.email;

    // Check if user already has an enrolled vault
    const existingCredential = await ddb.send(new QueryCommand({
      TableName: TABLE_CREDENTIALS,
      IndexName: 'user-guid-index',
      KeyConditionExpression: 'user_guid = :guid',
      ExpressionAttributeValues: marshall({
        ':guid': userGuid,
      }),
      Limit: 1,
    }));

    if (existingCredential.Items && existingCredential.Items.length > 0) {
      return conflict('Vault already enrolled. Only one vault per account is allowed.');
    }

    // Check for existing pending invite
    const existingInvite = await ddb.send(new QueryCommand({
      TableName: TABLE_INVITES,
      IndexName: 'user-guid-index',
      KeyConditionExpression: 'user_guid = :guid',
      FilterExpression: '#status = :pending AND expires_at > :now',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':guid': userGuid,
        ':pending': 'new',
        ':now': new Date().toISOString(),
      }),
      Limit: 1,
    }));

    // If there's a valid pending invite, return it
    if (existingInvite.Items && existingInvite.Items.length > 0) {
      const invite = unmarshall(existingInvite.Items[0]);

      const qrData = JSON.stringify({
        type: 'vettid_vault_enrollment',
        code: invite.code,
        endpoint: process.env.API_ENDPOINT || 'https://api.vettid.dev',
        expires_at: invite.expires_at,
      });

      const response: DeployVaultResponse = {
        invite_code: invite.code,
        qr_data: qrData,
        expires_at: invite.expires_at,
        enrollment_endpoint: '/vault/enroll/start',
      };

      return ok(response);
    }

    // Generate new invite code
    const inviteCode = generateSecureId('vinv', 24);
    const now = new Date();
    const expiresAt = new Date(now.getTime() + INVITE_TTL_MS);

    // Create invite record
    await ddb.send(new PutItemCommand({
      TableName: TABLE_INVITES,
      Item: marshall({
        code: inviteCode,
        user_guid: userGuid,
        email: email,
        status: 'new',
        type: 'vault_enrollment',
        max_uses: 1,
        used: 0,
        created_at: now.toISOString(),
        expires_at: expiresAt.toISOString(),
        expires_at_ttl: Math.floor(expiresAt.getTime() / 1000),
      }),
    }));

    // Build QR data structure
    const qrData = JSON.stringify({
      type: 'vettid_vault_enrollment',
      code: inviteCode,
      endpoint: process.env.API_ENDPOINT || 'https://api.vettid.dev',
      expires_at: expiresAt.toISOString(),
    });

    // Audit log
    await putAudit({
      type: 'vault_deploy_initiated',
      user_guid: userGuid,
      invite_code: inviteCode.substring(0, 8) + '...',
      expires_at: expiresAt.toISOString(),
    }, requestId);

    const response: DeployVaultResponse = {
      invite_code: inviteCode,
      qr_data: qrData,
      expires_at: expiresAt.toISOString(),
      enrollment_endpoint: '/vault/enroll/start',
    };

    return ok(response);

  } catch (error: any) {
    console.error('Deploy vault error:', error);
    return internalError('Failed to initiate vault deployment');
  }
};
