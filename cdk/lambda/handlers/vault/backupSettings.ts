import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, PutItemCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  internalError,
  getRequestId,
  putAudit,
  requireUserClaims,
} from '../../common/util';

const ddb = new DynamoDBClient({});

const TABLE_BACKUP_SETTINGS = process.env.TABLE_BACKUP_SETTINGS!;

interface BackupSettingsBody {
  enabled?: boolean;
}

/**
 * GET/PUT /vault/credentials/backup/settings
 *
 * GET: Retrieve current backup settings for the authenticated member
 * PUT: Update backup settings (enable/disable automatic backups)
 *
 * Requires member JWT authentication.
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);
  const origin = event.headers?.origin;
  const method = event.requestContext.http.method.toUpperCase();

  try {
    // Validate member authentication and get claims
    const claimsResult = requireUserClaims(event);
    if ('error' in claimsResult) {
      return claimsResult.error;
    }
    const { claims } = claimsResult;
    const memberGuid = claims.user_guid;

    if (method === 'GET') {
      // Get current settings
      const settingsResult = await ddb.send(new GetItemCommand({
        TableName: TABLE_BACKUP_SETTINGS,
        Key: marshall({ member_guid: memberGuid }),
      }));

      if (!settingsResult.Item) {
        // Return defaults if no settings exist
        return ok({
          enabled: false,
          auto_backup: false,
          last_backup_at: null,
          backup_frequency: 'on_change',
        }, origin);
      }

      const settings = unmarshall(settingsResult.Item);
      return ok({
        enabled: settings.enabled || false,
        auto_backup: settings.auto_backup || false,
        last_backup_at: settings.last_backup_at || null,
        backup_frequency: settings.backup_frequency || 'on_change',
        updated_at: settings.updated_at || null,
      }, origin);
    }

    if (method === 'PUT') {
      // Parse request body
      let body: BackupSettingsBody = {};
      if (event.body) {
        try {
          body = JSON.parse(event.body) as BackupSettingsBody;
        } catch {
          return badRequest('Invalid JSON in request body', origin);
        }
      }

      if (typeof body.enabled !== 'boolean') {
        return badRequest('enabled field is required and must be a boolean', origin);
      }

      const now = new Date();

      // Check if settings exist
      const existingSettings = await ddb.send(new GetItemCommand({
        TableName: TABLE_BACKUP_SETTINGS,
        Key: marshall({ member_guid: memberGuid }),
      }));

      if (existingSettings.Item) {
        // Update existing settings
        await ddb.send(new UpdateItemCommand({
          TableName: TABLE_BACKUP_SETTINGS,
          Key: marshall({ member_guid: memberGuid }),
          UpdateExpression: 'SET enabled = :enabled, auto_backup = :auto_backup, updated_at = :now',
          ExpressionAttributeValues: marshall({
            ':enabled': body.enabled,
            ':auto_backup': body.enabled,
            ':now': now.toISOString(),
          }),
        }));
      } else {
        // Create new settings
        await ddb.send(new PutItemCommand({
          TableName: TABLE_BACKUP_SETTINGS,
          Item: marshall({
            member_guid: memberGuid,
            enabled: body.enabled,
            auto_backup: body.enabled,
            backup_frequency: 'on_change',
            created_at: now.toISOString(),
            updated_at: now.toISOString(),
          }, { removeUndefinedValues: true }),
        }));
      }

      // Audit log
      await putAudit({
        type: 'backup_settings_updated',
        member_guid: memberGuid,
        enabled: body.enabled,
      }, requestId);

      return ok({
        enabled: body.enabled,
        auto_backup: body.enabled,
        updated_at: now.toISOString(),
        message: body.enabled
          ? 'Automatic credential backups enabled.'
          : 'Automatic credential backups disabled.',
      }, origin);
    }

    return badRequest('Method not allowed', origin);

  } catch (error: any) {
    console.error('Backup settings error:', error);
    return internalError('Failed to process backup settings', origin);
  }
};
