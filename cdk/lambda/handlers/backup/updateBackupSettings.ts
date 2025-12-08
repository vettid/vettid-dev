import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { DynamoDBClient, PutItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall } from "@aws-sdk/util-dynamodb";
import {
  ok,
  badRequest,
  internalError,
  requireUserClaims,
  ValidationError,
  nowIso,
} from "../../common/util";

const ddb = new DynamoDBClient({});
const TABLE_BACKUP_SETTINGS = process.env.TABLE_BACKUP_SETTINGS!;

interface UpdateBackupSettingsRequest {
  auto_backup_enabled?: boolean;
  backup_frequency?: "daily" | "weekly" | "monthly";
  backup_time_utc?: string;
  retention_days?: number;
  include_messages?: boolean;
  wifi_only?: boolean;
}

const VALID_FREQUENCIES = ["daily", "weekly", "monthly"];
const TIME_REGEX = /^([01]\d|2[0-3]):([0-5]\d)$/;

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
    if (!event.body) {
      return badRequest("Request body required", origin);
    }

    let request: UpdateBackupSettingsRequest;
    try {
      request = JSON.parse(event.body);
    } catch {
      return badRequest("Invalid JSON body", origin);
    }

    // Validate fields
    if (request.backup_frequency !== undefined && !VALID_FREQUENCIES.includes(request.backup_frequency)) {
      return badRequest(`backup_frequency must be one of: ${VALID_FREQUENCIES.join(", ")}`, origin);
    }

    if (request.backup_time_utc !== undefined && !TIME_REGEX.test(request.backup_time_utc)) {
      return badRequest("backup_time_utc must be in HH:mm format", origin);
    }

    if (request.retention_days !== undefined) {
      if (!Number.isInteger(request.retention_days) || request.retention_days < 7 || request.retention_days > 365) {
        return badRequest("retention_days must be between 7 and 365", origin);
      }
    }

    const now = nowIso();

    // Build settings record
    const settings: any = {
      member_guid: claims.user_guid,
      updated_at: now,
    };

    if (request.auto_backup_enabled !== undefined) {
      settings.auto_backup_enabled = request.auto_backup_enabled;
    }
    if (request.backup_frequency !== undefined) {
      settings.backup_frequency = request.backup_frequency;
    }
    if (request.backup_time_utc !== undefined) {
      settings.backup_time_utc = request.backup_time_utc;
    }
    if (request.retention_days !== undefined) {
      settings.retention_days = request.retention_days;
    }
    if (request.include_messages !== undefined) {
      settings.include_messages = request.include_messages;
    }
    if (request.wifi_only !== undefined) {
      settings.wifi_only = request.wifi_only;
    }

    // Save settings
    await ddb.send(new PutItemCommand({
      TableName: TABLE_BACKUP_SETTINGS,
      Item: marshall(settings),
    }));

    return ok({
      ...settings,
      updated: true,
    }, origin);

  } catch (error) {
    console.error("Error updating backup settings:", error);
    if (error instanceof ValidationError) {
      return badRequest(error.message, origin);
    }
    return internalError("Failed to update backup settings", origin);
  }
};
