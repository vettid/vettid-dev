import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { DynamoDBClient, GetItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import {
  ok,
  badRequest,
  internalError,
  requireUserClaims,
  ValidationError,
} from "../../common/util";

const ddb = new DynamoDBClient({});
const TABLE_BACKUP_SETTINGS = process.env.TABLE_BACKUP_SETTINGS!;

interface BackupSettings {
  auto_backup_enabled: boolean;
  backup_frequency: "daily" | "weekly" | "monthly";
  backup_time_utc: string;  // HH:mm format
  retention_days: number;
  include_messages: boolean;
  wifi_only: boolean;
}

const DEFAULT_SETTINGS: BackupSettings = {
  auto_backup_enabled: true,
  backup_frequency: "daily",
  backup_time_utc: "03:00",
  retention_days: 30,
  include_messages: true,
  wifi_only: true,
};

export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const origin = event.headers?.origin;

  try {
    // Validate user claims
    const claimsResult = requireUserClaims(event, origin);
    if ("error" in claimsResult) {
      return claimsResult.error;
    }
    const { claims } = claimsResult;

    // Get backup settings
    const result = await ddb.send(new GetItemCommand({
      TableName: TABLE_BACKUP_SETTINGS,
      Key: marshall({ member_guid: claims.user_guid }),
    }));

    if (!result.Item) {
      // Return default settings
      return ok({
        ...DEFAULT_SETTINGS,
        is_default: true,
      }, origin);
    }

    const settings = unmarshall(result.Item);

    return ok({
      auto_backup_enabled: settings.auto_backup_enabled ?? DEFAULT_SETTINGS.auto_backup_enabled,
      backup_frequency: settings.backup_frequency ?? DEFAULT_SETTINGS.backup_frequency,
      backup_time_utc: settings.backup_time_utc ?? DEFAULT_SETTINGS.backup_time_utc,
      retention_days: settings.retention_days ?? DEFAULT_SETTINGS.retention_days,
      include_messages: settings.include_messages ?? DEFAULT_SETTINGS.include_messages,
      wifi_only: settings.wifi_only ?? DEFAULT_SETTINGS.wifi_only,
      is_default: false,
      last_updated: settings.updated_at,
    }, origin);

  } catch (error) {
    console.error("Error getting backup settings:", error);
    if (error instanceof ValidationError) {
      return badRequest(error.message, origin);
    }
    return internalError("Failed to get backup settings", origin);
  }
};
