/**
 * On Vault State Change Lambda
 *
 * Triggered by EventBridge when EC2 vault instances change state.
 * This provides a fallback mechanism to update DynamoDB when:
 * - Vault instances are terminated unexpectedly
 * - Vault instances are stopped
 * - Vault never calls the ready endpoint
 *
 * Triggered: EventBridge rule for EC2 state changes with VettID:Purpose=vault tag
 */

import { DynamoDBClient, UpdateItemCommand, ScanCommand } from '@aws-sdk/client-dynamodb';
import { EC2Client, DescribeInstancesCommand } from '@aws-sdk/client-ec2';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';

const ddb = new DynamoDBClient({});
const ec2 = new EC2Client({});

const TABLE_VAULT_INSTANCES = process.env.TABLE_VAULT_INSTANCES!;

/**
 * EC2 State Change Event from EventBridge
 */
interface EC2StateChangeEvent {
  source: 'aws.ec2';
  'detail-type': 'EC2 Instance State-change Notification';
  detail: {
    'instance-id': string;
    state: 'pending' | 'running' | 'stopping' | 'stopped' | 'shutting-down' | 'terminated';
  };
}

/**
 * Main handler - processes EC2 state change events
 */
export const handler = async (event: EC2StateChangeEvent): Promise<void> => {
  console.log('Processing EC2 state change event:', JSON.stringify(event));

  const instanceId = event.detail['instance-id'];
  const newState = event.detail.state;

  try {
    // Get instance details to find the user GUID
    const userGuid = await getUserGuidFromInstance(instanceId);

    if (!userGuid) {
      console.log(`Instance ${instanceId} is not a VettID vault, skipping`);
      return;
    }

    console.log(`Vault state change: instance=${instanceId}, user=${userGuid}, state=${newState}`);

    // Map EC2 state to vault status
    const vaultStatus = mapEC2StateToVaultStatus(newState);

    // Update DynamoDB
    await updateVaultStatus(userGuid, instanceId, vaultStatus, newState);

    console.log(`Updated vault status for ${userGuid} to ${vaultStatus}`);
  } catch (error) {
    console.error('Error processing vault state change:', error);
    throw error;
  }
};

/**
 * Get the user GUID from an EC2 instance's tags
 */
async function getUserGuidFromInstance(instanceId: string): Promise<string | null> {
  try {
    const result = await ec2.send(new DescribeInstancesCommand({
      InstanceIds: [instanceId],
    }));

    const instance = result.Reservations?.[0]?.Instances?.[0];
    if (!instance) {
      return null;
    }

    // Check if this is a VettID vault instance
    const purposeTag = instance.Tags?.find(t => t.Key === 'VettID:Purpose');
    if (purposeTag?.Value !== 'vault') {
      return null;
    }

    // Get the user GUID tag
    const userGuidTag = instance.Tags?.find(t => t.Key === 'VettID:UserGuid');
    return userGuidTag?.Value || null;
  } catch (error: any) {
    if (error.name === 'InvalidInstanceID.NotFound') {
      // Instance already terminated, try to find by scanning DynamoDB
      return await findUserGuidByInstanceId(instanceId);
    }
    throw error;
  }
}

/**
 * Find user GUID by scanning DynamoDB for matching instance ID
 * Used when instance is already terminated and tags are unavailable
 */
async function findUserGuidByInstanceId(instanceId: string): Promise<string | null> {
  try {
    // Scan for matching instance_id (not ideal, but rare case)
    const result = await ddb.send(new ScanCommand({
      TableName: TABLE_VAULT_INSTANCES,
      FilterExpression: 'instance_id = :iid',
      ExpressionAttributeValues: marshall({ ':iid': instanceId }),
      ProjectionExpression: 'user_guid',
      Limit: 1,
    }));

    if (result.Items && result.Items.length > 0) {
      const item = unmarshall(result.Items[0]);
      return item.user_guid;
    }

    return null;
  } catch (error) {
    console.warn('Failed to find user GUID by instance ID:', error);
    return null;
  }
}

/**
 * Map EC2 instance state to vault status
 */
function mapEC2StateToVaultStatus(ec2State: string): string {
  switch (ec2State) {
    case 'pending':
      return 'provisioning';
    case 'running':
      // Note: We don't override 'running' status here because
      // the vaultReady endpoint should set it after vault-manager starts
      return 'initializing';
    case 'stopping':
      return 'stopping';
    case 'stopped':
      return 'stopped';
    case 'shutting-down':
    case 'terminated':
      return 'terminated';
    default:
      return 'unknown';
  }
}

/**
 * Update vault status in DynamoDB
 */
async function updateVaultStatus(
  userGuid: string,
  instanceId: string,
  vaultStatus: string,
  ec2State: string
): Promise<void> {
  const now = new Date().toISOString();

  // Build update expression based on state
  let updateExpression = `
    SET ec2_state = :ec2_state,
        updated_at = :now
  `;
  const expressionAttributeNames: Record<string, string> = {};
  const expressionAttributeValues: Record<string, any> = {
    ':ec2_state': ec2State,
    ':now': now,
  };

  // Only update status for terminal states or if currently provisioning
  // Don't override 'running' status set by vaultReady
  if (ec2State === 'terminated' || ec2State === 'stopped' || ec2State === 'shutting-down') {
    updateExpression = `
      SET #status = :status,
          ec2_state = :ec2_state,
          updated_at = :now
    `;
    expressionAttributeNames['#status'] = 'status';
    expressionAttributeValues[':status'] = vaultStatus;

    // Add terminated_at timestamp for terminated instances
    if (ec2State === 'terminated') {
      updateExpression += ', terminated_at = :terminated_at';
      expressionAttributeValues[':terminated_at'] = now;
    }
  }

  try {
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_VAULT_INSTANCES,
      Key: marshall({ user_guid: userGuid }),
      UpdateExpression: updateExpression,
      ExpressionAttributeNames: Object.keys(expressionAttributeNames).length > 0
        ? expressionAttributeNames
        : undefined,
      ExpressionAttributeValues: marshall(expressionAttributeValues),
      ConditionExpression: 'attribute_exists(user_guid)',
    }));
  } catch (error: any) {
    if (error.name === 'ConditionalCheckFailedException') {
      console.warn(`No vault instance record found for user ${userGuid}`);
    } else {
      throw error;
    }
  }
}
