import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, PutItemCommand, QueryCommand } from '@aws-sdk/client-dynamodb';
import { EC2Client, RunInstancesCommand, CreateTagsCommand, DescribeSubnetsCommand } from '@aws-sdk/client-ec2';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import { randomUUID } from 'crypto';
import {
  ok,
  badRequest,
  forbidden,
  internalError,
  requireUserClaims,
  addMinutesIso,
} from '../../common/util';
import { generateUserCredentials, formatCredsFile } from '../../common/nats-jwt';

const ddb = new DynamoDBClient({});
const ec2 = new EC2Client({});

const TABLE_VAULT_INSTANCES = process.env.TABLE_VAULT_INSTANCES!;
const TABLE_CREDENTIALS = process.env.TABLE_CREDENTIALS!;
const TABLE_NATS_ACCOUNTS = process.env.TABLE_NATS_ACCOUNTS!;
const VAULT_AMI_ID = process.env.VAULT_AMI_ID || 'ami-placeholder';
const VAULT_INSTANCE_TYPE = process.env.VAULT_INSTANCE_TYPE || 't4g.nano';
const VAULT_SECURITY_GROUP = process.env.VAULT_SECURITY_GROUP!;
const VAULT_SUBNET_IDS = process.env.VAULT_SUBNET_IDS || '';
const VAULT_IAM_PROFILE = process.env.VAULT_IAM_PROFILE || '';

interface ProvisionResponse {
  instance_id: string;
  status: 'provisioning' | 'running' | 'failed';
  region: string;
  availability_zone: string;
  private_ip: string | null;
  estimated_ready_at: string;
}

/**
 * POST /vault/provision
 *
 * Provision a new vault EC2 instance for the authenticated member.
 * This starts the vault provisioning process which may take 1-2 minutes.
 *
 * Requires:
 * - Member JWT authentication
 * - Completed enrollment (active credential)
 * - NATS account created
 * - No existing active vault instance
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  try {
    // Validate member authentication
    const claimsResult = requireUserClaims(event);
    if ('error' in claimsResult) {
      return claimsResult.error;
    }
    const { claims } = claimsResult;
    const userGuid = claims.user_guid;

    // Check for existing vault instance
    const existingInstance = await ddb.send(new GetItemCommand({
      TableName: TABLE_VAULT_INSTANCES,
      Key: marshall({ user_guid: userGuid }),
    }));

    if (existingInstance.Item) {
      const instance = unmarshall(existingInstance.Item);
      if (['provisioning', 'running', 'initializing'].includes(instance.status)) {
        return badRequest('Vault instance already exists. Use /vault/health to check status.');
      }
      // If terminated or failed, allow re-provisioning
    }

    // Verify user has active credential (completed enrollment)
    const credentialResult = await ddb.send(new QueryCommand({
      TableName: TABLE_CREDENTIALS,
      KeyConditionExpression: 'user_guid = :guid',
      ExpressionAttributeValues: marshall({ ':guid': userGuid }),
      Limit: 1,
    }));

    if (!credentialResult.Items || credentialResult.Items.length === 0) {
      return forbidden('Vault enrollment required before provisioning.');
    }

    const credential = unmarshall(credentialResult.Items[0]);
    if (credential.status !== 'ACTIVE') {
      return forbidden('Active vault enrollment required.');
    }

    // Verify NATS account exists
    const natsAccount = await ddb.send(new GetItemCommand({
      TableName: TABLE_NATS_ACCOUNTS,
      Key: marshall({ user_guid: userGuid }),
    }));

    if (!natsAccount.Item) {
      return forbidden('NATS account required. Create via POST /vault/nats/account first.');
    }

    const natsInfo = unmarshall(natsAccount.Item);

    // Generate NATS credentials for the vault instance
    // These are passed via user data and stored locally by vault-manager
    const ownerSpace = natsInfo.owner_space_id;
    const messageSpace = natsInfo.message_space_id;
    const accountSeed = natsInfo.account_seed;

    if (!accountSeed) {
      return internalError('NATS account missing signing key.');
    }

    // Generate vault credentials valid for 30 days (will be refreshed via NATS)
    const expiresAt = new Date(addMinutesIso(60 * 24 * 30)); // 30 days
    const vaultCreds = await generateUserCredentials(
      userGuid,
      accountSeed,
      'vault',
      ownerSpace,
      messageSpace,
      expiresAt
    );

    const natsCreds = formatCredsFile(vaultCreds.jwt, vaultCreds.seed);

    // Select a random subnet from available subnets
    const subnetIds = VAULT_SUBNET_IDS.split(',').filter(s => s.trim());
    let selectedSubnet = subnetIds.length > 0
      ? subnetIds[Math.floor(Math.random() * subnetIds.length)]
      : undefined;

    let availabilityZone = 'us-east-1a';

    if (selectedSubnet) {
      // Get the AZ for the selected subnet
      const subnetInfo = await ec2.send(new DescribeSubnetsCommand({
        SubnetIds: [selectedSubnet],
      }));
      if (subnetInfo.Subnets?.[0]?.AvailabilityZone) {
        availabilityZone = subnetInfo.Subnets[0].AvailabilityZone;
      }
    }

    // Prepare user data script for vault initialization
    // NATS credentials are embedded and stored locally by vault-manager on first boot
    const userData = Buffer.from(`#!/bin/bash
# Vault instance initialization script
export VAULT_USER_GUID="${userGuid}"
export OWNER_SPACE_ID="${ownerSpace}"
export MESSAGE_SPACE_ID="${messageSpace}"
export NATS_ENDPOINT="nats.vettid.dev:4222"

# Write NATS credentials to disk for vault-manager to consume
# These will be moved to encrypted storage and this file deleted on first boot
mkdir -p /var/lib/vault-manager
cat > /var/lib/vault-manager/nats.creds << 'NATSCREDS'
${natsCreds}
NATSCREDS
chmod 600 /var/lib/vault-manager/nats.creds

# Write vault config
cat > /var/lib/vault-manager/config.json << 'CONFIG'
{
  "user_guid": "${userGuid}",
  "owner_space_id": "${ownerSpace}",
  "message_space_id": "${messageSpace}",
  "nats_endpoint": "nats.vettid.dev:4222"
}
CONFIG
chmod 600 /var/lib/vault-manager/config.json

# Start vault-manager service (reads creds and stores in encrypted local db)
systemctl enable vault-manager
systemctl start vault-manager
`).toString('base64');

    // Launch EC2 instance
    const instanceParams: any = {
      ImageId: VAULT_AMI_ID,
      InstanceType: VAULT_INSTANCE_TYPE,
      MinCount: 1,
      MaxCount: 1,
      UserData: userData,
      TagSpecifications: [
        {
          ResourceType: 'instance',
          Tags: [
            { Key: 'Name', Value: `vettid-vault-${userGuid.slice(0, 8)}` },
            { Key: 'VettID:UserGuid', Value: userGuid },
            { Key: 'VettID:Purpose', Value: 'vault' },
            { Key: 'VettID:OwnerSpace', Value: natsInfo.owner_space_id },
          ],
        },
      ],
    };

    if (selectedSubnet) {
      instanceParams.SubnetId = selectedSubnet;
    }

    if (VAULT_SECURITY_GROUP) {
      instanceParams.SecurityGroupIds = [VAULT_SECURITY_GROUP];
    }

    if (VAULT_IAM_PROFILE) {
      instanceParams.IamInstanceProfile = { Name: VAULT_IAM_PROFILE };
    }

    const runResult = await ec2.send(new RunInstancesCommand(instanceParams));

    if (!runResult.Instances || runResult.Instances.length === 0) {
      return internalError('Failed to launch vault instance.');
    }

    const ec2Instance = runResult.Instances[0];
    const instanceId = ec2Instance.InstanceId!;
    const region = process.env.AWS_REGION || 'us-east-1';

    // Estimate ready time (2 minutes from now)
    const estimatedReadyAt = new Date(Date.now() + 2 * 60 * 1000).toISOString();

    // Store vault instance record
    const vaultInstance = {
      user_guid: userGuid,
      instance_id: instanceId,
      status: 'provisioning',
      region,
      availability_zone: availabilityZone,
      private_ip: ec2Instance.PrivateIpAddress || null,
      owner_space_id: natsInfo.owner_space_id,
      message_space_id: natsInfo.message_space_id,
      created_at: new Date().toISOString(),
      estimated_ready_at: estimatedReadyAt,
      last_health_check: null,
      local_nats_status: 'unknown',
      central_nats_status: 'unknown',
      vault_manager_status: 'unknown',
    };

    await ddb.send(new PutItemCommand({
      TableName: TABLE_VAULT_INSTANCES,
      Item: marshall(vaultInstance, { removeUndefinedValues: true }),
    }));

    const response: ProvisionResponse = {
      instance_id: instanceId,
      status: 'provisioning',
      region,
      availability_zone: availabilityZone,
      private_ip: ec2Instance.PrivateIpAddress || null,
      estimated_ready_at: estimatedReadyAt,
    };

    return ok(response);

  } catch (error: any) {
    console.error('Provision vault error:', error);
    return internalError('Failed to provision vault instance.');
  }
};
