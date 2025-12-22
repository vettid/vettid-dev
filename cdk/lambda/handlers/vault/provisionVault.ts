import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, PutItemCommand, QueryCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { EC2Client, RunInstancesCommand, DescribeSubnetsCommand, TerminateInstancesCommand } from '@aws-sdk/client-ec2';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  forbidden,
  internalError,
  requireUserClaims,
  addMinutesIso,
  parseJsonBody,
} from '../../common/util';
import { generateUserCredentials, formatCredsFile } from '../../common/nats-jwt';

interface ProvisionRequest {
  force?: boolean;
}

const ddb = new DynamoDBClient({});
const ec2 = new EC2Client({});

const TABLE_VAULT_INSTANCES = process.env.TABLE_VAULT_INSTANCES!;
const TABLE_CREDENTIALS = process.env.TABLE_CREDENTIALS!;
const TABLE_NATS_ACCOUNTS = process.env.TABLE_NATS_ACCOUNTS!;
const VAULT_AMI_ID = process.env.VAULT_AMI_ID || 'ami-0c5a49678d50b9305';
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
 * Request body:
 * - force: boolean (optional) - If true, terminates existing vault and re-provisions
 *
 * Requires:
 * - Member JWT authentication
 * - Completed enrollment (active credential)
 * - NATS account created
 * - No existing active vault instance (unless force=true)
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const origin = event.headers?.origin;

  try {
    // Validate member authentication
    const claimsResult = requireUserClaims(event);
    if ('error' in claimsResult) {
      return claimsResult.error;
    }
    const { claims } = claimsResult;
    const userGuid = claims.user_guid;

    // Parse request body for force option
    const body = parseJsonBody<ProvisionRequest>(event) || {};
    const forceReprovision = body.force === true;

    // Check for existing vault instance
    const existingInstance = await ddb.send(new GetItemCommand({
      TableName: TABLE_VAULT_INSTANCES,
      Key: marshall({ user_guid: userGuid }),
    }));

    if (existingInstance.Item) {
      const instance = unmarshall(existingInstance.Item);

      if (forceReprovision) {
        // Force mode: terminate existing instance if it's active
        if (['provisioning', 'running', 'initializing'].includes(instance.status) && instance.instance_id) {
          console.log(`Force re-provisioning: terminating existing instance ${instance.instance_id}`);

          try {
            await ec2.send(new TerminateInstancesCommand({
              InstanceIds: [instance.instance_id],
            }));
          } catch (terminateErr: any) {
            // Log but continue - the instance might already be terminated
            console.warn(`Failed to terminate instance ${instance.instance_id}:`, terminateErr.message);
          }

          // Update status to terminated
          await ddb.send(new UpdateItemCommand({
            TableName: TABLE_VAULT_INSTANCES,
            Key: marshall({ user_guid: userGuid }),
            UpdateExpression: 'SET #status = :status, terminated_at = :now, terminated_by = :by',
            ExpressionAttributeNames: { '#status': 'status' },
            ExpressionAttributeValues: marshall({
              ':status': 'terminated',
              ':now': new Date().toISOString(),
              ':by': 'force_reprovision',
            }),
          }));
        }
        // Continue to provision new instance
      } else {
        // Normal mode: block if active instance exists
        if (['provisioning', 'running', 'initializing'].includes(instance.status)) {
          return badRequest('Vault instance already exists. Use force=true to terminate and re-provision, or /vault/health to check status.', origin);
        }
        // If terminated or failed, allow re-provisioning
      }
    }

    // Verify user has active credential (completed enrollment)
    const credentialResult = await ddb.send(new QueryCommand({
      TableName: TABLE_CREDENTIALS,
      KeyConditionExpression: 'user_guid = :guid',
      ExpressionAttributeValues: marshall({ ':guid': userGuid }),
      Limit: 1,
    }));

    if (!credentialResult.Items || credentialResult.Items.length === 0) {
      return forbidden('Vault enrollment required before provisioning.', origin);
    }

    const credential = unmarshall(credentialResult.Items[0]);
    if (credential.status !== 'ACTIVE') {
      return forbidden('Active vault enrollment required.', origin);
    }

    // Verify NATS account exists
    const natsAccount = await ddb.send(new GetItemCommand({
      TableName: TABLE_NATS_ACCOUNTS,
      Key: marshall({ user_guid: userGuid }),
    }));

    if (!natsAccount.Item) {
      return forbidden('NATS account required. Create via POST /vault/nats/account first.', origin);
    }

    const natsInfo = unmarshall(natsAccount.Item);

    // Generate NATS credentials for the vault instance
    // These are passed via user data and stored locally by vault-manager
    const ownerSpace = natsInfo.owner_space_id;
    const messageSpace = natsInfo.message_space_id;
    const accountSeed = natsInfo.account_seed;

    if (!accountSeed) {
      return internalError('NATS account missing signing key.', origin);
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

    // Generate owner/message space IDs (remove hyphens from GUID)
    const guidNoHyphens = userGuid.replace(/-/g, '');
    const ownerSpaceForTopics = `OwnerSpace.${guidNoHyphens}`;
    const messageSpaceForTopics = `MessageSpace.${guidNoHyphens}`;

    // Prepare user data script for vault initialization
    // NATS credentials are embedded and stored locally by vault-manager on first boot
    const userData = Buffer.from(`#!/bin/bash
# Vault instance initialization script
set -e

echo "Starting vault initialization..."

# Write NATS credentials to disk (location expected by config.yaml)
mkdir -p /var/lib/vault-manager
cat > /var/lib/vault-manager/creds.creds << 'NATSCREDS'
${natsCreds}
NATSCREDS
chown vault-manager:vault-manager /var/lib/vault-manager/creds.creds
chmod 600 /var/lib/vault-manager/creds.creds

# Write vault config JSON (for reference/debugging)
cat > /var/lib/vault-manager/config.json << 'CONFIG'
{
  "user_guid": "${userGuid}",
  "owner_space_id": "${ownerSpace}",
  "message_space_id": "${messageSpace}",
  "nats_endpoint": "nats.vettid.dev:4222"
}
CONFIG
chown vault-manager:vault-manager /var/lib/vault-manager/config.json
chmod 600 /var/lib/vault-manager/config.json

# Write vault-manager config.yaml with actual values (Go doesn't expand env vars in YAML)
cat > /etc/vault-manager/config.yaml << 'VAULTCONFIG'
# VettID Vault Manager Configuration (auto-generated)

central_nats:
  url: "nats://nats.vettid.dev:4222"
  creds_file: "/var/lib/vault-manager/creds.creds"
  reconnect_wait: 2s
  max_reconnects: -1
  ping_interval: 30s

local_nats:
  url: "nats://127.0.0.1:4223"
  jetstream:
    enabled: true
    buckets:
      - name: handlers
        description: "Installed handler WASM packages"
        max_value_size: 10MB
        history: 1
      - name: handler-state
        description: "Handler state storage"
        max_value_size: 1MB
        history: 5
      - name: connections
        description: "Connection keys and profiles"
        max_value_size: 64KB
        history: 3

handlers:
  cache_dir: /var/lib/vault-manager/handlers
  wasm_cache_dir: /var/lib/vault-manager/wasm-cache
  max_execution_time: 30s
  max_memory: 128MB
  max_cpu_time: 10s
  sandbox:
    allow_network: false
    allow_filesystem: false
    allow_env: false

member:
  guid: "${userGuid}"
  owner_space: "${ownerSpaceForTopics}"
  message_space: "${messageSpaceForTopics}"

topics:
  for_vault: "${ownerSpaceForTopics}.forVault.>"
  for_app: "${ownerSpaceForTopics}.forApp.>"
  control: "${ownerSpaceForTopics}.control"
  event_types: "${ownerSpaceForTopics}.eventTypes"
  for_owner: "${messageSpaceForTopics}.forOwner.>"
  owner_profile: "${messageSpaceForTopics}.ownerProfile"

health:
  heartbeat_interval: 30s
  heartbeat_topic: "${ownerSpaceForTopics}.control"
  status_file: /var/lib/vault-manager/health.json

logging:
  level: info
  format: json
  output: /var/log/vault-manager/vault-manager.log

metrics:
  enabled: false
  port: 9090
VAULTCONFIG
chown vault-manager:vault-manager /etc/vault-manager/config.yaml
chmod 640 /etc/vault-manager/config.yaml

# Start vault-manager service
systemctl enable vault-manager
systemctl restart vault-manager

echo "Vault initialization complete"
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
            { Key: 'Application', Value: 'vettid-vault' },
          ],
        },
        {
          ResourceType: 'volume',
          Tags: [
            { Key: 'Name', Value: `vettid-vault-${userGuid.slice(0, 8)}-vol` },
            { Key: 'VettID:UserGuid', Value: userGuid },
            { Key: 'Application', Value: 'vettid-vault' },
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
      return internalError('Failed to launch vault instance.', origin);
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

    return ok(response, origin);

  } catch (error: any) {
    console.error('Provision vault error:', error);
    return internalError('Failed to provision vault instance.', origin);
  }
};
