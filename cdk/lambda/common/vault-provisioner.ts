/**
 * Vault EC2 Provisioning Helper
 *
 * Provides a reusable function to trigger vault EC2 provisioning.
 * Called from enrollFinalize.ts for auto-provisioning and provisionVault.ts for on-demand.
 */

import { DynamoDBClient, PutItemCommand } from '@aws-sdk/client-dynamodb';
import { EC2Client, RunInstancesCommand, DescribeSubnetsCommand } from '@aws-sdk/client-ec2';
import { marshall } from '@aws-sdk/util-dynamodb';
import { generateUserCredentials, formatCredsFile } from './nats-jwt';
import { addMinutesIso } from './util';

const ddb = new DynamoDBClient({});
const ec2 = new EC2Client({});

// Environment configuration
const TABLE_VAULT_INSTANCES = process.env.TABLE_VAULT_INSTANCES!;
const VAULT_AMI_ID = process.env.VAULT_AMI_ID || 'ami-083a1d18cec04eca1';
const VAULT_INSTANCE_TYPE = process.env.VAULT_INSTANCE_TYPE || 't4g.nano';
const VAULT_SECURITY_GROUP = process.env.VAULT_SECURITY_GROUP || '';
const VAULT_SUBNET_IDS = process.env.VAULT_SUBNET_IDS || '';
const VAULT_IAM_PROFILE = process.env.VAULT_IAM_PROFILE || '';
const NATS_ENDPOINT = process.env.NATS_ENDPOINT || 'nats.vettid.dev:4222';

export interface VaultProvisioningParams {
  userGuid: string;
  ownerSpaceId: string;
  messageSpaceId: string;
  accountSeed: string;
}

export interface VaultProvisioningResult {
  instanceId: string;
  status: 'provisioning';
  region: string;
  availabilityZone: string;
  privateIp: string | null;
  estimatedReadyAt: string;
}

/**
 * Trigger vault EC2 provisioning for a user.
 *
 * This function:
 * 1. Generates NATS credentials for the vault (30-day validity)
 * 2. Creates user data script with NATS creds + config
 * 3. Launches EC2 instance with vault-manager AMI
 * 4. Stores record in TABLE_VAULT_INSTANCES
 */
export async function triggerVaultProvisioning(
  params: VaultProvisioningParams
): Promise<VaultProvisioningResult> {
  const { userGuid, ownerSpaceId, messageSpaceId, accountSeed } = params;

  // Generate vault credentials valid for 30 days (will be refreshed via NATS)
  const expiresAt = new Date(addMinutesIso(60 * 24 * 30)); // 30 days
  const vaultCreds = await generateUserCredentials(
    userGuid,
    accountSeed,
    'vault',
    ownerSpaceId,
    messageSpaceId,
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

# Write vault config JSON (includes account seed for connection credential generation)
cat > /var/lib/vault-manager/config.json << 'CONFIG'
{
  "user_guid": "${userGuid}",
  "owner_space_id": "${ownerSpaceId}",
  "message_space_id": "${messageSpaceId}",
  "nats_endpoint": "${NATS_ENDPOINT}",
  "account_seed": "${accountSeed}"
}
CONFIG
chown vault-manager:vault-manager /var/lib/vault-manager/config.json
chmod 600 /var/lib/vault-manager/config.json

# Write vault-manager config.yaml with actual values (Go doesn't expand env vars in YAML)
cat > /etc/vault-manager/config.yaml << 'VAULTCONFIG'
# VettID Vault Manager Configuration (auto-generated)

central_nats:
  url: "nats://${NATS_ENDPOINT}"
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
  heartbeat_topic: "${ownerSpaceForTopics}.forApp.heartbeat"
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

  // Build EC2 instance parameters
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
          { Key: 'VettID:OwnerSpace', Value: ownerSpaceId },
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

  // Launch EC2 instance
  const runResult = await ec2.send(new RunInstancesCommand(instanceParams));

  if (!runResult.Instances || runResult.Instances.length === 0) {
    throw new Error('Failed to launch vault instance');
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
    owner_space_id: ownerSpaceId,
    message_space_id: messageSpaceId,
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

  return {
    instanceId,
    status: 'provisioning',
    region,
    availabilityZone,
    privateIp: ec2Instance.PrivateIpAddress || null,
    estimatedReadyAt,
  };
}
