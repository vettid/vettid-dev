/**
 * Vault EC2 Provisioning Helper
 *
 * Provides a reusable function to trigger vault EC2 provisioning.
 * Called from enrollFinalize.ts for auto-provisioning and provisionVault.ts for on-demand.
 *
 * NOTE: This provisioner does NOT generate vault credentials. The vault-manager
 * on the EC2 instance generates its own credentials from the account seed on startup.
 * This is the intended architecture: vault is the authority for its own credentials.
 */

import { DynamoDBClient, PutItemCommand } from '@aws-sdk/client-dynamodb';
import { EC2Client, RunInstancesCommand, DescribeSubnetsCommand } from '@aws-sdk/client-ec2';
import { SSMClient, GetParameterCommand } from '@aws-sdk/client-ssm';
import { marshall } from '@aws-sdk/util-dynamodb';
import { addMinutesIso } from './util';

const ddb = new DynamoDBClient({});
const ec2 = new EC2Client({});
const ssm = new SSMClient({});

// Environment configuration
const TABLE_VAULT_INSTANCES = process.env.TABLE_VAULT_INSTANCES!;

// Default AMI ID (fallback if SSM parameter doesn't exist)
const DEFAULT_VAULT_AMI_ID = 'ami-0b7fe186af6ed8d96';

// SSM Parameter name for vault AMI ID
const VAULT_AMI_PARAMETER_NAME = '/vettid/vault/ami-id';

// Cache for AMI ID to avoid repeated SSM calls
let cachedAmiId: string | null = null;
let cacheTimestamp = 0;
const CACHE_TTL_MS = 60000; // 1 minute cache

/**
 * Get the vault AMI ID from SSM Parameter Store.
 * Uses caching to avoid repeated SSM calls during Lambda warm starts.
 * Falls back to default if parameter doesn't exist.
 */
async function getVaultAmiId(): Promise<string> {
  const now = Date.now();

  // Return cached value if still valid
  if (cachedAmiId && (now - cacheTimestamp) < CACHE_TTL_MS) {
    return cachedAmiId;
  }

  try {
    const response = await ssm.send(new GetParameterCommand({
      Name: VAULT_AMI_PARAMETER_NAME,
    }));

    if (response.Parameter?.Value) {
      const amiId = response.Parameter.Value;
      cachedAmiId = amiId;
      cacheTimestamp = now;
      console.log(`Using vault AMI from SSM: ${amiId}`);
      return amiId;
    }
  } catch (error: any) {
    if (error.name === 'ParameterNotFound') {
      console.log(`SSM parameter ${VAULT_AMI_PARAMETER_NAME} not found, using default: ${DEFAULT_VAULT_AMI_ID}`);
    } else {
      console.error(`Error fetching SSM parameter: ${error.message}, using default: ${DEFAULT_VAULT_AMI_ID}`);
    }
  }

  return DEFAULT_VAULT_AMI_ID;
}
const VAULT_INSTANCE_TYPE = process.env.VAULT_INSTANCE_TYPE || 't4g.nano';
const VAULT_SECURITY_GROUP = process.env.VAULT_SECURITY_GROUP || '';
const VAULT_SUBNET_IDS = process.env.VAULT_SUBNET_IDS || '';
const VAULT_IAM_PROFILE = process.env.VAULT_IAM_PROFILE || '';
// Internal NATS endpoint for vault-to-NATS communication via VPC peering (plain TCP)
const NATS_INTERNAL_ENDPOINT = process.env.NATS_INTERNAL_ENDPOINT || 'nats.internal.vettid.dev:4222';
const BACKEND_API_URL = process.env.BACKEND_API_URL || '';
// Note: No TLS needed for internal endpoint - traffic stays within VPC peering

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
 * 1. Creates user data script with account seed (vault generates its own creds)
 * 2. Launches EC2 instance with vault-manager AMI
 * 3. Stores record in TABLE_VAULT_INSTANCES
 *
 * NOTE: The vault-manager generates its own NATS credentials from the account seed
 * on first boot. This is the intended architecture where vault is the authority
 * for credential generation.
 */
export async function triggerVaultProvisioning(
  params: VaultProvisioningParams
): Promise<VaultProvisioningResult> {
  const { userGuid, ownerSpaceId, messageSpaceId, accountSeed } = params;

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
  // Note: NATS CA certificate no longer needed - NLB terminates TLS with ACM (publicly trusted)
  // vault-manager generates its own NATS credentials from account seed on first boot
  const userData = Buffer.from(`#!/bin/bash
# Vault instance initialization script
set -e

echo "Starting vault initialization..."

# Create vault-manager data directory
mkdir -p /var/lib/vault-manager
chown vault-manager:vault-manager /var/lib/vault-manager

# Write vault config JSON (includes account seed for self-credential generation)
# vault-manager will generate its own NATS credentials from this seed on startup
# Note: nats_endpoint removed to let config.yaml be authoritative for the URL
# (old vault-manager code forces tls:// prefix which breaks internal NLB)
cat > /var/lib/vault-manager/config.json << 'CONFIG'
{
  "user_guid": "${userGuid}",
  "owner_space_id": "${ownerSpaceId}",
  "message_space_id": "${messageSpaceId}",
  "account_seed": "${accountSeed}",
  "backend_api_url": "${BACKEND_API_URL}"
}
CONFIG
chown vault-manager:vault-manager /var/lib/vault-manager/config.json
chmod 600 /var/lib/vault-manager/config.json

# No TLS/CA needed - internal NLB uses plain TCP over VPC peering

# Write vault-manager config.yaml with actual values (Go doesn't expand env vars in YAML)
cat > /etc/vault-manager/config.yaml << 'VAULTCONFIG'
# VettID Vault Manager Configuration (auto-generated)

central_nats:
  url: "nats://${NATS_INTERNAL_ENDPOINT}"
  creds_file: "/var/lib/vault-manager/creds.creds"
  # Plain TCP over VPC peering - no TLS needed for internal traffic
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
  heartbeat_topic: "${ownerSpaceForTopics}.forServices.health"
  app_heartbeat_topic: "${ownerSpaceForTopics}.forApp.heartbeat"
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

  // Get the vault AMI ID from SSM Parameter Store
  const vaultAmiId = await getVaultAmiId();

  // Build EC2 instance parameters
  const instanceParams: any = {
    ImageId: vaultAmiId,
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
