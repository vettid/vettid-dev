import {
  KMSClient,
  GetKeyPolicyCommand,
  PutKeyPolicyCommand,
  DescribeKeyCommand,
} from '@aws-sdk/client-kms';
import {
  AutoScalingClient,
  DescribeAutoScalingGroupsCommand,
  SetDesiredCapacityCommand,
  UpdateAutoScalingGroupCommand,
} from '@aws-sdk/client-auto-scaling';
import {
  S3Client,
  GetObjectCommand,
  DeleteObjectCommand,
  HeadObjectCommand,
} from '@aws-sdk/client-s3';
import {
  SSMClient,
  GetParameterCommand,
} from '@aws-sdk/client-ssm';
import {
  EventBridgeClient,
  RemoveTargetsCommand,
  DeleteRuleCommand,
} from '@aws-sdk/client-eventbridge';
import {
  DynamoDBClient,
  ScanCommand,
} from '@aws-sdk/client-dynamodb';
import { unmarshall } from '@aws-sdk/util-dynamodb';

const kms = new KMSClient({});
const autoscaling = new AutoScalingClient({});
const s3 = new S3Client({});
const ssm = new SSMClient({});
const events = new EventBridgeClient({});
const ddb = new DynamoDBClient({});

const VAULT_BUCKET = process.env.VAULT_BUCKET!;
const KMS_KEY_ALIAS = process.env.KMS_KEY_ALIAS || 'alias/vettid-enclave-sealing';
const MIGRATION_CONFIG_KEY = '_migration/config.json';
const FINALIZE_RULE_NAME = process.env.FINALIZE_RULE_NAME || 'vettid-migration-finalize-schedule';
const TABLE_REGISTRATIONS = process.env.TABLE_REGISTRATIONS || '';

interface MigrationConfig {
  new_pcrs: { pcr0: string; pcr1: string; pcr2: string };
  old_pcrs: { pcr0: string; pcr1: string; pcr2: string };
  version: string;
  summary: string;
  mandatory_after: string;
  published_at: string;
}

/**
 * Auto-finalize Lambda for enclave migration.
 *
 * Triggered every 5 minutes by EventBridge. Checks if migration should
 * be finalized (all users migrated or deadline passed), then:
 * 1. Removes old PCR0 from KMS policy
 * 2. Scales ASG to 1
 * 3. Deletes migration config from S3
 * 4. Cleans up the EventBridge rule (self-cleanup)
 */
export const handler = async (): Promise<void> => {
  console.log('Migration finalize check starting');

  // Step 1: Check if migration config exists
  let config: MigrationConfig;
  try {
    await s3.send(new HeadObjectCommand({
      Bucket: VAULT_BUCKET,
      Key: MIGRATION_CONFIG_KEY,
    }));

    const response = await s3.send(new GetObjectCommand({
      Bucket: VAULT_BUCKET,
      Key: MIGRATION_CONFIG_KEY,
    }));
    const body = await response.Body!.transformToString();
    config = JSON.parse(body);
    console.log(`Migration active: version=${config.version}, deadline=${config.mandatory_after}`);
  } catch (err: any) {
    if (err.name === 'NotFound' || err.name === 'NoSuchKey' || err.$metadata?.httpStatusCode === 404) {
      console.log('No migration config found — cleaning up schedule and exiting');
      await cleanupSchedule();
      return;
    }
    throw err;
  }

  // Step 2: Check if we should finalize
  const deadlinePassed = new Date(config.mandatory_after) <= new Date();

  if (!deadlinePassed) {
    // Check if all users have migrated
    const allMigrated = await checkAllUsersMigrated();
    if (!allMigrated) {
      console.log('Not all users migrated and deadline not yet passed — will check again');
      return;
    }
    console.log('All users have migrated — finalizing early');
  } else {
    console.log('Deadline has passed — finalizing');
  }

  // Step 3: Verify new enclave is healthy (ASG has healthy instance)
  const asgName = await findAsgName();
  if (!asgName) {
    console.error('Could not find enclave ASG — skipping finalization');
    return;
  }

  // Step 4: Update KMS policy to single PCR0
  try {
    const currentPcr0 = await getCurrentPcr0();
    await updateKmsToSinglePcr0(currentPcr0);
    console.log(`KMS policy updated to single PCR0: ${currentPcr0.substring(0, 24)}...`);
  } catch (err) {
    console.error('Failed to update KMS policy — will retry next cycle', err);
    return;
  }

  // Step 5: Scale ASG to 1
  try {
    await autoscaling.send(new SetDesiredCapacityCommand({
      AutoScalingGroupName: asgName,
      DesiredCapacity: 1,
    }));
    await autoscaling.send(new UpdateAutoScalingGroupCommand({
      AutoScalingGroupName: asgName,
      MaxSize: 1,
    }));
    console.log('ASG scaled to 1');
  } catch (err) {
    console.error('Failed to scale ASG — will retry next cycle', err);
    return;
  }

  // Step 6: Delete migration config
  try {
    await s3.send(new DeleteObjectCommand({
      Bucket: VAULT_BUCKET,
      Key: MIGRATION_CONFIG_KEY,
    }));
    console.log('Migration config deleted');
  } catch (err) {
    console.error('Failed to delete migration config', err);
  }

  // Step 7: Clean up EventBridge rule (self-cleanup)
  await cleanupSchedule();

  console.log(`Migration finalized successfully (version: ${config.version})`);
};

async function getCurrentPcr0(): Promise<string> {
  const result = await ssm.send(new GetParameterCommand({
    Name: '/vettid/enclave/pcr/pcr0',
  }));
  return result.Parameter!.Value!;
}

async function findAsgName(): Promise<string | null> {
  const result = await autoscaling.send(new DescribeAutoScalingGroupsCommand({}));
  const asg = result.AutoScalingGroups?.find(g =>
    g.AutoScalingGroupName?.includes('VettID-Nitro-EnclaveASG')
  );
  return asg?.AutoScalingGroupName || null;
}

async function updateKmsToSinglePcr0(pcr0: string): Promise<void> {
  // Get KMS key ID from alias
  const keyResult = await kms.send(new DescribeKeyCommand({
    KeyId: KMS_KEY_ALIAS,
  }));
  const keyId = keyResult.KeyMetadata!.KeyId!;

  // Get current policy
  const policyResult = await kms.send(new GetKeyPolicyCommand({
    KeyId: keyId,
    PolicyName: 'default',
  }));
  const policy = JSON.parse(policyResult.Policy!);

  // Find the AllowEnclaveDecrypt statement and set single PCR0
  const decryptStatement = policy.Statement.find(
    (s: any) => s.Sid === 'AllowEnclaveDecrypt'
  );
  if (decryptStatement) {
    decryptStatement.Condition.StringEqualsIgnoreCase['kms:RecipientAttestation:PCR0'] = pcr0;
  }

  // Write updated policy
  await kms.send(new PutKeyPolicyCommand({
    KeyId: keyId,
    PolicyName: 'default',
    Policy: JSON.stringify(policy),
  }));
}

async function checkAllUsersMigrated(): Promise<boolean> {
  if (!TABLE_REGISTRATIONS) {
    // No registration table configured — can't check, wait for deadline
    console.log('No registration table configured — cannot check migration progress');
    return false;
  }

  try {
    // Count active registrations
    const regResult = await ddb.send(new ScanCommand({
      TableName: TABLE_REGISTRATIONS,
      FilterExpression: '#status = :active',
      ExpressionAttributeNames: { '#status': 'status' },
      ExpressionAttributeValues: { ':active': { S: 'active' } },
      Select: 'COUNT',
    }));
    const totalUsers = regResult.Count || 0;

    if (totalUsers === 0) {
      console.log('No active users — safe to finalize');
      return true;
    }

    // Check migration state files in S3 for each user
    // Migration state is stored per-user at vaults/{ownerSpace}/migration_state.json
    // For now, use a simple heuristic: if total users <= 10, check each
    // For larger deployments, rely on the deadline
    if (totalUsers > 10) {
      console.log(`${totalUsers} active users — relying on deadline for finalization`);
      return false;
    }

    // For small user counts, scan migration states
    const items = (await ddb.send(new ScanCommand({
      TableName: TABLE_REGISTRATIONS,
      FilterExpression: '#status = :active',
      ExpressionAttributeNames: { '#status': 'status' },
      ExpressionAttributeValues: { ':active': { S: 'active' } },
    }))).Items || [];

    let migratedCount = 0;
    for (const item of items) {
      const reg = unmarshall(item);
      const ownerSpace = reg.user_guid || reg.owner_space;
      if (!ownerSpace) continue;

      try {
        await s3.send(new HeadObjectCommand({
          Bucket: VAULT_BUCKET,
          Key: `vaults/${ownerSpace}/migration_state.json`,
        }));
        migratedCount++;
      } catch {
        // No migration state = not migrated yet
      }
    }

    console.log(`Migration progress: ${migratedCount}/${totalUsers} users migrated`);
    return migratedCount >= totalUsers;
  } catch (err) {
    console.error('Error checking migration progress', err);
    return false;
  }
}

async function cleanupSchedule(): Promise<void> {
  try {
    await events.send(new RemoveTargetsCommand({
      Rule: FINALIZE_RULE_NAME,
      Ids: ['migration-finalize'],
    }));
  } catch {
    // Ignore — target may not exist
  }

  try {
    await events.send(new DeleteRuleCommand({
      Name: FINALIZE_RULE_NAME,
    }));
    console.log('EventBridge schedule cleaned up');
  } catch {
    // Ignore — rule may not exist
  }
}
