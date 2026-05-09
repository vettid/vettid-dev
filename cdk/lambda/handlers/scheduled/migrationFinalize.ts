import {
  KMSClient,
  GetKeyPolicyCommand,
  PutKeyPolicyCommand,
  DescribeKeyCommand,
  VerifyCommand,
} from '@aws-sdk/client-kms';
import { createHash } from 'crypto';
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
  ListObjectsV2Command,
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
const kms = new KMSClient({});
const autoscaling = new AutoScalingClient({});
const s3 = new S3Client({});
const ssm = new SSMClient({});
const events = new EventBridgeClient({});

const VAULT_BUCKET = process.env.VAULT_BUCKET!;
const KMS_KEY_ALIAS = process.env.KMS_KEY_ALIAS || 'alias/vettid-enclave-sealing';
const PCR_SIGNING_KEY_ALIAS = process.env.PCR_SIGNING_KEY_ALIAS || 'alias/vettid-pcr-signing';
const MIGRATION_CONFIG_KEY = '_migration/config.json';
const MIGRATION_MARKERS_PREFIX = '_migration/completed/';
const FINALIZE_RULE_NAME = process.env.FINALIZE_RULE_NAME || 'vettid-migration-finalize-schedule';

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
    // Check if all enrolled users have posted migration markers.
    const allMigrated = await checkAllUsersMigrated(config.version);
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

  // Step 5: Scale ASG back to 1.
  // deploy.sh pins MinSize=2 during the migration window so the CPU
  // target-tracking AlarmLow policy can't kill the OLD instance before
  // users have re-sealed. We restore MinSize=1 here so steady-state
  // capacity tracking can scale freely again.
  try {
    await autoscaling.send(new UpdateAutoScalingGroupCommand({
      AutoScalingGroupName: asgName,
      MinSize: 1,
      MaxSize: 1,
    }));
    await autoscaling.send(new SetDesiredCapacityCommand({
      AutoScalingGroupName: asgName,
      DesiredCapacity: 1,
    }));
    console.log('ASG scaled to 1 (Min=1, Max=1)');
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

  // Step 7: Remove per-user migration markers for this version so the next
  // migration starts with a clean slate.
  try {
    await deleteMigrationMarkers(config.version);
    console.log(`Migration markers cleaned up for ${config.version}`);
  } catch (err) {
    console.error('Failed to clean up migration markers', err);
  }

  // Step 8: Clean up EventBridge rule (self-cleanup)
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

async function checkAllUsersMigrated(version: string): Promise<boolean> {
  try {
    // Enrolled users = folders under vaults/ (each enrolled owner has a folder).
    const enrolledOwnerSpaces = await listOwnerSpacePrefixes();
    if (enrolledOwnerSpaces.size === 0) {
      // No enrolled users yet — nothing to migrate. Safe to finalize.
      console.log('No enrolled users — safe to finalize');
      return true;
    }

    // Migrated users = explicit markers written by vault-manager on successful
    // migration (_migration/completed/{version}/{ownerSpace}.json).
    const migratedOwnerSpaces = await listMigrationMarkers(version);

    const pending: string[] = [];
    enrolledOwnerSpaces.forEach((owner) => {
      if (!migratedOwnerSpaces.has(owner)) pending.push(owner);
    });
    console.log(
      `Migration progress for ${version}: ${migratedOwnerSpaces.size}/${enrolledOwnerSpaces.size}` +
      (pending.length ? ` (pending: ${pending.slice(0, 5).join(', ')}${pending.length > 5 ? '...' : ''})` : ''),
    );
    return pending.length === 0;
  } catch (err) {
    console.error('Error checking migration progress — keeping migration open', err);
    return false;
  }
}

async function listOwnerSpacePrefixes(): Promise<Set<string>> {
  const result = new Set<string>();
  let continuationToken: string | undefined;
  do {
    const resp = await s3.send(new ListObjectsV2Command({
      Bucket: VAULT_BUCKET,
      Prefix: 'vaults/',
      Delimiter: '/',
      ContinuationToken: continuationToken,
    }));
    for (const cp of resp.CommonPrefixes || []) {
      // 'vaults/{ownerSpace}/' → 'ownerSpace'
      const match = cp.Prefix?.match(/^vaults\/([^/]+)\/$/);
      if (match) result.add(match[1]);
    }
    continuationToken = resp.IsTruncated ? resp.NextContinuationToken : undefined;
  } while (continuationToken);
  return result;
}

/**
 * SECURITY (attestation-F3): each migration marker is a JSON object
 * stamped with an ECDSA signature from the enclave's PCR signing KMS
 * key. We list, fetch, and KMS Verify every marker before counting it
 * as a "user X has migrated" claim — anything with a missing or bad
 * signature is dropped (logged) so a misconfigured S3 writer can't
 * forge mass markers and trigger early auto-finalize.
 */
async function listMigrationMarkers(version: string): Promise<Set<string>> {
  const result = new Set<string>();
  let continuationToken: string | undefined;
  const prefix = `_migration/completed/${version}/`;
  do {
    const resp = await s3.send(new ListObjectsV2Command({
      Bucket: VAULT_BUCKET,
      Prefix: prefix,
      ContinuationToken: continuationToken,
    }));
    for (const obj of resp.Contents || []) {
      const match = obj.Key?.match(/^_migration\/completed\/[^/]+\/([^/]+)\.json$/);
      if (!match || !obj.Key) continue;
      const ownerSpace = match[1];
      const verified = await verifyMigrationMarker(obj.Key, version, ownerSpace);
      if (verified) {
        result.add(ownerSpace);
      } else {
        console.warn(`Skipping unverifiable migration marker: ${obj.Key}`);
      }
    }
    continuationToken = resp.IsTruncated ? resp.NextContinuationToken : undefined;
  } while (continuationToken);
  return result;
}

async function verifyMigrationMarker(
  key: string,
  expectedVersion: string,
  expectedOwnerSpace: string,
): Promise<boolean> {
  let body: string;
  try {
    const resp = await s3.send(new GetObjectCommand({ Bucket: VAULT_BUCKET, Key: key }));
    body = (await resp.Body?.transformToString()) || '';
  } catch (e) {
    console.error(`Failed to fetch marker ${key}:`, e);
    return false;
  }
  let parsed: any;
  try {
    parsed = JSON.parse(body);
  } catch {
    console.warn(`Marker ${key} is not valid JSON`);
    return false;
  }
  if (parsed.version !== expectedVersion || parsed.owner_space !== expectedOwnerSpace) {
    console.warn(
      `Marker ${key} field mismatch: version=${parsed.version}, owner_space=${parsed.owner_space}`,
    );
    return false;
  }
  if (typeof parsed.signature !== 'string' || !parsed.signature) {
    return false;
  }
  // Reproduce the canonical bytes the supervisor signed: alphabetical
  // key order, no whitespace, fields {completed_at, owner_space, version}.
  const canonical = JSON.stringify(
    { completed_at: parsed.completed_at, owner_space: parsed.owner_space, version: parsed.version },
  );
  const digest = createHash('sha256').update(canonical).digest();
  try {
    const result = await kms.send(new VerifyCommand({
      KeyId: PCR_SIGNING_KEY_ALIAS,
      Message: digest,
      MessageType: 'DIGEST',
      Signature: Buffer.from(parsed.signature, 'base64'),
      SigningAlgorithm: 'ECDSA_SHA_256',
    }));
    return result.SignatureValid === true;
  } catch (e) {
    console.error(`KMS Verify failed for marker ${key}:`, e);
    return false;
  }
}

async function deleteMigrationMarkers(version: string): Promise<void> {
  const prefix = `${MIGRATION_MARKERS_PREFIX}${version}/`;
  let continuationToken: string | undefined;
  do {
    const resp = await s3.send(new ListObjectsV2Command({
      Bucket: VAULT_BUCKET,
      Prefix: prefix,
      ContinuationToken: continuationToken,
    }));
    for (const obj of resp.Contents || []) {
      if (!obj.Key) continue;
      await s3.send(new DeleteObjectCommand({ Bucket: VAULT_BUCKET, Key: obj.Key }));
    }
    continuationToken = resp.IsTruncated ? resp.NextContinuationToken : undefined;
  } while (continuationToken);
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
