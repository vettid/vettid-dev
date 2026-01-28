#!/usr/bin/env npx ts-node
/**
 * Reset Enrollment Script
 *
 * Cleans up all enrollment and vault data for a user, allowing them to re-enroll.
 *
 * Usage:
 *   npx ts-node scripts/reset-enrollment.ts <email>
 *   npx ts-node scripts/reset-enrollment.ts mesmerverse@proton.me
 *
 * What it deletes:
 *   - NATS account (DynamoDB)
 *   - NATS tokens (DynamoDB)
 *   - Enrollment sessions (DynamoDB)
 *   - Credential backups (DynamoDB + S3)
 *   - User profiles (DynamoDB)
 */

import {
  CognitoIdentityProviderClient,
  AdminGetUserCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import {
  DynamoDBClient,
  DeleteItemCommand,
  QueryCommand,
  ScanCommand,
  BatchWriteItemCommand,
} from '@aws-sdk/client-dynamodb';
import {
  S3Client,
  ListObjectsV2Command,
  DeleteObjectsCommand,
} from '@aws-sdk/client-s3';
import {
  SSMClient,
  SendCommandCommand,
  GetCommandInvocationCommand,
} from '@aws-sdk/client-ssm';
import {
  EC2Client,
  DescribeInstancesCommand,
} from '@aws-sdk/client-ec2';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';

// Configuration - table names from CDK deployment
const USER_POOL_ID = 'us-east-1_HziV7gn9Q';
const TABLE_NATS_ACCOUNTS = 'VettID-Infrastructure-NatsAccounts8A092954-1EQ9UEJWBL574';
const TABLE_NATS_TOKENS = 'VettID-Infrastructure-NatsTokensF1A0FFC9-2URUMO9P1I0O';
const TABLE_ENROLLMENT_SESSIONS = 'VettID-Infrastructure-EnrollmentSessions54BF48AC-1I8UL5Q8GOKG5';
const TABLE_CREDENTIAL_BACKUPS = 'VettID-Infrastructure-CredentialBackups49D8A239-1XNZVD3X5F413';
const TABLE_PROFILES = 'VettID-Infrastructure-Profiles4FC22479-JNQ6UGBR9JRK';
const BACKUP_BUCKET = 'vettid-infrastructure-vaultbackupsbucket803b5ae6-iprvicfnrkma';

const cognito = new CognitoIdentityProviderClient({ region: 'us-east-1' });
const ddb = new DynamoDBClient({ region: 'us-east-1' });
const s3 = new S3Client({ region: 'us-east-1' });
const ssm = new SSMClient({ region: 'us-east-1' });
const ec2 = new EC2Client({ region: 'us-east-1' });

interface CleanupResult {
  natsAccountDeleted: boolean;
  natsTokensDeleted: number;
  enrollmentSessionsDeleted: number;
  credentialBackupsDeleted: number;
  profilesDeleted: number;
  s3ObjectsDeleted: number;
  enclaveCredentialDeleted: boolean;
}

async function getUserGuid(email: string): Promise<string | null> {
  try {
    const result = await cognito.send(new AdminGetUserCommand({
      UserPoolId: USER_POOL_ID,
      Username: email,
    }));

    const guidAttr = result.UserAttributes?.find(a => a.Name === 'custom:user_guid');
    return guidAttr?.Value || null;
  } catch (error: any) {
    if (error.name === 'UserNotFoundException') {
      return null;
    }
    throw error;
  }
}

async function deleteNatsAccount(userGuid: string): Promise<boolean> {
  try {
    await ddb.send(new DeleteItemCommand({
      TableName: TABLE_NATS_ACCOUNTS,
      Key: marshall({ user_guid: userGuid }),
    }));
    return true;
  } catch (error: any) {
    console.error('  Error deleting NATS account:', error.message);
    return false;
  }
}

async function deleteNatsTokens(userGuid: string): Promise<number> {
  try {
    const result = await ddb.send(new QueryCommand({
      TableName: TABLE_NATS_TOKENS,
      IndexName: 'user-index',
      KeyConditionExpression: 'user_guid = :guid',
      ExpressionAttributeValues: marshall({ ':guid': userGuid }),
    }));

    const items = result.Items || [];
    if (items.length === 0) return 0;

    for (const item of items) {
      const token = unmarshall(item);
      await ddb.send(new DeleteItemCommand({
        TableName: TABLE_NATS_TOKENS,
        Key: marshall({ token_id: token.token_id }),
      }));
    }

    return items.length;
  } catch (error: any) {
    console.error('  Error deleting NATS tokens:', error.message);
    return 0;
  }
}

async function deleteEnrollmentSessions(userGuid: string): Promise<number> {
  try {
    // Scan for sessions (no direct index on user_guid for this table)
    const result = await ddb.send(new ScanCommand({
      TableName: TABLE_ENROLLMENT_SESSIONS,
      FilterExpression: 'user_guid = :guid',
      ExpressionAttributeValues: marshall({ ':guid': userGuid }),
    }));

    const items = result.Items || [];
    if (items.length === 0) return 0;

    for (const item of items) {
      const session = unmarshall(item);
      await ddb.send(new DeleteItemCommand({
        TableName: TABLE_ENROLLMENT_SESSIONS,
        Key: marshall({ session_id: session.session_id }),
      }));
    }

    return items.length;
  } catch (error: any) {
    console.error('  Error deleting enrollment sessions:', error.message);
    return 0;
  }
}

async function deleteCredentialBackups(userGuid: string): Promise<number> {
  try {
    await ddb.send(new DeleteItemCommand({
      TableName: TABLE_CREDENTIAL_BACKUPS,
      Key: marshall({ member_guid: userGuid }),
    }));
    return 1;
  } catch (error: any) {
    if (error.name !== 'ResourceNotFoundException') {
      console.error('  Error deleting credential backups:', error.message);
    }
    return 0;
  }
}

async function deleteProfiles(userGuid: string): Promise<number> {
  try {
    const result = await ddb.send(new ScanCommand({
      TableName: TABLE_PROFILES,
      FilterExpression: 'user_guid = :guid',
      ExpressionAttributeValues: marshall({ ':guid': userGuid }),
    }));

    const items = result.Items || [];
    if (items.length === 0) return 0;

    for (const item of items) {
      const profile = unmarshall(item);
      await ddb.send(new DeleteItemCommand({
        TableName: TABLE_PROFILES,
        Key: marshall({ profile_id: profile.profile_id }),
      }));
    }

    return items.length;
  } catch (error: any) {
    console.error('  Error deleting profiles:', error.message);
    return 0;
  }
}

async function deleteS3Backups(userGuid: string): Promise<number> {
  try {
    const listResult = await s3.send(new ListObjectsV2Command({
      Bucket: BACKUP_BUCKET,
      Prefix: `${userGuid}/`,
    }));

    if (!listResult.Contents || listResult.Contents.length === 0) return 0;

    const deleteResult = await s3.send(new DeleteObjectsCommand({
      Bucket: BACKUP_BUCKET,
      Delete: {
        Objects: listResult.Contents.map(obj => ({ Key: obj.Key! })),
      },
    }));

    return deleteResult.Deleted?.length || 0;
  } catch (error: any) {
    console.error('  Error deleting S3 backups:', error.message);
    return 0;
  }
}

// ============================================================================
// SSM Functions - Reset enclave credential via NATS server
// ============================================================================

/**
 * Find a running NATS server instance ID
 */
async function findNatsServerInstance(): Promise<string | null> {
  try {
    const result = await ec2.send(new DescribeInstancesCommand({
      Filters: [
        { Name: 'instance-state-name', Values: ['running'] },
        { Name: 'tag:Name', Values: ['VettID-NATS'] },
      ],
    }));

    const instances = result.Reservations?.flatMap(r => r.Instances || []) || [];
    if (instances.length === 0) return null;

    return instances[0].InstanceId || null;
  } catch (error: any) {
    console.error('  Error finding NATS server:', error.message);
    return null;
  }
}

/**
 * Send vault reset message to enclave via SSM command on NATS server
 * This clears the credential from the enclave's SQLite storage
 */
async function resetEnclaveCredential(userGuid: string): Promise<boolean> {
  try {
    // Find a NATS server instance
    const instanceId = await findNatsServerInstance();
    if (!instanceId) {
      console.error('  No running NATS server found');
      return false;
    }

    // Send the NATS publish command via SSM
    const payload = JSON.stringify({ user_guid: userGuid });
    const command = `nats pub enclave.vault.reset '${payload}'`;

    const sendResult = await ssm.send(new SendCommandCommand({
      InstanceIds: [instanceId],
      DocumentName: 'AWS-RunShellScript',
      Parameters: { commands: [command] },
    }));

    const commandId = sendResult.Command?.CommandId;
    if (!commandId) {
      console.error('  Failed to send SSM command');
      return false;
    }

    // Wait for command to complete
    await new Promise(resolve => setTimeout(resolve, 2000));

    // Check command result
    const invocationResult = await ssm.send(new GetCommandInvocationCommand({
      CommandId: commandId,
      InstanceId: instanceId,
    }));

    if (invocationResult.Status === 'Success') {
      return true;
    } else {
      console.error('  SSM command failed:', invocationResult.StandardErrorContent);
      return false;
    }
  } catch (error: any) {
    console.error('  Error resetting enclave credential:', error.message);
    return false;
  }
}

async function resetEnrollment(email: string): Promise<void> {
  console.log(`\nResetting enrollment for: ${email}`);
  console.log('='.repeat(50));

  // 1. Look up user GUID
  console.log('\n1. Looking up user...');
  const userGuid = await getUserGuid(email);

  if (!userGuid) {
    console.error(`   User not found in Cognito: ${email}`);
    process.exit(1);
  }
  console.log(`   Found user GUID: ${userGuid}`);

  const result: CleanupResult = {
    natsAccountDeleted: false,
    natsTokensDeleted: 0,
    enrollmentSessionsDeleted: 0,
    credentialBackupsDeleted: 0,
    profilesDeleted: 0,
    s3ObjectsDeleted: 0,
    enclaveCredentialDeleted: false,
  };

  // 2. Delete NATS tokens first (to prevent new connections)
  console.log('\n2. Deleting NATS tokens...');
  result.natsTokensDeleted = await deleteNatsTokens(userGuid);
  console.log(`   Deleted ${result.natsTokensDeleted} token(s)`);

  // 3. Delete NATS account
  console.log('\n3. Deleting NATS account...');
  result.natsAccountDeleted = await deleteNatsAccount(userGuid);
  console.log(`   ${result.natsAccountDeleted ? 'Deleted' : 'Not found or failed'}`);

  // 4. Delete enrollment sessions
  console.log('\n4. Deleting enrollment sessions...');
  result.enrollmentSessionsDeleted = await deleteEnrollmentSessions(userGuid);
  console.log(`   Deleted ${result.enrollmentSessionsDeleted} session(s)`);

  // 5. Delete credential backups
  console.log('\n5. Deleting credential backups...');
  result.credentialBackupsDeleted = await deleteCredentialBackups(userGuid);
  console.log(`   Deleted ${result.credentialBackupsDeleted} backup(s)`);

  // 6. Delete profiles
  console.log('\n6. Deleting profiles...');
  result.profilesDeleted = await deleteProfiles(userGuid);
  console.log(`   Deleted ${result.profilesDeleted} profile(s)`);

  // 7. Delete S3 backup blobs
  console.log('\n7. Deleting S3 backup files...');
  result.s3ObjectsDeleted = await deleteS3Backups(userGuid);
  console.log(`   Deleted ${result.s3ObjectsDeleted} file(s)`);

  // 8. Reset enclave credential storage
  console.log('\n8. Resetting enclave credential storage...');
  result.enclaveCredentialDeleted = await resetEnclaveCredential(userGuid);
  console.log(`   ${result.enclaveCredentialDeleted ? 'Reset message sent' : 'Failed to send reset'}`);

  // Summary
  const totalDeleted =
    (result.natsAccountDeleted ? 1 : 0) +
    result.natsTokensDeleted +
    result.enrollmentSessionsDeleted +
    result.credentialBackupsDeleted +
    result.profilesDeleted +
    result.s3ObjectsDeleted +
    (result.enclaveCredentialDeleted ? 1 : 0);

  console.log('\n' + '='.repeat(50));
  console.log('SUMMARY');
  console.log('='.repeat(50));
  console.log(`Total items deleted: ${totalDeleted}`);
  console.log(`\nUser ${email} can now re-enroll.`);
}

// Main
const email = process.argv[2];

if (!email) {
  console.error('Usage: npx ts-node scripts/reset-enrollment.ts <email>');
  console.error('Example: npx ts-node scripts/reset-enrollment.ts mesmerverse@proton.me');
  process.exit(1);
}

resetEnrollment(email).catch(error => {
  console.error('\nFatal error:', error);
  process.exit(1);
});
