#!/usr/bin/env npx tsx
/**
 * CLI script to publish PCR sets to the signed manifest
 *
 * This script:
 * 1. Reads the current PCR manifest from S3 (or creates a new one)
 * 2. Adds or updates a PCR set
 * 3. Signs the manifest with KMS ECDSA key
 * 4. Uploads the signed manifest to S3
 *
 * Usage:
 *   npx tsx scripts/publish-pcr-set.ts \
 *     --pcr0 "c4fbe85714ce8e31e8568edf0bd0022f3341a18b3060b2ebafcb4b706bc8c7870b9d2353b9eba1c0b4dd94b80238a208" \
 *     --pcr1 "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493" \
 *     --pcr2 "3f37ae4b5a503d457cf198ac15010f595383796bfdd4c779eb255acb9cdec61fce3dc430368561807a32d483faeed5dc" \
 *     --id "production-v1" \
 *     --description "Initial production release" \
 *     --current
 *
 * Environment variables (or use --bucket and --key-id):
 *   PCR_MANIFEST_BUCKET - S3 bucket name (from NitroStack)
 *   PCR_SIGNING_KEY_ID - KMS key ID or alias (alias/vettid-pcr-signing)
 */

import { S3Client, GetObjectCommand, PutObjectCommand } from '@aws-sdk/client-s3';
import { KMSClient, SignCommand, GetPublicKeyCommand } from '@aws-sdk/client-kms';
import { CloudFormationClient, DescribeStacksCommand } from '@aws-sdk/client-cloudformation';
import { createHash, randomUUID } from 'crypto';
import { parseArgs } from 'util';

interface PcrSet {
  id: string;
  pcr0: string;
  pcr1: string;
  pcr2: string;
  valid_from: string;
  valid_until: string | null;
  is_current: boolean;
  description?: string;
}

interface PcrManifest {
  version: number;
  timestamp: string;
  pcr_sets: PcrSet[];
  signature: string;
  public_key?: string;
}

const MANIFEST_KEY = 'pcr-manifest.json';

async function getStackOutputs(): Promise<{ bucket: string; keyId: string }> {
  const cfn = new CloudFormationClient({});
  const response = await cfn.send(new DescribeStacksCommand({
    StackName: 'VettID-Nitro',
  }));

  const outputs = response.Stacks?.[0]?.Outputs || [];
  const bucket = outputs.find(o => o.OutputKey === 'PcrManifestBucketName')?.OutputValue;
  const keyId = outputs.find(o => o.OutputKey === 'PcrSigningKeyId')?.OutputValue;

  if (!bucket || !keyId) {
    throw new Error('Could not find PcrManifestBucketName or PcrSigningKeyId in VettID-Nitro stack outputs');
  }

  return { bucket, keyId };
}

async function signManifest(kms: KMSClient, keyId: string, data: string): Promise<string> {
  const hash = createHash('sha256').update(data).digest();

  const response = await kms.send(new SignCommand({
    KeyId: keyId,
    Message: hash,
    MessageType: 'DIGEST',
    SigningAlgorithm: 'ECDSA_SHA_256',
  }));

  if (!response.Signature) {
    throw new Error('KMS did not return a signature');
  }

  return Buffer.from(response.Signature).toString('base64');
}

async function getPublicKey(kms: KMSClient, keyId: string): Promise<string> {
  const response = await kms.send(new GetPublicKeyCommand({
    KeyId: keyId,
  }));

  if (!response.PublicKey) {
    throw new Error('KMS did not return public key');
  }

  return Buffer.from(response.PublicKey).toString('base64');
}

function validatePcrValue(value: string, name: string): void {
  const pcrRegex = /^[a-f0-9]{96}$/i;
  if (!pcrRegex.test(value)) {
    throw new Error(`${name} must be a 96-character hex string (SHA-384 hash). Got: ${value.length} chars`);
  }
}

async function main() {
  const { values } = parseArgs({
    options: {
      pcr0: { type: 'string' },
      pcr1: { type: 'string' },
      pcr2: { type: 'string' },
      id: { type: 'string' },
      description: { type: 'string' },
      current: { type: 'boolean', default: false },
      'valid-from': { type: 'string' },
      'valid-until': { type: 'string' },
      bucket: { type: 'string' },
      'key-id': { type: 'string' },
      'get-public-key': { type: 'boolean', default: false },
      help: { type: 'boolean', short: 'h', default: false },
    },
    strict: true,
  });

  if (values.help) {
    console.log(`
Usage: npx tsx scripts/publish-pcr-set.ts [options]

Options:
  --pcr0 <hex>         PCR0 value (96-char hex, required)
  --pcr1 <hex>         PCR1 value (96-char hex, required)
  --pcr2 <hex>         PCR2 value (96-char hex, required)
  --id <string>        PCR set identifier (auto-generated if not provided)
  --description <text> Human-readable description
  --current            Mark this PCR set as current (default: false)
  --valid-from <date>  ISO 8601 date (default: now)
  --valid-until <date> ISO 8601 expiration date (default: null/forever)
  --bucket <name>      S3 bucket (default: from VettID-Nitro stack)
  --key-id <id>        KMS key ID (default: from VettID-Nitro stack)
  --get-public-key     Just print the public key and exit
  -h, --help           Show this help

Examples:
  # Publish new PCR set as current
  npx tsx scripts/publish-pcr-set.ts \\
    --pcr0 "c4fbe857..." \\
    --pcr1 "4b4d5b36..." \\
    --pcr2 "3f37ae4b..." \\
    --current \\
    --description "Production v1.2.3"

  # Get the signing public key (for embedding in mobile apps)
  npx tsx scripts/publish-pcr-set.ts --get-public-key
`);
    process.exit(0);
  }

  // Get bucket and key from environment, args, or stack outputs
  let bucket = values.bucket || process.env.PCR_MANIFEST_BUCKET;
  let keyId = values['key-id'] || process.env.PCR_SIGNING_KEY_ID;

  if (!bucket || !keyId) {
    console.log('Fetching configuration from VettID-Nitro stack outputs...');
    const stackOutputs = await getStackOutputs();
    bucket = bucket || stackOutputs.bucket;
    keyId = keyId || stackOutputs.keyId;
  }

  console.log(`Using bucket: ${bucket}`);
  console.log(`Using key: ${keyId}`);

  const s3 = new S3Client({});
  const kms = new KMSClient({});

  // Handle --get-public-key flag
  if (values['get-public-key']) {
    const publicKey = await getPublicKey(kms, keyId);
    console.log('\n=== VettID PCR Signing Public Key (Base64 DER) ===');
    console.log(publicKey);
    console.log('\nUse this value to update:');
    console.log('  - iOS: PCRManifestManager.swift - signingPublicKeyBase64');
    console.log('  - Android: PcrConfigManager.kt - VETTID_SIGNING_KEY_BASE64');
    return;
  }

  // Validate required args for publishing
  if (!values.pcr0 || !values.pcr1 || !values.pcr2) {
    console.error('Error: --pcr0, --pcr1, and --pcr2 are required');
    console.error('Run with --help for usage information');
    process.exit(1);
  }

  validatePcrValue(values.pcr0, 'pcr0');
  validatePcrValue(values.pcr1, 'pcr1');
  validatePcrValue(values.pcr2, 'pcr2');

  // Load existing manifest or create new one
  let manifest: PcrManifest;
  try {
    const existing = await s3.send(new GetObjectCommand({
      Bucket: bucket,
      Key: MANIFEST_KEY,
    }));
    const content = await existing.Body?.transformToString();
    manifest = content ? JSON.parse(content) : createEmptyManifest();
    console.log(`Loaded existing manifest (version ${manifest.version})`);
  } catch (error: unknown) {
    if (error && typeof error === 'object' && 'name' in error && error.name === 'NoSuchKey') {
      manifest = createEmptyManifest();
      console.log('Creating new manifest');
    } else {
      throw error;
    }
  }

  // Create new PCR set
  const newPcrSet: PcrSet = {
    id: values.id || `pcr-set-${randomUUID().slice(0, 8)}`,
    pcr0: values.pcr0.toLowerCase(),
    pcr1: values.pcr1.toLowerCase(),
    pcr2: values.pcr2.toLowerCase(),
    valid_from: values['valid-from'] || new Date().toISOString(),
    valid_until: values['valid-until'] || null,
    is_current: values.current || false,
    description: values.description,
  };

  // If new set is_current, unset is_current on all others
  if (newPcrSet.is_current) {
    manifest.pcr_sets.forEach(set => {
      set.is_current = false;
    });
  }

  // Update or add the PCR set
  const existingIndex = manifest.pcr_sets.findIndex(s => s.id === newPcrSet.id);
  if (existingIndex >= 0) {
    manifest.pcr_sets[existingIndex] = newPcrSet;
    console.log(`Updating existing PCR set: ${newPcrSet.id}`);
  } else {
    manifest.pcr_sets.push(newPcrSet);
    console.log(`Adding new PCR set: ${newPcrSet.id}`);
  }

  // Update manifest metadata
  manifest.version += 1;
  manifest.timestamp = new Date().toISOString();

  // Sign the manifest
  const dataToSign = JSON.stringify({
    version: manifest.version,
    timestamp: manifest.timestamp,
    pcr_sets: manifest.pcr_sets,
  });

  console.log('Signing manifest with KMS...');
  manifest.signature = await signManifest(kms, keyId, dataToSign);
  manifest.public_key = await getPublicKey(kms, keyId);

  // Upload signed manifest
  await s3.send(new PutObjectCommand({
    Bucket: bucket,
    Key: MANIFEST_KEY,
    Body: JSON.stringify(manifest, null, 2),
    ContentType: 'application/json',
    CacheControl: 'public, max-age=60',
  }));

  console.log('\n✅ PCR manifest published successfully!');
  console.log(`   Version: ${manifest.version}`);
  console.log(`   PCR Set ID: ${newPcrSet.id}`);
  console.log(`   Is Current: ${newPcrSet.is_current}`);
  console.log(`   Total Sets: ${manifest.pcr_sets.length}`);
  console.log(`\nManifest available at: https://pcr-manifest.vettid.dev/${MANIFEST_KEY}`);
}

function createEmptyManifest(): PcrManifest {
  return {
    version: 0,
    timestamp: new Date().toISOString(),
    pcr_sets: [],
    signature: '',
  };
}

main().catch(error => {
  console.error('Error:', error.message);
  process.exit(1);
});
