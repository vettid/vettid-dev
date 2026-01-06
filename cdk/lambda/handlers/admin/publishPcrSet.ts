import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { S3Client, GetObjectCommand, PutObjectCommand } from '@aws-sdk/client-s3';
import { KMSClient, SignCommand, GetPublicKeyCommand } from '@aws-sdk/client-kms';
import { createHash, randomUUID } from 'crypto';
import { requireAdminGroup, ok, badRequest, internalError } from '../../common/util';

const s3 = new S3Client({});
const kms = new KMSClient({});

const BUCKET = process.env.PCR_MANIFEST_BUCKET!;
const SIGNING_KEY_ID = process.env.PCR_SIGNING_KEY_ID!;
const MANIFEST_KEY = 'pcr-manifest.json';

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
  public_key?: string; // DER-encoded public key for verification
}

/**
 * POST /admin/attestation/pcr-sets
 *
 * Add a new PCR set to the manifest or update an existing one.
 * The manifest is signed with the VettID PCR signing key.
 *
 * Request body:
 * {
 *   "id": "production-v2",
 *   "pcr0": "hex-string-96-chars",
 *   "pcr1": "hex-string-96-chars",
 *   "pcr2": "hex-string-96-chars",
 *   "valid_from": "2026-01-06T00:00:00Z",
 *   "valid_until": null,
 *   "is_current": true,
 *   "description": "Updated enclave with bug fix"
 * }
 *
 * If is_current=true, all other sets will have is_current set to false.
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestOrigin = event.headers?.origin;

  try {
    // Require admin authentication
    const adminCheck = requireAdminGroup(event, requestOrigin);
    if (adminCheck) {
      return adminCheck;
    }

    // Parse request body
    if (!event.body) {
      return badRequest('Request body is required');
    }

    let newPcrSet: PcrSet;
    try {
      newPcrSet = JSON.parse(event.body);
    } catch {
      return badRequest('Invalid JSON in request body');
    }

    // Validate PCR set
    const validationError = validatePcrSet(newPcrSet);
    if (validationError) {
      return badRequest(validationError);
    }

    // Generate ID if not provided
    if (!newPcrSet.id) {
      newPcrSet.id = `pcr-set-${randomUUID().slice(0, 8)}`;
    }

    // Load existing manifest or create new one
    let manifest: PcrManifest;
    try {
      const existing = await s3.send(new GetObjectCommand({
        Bucket: BUCKET,
        Key: MANIFEST_KEY,
      }));
      const content = await existing.Body?.transformToString();
      manifest = content ? JSON.parse(content) : createEmptyManifest();
    } catch (error: any) {
      if (error.name === 'NoSuchKey') {
        manifest = createEmptyManifest();
      } else {
        throw error;
      }
    }

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
    } else {
      manifest.pcr_sets.push(newPcrSet);
    }

    // Update manifest metadata
    manifest.version += 1;
    manifest.timestamp = new Date().toISOString();

    // Sign the manifest (excluding the signature field)
    const dataToSign = JSON.stringify({
      version: manifest.version,
      timestamp: manifest.timestamp,
      pcr_sets: manifest.pcr_sets,
    });

    const signature = await signManifest(dataToSign);
    manifest.signature = signature;

    // Get and include public key for easy verification
    const publicKey = await getPublicKey();
    manifest.public_key = publicKey;

    // Store the signed manifest
    await s3.send(new PutObjectCommand({
      Bucket: BUCKET,
      Key: MANIFEST_KEY,
      Body: JSON.stringify(manifest, null, 2),
      ContentType: 'application/json',
      CacheControl: 'public, max-age=60', // Short cache for updates
    }));

    // Also update SSM parameters for the enclave PCRs (used by KMS policy)
    // This is done separately via CLI/CDK for security

    console.log(`PCR manifest updated to version ${manifest.version} by admin`);

    return ok({
      message: 'PCR set published successfully',
      manifest_version: manifest.version,
      pcr_set_id: newPcrSet.id,
      total_sets: manifest.pcr_sets.length,
    });

  } catch (error: any) {
    console.error('Error publishing PCR set:', error);
    return internalError('Failed to publish PCR set');
  }
};

/**
 * Validate a PCR set structure
 */
function validatePcrSet(set: PcrSet): string | null {
  // PCR values are SHA-384 hashes = 96 hex characters
  const pcrRegex = /^[a-f0-9]{96}$/i;

  if (!set.pcr0 || !pcrRegex.test(set.pcr0)) {
    return 'pcr0 must be a 96-character hex string (SHA-384 hash)';
  }
  if (!set.pcr1 || !pcrRegex.test(set.pcr1)) {
    return 'pcr1 must be a 96-character hex string (SHA-384 hash)';
  }
  if (!set.pcr2 || !pcrRegex.test(set.pcr2)) {
    return 'pcr2 must be a 96-character hex string (SHA-384 hash)';
  }

  if (!set.valid_from) {
    return 'valid_from is required (ISO 8601 date)';
  }

  try {
    new Date(set.valid_from).toISOString();
  } catch {
    return 'valid_from must be a valid ISO 8601 date';
  }

  if (set.valid_until !== null && set.valid_until !== undefined) {
    try {
      new Date(set.valid_until).toISOString();
    } catch {
      return 'valid_until must be a valid ISO 8601 date or null';
    }
  }

  if (typeof set.is_current !== 'boolean') {
    return 'is_current must be a boolean';
  }

  return null;
}

/**
 * Create an empty manifest structure
 */
function createEmptyManifest(): PcrManifest {
  return {
    version: 0,
    timestamp: new Date().toISOString(),
    pcr_sets: [],
    signature: '',
  };
}

/**
 * Sign data using KMS ECDSA key
 */
async function signManifest(data: string): Promise<string> {
  // Hash the data first (ECDSA_SHA_256 requires pre-hashed input for MESSAGE_DIGEST)
  const hash = createHash('sha256').update(data).digest();

  const response = await kms.send(new SignCommand({
    KeyId: SIGNING_KEY_ID,
    Message: hash,
    MessageType: 'DIGEST',
    SigningAlgorithm: 'ECDSA_SHA_256',
  }));

  if (!response.Signature) {
    throw new Error('KMS did not return a signature');
  }

  return Buffer.from(response.Signature).toString('base64');
}

/**
 * Get the public key for the signing key
 */
async function getPublicKey(): Promise<string> {
  const response = await kms.send(new GetPublicKeyCommand({
    KeyId: SIGNING_KEY_ID,
  }));

  if (!response.PublicKey) {
    throw new Error('KMS did not return public key');
  }

  return Buffer.from(response.PublicKey).toString('base64');
}
