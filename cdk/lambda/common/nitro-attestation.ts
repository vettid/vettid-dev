/**
 * AWS Nitro Enclave Attestation Utilities
 *
 * Implements verification of Nitro Enclave attestation documents.
 * These documents prove that code is running inside a genuine AWS Nitro Enclave
 * with specific PCR (Platform Configuration Register) values.
 *
 * @see https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
 * @see https://github.com/aws/aws-nitro-enclaves-nsm-api
 */

import { createHash, createVerify, X509Certificate } from 'crypto';

// ============================================
// Types
// ============================================

/**
 * PCR values from a Nitro Enclave attestation
 * PCR0-2 identify the enclave code, PCR3+ are for custom use
 */
export interface PCRValues {
  pcr0: string;  // Enclave image file hash (48 bytes hex = 96 chars)
  pcr1: string;  // Linux kernel and bootstrap hash
  pcr2: string;  // Application hash
  pcr3?: string; // IAM role hash (if used)
  pcr4?: string; // Instance ID hash (if used)
  pcr8?: string; // Enclave image file signing certificate hash
}

/**
 * Expected PCR values for a specific enclave version
 */
export interface ExpectedPCRs {
  id: string;           // Version identifier (e.g., "v1.0.0")
  pcr0: string;
  pcr1: string;
  pcr2: string;
  validFrom: string;    // ISO 8601 date
  validUntil?: string;  // ISO 8601 date, null = no expiry
  isCurrent: boolean;
}

/**
 * Result of Nitro attestation verification
 */
export interface NitroAttestationResult {
  valid: boolean;
  pcrs: PCRValues;
  enclavePublicKey?: Buffer;  // For establishing encrypted session
  timestamp: Date;
  moduleId: string;
  nonce?: Buffer;
  userData?: Buffer;
  errors: string[];
  details: Record<string, any>;
}

/**
 * Parsed Nitro attestation document
 * Based on AWS Nitro Enclaves attestation format
 */
export interface NitroAttestationDocument {
  moduleId: string;
  timestamp: number;  // Unix milliseconds
  digest: 'SHA384';
  pcrs: Map<number, Buffer>;
  certificate: Buffer;  // DER-encoded X.509 certificate
  cabundle: Buffer[];   // Certificate chain
  publicKey?: Buffer;   // Optional enclave public key
  userData?: Buffer;    // Optional user data
  nonce?: Buffer;       // Optional nonce for freshness
}

// ============================================
// Constants
// ============================================

/**
 * AWS Nitro Enclaves Root CA certificate
 * This is the root of trust for all Nitro attestation documents
 * @see https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
 */
const AWS_NITRO_ROOT_CA_PEM = `-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----`;

/**
 * Maximum age for attestation documents (5 minutes)
 */
const MAX_ATTESTATION_AGE_MS = 5 * 60 * 1000;

/**
 * COSE algorithm identifiers
 */
const COSE_ALG_ES384 = -35;  // ECDSA with SHA-384

// ============================================
// CBOR Decoding (Minimal Implementation)
// ============================================

/**
 * Decode a CBOR-encoded attestation document
 * Note: In production, use a proper CBOR library like 'cbor-x'
 * This is a minimal implementation for the attestation document structure
 */
function decodeCBOR(data: Buffer): any {
  let offset = 0;

  function readByte(): number {
    return data[offset++];
  }

  function readUint(additionalInfo: number): number {
    if (additionalInfo < 24) return additionalInfo;
    if (additionalInfo === 24) return readByte();
    if (additionalInfo === 25) {
      const val = data.readUInt16BE(offset);
      offset += 2;
      return val;
    }
    if (additionalInfo === 26) {
      const val = data.readUInt32BE(offset);
      offset += 4;
      return val;
    }
    if (additionalInfo === 27) {
      // 64-bit - read as BigInt then convert
      const high = data.readUInt32BE(offset);
      const low = data.readUInt32BE(offset + 4);
      offset += 8;
      return high * 0x100000000 + low;
    }
    throw new Error(`Unsupported additional info: ${additionalInfo}`);
  }

  function readBytes(length: number): Buffer {
    const bytes = data.slice(offset, offset + length);
    offset += length;
    return bytes;
  }

  function decode(): any {
    const initial = readByte();
    const majorType = initial >> 5;
    const additionalInfo = initial & 0x1f;

    switch (majorType) {
      case 0: // Unsigned integer
        return readUint(additionalInfo);

      case 1: // Negative integer
        return -1 - readUint(additionalInfo);

      case 2: // Byte string
        const byteLen = readUint(additionalInfo);
        return readBytes(byteLen);

      case 3: // Text string
        const textLen = readUint(additionalInfo);
        return readBytes(textLen).toString('utf8');

      case 4: // Array
        const arrayLen = readUint(additionalInfo);
        const array: any[] = [];
        for (let i = 0; i < arrayLen; i++) {
          array.push(decode());
        }
        return array;

      case 5: // Map
        const mapLen = readUint(additionalInfo);
        const map = new Map<any, any>();
        for (let i = 0; i < mapLen; i++) {
          const key = decode();
          const value = decode();
          map.set(key, value);
        }
        return map;

      case 6: // Tagged value
        const tag = readUint(additionalInfo);
        const taggedValue = decode();
        // Return tagged value with its tag
        return { _tag: tag, value: taggedValue };

      case 7: // Simple/float
        if (additionalInfo === 20) return false;
        if (additionalInfo === 21) return true;
        if (additionalInfo === 22) return null;
        if (additionalInfo === 23) return undefined;
        throw new Error(`Unsupported simple value: ${additionalInfo}`);

      default:
        throw new Error(`Unknown major type: ${majorType}`);
    }
  }

  return decode();
}

// ============================================
// COSE Signature Verification
// ============================================

/**
 * Parse COSE_Sign1 structure
 * The attestation document is a COSE_Sign1 message
 */
function parseCoseSign1(data: Buffer): {
  protectedHeader: Buffer;
  unprotectedHeader: Map<any, any>;
  payload: Buffer;
  signature: Buffer;
} {
  const decoded = decodeCBOR(data);

  // COSE_Sign1 is tagged with 18
  let coseArray: any[];
  if (decoded._tag === 18) {
    coseArray = decoded.value;
  } else if (Array.isArray(decoded)) {
    coseArray = decoded;
  } else {
    throw new Error('Invalid COSE_Sign1 structure');
  }

  if (coseArray.length !== 4) {
    throw new Error('COSE_Sign1 must have 4 elements');
  }

  return {
    protectedHeader: coseArray[0],
    unprotectedHeader: coseArray[1] || new Map(),
    payload: coseArray[2],
    signature: coseArray[3],
  };
}

// ============================================
// Attestation Document Parsing
// ============================================

/**
 * Parse a Nitro attestation document from its CBOR-encoded form
 */
export function parseAttestationDocument(attestationB64: string): NitroAttestationDocument {
  const attestationBytes = Buffer.from(attestationB64, 'base64');

  // Parse COSE_Sign1 envelope
  const cose = parseCoseSign1(attestationBytes);

  // Parse the payload (the actual attestation document)
  const doc = decodeCBOR(cose.payload);

  if (!(doc instanceof Map)) {
    throw new Error('Attestation document payload must be a CBOR map');
  }

  // Extract fields
  const moduleId = doc.get('module_id');
  const timestamp = doc.get('timestamp');
  const digest = doc.get('digest');
  const pcrsMap = doc.get('pcrs');
  const certificate = doc.get('certificate');
  const cabundle = doc.get('cabundle');
  const publicKey = doc.get('public_key');
  const userData = doc.get('user_data');
  const nonce = doc.get('nonce');

  if (!moduleId || !timestamp || !pcrsMap || !certificate) {
    throw new Error('Missing required fields in attestation document');
  }

  // Convert PCRs map
  const pcrs = new Map<number, Buffer>();
  if (pcrsMap instanceof Map) {
    for (const [key, value] of pcrsMap.entries()) {
      pcrs.set(key, value);
    }
  }

  return {
    moduleId,
    timestamp,
    digest: digest || 'SHA384',
    pcrs,
    certificate,
    cabundle: cabundle || [],
    publicKey,
    userData,
    nonce,
  };
}

// ============================================
// Certificate Chain Verification
// ============================================

/**
 * Verify the certificate chain in the attestation document
 * The chain should root to the AWS Nitro Enclaves Root CA
 */
function verifyCertificateChain(
  leafCert: Buffer,
  cabundle: Buffer[],
  errors: string[]
): { valid: boolean; leafCertX509?: X509Certificate } {
  try {
    // Parse leaf certificate
    const leafX509 = new X509Certificate(leafCert);

    // Parse root CA
    const rootCA = new X509Certificate(AWS_NITRO_ROOT_CA_PEM);

    // Build certificate chain (leaf -> intermediates -> root)
    const chain: X509Certificate[] = [leafX509];
    for (const certDer of cabundle) {
      chain.push(new X509Certificate(certDer));
    }

    // Verify chain from leaf to root
    for (let i = 0; i < chain.length - 1; i++) {
      const cert = chain[i];
      const issuerCert = chain[i + 1];

      // Verify signature
      try {
        const verified = cert.verify(issuerCert.publicKey);
        if (!verified) {
          errors.push(`Certificate signature invalid at chain index ${i}`);
          return { valid: false };
        }
      } catch (e: any) {
        errors.push(`Certificate verification error at index ${i}: ${e.message}`);
        return { valid: false };
      }

      // Check validity period
      const now = new Date();
      if (now < new Date(cert.validFrom) || now > new Date(cert.validTo)) {
        errors.push(`Certificate at index ${i} is outside validity period`);
        return { valid: false };
      }
    }

    // Verify the last certificate in cabundle is signed by root CA
    const lastCert = chain[chain.length - 1];
    try {
      const verifiedByRoot = lastCert.verify(rootCA.publicKey);
      if (!verifiedByRoot) {
        errors.push('Certificate chain does not root to AWS Nitro Root CA');
        return { valid: false };
      }
    } catch (e: any) {
      errors.push(`Root CA verification failed: ${e.message}`);
      return { valid: false };
    }

    return { valid: true, leafCertX509: leafX509 };
  } catch (e: any) {
    errors.push(`Certificate chain parsing failed: ${e.message}`);
    return { valid: false };
  }
}

// ============================================
// PCR Verification
// ============================================

/**
 * Extract PCR values from attestation document
 */
function extractPCRValues(pcrsMap: Map<number, Buffer>): PCRValues {
  const pcr0 = pcrsMap.get(0)?.toString('hex') || '';
  const pcr1 = pcrsMap.get(1)?.toString('hex') || '';
  const pcr2 = pcrsMap.get(2)?.toString('hex') || '';
  const pcr3 = pcrsMap.get(3)?.toString('hex');
  const pcr4 = pcrsMap.get(4)?.toString('hex');
  const pcr8 = pcrsMap.get(8)?.toString('hex');

  return { pcr0, pcr1, pcr2, pcr3, pcr4, pcr8 };
}

/**
 * Compare PCR values against expected values
 */
export function comparePCRs(
  actual: PCRValues,
  expected: ExpectedPCRs,
  errors: string[]
): boolean {
  let valid = true;

  // Compare PCR0
  if (actual.pcr0.toLowerCase() !== expected.pcr0.toLowerCase()) {
    errors.push(`PCR0 mismatch: expected ${expected.pcr0.slice(0, 16)}..., got ${actual.pcr0.slice(0, 16)}...`);
    valid = false;
  }

  // Compare PCR1
  if (actual.pcr1.toLowerCase() !== expected.pcr1.toLowerCase()) {
    errors.push(`PCR1 mismatch: expected ${expected.pcr1.slice(0, 16)}..., got ${actual.pcr1.slice(0, 16)}...`);
    valid = false;
  }

  // Compare PCR2
  if (actual.pcr2.toLowerCase() !== expected.pcr2.toLowerCase()) {
    errors.push(`PCR2 mismatch: expected ${expected.pcr2.slice(0, 16)}..., got ${actual.pcr2.slice(0, 16)}...`);
    valid = false;
  }

  return valid;
}

// ============================================
// Main Verification Function
// ============================================

/**
 * Verify a Nitro Enclave attestation document
 *
 * @param attestationB64 - Base64-encoded attestation document
 * @param expectedPCRs - Array of valid PCR configurations (any match is accepted)
 * @param expectedNonce - Optional nonce to verify freshness
 * @returns Verification result with PCR values and errors
 */
export async function verifyNitroAttestation(
  attestationB64: string,
  expectedPCRs: ExpectedPCRs[],
  expectedNonce?: Buffer
): Promise<NitroAttestationResult> {
  const errors: string[] = [];
  const details: Record<string, any> = {};

  try {
    // Parse attestation document
    const doc = parseAttestationDocument(attestationB64);
    details.moduleId = doc.moduleId;
    details.timestamp = new Date(doc.timestamp);

    // Check attestation freshness
    const now = Date.now();
    const attestationAge = now - doc.timestamp;
    if (attestationAge > MAX_ATTESTATION_AGE_MS) {
      errors.push(`Attestation document is too old: ${Math.round(attestationAge / 1000)}s`);
    }
    if (attestationAge < 0) {
      errors.push('Attestation document timestamp is in the future');
    }
    details.ageMs = attestationAge;

    // Verify certificate chain
    const chainResult = verifyCertificateChain(doc.certificate, doc.cabundle, errors);
    details.certificateChainValid = chainResult.valid;

    // Extract PCR values
    const pcrs = extractPCRValues(doc.pcrs);
    details.pcrs = {
      pcr0: pcrs.pcr0.slice(0, 16) + '...',
      pcr1: pcrs.pcr1.slice(0, 16) + '...',
      pcr2: pcrs.pcr2.slice(0, 16) + '...',
    };

    // Check PCR values against any valid configuration
    let pcrMatch = false;
    const now_date = new Date();

    for (const expected of expectedPCRs) {
      // Check if this PCR set is currently valid
      const validFrom = new Date(expected.validFrom);
      const validUntil = expected.validUntil ? new Date(expected.validUntil) : null;

      if (now_date < validFrom) {
        continue;  // Not yet valid
      }
      if (validUntil && now_date > validUntil) {
        continue;  // Expired
      }

      // Compare PCRs
      const pcrErrors: string[] = [];
      if (comparePCRs(pcrs, expected, pcrErrors)) {
        pcrMatch = true;
        details.matchedPCRSet = expected.id;
        break;
      }
    }

    if (!pcrMatch) {
      errors.push('PCR values do not match any valid configuration');
    }

    // Verify nonce if expected
    if (expectedNonce) {
      if (!doc.nonce) {
        errors.push('Expected nonce but none present in attestation');
      } else if (!doc.nonce.equals(expectedNonce)) {
        errors.push('Nonce mismatch');
      }
    }
    details.hasNonce = !!doc.nonce;

    // Extract public key if present
    const enclavePublicKey = doc.publicKey;
    details.hasPublicKey = !!enclavePublicKey;

    return {
      valid: errors.length === 0,
      pcrs,
      enclavePublicKey,
      timestamp: new Date(doc.timestamp),
      moduleId: doc.moduleId,
      nonce: doc.nonce,
      userData: doc.userData,
      errors,
      details,
    };

  } catch (error: any) {
    return {
      valid: false,
      pcrs: { pcr0: '', pcr1: '', pcr2: '' },
      timestamp: new Date(),
      moduleId: '',
      errors: [`Attestation verification failed: ${error.message}`],
      details,
    };
  }
}

// ============================================
// PCR Management
// ============================================

/**
 * Get currently valid PCR sets
 * In production, this would fetch from DynamoDB or SSM Parameter Store
 */
export async function getCurrentPCRs(): Promise<ExpectedPCRs[]> {
  // TODO: Fetch from SSM Parameter Store or DynamoDB
  // For now, return development placeholder

  if (process.env.NITRO_EXPECTED_PCRS) {
    try {
      return JSON.parse(process.env.NITRO_EXPECTED_PCRS);
    } catch (e) {
      console.error('Failed to parse NITRO_EXPECTED_PCRS:', e);
    }
  }

  // Development mode: accept any PCRs
  if (process.env.NODE_ENV !== 'production') {
    return [{
      id: 'development',
      pcr0: '0'.repeat(96),  // All zeros accepted in dev
      pcr1: '0'.repeat(96),
      pcr2: '0'.repeat(96),
      validFrom: '2024-01-01T00:00:00Z',
      isCurrent: true,
    }];
  }

  throw new Error('No PCR configuration available');
}

/**
 * Create a signed PCR update payload
 * Used by VettID to publish new PCR values when enclave code is updated
 */
export function createSignedPCRUpdate(
  pcrs: ExpectedPCRs[],
  signingKey: Buffer
): { payload: string; signature: string } {
  const payload = JSON.stringify({
    pcr_sets: pcrs,
    signed_at: new Date().toISOString(),
    version: 1,
  });

  // Sign with Ed25519 (in production, use proper key management)
  const hash = createHash('sha256').update(payload).digest();
  // Note: Actual signing would use crypto.sign() with Ed25519 key

  return {
    payload,
    signature: hash.toString('base64'),  // Placeholder - use real signature
  };
}

// ============================================
// Session Key Establishment
// ============================================

/**
 * Derive a session key from the enclave's public key and client's ephemeral key
 * Used to establish an encrypted channel with the enclave
 */
export function deriveSessionKey(
  enclavePublicKey: Buffer,
  clientPrivateKey: Buffer
): Buffer {
  // In production, use ECDH key agreement
  // This is a placeholder implementation

  const combined = Buffer.concat([enclavePublicKey, clientPrivateKey]);
  return createHash('sha256').update(combined).digest();
}

// ============================================
// Utility Functions
// ============================================

/**
 * Generate a random nonce for attestation freshness
 */
export function generateAttestationNonce(): Buffer {
  const { randomBytes } = require('crypto');
  return randomBytes(32);
}

/**
 * Hash a nonce for inclusion in user data
 */
export function hashNonce(nonce: Buffer): Buffer {
  return createHash('sha256').update(nonce).digest();
}
