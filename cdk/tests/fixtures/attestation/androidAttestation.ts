/**
 * Mock Android Hardware Key Attestation Data
 *
 * This module provides test fixtures for Android Key Attestation verification.
 * These are synthetic test certificates - NOT for production use.
 *
 * Android Key Attestation Structure:
 * - Leaf certificate: Contains attestation extension (OID 1.3.6.1.4.1.11129.2.1.17)
 * - Intermediate certificate(s): Signed by Google
 * - Root certificate: Google Hardware Attestation Root
 *
 * @see https://developer.android.com/training/articles/security-key-attestation
 * @see https://source.android.com/security/keystore/attestation
 */

import * as crypto from 'crypto';

// ============================================
// ASN.1 Constants for Attestation Extension
// ============================================

/**
 * Android Key Attestation Extension OID
 * 1.3.6.1.4.1.11129.2.1.17
 */
export const ATTESTATION_EXTENSION_OID = '1.3.6.1.4.1.11129.2.1.17';

/**
 * Security levels as defined in attestation extension
 */
export enum AndroidSecurityLevel {
  SOFTWARE = 0,
  TRUSTED_ENVIRONMENT = 1,  // TEE
  STRONGBOX = 2,
}

/**
 * Attestation version constants
 */
export enum AttestationVersion {
  KEYMASTER_V1 = 1,
  KEYMASTER_V2 = 2,
  KEYMASTER_V3 = 3,
  KEYMASTER_V4 = 4,
  KEYMINT_V1 = 100,
  KEYMINT_V2 = 200,
  KEYMINT_V3 = 300,
}

// ============================================
// Mock Certificate Data
// ============================================

/**
 * Mock Google Hardware Attestation Root CA
 * This is a synthetic certificate for testing - NOT the real Google root
 */
export const MOCK_GOOGLE_ROOT_CA = {
  subject: 'CN=Google Hardware Attestation Root, O=Google LLC',
  issuer: 'CN=Google Hardware Attestation Root, O=Google LLC',
  serialNumber: '01',
  notBefore: new Date('2020-01-01T00:00:00Z'),
  notAfter: new Date('2050-01-01T00:00:00Z'),
  // DER-encoded mock certificate (truncated for testing)
  der: Buffer.from([
    0x30, 0x82, 0x02, 0x5a, // SEQUENCE, length
    0x30, 0x82, 0x01, 0x42, // tbsCertificate SEQUENCE
    0xa0, 0x03, 0x02, 0x01, 0x02, // version [0] INTEGER 2 (v3)
    0x02, 0x01, 0x01, // serialNumber INTEGER 1
    // ... additional ASN.1 structure would follow
  ]),
};

/**
 * Mock intermediate certificate
 */
export const MOCK_INTERMEDIATE_CA = {
  subject: 'CN=Google Hardware Attestation Intermediate, O=Google LLC',
  issuer: 'CN=Google Hardware Attestation Root, O=Google LLC',
  serialNumber: '02',
  notBefore: new Date('2020-01-01T00:00:00Z'),
  notAfter: new Date('2040-01-01T00:00:00Z'),
  der: Buffer.from([
    0x30, 0x82, 0x02, 0x8a, // SEQUENCE
    0x30, 0x82, 0x01, 0x72,
    0xa0, 0x03, 0x02, 0x01, 0x02,
    0x02, 0x01, 0x02,
  ]),
};

// ============================================
// Attestation Extension Structure
// ============================================

/**
 * Attestation extension data structure
 * @see https://source.android.com/security/keystore/attestation#schema
 */
export interface AttestationExtension {
  attestationVersion: AttestationVersion;
  attestationSecurityLevel: AndroidSecurityLevel;
  keymasterVersion: number;
  keymasterSecurityLevel: AndroidSecurityLevel;
  attestationChallenge: Buffer;
  uniqueId: Buffer;
  softwareEnforced: AuthorizationList;
  teeEnforced: AuthorizationList;
}

export interface AuthorizationList {
  purpose?: number[];
  algorithm?: number;
  keySize?: number;
  digest?: number[];
  padding?: number[];
  ecCurve?: number;
  rsaPublicExponent?: number;
  rollbackResistance?: boolean;
  activeDateTime?: Date;
  originationExpireDateTime?: Date;
  usageExpireDateTime?: Date;
  noAuthRequired?: boolean;
  userAuthType?: number;
  authTimeout?: number;
  allowWhileOnBody?: boolean;
  trustedUserPresenceRequired?: boolean;
  trustedConfirmationRequired?: boolean;
  unlockedDeviceRequired?: boolean;
  allApplications?: boolean;
  applicationId?: Buffer;
  creationDateTime?: Date;
  origin?: number;
  rootOfTrust?: RootOfTrust;
  osVersion?: number;
  osPatchLevel?: number;
  attestationApplicationId?: Buffer;
  attestationIdBrand?: Buffer;
  attestationIdDevice?: Buffer;
  attestationIdProduct?: Buffer;
  attestationIdSerial?: Buffer;
  attestationIdImei?: Buffer;
  attestationIdMeid?: Buffer;
  attestationIdManufacturer?: Buffer;
  attestationIdModel?: Buffer;
  vendorPatchLevel?: number;
  bootPatchLevel?: number;
  deviceUniqueAttestation?: boolean;
}

export interface RootOfTrust {
  verifiedBootKey: Buffer;
  deviceLocked: boolean;
  verifiedBootState: VerifiedBootState;
  verifiedBootHash?: Buffer;
}

export enum VerifiedBootState {
  VERIFIED = 0,
  SELF_SIGNED = 1,
  UNVERIFIED = 2,
  FAILED = 3,
}

// ============================================
// Mock Attestation Generator
// ============================================

export interface MockAttestationOptions {
  challenge: Buffer;
  securityLevel: AndroidSecurityLevel;
  verifiedBootState?: VerifiedBootState;
  deviceLocked?: boolean;
  osVersion?: number;
  osPatchLevel?: number;
  vendorPatchLevel?: number;
  bootPatchLevel?: number;
  applicationId?: string;
}

/**
 * Generates mock attestation certificate chain for testing
 */
export function generateMockAndroidAttestation(options: MockAttestationOptions): {
  certChain: Buffer[];
  extension: AttestationExtension;
  keyId: string;
} {
  const {
    challenge,
    securityLevel,
    verifiedBootState = VerifiedBootState.VERIFIED,
    deviceLocked = true,
    osVersion = 140000, // Android 14
    osPatchLevel = 202401, // January 2024
    vendorPatchLevel = 202401,
    bootPatchLevel = 202401,
    applicationId = 'com.vettid.app',
  } = options;

  // Create attestation extension
  const extension: AttestationExtension = {
    attestationVersion: AttestationVersion.KEYMINT_V3,
    attestationSecurityLevel: securityLevel,
    keymasterVersion: 300,
    keymasterSecurityLevel: securityLevel,
    attestationChallenge: challenge,
    uniqueId: Buffer.alloc(0),
    softwareEnforced: {
      creationDateTime: new Date(),
      attestationApplicationId: Buffer.from(applicationId),
    },
    teeEnforced: {
      purpose: [2, 3], // SIGN, VERIFY
      algorithm: 3, // EC
      keySize: 256,
      digest: [4], // SHA256
      ecCurve: 1, // P256
      noAuthRequired: false,
      origin: 0, // GENERATED
      rootOfTrust: {
        verifiedBootKey: crypto.randomBytes(32),
        deviceLocked,
        verifiedBootState,
        verifiedBootHash: crypto.randomBytes(32),
      },
      osVersion,
      osPatchLevel,
      vendorPatchLevel,
      bootPatchLevel,
    },
  };

  // Generate mock certificate chain (leaf, intermediate, root)
  const keyId = `android_${crypto.randomBytes(8).toString('hex')}`;

  // Create mock leaf certificate with attestation extension
  const leafCert = createMockLeafCertificate(extension, keyId);

  return {
    certChain: [leafCert, MOCK_INTERMEDIATE_CA.der, MOCK_GOOGLE_ROOT_CA.der],
    extension,
    keyId,
  };
}

/**
 * Creates a mock leaf certificate with attestation extension
 * This is a simplified mock - real certificates require proper X.509 encoding
 */
function createMockLeafCertificate(extension: AttestationExtension, keyId: string): Buffer {
  // In a real implementation, this would create a proper X.509 certificate
  // with the attestation extension. For testing, we create a mock structure.

  const extensionData = encodeAttestationExtension(extension);

  // Mock certificate structure
  const cert = Buffer.concat([
    Buffer.from([0x30, 0x82]), // SEQUENCE
    Buffer.from([0x03, 0x00]), // Length placeholder
    // tbsCertificate
    Buffer.from([0x30, 0x82, 0x02, 0x00]),
    // version v3
    Buffer.from([0xa0, 0x03, 0x02, 0x01, 0x02]),
    // serialNumber
    Buffer.from([0x02, 0x10]),
    crypto.randomBytes(16),
    // signature algorithm (ECDSA with SHA256)
    Buffer.from([0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]),
    // issuer
    Buffer.from([0x30, 0x40]),
    Buffer.from(MOCK_INTERMEDIATE_CA.subject),
    // validity
    Buffer.from([0x30, 0x1e]),
    // extensions including attestation
    extensionData,
  ]);

  return cert;
}

/**
 * Encodes attestation extension to ASN.1 DER format (simplified mock)
 */
function encodeAttestationExtension(extension: AttestationExtension): Buffer {
  // This is a simplified encoding for testing
  // Real implementation would use proper ASN.1 encoding

  const parts: Buffer[] = [
    // Extension OID
    Buffer.from([0x06, 0x0b, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x01, 0x11]),
    // Challenge
    Buffer.from([0x04]),
    Buffer.from([extension.attestationChallenge.length]),
    extension.attestationChallenge,
    // Security level
    Buffer.from([0x02, 0x01, extension.attestationSecurityLevel]),
  ];

  return Buffer.concat(parts);
}

// ============================================
// Test Helpers
// ============================================

/**
 * Creates a valid attestation for TEE security level
 */
export function createTEEAttestation(challenge: Buffer): ReturnType<typeof generateMockAndroidAttestation> {
  return generateMockAndroidAttestation({
    challenge,
    securityLevel: AndroidSecurityLevel.TRUSTED_ENVIRONMENT,
  });
}

/**
 * Creates a valid attestation for StrongBox security level
 */
export function createStrongBoxAttestation(challenge: Buffer): ReturnType<typeof generateMockAndroidAttestation> {
  return generateMockAndroidAttestation({
    challenge,
    securityLevel: AndroidSecurityLevel.STRONGBOX,
  });
}

/**
 * Creates an attestation with unlocked bootloader (should be rejected)
 */
export function createUnlockedBootloaderAttestation(challenge: Buffer): ReturnType<typeof generateMockAndroidAttestation> {
  return generateMockAndroidAttestation({
    challenge,
    securityLevel: AndroidSecurityLevel.TRUSTED_ENVIRONMENT,
    deviceLocked: false,
    verifiedBootState: VerifiedBootState.UNVERIFIED,
  });
}

/**
 * Creates an attestation with wrong challenge (should be rejected)
 */
export function createWrongChallengeAttestation(
  expectedChallenge: Buffer,
  wrongChallenge: Buffer
): ReturnType<typeof generateMockAndroidAttestation> {
  return generateMockAndroidAttestation({
    challenge: wrongChallenge,
    securityLevel: AndroidSecurityLevel.TRUSTED_ENVIRONMENT,
  });
}

/**
 * Validates an attestation certificate chain (mock implementation)
 */
export function validateMockCertChain(certChain: Buffer[]): {
  valid: boolean;
  securityLevel?: AndroidSecurityLevel;
  challenge?: Buffer;
  error?: string;
} {
  if (certChain.length < 3) {
    return { valid: false, error: 'Certificate chain too short' };
  }

  // In a real implementation, this would:
  // 1. Parse each certificate
  // 2. Verify signatures up the chain
  // 3. Check against known Google root CA
  // 4. Extract and parse attestation extension

  // For testing, we return a mock success
  return {
    valid: true,
    securityLevel: AndroidSecurityLevel.TRUSTED_ENVIRONMENT,
    challenge: Buffer.alloc(32), // Would be extracted from extension
  };
}

// ============================================
// GrapheneOS Support
// ============================================

/**
 * Mock GrapheneOS attestation root CA
 * GrapheneOS uses Auditor for hardware-backed attestation
 */
export const MOCK_GRAPHENEOS_ROOT_CA = {
  subject: 'CN=Auditor Root CA, O=GrapheneOS',
  issuer: 'CN=Auditor Root CA, O=GrapheneOS',
  serialNumber: '01',
  notBefore: new Date('2020-01-01T00:00:00Z'),
  notAfter: new Date('2050-01-01T00:00:00Z'),
  der: Buffer.from([0x30, 0x82, 0x02, 0x5a]),
};

/**
 * Creates a GrapheneOS attestation
 */
export function createGrapheneOSAttestation(challenge: Buffer): ReturnType<typeof generateMockAndroidAttestation> {
  const attestation = generateMockAndroidAttestation({
    challenge,
    securityLevel: AndroidSecurityLevel.TRUSTED_ENVIRONMENT,
    // GrapheneOS typically has verified boot with Auditor
    verifiedBootState: VerifiedBootState.VERIFIED,
    deviceLocked: true,
  });

  // Replace root with GrapheneOS root
  attestation.certChain[attestation.certChain.length - 1] = MOCK_GRAPHENEOS_ROOT_CA.der;

  return attestation;
}
