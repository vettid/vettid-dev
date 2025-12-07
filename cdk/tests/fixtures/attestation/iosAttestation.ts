/**
 * Mock iOS App Attest Data
 *
 * This module provides test fixtures for iOS App Attest verification.
 * These are synthetic test objects - NOT for production use.
 *
 * iOS App Attest Structure:
 * - Attestation Object: CBOR-encoded with format "apple-appattest"
 * - Contains: authData (authenticator data) + attStmt (attestation statement)
 * - Certificate chain signed by Apple App Attestation CA
 *
 * @see https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server
 * @see https://www.w3.org/TR/webauthn/#sctn-attestation
 */

import * as crypto from 'crypto';

// ============================================
// Constants
// ============================================

/**
 * Apple App Attestation format identifier
 */
export const ATTESTATION_FORMAT = 'apple-appattest';

/**
 * AAGUID for Apple App Attest (16 bytes of zeros)
 */
export const APPLE_APP_ATTEST_AAGUID = Buffer.alloc(16, 0);

/**
 * Apple App Attestation Root CA OID
 */
export const APPLE_APP_ATTESTATION_ROOT_CA_OID = '1.2.840.113635.100.8.2';

/**
 * Environment types
 */
export enum AppAttestEnvironment {
  PRODUCTION = 'production',
  DEVELOPMENT = 'development',
}

// ============================================
// CBOR Encoding Helpers (Simplified)
// ============================================

/**
 * Simple CBOR encoder for attestation objects
 * In production, use a proper CBOR library like 'cbor' or 'cbor-x'
 */
class SimpleCBOR {
  /**
   * Encode a map to CBOR
   */
  static encodeMap(map: Map<string, unknown>): Buffer {
    const entries: Buffer[] = [];

    // CBOR map header
    const mapSize = map.size;
    let header: Buffer;

    if (mapSize < 24) {
      header = Buffer.from([0xa0 + mapSize]);
    } else if (mapSize < 256) {
      header = Buffer.from([0xb8, mapSize]);
    } else {
      header = Buffer.from([0xb9, (mapSize >> 8) & 0xff, mapSize & 0xff]);
    }

    entries.push(header);

    for (const [key, value] of map) {
      entries.push(this.encodeString(key));
      entries.push(this.encodeValue(value));
    }

    return Buffer.concat(entries);
  }

  /**
   * Encode a string to CBOR
   */
  static encodeString(str: string): Buffer {
    const utf8 = Buffer.from(str, 'utf8');
    const len = utf8.length;

    let header: Buffer;
    if (len < 24) {
      header = Buffer.from([0x60 + len]);
    } else if (len < 256) {
      header = Buffer.from([0x78, len]);
    } else {
      header = Buffer.from([0x79, (len >> 8) & 0xff, len & 0xff]);
    }

    return Buffer.concat([header, utf8]);
  }

  /**
   * Encode bytes to CBOR
   */
  static encodeBytes(bytes: Buffer): Buffer {
    const len = bytes.length;

    let header: Buffer;
    if (len < 24) {
      header = Buffer.from([0x40 + len]);
    } else if (len < 256) {
      header = Buffer.from([0x58, len]);
    } else {
      header = Buffer.from([0x59, (len >> 8) & 0xff, len & 0xff]);
    }

    return Buffer.concat([header, bytes]);
  }

  /**
   * Encode any value to CBOR
   */
  static encodeValue(value: unknown): Buffer {
    if (Buffer.isBuffer(value)) {
      return this.encodeBytes(value);
    }
    if (typeof value === 'string') {
      return this.encodeString(value);
    }
    if (Array.isArray(value)) {
      return this.encodeArray(value);
    }
    if (value instanceof Map) {
      return this.encodeMap(value);
    }
    if (typeof value === 'object' && value !== null) {
      const map = new Map(Object.entries(value));
      return this.encodeMap(map);
    }
    if (typeof value === 'number') {
      return this.encodeNumber(value);
    }
    // Default: encode as empty
    return Buffer.from([0xf6]); // null
  }

  /**
   * Encode array to CBOR
   */
  static encodeArray(arr: unknown[]): Buffer {
    const entries: Buffer[] = [];
    const len = arr.length;

    let header: Buffer;
    if (len < 24) {
      header = Buffer.from([0x80 + len]);
    } else if (len < 256) {
      header = Buffer.from([0x98, len]);
    } else {
      header = Buffer.from([0x99, (len >> 8) & 0xff, len & 0xff]);
    }

    entries.push(header);
    for (const item of arr) {
      entries.push(this.encodeValue(item));
    }

    return Buffer.concat(entries);
  }

  /**
   * Encode number to CBOR
   */
  static encodeNumber(num: number): Buffer {
    if (num >= 0 && num < 24) {
      return Buffer.from([num]);
    }
    if (num >= 0 && num < 256) {
      return Buffer.from([0x18, num]);
    }
    if (num >= 0 && num < 65536) {
      return Buffer.from([0x19, (num >> 8) & 0xff, num & 0xff]);
    }
    // For larger numbers, use 4-byte encoding
    return Buffer.from([
      0x1a,
      (num >> 24) & 0xff,
      (num >> 16) & 0xff,
      (num >> 8) & 0xff,
      num & 0xff,
    ]);
  }
}

// ============================================
// Attestation Object Structure
// ============================================

/**
 * Authenticator data structure
 * @see https://www.w3.org/TR/webauthn/#authenticator-data
 */
export interface AuthenticatorData {
  rpIdHash: Buffer;     // 32 bytes - SHA256 of App ID
  flags: number;        // 1 byte - AT flag (0x40) for attestation
  signCount: number;    // 4 bytes - Signature counter
  aaguid: Buffer;       // 16 bytes - All zeros for Apple
  credentialId: Buffer; // Variable - The key identifier
  publicKey: Buffer;    // Variable - COSE-encoded public key
}

/**
 * Attestation statement for apple-appattest format
 */
export interface AttestationStatement {
  x5c: Buffer[];  // Certificate chain
  receipt: Buffer; // App Attest receipt
}

/**
 * Complete attestation object
 */
export interface AttestationObject {
  fmt: string;
  authData: Buffer;
  attStmt: AttestationStatement;
}

// ============================================
// Mock Certificate Data
// ============================================

/**
 * Mock Apple App Attestation Root CA
 */
export const MOCK_APPLE_ROOT_CA = {
  subject: 'CN=Apple App Attestation Root CA, O=Apple Inc.',
  issuer: 'CN=Apple App Attestation Root CA, O=Apple Inc.',
  serialNumber: '01',
  notBefore: new Date('2020-03-18T00:00:00Z'),
  notAfter: new Date('2045-03-15T00:00:00Z'),
  der: Buffer.from([
    0x30, 0x82, 0x02, 0x5a,
    0x30, 0x82, 0x01, 0x42,
    0xa0, 0x03, 0x02, 0x01, 0x02,
    0x02, 0x01, 0x01,
  ]),
};

/**
 * Mock Apple App Attestation CA 1
 */
export const MOCK_APPLE_INTERMEDIATE_CA = {
  subject: 'CN=Apple App Attestation CA 1, O=Apple Inc.',
  issuer: 'CN=Apple App Attestation Root CA, O=Apple Inc.',
  serialNumber: '02',
  notBefore: new Date('2020-03-18T00:00:00Z'),
  notAfter: new Date('2030-03-15T00:00:00Z'),
  der: Buffer.from([
    0x30, 0x82, 0x02, 0x8a,
    0x30, 0x82, 0x01, 0x72,
    0xa0, 0x03, 0x02, 0x01, 0x02,
    0x02, 0x01, 0x02,
  ]),
};

// ============================================
// Mock Attestation Generator
// ============================================

export interface MockiOSAttestationOptions {
  challenge: Buffer;
  appId: string;
  environment: AppAttestEnvironment;
  keyId?: string;
  counter?: number;
}

/**
 * Generates mock iOS App Attest attestation object for testing
 */
export function generateMockiOSAttestation(options: MockiOSAttestationOptions): {
  attestationObject: Buffer;
  keyId: string;
  challenge: Buffer;
  decoded: AttestationObject;
} {
  const {
    challenge,
    appId,
    environment,
    keyId = crypto.randomBytes(32).toString('base64url'),
    counter = 0,
  } = options;

  // Generate mock key pair
  const { publicKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
  });

  // Create authenticator data
  const authData = createAuthenticatorData({
    appId,
    keyId: Buffer.from(keyId, 'base64url'),
    publicKey: publicKey.export({ type: 'spki', format: 'der' }),
    counter,
  });

  // Create mock certificate chain
  const leafCert = createMockLeafCertificate(keyId, appId, environment);
  const certChain = [leafCert, MOCK_APPLE_INTERMEDIATE_CA.der, MOCK_APPLE_ROOT_CA.der];

  // Create attestation statement
  const attStmt: AttestationStatement = {
    x5c: certChain,
    receipt: createMockReceipt(appId, environment),
  };

  // Create attestation object
  const attestationObj: AttestationObject = {
    fmt: ATTESTATION_FORMAT,
    authData,
    attStmt,
  };

  // Encode to CBOR
  const attestationObject = encodeAttestationObject(attestationObj);

  return {
    attestationObject,
    keyId,
    challenge,
    decoded: attestationObj,
  };
}

/**
 * Creates authenticator data structure
 */
function createAuthenticatorData(options: {
  appId: string;
  keyId: Buffer;
  publicKey: Buffer;
  counter: number;
}): Buffer {
  const { appId, keyId, publicKey, counter } = options;

  // RP ID Hash (SHA256 of App ID)
  const rpIdHash = crypto.createHash('sha256').update(appId).digest();

  // Flags: AT (0x40) - Attestation data present
  const flags = 0x41; // UP (0x01) + AT (0x40)

  // Sign count (4 bytes, big-endian)
  const signCount = Buffer.alloc(4);
  signCount.writeUInt32BE(counter, 0);

  // Credential ID length (2 bytes, big-endian)
  const credIdLen = Buffer.alloc(2);
  credIdLen.writeUInt16BE(keyId.length, 0);

  // COSE key (simplified - just include raw public key)
  const coseKey = createCOSEKey(publicKey);

  return Buffer.concat([
    rpIdHash,           // 32 bytes
    Buffer.from([flags]), // 1 byte
    signCount,          // 4 bytes
    APPLE_APP_ATTEST_AAGUID, // 16 bytes
    credIdLen,          // 2 bytes
    keyId,              // Variable
    coseKey,            // Variable
  ]);
}

/**
 * Creates a COSE-encoded public key (simplified)
 */
function createCOSEKey(publicKey: Buffer): Buffer {
  // This is a simplified COSE key encoding
  // Real implementation would parse SPKI and create proper COSE structure
  const coseMap = new Map<number, unknown>();
  coseMap.set(1, 2);  // kty: EC2
  coseMap.set(3, -7); // alg: ES256
  coseMap.set(-1, 1); // crv: P-256
  coseMap.set(-2, publicKey.slice(-64, -32)); // x coordinate
  coseMap.set(-3, publicKey.slice(-32));      // y coordinate

  // Simplified encoding
  return Buffer.concat([
    Buffer.from([0xa5]), // Map with 5 entries
    Buffer.from([0x01, 0x02]), // kty: EC2
    Buffer.from([0x03, 0x26]), // alg: ES256 (-7)
    Buffer.from([0x20, 0x01]), // crv: P-256
    Buffer.from([0x21, 0x58, 0x20]), publicKey.slice(-64, -32), // x
    Buffer.from([0x22, 0x58, 0x20]), publicKey.slice(-32),      // y
  ]);
}

/**
 * Creates a mock leaf certificate
 */
function createMockLeafCertificate(
  keyId: string,
  appId: string,
  environment: AppAttestEnvironment
): Buffer {
  // Mock certificate with key ID extension
  const envByte = environment === AppAttestEnvironment.PRODUCTION ? 0x01 : 0x00;

  return Buffer.concat([
    Buffer.from([0x30, 0x82, 0x03, 0x00]), // SEQUENCE
    Buffer.from([0x30, 0x82, 0x02, 0x00]), // tbsCertificate
    // Version v3
    Buffer.from([0xa0, 0x03, 0x02, 0x01, 0x02]),
    // Serial number
    Buffer.from([0x02, 0x10]),
    crypto.randomBytes(16),
    // Key ID in extension
    Buffer.from([0xa3, 0x20]),
    Buffer.from(keyId, 'base64url'),
    // App ID
    Buffer.from(appId),
    // Environment
    Buffer.from([envByte]),
  ]);
}

/**
 * Creates a mock receipt
 */
function createMockReceipt(appId: string, environment: AppAttestEnvironment): Buffer {
  // Mock receipt structure
  return Buffer.concat([
    Buffer.from([0x30, 0x82, 0x01, 0x00]), // SEQUENCE
    Buffer.from(appId),
    Buffer.from([environment === AppAttestEnvironment.PRODUCTION ? 0x01 : 0x00]),
    crypto.randomBytes(32), // Nonce
    Buffer.from(new Date().toISOString()), // Timestamp
  ]);
}

/**
 * Encodes attestation object to CBOR
 */
function encodeAttestationObject(obj: AttestationObject): Buffer {
  const map = new Map<string, unknown>();
  map.set('fmt', obj.fmt);
  map.set('authData', obj.authData);
  map.set('attStmt', {
    x5c: obj.attStmt.x5c,
    receipt: obj.attStmt.receipt,
  });

  return SimpleCBOR.encodeMap(map);
}

// ============================================
// Test Helpers
// ============================================

/**
 * Creates a valid production attestation
 */
export function createProductionAttestation(
  challenge: Buffer,
  appId: string = 'TEAMID.com.vettid.app'
): ReturnType<typeof generateMockiOSAttestation> {
  return generateMockiOSAttestation({
    challenge,
    appId,
    environment: AppAttestEnvironment.PRODUCTION,
  });
}

/**
 * Creates a valid development attestation
 */
export function createDevelopmentAttestation(
  challenge: Buffer,
  appId: string = 'TEAMID.com.vettid.app'
): ReturnType<typeof generateMockiOSAttestation> {
  return generateMockiOSAttestation({
    challenge,
    appId,
    environment: AppAttestEnvironment.DEVELOPMENT,
  });
}

/**
 * Creates an attestation with wrong app ID (should be rejected)
 */
export function createWrongAppIdAttestation(
  challenge: Buffer,
  wrongAppId: string = 'WRONGTEAM.com.other.app'
): ReturnType<typeof generateMockiOSAttestation> {
  return generateMockiOSAttestation({
    challenge,
    appId: wrongAppId,
    environment: AppAttestEnvironment.PRODUCTION,
  });
}

/**
 * Generates client data hash for attestation verification
 * clientDataHash = SHA256(challenge)
 */
export function createClientDataHash(challenge: Buffer): Buffer {
  return crypto.createHash('sha256').update(challenge).digest();
}

/**
 * Computes the nonce for attestation verification
 * nonce = SHA256(authData || clientDataHash)
 */
export function computeNonce(authData: Buffer, clientDataHash: Buffer): Buffer {
  return crypto.createHash('sha256')
    .update(authData)
    .update(clientDataHash)
    .digest();
}

// ============================================
// Assertion Helpers (for post-attestation verification)
// ============================================

export interface AssertionOptions {
  keyId: string;
  challenge: Buffer;
  appId: string;
  counter: number;
}

/**
 * Generates a mock assertion for testing
 */
export function generateMockAssertion(options: AssertionOptions): {
  assertion: Buffer;
  authenticatorData: Buffer;
  signature: Buffer;
} {
  const { keyId, challenge, appId, counter } = options;

  // Create authenticator data (without attestation data)
  const rpIdHash = crypto.createHash('sha256').update(appId).digest();
  const flags = 0x01; // UP only
  const signCount = Buffer.alloc(4);
  signCount.writeUInt32BE(counter, 0);

  const authenticatorData = Buffer.concat([rpIdHash, Buffer.from([flags]), signCount]);

  // Client data hash
  const clientDataHash = createClientDataHash(challenge);

  // Create signature (mock - would use actual key in real implementation)
  const signatureBase = Buffer.concat([authenticatorData, clientDataHash]);
  const signature = crypto.createHash('sha256').update(signatureBase).digest();

  // Encode assertion as CBOR
  const assertionMap = new Map<string, unknown>();
  assertionMap.set('signature', signature);
  assertionMap.set('authenticatorData', authenticatorData);

  return {
    assertion: SimpleCBOR.encodeMap(assertionMap),
    authenticatorData,
    signature,
  };
}

/**
 * Validates counter increment (prevents replay)
 */
export function validateCounter(previousCounter: number, newCounter: number): boolean {
  return newCounter > previousCounter;
}
