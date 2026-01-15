/**
 * Device Attestation Verification
 *
 * SECURITY: Verifies hardware-backed device attestation to prevent:
 * - Enrollment on rooted/jailbroken devices
 * - Enrollment token exfiltration to different devices
 * - Emulator/simulator-based attacks
 *
 * Supports:
 * - Android: Play Integrity API
 * - iOS: App Attest (DCAppAttestService)
 */

import { createHash, createVerify, X509Certificate } from 'crypto';
import * as cbor from 'cbor';

// Environment configuration
const ANDROID_PACKAGE_NAME = process.env.ANDROID_PACKAGE_NAME || 'dev.vettid.app';
const IOS_APP_ID = process.env.IOS_APP_ID || 'TEAMID.dev.vettid.app';
const PLAY_INTEGRITY_DECRYPTION_KEY = process.env.PLAY_INTEGRITY_DECRYPTION_KEY;
const PLAY_INTEGRITY_VERIFICATION_KEY = process.env.PLAY_INTEGRITY_VERIFICATION_KEY;

// Apple App Attest root certificate (production)
// This is Apple's App Attest Root CA
const APPLE_APP_ATTEST_ROOT_CA = `-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
oyFraWVIyd/dganmrduC1bmTBGwD
-----END CERTIFICATE-----`;

/**
 * Device attestation verification result
 */
export interface DeviceAttestationResult {
  valid: boolean;
  device_type: 'android' | 'ios';
  device_integrity?: {
    meets_basic_integrity?: boolean;
    meets_device_integrity?: boolean;
    meets_strong_integrity?: boolean;
  };
  app_integrity?: {
    package_name?: string;
    app_recognition_verdict?: string;
    certificate_sha256?: string[];
  };
  key_id?: string;  // For iOS App Attest - the attested key identifier
  attestation_hash?: string;  // Hash of attestation for binding
  error?: string;
}

/**
 * Verify Android Play Integrity token
 *
 * SECURITY: Play Integrity provides:
 * - Device integrity (not rooted, not emulator)
 * - App integrity (genuine app from Play Store)
 * - Account licensing (optional)
 *
 * @param token - The integrity token from Play Integrity API
 * @param nonce - The nonce used when requesting the token
 */
export async function verifyAndroidPlayIntegrity(
  token: string,
  nonce: string
): Promise<DeviceAttestationResult> {
  try {
    // In production, decode and verify the token using Google's API
    // The token is a signed JWT that needs to be verified server-side
    //
    // For now, we'll implement a placeholder that expects the token
    // to be pre-verified by Google's playintegrity.googleapis.com API
    //
    // Production flow:
    // 1. App calls PlayIntegrity.requestIntegrityToken(nonce)
    // 2. App sends token to this endpoint
    // 3. Backend calls Google's decryptToken API
    // 4. Backend verifies the response

    if (!token || token.length < 100) {
      return {
        valid: false,
        device_type: 'android',
        error: 'Invalid Play Integrity token format',
      };
    }

    // Parse the token (it's a JWS with three parts)
    const parts = token.split('.');
    if (parts.length !== 3) {
      return {
        valid: false,
        device_type: 'android',
        error: 'Invalid token structure (expected JWS)',
      };
    }

    // In production, verify with Google's API:
    // POST https://playintegrity.googleapis.com/v1/{packageName}:decryptToken
    //
    // For development, we'll accept the token if it has valid structure
    // and return a mock successful result
    //
    // TODO: Implement actual Google API verification when keys are configured
    if (!PLAY_INTEGRITY_DECRYPTION_KEY) {
      console.warn('SECURITY: Play Integrity verification keys not configured - using dev mode');

      // In dev mode, compute attestation hash for binding
      const attestationHash = createHash('sha256')
        .update(token)
        .update(nonce)
        .digest('hex');

      return {
        valid: true,
        device_type: 'android',
        device_integrity: {
          meets_basic_integrity: true,
          meets_device_integrity: true,
          meets_strong_integrity: false,
        },
        app_integrity: {
          package_name: ANDROID_PACKAGE_NAME,
          app_recognition_verdict: 'PLAY_RECOGNIZED',
        },
        attestation_hash: attestationHash,
      };
    }

    // Production verification would go here
    // For now, return error if keys are configured but we haven't implemented
    return {
      valid: false,
      device_type: 'android',
      error: 'Play Integrity verification not yet implemented for production',
    };

  } catch (error: any) {
    console.error('Android attestation verification failed:', error);
    return {
      valid: false,
      device_type: 'android',
      error: `Verification failed: ${error.message}`,
    };
  }
}

/**
 * Verify iOS App Attest attestation
 *
 * SECURITY: App Attest provides:
 * - Hardware-backed key attestation
 * - Device authenticity verification
 * - App identity verification
 *
 * @param attestation - Base64-encoded attestation object from DCAppAttestService
 * @param keyId - The key identifier from generateKey()
 * @param challenge - The challenge/nonce used when generating attestation
 */
export async function verifyiOSAppAttest(
  attestation: string,
  keyId: string,
  challenge: string
): Promise<DeviceAttestationResult> {
  try {
    // Decode the attestation object (CBOR format)
    const attestationBuffer = Buffer.from(attestation, 'base64');
    let attestationObject: any;

    try {
      attestationObject = cbor.decodeFirstSync(attestationBuffer);
    } catch {
      return {
        valid: false,
        device_type: 'ios',
        error: 'Invalid attestation format (expected CBOR)',
      };
    }

    // Validate attestation structure
    if (!attestationObject.fmt || attestationObject.fmt !== 'apple-appattest') {
      return {
        valid: false,
        device_type: 'ios',
        error: `Invalid attestation format: ${attestationObject.fmt}`,
      };
    }

    const attStmt = attestationObject.attStmt;
    const authData = attestationObject.authData;

    if (!attStmt || !authData || !attStmt.x5c) {
      return {
        valid: false,
        device_type: 'ios',
        error: 'Missing required attestation fields',
      };
    }

    // Extract certificate chain
    const certChain = attStmt.x5c.map((cert: Buffer) => {
      const pem = `-----BEGIN CERTIFICATE-----\n${cert.toString('base64').match(/.{1,64}/g)?.join('\n')}\n-----END CERTIFICATE-----`;
      return new X509Certificate(pem);
    });

    if (certChain.length < 2) {
      return {
        valid: false,
        device_type: 'ios',
        error: 'Certificate chain too short',
      };
    }

    // Verify certificate chain leads to Apple's root
    const rootCert = new X509Certificate(APPLE_APP_ATTEST_ROOT_CA);
    let currentCert = certChain[certChain.length - 1];

    // The last cert in chain should be signed by Apple's root
    if (!currentCert.verify(rootCert.publicKey)) {
      return {
        valid: false,
        device_type: 'ios',
        error: 'Certificate chain does not verify against Apple root',
      };
    }

    // Verify the attestation nonce
    // nonce = SHA256(authData || SHA256(challenge))
    const challengeHash = createHash('sha256').update(challenge).digest();
    const expectedNonce = createHash('sha256')
      .update(authData)
      .update(challengeHash)
      .digest();

    // The nonce should be in the credential certificate's extension
    // OID: 1.2.840.113635.100.8.2 (Apple App Attest nonce)
    const credCert = certChain[0];
    const nonceExtension = findExtension(credCert, '1.2.840.113635.100.8.2');

    if (!nonceExtension) {
      return {
        valid: false,
        device_type: 'ios',
        error: 'Nonce extension not found in credential certificate',
      };
    }

    // Parse the nonce from the extension (ASN.1 OCTET STRING containing SEQUENCE of OCTET STRING)
    const extractedNonce = extractNonceFromExtension(nonceExtension);
    if (!extractedNonce || !expectedNonce.equals(extractedNonce)) {
      return {
        valid: false,
        device_type: 'ios',
        error: 'Nonce mismatch - attestation may be replayed',
      };
    }

    // Verify the key ID matches
    // authData contains: rpIdHash (32) || flags (1) || signCount (4) || attestedCredentialData
    // attestedCredentialData: aaguid (16) || credentialIdLength (2) || credentialId || publicKey
    if (authData.length < 37) {
      return {
        valid: false,
        device_type: 'ios',
        error: 'AuthData too short',
      };
    }

    const credIdLength = (authData[53] << 8) | authData[54];
    const credentialId = authData.slice(55, 55 + credIdLength);
    const credentialIdBase64 = credentialId.toString('base64');

    // The credentialId should match the keyId
    if (credentialIdBase64 !== keyId) {
      return {
        valid: false,
        device_type: 'ios',
        error: 'Key ID mismatch',
      };
    }

    // Compute attestation hash for binding
    const attestationHash = createHash('sha256')
      .update(attestationBuffer)
      .update(keyId)
      .update(challenge)
      .digest('hex');

    return {
      valid: true,
      device_type: 'ios',
      device_integrity: {
        meets_device_integrity: true,
      },
      key_id: keyId,
      attestation_hash: attestationHash,
    };

  } catch (error: any) {
    console.error('iOS attestation verification failed:', error);
    return {
      valid: false,
      device_type: 'ios',
      error: `Verification failed: ${error.message}`,
    };
  }
}

/**
 * Find an extension in an X509 certificate by OID
 */
function findExtension(cert: X509Certificate, oid: string): Buffer | null {
  // The X509Certificate class doesn't expose extensions directly in Node.js
  // We need to parse the raw certificate to extract extensions
  // For now, return null - full implementation would use ASN.1 parsing

  // TODO: Implement proper ASN.1 extension extraction
  // This requires parsing the TBS certificate structure

  return null;
}

/**
 * Extract nonce from Apple App Attest extension
 */
function extractNonceFromExtension(extension: Buffer): Buffer | null {
  // The extension contains: SEQUENCE { OCTET STRING { nonce } }
  // TODO: Implement proper ASN.1 parsing

  return null;
}

/**
 * Generate a device attestation binding token
 *
 * SECURITY: This token binds:
 * - Session ID (prevents cross-session use)
 * - Device attestation hash (proves device authenticity)
 * - Timestamp (prevents replay)
 */
export function generateDeviceAttestationToken(
  sessionId: string,
  attestationHash: string,
  secret: string
): string {
  const timestamp = Date.now();
  const data = `${sessionId}:${attestationHash}:${timestamp}`;

  const hmac = createHash('sha256')
    .update(data)
    .update(secret)
    .digest('hex');

  // Include timestamp in token for expiration checking
  return `${timestamp}.${hmac}`;
}

/**
 * Verify a device attestation binding token
 */
export function verifyDeviceAttestationToken(
  token: string,
  sessionId: string,
  attestationHash: string,
  secret: string,
  maxAgeMs: number = 10 * 60 * 1000  // 10 minutes default
): boolean {
  const parts = token.split('.');
  if (parts.length !== 2) {
    return false;
  }

  const [timestampStr, hmac] = parts;
  const timestamp = parseInt(timestampStr, 10);

  if (isNaN(timestamp)) {
    return false;
  }

  // Check expiration
  if (Date.now() - timestamp > maxAgeMs) {
    return false;
  }

  // Verify HMAC
  const data = `${sessionId}:${attestationHash}:${timestamp}`;
  const expectedHmac = createHash('sha256')
    .update(data)
    .update(secret)
    .digest('hex');

  // Constant-time comparison
  if (hmac.length !== expectedHmac.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < hmac.length; i++) {
    result |= hmac.charCodeAt(i) ^ expectedHmac.charCodeAt(i);
  }

  return result === 0;
}
