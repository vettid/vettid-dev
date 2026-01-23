/**
 * Verify Nitro Enclave Attestation
 *
 * POST /vault/attestation/nitro
 *
 * Verifies an AWS Nitro Enclave attestation document.
 * Returns the verified PCR values and enclave public key for session establishment.
 *
 * This endpoint is called by mobile apps during enrollment to verify
 * they are communicating with a genuine VettID Nitro Enclave.
 *
 * In the Nitro model, attestation happens BEFORE credential creation.
 * The app verifies the enclave's identity, then trusts it to create
 * and store the Protean Credential.
 */

import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import { createHmac } from 'crypto';
import {
  ok,
  badRequest,
  internalError,
  parseJsonBody,
  getRequestId,
  putAudit,
  checkRateLimit,
  hashIdentifier,
  tooManyRequests,
  getClientIp,
  extractUserClaims,
} from '../../common/util';
import {
  verifyNitroAttestation,
  getCurrentPCRs,
  NitroAttestationResult,
} from '../../common/nitro-attestation';

const ddb = new DynamoDBClient({});

const TABLE_ENROLLMENT_SESSIONS = process.env.TABLE_ENROLLMENT_SESSIONS!;
// SECURITY: Secret for generating attestation binding tokens - must be explicitly configured
// Generate with: export ATTESTATION_BINDING_SECRET=$(openssl rand -hex 32)
if (!process.env.ATTESTATION_BINDING_SECRET) {
  throw new Error('ATTESTATION_BINDING_SECRET environment variable is required');
}
const ATTESTATION_BINDING_SECRET = process.env.ATTESTATION_BINDING_SECRET;

// Rate limiting: 20 attestation verifications per IP per 5 minutes
const RATE_LIMIT_MAX_REQUESTS = 20;
const RATE_LIMIT_WINDOW_MINUTES = 5;

/**
 * Generate attestation binding token
 * SECURITY: This token proves the app's public key was verified during attestation.
 * The enclave can verify this token to prevent MITM attacks on key exchange.
 *
 * Token = HMAC-SHA256(session_id || app_public_key_hash || pcr_hash, secret)
 */
function generateBindingToken(
  sessionId: string,
  appPublicKeyHash: string,
  pcrHash: string
): string {
  const data = `${sessionId}:${appPublicKeyHash}:${pcrHash}`;
  const hmac = createHmac('sha256', ATTESTATION_BINDING_SECRET);
  hmac.update(data);
  return hmac.digest('hex');
}

interface VerifyAttestationRequest {
  attestation_document: string;  // Base64-encoded attestation document
  nonce?: string;                // Optional nonce (base64) for freshness verification
  session_id?: string;           // Optional session ID to bind attestation to
  // SECURITY: Attestation-bound key exchange fields
  app_public_key_hash?: string;  // SHA-256 hash of app's X25519 public key (hex)
}

interface VerifyAttestationResponse {
  valid: boolean;
  enclave_public_key?: string;   // Base64-encoded public key for session encryption
  pcr_version?: string;          // Which PCR set was matched
  module_id?: string;            // Enclave module identifier
  timestamp?: string;            // Attestation timestamp
  errors?: string[];             // Verification errors if invalid
  // SECURITY: Attestation-bound key exchange fields
  binding_token?: string;        // Token proving app's public key was bound to attestation
}

export const handler = async (
  event: APIGatewayProxyEventV2
): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);

  try {
    // Rate limiting by IP
    const clientIp = getClientIp(event);
    const rateLimitKey = `nitro-attest:${hashIdentifier(clientIp)}`;

    const allowed = await checkRateLimit(
      rateLimitKey,
      'nitro_attestation',
      RATE_LIMIT_MAX_REQUESTS,
      RATE_LIMIT_WINDOW_MINUTES
    );

    if (!allowed) {
      return tooManyRequests('Too many attestation requests. Please try again later.');
    }

    // Parse request
    let body: VerifyAttestationRequest;
    try {
      body = parseJsonBody<VerifyAttestationRequest>(event);
    } catch (e) {
      return badRequest('Invalid JSON body');
    }

    const { attestation_document, nonce, session_id, app_public_key_hash } = body;

    if (!attestation_document) {
      return badRequest('attestation_document is required');
    }

    // SECURITY: Validate app_public_key_hash format if provided
    // Must be 64 hex characters (SHA-256 = 32 bytes = 64 hex chars)
    if (app_public_key_hash) {
      if (!/^[a-fA-F0-9]{64}$/.test(app_public_key_hash)) {
        return badRequest('app_public_key_hash must be 64 hex characters (SHA-256)');
      }
    }

    // Validate attestation document format
    let attestationBuffer: Buffer;
    try {
      attestationBuffer = Buffer.from(attestation_document, 'base64');
      if (attestationBuffer.length < 100) {
        return badRequest('attestation_document is too short');
      }
      if (attestationBuffer.length > 100000) {
        return badRequest('attestation_document is too large');
      }
    } catch (e) {
      return badRequest('attestation_document must be valid base64');
    }

    // Parse optional nonce
    let expectedNonce: Buffer | undefined;
    if (nonce) {
      try {
        expectedNonce = Buffer.from(nonce, 'base64');
        if (expectedNonce.length !== 32) {
          return badRequest('nonce must be 32 bytes');
        }
      } catch (e) {
        return badRequest('nonce must be valid base64');
      }
    }

    // Get currently valid PCR configurations
    let expectedPCRs;
    try {
      expectedPCRs = await getCurrentPCRs();
    } catch (e: any) {
      console.error('Failed to get PCR configuration:', e);
      return internalError('Attestation verification temporarily unavailable');
    }

    // Verify attestation document
    let result: NitroAttestationResult;
    try {
      result = await verifyNitroAttestation(
        attestation_document,
        expectedPCRs,
        expectedNonce
      );
    } catch (e: any) {
      console.error('Attestation verification error:', e);
      return internalError('Attestation verification failed');
    }

    // Log attestation attempt
    await putAudit({
      action: 'nitro_attestation_verify',
      request_id: requestId,
      client_ip_hash: hashIdentifier(clientIp),
      session_id: session_id || null,
      valid: result.valid,
      module_id: result.moduleId || null,
      pcr_version: result.details.matchedPCRSet || null,
      error_count: result.errors.length,
    });

    // If attestation is valid and we have a session_id, update the enrollment session
    // This records that the app verified the enclave before proceeding with enrollment
    let bindingToken: string | undefined;
    if (result.valid && session_id) {
      try {
        const sessionResult = await ddb.send(new GetItemCommand({
          TableName: TABLE_ENROLLMENT_SESSIONS,
          Key: marshall({ session_id: session_id }),
        }));

        if (sessionResult.Item) {
          const session = unmarshall(sessionResult.Item);

          // Compute a short hash of PCR0 for display (first 24 chars of hex = 12 bytes)
          const pcrHash = result.pcrs.pcr0 ? result.pcrs.pcr0.substring(0, 24) : null;

          // SECURITY: Build update expression including app_public_key_hash if provided
          // This binds the attestation verification to the app's key exchange material
          let updateExpression = 'SET attestation_verified = :verified, attestation_time = :time, pcr_hash = :pcr, enclave_id = :enclave';
          const expressionValues: Record<string, any> = {
            ':verified': true,
            ':time': result.timestamp.toISOString(),
            ':pcr': pcrHash,
            ':enclave': result.moduleId || 'nitro-enclave',
          };

          if (app_public_key_hash) {
            updateExpression += ', app_public_key_hash = :apkh';
            expressionValues[':apkh'] = app_public_key_hash.toLowerCase();

            // Generate binding token for the enclave to verify
            if (pcrHash) {
              bindingToken = generateBindingToken(session_id, app_public_key_hash.toLowerCase(), pcrHash);
            }
          }

          await ddb.send(new UpdateItemCommand({
            TableName: TABLE_ENROLLMENT_SESSIONS,
            Key: marshall({ session_id: session_id }),
            UpdateExpression: updateExpression,
            ExpressionAttributeValues: marshall(expressionValues),
          }));

          console.log(`Updated attestation data for session ${session_id}${app_public_key_hash ? ' with key binding' : ''}`);
        }
      } catch (e: any) {
        // Don't fail the request if session update fails
        console.warn('Failed to update session with attestation data:', e);
      }
    }

    // Build response
    const response: VerifyAttestationResponse = {
      valid: result.valid,
    };

    if (result.valid) {
      if (result.enclavePublicKey) {
        response.enclave_public_key = result.enclavePublicKey.toString('base64');
      }
      response.pcr_version = result.details.matchedPCRSet;
      response.module_id = result.moduleId;
      response.timestamp = result.timestamp.toISOString();
      // SECURITY: Include binding token if app provided public key hash
      if (bindingToken) {
        response.binding_token = bindingToken;
      }
    } else {
      response.errors = result.errors;
    }

    return ok(response);

  } catch (error: any) {
    console.error('Unexpected error in verifyNitroAttestation:', error);
    return internalError('Internal server error');
  }
};
