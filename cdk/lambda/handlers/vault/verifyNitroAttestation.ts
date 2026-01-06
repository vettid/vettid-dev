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
 */

import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, UpdateItemCommand, QueryCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
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
  generateAttestationNonce,
  NitroAttestationResult,
} from '../../common/nitro-attestation';

const ddb = new DynamoDBClient({});

const TABLE_CREDENTIALS = process.env.TABLE_CREDENTIALS!;
const TABLE_ENROLLMENT_SESSIONS = process.env.TABLE_ENROLLMENT_SESSIONS!;

// Rate limiting: 20 attestation verifications per IP per 5 minutes
const RATE_LIMIT_MAX_REQUESTS = 20;
const RATE_LIMIT_WINDOW_MINUTES = 5;

interface VerifyAttestationRequest {
  attestation_document: string;  // Base64-encoded attestation document
  nonce?: string;                // Optional nonce (base64) for freshness verification
  session_id?: string;           // Optional session ID to bind attestation to
}

interface VerifyAttestationResponse {
  valid: boolean;
  enclave_public_key?: string;   // Base64-encoded public key for session encryption
  pcr_version?: string;          // Which PCR set was matched
  module_id?: string;            // Enclave module identifier
  timestamp?: string;            // Attestation timestamp
  errors?: string[];             // Verification errors if invalid
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

    const { attestation_document, nonce, session_id } = body;

    if (!attestation_document) {
      return badRequest('attestation_document is required');
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

    // If attestation is valid, update the credential record with attestation data
    if (result.valid) {
      let userGuid: string | null = null;

      // Try to get user_guid from member JWT claims
      const claims = extractUserClaims(event);
      if (claims && claims.user_guid) {
        userGuid = claims.user_guid;
      }

      // If no JWT, try to get user_guid from session_id (enrollment flow)
      if (!userGuid && session_id) {
        try {
          const sessionResult = await ddb.send(new GetItemCommand({
            TableName: TABLE_ENROLLMENT_SESSIONS,
            Key: marshall({ session_id: session_id }),
          }));

          if (sessionResult.Item) {
            const session = unmarshall(sessionResult.Item);
            userGuid = session.user_guid;
          }
        } catch (e) {
          console.warn('Failed to look up session for attestation:', e);
        }
      }

      // Update credential with attestation data if we have a user
      if (userGuid) {
        try {
          // First, query to get the credential (table has composite key: user_guid + credential_id)
          const credentialResult = await ddb.send(new QueryCommand({
            TableName: TABLE_CREDENTIALS,
            KeyConditionExpression: 'user_guid = :guid',
            ExpressionAttributeValues: marshall({ ':guid': userGuid }),
            Limit: 1,
          }));

          if (credentialResult.Items && credentialResult.Items.length > 0) {
            const credential = unmarshall(credentialResult.Items[0]);

            // Compute a short hash of PCR0 for display (first 24 chars of hex = 12 bytes)
            const pcrHash = result.pcrs.pcr0 ? result.pcrs.pcr0.substring(0, 24) : null;

            await ddb.send(new UpdateItemCommand({
              TableName: TABLE_CREDENTIALS,
              Key: marshall({
                user_guid: userGuid,
                credential_id: credential.credential_id,
              }),
              UpdateExpression: 'SET attestation_time = :time, pcr_hash = :pcr, enclave_id = :enclave, last_attestation_at = :time',
              ExpressionAttributeValues: marshall({
                ':time': result.timestamp.toISOString(),
                ':pcr': pcrHash,
                ':enclave': result.moduleId || 'nitro-enclave',
              }),
            }));

            console.log(`Updated attestation data for user ${userGuid}`);
          }
        } catch (e: any) {
          // Don't fail the request if credential update fails
          console.warn('Failed to update credential with attestation data:', e);
        }
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
    } else {
      response.errors = result.errors;
    }

    return ok(response);

  } catch (error: any) {
    console.error('Unexpected error in verifyNitroAttestation:', error);
    return internalError('Internal server error');
  }
};
