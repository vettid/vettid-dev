import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  notFound,
  conflict,
  internalError,
  parseJsonBody,
  getRequestId,
  putAudit,
} from '../../common/util';
import {
  verifyIosAttestation,
  meetsSecurityRequirements,
  IosAttestationData,
} from '../../common/attestation';

const ddb = new DynamoDBClient({});

const TABLE_ENROLLMENT_SESSIONS = process.env.TABLE_ENROLLMENT_SESSIONS!;

interface VerifyIosRequest {
  enrollment_session_id: string;
  attestation_object: string;  // Base64-encoded CBOR
  key_id: string;
}

/**
 * POST /vault/enroll/attestation/ios
 *
 * Verify iOS App Attest attestation during enrollment.
 *
 * The mobile app sends the attestation object from DCAppAttestService.
 * We verify:
 * 1. Attestation object is valid CBOR
 * 2. Certificate chain roots to Apple
 * 3. Challenge matches what we sent
 * 4. Key ID is properly formatted
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);

  try {
    const body = parseJsonBody<VerifyIosRequest>(event);

    if (!body.enrollment_session_id) {
      return badRequest('enrollment_session_id is required');
    }
    if (!body.attestation_object) {
      return badRequest('attestation_object is required');
    }
    if (!body.key_id) {
      return badRequest('key_id is required');
    }

    // Get enrollment session
    const sessionResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_ENROLLMENT_SESSIONS,
      Key: marshall({ session_id: body.enrollment_session_id }),
    }));

    if (!sessionResult.Item) {
      return notFound('Enrollment session not found');
    }

    const session = unmarshall(sessionResult.Item);

    // Validate session state
    if (session.status !== 'STARTED') {
      return conflict(`Invalid session status: ${session.status}`);
    }

    if (session.step !== 'attestation_required') {
      return conflict(`Invalid session step: ${session.step}. Expected attestation_required.`);
    }

    // Check session expiry
    if (new Date(session.expires_at) < new Date()) {
      return badRequest('Enrollment session has expired');
    }

    // Get the challenge that was sent to the device
    const challenge = session.attestation_challenge;
    if (!challenge) {
      return conflict('No attestation challenge found in session');
    }

    // Verify the attestation
    const attestationData: IosAttestationData = {
      attestationObject: body.attestation_object,
      keyId: body.key_id,
      challenge: challenge,
    };

    const result = await verifyIosAttestation(attestationData);

    // Check if attestation meets requirements
    if (!meetsSecurityRequirements(result)) {
      await putAudit({
        type: 'attestation_failed',
        user_guid: session.user_guid,
        session_id: body.enrollment_session_id,
        device_type: 'ios',
        security_level: result.securityLevel,
        errors: result.errors,
      }, requestId);

      return badRequest(`Attestation verification failed: ${result.errors.join(', ')}`);
    }

    const now = new Date();

    // Update session with attestation result
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_ENROLLMENT_SESSIONS,
      Key: marshall({ session_id: body.enrollment_session_id }),
      UpdateExpression: 'SET #step = :step, attestation_verified = :verified, attestation_result = :result, attestation_verified_at = :verified_at, ios_key_id = :key_id',
      ExpressionAttributeNames: {
        '#step': 'step',
      },
      ExpressionAttributeValues: marshall({
        ':step': 'password_required',
        ':verified': true,
        ':result': {
          deviceType: result.deviceType,
          securityLevel: result.securityLevel,
          details: result.details,
        },
        ':verified_at': now.toISOString(),
        ':key_id': body.key_id,
      }),
    }));

    // Audit log
    await putAudit({
      type: 'attestation_verified',
      user_guid: session.user_guid,
      session_id: body.enrollment_session_id,
      device_type: 'ios',
      security_level: result.securityLevel,
    }, requestId);

    return ok({
      status: 'attestation_verified',
      device_type: 'ios',
      security_level: result.securityLevel,
      next_step: 'password_required',
      password_key_id: session.password_key_id,
    });

  } catch (error: any) {
    console.error('iOS attestation error:', error);
    return internalError('Failed to verify attestation');
  }
};
