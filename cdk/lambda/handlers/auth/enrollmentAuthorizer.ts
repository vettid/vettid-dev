import {
  APIGatewayRequestAuthorizerEventV2,
  APIGatewaySimpleAuthorizerWithContextResult,
} from 'aws-lambda';
import {
  verifyEnrollmentToken,
  extractTokenFromHeader,
  EnrollmentTokenPayload,
} from '../../common/enrollment-jwt';

/**
 * Context passed to downstream Lambda functions
 */
export interface EnrollmentAuthorizerContext {
  userGuid: string;
  sessionId: string;
  deviceId: string;
  deviceType: string;
  scope: string;
}

/**
 * Custom Lambda authorizer for enrollment endpoints
 *
 * Validates enrollment JWTs issued by the /vault/enroll/authenticate endpoint.
 * Passes user context (user_guid, session_id, device info) to downstream Lambdas.
 *
 * This authorizer is used for:
 * - POST /vault/enroll/start
 * - POST /vault/enroll/set-password
 * - POST /vault/enroll/finalize
 * - POST /vault/enroll/attestation/android
 * - POST /vault/enroll/attestation/ios
 */
export const handler = async (
  event: APIGatewayRequestAuthorizerEventV2
): Promise<APIGatewaySimpleAuthorizerWithContextResult<EnrollmentAuthorizerContext>> => {
  console.log('Enrollment authorizer invoked for:', event.routeKey);

  try {
    // Extract token from Authorization header
    const authHeader = event.headers?.authorization;
    const token = extractTokenFromHeader(authHeader);

    if (!token) {
      // No token - allow through for invitation code flow
      // The handler will check for invitation_code in body
      console.log('No token found - allowing for invitation code flow');
      return {
        isAuthorized: true,
        context: {
          userGuid: '',
          sessionId: '',
          deviceId: '',
          deviceType: '',
          scope: 'invitation_code',
        },
      };
    }

    // Verify and decode the token
    const payload = await verifyEnrollmentToken(token);

    if (!payload) {
      console.log('Token verification failed');
      return {
        isAuthorized: false,
        context: {
          userGuid: '',
          sessionId: '',
          deviceId: '',
          deviceType: '',
          scope: '',
        },
      };
    }

    console.log('Token verified for user:', payload.sub, 'session:', payload.session_id);

    // Return authorized with context
    return {
      isAuthorized: true,
      context: {
        userGuid: payload.sub,
        sessionId: payload.session_id,
        deviceId: payload.device_id || '',
        deviceType: payload.device_type || '',
        scope: payload.scope,
      },
    };
  } catch (error) {
    console.error('Authorizer error:', error);
    return {
      isAuthorized: false,
      context: {
        userGuid: '',
        sessionId: '',
        deviceId: '',
        deviceType: '',
        scope: '',
      },
    };
  }
};
