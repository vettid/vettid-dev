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
 * SECURITY: Routes that are allowed without authentication
 * Only /vault/enroll/start is allowed unauthenticated (users don't have accounts yet)
 * All other enrollment endpoints REQUIRE a valid enrollment JWT
 */
const UNAUTHENTICATED_ROUTES = [
  'POST /vault/enroll/start',
];

/**
 * Custom Lambda authorizer for enrollment endpoints
 *
 * Validates enrollment JWTs issued by the /vault/enroll/authenticate endpoint.
 * Passes user context (user_guid, session_id, device info) to downstream Lambdas.
 *
 * SECURITY: Only /vault/enroll/start allows unauthenticated access.
 * All other endpoints require a valid enrollment token.
 *
 * This authorizer is used for:
 * - POST /vault/enroll/start (unauthenticated - invitation code flow)
 * - POST /vault/enroll/set-password (requires token)
 * - POST /vault/enroll/finalize (requires token)
 * - POST /vault/enroll/attestation/android (requires token)
 * - POST /vault/enroll/attestation/ios (requires token)
 */
export const handler = async (
  event: APIGatewayRequestAuthorizerEventV2
): Promise<APIGatewaySimpleAuthorizerWithContextResult<EnrollmentAuthorizerContext>> => {
  const routeKey = event.routeKey || '';
  console.log('Enrollment authorizer invoked for:', routeKey);

  try {
    // Extract token from Authorization header
    const authHeader = event.headers?.authorization;
    const token = extractTokenFromHeader(authHeader);

    if (!token) {
      // SECURITY: Only allow unauthenticated access to specific routes
      const isAllowedUnauthenticated = UNAUTHENTICATED_ROUTES.includes(routeKey);

      if (isAllowedUnauthenticated) {
        // Allow /vault/enroll/start without token (invitation code flow)
        console.log('No token - allowing unauthenticated access for:', routeKey);
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

      // SECURITY: Deny all other routes without authentication
      console.warn('SECURITY: Denied unauthenticated access to:', routeKey);
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
