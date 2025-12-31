import { APIGatewayRequestAuthorizerEvent, APIGatewayAuthorizerResult } from 'aws-lambda';
import { CognitoJwtVerifier } from 'aws-jwt-verify';

/**
 * Cookie-Based Lambda Authorizer
 *
 * Reads JWT tokens from httpOnly cookies instead of Authorization header.
 * This provides XSS protection since cookies with HttpOnly flag are not
 * accessible to JavaScript.
 *
 * Validates the token against Cognito and returns an IAM policy.
 */

const USER_POOL_ID = process.env.USER_POOL_ID!;
const CLIENT_ID = process.env.CLIENT_ID!;

// Create verifier instance (cached across invocations)
const verifier = CognitoJwtVerifier.create({
  userPoolId: USER_POOL_ID,
  tokenUse: 'id',
  clientId: CLIENT_ID
});

// Parse cookies from Cookie header
function parseCookies(cookieHeader: string | undefined): Record<string, string> {
  const cookies: Record<string, string> = {};
  if (!cookieHeader) return cookies;

  cookieHeader.split(';').forEach(cookie => {
    const [name, ...valueParts] = cookie.trim().split('=');
    if (name && valueParts.length > 0) {
      cookies[name.trim()] = valueParts.join('=').trim();
    }
  });

  return cookies;
}

// Generate IAM policy
function generatePolicy(
  principalId: string,
  effect: 'Allow' | 'Deny',
  resource: string,
  context?: Record<string, string | number | boolean>
): APIGatewayAuthorizerResult {
  return {
    principalId,
    policyDocument: {
      Version: '2012-10-17',
      Statement: [{
        Action: 'execute-api:Invoke',
        Effect: effect,
        Resource: resource
      }]
    },
    context
  };
}

export const handler = async (
  event: APIGatewayRequestAuthorizerEvent
): Promise<APIGatewayAuthorizerResult> => {
  try {
    // Get cookies from headers
    const cookieHeader = event.headers?.cookie || event.headers?.Cookie;
    const cookies = parseCookies(cookieHeader);

    // Look for the id_token in cookies
    const idToken = cookies['vettid_id_token'];

    if (!idToken) {
      console.log('No vettid_id_token cookie found');
      return generatePolicy('anonymous', 'Deny', event.methodArn);
    }

    // Verify the token with Cognito
    const payload = await verifier.verify(idToken);

    // Extract user info for context
    const userId = payload.sub;
    const email = payload.email as string || '';
    const groups = (payload['cognito:groups'] as string[]) || [];

    // Generate Allow policy with user context
    return generatePolicy(userId, 'Allow', event.methodArn, {
      userId,
      email,
      groups: groups.join(','),
      tokenUse: 'id'
    });

  } catch (error) {
    console.error('Authorization error:', error);
    // Return Deny policy on any error
    return generatePolicy('anonymous', 'Deny', event.methodArn);
  }
};
