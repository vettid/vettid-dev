import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { CognitoIdentityProviderClient, InitiateAuthCommand } from '@aws-sdk/client-cognito-identity-provider';

/**
 * Session Handler (Secure Token Refresh)
 *
 * Reads the httpOnly refresh token cookie and returns fresh id/access tokens.
 * This allows the frontend to:
 * 1. Store refresh token securely in httpOnly cookie (protected from XSS)
 * 2. Get fresh tokens on page load for API calls
 *
 * Security model:
 * - Refresh token comes from httpOnly cookie (not JavaScript-accessible)
 * - New id/access tokens returned in response body for frontend memory storage
 * - Short-lived tokens minimize exposure window if stolen
 */

const cognito = new CognitoIdentityProviderClient({});
const CLIENT_ID = process.env.MEMBER_CLIENT_ID!;

// Parse cookies from the request
function parseCookies(event: APIGatewayProxyEventV2): Record<string, string> {
  const cookies: Record<string, string> = {};

  // HTTP API v2 provides cookies as an array
  const cookieArray = event.cookies || [];

  for (const cookie of cookieArray) {
    const [name, ...valueParts] = cookie.split('=');
    if (name) {
      cookies[name.trim()] = valueParts.join('=').trim();
    }
  }

  return cookies;
}

// Parse JWT without verification to get expiration
function parseJwtPayload(token: string): Record<string, unknown> | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const payload = Buffer.from(parts[1], 'base64url').toString('utf8');
    return JSON.parse(payload);
  } catch {
    return null;
  }
}

export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  // CORS headers - allow credentials for cookie access
  const origin = event.headers.origin || '';
  const allowedOrigins = [
    'https://vettid.dev',
    'https://account.vettid.dev',
    'https://admin.vettid.dev'
  ];

  const corsOrigin = allowedOrigins.includes(origin) ? origin : allowedOrigins[0];

  const corsHeaders = {
    'Access-Control-Allow-Origin': corsOrigin,
    'Access-Control-Allow-Credentials': 'true',
    'Content-Type': 'application/json'
  };

  const method = event.requestContext.http.method;

  // Handle preflight
  if (method === 'OPTIONS') {
    return {
      statusCode: 204,
      headers: {
        ...corsHeaders,
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type'
      },
      body: ''
    };
  }

  // Only allow GET or POST
  if (method !== 'GET' && method !== 'POST') {
    return {
      statusCode: 405,
      headers: corsHeaders,
      body: JSON.stringify({ message: 'Method not allowed' })
    };
  }

  try {
    // Extract refresh token from httpOnly cookie
    const cookies = parseCookies(event);
    const refreshToken = cookies['vettid_refresh_token'];

    if (!refreshToken) {
      return {
        statusCode: 401,
        headers: corsHeaders,
        body: JSON.stringify({
          message: 'No session found',
          authenticated: false
        })
      };
    }

    // Use Cognito to exchange refresh token for new tokens
    const authResult = await cognito.send(new InitiateAuthCommand({
      AuthFlow: 'REFRESH_TOKEN_AUTH',
      ClientId: CLIENT_ID,
      AuthParameters: {
        REFRESH_TOKEN: refreshToken
      }
    }));

    if (!authResult.AuthenticationResult) {
      return {
        statusCode: 401,
        headers: corsHeaders,
        body: JSON.stringify({
          message: 'Session expired',
          authenticated: false
        })
      };
    }

    const { IdToken, AccessToken } = authResult.AuthenticationResult;

    if (!IdToken || !AccessToken) {
      return {
        statusCode: 500,
        headers: corsHeaders,
        body: JSON.stringify({ message: 'Token refresh failed' })
      };
    }

    // Calculate expires_in from the id token
    const idPayload = parseJwtPayload(IdToken);
    const exp = idPayload?.exp as number || 0;
    const now = Math.floor(Date.now() / 1000);
    const expiresIn = exp > now ? exp - now - 60 : 3600; // 1 minute buffer, fallback to 1 hour

    // Return fresh tokens in response body
    // Frontend stores these in memory (not localStorage for XSS protection)
    return {
      statusCode: 200,
      headers: corsHeaders,
      body: JSON.stringify({
        authenticated: true,
        id_token: IdToken,
        access_token: AccessToken,
        expires_in: expiresIn
      })
    };

  } catch (error: any) {
    console.error('Session refresh error:', error);

    // Handle specific Cognito errors
    if (error.name === 'NotAuthorizedException') {
      // Clear the invalid refresh token cookie
      return {
        statusCode: 401,
        headers: corsHeaders,
        cookies: [
          'vettid_refresh_token=; HttpOnly; Secure; SameSite=Lax; Path=/; Domain=.vettid.dev; Max-Age=0'
        ],
        body: JSON.stringify({
          message: 'Session expired',
          authenticated: false
        })
      };
    }

    return {
      statusCode: 500,
      headers: corsHeaders,
      body: JSON.stringify({ message: 'Internal server error' })
    };
  }
};
