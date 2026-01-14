import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';

/**
 * Token Exchange Handler (Secure Version)
 *
 * Receives JWT tokens from frontend after Cognito authentication.
 *
 * Security model:
 * - Refresh token: Stored as httpOnly cookie (protected from XSS)
 * - ID/Access tokens: Returned in response body for frontend to store in memory
 *
 * This approach:
 * - Protects the long-lived refresh token from XSS attacks
 * - Allows frontend to use short-lived tokens for API calls
 * - On page refresh, frontend calls /auth/session to get new tokens using httpOnly cookie
 */

interface TokenPayload {
  id_token: string;
  access_token: string;
  refresh_token?: string;
}

// Parse JWT without verification (verification happens in authorizer)
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
  // CORS headers
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
  };

  // HTTP API v2 uses requestContext.http.method instead of httpMethod
  const method = event.requestContext.http.method;
  if (method !== 'POST') {
    return {
      statusCode: 405,
      headers: corsHeaders,
      body: JSON.stringify({ message: 'Method not allowed' })
    };
  }

  try {
    if (!event.body) {
      return {
        statusCode: 400,
        headers: corsHeaders,
        body: JSON.stringify({ message: 'Missing request body' })
      };
    }

    const tokens: TokenPayload = JSON.parse(event.body);

    if (!tokens.id_token || !tokens.access_token) {
      return {
        statusCode: 400,
        headers: corsHeaders,
        body: JSON.stringify({ message: 'Missing required tokens' })
      };
    }

    // Parse and validate token expiration
    const idPayload = parseJwtPayload(tokens.id_token);
    if (!idPayload || !idPayload.exp) {
      return {
        statusCode: 400,
        headers: corsHeaders,
        body: JSON.stringify({ message: 'Invalid token format' })
      };
    }

    const exp = idPayload.exp as number;
    const now = Math.floor(Date.now() / 1000);

    if (exp <= now) {
      return {
        statusCode: 400,
        headers: corsHeaders,
        body: JSON.stringify({ message: 'Token expired' })
      };
    }

    // Calculate max age for short-lived tokens
    const maxAge = exp - now - 60; // 1 minute buffer

    // Only set refresh token as httpOnly cookie (most sensitive, long-lived)
    // ID and access tokens are returned in response body for frontend memory storage
    const cookies: string[] = [];

    if (tokens.refresh_token) {
      const refreshMaxAge = 30 * 24 * 60 * 60; // 30 days
      // HttpOnly: Not accessible via JavaScript (XSS protection)
      // Secure: Only sent over HTTPS
      // SameSite=Lax: Sent with top-level navigations (needed for redirect flows)
      // Domain: Set to .vettid.dev for cross-subdomain access
      cookies.push(`vettid_refresh_token=${tokens.refresh_token}; HttpOnly; Secure; SameSite=Lax; Path=/; Domain=.vettid.dev; Max-Age=${refreshMaxAge}`);
    }

    // Return ID and access tokens in response body
    // Frontend stores these in memory (sessionStorage as fallback for page refresh)
    return {
      statusCode: 200,
      headers: {
        ...corsHeaders,
        'Content-Type': 'application/json'
      },
      cookies: cookies,
      body: JSON.stringify({
        success: true,
        id_token: tokens.id_token,
        access_token: tokens.access_token,
        expires_in: maxAge
      })
    };

  } catch (error) {
    console.error('Token exchange error:', error);
    return {
      statusCode: 500,
      headers: corsHeaders,
      body: JSON.stringify({ message: 'Internal server error' })
    };
  }
};
