import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';

/**
 * Token Exchange Handler
 *
 * Receives JWT tokens from frontend after Cognito PKCE authentication
 * and sets them as httpOnly cookies for secure storage.
 *
 * This eliminates localStorage token storage vulnerability to XSS attacks.
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

export const handler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
  // CORS headers
  const origin = event.headers.origin || event.headers.Origin || '';
  const allowedOrigins = [
    'https://vettid.dev',
    'https://account.vettid.dev',
    'https://admin.vettid.dev'
  ];

  const corsOrigin = allowedOrigins.includes(origin) ? origin : allowedOrigins[0];

  const corsHeaders = {
    'Access-Control-Allow-Origin': corsOrigin,
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS'
  };

  // Handle preflight
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers: corsHeaders, body: '' };
  }

  if (event.httpMethod !== 'POST') {
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

    // Calculate max age (token expiry minus current time, with buffer)
    const maxAge = exp - now - 60; // 1 minute buffer

    // Cookie options for security
    // HttpOnly: Not accessible via JavaScript
    // Secure: Only sent over HTTPS
    // SameSite=Strict: Not sent in cross-site requests (CSRF protection)
    // Path=/: Available for all paths
    // Domain: Set to .vettid.dev for cross-subdomain access
    const cookieOptions = `HttpOnly; Secure; SameSite=Strict; Path=/; Domain=.vettid.dev; Max-Age=${maxAge}`;

    // Set cookies via Set-Cookie headers
    const cookies = [
      `vettid_id_token=${tokens.id_token}; ${cookieOptions}`,
      `vettid_access_token=${tokens.access_token}; ${cookieOptions}`
    ];

    // Refresh token has longer expiry (typically 30 days)
    if (tokens.refresh_token) {
      const refreshMaxAge = 30 * 24 * 60 * 60; // 30 days
      cookies.push(`vettid_refresh_token=${tokens.refresh_token}; HttpOnly; Secure; SameSite=Strict; Path=/; Domain=.vettid.dev; Max-Age=${refreshMaxAge}`);
    }

    return {
      statusCode: 200,
      headers: {
        ...corsHeaders,
        'Content-Type': 'application/json'
      },
      multiValueHeaders: {
        'Set-Cookie': cookies
      },
      body: JSON.stringify({
        success: true,
        message: 'Tokens stored securely',
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
