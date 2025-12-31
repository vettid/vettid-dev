import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';

/**
 * Token Clear Handler
 *
 * Clears httpOnly cookies containing JWT tokens.
 * Used for logout functionality.
 */

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

  // Clear cookies by setting them with Max-Age=0
  const cookieOptions = 'HttpOnly; Secure; SameSite=Strict; Path=/; Domain=.vettid.dev; Max-Age=0';

  const cookies = [
    `vettid_id_token=; ${cookieOptions}`,
    `vettid_access_token=; ${cookieOptions}`,
    `vettid_refresh_token=; ${cookieOptions}`
  ];

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
      message: 'Tokens cleared'
    })
  };
};
