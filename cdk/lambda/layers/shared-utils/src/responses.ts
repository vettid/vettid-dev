/**
 * HTTP response helpers with CORS support
 */

import type { APIGatewayProxyResult } from 'aws-lambda';

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-Amz-Date,X-Api-Key,X-Amz-Security-Token',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  'Content-Type': 'application/json',
};

export function successResponse(body: unknown, statusCode = 200): APIGatewayProxyResult {
  return {
    statusCode,
    headers: CORS_HEADERS,
    body: JSON.stringify(body),
  };
}

export function errorResponse(message: string, statusCode = 400): APIGatewayProxyResult {
  return {
    statusCode,
    headers: CORS_HEADERS,
    body: JSON.stringify({ error: message }),
  };
}

export function notFoundResponse(message = 'Not found'): APIGatewayProxyResult {
  return errorResponse(message, 404);
}

export function unauthorizedResponse(message = 'Unauthorized'): APIGatewayProxyResult {
  return errorResponse(message, 401);
}

export function forbiddenResponse(message = 'Forbidden'): APIGatewayProxyResult {
  return errorResponse(message, 403);
}

export function serverErrorResponse(message = 'Internal server error'): APIGatewayProxyResult {
  return errorResponse(message, 500);
}

export function corsOptionsResponse(): APIGatewayProxyResult {
  return {
    statusCode: 200,
    headers: CORS_HEADERS,
    body: '',
  };
}
