import { DynamoDBClient, PutItemCommand, GetItemCommand, DeleteItemCommand, UpdateItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import { SESClient, SendTemplatedEmailCommand } from "@aws-sdk/client-ses";
import { CognitoIdentityProviderClient, AdminGetUserCommand } from "@aws-sdk/client-cognito-identity-provider";
import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { randomUUID } from "crypto";

export const ddb = new DynamoDBClient({});
export const ses = new SESClient({});
export const cognito = new CognitoIdentityProviderClient({});

export const TABLES = {
  invites: process.env.TABLE_INVITES!,
  registrations: process.env.TABLE_REGISTRATIONS!,
  audit: process.env.TABLE_AUDIT!,
};

export const USER_POOL_ID = process.env.USER_POOL_ID!;

/**
 * Custom error classes for better error handling
 */
export class NotFoundError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NotFoundError";
  }
}

export class ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ValidationError";
  }
}

/**
 * Generate cryptographically secure unique IDs
 */
export function generateSecureId(prefix?: string): string {
  const id = randomUUID().replace(/-/g, '').substring(0, 12).toUpperCase();
  return prefix ? `${prefix}-${id}` : id;
}

/**
 * Audit logging with secure ID generation
 */
export async function putAudit(entry: Record<string, any>): Promise<void> {
  entry.id = generateSecureId('AUDIT');
  entry.ts = new Date().toISOString();

  try {
    await ddb.send(new PutItemCommand({
      TableName: TABLES.audit,
      Item: marshall(entry)
    }));
  } catch (error) {
    console.error('Failed to write audit log:', error);
    // Don't throw - audit failures shouldn't break the main flow
  }
}

/**
 * Send templated email with error handling
 */
export async function sendTemplateEmail(
  to: string,
  template: string,
  data: any
): Promise<boolean> {
  try {
    await ses.send(new SendTemplatedEmailCommand({
      Source: process.env.SES_FROM!,
      Destination: { ToAddresses: [to] },
      Template: template,
      TemplateData: JSON.stringify(data),
    }));
    return true;
  } catch (error) {
    console.error(`Failed to send email to ${to}:`, error);
    return false;
  }
}

/**
 * HTTP Response helpers
 */
export function ok(body: any): APIGatewayProxyResultV2 {
  return {
    statusCode: 200,
    headers: cors(),
    body: JSON.stringify(body)
  };
}

export function created(body: any): APIGatewayProxyResultV2 {
  return {
    statusCode: 201,
    headers: cors(),
    body: JSON.stringify(body)
  };
}

export function noContent(): APIGatewayProxyResultV2 {
  return {
    statusCode: 204,
    headers: cors()
  };
}

export function badRequest(message: string): APIGatewayProxyResultV2 {
  return {
    statusCode: 400,
    headers: cors(),
    body: JSON.stringify({ message })
  };
}

export function unauthorized(message: string = "Unauthorized"): APIGatewayProxyResultV2 {
  return {
    statusCode: 401,
    headers: cors(),
    body: JSON.stringify({ message })
  };
}

export function forbidden(message: string = "Forbidden"): APIGatewayProxyResultV2 {
  return {
    statusCode: 403,
    headers: cors(),
    body: JSON.stringify({ message })
  };
}

export function notFound(message: string = "Not found"): APIGatewayProxyResultV2 {
  return {
    statusCode: 404,
    headers: cors(),
    body: JSON.stringify({ message })
  };
}

export function conflict(message: string): APIGatewayProxyResultV2 {
  return {
    statusCode: 409,
    headers: cors(),
    body: JSON.stringify({ message })
  };
}

export function internalError(message: string = "Internal server error"): APIGatewayProxyResultV2 {
  return {
    statusCode: 500,
    headers: cors(),
    body: JSON.stringify({ message })
  };
}

/**
 * SECURITY: Strict CORS - only allow specific origins
 */
const ALLOWED_ORIGINS = [
  'https://admin.vettid.dev',
  'https://account.vettid.dev',
  'https://register.vettid.dev',
  'https://vettid.dev',
  'https://www.vettid.dev',
  'http://localhost:3000',
  'http://localhost:5173',
];

/**
 * CORS headers with support for different HTTP methods
 * SECURITY: Never defaults to wildcard - requires explicit origin matching
 */
export function cors(methods: string = "OPTIONS,GET,POST,PUT,DELETE", origin?: string): Record<string, string> {
  // Use env var if set (and not wildcard), otherwise use allowed list
  const envOrigins = process.env.CORS_ORIGIN && process.env.CORS_ORIGIN !== '*'
    ? process.env.CORS_ORIGIN.split(',').map(o => o.trim())
    : ALLOWED_ORIGINS;

  // SECURITY: Only allow explicitly listed origins
  let allowedOrigin: string;
  if (origin && envOrigins.includes(origin)) {
    allowedOrigin = origin;
  } else {
    // Default to primary domain - will cause CORS errors for unknown origins
    allowedOrigin = envOrigins.find(o => o !== '*') || 'https://admin.vettid.dev';
  }

  return {
    "Access-Control-Allow-Origin": allowedOrigin,
    "Access-Control-Allow-Headers": "Content-Type,Authorization",
    "Access-Control-Allow-Methods": methods,
  };
}

/**
 * Extract admin email from API Gateway event
 */
export function getAdminEmail(event: APIGatewayProxyEventV2): string {
  return (event.requestContext as any)?.authorizer?.jwt?.claims?.email || "unknown@vettid.dev";
}

/**
 * DynamoDB helpers to reduce code duplication
 */
export async function getRegistration(registrationId: string): Promise<any> {
  const res = await ddb.send(new GetItemCommand({
    TableName: TABLES.registrations,
    Key: marshall({ registration_id: registrationId })
  }));

  if (!res.Item) {
    throw new NotFoundError("Registration not found");
  }

  return unmarshall(res.Item);
}

export async function getInvite(code: string): Promise<any> {
  const res = await ddb.send(new GetItemCommand({
    TableName: TABLES.invites,
    Key: marshall({ code }),
    ConsistentRead: true
  }));

  if (!res.Item) {
    throw new NotFoundError("Invite not found");
  }

  return unmarshall(res.Item);
}

export async function updateRegistrationStatus(
  registrationId: string,
  status: string,
  adminEmail: string,
  additionalFields?: Record<string, any>
): Promise<void> {
  const now = new Date().toISOString();
  const updateFields: Record<string, any> = {
    status,
    updated_at: now,
    [`${status}_at`]: now,
    [`${status}_by`]: adminEmail,
    ...additionalFields
  };

  const updateExpression = Object.keys(updateFields)
    .map((key, idx) => `#field${idx} = :val${idx}`)
    .join(", ");

  const expressionAttributeNames = Object.keys(updateFields)
    .reduce((acc, key, idx) => {
      acc[`#field${idx}`] = key;
      return acc;
    }, {} as Record<string, string>);

  const expressionAttributeValues = Object.keys(updateFields)
    .reduce((acc, key, idx) => {
      acc[`:val${idx}`] = updateFields[key];
      return acc;
    }, {} as Record<string, any>);

  await ddb.send(new UpdateItemCommand({
    TableName: TABLES.registrations,
    Key: marshall({ registration_id: registrationId }),
    UpdateExpression: `SET ${updateExpression}`,
    ExpressionAttributeNames: expressionAttributeNames,
    ExpressionAttributeValues: marshall(expressionAttributeValues)
  }));
}

/**
 * Cognito helpers to reduce code duplication
 */
export async function userExistsInCognito(email: string): Promise<boolean> {
  try {
    await cognito.send(new AdminGetUserCommand({
      UserPoolId: USER_POOL_ID,
      Username: email
    }));
    return true;
  } catch {
    return false;
  }
}

export async function getCognitoUser(email: string): Promise<any | null> {
  try {
    const result = await cognito.send(new AdminGetUserCommand({
      UserPoolId: USER_POOL_ID,
      Username: email
    }));
    return result;
  } catch {
    return null;
  }
}

/**
 * Input validation helpers
 */
export function validateEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

export function validateRequired(
  fields: Record<string, any>,
  requiredFields: string[]
): string | null {
  for (const field of requiredFields) {
    if (!fields[field] || (typeof fields[field] === 'string' && !fields[field].trim())) {
      return `Missing required field: ${field}`;
    }
  }
  return null;
}

/**
 * Parse and validate JSON body from event
 */
export function parseJsonBody<T = any>(event: APIGatewayProxyEventV2): T {
  if (!event.body) {
    throw new ValidationError("Missing request body");
  }

  try {
    return JSON.parse(event.body) as T;
  } catch {
    throw new ValidationError("Invalid JSON in request body");
  }
}
