/**
 * General helper functions
 */

import { getDynamoDBDocumentClient } from './clients';
import { GetCommand, QueryCommand } from '@aws-sdk/lib-dynamodb';

/**
 * Generate a VettID-style GUID
 */
export function generateGuid(prefix: string): string {
  const uuid = crypto.randomUUID().replace(/-/g, '').toUpperCase();
  return `${prefix}-${uuid}`;
}

/**
 * Get current ISO timestamp
 */
export function nowISO(): string {
  return new Date().toISOString();
}

/**
 * Calculate TTL timestamp (seconds since epoch)
 */
export function calculateTTL(daysFromNow: number): number {
  return Math.floor(Date.now() / 1000) + daysFromNow * 24 * 60 * 60;
}

/**
 * Get a single item from DynamoDB by primary key
 */
export async function getItem<T>(
  tableName: string,
  pk: string,
  sk?: string
): Promise<T | null> {
  const client = getDynamoDBDocumentClient();
  const key: Record<string, string> = { pk };
  if (sk !== undefined) {
    key.sk = sk;
  }

  const result = await client.send(new GetCommand({
    TableName: tableName,
    Key: key,
  }));

  return (result.Item as T) || null;
}

/**
 * Query items from DynamoDB by partition key
 */
export async function queryByPK<T>(
  tableName: string,
  pk: string,
  options?: {
    skPrefix?: string;
    limit?: number;
    scanIndexForward?: boolean;
  }
): Promise<T[]> {
  const client = getDynamoDBDocumentClient();

  let keyCondition = 'pk = :pk';
  const expressionValues: Record<string, unknown> = { ':pk': pk };

  if (options?.skPrefix) {
    keyCondition += ' AND begins_with(sk, :skPrefix)';
    expressionValues[':skPrefix'] = options.skPrefix;
  }

  const result = await client.send(new QueryCommand({
    TableName: tableName,
    KeyConditionExpression: keyCondition,
    ExpressionAttributeValues: expressionValues,
    Limit: options?.limit,
    ScanIndexForward: options?.scanIndexForward ?? true,
  }));

  return (result.Items as T[]) || [];
}

/**
 * Sleep for specified milliseconds
 */
export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Retry a function with exponential backoff
 */
export async function withRetry<T>(
  fn: () => Promise<T>,
  maxAttempts = 3,
  baseDelayMs = 100
): Promise<T> {
  let lastError: Error | undefined;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error as Error;
      if (attempt < maxAttempts) {
        await sleep(baseDelayMs * Math.pow(2, attempt - 1));
      }
    }
  }

  throw lastError;
}
