/**
 * Security utilities - rate limiting, audit logging
 */

import { randomBytes } from 'crypto';
import { getDynamoDBDocumentClient } from './clients';
import { GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb';

export interface RateLimitConfig {
  tableName: string;
  maxRequests: number;
  windowSeconds: number;
}

/**
 * Check rate limit for a given key (e.g., IP address, user ID)
 * Returns true if request is allowed, false if rate limited
 */
export async function checkRateLimit(
  key: string,
  config: RateLimitConfig
): Promise<boolean> {
  const client = getDynamoDBDocumentClient();
  const now = Math.floor(Date.now() / 1000);
  const windowStart = now - config.windowSeconds;

  const result = await client.send(new GetCommand({
    TableName: config.tableName,
    Key: { pk: `ratelimit#${key}` },
  }));

  const item = result.Item;
  if (!item || item.windowStart < windowStart) {
    // New window
    await client.send(new PutCommand({
      TableName: config.tableName,
      Item: {
        pk: `ratelimit#${key}`,
        windowStart: now,
        count: 1,
        ttl: now + config.windowSeconds * 2,
      },
    }));
    return true;
  }

  if (item.count >= config.maxRequests) {
    return false;
  }

  // Increment counter
  await client.send(new PutCommand({
    TableName: config.tableName,
    Item: {
      ...item,
      count: item.count + 1,
    },
  }));

  return true;
}

export interface AuditLogEntry {
  action: string;
  userGuid?: string;
  resourceId?: string;
  details?: Record<string, unknown>;
  ipAddress?: string;
  userAgent?: string;
}

/**
 * Write audit log entry
 */
export async function writeAuditLog(
  tableName: string,
  entry: AuditLogEntry
): Promise<void> {
  const client = getDynamoDBDocumentClient();
  const now = Date.now();

  await client.send(new PutCommand({
    TableName: tableName,
    Item: {
      pk: `audit#${entry.userGuid || 'system'}`,
      // SECURITY: Use cryptographic random for sort key uniqueness
      sk: `${now}#${randomBytes(4).toString('hex')}`,
      ...entry,
      timestamp: new Date(now).toISOString(),
      ttl: Math.floor(now / 1000) + 90 * 24 * 60 * 60, // 90 days
    },
  }));
}

/**
 * Timing-safe string comparison to prevent timing attacks
 */
export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    // Still do the comparison to maintain constant time
    b = a;
  }

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return result === 0 && a.length === b.length;
}
