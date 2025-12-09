/**
 * Ledger Database Connection Utility
 *
 * Provides connection pooling and query helpers for the Ledger PostgreSQL database.
 * Uses pg (node-postgres) with connection pooling optimized for Lambda.
 */

import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import { Pool, PoolClient, QueryResult, QueryResultRow } from 'pg';

// Environment variables set by CDK
const DB_HOST = process.env.LEDGER_DB_HOST;
const DB_PORT = process.env.LEDGER_DB_PORT || '5432';
const DB_NAME = process.env.LEDGER_DB_NAME || 'ledger';
const DB_SECRET_ARN = process.env.LEDGER_DB_SECRET_ARN;

// Connection pool (reused across Lambda invocations)
let pool: Pool | null = null;
let cachedCredentials: { username: string; password: string } | null = null;
let credentialsCacheTime: number = 0;
const CREDENTIALS_CACHE_TTL = 15 * 60 * 1000; // 15 minutes

const secretsClient = new SecretsManagerClient({});

/**
 * Get database credentials from Secrets Manager
 */
async function getCredentials(): Promise<{ username: string; password: string }> {
  const now = Date.now();

  // Return cached credentials if still valid
  if (cachedCredentials && (now - credentialsCacheTime) < CREDENTIALS_CACHE_TTL) {
    return cachedCredentials;
  }

  if (!DB_SECRET_ARN) {
    throw new Error('LEDGER_DB_SECRET_ARN environment variable not set');
  }

  const response = await secretsClient.send(
    new GetSecretValueCommand({ SecretId: DB_SECRET_ARN })
  );

  if (!response.SecretString) {
    throw new Error('Database secret is empty');
  }

  const secret = JSON.parse(response.SecretString);
  cachedCredentials = {
    username: secret.username,
    password: secret.password,
  };
  credentialsCacheTime = now;

  return cachedCredentials;
}

/**
 * Get or create the connection pool
 */
async function getPool(): Promise<Pool> {
  if (pool) {
    return pool;
  }

  if (!DB_HOST) {
    throw new Error('LEDGER_DB_HOST environment variable not set');
  }

  const credentials = await getCredentials();

  pool = new Pool({
    host: DB_HOST,
    port: parseInt(DB_PORT, 10),
    database: DB_NAME,
    user: credentials.username,
    password: credentials.password,
    // SSL configuration for AWS RDS
    // In production, bundle the RDS CA certificate for full verification
    // For VPC-internal connections, we can relax certificate validation
    ssl: {
      rejectUnauthorized: false, // TODO: Use RDS CA bundle in production
    },
    // Lambda-optimized pool settings
    max: 1, // Single connection per Lambda instance
    min: 0,
    idleTimeoutMillis: 60000, // Close idle connections after 1 minute
    connectionTimeoutMillis: 10000, // 10 second connection timeout
  });

  // Handle pool errors
  pool.on('error', (err) => {
    console.error('[LEDGER-DB] Unexpected pool error:', err);
    pool = null; // Force reconnection on next request
  });

  return pool;
}

/**
 * Execute a query against the Ledger database
 *
 * @param text SQL query with $1, $2, etc. placeholders
 * @param values Parameter values
 * @returns Query result
 */
export async function query<T extends QueryResultRow = QueryResultRow>(
  text: string,
  values?: unknown[]
): Promise<QueryResult<T>> {
  const dbPool = await getPool();
  const start = Date.now();

  try {
    const result = await dbPool.query<T>(text, values);
    const duration = Date.now() - start;

    // Log slow queries
    if (duration > 1000) {
      console.warn('[LEDGER-DB] Slow query:', { duration, text: text.slice(0, 100) });
    }

    return result;
  } catch (error) {
    console.error('[LEDGER-DB] Query error:', { text: text.slice(0, 100), error });
    throw error;
  }
}

/**
 * Execute a query and return the first row
 *
 * @param text SQL query
 * @param values Parameter values
 * @returns First row or null
 */
export async function queryOne<T extends QueryResultRow = QueryResultRow>(
  text: string,
  values?: unknown[]
): Promise<T | null> {
  const result = await query<T>(text, values);
  return result.rows[0] || null;
}

/**
 * Execute multiple queries in a transaction
 *
 * @param callback Function that receives a client and performs queries
 * @returns Result of the callback
 */
export async function transaction<T>(
  callback: (client: PoolClient) => Promise<T>
): Promise<T> {
  const dbPool = await getPool();
  const client = await dbPool.connect();

  try {
    await client.query('BEGIN');
    const result = await callback(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Check if the database connection is healthy
 */
export async function healthCheck(): Promise<boolean> {
  try {
    const result = await query('SELECT 1 as health');
    return result.rows.length === 1;
  } catch {
    return false;
  }
}

/**
 * Close the connection pool (for graceful shutdown)
 */
export async function closePool(): Promise<void> {
  if (pool) {
    await pool.end();
    pool = null;
  }
}

// ============================================
// Ledger-specific query helpers
// ============================================

/**
 * Get or create a user record
 */
export async function getOrCreateUser(userGuid: string): Promise<{
  user_guid: string;
  current_session_id: string | null;
  status: string;
  created_at: Date;
}> {
  const result = await query<{
    user_guid: string;
    current_session_id: string | null;
    status: string;
    created_at: Date;
  }>(
    `INSERT INTO users (user_guid)
     VALUES ($1)
     ON CONFLICT (user_guid) DO UPDATE
       SET updated_at = NOW()
     RETURNING user_guid, current_session_id, status, created_at`,
    [userGuid]
  );

  return result.rows[0];
}

/**
 * Atomically claim a session for a user
 * Returns false if another session is already active
 */
export async function claimSession(
  userGuid: string,
  sessionId: string,
  forceNew: boolean = false
): Promise<boolean> {
  const result = await query<{ claimed: boolean }>(
    `UPDATE users
     SET current_session_id = $2,
         session_started_at = NOW(),
         last_activity_at = NOW()
     WHERE user_guid = $1
       AND (current_session_id IS NULL OR $3 = true)
     RETURNING true as claimed`,
    [userGuid, sessionId, forceNew]
  );

  return result.rows.length > 0;
}

/**
 * Get an unused transaction key for a user
 */
export async function getUnusedTransactionKey(
  userGuid: string
): Promise<{
  key_id: string;
  public_key: Buffer;
  private_key: Buffer;
} | null> {
  return queryOne<{
    key_id: string;
    public_key: Buffer;
    private_key: Buffer;
  }>(
    `UPDATE transaction_keys
     SET status = 'used',
         used_at = NOW()
     WHERE key_id = (
       SELECT key_id FROM transaction_keys
       WHERE user_guid = $1
         AND status = 'unused'
         AND expires_at > NOW()
       ORDER BY created_at ASC
       LIMIT 1
       FOR UPDATE SKIP LOCKED
     )
     RETURNING key_id, public_key, private_key`,
    [userGuid]
  );
}

/**
 * Store a new transaction key pool
 */
export async function storeTransactionKeys(
  userGuid: string,
  keys: Array<{ publicKey: Buffer; privateKey: Buffer }>,
  expiresAt: Date
): Promise<string[]> {
  const keyIds: string[] = [];

  await transaction(async (client) => {
    for (const key of keys) {
      const result = await client.query<{ key_id: string }>(
        `INSERT INTO transaction_keys (user_guid, public_key, private_key, expires_at)
         VALUES ($1, $2, $3, $4)
         RETURNING key_id`,
        [userGuid, key.publicKey, key.privateKey, expiresAt]
      );
      keyIds.push(result.rows[0].key_id);
    }
  });

  return keyIds;
}

/**
 * Verify and rotate a LAT token
 * Returns the new token version if successful, null if verification failed
 */
export async function verifyAndRotateLAT(
  userGuid: string,
  tokenHash: Buffer
): Promise<{ version: number; oldTokenId: string } | null> {
  return transaction(async (client) => {
    // Find and mark the current token as used
    const currentToken = await client.query<{
      token_id: string;
      version: number;
    }>(
      `UPDATE ledger_auth_tokens
       SET status = 'used',
           last_used_at = NOW()
       WHERE user_guid = $1
         AND token_hash = $2
         AND status = 'active'
         AND expires_at > NOW()
       RETURNING token_id, version`,
      [userGuid, tokenHash]
    );

    if (currentToken.rows.length === 0) {
      return null; // Token not found or invalid
    }

    const oldToken = currentToken.rows[0];
    const newVersion = oldToken.version + 1;

    return {
      version: newVersion,
      oldTokenId: oldToken.token_id,
    };
  });
}

/**
 * Store a new LAT token
 */
export async function storeLAT(
  userGuid: string,
  tokenHash: Buffer,
  version: number,
  expiresAt: Date
): Promise<string> {
  const result = await query<{ token_id: string }>(
    `INSERT INTO ledger_auth_tokens (user_guid, token_hash, version, expires_at)
     VALUES ($1, $2, $3, $4)
     RETURNING token_id`,
    [userGuid, tokenHash, version, expiresAt]
  );

  return result.rows[0].token_id;
}

/**
 * Store a password hash
 */
export async function storePasswordHash(
  userGuid: string,
  passwordHash: string
): Promise<string> {
  return transaction(async (client) => {
    // Mark any existing hashes as non-current
    await client.query(
      `UPDATE password_hashes
       SET is_current = false, updated_at = NOW()
       WHERE user_guid = $1 AND is_current = true`,
      [userGuid]
    );

    // Insert the new hash
    const result = await client.query<{ hash_id: string }>(
      `INSERT INTO password_hashes (user_guid, password_hash, is_current)
       VALUES ($1, $2, true)
       RETURNING hash_id`,
      [userGuid, passwordHash]
    );

    return result.rows[0].hash_id;
  });
}

/**
 * Get the current password hash for verification
 */
export async function getPasswordHash(
  userGuid: string
): Promise<{
  hash_id: string;
  password_hash: string;
  failed_attempts: number;
  locked_until: Date | null;
} | null> {
  return queryOne(
    `SELECT hash_id, password_hash, failed_attempts, locked_until
     FROM password_hashes
     WHERE user_guid = $1 AND is_current = true`,
    [userGuid]
  );
}

/**
 * Record a failed password attempt
 */
export async function recordFailedAttempt(
  hashId: string,
  lockDuration?: number // Duration in minutes to lock the account
): Promise<{ failed_attempts: number; locked_until: Date | null }> {
  const lockUntil = lockDuration
    ? `NOW() + INTERVAL '${lockDuration} minutes'`
    : 'NULL';

  const result = await query<{
    failed_attempts: number;
    locked_until: Date | null;
  }>(
    `UPDATE password_hashes
     SET failed_attempts = failed_attempts + 1,
         last_failed_at = NOW(),
         locked_until = CASE
           WHEN failed_attempts + 1 >= 5 THEN ${lockUntil}::TIMESTAMP WITH TIME ZONE
           ELSE locked_until
         END
     WHERE hash_id = $1
     RETURNING failed_attempts, locked_until`,
    [hashId]
  );

  return result.rows[0];
}

/**
 * Reset failed attempts after successful login
 */
export async function resetFailedAttempts(hashId: string): Promise<void> {
  await query(
    `UPDATE password_hashes
     SET failed_attempts = 0,
         last_failed_at = NULL,
         locked_until = NULL
     WHERE hash_id = $1`,
    [hashId]
  );
}

/**
 * Log a security event to the audit log
 */
export async function logSecurityEvent(
  eventType: string,
  userGuid?: string,
  sessionId?: string,
  details?: Record<string, unknown>,
  severity: 'debug' | 'info' | 'warning' | 'error' | 'critical' = 'info',
  ipAddress?: string
): Promise<string> {
  const result = await query<{ log_id: string }>(
    `INSERT INTO audit_log (event_type, user_guid, session_id, details, event_severity, ip_address)
     VALUES ($1, $2, $3, $4, $5, $6::INET)
     RETURNING log_id`,
    [eventType, userGuid, sessionId, details ? JSON.stringify(details) : null, severity, ipAddress]
  );

  return result.rows[0].log_id;
}
