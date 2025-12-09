/**
 * Run Database Migration
 *
 * This Lambda function runs SQL migrations against the Ledger PostgreSQL database.
 * It's designed to be invoked manually or as a CDK custom resource.
 *
 * The function:
 * 1. Connects to the Aurora PostgreSQL database
 * 2. Checks the current migration version
 * 3. Runs any pending migrations
 * 4. Records the migration in a migrations table
 */

import { Handler } from 'aws-lambda';
import { query, transaction } from '../../common/ledger-db';

// Migration SQL - embedded for simplicity
// In production, consider loading from S3 or bundling files
const MIGRATION_001 = `
-- VettID Ledger Database - Initial Schema
-- Phase 1: Protean Credential System - Core

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================
-- Users Table
-- ============================================
CREATE TABLE IF NOT EXISTS users (
    user_guid UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    current_session_id UUID,
    session_started_at TIMESTAMP WITH TIME ZONE,
    last_activity_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT users_status_check CHECK (status IN ('active', 'suspended', 'deleted'))
);

CREATE INDEX IF NOT EXISTS idx_users_session ON users (current_session_id) WHERE current_session_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_status ON users (status);

-- ============================================
-- Credential Keys (CEK)
-- ============================================
CREATE TABLE IF NOT EXISTS credential_keys (
    key_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_guid UUID NOT NULL REFERENCES users(user_guid) ON DELETE CASCADE,
    public_key BYTEA NOT NULL,
    encrypted_private_key BYTEA NOT NULL,
    encryption_nonce BYTEA NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    is_current BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    rotated_at TIMESTAMP WITH TIME ZONE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_credential_keys_current ON credential_keys (user_guid) WHERE is_current = true;
CREATE INDEX IF NOT EXISTS idx_credential_keys_user ON credential_keys (user_guid);

-- ============================================
-- Transaction Keys (UTK/LTK)
-- ============================================
CREATE TABLE IF NOT EXISTS transaction_keys (
    key_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_guid UUID NOT NULL REFERENCES users(user_guid) ON DELETE CASCADE,
    public_key BYTEA NOT NULL,
    private_key BYTEA NOT NULL,
    encryption_nonce BYTEA,
    status VARCHAR(20) NOT NULL DEFAULT 'unused',
    used_at TIMESTAMP WITH TIME ZONE,
    session_id UUID,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT transaction_keys_status_check CHECK (status IN ('unused', 'used', 'expired'))
);

CREATE INDEX IF NOT EXISTS idx_transaction_keys_user ON transaction_keys (user_guid);
CREATE INDEX IF NOT EXISTS idx_transaction_keys_user_unused ON transaction_keys (user_guid, status) WHERE status = 'unused';
CREATE INDEX IF NOT EXISTS idx_transaction_keys_expires ON transaction_keys (expires_at);
CREATE INDEX IF NOT EXISTS idx_transaction_keys_public_key ON transaction_keys (public_key);

-- ============================================
-- Ledger Authentication Tokens (LAT)
-- ============================================
CREATE TABLE IF NOT EXISTS ledger_auth_tokens (
    token_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_guid UUID NOT NULL REFERENCES users(user_guid) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT ledger_auth_tokens_status_check CHECK (status IN ('active', 'used', 'revoked', 'expired'))
);

CREATE INDEX IF NOT EXISTS idx_lat_user_version ON ledger_auth_tokens (user_guid, version);
CREATE INDEX IF NOT EXISTS idx_lat_hash ON ledger_auth_tokens (token_hash) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_lat_expires ON ledger_auth_tokens (expires_at);

-- ============================================
-- Password Hashes
-- ============================================
CREATE TABLE IF NOT EXISTS password_hashes (
    hash_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_guid UUID NOT NULL REFERENCES users(user_guid) ON DELETE CASCADE,
    password_hash TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    is_current BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    last_failed_at TIMESTAMP WITH TIME ZONE,
    locked_until TIMESTAMP WITH TIME ZONE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_password_hashes_current ON password_hashes (user_guid) WHERE is_current = true;
CREATE INDEX IF NOT EXISTS idx_password_hashes_user ON password_hashes (user_guid);

-- ============================================
-- Audit Log
-- ============================================
CREATE TABLE IF NOT EXISTS audit_log (
    log_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_type VARCHAR(50) NOT NULL,
    event_severity VARCHAR(20) NOT NULL DEFAULT 'info',
    user_guid UUID,
    session_id UUID,
    ip_address INET,
    user_agent TEXT,
    details JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT audit_log_severity_check CHECK (event_severity IN ('debug', 'info', 'warning', 'error', 'critical'))
);

CREATE INDEX IF NOT EXISTS idx_audit_log_user ON audit_log (user_guid);
CREATE INDEX IF NOT EXISTS idx_audit_log_event_type ON audit_log (event_type);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log (created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_session ON audit_log (session_id) WHERE session_id IS NOT NULL;

-- ============================================
-- Sessions Table
-- ============================================
CREATE TABLE IF NOT EXISTS sessions (
    session_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_guid UUID NOT NULL REFERENCES users(user_guid) ON DELETE CASCADE,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    device_id VARCHAR(255),
    device_type VARCHAR(50),
    device_fingerprint BYTEA,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_activity_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    ip_address INET,
    CONSTRAINT sessions_status_check CHECK (status IN ('active', 'expired', 'revoked'))
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (user_guid);
CREATE INDEX IF NOT EXISTS idx_sessions_user_active ON sessions (user_guid, status) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions (expires_at);

-- ============================================
-- Functions and Triggers
-- ============================================

-- Function to update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply updated_at trigger to users table
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Function to expire old transaction keys
CREATE OR REPLACE FUNCTION expire_old_transaction_keys()
RETURNS void AS $$
BEGIN
    UPDATE transaction_keys
    SET status = 'expired'
    WHERE status = 'unused'
      AND expires_at < NOW();
END;
$$ LANGUAGE plpgsql;

-- Function to clean up expired sessions
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS void AS $$
BEGIN
    UPDATE sessions
    SET status = 'expired'
    WHERE status = 'active'
      AND expires_at < NOW();

    UPDATE users u
    SET current_session_id = NULL,
        session_started_at = NULL
    FROM sessions s
    WHERE u.current_session_id = s.session_id
      AND s.status = 'expired';
END;
$$ LANGUAGE plpgsql;

-- Function to log security events
CREATE OR REPLACE FUNCTION log_security_event(
    p_event_type VARCHAR(50),
    p_user_guid UUID DEFAULT NULL,
    p_session_id UUID DEFAULT NULL,
    p_details JSONB DEFAULT NULL,
    p_severity VARCHAR(20) DEFAULT 'info',
    p_ip_address INET DEFAULT NULL
)
RETURNS UUID AS $$
DECLARE
    v_log_id UUID;
BEGIN
    INSERT INTO audit_log (event_type, user_guid, session_id, details, event_severity, ip_address)
    VALUES (p_event_type, p_user_guid, p_session_id, p_details, p_severity, p_ip_address)
    RETURNING log_id INTO v_log_id;

    RETURN v_log_id;
END;
$$ LANGUAGE plpgsql;

-- Add table comments
COMMENT ON TABLE users IS 'User accounts and session state for the Protean Credential System';
COMMENT ON TABLE credential_keys IS 'Credential Encryption Keys (CEK) - X25519 key pairs for credential blob encryption';
COMMENT ON TABLE transaction_keys IS 'Transaction Keys (UTK/LTK) - One-time-use keys for session encryption';
COMMENT ON TABLE ledger_auth_tokens IS 'Ledger Authentication Tokens (LAT) - Mutual authentication tokens';
COMMENT ON TABLE password_hashes IS 'Password hashes (Argon2id) - Separated for security isolation';
COMMENT ON TABLE audit_log IS 'Security audit log for compliance and forensics';
COMMENT ON TABLE sessions IS 'Active authentication sessions';
`;

// Migration tracking table
const MIGRATIONS_TABLE = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    applied_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
`;

// CloudFormation Custom Resource event type
interface CfnEvent {
  RequestType: 'Create' | 'Update' | 'Delete';
  ResourceProperties?: {
    action?: string;
    version?: string;
  };
}

interface MigrationResult {
  success: boolean;
  message: string;
  currentVersion: number;
  appliedMigrations: number[];
}

export const handler: Handler<CfnEvent, MigrationResult> = async (event) => {
  console.log('[MIGRATION] Starting migration handler', {
    requestType: event.RequestType,
    properties: event.ResourceProperties
  });

  // For Delete events, just return success (nothing to do)
  if (event.RequestType === 'Delete') {
    return {
      success: true,
      message: 'Delete: No migration action needed',
      currentVersion: 0,
      appliedMigrations: [],
    };
  }

  try {
    // Ensure migrations table exists
    await query(MIGRATIONS_TABLE);

    // For Create and Update, run migrations
    return await runMigrations();
  } catch (error: any) {
    console.error('[MIGRATION] Error:', error);
    return {
      success: false,
      message: error.message || 'Unknown error',
      currentVersion: 0,
      appliedMigrations: [],
    };
  }
};

async function getMigrationStatus(): Promise<MigrationResult> {
  const result = await query<{ version: number }>(
    'SELECT version FROM schema_migrations ORDER BY version DESC'
  );

  const versions = result.rows.map(r => r.version);
  const currentVersion = versions.length > 0 ? Math.max(...versions) : 0;

  return {
    success: true,
    message: `Current schema version: ${currentVersion}`,
    currentVersion,
    appliedMigrations: versions,
  };
}

async function runMigrations(): Promise<MigrationResult> {
  // Check if migration 001 has been applied
  const existing = await query<{ version: number }>(
    'SELECT version FROM schema_migrations WHERE version = 1'
  );

  if (existing.rows.length > 0) {
    console.log('[MIGRATION] Migration 001 already applied');
    return {
      success: true,
      message: 'All migrations already applied',
      currentVersion: 1,
      appliedMigrations: [1],
    };
  }

  console.log('[MIGRATION] Applying migration 001: Initial Ledger Schema');

  // Run the migration
  await query(MIGRATION_001);

  // Record the migration
  await query(
    'INSERT INTO schema_migrations (version, name) VALUES ($1, $2)',
    [1, '001_initial_ledger_schema']
  );

  console.log('[MIGRATION] Migration 001 applied successfully');

  return {
    success: true,
    message: 'Migration 001 applied successfully',
    currentVersion: 1,
    appliedMigrations: [1],
  };
}
