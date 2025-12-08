-- VettID Ledger Database - Initial Schema
-- Phase 1: Protean Credential System - Core
--
-- This migration creates the core tables for the Ledger database:
-- - users: User session management
-- - credential_keys: CEK (Credential Encryption Keys)
-- - transaction_keys: UTK/LTK (User/Ledger Transaction Keys)
-- - ledger_auth_tokens: LAT (Ledger Authentication Tokens)
-- - password_hashes: Argon2id password hashes
-- - audit_log: Security event logging

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================
-- Users Table
-- ============================================
-- Manages user session state and tracks active sessions.
-- Implements atomic session management - only one active session per user.

CREATE TABLE users (
    user_guid UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Session state (atomic - only one session active at a time)
    current_session_id UUID,
    session_started_at TIMESTAMP WITH TIME ZONE,
    last_activity_at TIMESTAMP WITH TIME ZONE,

    -- Account state
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    -- Constraints
    CONSTRAINT users_status_check CHECK (status IN ('active', 'suspended', 'deleted'))
);

-- Index for session lookups
CREATE INDEX idx_users_session ON users (current_session_id) WHERE current_session_id IS NOT NULL;
CREATE INDEX idx_users_status ON users (status);

-- ============================================
-- Credential Keys (CEK)
-- ============================================
-- Stores encrypted credential encryption keys.
-- CEKs are X25519 key pairs used to encrypt credential blobs.
-- The private key is encrypted with the user's password-derived key.

CREATE TABLE credential_keys (
    key_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_guid UUID NOT NULL REFERENCES users(user_guid) ON DELETE CASCADE,

    -- X25519 key material
    public_key BYTEA NOT NULL,                    -- 32 bytes, unencrypted
    encrypted_private_key BYTEA NOT NULL,         -- Encrypted with password-derived key
    encryption_nonce BYTEA NOT NULL,              -- Nonce used for encryption

    -- Key versioning for rotation
    version INTEGER NOT NULL DEFAULT 1,
    is_current BOOLEAN NOT NULL DEFAULT true,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    rotated_at TIMESTAMP WITH TIME ZONE,

    -- Only one current CEK per user
    CONSTRAINT unique_current_cek UNIQUE (user_guid, is_current) DEFERRABLE INITIALLY DEFERRED
);

-- Partial unique index to enforce only one current key per user
CREATE UNIQUE INDEX idx_credential_keys_current ON credential_keys (user_guid) WHERE is_current = true;
CREATE INDEX idx_credential_keys_user ON credential_keys (user_guid);

-- ============================================
-- Transaction Keys (UTK/LTK)
-- ============================================
-- Pool of one-time-use transaction keys.
-- UTK (User Transaction Key) = public key sent to user
-- LTK (Ledger Transaction Key) = private key stored here
-- Each key is used once for encrypting session-specific data.

CREATE TABLE transaction_keys (
    key_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_guid UUID NOT NULL REFERENCES users(user_guid) ON DELETE CASCADE,

    -- X25519 key material
    public_key BYTEA NOT NULL,            -- 32 bytes (UTK - sent to user)
    private_key BYTEA NOT NULL,           -- 32 bytes (LTK - stored encrypted)
    encryption_nonce BYTEA,               -- Nonce if private key is encrypted

    -- Key state
    status VARCHAR(20) NOT NULL DEFAULT 'unused',
    used_at TIMESTAMP WITH TIME ZONE,
    session_id UUID,                      -- Session that used this key

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Constraints
    CONSTRAINT transaction_keys_status_check CHECK (status IN ('unused', 'used', 'expired'))
);

-- Indexes for efficient key management
CREATE INDEX idx_transaction_keys_user ON transaction_keys (user_guid);
CREATE INDEX idx_transaction_keys_user_unused ON transaction_keys (user_guid, status) WHERE status = 'unused';
CREATE INDEX idx_transaction_keys_expires ON transaction_keys (expires_at);
CREATE INDEX idx_transaction_keys_public_key ON transaction_keys (public_key);

-- ============================================
-- Ledger Authentication Tokens (LAT)
-- ============================================
-- Mutual authentication tokens between user app and ledger.
-- Tokens are rotated after each successful authentication.
-- Only the hash is stored - never the raw token.

CREATE TABLE ledger_auth_tokens (
    token_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_guid UUID NOT NULL REFERENCES users(user_guid) ON DELETE CASCADE,

    -- Token data (always hashed - never store raw)
    token_hash BYTEA NOT NULL,            -- SHA-256 hash of the token

    -- Versioning for rotation
    version INTEGER NOT NULL DEFAULT 1,

    -- Token state
    status VARCHAR(20) NOT NULL DEFAULT 'active',

    -- Timing
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Constraints
    CONSTRAINT ledger_auth_tokens_status_check CHECK (status IN ('active', 'used', 'revoked', 'expired'))
);

-- Only one active LAT per user per version
CREATE INDEX idx_lat_user_version ON ledger_auth_tokens (user_guid, version);
CREATE INDEX idx_lat_hash ON ledger_auth_tokens (token_hash) WHERE status = 'active';
CREATE INDEX idx_lat_expires ON ledger_auth_tokens (expires_at);

-- ============================================
-- Password Hashes
-- ============================================
-- Stores Argon2id password hashes for user authentication.
-- Separated from users table for security isolation.

CREATE TABLE password_hashes (
    hash_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_guid UUID NOT NULL REFERENCES users(user_guid) ON DELETE CASCADE,

    -- Argon2id hash in PHC format
    -- Format: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
    password_hash TEXT NOT NULL,

    -- Hash versioning for algorithm upgrades
    version INTEGER NOT NULL DEFAULT 1,
    is_current BOOLEAN NOT NULL DEFAULT true,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE,

    -- Security tracking
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    last_failed_at TIMESTAMP WITH TIME ZONE,
    locked_until TIMESTAMP WITH TIME ZONE
);

-- Only one current password hash per user
CREATE UNIQUE INDEX idx_password_hashes_current ON password_hashes (user_guid) WHERE is_current = true;
CREATE INDEX idx_password_hashes_user ON password_hashes (user_guid);

-- ============================================
-- Audit Log
-- ============================================
-- Security event logging for compliance and forensics.
-- All sensitive operations are logged here.

CREATE TABLE audit_log (
    log_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Event identification
    event_type VARCHAR(50) NOT NULL,
    event_severity VARCHAR(20) NOT NULL DEFAULT 'info',

    -- Actor information
    user_guid UUID,
    session_id UUID,
    ip_address INET,
    user_agent TEXT,

    -- Event details
    details JSONB,

    -- Timing
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    -- Constraints
    CONSTRAINT audit_log_severity_check CHECK (event_severity IN ('debug', 'info', 'warning', 'error', 'critical'))
);

-- Partitioning by time for efficient querying and retention
-- (In production, consider range partitioning by created_at)
CREATE INDEX idx_audit_log_user ON audit_log (user_guid);
CREATE INDEX idx_audit_log_event_type ON audit_log (event_type);
CREATE INDEX idx_audit_log_created_at ON audit_log (created_at);
CREATE INDEX idx_audit_log_session ON audit_log (session_id) WHERE session_id IS NOT NULL;

-- ============================================
-- Sessions Table
-- ============================================
-- Tracks active authentication sessions.
-- Sessions are short-lived and tied to a specific device/context.

CREATE TABLE sessions (
    session_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_guid UUID NOT NULL REFERENCES users(user_guid) ON DELETE CASCADE,

    -- Session state
    status VARCHAR(20) NOT NULL DEFAULT 'active',

    -- Device/context information
    device_id VARCHAR(255),
    device_type VARCHAR(50),
    device_fingerprint BYTEA,

    -- Timing
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_activity_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    -- Security
    ip_address INET,

    -- Constraints
    CONSTRAINT sessions_status_check CHECK (status IN ('active', 'expired', 'revoked'))
);

CREATE INDEX idx_sessions_user ON sessions (user_guid);
CREATE INDEX idx_sessions_user_active ON sessions (user_guid, status) WHERE status = 'active';
CREATE INDEX idx_sessions_expires ON sessions (expires_at);

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

    -- Also clear current_session_id from users table
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

-- ============================================
-- Initial Data / Seed
-- ============================================

-- (No seed data for security tables)

-- ============================================
-- Permissions
-- ============================================

-- The Lambda role will connect using the secret from Secrets Manager
-- No additional user setup needed - Aurora handles this automatically

COMMENT ON TABLE users IS 'User accounts and session state for the Protean Credential System';
COMMENT ON TABLE credential_keys IS 'Credential Encryption Keys (CEK) - X25519 key pairs for credential blob encryption';
COMMENT ON TABLE transaction_keys IS 'Transaction Keys (UTK/LTK) - One-time-use keys for session encryption';
COMMENT ON TABLE ledger_auth_tokens IS 'Ledger Authentication Tokens (LAT) - Mutual authentication tokens';
COMMENT ON TABLE password_hashes IS 'Password hashes (Argon2id) - Separated for security isolation';
COMMENT ON TABLE audit_log IS 'Security audit log for compliance and forensics';
COMMENT ON TABLE sessions IS 'Active authentication sessions';
