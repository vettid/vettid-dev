package storage

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	_ "modernc.org/sqlite"
)

// SQLiteStorage provides encrypted SQLite storage for vault data
// The entire database is encrypted at rest using the DEK (Data Encryption Key)
// derived from the user's vault credentials.
//
// Architecture v2.0 Section 7.1 requirements:
// - Tables: cek_keypairs, transport_keys, ledger_entries, handler_state
// - Encrypt entire database with DEK
// - S3 sync with rollback protection counter
// - HMAC integrity verification for backups
type SQLiteStorage struct {
	db         *sql.DB
	dek        []byte // 32-byte Data Encryption Key
	ownerSpace string
	dbPath     string

	// Rollback protection counter - incremented on each write
	// Prevents replay attacks where attacker restores old backup
	rollbackCounter int64

	mu sync.RWMutex
}

// NewSQLiteStorage creates a new encrypted SQLite storage
// The database is stored in memory and synced to S3 periodically
func NewSQLiteStorage(ownerSpace string, dek []byte) (*SQLiteStorage, error) {
	if len(dek) != 32 {
		return nil, fmt.Errorf("DEK must be 32 bytes")
	}

	// Use in-memory database - will be synced to S3
	// In production, this runs entirely in enclave memory
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, fmt.Errorf("failed to open SQLite: %w", err)
	}

	// Set pragmas for security and performance
	pragmas := []string{
		"PRAGMA journal_mode=WAL",      // Write-ahead logging for better concurrency
		"PRAGMA synchronous=NORMAL",    // Balance between safety and speed
		"PRAGMA foreign_keys=ON",       // Enforce referential integrity
		"PRAGMA busy_timeout=5000",     // 5 second timeout for locks
	}

	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to set pragma %q: %w", pragma, err)
		}
	}

	// Make a copy of the DEK to prevent aliasing issues.
	// The caller may zero the original DEK after this call (e.g., for security),
	// which would corrupt our encryption key if we just stored a reference.
	dekCopy := make([]byte, len(dek))
	copy(dekCopy, dek)

	storage := &SQLiteStorage{
		db:              db,
		dek:             dekCopy,
		ownerSpace:      ownerSpace,
		dbPath:          ":memory:",
		rollbackCounter: 0,
	}

	// Initialize schema
	if err := storage.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return storage, nil
}

// initSchema creates the database tables per Architecture v2.0 Section 7.1
func (s *SQLiteStorage) initSchema() error {
	schema := `
	-- CEK keypair storage
	-- CEK (Credential Encryption Key) rotates after every operation
	CREATE TABLE IF NOT EXISTS cek_keypairs (
		version INTEGER PRIMARY KEY,
		private_key BLOB NOT NULL,
		public_key BLOB NOT NULL,
		created_at INTEGER NOT NULL,
		is_current INTEGER DEFAULT 0
	);
	CREATE INDEX IF NOT EXISTS idx_cek_current ON cek_keypairs(is_current) WHERE is_current = 1;

	-- Transport keys (UTK/LTK pairs)
	-- UTK: User Transaction Key (public, sent to app)
	-- LTK: Ledger Transaction Key (private, kept in vault)
	CREATE TABLE IF NOT EXISTS transport_keys (
		key_id TEXT PRIMARY KEY,
		key_type TEXT NOT NULL CHECK(key_type IN ('UTK', 'LTK')),
		private_key BLOB NOT NULL,
		public_key BLOB NOT NULL,
		used INTEGER DEFAULT 0,
		created_at INTEGER NOT NULL,
		used_at INTEGER
	);
	CREATE INDEX IF NOT EXISTS idx_transport_unused ON transport_keys(key_type, used) WHERE used = 0;

	-- User ledger entries
	-- Stores credential operations, call history, etc.
	CREATE TABLE IF NOT EXISTS ledger_entries (
		entry_id TEXT PRIMARY KEY,
		entry_type TEXT NOT NULL,
		payload BLOB NOT NULL,
		created_at INTEGER NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_ledger_type ON ledger_entries(entry_type, created_at DESC);

	-- Handler state
	-- Stores state for message handlers (connections, sessions, etc.)
	CREATE TABLE IF NOT EXISTS handler_state (
		handler_id TEXT PRIMARY KEY,
		state BLOB NOT NULL,
		updated_at INTEGER NOT NULL
	);

	-- Metadata table for rollback protection and sync state
	CREATE TABLE IF NOT EXISTS _metadata (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL,
		updated_at INTEGER NOT NULL
	);

	-- Processed events table for replay attack prevention
	-- Tracks event_ids that have been processed to prevent duplicate processing
	-- TTL-based cleanup removes entries older than 24 hours
	CREATE TABLE IF NOT EXISTS processed_events (
		event_id TEXT PRIMARY KEY,
		event_type TEXT NOT NULL,
		processed_at INTEGER NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_processed_events_cleanup ON processed_events(processed_at);

	-- Unified events table for audit logging and user feed
	-- This replaces the ledger_entries table with a more comprehensive schema
	-- Includes hash chain for tamper evidence (DEV-025)
	CREATE TABLE IF NOT EXISTS events (
		event_id TEXT PRIMARY KEY,
		event_type TEXT NOT NULL,
		source_type TEXT,
		source_id TEXT,
		payload BLOB NOT NULL,           -- Encrypted JSON with title, message, metadata

		-- Feed control (plaintext for efficient queries)
		feed_status TEXT NOT NULL DEFAULT 'hidden',
		action_type TEXT DEFAULT '',
		priority INTEGER DEFAULT 0,

		-- Timestamps
		created_at INTEGER NOT NULL,
		read_at INTEGER,
		actioned_at INTEGER,
		archived_at INTEGER,
		expires_at INTEGER,

		-- Sync
		sync_sequence INTEGER NOT NULL,

		-- Retention
		retention_class TEXT DEFAULT 'standard',

		-- Hash chain for tamper evidence (DEV-025)
		-- Each entry includes hash of previous entry
		previous_hash TEXT,              -- SHA-256 hash of previous entry (hex)
		entry_hash TEXT                  -- SHA-256 hash of this entry (hex)
	);

	-- Index for feed queries (most common: list active items)
	CREATE INDEX IF NOT EXISTS idx_events_feed
		ON events(feed_status, priority DESC, created_at DESC)
		WHERE feed_status IN ('active', 'read');

	-- Index for archive browsing
	CREATE INDEX IF NOT EXISTS idx_events_archive
		ON events(archived_at DESC)
		WHERE feed_status = 'archived';

	-- Index for audit log queries by type
	CREATE INDEX IF NOT EXISTS idx_events_audit
		ON events(event_type, created_at DESC);

	-- Index for sync endpoint
	CREATE INDEX IF NOT EXISTS idx_events_sync
		ON events(sync_sequence)
		WHERE feed_status != 'deleted';

	-- Index for cleanup operations
	CREATE INDEX IF NOT EXISTS idx_events_cleanup
		ON events(created_at)
		WHERE feed_status = 'deleted' OR retention_class = 'ephemeral';

	-- Index for source-based queries
	CREATE INDEX IF NOT EXISTS idx_events_source
		ON events(source_type, source_id, created_at DESC)
		WHERE source_id IS NOT NULL;

	-- ===============================
	-- Service Connections Tables
	-- ===============================

	-- Service contracts table - stores cryptographically signed connection agreements
	-- Each contract defines what capabilities a service has to access vault data.
	-- Contracts are versioned to support renegotiation without losing history.
	CREATE TABLE IF NOT EXISTS service_contracts (
		contract_id TEXT PRIMARY KEY,
		connection_id TEXT NOT NULL,
		service_guid TEXT NOT NULL,
		version INTEGER NOT NULL,
		status TEXT NOT NULL CHECK(status IN ('pending','active','superseded','rejected','expired')),
		contract_data BLOB NOT NULL,          -- Encrypted contract terms (JSON)
		user_signature BLOB,                   -- User's Ed25519 signature of contract
		service_signature BLOB,                -- Service's Ed25519 signature of contract
		signed_at INTEGER,                     -- When both parties signed
		capabilities TEXT NOT NULL DEFAULT '', -- Comma-separated: auth,authz,data,payment,call,notify
		created_at INTEGER NOT NULL,
		expires_at INTEGER,
		UNIQUE(connection_id, version)
	);

	-- Index for finding active contracts by connection
	CREATE INDEX IF NOT EXISTS idx_contracts_connection
		ON service_contracts(connection_id, status)
		WHERE status = 'active';

	-- Index for finding contracts by service
	CREATE INDEX IF NOT EXISTS idx_contracts_service
		ON service_contracts(service_guid, status);

	-- Service connection keys table - stores per-connection encryption keys
	-- Each connection has its own X25519 keypair for E2E encryption with the service.
	CREATE TABLE IF NOT EXISTS service_connection_keys (
		connection_id TEXT PRIMARY KEY,
		service_guid TEXT NOT NULL,
		private_key BLOB NOT NULL,             -- X25519 private key (encrypted with DEK)
		public_key BLOB NOT NULL,              -- X25519 public key
		service_public_key BLOB,               -- Service's X25519 public key (once established)
		shared_secret BLOB,                    -- Cached ECDH shared secret (encrypted with DEK)
		created_at INTEGER NOT NULL,
		rotated_at INTEGER
	);

	-- Index for finding keys by service
	CREATE INDEX IF NOT EXISTS idx_connection_keys_service
		ON service_connection_keys(service_guid);

	-- Service auth requests table - tracks pending authentication requests from services
	-- Services send auth requests, vault creates feed event, user approves/denies.
	CREATE TABLE IF NOT EXISTS service_auth_requests (
		request_id TEXT PRIMARY KEY,
		connection_id TEXT NOT NULL,
		service_guid TEXT NOT NULL,
		challenge BLOB NOT NULL,               -- Service-provided challenge to sign
		status TEXT NOT NULL CHECK(status IN ('pending','approved','denied','expired')),
		context TEXT,                          -- Service-provided context (JSON)
		callback_subject TEXT NOT NULL,        -- NATS subject for response
		feed_event_id TEXT,                    -- Link to user feed event
		response_signature BLOB,               -- User's signature if approved
		created_at INTEGER NOT NULL,
		responded_at INTEGER,
		expires_at INTEGER NOT NULL
	);

	-- Index for pending requests by connection
	CREATE INDEX IF NOT EXISTS idx_auth_requests_pending
		ON service_auth_requests(connection_id, status, expires_at)
		WHERE status = 'pending';

	-- ===============================
	-- User Secrets Storage (DEV-040)
	-- ===============================

	-- Secrets table - user-managed password vault
	-- Stores passwords, API keys, secure notes, etc.
	-- All sensitive fields encrypted with vault DEK.
	CREATE TABLE IF NOT EXISTS secrets (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		category TEXT NOT NULL CHECK(category IN ('login','card','identity','secure_note','api_key','crypto_wallet','custom')),
		fields BLOB NOT NULL,              -- CBOR-encoded SecretField array, encrypted
		notes BLOB,                        -- Encrypted notes
		tags TEXT,                         -- JSON array of tag strings
		favorite INTEGER DEFAULT 0,
		created_at INTEGER NOT NULL,
		updated_at INTEGER NOT NULL,
		last_viewed INTEGER,
		deleted_at INTEGER,                -- Soft delete timestamp (for sync)
		sync_version INTEGER DEFAULT 1     -- Incremented on each change (for sync)
	);

	-- Index for category filtering
	CREATE INDEX IF NOT EXISTS idx_secrets_category
		ON secrets(category, updated_at DESC)
		WHERE deleted_at IS NULL;

	-- Index for favorites
	CREATE INDEX IF NOT EXISTS idx_secrets_favorite
		ON secrets(favorite, updated_at DESC)
		WHERE favorite = 1 AND deleted_at IS NULL;

	-- Index for sync (find changes since last sync)
	CREATE INDEX IF NOT EXISTS idx_secrets_sync
		ON secrets(sync_version)
		WHERE deleted_at IS NULL;

	-- Index for soft-deleted secrets (tombstones for sync)
	CREATE INDEX IF NOT EXISTS idx_secrets_deleted
		ON secrets(deleted_at)
		WHERE deleted_at IS NOT NULL;

	-- Full-text search for secrets (name and tags)
	-- FTS5 allows efficient searching across secret names
	CREATE VIRTUAL TABLE IF NOT EXISTS secrets_fts USING fts5(
		id UNINDEXED,
		name,
		tags,
		content='secrets',
		content_rowid='rowid'
	);

	-- Triggers to keep FTS index in sync
	CREATE TRIGGER IF NOT EXISTS secrets_ai AFTER INSERT ON secrets BEGIN
		INSERT INTO secrets_fts(id, name, tags)
		VALUES (new.id, new.name, new.tags);
	END;

	CREATE TRIGGER IF NOT EXISTS secrets_ad AFTER DELETE ON secrets BEGIN
		DELETE FROM secrets_fts WHERE id = old.id;
	END;

	CREATE TRIGGER IF NOT EXISTS secrets_au AFTER UPDATE ON secrets BEGIN
		DELETE FROM secrets_fts WHERE id = old.id;
		INSERT INTO secrets_fts(id, name, tags)
		VALUES (new.id, new.name, new.tags);
	END;
	`

	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	// Initialize rollback counter if not exists
	_, err := s.db.Exec(`
		INSERT OR IGNORE INTO _metadata (key, value, updated_at)
		VALUES ('rollback_counter', '0', ?)
	`, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("failed to initialize metadata: %w", err)
	}

	// Initialize event sync sequence if not exists
	_, err = s.db.Exec(`
		INSERT OR IGNORE INTO _metadata (key, value, updated_at)
		VALUES ('event_sync_sequence', '0', ?)
	`, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("failed to initialize event sync sequence: %w", err)
	}

	// Load rollback counter
	var counterStr string
	err = s.db.QueryRow(`SELECT value FROM _metadata WHERE key = 'rollback_counter'`).Scan(&counterStr)
	if err != nil {
		return fmt.Errorf("failed to load rollback counter: %w", err)
	}
	fmt.Sscanf(counterStr, "%d", &s.rollbackCounter)

	return nil
}

// CEKKeypair represents a CEK keypair stored in the database
type CEKKeypair struct {
	Version    int64
	PrivateKey []byte
	PublicKey  []byte
	CreatedAt  int64
	IsCurrent  bool
}

// TransportKey represents a transport key (UTK/LTK)
type TransportKey struct {
	KeyID      string
	KeyType    string // "UTK" or "LTK"
	PrivateKey []byte
	PublicKey  []byte
	Used       bool
	CreatedAt  int64
	UsedAt     *int64
}

// LedgerEntry represents a ledger entry
type LedgerEntry struct {
	EntryID   string
	EntryType string
	Payload   []byte
	CreatedAt int64
}

// HandlerState represents handler state
type HandlerState struct {
	HandlerID string
	State     []byte
	UpdatedAt int64
}

// ===============================
// CEK Keypair Operations
// ===============================

// StoreCEKKeypair stores a new CEK keypair
func (s *SQLiteStorage) StoreCEKKeypair(privateKey, publicKey []byte, isCurrent bool) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Encrypt keys before storing
	encPrivate, err := s.encrypt(privateKey)
	if err != nil {
		return 0, fmt.Errorf("failed to encrypt private key: %w", err)
	}
	encPublic, err := s.encrypt(publicKey)
	if err != nil {
		return 0, fmt.Errorf("failed to encrypt public key: %w", err)
	}

	now := time.Now().Unix()

	// If this is the new current key, unset previous current
	if isCurrent {
		if _, err := s.db.Exec(`UPDATE cek_keypairs SET is_current = 0 WHERE is_current = 1`); err != nil {
			return 0, fmt.Errorf("failed to unset current CEK: %w", err)
		}
	}

	result, err := s.db.Exec(`
		INSERT INTO cek_keypairs (private_key, public_key, created_at, is_current)
		VALUES (?, ?, ?, ?)
	`, encPrivate, encPublic, now, boolToInt(isCurrent))
	if err != nil {
		return 0, fmt.Errorf("failed to store CEK keypair: %w", err)
	}

	version, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("failed to get version: %w", err)
	}

	s.incrementRollbackCounter()
	return version, nil
}

// GetCurrentCEK returns the current CEK keypair
func (s *SQLiteStorage) GetCurrentCEK() (*CEKKeypair, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var kp CEKKeypair
	var encPrivate, encPublic []byte
	var isCurrent int

	err := s.db.QueryRow(`
		SELECT version, private_key, public_key, created_at, is_current
		FROM cek_keypairs
		WHERE is_current = 1
	`).Scan(&kp.Version, &encPrivate, &encPublic, &kp.CreatedAt, &isCurrent)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get current CEK: %w", err)
	}

	// Decrypt keys
	kp.PrivateKey, err = s.decrypt(encPrivate)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt private key: %w", err)
	}
	kp.PublicKey, err = s.decrypt(encPublic)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt public key: %w", err)
	}
	kp.IsCurrent = isCurrent == 1

	return &kp, nil
}

// GetCEKByVersion returns a CEK keypair by version
func (s *SQLiteStorage) GetCEKByVersion(version int64) (*CEKKeypair, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var kp CEKKeypair
	var encPrivate, encPublic []byte
	var isCurrent int

	err := s.db.QueryRow(`
		SELECT version, private_key, public_key, created_at, is_current
		FROM cek_keypairs
		WHERE version = ?
	`, version).Scan(&kp.Version, &encPrivate, &encPublic, &kp.CreatedAt, &isCurrent)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get CEK by version: %w", err)
	}

	// Decrypt keys
	kp.PrivateKey, err = s.decrypt(encPrivate)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt private key: %w", err)
	}
	kp.PublicKey, err = s.decrypt(encPublic)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt public key: %w", err)
	}
	kp.IsCurrent = isCurrent == 1

	return &kp, nil
}

// ===============================
// Transport Key Operations
// ===============================

// StoreTransportKey stores a new transport key
func (s *SQLiteStorage) StoreTransportKey(keyID, keyType string, privateKey, publicKey []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if keyType != "UTK" && keyType != "LTK" {
		return fmt.Errorf("invalid key type: %s", keyType)
	}

	encPrivate, err := s.encrypt(privateKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt private key: %w", err)
	}
	encPublic, err := s.encrypt(publicKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt public key: %w", err)
	}

	now := time.Now().Unix()
	_, err = s.db.Exec(`
		INSERT INTO transport_keys (key_id, key_type, private_key, public_key, used, created_at)
		VALUES (?, ?, ?, ?, 0, ?)
	`, keyID, keyType, encPrivate, encPublic, now)
	if err != nil {
		return fmt.Errorf("failed to store transport key: %w", err)
	}

	s.incrementRollbackCounter()
	return nil
}

// GetUnusedTransportKey returns an unused transport key of the given type
func (s *SQLiteStorage) GetUnusedTransportKey(keyType string) (*TransportKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var tk TransportKey
	var encPrivate, encPublic []byte
	var used int
	var usedAt sql.NullInt64

	err := s.db.QueryRow(`
		SELECT key_id, key_type, private_key, public_key, used, created_at, used_at
		FROM transport_keys
		WHERE key_type = ? AND used = 0
		ORDER BY created_at ASC
		LIMIT 1
	`, keyType).Scan(&tk.KeyID, &tk.KeyType, &encPrivate, &encPublic, &used, &tk.CreatedAt, &usedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get unused transport key: %w", err)
	}

	// Decrypt keys
	tk.PrivateKey, err = s.decrypt(encPrivate)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt private key: %w", err)
	}
	tk.PublicKey, err = s.decrypt(encPublic)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt public key: %w", err)
	}
	tk.Used = used == 1
	if usedAt.Valid {
		tk.UsedAt = &usedAt.Int64
	}

	return &tk, nil
}

// MarkTransportKeyUsed marks a transport key as used
func (s *SQLiteStorage) MarkTransportKeyUsed(keyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().Unix()
	result, err := s.db.Exec(`
		UPDATE transport_keys
		SET used = 1, used_at = ?
		WHERE key_id = ?
	`, now, keyID)
	if err != nil {
		return fmt.Errorf("failed to mark transport key used: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("transport key not found: %s", keyID)
	}

	s.incrementRollbackCounter()
	return nil
}

// CountUnusedTransportKeys returns the count of unused keys of a given type
func (s *SQLiteStorage) CountUnusedTransportKeys(keyType string) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var count int
	err := s.db.QueryRow(`
		SELECT COUNT(*) FROM transport_keys
		WHERE key_type = ? AND used = 0
	`, keyType).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count unused transport keys: %w", err)
	}

	return count, nil
}

// ===============================
// Ledger Entry Operations
// ===============================

// StoreLedgerEntry stores a new ledger entry
func (s *SQLiteStorage) StoreLedgerEntry(entryID, entryType string, payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	encPayload, err := s.encrypt(payload)
	if err != nil {
		return fmt.Errorf("failed to encrypt payload: %w", err)
	}

	now := time.Now().Unix()
	_, err = s.db.Exec(`
		INSERT INTO ledger_entries (entry_id, entry_type, payload, created_at)
		VALUES (?, ?, ?, ?)
	`, entryID, entryType, encPayload, now)
	if err != nil {
		return fmt.Errorf("failed to store ledger entry: %w", err)
	}

	s.incrementRollbackCounter()
	return nil
}

// GetLedgerEntry returns a ledger entry by ID
func (s *SQLiteStorage) GetLedgerEntry(entryID string) (*LedgerEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var entry LedgerEntry
	var encPayload []byte

	err := s.db.QueryRow(`
		SELECT entry_id, entry_type, payload, created_at
		FROM ledger_entries
		WHERE entry_id = ?
	`, entryID).Scan(&entry.EntryID, &entry.EntryType, &encPayload, &entry.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get ledger entry: %w", err)
	}

	entry.Payload, err = s.decrypt(encPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt payload: %w", err)
	}

	return &entry, nil
}

// ListLedgerEntries returns ledger entries of a given type
func (s *SQLiteStorage) ListLedgerEntries(entryType string, limit int) ([]LedgerEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`
		SELECT entry_id, entry_type, payload, created_at
		FROM ledger_entries
		WHERE entry_type = ?
		ORDER BY created_at DESC
		LIMIT ?
	`, entryType, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list ledger entries: %w", err)
	}
	defer rows.Close()

	var entries []LedgerEntry
	for rows.Next() {
		var entry LedgerEntry
		var encPayload []byte
		if err := rows.Scan(&entry.EntryID, &entry.EntryType, &encPayload, &entry.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan ledger entry: %w", err)
		}
		entry.Payload, err = s.decrypt(encPayload)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt payload: %w", err)
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

// ===============================
// Handler State Operations
// ===============================

// StoreHandlerState stores or updates handler state
func (s *SQLiteStorage) StoreHandlerState(handlerID string, state []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	encState, err := s.encrypt(state)
	if err != nil {
		return fmt.Errorf("failed to encrypt state: %w", err)
	}

	now := time.Now().Unix()
	_, err = s.db.Exec(`
		INSERT INTO handler_state (handler_id, state, updated_at)
		VALUES (?, ?, ?)
		ON CONFLICT(handler_id) DO UPDATE SET
			state = excluded.state,
			updated_at = excluded.updated_at
	`, handlerID, encState, now)
	if err != nil {
		return fmt.Errorf("failed to store handler state: %w", err)
	}

	s.incrementRollbackCounter()
	return nil
}

// GetHandlerState returns handler state by ID
func (s *SQLiteStorage) GetHandlerState(handlerID string) (*HandlerState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var hs HandlerState
	var encState []byte

	err := s.db.QueryRow(`
		SELECT handler_id, state, updated_at
		FROM handler_state
		WHERE handler_id = ?
	`, handlerID).Scan(&hs.HandlerID, &encState, &hs.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get handler state: %w", err)
	}

	hs.State, err = s.decrypt(encState)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt state: %w", err)
	}

	return &hs, nil
}

// DeleteHandlerState deletes handler state
func (s *SQLiteStorage) DeleteHandlerState(handlerID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`DELETE FROM handler_state WHERE handler_id = ?`, handlerID)
	if err != nil {
		return fmt.Errorf("failed to delete handler state: %w", err)
	}

	s.incrementRollbackCounter()
	return nil
}

// ===============================
// Generic Key-Value Operations
// ===============================
// These methods provide a simple key-value interface using the handler_state table.
// This maintains compatibility with existing handlers that use Get/Put/Delete.

// Get retrieves a value by key (stored in handler_state table)
func (s *SQLiteStorage) Get(key string) ([]byte, error) {
	hs, err := s.GetHandlerState(key)
	if err != nil {
		return nil, err
	}
	if hs == nil {
		return nil, ErrKeyNotFound
	}
	return hs.State, nil
}

// Put stores a value by key (stored in handler_state table)
func (s *SQLiteStorage) Put(key string, value []byte) error {
	return s.StoreHandlerState(key, value)
}

// Delete removes a value by key (from handler_state table)
func (s *SQLiteStorage) Delete(key string) error {
	return s.DeleteHandlerState(key)
}

// ErrKeyNotFound is returned when a key is not found in storage
var ErrKeyNotFound = fmt.Errorf("key not found")

// ===============================
// Backup & Sync Operations
// ===============================

// BackupData represents a serialized database backup
type BackupData struct {
	Version         int    `json:"version"`          // Backup format version
	OwnerSpace      string `json:"owner_space"`      // Owner space identifier
	RollbackCounter int64  `json:"rollback_counter"` // Monotonic counter for replay protection
	Data            []byte `json:"data"`             // Encrypted SQLite dump
	HMAC            []byte `json:"hmac"`             // HMAC-SHA256 of Data
	CreatedAt       int64  `json:"created_at"`       // Unix timestamp
}

// CreateBackup creates an encrypted backup of the database
func (s *SQLiteStorage) CreateBackup() (*BackupData, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Export all data as JSON (tables are already encrypted)
	backup, err := s.exportData()
	if err != nil {
		return nil, fmt.Errorf("failed to export data: %w", err)
	}

	// Encrypt the backup
	encryptedBackup, err := s.encrypt(backup)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt backup: %w", err)
	}

	// Calculate HMAC for integrity verification
	h := hmac.New(sha256.New, s.dek)
	h.Write(encryptedBackup)
	backupHMAC := h.Sum(nil)

	return &BackupData{
		Version:         1,
		OwnerSpace:      s.ownerSpace,
		RollbackCounter: s.rollbackCounter,
		Data:            encryptedBackup,
		HMAC:            backupHMAC,
		CreatedAt:       time.Now().Unix(),
	}, nil
}

// RestoreBackup restores the database from a backup
func (s *SQLiteStorage) RestoreBackup(backup *BackupData) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Verify HMAC
	h := hmac.New(sha256.New, s.dek)
	h.Write(backup.Data)
	expectedHMAC := h.Sum(nil)
	if !hmac.Equal(backup.HMAC, expectedHMAC) {
		return fmt.Errorf("backup HMAC verification failed")
	}

	// Check rollback counter
	if backup.RollbackCounter < s.rollbackCounter {
		return fmt.Errorf("rollback detected: backup counter %d < current %d",
			backup.RollbackCounter, s.rollbackCounter)
	}

	// Decrypt backup
	data, err := s.decrypt(backup.Data)
	if err != nil {
		return fmt.Errorf("failed to decrypt backup: %w", err)
	}

	// Import data
	if err := s.importData(data); err != nil {
		return fmt.Errorf("failed to import data: %w", err)
	}

	// Update rollback counter
	s.rollbackCounter = backup.RollbackCounter

	return nil
}

// GetRollbackCounter returns the current rollback counter
func (s *SQLiteStorage) GetRollbackCounter() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rollbackCounter
}

// exportData exports all table data as JSON
func (s *SQLiteStorage) exportData() ([]byte, error) {
	export := make(map[string]interface{})

	// Export each table (excluding processed_events which is ephemeral)
	tables := []string{"cek_keypairs", "transport_keys", "ledger_entries", "handler_state", "_metadata"}
	for _, table := range tables {
		rows, err := s.db.Query(fmt.Sprintf("SELECT * FROM %s", table))
		if err != nil {
			return nil, fmt.Errorf("failed to query table %s: %w", table, err)
		}
		defer rows.Close()

		cols, err := rows.Columns()
		if err != nil {
			return nil, fmt.Errorf("failed to get columns for %s: %w", table, err)
		}

		var tableData []map[string]interface{}
		for rows.Next() {
			values := make([]interface{}, len(cols))
			valuePtrs := make([]interface{}, len(cols))
			for i := range values {
				valuePtrs[i] = &values[i]
			}
			if err := rows.Scan(valuePtrs...); err != nil {
				return nil, fmt.Errorf("failed to scan row in %s: %w", table, err)
			}
			row := make(map[string]interface{})
			for i, col := range cols {
				row[col] = values[i]
			}
			tableData = append(tableData, row)
		}
		export[table] = tableData
	}

	return json.Marshal(export)
}

// importData imports data from JSON export
func (s *SQLiteStorage) importData(data []byte) error {
	var export map[string][]map[string]interface{}
	if err := json.Unmarshal(data, &export); err != nil {
		return fmt.Errorf("failed to unmarshal export: %w", err)
	}

	// BLOB columns per table - these are base64-encoded in JSON and need decoding
	blobColumns := map[string]map[string]bool{
		"handler_state":  {"state": true},
		"cek_keypairs":   {"private_key": true, "public_key": true},
		"transport_keys": {"private_key": true, "public_key": true},
		"ledger_entries": {"payload": true},
		"_metadata":      {},
	}

	// Clear existing data
	tables := []string{"cek_keypairs", "transport_keys", "ledger_entries", "handler_state", "_metadata"}
	for _, table := range tables {
		if _, err := s.db.Exec(fmt.Sprintf("DELETE FROM %s", table)); err != nil {
			return fmt.Errorf("failed to clear table %s: %w", table, err)
		}
	}

	// Import rows for each table
	for table, rows := range export {
		tableBlobs := blobColumns[table]
		if tableBlobs == nil {
			tableBlobs = map[string]bool{}
		}

		for _, row := range rows {
			if len(row) == 0 {
				continue
			}

			cols := make([]string, 0, len(row))
			vals := make([]interface{}, 0, len(row))
			placeholders := make([]string, 0, len(row))

			for col, val := range row {
				cols = append(cols, col)
				placeholders = append(placeholders, "?")

				if tableBlobs[col] {
					// BLOB columns: decode base64 string back to []byte
					if strVal, ok := val.(string); ok {
						decoded, err := base64.StdEncoding.DecodeString(strVal)
						if err != nil {
							return fmt.Errorf("failed to decode BLOB %s.%s: %w", table, col, err)
						}
						vals = append(vals, decoded)
					} else {
						vals = append(vals, val)
					}
				} else if numVal, ok := val.(float64); ok {
					// JSON numbers become float64, convert to int64 for INTEGER columns
					vals = append(vals, int64(numVal))
				} else {
					vals = append(vals, val)
				}
			}

			query := fmt.Sprintf("INSERT OR REPLACE INTO %s (%s) VALUES (%s)",
				table,
				strings.Join(cols, ", "),
				strings.Join(placeholders, ", "),
			)

			if _, err := s.db.Exec(query, vals...); err != nil {
				return fmt.Errorf("failed to insert row into %s: %w", table, err)
			}
		}
	}

	return nil
}

// ===============================
// Encryption Helpers
// ===============================

// encrypt encrypts data using ChaCha20-Poly1305 with the DEK
func (s *SQLiteStorage) encrypt(plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(s.dek)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// decrypt decrypts data using ChaCha20-Poly1305 with the DEK
func (s *SQLiteStorage) decrypt(ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(s.dek)
	if err != nil {
		return nil, err
	}

	nonceSize := aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertext[:nonceSize]
	ciphertext = ciphertext[nonceSize:]

	return aead.Open(nil, nonce, ciphertext, nil)
}

// incrementRollbackCounter increments the rollback counter and updates metadata
func (s *SQLiteStorage) incrementRollbackCounter() {
	s.rollbackCounter++
	s.db.Exec(`
		UPDATE _metadata
		SET value = ?, updated_at = ?
		WHERE key = 'rollback_counter'
	`, fmt.Sprintf("%d", s.rollbackCounter), time.Now().Unix())
}

// boolToInt converts bool to int for SQLite storage
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ===============================
// Replay Attack Prevention
// ===============================
// These methods track processed event IDs to prevent replay attacks.
// Events are stored with a 24-hour TTL and cleaned up periodically.

const (
	// ReplayTTLSeconds is the time window for replay detection (24 hours)
	ReplayTTLSeconds = 86400
	// MaxEventAge is the maximum age of events to accept (5 minutes)
	MaxEventAge = 300
)

// IsEventProcessed checks if an event has already been processed
// Returns true if the event was already processed (replay detected)
func (s *SQLiteStorage) IsEventProcessed(eventID string) (bool, error) {
	if eventID == "" {
		return false, nil // Empty event IDs are not tracked
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	var count int
	err := s.db.QueryRow(`
		SELECT COUNT(*) FROM processed_events WHERE event_id = ?
	`, eventID).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check processed event: %w", err)
	}

	return count > 0, nil
}

// MarkEventProcessed marks an event as processed to prevent replay
func (s *SQLiteStorage) MarkEventProcessed(eventID, eventType string) error {
	if eventID == "" {
		return nil // Don't track empty event IDs
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`
		INSERT OR IGNORE INTO processed_events (event_id, event_type, processed_at)
		VALUES (?, ?, ?)
	`, eventID, eventType, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("failed to mark event processed: %w", err)
	}

	return nil
}

// CleanupExpiredEvents removes processed events older than TTL
// Should be called periodically (e.g., hourly) to prevent unbounded growth
func (s *SQLiteStorage) CleanupExpiredEvents() (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Unix() - ReplayTTLSeconds
	result, err := s.db.Exec(`
		DELETE FROM processed_events WHERE processed_at < ?
	`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired events: %w", err)
	}

	deleted, _ := result.RowsAffected()
	return deleted, nil
}

// CheckEventFreshness validates that an event timestamp is recent enough
// Returns error if the event is too old (possible replay attack)
func CheckEventFreshness(eventTimestamp int64) error {
	now := time.Now().Unix()
	age := now - eventTimestamp

	if age < 0 {
		// Future timestamp - clock skew or manipulation
		return fmt.Errorf("event timestamp is in the future")
	}

	if age > MaxEventAge {
		return fmt.Errorf("event is too old: %d seconds (max %d)", age, MaxEventAge)
	}

	return nil
}

// Close closes the database connection
func (s *SQLiteStorage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db.Close()
}

// ===============================
// Unified Event System Operations
// ===============================
// These methods manage the unified events table that serves both
// audit logging and user feed purposes.

// EventRecord represents an event stored in the database
type EventRecord struct {
	EventID        string
	EventType      string
	SourceType     string
	SourceID       string
	Payload        []byte // Decrypted payload
	FeedStatus     string
	ActionType     string
	Priority       int
	CreatedAt      int64
	ReadAt         *int64
	ActionedAt     *int64
	ArchivedAt     *int64
	ExpiresAt      *int64
	SyncSequence   int64
	RetentionClass string
	// Hash chain for tamper evidence (DEV-025)
	PreviousHash string // SHA-256 hash of previous entry (hex)
	EntryHash    string // SHA-256 hash of this entry (hex)
}

// StoreEvent stores a new event in the events table with hash chain integrity
func (s *SQLiteStorage) StoreEvent(event *EventRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Encrypt the payload
	encPayload, err := s.encrypt(event.Payload)
	if err != nil {
		return fmt.Errorf("failed to encrypt event payload: %w", err)
	}

	// Get the previous entry's hash for chain integrity (DEV-025)
	var previousHash string
	row := s.db.QueryRow(`SELECT entry_hash FROM events ORDER BY sync_sequence DESC LIMIT 1`)
	if err := row.Scan(&previousHash); err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("failed to get previous hash: %w", err)
	}
	// If no previous entries, use genesis hash
	if previousHash == "" {
		previousHash = "genesis"
	}

	// Compute entry hash: SHA256(previous_hash || event_id || event_type || source_id || payload || created_at)
	hashInput := fmt.Sprintf("%s|%s|%s|%s|%x|%d",
		previousHash, event.EventID, event.EventType, event.SourceID, encPayload, event.CreatedAt)
	entryHash := fmt.Sprintf("%x", sha256.Sum256([]byte(hashInput)))

	event.PreviousHash = previousHash
	event.EntryHash = entryHash

	_, err = s.db.Exec(`
		INSERT INTO events (
			event_id, event_type, source_type, source_id, payload,
			feed_status, action_type, priority,
			created_at, read_at, actioned_at, archived_at, expires_at,
			sync_sequence, retention_class, previous_hash, entry_hash
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		event.EventID, event.EventType, event.SourceType, event.SourceID, encPayload,
		event.FeedStatus, event.ActionType, event.Priority,
		event.CreatedAt, event.ReadAt, event.ActionedAt, event.ArchivedAt, event.ExpiresAt,
		event.SyncSequence, event.RetentionClass, event.PreviousHash, event.EntryHash,
	)
	if err != nil {
		return fmt.Errorf("failed to store event: %w", err)
	}

	s.incrementRollbackCounter()
	return nil
}

// GetEvent retrieves a single event by ID
func (s *SQLiteStorage) GetEvent(eventID string) (*EventRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var event EventRecord
	var encPayload []byte
	var readAt, actionedAt, archivedAt, expiresAt sql.NullInt64

	err := s.db.QueryRow(`
		SELECT event_id, event_type, source_type, source_id, payload,
		       feed_status, action_type, priority,
		       created_at, read_at, actioned_at, archived_at, expires_at,
		       sync_sequence, retention_class
		FROM events
		WHERE event_id = ?
	`, eventID).Scan(
		&event.EventID, &event.EventType, &event.SourceType, &event.SourceID, &encPayload,
		&event.FeedStatus, &event.ActionType, &event.Priority,
		&event.CreatedAt, &readAt, &actionedAt, &archivedAt, &expiresAt,
		&event.SyncSequence, &event.RetentionClass,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get event: %w", err)
	}

	// Decrypt payload
	event.Payload, err = s.decrypt(encPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt event payload: %w", err)
	}

	// Convert nullable fields
	if readAt.Valid {
		event.ReadAt = &readAt.Int64
	}
	if actionedAt.Valid {
		event.ActionedAt = &actionedAt.Int64
	}
	if archivedAt.Valid {
		event.ArchivedAt = &archivedAt.Int64
	}
	if expiresAt.Valid {
		event.ExpiresAt = &expiresAt.Int64
	}

	return &event, nil
}

// ListFeedEvents returns events for the user feed
func (s *SQLiteStorage) ListFeedEvents(statuses []string, limit, offset int) ([]EventRecord, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(statuses) == 0 {
		statuses = []string{"active", "read"}
	}
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}

	// Build query with status filter
	placeholders := make([]string, len(statuses))
	args := make([]interface{}, len(statuses))
	for i, status := range statuses {
		placeholders[i] = "?"
		args[i] = status
	}
	statusFilter := "(" + join(placeholders, ",") + ")"

	// Get total count
	var total int
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM events WHERE feed_status IN %s`, statusFilter)
	if err := s.db.QueryRow(countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count events: %w", err)
	}

	// Get events
	query := fmt.Sprintf(`
		SELECT event_id, event_type, source_type, source_id, payload,
		       feed_status, action_type, priority,
		       created_at, read_at, actioned_at, archived_at, expires_at,
		       sync_sequence, retention_class
		FROM events
		WHERE feed_status IN %s
		ORDER BY priority DESC, created_at DESC
		LIMIT ? OFFSET ?
	`, statusFilter)
	args = append(args, limit, offset)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list feed events: %w", err)
	}
	defer rows.Close()

	events, err := s.scanEventRows(rows)
	if err != nil {
		return nil, 0, err
	}

	return events, total, nil
}

// QueryAuditEvents returns events for audit purposes
func (s *SQLiteStorage) QueryAuditEvents(eventTypes []string, startTime, endTime int64, sourceID string, limit, offset int) ([]EventRecord, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	// Build dynamic WHERE clause
	var conditions []string
	var args []interface{}

	if len(eventTypes) > 0 {
		placeholders := make([]string, len(eventTypes))
		for i, et := range eventTypes {
			placeholders[i] = "?"
			args = append(args, et)
		}
		conditions = append(conditions, fmt.Sprintf("event_type IN (%s)", join(placeholders, ",")))
	}

	if startTime > 0 {
		conditions = append(conditions, "created_at >= ?")
		args = append(args, startTime)
	}

	if endTime > 0 {
		conditions = append(conditions, "created_at <= ?")
		args = append(args, endTime)
	}

	if sourceID != "" {
		conditions = append(conditions, "source_id = ?")
		args = append(args, sourceID)
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + join(conditions, " AND ")
	}

	// Get total count
	var total int
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM events %s`, whereClause)
	if err := s.db.QueryRow(countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count audit events: %w", err)
	}

	// Get events
	query := fmt.Sprintf(`
		SELECT event_id, event_type, source_type, source_id, payload,
		       feed_status, action_type, priority,
		       created_at, read_at, actioned_at, archived_at, expires_at,
		       sync_sequence, retention_class
		FROM events
		%s
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?
	`, whereClause)
	args = append(args, limit, offset)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query audit events: %w", err)
	}
	defer rows.Close()

	events, err := s.scanEventRows(rows)
	if err != nil {
		return nil, 0, err
	}

	return events, total, nil
}

// GetEventsSince returns events with sync_sequence > lastSeq for sync
func (s *SQLiteStorage) GetEventsSince(lastSeq int64, limit int) ([]EventRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 {
		limit = 100
	}

	rows, err := s.db.Query(`
		SELECT event_id, event_type, source_type, source_id, payload,
		       feed_status, action_type, priority,
		       created_at, read_at, actioned_at, archived_at, expires_at,
		       sync_sequence, retention_class
		FROM events
		WHERE sync_sequence > ? AND feed_status != 'deleted'
		ORDER BY sync_sequence ASC
		LIMIT ?
	`, lastSeq, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get events since sequence: %w", err)
	}
	defer rows.Close()

	return s.scanEventRows(rows)
}

// UpdateEventStatus updates the feed_status and related timestamps
func (s *SQLiteStorage) UpdateEventStatus(eventID string, newStatus string, timestamp int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var query string
	var args []interface{}

	switch newStatus {
	case "read":
		query = `UPDATE events SET feed_status = ?, read_at = ? WHERE event_id = ?`
		args = []interface{}{newStatus, timestamp, eventID}
	case "archived":
		query = `UPDATE events SET feed_status = ?, archived_at = ? WHERE event_id = ?`
		args = []interface{}{newStatus, timestamp, eventID}
	case "deleted":
		query = `UPDATE events SET feed_status = ? WHERE event_id = ?`
		args = []interface{}{newStatus, eventID}
	default:
		query = `UPDATE events SET feed_status = ? WHERE event_id = ?`
		args = []interface{}{newStatus, eventID}
	}

	result, err := s.db.Exec(query, args...)
	if err != nil {
		return fmt.Errorf("failed to update event status: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("event not found: %s", eventID)
	}

	s.incrementRollbackCounter()
	return nil
}

// UpdateEventActioned marks an event as actioned
func (s *SQLiteStorage) UpdateEventActioned(eventID string, timestamp int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.Exec(`
		UPDATE events SET actioned_at = ? WHERE event_id = ?
	`, timestamp, eventID)
	if err != nil {
		return fmt.Errorf("failed to update event actioned: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("event not found: %s", eventID)
	}

	s.incrementRollbackCounter()
	return nil
}

// GetSyncSequence returns the current sync sequence number
func (s *SQLiteStorage) GetSyncSequence() (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var seqStr string
	err := s.db.QueryRow(`SELECT value FROM _metadata WHERE key = 'event_sync_sequence'`).Scan(&seqStr)
	if err != nil {
		return 0, fmt.Errorf("failed to get sync sequence: %w", err)
	}

	var seq int64
	fmt.Sscanf(seqStr, "%d", &seq)
	return seq, nil
}

// IncrementSyncSequence increments and returns the new sync sequence
func (s *SQLiteStorage) IncrementSyncSequence() (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Get current value
	var seqStr string
	err := s.db.QueryRow(`SELECT value FROM _metadata WHERE key = 'event_sync_sequence'`).Scan(&seqStr)
	if err != nil {
		return 0, fmt.Errorf("failed to get sync sequence: %w", err)
	}

	var seq int64
	fmt.Sscanf(seqStr, "%d", &seq)
	seq++

	// Update
	_, err = s.db.Exec(`
		UPDATE _metadata SET value = ?, updated_at = ?
		WHERE key = 'event_sync_sequence'
	`, fmt.Sprintf("%d", seq), time.Now().Unix())
	if err != nil {
		return 0, fmt.Errorf("failed to update sync sequence: %w", err)
	}

	return seq, nil
}

// CleanupEvents removes old events based on retention policies
func (s *SQLiteStorage) CleanupEvents(feedRetentionDays, auditRetentionDays int, autoArchive bool) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().Unix()
	var totalDeleted int64

	// 1. Remove soft-deleted items older than 7 days
	result, err := s.db.Exec(`
		DELETE FROM events
		WHERE feed_status = 'deleted' AND created_at < ?
	`, now-7*24*3600)
	if err == nil {
		n, _ := result.RowsAffected()
		totalDeleted += n
	}

	// 2. Remove ephemeral items older than 24 hours
	result, err = s.db.Exec(`
		DELETE FROM events
		WHERE retention_class = 'ephemeral' AND created_at < ?
	`, now-24*3600)
	if err == nil {
		n, _ := result.RowsAffected()
		totalDeleted += n
	}

	// 3. Remove hidden (audit-only) items older than audit retention
	if auditRetentionDays > 0 {
		auditCutoff := now - int64(auditRetentionDays)*24*3600
		result, err = s.db.Exec(`
			DELETE FROM events
			WHERE feed_status = 'hidden' AND retention_class != 'permanent' AND created_at < ?
		`, auditCutoff)
		if err == nil {
			n, _ := result.RowsAffected()
			totalDeleted += n
		}
	}

	// 4. Auto-archive feed items older than feed retention
	if autoArchive && feedRetentionDays > 0 {
		feedCutoff := now - int64(feedRetentionDays)*24*3600
		s.db.Exec(`
			UPDATE events
			SET feed_status = 'archived', archived_at = ?
			WHERE feed_status IN ('active', 'read') AND created_at < ?
		`, now, feedCutoff)
	}

	if totalDeleted > 0 {
		s.incrementRollbackCounter()
	}

	return totalDeleted, nil
}

// VerifyEventChain verifies the integrity of the event hash chain (DEV-025)
// Returns the number of verified events and any integrity violation error
func (s *SQLiteStorage) VerifyEventChain() (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`
		SELECT event_id, event_type, source_id, payload, created_at, previous_hash, entry_hash
		FROM events
		ORDER BY sync_sequence ASC
	`)
	if err != nil {
		return 0, fmt.Errorf("failed to query events: %w", err)
	}
	defer rows.Close()

	verified := 0
	expectedPreviousHash := "genesis"

	for rows.Next() {
		var eventID, eventType, sourceID string
		var encPayload []byte
		var createdAt int64
		var previousHash, entryHash sql.NullString

		if err := rows.Scan(&eventID, &eventType, &sourceID, &encPayload, &createdAt, &previousHash, &entryHash); err != nil {
			return verified, fmt.Errorf("failed to scan event: %w", err)
		}

		// Skip events without hash (pre-DEV-025)
		if !entryHash.Valid || entryHash.String == "" {
			expectedPreviousHash = "legacy"
			verified++
			continue
		}

		// Verify previous hash matches
		if previousHash.Valid && previousHash.String != expectedPreviousHash {
			return verified, fmt.Errorf("chain broken at event %s: expected previous_hash %s, got %s",
				eventID, expectedPreviousHash, previousHash.String)
		}

		// Recompute hash to verify entry_hash
		hashInput := fmt.Sprintf("%s|%s|%s|%s|%x|%d",
			expectedPreviousHash, eventID, eventType, sourceID, encPayload, createdAt)
		computedHash := fmt.Sprintf("%x", sha256.Sum256([]byte(hashInput)))

		if computedHash != entryHash.String {
			return verified, fmt.Errorf("hash mismatch at event %s: computed %s, stored %s",
				eventID, computedHash, entryHash.String)
		}

		expectedPreviousHash = entryHash.String
		verified++
	}

	return verified, nil
}

// GetChainHead returns the hash of the most recent event for chain continuation
func (s *SQLiteStorage) GetChainHead() (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var hash sql.NullString
	err := s.db.QueryRow(`SELECT entry_hash FROM events ORDER BY sync_sequence DESC LIMIT 1`).Scan(&hash)
	if err == sql.ErrNoRows {
		return "genesis", nil
	}
	if err != nil {
		return "", err
	}
	if !hash.Valid || hash.String == "" {
		return "genesis", nil
	}
	return hash.String, nil
}

// scanEventRows scans multiple event rows and decrypts payloads
func (s *SQLiteStorage) scanEventRows(rows *sql.Rows) ([]EventRecord, error) {
	var events []EventRecord

	for rows.Next() {
		var event EventRecord
		var encPayload []byte
		var readAt, actionedAt, archivedAt, expiresAt sql.NullInt64

		if err := rows.Scan(
			&event.EventID, &event.EventType, &event.SourceType, &event.SourceID, &encPayload,
			&event.FeedStatus, &event.ActionType, &event.Priority,
			&event.CreatedAt, &readAt, &actionedAt, &archivedAt, &expiresAt,
			&event.SyncSequence, &event.RetentionClass,
		); err != nil {
			return nil, fmt.Errorf("failed to scan event row: %w", err)
		}

		// Decrypt payload
		var err error
		event.Payload, err = s.decrypt(encPayload)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt event payload: %w", err)
		}

		// Convert nullable fields
		if readAt.Valid {
			event.ReadAt = &readAt.Int64
		}
		if actionedAt.Valid {
			event.ActionedAt = &actionedAt.Int64
		}
		if archivedAt.Valid {
			event.ArchivedAt = &archivedAt.Int64
		}
		if expiresAt.Valid {
			event.ExpiresAt = &expiresAt.Int64
		}

		events = append(events, event)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating event rows: %w", err)
	}

	return events, nil
}

// join is a simple string join helper (avoiding strings package import)
func join(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += sep + strs[i]
	}
	return result
}

// ===============================
// Service Contracts Operations
// ===============================
// These methods manage service connections including contracts,
// encryption keys, and authentication requests.

// ServiceContract represents a signed agreement between user and service
type ServiceContract struct {
	ContractID       string
	ConnectionID     string
	ServiceGUID      string
	Version          int
	Status           string // pending, active, superseded, rejected, expired
	ContractData     []byte // Decrypted contract terms
	UserSignature    []byte
	ServiceSignature []byte
	SignedAt         *int64
	Capabilities     string // Comma-separated: auth,authz,data,payment,call,notify
	CreatedAt        int64
	ExpiresAt        *int64
}

// ServiceConnectionKey represents per-connection encryption keys
type ServiceConnectionKey struct {
	ConnectionID     string
	ServiceGUID      string
	PrivateKey       []byte // Decrypted X25519 private key
	PublicKey        []byte
	ServicePublicKey []byte
	SharedSecret     []byte // Decrypted cached ECDH result
	CreatedAt        int64
	RotatedAt        *int64
}

// ServiceAuthRequest represents a pending auth request from a service
type ServiceAuthRequest struct {
	RequestID         string
	ConnectionID      string
	ServiceGUID       string
	Challenge         []byte
	Status            string // pending, approved, denied, expired
	Context           string // JSON context from service
	CallbackSubject   string
	FeedEventID       string
	ResponseSignature []byte
	CreatedAt         int64
	RespondedAt       *int64
	ExpiresAt         int64
}

// StoreServiceContract stores a new service contract
func (s *SQLiteStorage) StoreServiceContract(contract *ServiceContract) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Encrypt contract data
	encContractData, err := s.encrypt(contract.ContractData)
	if err != nil {
		return fmt.Errorf("failed to encrypt contract data: %w", err)
	}

	_, err = s.db.Exec(`
		INSERT INTO service_contracts (
			contract_id, connection_id, service_guid, version, status,
			contract_data, user_signature, service_signature, signed_at,
			capabilities, created_at, expires_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		contract.ContractID, contract.ConnectionID, contract.ServiceGUID,
		contract.Version, contract.Status, encContractData,
		contract.UserSignature, contract.ServiceSignature, contract.SignedAt,
		contract.Capabilities, contract.CreatedAt, contract.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("failed to store service contract: %w", err)
	}

	s.incrementRollbackCounter()
	return nil
}

// GetServiceContract retrieves a contract by ID
func (s *SQLiteStorage) GetServiceContract(contractID string) (*ServiceContract, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var contract ServiceContract
	var encContractData []byte
	var signedAt, expiresAt sql.NullInt64

	err := s.db.QueryRow(`
		SELECT contract_id, connection_id, service_guid, version, status,
		       contract_data, user_signature, service_signature, signed_at,
		       capabilities, created_at, expires_at
		FROM service_contracts
		WHERE contract_id = ?
	`, contractID).Scan(
		&contract.ContractID, &contract.ConnectionID, &contract.ServiceGUID,
		&contract.Version, &contract.Status, &encContractData,
		&contract.UserSignature, &contract.ServiceSignature, &signedAt,
		&contract.Capabilities, &contract.CreatedAt, &expiresAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get service contract: %w", err)
	}

	// Decrypt contract data
	contract.ContractData, err = s.decrypt(encContractData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt contract data: %w", err)
	}

	if signedAt.Valid {
		contract.SignedAt = &signedAt.Int64
	}
	if expiresAt.Valid {
		contract.ExpiresAt = &expiresAt.Int64
	}

	return &contract, nil
}

// GetActiveContractByConnection returns the active contract for a connection
func (s *SQLiteStorage) GetActiveContractByConnection(connectionID string) (*ServiceContract, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var contract ServiceContract
	var encContractData []byte
	var signedAt, expiresAt sql.NullInt64

	err := s.db.QueryRow(`
		SELECT contract_id, connection_id, service_guid, version, status,
		       contract_data, user_signature, service_signature, signed_at,
		       capabilities, created_at, expires_at
		FROM service_contracts
		WHERE connection_id = ? AND status = 'active'
		ORDER BY version DESC
		LIMIT 1
	`, connectionID).Scan(
		&contract.ContractID, &contract.ConnectionID, &contract.ServiceGUID,
		&contract.Version, &contract.Status, &encContractData,
		&contract.UserSignature, &contract.ServiceSignature, &signedAt,
		&contract.Capabilities, &contract.CreatedAt, &expiresAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get active contract: %w", err)
	}

	contract.ContractData, err = s.decrypt(encContractData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt contract data: %w", err)
	}

	if signedAt.Valid {
		contract.SignedAt = &signedAt.Int64
	}
	if expiresAt.Valid {
		contract.ExpiresAt = &expiresAt.Int64
	}

	return &contract, nil
}

// ListContractsByService returns all contracts for a service
func (s *SQLiteStorage) ListContractsByService(serviceGUID string, includeInactive bool) ([]ServiceContract, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
		SELECT contract_id, connection_id, service_guid, version, status,
		       contract_data, user_signature, service_signature, signed_at,
		       capabilities, created_at, expires_at
		FROM service_contracts
		WHERE service_guid = ?
	`
	if !includeInactive {
		query += ` AND status = 'active'`
	}
	query += ` ORDER BY created_at DESC`

	rows, err := s.db.Query(query, serviceGUID)
	if err != nil {
		return nil, fmt.Errorf("failed to list contracts: %w", err)
	}
	defer rows.Close()

	var contracts []ServiceContract
	for rows.Next() {
		var contract ServiceContract
		var encContractData []byte
		var signedAt, expiresAt sql.NullInt64

		if err := rows.Scan(
			&contract.ContractID, &contract.ConnectionID, &contract.ServiceGUID,
			&contract.Version, &contract.Status, &encContractData,
			&contract.UserSignature, &contract.ServiceSignature, &signedAt,
			&contract.Capabilities, &contract.CreatedAt, &expiresAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan contract: %w", err)
		}

		contract.ContractData, err = s.decrypt(encContractData)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt contract data: %w", err)
		}

		if signedAt.Valid {
			contract.SignedAt = &signedAt.Int64
		}
		if expiresAt.Valid {
			contract.ExpiresAt = &expiresAt.Int64
		}

		contracts = append(contracts, contract)
	}

	return contracts, nil
}

// UpdateContractStatus updates the status of a contract
func (s *SQLiteStorage) UpdateContractStatus(contractID, newStatus string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.Exec(`
		UPDATE service_contracts SET status = ? WHERE contract_id = ?
	`, newStatus, contractID)
	if err != nil {
		return fmt.Errorf("failed to update contract status: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("contract not found: %s", contractID)
	}

	s.incrementRollbackCounter()
	return nil
}

// SignContract updates a contract with signatures
func (s *SQLiteStorage) SignContract(contractID string, userSig, serviceSig []byte, signedAt int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.Exec(`
		UPDATE service_contracts
		SET user_signature = ?, service_signature = ?, signed_at = ?, status = 'active'
		WHERE contract_id = ?
	`, userSig, serviceSig, signedAt, contractID)
	if err != nil {
		return fmt.Errorf("failed to sign contract: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("contract not found: %s", contractID)
	}

	s.incrementRollbackCounter()
	return nil
}

// ===============================
// Service Connection Key Operations
// ===============================

// StoreConnectionKey stores a new connection key pair
func (s *SQLiteStorage) StoreConnectionKey(key *ServiceConnectionKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Encrypt private key and shared secret
	encPrivateKey, err := s.encrypt(key.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt private key: %w", err)
	}

	var encSharedSecret []byte
	if key.SharedSecret != nil {
		encSharedSecret, err = s.encrypt(key.SharedSecret)
		if err != nil {
			return fmt.Errorf("failed to encrypt shared secret: %w", err)
		}
	}

	_, err = s.db.Exec(`
		INSERT INTO service_connection_keys (
			connection_id, service_guid, private_key, public_key,
			service_public_key, shared_secret, created_at, rotated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`,
		key.ConnectionID, key.ServiceGUID, encPrivateKey, key.PublicKey,
		key.ServicePublicKey, encSharedSecret, key.CreatedAt, key.RotatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to store connection key: %w", err)
	}

	s.incrementRollbackCounter()
	return nil
}

// GetConnectionKey retrieves connection keys by connection ID
func (s *SQLiteStorage) GetConnectionKey(connectionID string) (*ServiceConnectionKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var key ServiceConnectionKey
	var encPrivateKey []byte
	var encSharedSecret []byte
	var rotatedAt sql.NullInt64

	err := s.db.QueryRow(`
		SELECT connection_id, service_guid, private_key, public_key,
		       service_public_key, shared_secret, created_at, rotated_at
		FROM service_connection_keys
		WHERE connection_id = ?
	`, connectionID).Scan(
		&key.ConnectionID, &key.ServiceGUID, &encPrivateKey, &key.PublicKey,
		&key.ServicePublicKey, &encSharedSecret, &key.CreatedAt, &rotatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get connection key: %w", err)
	}

	// Decrypt private key
	key.PrivateKey, err = s.decrypt(encPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt private key: %w", err)
	}

	// Decrypt shared secret if present
	if len(encSharedSecret) > 0 {
		key.SharedSecret, err = s.decrypt(encSharedSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt shared secret: %w", err)
		}
	}

	if rotatedAt.Valid {
		key.RotatedAt = &rotatedAt.Int64
	}

	return &key, nil
}

// UpdateConnectionKeySharedSecret updates the cached shared secret
func (s *SQLiteStorage) UpdateConnectionKeySharedSecret(connectionID string, servicePubKey, sharedSecret []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	encSharedSecret, err := s.encrypt(sharedSecret)
	if err != nil {
		return fmt.Errorf("failed to encrypt shared secret: %w", err)
	}

	result, err := s.db.Exec(`
		UPDATE service_connection_keys
		SET service_public_key = ?, shared_secret = ?
		WHERE connection_id = ?
	`, servicePubKey, encSharedSecret, connectionID)
	if err != nil {
		return fmt.Errorf("failed to update shared secret: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("connection key not found: %s", connectionID)
	}

	s.incrementRollbackCounter()
	return nil
}

// DeleteConnectionKey deletes connection keys
func (s *SQLiteStorage) DeleteConnectionKey(connectionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`DELETE FROM service_connection_keys WHERE connection_id = ?`, connectionID)
	if err != nil {
		return fmt.Errorf("failed to delete connection key: %w", err)
	}

	s.incrementRollbackCounter()
	return nil
}

// ===============================
// Service Auth Request Operations
// ===============================

// StoreAuthRequest stores a new auth request from a service
func (s *SQLiteStorage) StoreAuthRequest(req *ServiceAuthRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`
		INSERT INTO service_auth_requests (
			request_id, connection_id, service_guid, challenge, status,
			context, callback_subject, feed_event_id, response_signature,
			created_at, responded_at, expires_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		req.RequestID, req.ConnectionID, req.ServiceGUID, req.Challenge, req.Status,
		req.Context, req.CallbackSubject, req.FeedEventID, req.ResponseSignature,
		req.CreatedAt, req.RespondedAt, req.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("failed to store auth request: %w", err)
	}

	s.incrementRollbackCounter()
	return nil
}

// GetAuthRequest retrieves an auth request by ID
func (s *SQLiteStorage) GetAuthRequest(requestID string) (*ServiceAuthRequest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var req ServiceAuthRequest
	var respondedAt sql.NullInt64

	err := s.db.QueryRow(`
		SELECT request_id, connection_id, service_guid, challenge, status,
		       context, callback_subject, feed_event_id, response_signature,
		       created_at, responded_at, expires_at
		FROM service_auth_requests
		WHERE request_id = ?
	`, requestID).Scan(
		&req.RequestID, &req.ConnectionID, &req.ServiceGUID, &req.Challenge, &req.Status,
		&req.Context, &req.CallbackSubject, &req.FeedEventID, &req.ResponseSignature,
		&req.CreatedAt, &respondedAt, &req.ExpiresAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get auth request: %w", err)
	}

	if respondedAt.Valid {
		req.RespondedAt = &respondedAt.Int64
	}

	return &req, nil
}

// GetPendingAuthRequests returns pending auth requests for a connection
func (s *SQLiteStorage) GetPendingAuthRequests(connectionID string) ([]ServiceAuthRequest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now().Unix()
	rows, err := s.db.Query(`
		SELECT request_id, connection_id, service_guid, challenge, status,
		       context, callback_subject, feed_event_id, response_signature,
		       created_at, responded_at, expires_at
		FROM service_auth_requests
		WHERE connection_id = ? AND status = 'pending' AND expires_at > ?
		ORDER BY created_at DESC
	`, connectionID, now)
	if err != nil {
		return nil, fmt.Errorf("failed to get pending auth requests: %w", err)
	}
	defer rows.Close()

	var requests []ServiceAuthRequest
	for rows.Next() {
		var req ServiceAuthRequest
		var respondedAt sql.NullInt64

		if err := rows.Scan(
			&req.RequestID, &req.ConnectionID, &req.ServiceGUID, &req.Challenge, &req.Status,
			&req.Context, &req.CallbackSubject, &req.FeedEventID, &req.ResponseSignature,
			&req.CreatedAt, &respondedAt, &req.ExpiresAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan auth request: %w", err)
		}

		if respondedAt.Valid {
			req.RespondedAt = &respondedAt.Int64
		}

		requests = append(requests, req)
	}

	return requests, nil
}

// UpdateAuthRequestStatus updates the status of an auth request
func (s *SQLiteStorage) UpdateAuthRequestStatus(requestID, newStatus string, signature []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().Unix()
	result, err := s.db.Exec(`
		UPDATE service_auth_requests
		SET status = ?, response_signature = ?, responded_at = ?
		WHERE request_id = ?
	`, newStatus, signature, now, requestID)
	if err != nil {
		return fmt.Errorf("failed to update auth request status: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("auth request not found: %s", requestID)
	}

	s.incrementRollbackCounter()
	return nil
}

// CleanupExpiredAuthRequests removes expired auth requests
func (s *SQLiteStorage) CleanupExpiredAuthRequests() (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().Unix()
	result, err := s.db.Exec(`
		UPDATE service_auth_requests
		SET status = 'expired'
		WHERE status = 'pending' AND expires_at < ?
	`, now)
	if err != nil {
		return 0, fmt.Errorf("failed to expire auth requests: %w", err)
	}

	expired, _ := result.RowsAffected()

	// Delete old expired/denied requests (older than 7 days)
	cutoff := now - 7*24*3600
	result, err = s.db.Exec(`
		DELETE FROM service_auth_requests
		WHERE status IN ('expired', 'denied') AND created_at < ?
	`, cutoff)
	if err != nil {
		return expired, fmt.Errorf("failed to cleanup old auth requests: %w", err)
	}

	deleted, _ := result.RowsAffected()
	if expired+deleted > 0 {
		s.incrementRollbackCounter()
	}

	return expired + deleted, nil
}
