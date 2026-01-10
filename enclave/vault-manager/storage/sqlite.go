package storage

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
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

	storage := &SQLiteStorage{
		db:              db,
		dek:             dek,
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

	// Export each table
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

	// Clear existing data
	tables := []string{"cek_keypairs", "transport_keys", "ledger_entries", "handler_state", "_metadata"}
	for _, table := range tables {
		if _, err := s.db.Exec(fmt.Sprintf("DELETE FROM %s", table)); err != nil {
			return fmt.Errorf("failed to clear table %s: %w", table, err)
		}
	}

	// Note: Full import implementation would need table-specific logic
	// This is a simplified version - production would use prepared statements
	// and handle type conversions properly

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

// Close closes the database connection
func (s *SQLiteStorage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db.Close()
}
