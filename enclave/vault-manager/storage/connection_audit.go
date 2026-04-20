package storage

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// AuditEntryRecord is the persistence shape of an audit-trail row.
// The vault-manager package keeps its own richer type that serializes to
// the `payload` column; this record is just the indexable columns plus
// the raw payload blob so pagination + type filter + FTS can run in SQL.
type AuditEntryRecord struct {
	EntryID      string
	ConnectionID string
	PeerGUID     string
	EventType    string
	Direction    string
	Title        string
	Body         string
	CreatedAt    int64
	Payload      []byte
}

// AuditListOptions controls list pagination and filtering.
type AuditListOptions struct {
	ConnectionID string
	Limit        int
	// Cursor: (created_at, entry_id) from the previous page's last row.
	// Zero values mean "start from the top".
	CursorCreatedAt int64
	CursorEntryID   string
	SinceEpoch      int64
	UntilEpoch      int64 // Exclude entries with created_at >= this value (exclusive upper bound).
	// Prefix match; "message." matches message.sent / message.received.
	EventTypePrefixes []string
}

// AuditListResult pairs the returned records with the cursor for the next
// page.
type AuditListResult struct {
	Entries    []AuditEntryRecord
	NextCursor *AuditCursor
}

// AuditCursor is the opaque pagination token returned to callers.
type AuditCursor struct {
	CreatedAt int64
	EntryID   string
}

// Retention policy (plan §8): cap at max entries OR 2 years, whichever
// hits first. Trimming runs inline on append so the steady-state size
// per connection stays bounded. Cheap in practice — the DELETE is a
// no-op below cap and rarely deletes more than one row at a time.
const (
	auditMaxEntriesPerConnection = 10000
	auditMaxAgeSeconds           = 2 * 365 * 24 * 60 * 60 // ~2 years
)

// AppendAuditEntry inserts one audit row. Safe to call from any handler
// — does not increment the rollback counter because a missing audit
// entry is less bad than a failing primary operation.
func (s *SQLiteStorage) AppendAuditEntry(r AuditEntryRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if r.CreatedAt == 0 {
		r.CreatedAt = time.Now().Unix()
	}

	_, err := s.db.Exec(`
		INSERT INTO connection_audit
			(entry_id, connection_id, peer_guid, event_type, direction,
			 title, body, created_at, payload)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		r.EntryID, r.ConnectionID, nullIfEmpty(r.PeerGUID), r.EventType,
		nullIfEmpty(r.Direction), r.Title, nullIfEmpty(r.Body),
		r.CreatedAt, r.Payload,
	)
	if err != nil {
		return fmt.Errorf("append audit entry: %w", err)
	}

	s.trimAuditEntriesLocked(r.ConnectionID)
	return nil
}

// trimAuditEntriesLocked enforces the retention policy for one
// connection. Caller holds s.mu. Runs two cheap DELETEs:
//   - rows older than the age cap (uses idx_connection_audit_conn_created)
//   - rows past the entry-count cap (anti-join on the top-N rowids)
//
// FTS5 content stays in sync via the AFTER DELETE trigger on the
// connection_audit table.
func (s *SQLiteStorage) trimAuditEntriesLocked(connectionID string) {
	if connectionID == "" {
		return
	}
	cutoff := time.Now().Unix() - auditMaxAgeSeconds
	if _, err := s.db.Exec(
		`DELETE FROM connection_audit WHERE connection_id = ? AND created_at < ?`,
		connectionID, cutoff,
	); err != nil {
		// Trim failures are not fatal — the next append will try again.
		return
	}
	_, _ = s.db.Exec(`
		DELETE FROM connection_audit
		WHERE connection_id = ?
		  AND rowid NOT IN (
		    SELECT rowid FROM connection_audit
		    WHERE connection_id = ?
		    ORDER BY created_at DESC, entry_id DESC
		    LIMIT ?
		  )
	`, connectionID, connectionID, auditMaxEntriesPerConnection)
}

// ListAuditEntries returns a page of entries for a connection, newest
// first. Empty ConnectionID is rejected — callers must scope the query.
func (s *SQLiteStorage) ListAuditEntries(opts AuditListOptions) (*AuditListResult, error) {
	if opts.ConnectionID == "" {
		return nil, fmt.Errorf("connection_id required")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	limit := opts.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	var (
		where []string
		args  []interface{}
	)
	where = append(where, "connection_id = ?")
	args = append(args, opts.ConnectionID)

	if opts.SinceEpoch > 0 {
		where = append(where, "created_at >= ?")
		args = append(args, opts.SinceEpoch)
	}
	if opts.UntilEpoch > 0 {
		where = append(where, "created_at < ?")
		args = append(args, opts.UntilEpoch)
	}

	// Cursor: rows strictly older than (cursor.created_at, cursor.entry_id)
	// when sorted by (created_at DESC, entry_id DESC).
	if opts.CursorCreatedAt > 0 && opts.CursorEntryID != "" {
		where = append(where, "(created_at < ? OR (created_at = ? AND entry_id < ?))")
		args = append(args, opts.CursorCreatedAt, opts.CursorCreatedAt, opts.CursorEntryID)
	}

	if len(opts.EventTypePrefixes) > 0 {
		placeholders := make([]string, len(opts.EventTypePrefixes))
		for i, p := range opts.EventTypePrefixes {
			placeholders[i] = "event_type LIKE ?"
			args = append(args, p+"%")
		}
		where = append(where, "("+strings.Join(placeholders, " OR ")+")")
	}

	q := `
		SELECT entry_id, connection_id, peer_guid, event_type, direction,
		       title, body, created_at, payload
		FROM connection_audit
		WHERE ` + strings.Join(where, " AND ") + `
		ORDER BY created_at DESC, entry_id DESC
		LIMIT ?
	`
	args = append(args, limit+1) // +1 to detect if more rows exist

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("list audit entries: %w", err)
	}
	defer rows.Close()

	entries := make([]AuditEntryRecord, 0, limit)
	for rows.Next() {
		var r AuditEntryRecord
		var peer, dir, body sql.NullString
		if err := rows.Scan(&r.EntryID, &r.ConnectionID, &peer, &r.EventType,
			&dir, &r.Title, &body, &r.CreatedAt, &r.Payload); err != nil {
			return nil, fmt.Errorf("scan audit row: %w", err)
		}
		r.PeerGUID = peer.String
		r.Direction = dir.String
		r.Body = body.String
		entries = append(entries, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	result := &AuditListResult{}
	if len(entries) > limit {
		last := entries[limit-1]
		result.NextCursor = &AuditCursor{CreatedAt: last.CreatedAt, EntryID: last.EntryID}
		entries = entries[:limit]
	}
	result.Entries = entries
	return result, nil
}

// AuditSearchOptions adds a FTS5 query string on top of the list options.
type AuditSearchOptions struct {
	ConnectionID      string
	Query             string
	Limit             int
	CursorCreatedAt   int64
	CursorEntryID     string
	EventTypePrefixes []string
}

// SearchAuditEntries runs a FTS5 MATCH across title + body, scoped to
// the connection. Empty Query degrades to a plain list.
func (s *SQLiteStorage) SearchAuditEntries(opts AuditSearchOptions) (*AuditListResult, error) {
	if opts.ConnectionID == "" {
		return nil, fmt.Errorf("connection_id required")
	}
	if strings.TrimSpace(opts.Query) == "" {
		return s.ListAuditEntries(AuditListOptions{
			ConnectionID:      opts.ConnectionID,
			Limit:             opts.Limit,
			CursorCreatedAt:   opts.CursorCreatedAt,
			CursorEntryID:     opts.CursorEntryID,
			EventTypePrefixes: opts.EventTypePrefixes,
		})
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	limit := opts.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	// FTS5 MATCH restricts candidate rows; further filters (connection
	// scope, cursor, type prefix) are applied in the outer SELECT so we
	// don't rely on FTS's unindexed-column storage for the connection id.
	var (
		where = []string{"ca.connection_id = ?"}
		args  = []interface{}{opts.ConnectionID}
	)

	if opts.CursorCreatedAt > 0 && opts.CursorEntryID != "" {
		where = append(where, "(ca.created_at < ? OR (ca.created_at = ? AND ca.entry_id < ?))")
		args = append(args, opts.CursorCreatedAt, opts.CursorCreatedAt, opts.CursorEntryID)
	}

	if len(opts.EventTypePrefixes) > 0 {
		placeholders := make([]string, len(opts.EventTypePrefixes))
		for i, p := range opts.EventTypePrefixes {
			placeholders[i] = "ca.event_type LIKE ?"
			args = append(args, p+"%")
		}
		where = append(where, "("+strings.Join(placeholders, " OR ")+")")
	}

	q := `
		SELECT ca.entry_id, ca.connection_id, ca.peer_guid, ca.event_type,
		       ca.direction, ca.title, ca.body, ca.created_at, ca.payload
		FROM connection_audit_fts fts
		JOIN connection_audit ca ON ca.rowid = fts.rowid
		WHERE fts.connection_audit_fts MATCH ?
		  AND ` + strings.Join(where, " AND ") + `
		ORDER BY ca.created_at DESC, ca.entry_id DESC
		LIMIT ?
	`

	fullArgs := append([]interface{}{sanitizeFtsQuery(opts.Query)}, args...)
	fullArgs = append(fullArgs, limit+1)

	rows, err := s.db.Query(q, fullArgs...)
	if err != nil {
		return nil, fmt.Errorf("search audit entries: %w", err)
	}
	defer rows.Close()

	entries := make([]AuditEntryRecord, 0, limit)
	for rows.Next() {
		var r AuditEntryRecord
		var peer, dir, body sql.NullString
		if err := rows.Scan(&r.EntryID, &r.ConnectionID, &peer, &r.EventType,
			&dir, &r.Title, &body, &r.CreatedAt, &r.Payload); err != nil {
			return nil, fmt.Errorf("scan audit search row: %w", err)
		}
		r.PeerGUID = peer.String
		r.Direction = dir.String
		r.Body = body.String
		entries = append(entries, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	result := &AuditListResult{}
	if len(entries) > limit {
		last := entries[limit-1]
		result.NextCursor = &AuditCursor{CreatedAt: last.CreatedAt, EntryID: last.EntryID}
		entries = entries[:limit]
	}
	result.Entries = entries
	return result, nil
}

// AuditEntryCount returns the approximate number of entries for a
// connection. Used for UI hints ("… of N events").
func (s *SQLiteStorage) AuditEntryCount(connectionID string) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var n int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM connection_audit WHERE connection_id = ?`,
		connectionID,
	).Scan(&n)
	return n, err
}

// AuditEntryExists lets the backfill routine skip connections that
// have already been filled in.
func (s *SQLiteStorage) AuditEntryExists(entryID string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var exists int
	err := s.db.QueryRow(
		`SELECT 1 FROM connection_audit WHERE entry_id = ? LIMIT 1`,
		entryID,
	).Scan(&exists)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

func nullIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// sanitizeFtsQuery keeps the caller's query safe for FTS5 MATCH. FTS5
// interprets punctuation like " and : as operators; stray operators from
// a human typing a phrase produce syntax errors. Strip characters FTS5
// treats specially and fall back to a prefix match on each word so the
// UI search-as-you-type feels right.
func sanitizeFtsQuery(q string) string {
	q = strings.TrimSpace(q)
	// Remove characters FTS5 uses as syntax.
	bad := []string{"\"", "'", ":", "^", "*", "(", ")", "-", "+", "~"}
	for _, b := range bad {
		q = strings.ReplaceAll(q, b, " ")
	}
	// Tokenize on whitespace, append a prefix star to each term.
	words := strings.Fields(q)
	if len(words) == 0 {
		return ""
	}
	for i, w := range words {
		words[i] = w + "*"
	}
	return strings.Join(words, " ")
}
