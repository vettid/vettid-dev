package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"
)

// DBQueryBridge is a lightweight HTTP server that accepts SQL queries via HTTP POST
// and executes them against PostgreSQL. It runs on localhost:5433 — only accessible
// from the enclave via the HTTP proxy (vsock boundary is the trust perimeter).
//
// SECURITY: Credentials arrive in HTTP headers from the enclave. They travel over
// vsock (same host, mutually authenticated). The bridge opens an ephemeral PostgreSQL
// connection per query — no connection pooling, no credential caching.
type DBQueryBridge struct {
	listenAddr string
	server     *http.Server
}

// DBQueryRequest is the JSON body for a query request.
type DBQueryRequest struct {
	Query  string        `json:"query"`
	Params []interface{} `json:"params,omitempty"`
}

// DBQueryResponse is the JSON response from a query execution.
type DBQueryResponse struct {
	Columns  []string          `json:"columns"`
	Rows     []json.RawMessage `json:"rows"`
	RowCount int               `json:"row_count"`
	Error    string            `json:"error,omitempty"`
}

// NewDBQueryBridge creates a new DB query bridge.
func NewDBQueryBridge(listenAddr string) *DBQueryBridge {
	return &DBQueryBridge{
		listenAddr: listenAddr,
	}
}

// Start starts the DB query bridge HTTP server.
func (b *DBQueryBridge) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/query", b.handleQuery)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	b.server = &http.Server{
		Addr:         b.listenAddr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	// SECURITY: Only bind to localhost
	listener, err := net.Listen("tcp", b.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to bind DB query bridge: %w", err)
	}

	log.Info().Str("addr", b.listenAddr).Msg("DB query bridge started")

	go func() {
		<-ctx.Done()
		b.server.Shutdown(context.Background())
	}()

	go func() {
		if err := b.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Msg("DB query bridge error")
		}
	}()

	return nil
}

// handleQuery processes a POST /query request.
func (b *DBQueryBridge) handleQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// SECURITY: Only accept from localhost
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if host != "127.0.0.1" && host != "::1" {
		log.Warn().Str("remote", r.RemoteAddr).Msg("SECURITY: Rejected non-localhost DB query")
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// Read DB credentials from headers
	dbHost := r.Header.Get("X-DB-Host")
	dbPort := r.Header.Get("X-DB-Port")
	dbName := r.Header.Get("X-DB-Name")
	dbUser := r.Header.Get("X-DB-User")
	dbPassword := r.Header.Get("X-DB-Password")
	dbSSLMode := r.Header.Get("X-DB-SSLMode")

	if dbHost == "" || dbUser == "" || dbName == "" {
		writeJSONError(w, "missing required DB credentials in headers")
		return
	}
	if dbPort == "" {
		dbPort = "5432"
	}
	if dbSSLMode == "" {
		dbSSLMode = "require"
	}

	// Parse request body
	var req DBQueryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "invalid request body: "+err.Error())
		return
	}
	defer r.Body.Close()

	if req.Query == "" {
		writeJSONError(w, "query is required")
		return
	}

	// Build connection string
	connStr := fmt.Sprintf("host=%s port=%s dbname=%s user=%s password=%s sslmode=%s",
		dbHost, dbPort, dbName, dbUser, dbPassword, dbSSLMode)

	// SECURITY: Ephemeral connection — open, execute, close. No pooling.
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, connStr)
	if err != nil {
		log.Error().Err(err).Str("host", dbHost).Msg("Failed to connect to database")
		writeJSONError(w, "database connection failed")
		return
	}
	defer conn.Close(ctx)

	// Execute the parameterized query
	rows, err := conn.Query(ctx, req.Query, req.Params...)
	if err != nil {
		log.Error().Err(err).Msg("Query execution failed")
		writeJSONError(w, "query execution failed: "+err.Error())
		return
	}
	defer rows.Close()

	// Get column names
	fieldDescriptions := rows.FieldDescriptions()
	columns := make([]string, len(fieldDescriptions))
	for i, fd := range fieldDescriptions {
		columns[i] = string(fd.Name)
	}

	// Read all rows
	var resultRows []json.RawMessage
	for rows.Next() {
		values, err := rows.Values()
		if err != nil {
			writeJSONError(w, "failed to read row: "+err.Error())
			return
		}

		// Convert row to a map of column→value
		rowMap := make(map[string]interface{})
		for i, col := range columns {
			if i < len(values) {
				rowMap[col] = values[i]
			}
		}

		rowJSON, err := json.Marshal(rowMap)
		if err != nil {
			writeJSONError(w, "failed to marshal row: "+err.Error())
			return
		}
		resultRows = append(resultRows, rowJSON)
	}

	if err := rows.Err(); err != nil {
		writeJSONError(w, "row iteration error: "+err.Error())
		return
	}

	// Write response
	resp := DBQueryResponse{
		Columns:  columns,
		Rows:     resultRows,
		RowCount: len(resultRows),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// writeJSONError writes a JSON error response.
func writeJSONError(w http.ResponseWriter, errMsg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	json.NewEncoder(w).Encode(DBQueryResponse{Error: errMsg})
}
