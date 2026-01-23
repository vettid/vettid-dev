package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
)

// DatastoreAuditHandler manages comprehensive audit logging for combined datastores.
// All operations are logged with tamper-evident hash chains.
type DatastoreAuditHandler struct {
	ownerSpace       string
	storage          *EncryptedStorage
	datastoreHandler *CombinedDatastoreHandler
}

// NewDatastoreAuditHandler creates a new audit handler
func NewDatastoreAuditHandler(
	ownerSpace string,
	storage *EncryptedStorage,
	datastoreHandler *CombinedDatastoreHandler,
) *DatastoreAuditHandler {
	return &DatastoreAuditHandler{
		ownerSpace:       ownerSpace,
		storage:          storage,
		datastoreHandler: datastoreHandler,
	}
}

// --- Data Models ---

// DatastoreAuditEntry represents a single audit log entry
type DatastoreAuditEntry struct {
	ID           string                 `json:"id"`
	DatastoreID  string                 `json:"datastore_id"`
	Timestamp    time.Time              `json:"timestamp"`
	ServiceID    string                 `json:"service_id"`
	ServiceName  string                 `json:"service_name"`
	Operation    DatastoreOperation     `json:"operation"`
	Fields       []string               `json:"fields,omitempty"`
	OldValues    map[string]interface{} `json:"old_values,omitempty"`
	NewValues    map[string]interface{} `json:"new_values,omitempty"`
	RequestID    string                 `json:"request_id,omitempty"` // Correlation
	Result       AuditResult            `json:"result"`
	ErrorMessage string                 `json:"error,omitempty"`
	// Hash chain for tamper evidence
	EntryHash    string `json:"entry_hash"`
	PreviousHash string `json:"previous_hash"`
}

// DatastoreOperation represents the type of operation
type DatastoreOperation string

const (
	OpRead             DatastoreOperation = "read"
	OpWrite            DatastoreOperation = "write"
	OpDelete           DatastoreOperation = "delete"
	OpSubscribe        DatastoreOperation = "subscribe"
	OpUnsubscribe      DatastoreOperation = "unsubscribe"
	OpInvite           DatastoreOperation = "invite"
	OpJoin             DatastoreOperation = "join"
	OpLeave            DatastoreOperation = "leave"
	OpPermissionChange DatastoreOperation = "permission_change"
	OpCreate           DatastoreOperation = "create"
	OpApprove          DatastoreOperation = "approve"
	OpReject           DatastoreOperation = "reject"
)

// AuditResult represents the outcome of an operation
type AuditResult string

const (
	ResultSuccess AuditResult = "success"
	ResultDenied  AuditResult = "denied"
	ResultError   AuditResult = "error"
)

// AuditChainState tracks the hash chain state
type AuditChainState struct {
	DatastoreID   string `json:"datastore_id"`
	LastEntryID   string `json:"last_entry_id"`
	LastEntryHash string `json:"last_entry_hash"`
	EntryCount    int64  `json:"entry_count"`
}

// Storage keys
const (
	KeyAuditPrefix      = "datastore-audit/"       // datastore-audit/{datastore_id}/{entry_id}
	KeyAuditIndex       = "datastore-audit-index/" // datastore-audit-index/{datastore_id}
	KeyAuditChainState  = "datastore-audit-chain/" // datastore-audit-chain/{datastore_id}
)

// --- Request/Response Types ---

// DatastoreAuditQuery is the payload for datastore.audit.query
type DatastoreAuditQuery struct {
	DatastoreID *string             `json:"datastore_id,omitempty"`
	ServiceID   *string             `json:"service_id,omitempty"`
	Operation   *DatastoreOperation `json:"operation,omitempty"`
	StartTime   *time.Time          `json:"start_time,omitempty"`
	EndTime     *time.Time          `json:"end_time,omitempty"`
	Result      *AuditResult        `json:"result,omitempty"`
	Limit       int                 `json:"limit"`
	Offset      int                 `json:"offset"`
}

// DatastoreAuditQueryResponse is the response for datastore.audit.query
type DatastoreAuditQueryResponse struct {
	Entries []DatastoreAuditEntry `json:"entries"`
	Total   int                   `json:"total"`
}

// DatastoreAuditExportRequest is the payload for datastore.audit.export
type DatastoreAuditExportRequest struct {
	DatastoreID string     `json:"datastore_id"`
	Format      string     `json:"format"` // "json" or "csv"
	StartTime   *time.Time `json:"start_time,omitempty"`
	EndTime     *time.Time `json:"end_time,omitempty"`
}

// DatastoreAuditExportResponse is the response for datastore.audit.export
type DatastoreAuditExportResponse struct {
	Success bool   `json:"success"`
	Data    string `json:"data"` // JSON or CSV formatted data
	Format  string `json:"format"`
	Count   int    `json:"count"`
}

// VerifyChainRequest is the payload for datastore.audit.verify
type VerifyChainRequest struct {
	DatastoreID string `json:"datastore_id"`
}

// VerifyChainResponse is the response for datastore.audit.verify
type VerifyChainResponse struct {
	Success      bool      `json:"success"`
	Valid        bool      `json:"valid"`
	EntryCount   int64     `json:"entry_count"`
	FirstEntry   time.Time `json:"first_entry,omitempty"`
	LastEntry    time.Time `json:"last_entry,omitempty"`
	InvalidEntry *string   `json:"invalid_entry,omitempty"` // First invalid entry ID if any
	Message      string    `json:"message,omitempty"`
}

// --- Audit Logging ---

// LogOperation logs a datastore operation to the audit trail
func (h *DatastoreAuditHandler) LogOperation(
	ctx context.Context,
	datastoreID string,
	serviceID string,
	serviceName string,
	operation DatastoreOperation,
	fields []string,
	oldValues map[string]interface{},
	newValues map[string]interface{},
	requestID string,
	result AuditResult,
	errorMessage string,
) error {
	// Generate entry ID
	entryID := generateAuditEntryID()

	// Get previous hash from chain state
	previousHash := ""
	chainState, err := h.getChainState(datastoreID)
	if err == nil && chainState != nil {
		previousHash = chainState.LastEntryHash
	}

	// Create entry
	entry := &DatastoreAuditEntry{
		ID:           entryID,
		DatastoreID:  datastoreID,
		Timestamp:    time.Now(),
		ServiceID:    serviceID,
		ServiceName:  serviceName,
		Operation:    operation,
		Fields:       fields,
		OldValues:    oldValues,
		NewValues:    newValues,
		RequestID:    requestID,
		Result:       result,
		ErrorMessage: errorMessage,
		PreviousHash: previousHash,
	}

	// Compute entry hash
	entry.EntryHash = h.computeEntryHash(entry)

	// Store entry
	entryKey := fmt.Sprintf("%s%s/%s", KeyAuditPrefix, datastoreID, entryID)
	if err := h.storage.PutJSON(entryKey, entry); err != nil {
		return fmt.Errorf("failed to store audit entry: %w", err)
	}

	// Update index
	indexKey := KeyAuditIndex + datastoreID
	if err := h.storage.AddToIndex(indexKey, entryID); err != nil {
		log.Warn().Err(err).Msg("Failed to update audit index")
	}

	// Update chain state
	newState := &AuditChainState{
		DatastoreID:   datastoreID,
		LastEntryID:   entryID,
		LastEntryHash: entry.EntryHash,
		EntryCount:    1,
	}
	if chainState != nil {
		newState.EntryCount = chainState.EntryCount + 1
	}
	if err := h.storeChainState(newState); err != nil {
		log.Warn().Err(err).Msg("Failed to update chain state")
	}

	log.Debug().
		Str("entry_id", entryID).
		Str("datastore_id", datastoreID).
		Str("operation", string(operation)).
		Str("result", string(result)).
		Msg("Audit entry logged")

	return nil
}

// computeEntryHash computes the SHA256 hash of an entry
func (h *DatastoreAuditHandler) computeEntryHash(entry *DatastoreAuditEntry) string {
	// Serialize deterministically
	data := fmt.Sprintf("%s|%s|%d|%s|%s|%s|%s|%s",
		entry.ID,
		entry.DatastoreID,
		entry.Timestamp.UnixNano(),
		entry.ServiceID,
		entry.Operation,
		entry.Result,
		entry.PreviousHash,
		serializeFields(entry.Fields),
	)

	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func serializeFields(fields []string) string {
	data, _ := json.Marshal(fields)
	return string(data)
}

// --- Handlers ---

// HandleQuery handles datastore.audit.query
func (h *DatastoreAuditHandler) HandleQuery(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var query DatastoreAuditQuery
	if err := json.Unmarshal(msg.Payload, &query); err != nil {
		return h.errorResponse(msg.GetID(), "invalid query payload")
	}

	// Set defaults
	if query.Limit <= 0 || query.Limit > 1000 {
		query.Limit = 100
	}

	// Get entries for the datastore(s)
	var allEntries []DatastoreAuditEntry

	if query.DatastoreID != nil {
		// Query specific datastore
		entries, err := h.getEntriesForDatastore(*query.DatastoreID)
		if err != nil {
			return h.errorResponse(msg.GetID(), "failed to query entries")
		}
		allEntries = entries
	} else {
		// Query all datastores
		datastoreIDs, err := h.storage.GetIndex(KeyDatastoreIndex)
		if err != nil {
			return h.errorResponse(msg.GetID(), "failed to list datastores")
		}
		for _, dsID := range datastoreIDs {
			entries, err := h.getEntriesForDatastore(dsID)
			if err != nil {
				continue
			}
			allEntries = append(allEntries, entries...)
		}
	}

	// Apply filters
	var filtered []DatastoreAuditEntry
	for _, entry := range allEntries {
		if query.ServiceID != nil && entry.ServiceID != *query.ServiceID {
			continue
		}
		if query.Operation != nil && entry.Operation != *query.Operation {
			continue
		}
		if query.Result != nil && entry.Result != *query.Result {
			continue
		}
		if query.StartTime != nil && entry.Timestamp.Before(*query.StartTime) {
			continue
		}
		if query.EndTime != nil && entry.Timestamp.After(*query.EndTime) {
			continue
		}
		filtered = append(filtered, entry)
	}

	// Apply pagination
	total := len(filtered)
	start := query.Offset
	end := start + query.Limit
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}
	filtered = filtered[start:end]

	return h.successResponse(msg.GetID(), DatastoreAuditQueryResponse{
		Entries: filtered,
		Total:   total,
	})
}

// HandleExport handles datastore.audit.export
func (h *DatastoreAuditHandler) HandleExport(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req DatastoreAuditExportRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "invalid export request")
	}

	// Get entries
	entries, err := h.getEntriesForDatastore(req.DatastoreID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "failed to get entries")
	}

	// Apply time filters
	var filtered []DatastoreAuditEntry
	for _, entry := range entries {
		if req.StartTime != nil && entry.Timestamp.Before(*req.StartTime) {
			continue
		}
		if req.EndTime != nil && entry.Timestamp.After(*req.EndTime) {
			continue
		}
		filtered = append(filtered, entry)
	}

	// Format output
	var data string
	format := req.Format
	if format == "" {
		format = "json"
	}

	if format == "csv" {
		data = h.formatAsCSV(filtered)
	} else {
		jsonData, _ := json.MarshalIndent(filtered, "", "  ")
		data = string(jsonData)
	}

	return h.successResponse(msg.GetID(), DatastoreAuditExportResponse{
		Success: true,
		Data:    data,
		Format:  format,
		Count:   len(filtered),
	})
}

// HandleVerifyChain handles datastore.audit.verify - verify chain integrity
func (h *DatastoreAuditHandler) HandleVerifyChain(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req VerifyChainRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return h.errorResponse(msg.GetID(), "invalid verify request")
	}

	// Get all entries
	entries, err := h.getEntriesForDatastore(req.DatastoreID)
	if err != nil {
		return h.errorResponse(msg.GetID(), "failed to get entries")
	}

	if len(entries) == 0 {
		return h.successResponse(msg.GetID(), VerifyChainResponse{
			Success:    true,
			Valid:      true,
			EntryCount: 0,
			Message:    "No entries to verify",
		})
	}

	// Verify chain
	var invalidEntry *string
	valid := true
	previousHash := ""

	for i, entry := range entries {
		// Check previous hash matches
		if entry.PreviousHash != previousHash {
			valid = false
			invalidEntry = &entry.ID
			break
		}

		// Recompute and verify entry hash
		expectedHash := h.computeEntryHash(&entries[i])
		if entry.EntryHash != expectedHash {
			valid = false
			invalidEntry = &entry.ID
			break
		}

		previousHash = entry.EntryHash
	}

	response := VerifyChainResponse{
		Success:      true,
		Valid:        valid,
		EntryCount:   int64(len(entries)),
		FirstEntry:   entries[0].Timestamp,
		LastEntry:    entries[len(entries)-1].Timestamp,
		InvalidEntry: invalidEntry,
	}

	if valid {
		response.Message = "Audit chain integrity verified"
	} else {
		response.Message = "Audit chain integrity violation detected"
	}

	return h.successResponse(msg.GetID(), response)
}

// --- Helper Methods ---

func (h *DatastoreAuditHandler) getEntriesForDatastore(datastoreID string) ([]DatastoreAuditEntry, error) {
	indexKey := KeyAuditIndex + datastoreID
	entryIDs, err := h.storage.GetIndex(indexKey)
	if err != nil {
		return nil, err
	}

	var entries []DatastoreAuditEntry
	for _, entryID := range entryIDs {
		entryKey := fmt.Sprintf("%s%s/%s", KeyAuditPrefix, datastoreID, entryID)
		var entry DatastoreAuditEntry
		if err := h.storage.GetJSON(entryKey, &entry); err != nil {
			continue
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

func (h *DatastoreAuditHandler) getChainState(datastoreID string) (*AuditChainState, error) {
	key := KeyAuditChainState + datastoreID
	var state AuditChainState
	if err := h.storage.GetJSON(key, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

func (h *DatastoreAuditHandler) storeChainState(state *AuditChainState) error {
	key := KeyAuditChainState + state.DatastoreID
	return h.storage.PutJSON(key, state)
}

func (h *DatastoreAuditHandler) formatAsCSV(entries []DatastoreAuditEntry) string {
	// Header
	csv := "id,datastore_id,timestamp,service_id,service_name,operation,result,error\n"

	for _, e := range entries {
		csv += fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%s\n",
			e.ID,
			e.DatastoreID,
			e.Timestamp.Format(time.RFC3339),
			e.ServiceID,
			e.ServiceName,
			e.Operation,
			e.Result,
			e.ErrorMessage,
		)
	}

	return csv
}

func generateAuditEntryID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return "AUD-" + hex.EncodeToString(b)
}

func (h *DatastoreAuditHandler) errorResponse(requestID, message string) (*OutgoingMessage, error) {
	return &OutgoingMessage{
		RequestID: requestID,
		Type:      MessageTypeResponse,
		Payload:   mustMarshalJSON(map[string]interface{}{"success": false, "error": message}),
	}, nil
}

func (h *DatastoreAuditHandler) successResponse(requestID string, payload interface{}) (*OutgoingMessage, error) {
	return &OutgoingMessage{
		RequestID: requestID,
		Type:      MessageTypeResponse,
		Payload:   mustMarshalJSON(payload),
	}, nil
}
