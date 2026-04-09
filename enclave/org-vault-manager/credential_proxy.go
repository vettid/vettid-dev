package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
)

// CredentialProxy is the core feature of the org vault.
// It proxies database queries and API requests using stored credentials,
// ensuring credentials never leave the enclave and every operation is
// attributed to a specific operator with a stated purpose.
type CredentialProxy struct {
	ownerSpace      string
	credentialStore *CredentialStore
	httpProxy       *HTTPProxy
	auditHandler    *AuditHandler
	connectionMgr   *ConnectionManager
	contract        *ContractManager
}

// NewCredentialProxy creates a new credential proxy.
func NewCredentialProxy(
	ownerSpace string,
	credentialStore *CredentialStore,
	httpProxy *HTTPProxy,
	auditHandler *AuditHandler,
	connectionMgr *ConnectionManager,
	contract *ContractManager,
) *CredentialProxy {
	return &CredentialProxy{
		ownerSpace:      ownerSpace,
		credentialStore: credentialStore,
		httpProxy:       httpProxy,
		auditHandler:    auditHandler,
		connectionMgr:   connectionMgr,
		contract:        contract,
	}
}

// HandleProxy executes a proxied query on behalf of an identified operator.
// This is the "money shot" — credentials decrypted in-memory, query executed
// through parent's DB bridge, audit event emitted, credentials zeroed.
func (cp *CredentialProxy) HandleProxy(ctx context.Context, msg *IncomingMessage, operator *OperatorConnection) (*OutgoingMessage, error) {
	startTime := time.Now()

	var req ProxyQueryRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return errorResponse(msg.GetID(), "invalid request: "+err.Error())
	}

	// Validate required fields
	if req.CredentialID == "" {
		return cp.denyWithAudit(msg, operator, &req, "denied_validation", "credential_id is required")
	}
	if req.Query == "" {
		return cp.denyWithAudit(msg, operator, &req, "denied_validation", "query is required")
	}

	// Check access policy
	cred, err := cp.credentialStore.GetCredentialMetadata(req.CredentialID)
	if err != nil {
		return cp.denyWithAudit(msg, operator, &req, "denied_not_found", "credential not found")
	}

	// Enforce access policy
	if !cp.checkAccessPolicy(cred.AccessPolicy, operator, &req) {
		return cp.denyWithAudit(msg, operator, &req, "denied_policy", "access denied by policy")
	}

	// Check rate limit
	if !cp.checkRateLimit(cred.AccessPolicy, operator) {
		return cp.denyWithAudit(msg, operator, &req, "denied_rate_limit", "rate limit exceeded")
	}

	// Get the credential secret (decrypted in-memory only)
	secretData, err := cp.credentialStore.GetCredentialSecret(req.CredentialID)
	if err != nil {
		return cp.denyWithAudit(msg, operator, &req, "error", "failed to retrieve credential")
	}
	// SECURITY: Ensure secret is zeroed after use
	defer func() {
		for i := range secretData {
			secretData[i] = 0
		}
	}()

	// Execute the proxied query based on credential type
	var result *ProxyQueryResponse
	switch cred.CredentialType {
	case "database":
		result, err = cp.executeDatabaseQuery(secretData, &req)
	default:
		return cp.denyWithAudit(msg, operator, &req, "error", fmt.Sprintf("unsupported credential type: %s", cred.CredentialType))
	}

	durationMs := time.Since(startTime).Milliseconds()

	if err != nil {
		log.Error().
			Err(err).
			Str("credential_id", req.CredentialID).
			Str("operator", operator.OperatorEmail).
			Msg("Credential proxy query failed")

		auditID := cp.auditHandler.EmitCredentialProxyEvent(operator, &req, "error", durationMs, 0)
		return errorResponse(msg.GetID(), fmt.Sprintf("query failed (audit_id: %s): %s", auditID, err.Error()))
	}

	// Emit success audit event
	result.DurationMs = durationMs
	result.AuditID = cp.auditHandler.EmitCredentialProxyEvent(operator, &req, "success", durationMs, result.RowCount)
	result.Success = true

	log.Info().
		Str("credential_id", req.CredentialID).
		Str("operator", operator.OperatorEmail).
		Str("purpose", req.Purpose).
		Str("resource", req.ResourceID).
		Int("row_count", result.RowCount).
		Int64("duration_ms", durationMs).
		Msg("Credential proxy query completed")

	return successResponse(msg.GetID(), result)
}

// executeDatabaseQuery sends a query to the parent's DB bridge via HTTP proxy.
// The DB credentials are passed in HTTP headers (localhost only, vsock boundary).
func (cp *CredentialProxy) executeDatabaseQuery(secretData []byte, req *ProxyQueryRequest) (*ProxyQueryResponse, error) {
	var dbCred DatabaseCredential
	if err := json.Unmarshal(secretData, &dbCred); err != nil {
		return nil, fmt.Errorf("failed to parse database credential: %w", err)
	}

	// Build the request for the parent's DB query bridge
	bridgeReq := map[string]interface{}{
		"query":  req.Query,
		"params": req.QueryParams,
	}
	bodyBytes, err := json.Marshal(bridgeReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal bridge request: %w", err)
	}

	// DB credentials go in headers — they travel over vsock (same host, authenticated)
	// SECURITY: These headers never leave the host. The parent's DB bridge is localhost-only.
	headers := map[string]string{
		"X-DB-Host":     dbCred.Host,
		"X-DB-Port":     fmt.Sprintf("%d", dbCred.Port),
		"X-DB-Name":     dbCred.Database,
		"X-DB-User":     dbCred.Username,
		"X-DB-Password": dbCred.Password,
		"X-DB-SSLMode":  dbCred.SSLMode,
		"Content-Type":  "application/json",
	}

	// Send to parent's DB query bridge on localhost
	respBody, statusCode, err := cp.httpProxy.Post("http://127.0.0.1:5433/query", bodyBytes, headers)
	if err != nil {
		return nil, fmt.Errorf("DB bridge request failed: %w", err)
	}

	if statusCode != 200 {
		return nil, fmt.Errorf("DB bridge returned status %d: %s", statusCode, string(respBody))
	}

	// Parse the bridge response
	var bridgeResp struct {
		Columns  []string          `json:"columns"`
		Rows     []json.RawMessage `json:"rows"`
		RowCount int               `json:"row_count"`
		Error    string            `json:"error,omitempty"`
	}
	if err := json.Unmarshal(respBody, &bridgeResp); err != nil {
		return nil, fmt.Errorf("failed to parse bridge response: %w", err)
	}

	if bridgeResp.Error != "" {
		return nil, fmt.Errorf("DB query error: %s", bridgeResp.Error)
	}

	// Build the result rows as a JSON array
	rowsJSON, _ := json.Marshal(bridgeResp.Rows)

	return &ProxyQueryResponse{
		Results:  rowsJSON,
		Columns:  bridgeResp.Columns,
		RowCount: bridgeResp.RowCount,
	}, nil
}

// checkAccessPolicy verifies the operator's role and purpose against the credential's policy.
func (cp *CredentialProxy) checkAccessPolicy(policy AccessPolicy, operator *OperatorConnection, req *ProxyQueryRequest) bool {
	// Check role
	if len(policy.AllowedRoles) > 0 {
		roleAllowed := false
		for _, role := range policy.AllowedRoles {
			if role == "*" || role == operator.OperatorRole {
				roleAllowed = true
				break
			}
		}
		if !roleAllowed {
			log.Warn().
				Str("operator", operator.OperatorEmail).
				Str("role", operator.OperatorRole).
				Strs("allowed_roles", policy.AllowedRoles).
				Msg("Access denied: role not allowed")
			return false
		}
	}

	// Check operation type
	if len(policy.AllowedOperations) > 0 {
		opAllowed := false
		for _, op := range policy.AllowedOperations {
			if op == "*" || op == "query" {
				opAllowed = true
				break
			}
		}
		if !opAllowed {
			return false
		}
	}

	// Check purpose requirement
	if policy.RequirePurpose && req.Purpose == "" {
		log.Warn().
			Str("operator", operator.OperatorEmail).
			Msg("Access denied: purpose required but not provided")
		return false
	}

	return true
}

// checkRateLimit verifies the operator hasn't exceeded their query rate.
func (cp *CredentialProxy) checkRateLimit(policy AccessPolicy, operator *OperatorConnection) bool {
	if policy.MaxQueryRate <= 0 {
		return true // No rate limit
	}

	// Simple per-hour counter stored in vault
	key := KeyRateLimitPrefix + operator.ConnectionID
	var counter struct {
		Count     int   `json:"count"`
		ResetAt   int64 `json:"reset_at"` // Unix timestamp
	}

	now := time.Now()
	hourStart := now.Truncate(time.Hour).Unix()

	data, _ := cp.credentialStore.storage.Get(key)
	if data != nil {
		json.Unmarshal(data, &counter)
	}

	// Reset counter if we're in a new hour
	if counter.ResetAt < hourStart {
		counter.Count = 0
		counter.ResetAt = hourStart
	}

	if counter.Count >= policy.MaxQueryRate {
		log.Warn().
			Str("operator", operator.OperatorEmail).
			Int("count", counter.Count).
			Int("limit", policy.MaxQueryRate).
			Msg("Rate limit exceeded")
		return false
	}

	counter.Count++
	counterBytes, _ := json.Marshal(counter)
	cp.credentialStore.storage.Put(key, counterBytes)

	return true
}

// denyWithAudit emits an audit event for a denied request and returns an error response.
func (cp *CredentialProxy) denyWithAudit(msg *IncomingMessage, operator *OperatorConnection, req *ProxyQueryRequest, outcome, reason string) (*OutgoingMessage, error) {
	cp.auditHandler.EmitCredentialProxyEvent(operator, req, outcome, 0, 0)
	return errorResponse(msg.GetID(), reason)
}
