package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// SECURITY: HTTP proxy configuration
const (
	// Maximum time allowed for an HTTP proxy request
	httpProxyTimeout = 30 * time.Second
	// Maximum response body size (5MB) to prevent resource exhaustion
	httpProxyMaxResponseBody = 5 * 1024 * 1024
	// Maximum request body size (1MB)
	httpProxyMaxRequestBody = 1 * 1024 * 1024
	// SECURITY: Rate limit — max requests per minute per vault
	httpProxyMaxRequestsPerMinute = 10
)

// SECURITY: URL allowlist for HTTP proxy requests.
// Only these host prefixes are permitted. The enclave should never be able
// to make arbitrary HTTP requests to the internet.
var httpProxyAllowedHosts = []string{
	"mempool.space",     // Bitcoin blockchain API (balance, UTXOs, broadcast, fees)
	"blockstream.info",  // Fallback Bitcoin blockchain API
}

// HTTPProxyRequest is the request payload from the enclave
type HTTPProxyRequest struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Body    []byte            `json:"body,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

// HTTPProxyResponse is the response payload sent back to the enclave
type HTTPProxyResponse struct {
	StatusCode int               `json:"status_code"`
	Body       []byte            `json:"body"`
	Headers    map[string]string `json:"headers,omitempty"`
	Error      string            `json:"error,omitempty"`
}

// httpProxyRateLimiter tracks request timestamps for rate limiting.
// SECURITY: Prevents the enclave from overwhelming external APIs.
var httpProxyRateLimiter = struct {
	mu         sync.Mutex
	timestamps []time.Time
}{
	timestamps: make([]time.Time, 0, httpProxyMaxRequestsPerMinute),
}

// httpProxyCheckRateLimit returns true if the request is allowed under the rate limit.
func httpProxyCheckRateLimit() bool {
	httpProxyRateLimiter.mu.Lock()
	defer httpProxyRateLimiter.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-time.Minute)

	// Remove timestamps outside the window
	valid := httpProxyRateLimiter.timestamps[:0]
	for _, t := range httpProxyRateLimiter.timestamps {
		if t.After(windowStart) {
			valid = append(valid, t)
		}
	}
	httpProxyRateLimiter.timestamps = valid

	if len(httpProxyRateLimiter.timestamps) >= httpProxyMaxRequestsPerMinute {
		return false
	}

	httpProxyRateLimiter.timestamps = append(httpProxyRateLimiter.timestamps, now)
	return true
}

// httpProxyClient is the shared HTTP client for proxy requests.
// SECURITY: Uses a dedicated client with strict timeouts to prevent resource exhaustion.
var httpProxyClient = &http.Client{
	Timeout: httpProxyTimeout,
	// SECURITY: Do not follow redirects automatically — the enclave should
	// receive the redirect response and decide how to handle it
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// handleHTTPProxy processes an HTTP proxy request from the enclave.
// SECURITY: Validates the URL against an allowlist before making the request.
func (p *ParentProcess) handleHTTPProxy(ctx context.Context, msg *EnclaveMessage) *EnclaveMessage {
	// SECURITY: Rate limit check
	if !httpProxyCheckRateLimit() {
		log.Warn().Msg("SECURITY: HTTP proxy rate limit exceeded")
		return httpProxyErrorResponse("rate limit exceeded: max 10 requests per minute")
	}

	// Parse the HTTP request from the payload
	var req HTTPProxyRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		log.Error().Err(err).Msg("Failed to unmarshal HTTP proxy request")
		return httpProxyErrorResponse("invalid request: " + err.Error())
	}

	// SECURITY: Validate HTTP method
	allowedMethods := map[string]bool{
		"GET":    true,
		"POST":   true,
		"PUT":    true,
		"PATCH":  true,
		"DELETE": true,
		"HEAD":   true,
	}
	if !allowedMethods[req.Method] {
		log.Warn().Str("method", req.Method).Msg("SECURITY: Rejected disallowed HTTP method")
		return httpProxyErrorResponse("method not allowed: " + req.Method)
	}

	// SECURITY: Validate URL format
	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		log.Warn().Str("url", req.URL).Err(err).Msg("SECURITY: Rejected invalid URL")
		return httpProxyErrorResponse("invalid URL: " + err.Error())
	}

	// SECURITY: Only allow HTTPS (except in development)
	if parsedURL.Scheme != "https" {
		log.Warn().
			Str("url", req.URL).
			Str("scheme", parsedURL.Scheme).
			Msg("SECURITY: Rejected non-HTTPS URL")
		return httpProxyErrorResponse("only HTTPS URLs are allowed")
	}

	// SECURITY: Validate against host allowlist
	if !isHostAllowed(parsedURL.Hostname()) {
		log.Warn().
			Str("url", req.URL).
			Str("host", parsedURL.Hostname()).
			Msg("SECURITY: Rejected URL - host not in allowlist")
		return httpProxyErrorResponse("host not allowed: " + parsedURL.Hostname())
	}

	// SECURITY: Validate request body size
	if len(req.Body) > httpProxyMaxRequestBody {
		log.Warn().
			Int("body_len", len(req.Body)).
			Int("max", httpProxyMaxRequestBody).
			Msg("SECURITY: Rejected oversized request body")
		return httpProxyErrorResponse("request body too large")
	}

	// Build the HTTP request
	var bodyReader io.Reader
	if len(req.Body) > 0 {
		bodyReader = bytes.NewReader(req.Body)
	}

	httpCtx, cancel := context.WithTimeout(ctx, httpProxyTimeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(httpCtx, req.Method, req.URL, bodyReader)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create HTTP request")
		return httpProxyErrorResponse("failed to create request: " + err.Error())
	}

	// Set request headers
	for key, value := range req.Headers {
		// SECURITY: Prevent header injection
		if strings.ContainsAny(key, "\r\n") || strings.ContainsAny(value, "\r\n") {
			log.Warn().Str("key", key).Msg("SECURITY: Rejected header with newline characters")
			continue
		}
		httpReq.Header.Set(key, value)
	}

	// Set default Content-Type for POST/PUT/PATCH if not specified
	if (req.Method == "POST" || req.Method == "PUT" || req.Method == "PATCH") &&
		httpReq.Header.Get("Content-Type") == "" && len(req.Body) > 0 {
		httpReq.Header.Set("Content-Type", "application/json")
	}

	log.Debug().
		Str("method", req.Method).
		Str("url", req.URL).
		Int("body_len", len(req.Body)).
		Msg("Executing HTTP proxy request")

	// Execute the request
	resp, err := httpProxyClient.Do(httpReq)
	if err != nil {
		log.Error().Err(err).Str("url", req.URL).Msg("HTTP proxy request failed")
		return httpProxyErrorResponse("request failed: " + err.Error())
	}
	defer resp.Body.Close()

	// Read response body with size limit
	limitedReader := io.LimitReader(resp.Body, int64(httpProxyMaxResponseBody)+1)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		log.Error().Err(err).Msg("Failed to read HTTP response body")
		return httpProxyErrorResponse("failed to read response body: " + err.Error())
	}

	// SECURITY: Check if response was truncated
	if len(body) > httpProxyMaxResponseBody {
		log.Warn().
			Int("body_len", len(body)).
			Int("max", httpProxyMaxResponseBody).
			Msg("SECURITY: Response body exceeded maximum size, truncated")
		body = body[:httpProxyMaxResponseBody]
	}

	// Extract response headers (only standard ones, not all)
	respHeaders := make(map[string]string)
	for _, key := range []string{"Content-Type", "Location", "Retry-After", "X-Request-Id"} {
		if v := resp.Header.Get(key); v != "" {
			respHeaders[key] = v
		}
	}

	log.Debug().
		Str("method", req.Method).
		Str("url", req.URL).
		Int("status_code", resp.StatusCode).
		Int("body_len", len(body)).
		Msg("HTTP proxy request completed")

	proxyResp := HTTPProxyResponse{
		StatusCode: resp.StatusCode,
		Body:       body,
		Headers:    respHeaders,
	}

	respPayload, err := json.Marshal(proxyResp)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal HTTP proxy response")
		return httpProxyErrorResponse("failed to marshal response")
	}

	return &EnclaveMessage{
		Type:    EnclaveMessageTypeHTTPResponse,
		Payload: respPayload,
	}
}

// isHostAllowed checks if a hostname is in the allowlist.
// SECURITY: Uses exact match or suffix match for subdomain support.
func isHostAllowed(host string) bool {
	host = strings.ToLower(host)
	for _, allowed := range httpProxyAllowedHosts {
		allowed = strings.ToLower(allowed)
		if host == allowed {
			return true
		}
		// Allow subdomains: "api.example.com" matches allowed "example.com"
		if strings.HasSuffix(host, "."+allowed) {
			return true
		}
	}
	return false
}

// httpProxyErrorResponse creates an error response for the HTTP proxy
func httpProxyErrorResponse(errMsg string) *EnclaveMessage {
	resp := HTTPProxyResponse{
		Error: errMsg,
	}
	payload, _ := json.Marshal(resp)
	return &EnclaveMessage{
		Type:    EnclaveMessageTypeHTTPResponse,
		Payload: payload,
	}
}
