package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
)

// SECURITY: Timeout for HTTP proxy responses.
// Prevents indefinite hangs if the parent becomes unresponsive.
const httpProxyTimeout = 30 * time.Second

// HTTPProxy proxies HTTP requests from org-vault-manager through the parent process.
// The enclave cannot make direct network calls, so all HTTP requests are sent
// as intermediate messages through the supervisor to the parent, which executes them.
// This follows the same pattern as vault-manager/http_proxy.go.
type HTTPProxy struct {
	ownerSpace string
	sendFn     func(msg *OutgoingMessage) error
	// responseCh receives HTTP responses routed by the main message loop.
	// Set by the main Run() loop before processing begins.
	responseCh chan *IncomingMessage
}

// HTTPProxyRequest is sent from org-vault-manager to parent via supervisor.
type HTTPProxyRequest struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Body    []byte            `json:"body,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

// HTTPProxyResponse is sent from parent back to org-vault-manager via supervisor.
type HTTPProxyResponse struct {
	StatusCode int               `json:"status_code"`
	Body       []byte            `json:"body"`
	Headers    map[string]string `json:"headers,omitempty"`
	Error      string            `json:"error,omitempty"`
}

// NewHTTPProxy creates a new HTTP proxy.
func NewHTTPProxy(ownerSpace string, sendFn func(msg *OutgoingMessage) error) *HTTPProxy {
	return &HTTPProxy{
		ownerSpace: ownerSpace,
		sendFn:     sendFn,
		responseCh: make(chan *IncomingMessage, 1),
	}
}

// Post performs an HTTP POST request through the parent process.
func (p *HTTPProxy) Post(url string, body []byte, headers map[string]string) ([]byte, int, error) {
	return p.Do("POST", url, body, headers)
}

// Do performs an HTTP request through the parent process.
// SECURITY: URL allowlist is enforced by the parent process, not here.
func (p *HTTPProxy) Do(method, url string, body []byte, headers map[string]string) ([]byte, int, error) {
	req := HTTPProxyRequest{
		Method:  method,
		URL:     url,
		Body:    body,
		Headers: headers,
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to marshal HTTP request: %w", err)
	}

	requestID := generateID()
	msg := &OutgoingMessage{
		RequestID: requestID,
		Type:      MessageTypeHTTPRequest,
		Payload:   reqBytes,
	}

	log.Debug().
		Str("method", method).
		Str("url", url).
		Str("request_id", requestID).
		Msg("Sending HTTP proxy request to supervisor")

	if err := p.sendFn(msg); err != nil {
		return nil, 0, fmt.Errorf("failed to send HTTP request: %w", err)
	}

	// Wait for response with timeout.
	// SECURITY: Match request ID to prevent processing stale responses.
	deadline := time.Now().Add(httpProxyTimeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			log.Error().
				Str("request_id", requestID).
				Dur("timeout", httpProxyTimeout).
				Msg("SECURITY: HTTP proxy timeout")
			return nil, 0, fmt.Errorf("HTTP proxy timeout after %v", httpProxyTimeout)
		}

		select {
		case respMsg := <-p.responseCh:
			if respMsg == nil {
				return nil, 0, fmt.Errorf("no response received (channel closed)")
			}

			// SECURITY: Discard stale responses from previous timed-out requests
			if respMsg.RequestID != "" && respMsg.RequestID != requestID {
				log.Warn().
					Str("expected_id", requestID).
					Str("received_id", respMsg.RequestID).
					Msg("Discarding stale HTTP response")
				continue
			}

			var resp HTTPProxyResponse
			if err := json.Unmarshal(respMsg.Payload, &resp); err != nil {
				return nil, 0, fmt.Errorf("failed to unmarshal HTTP response: %w", err)
			}

			log.Debug().
				Str("request_id", requestID).
				Int("status_code", resp.StatusCode).
				Msg("Received HTTP proxy response")

			if resp.Error != "" {
				return nil, 0, fmt.Errorf("HTTP proxy error: %s", resp.Error)
			}

			return resp.Body, resp.StatusCode, nil

		case <-time.After(remaining):
			log.Error().
				Str("request_id", requestID).
				Dur("timeout", httpProxyTimeout).
				Msg("SECURITY: HTTP proxy timeout")
			return nil, 0, fmt.Errorf("HTTP proxy timeout after %v", httpProxyTimeout)
		}
	}
}
