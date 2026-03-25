package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
)

// SECURITY: Timeout for HTTP proxy responses
// Prevents indefinite hangs if the parent becomes unresponsive
const httpProxyTimeout = 30 * time.Second

// HTTPProxy proxies HTTP requests from vault-manager through the parent process.
// The enclave cannot make direct network calls, so all HTTP requests are sent
// as intermediate messages through the supervisor to the parent, which executes them
// and returns the response. This follows the same pattern as SealerProxy.
type HTTPProxy struct {
	ownerSpace string
	sendFn     func(msg *OutgoingMessage) error
	// responseCh is set by the caller to receive responses
	responseCh chan *IncomingMessage
}

// HTTPProxyRequest is sent from vault-manager to parent via supervisor
type HTTPProxyRequest struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Body    []byte            `json:"body,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

// HTTPProxyResponse is sent from parent back to vault-manager via supervisor
type HTTPProxyResponse struct {
	StatusCode int               `json:"status_code"`
	Body       []byte            `json:"body"`
	Headers    map[string]string `json:"headers,omitempty"`
	Error      string            `json:"error,omitempty"`
}

// NewHTTPProxy creates a new HTTP proxy
func NewHTTPProxy(ownerSpace string, sendFn func(msg *OutgoingMessage) error) *HTTPProxy {
	return &HTTPProxy{
		ownerSpace: ownerSpace,
		sendFn:     sendFn,
	}
}

// SetResponseChannel sets the channel for receiving responses
func (p *HTTPProxy) SetResponseChannel(ch chan *IncomingMessage) {
	p.responseCh = ch
}

// Get performs an HTTP GET request through the parent process
func (p *HTTPProxy) Get(url string, headers map[string]string) ([]byte, int, error) {
	return p.Do("GET", url, nil, headers)
}

// Post performs an HTTP POST request through the parent process
func (p *HTTPProxy) Post(url string, body []byte, headers map[string]string) ([]byte, int, error) {
	return p.Do("POST", url, body, headers)
}

// Do performs an HTTP request through the parent process
// SECURITY: URL allowlist is enforced by the parent process, not here.
// The vault-manager trusts the parent to validate URLs since the parent
// is the security boundary for network access.
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

	requestID := generateMessageID()
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

	// Wait for response on the response channel with timeout
	// The main message loop routes HTTP responses here
	if p.responseCh == nil {
		return nil, 0, fmt.Errorf("HTTP response channel not set")
	}

	// SECURITY: Use timeout to prevent indefinite hangs
	// SECURITY: Match request ID to prevent processing stale responses from timed-out requests
	deadline := time.Now().Add(httpProxyTimeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			log.Error().
				Str("method", method).
				Str("url", url).
				Str("request_id", requestID).
				Dur("timeout", httpProxyTimeout).
				Msg("SECURITY: HTTP proxy timeout waiting for response")
			return nil, 0, fmt.Errorf("HTTP proxy timeout after %v", httpProxyTimeout)
		}

		select {
		case respMsg := <-p.responseCh:
			if respMsg == nil {
				return nil, 0, fmt.Errorf("no response received (channel closed)")
			}

			// SECURITY: Check if this response matches our request ID
			// If not, it's a stale response from a previous timed-out request - discard it
			if respMsg.RequestID != "" && respMsg.RequestID != requestID {
				log.Warn().
					Str("expected_id", requestID).
					Str("received_id", respMsg.RequestID).
					Str("method", method).
					Msg("Discarding stale HTTP response (request ID mismatch)")
				continue // Keep waiting for our response
			}

			var resp HTTPProxyResponse
			if err := json.Unmarshal(respMsg.Payload, &resp); err != nil {
				return nil, 0, fmt.Errorf("failed to unmarshal HTTP response: %w", err)
			}

			log.Debug().
				Str("method", method).
				Str("url", url).
				Str("request_id", requestID).
				Int("status_code", resp.StatusCode).
				Msg("Received HTTP proxy response")

			if resp.Error != "" {
				return nil, 0, fmt.Errorf("HTTP proxy error: %s", resp.Error)
			}

			return resp.Body, resp.StatusCode, nil

		case <-time.After(remaining):
			log.Error().
				Str("method", method).
				Str("url", url).
				Str("request_id", requestID).
				Dur("timeout", httpProxyTimeout).
				Msg("SECURITY: HTTP proxy timeout waiting for response")
			return nil, 0, fmt.Errorf("HTTP proxy timeout after %v", httpProxyTimeout)
		}
	}
}
