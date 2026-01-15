package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	// EC2 Instance Metadata Service (IMDSv2) token endpoint
	imdsTokenURL = "http://169.254.169.254/latest/api/token"
	// EC2 Instance Metadata Service endpoints
	imdsInstanceIDURL = "http://169.254.169.254/latest/meta-data/instance-id"
	imdsRegionURL     = "http://169.254.169.254/latest/meta-data/placement/region"
	// Token TTL in seconds
	imdsTokenTTL = "21600" // 6 hours
)

// GenerateEnclaveID creates a unique identifier for this enclave instance.
// Format: "{region}-{instance_id}-{timestamp}"
// Example: "us-east-1-i-0abc123def456-1705312800"
//
// In development mode (no EC2 metadata), generates a dev-prefixed ID.
func GenerateEnclaveID(devMode bool) (string, error) {
	if devMode {
		// Development mode: use hostname + timestamp
		hostname, err := os.Hostname()
		if err != nil {
			hostname = "dev"
		}
		timestamp := time.Now().Unix()
		return fmt.Sprintf("dev-%s-%d", sanitizeHostname(hostname), timestamp), nil
	}

	// Production mode: use EC2 instance metadata
	token, err := getIMDSToken()
	if err != nil {
		log.Warn().Err(err).Msg("Failed to get IMDS token, falling back to dev ID")
		return fmt.Sprintf("fallback-%d", time.Now().Unix()), nil
	}

	instanceID, err := getIMDSMetadata(imdsInstanceIDURL, token)
	if err != nil {
		return "", fmt.Errorf("failed to get instance ID: %w", err)
	}

	region, err := getIMDSMetadata(imdsRegionURL, token)
	if err != nil {
		return "", fmt.Errorf("failed to get region: %w", err)
	}

	timestamp := time.Now().Unix()
	return fmt.Sprintf("%s-%s-%d", region, instanceID, timestamp), nil
}

// getIMDSToken retrieves an IMDSv2 session token
func getIMDSToken() (string, error) {
	client := &http.Client{Timeout: 2 * time.Second}

	req, err := http.NewRequest("PUT", imdsTokenURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", imdsTokenTTL)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("IMDS token request failed: %s", resp.Status)
	}

	token, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(token), nil
}

// getIMDSMetadata retrieves a metadata value using IMDSv2
func getIMDSMetadata(url, token string) (string, error) {
	client := &http.Client{Timeout: 2 * time.Second}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-aws-ec2-metadata-token", token)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("IMDS metadata request failed: %s", resp.Status)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(data)), nil
}

// sanitizeHostname removes characters that aren't valid in NATS subjects
func sanitizeHostname(hostname string) string {
	// Replace invalid characters with underscores
	result := make([]byte, len(hostname))
	for i, c := range []byte(hostname) {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			result[i] = c
		} else {
			result[i] = '_'
		}
	}
	return string(result)
}
