package main

import (
	"context"
	"encoding/json"

	"github.com/rs/zerolog/log"
)

// handlePCRSigningKeyGet returns the DER-encoded SPKI public key for
// the PCR signing KMS key (alias `vettid-pcr-signing`). The
// vault-manager uses this to verify the ECDSA signature on every
// fetched migration config (`_migration/config.json`) before acting
// on it. Without this verification, anyone with S3 write access to
// the vault data bucket could forge a config that points the enclave
// at an attacker-controlled PCR0 during finalization.
//
// The response payload is just the raw DER bytes wrapped in a tiny
// JSON envelope so the existing `EnclaveMessage` flow can carry it.
func (p *ParentProcess) handlePCRSigningKeyGet(ctx context.Context, msg *EnclaveMessage) *EnclaveMessage {
	if p.kmsClient == nil {
		errBody, _ := json.Marshal(map[string]string{"error": "kms client not available"})
		return &EnclaveMessage{Type: EnclaveMessageTypePCRSigningKeyResponse, Payload: errBody}
	}
	der, err := p.kmsClient.GetPCRSigningPublicKey(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Failed to fetch PCR signing public key")
		errBody, _ := json.Marshal(map[string]string{"error": err.Error()})
		return &EnclaveMessage{Type: EnclaveMessageTypePCRSigningKeyResponse, Payload: errBody}
	}
	body, _ := json.Marshal(map[string][]byte{"public_key_der": der})
	return &EnclaveMessage{Type: EnclaveMessageTypePCRSigningKeyResponse, Payload: body}
}

// handlePCRSigningKeySign asks KMS to sign a SHA-256 digest with the
// PCR signing key. SECURITY (attestation-F3): the supervisor uses this
// to stamp migration-completion markers so Lambda can verify that each
// `_migration/completed/{version}/{ownerSpace}.json` came from an
// attested enclave instance, not a misconfigured S3 writer.
func (p *ParentProcess) handlePCRSigningKeySign(ctx context.Context, msg *EnclaveMessage) *EnclaveMessage {
	if p.kmsClient == nil {
		errBody, _ := json.Marshal(map[string]string{"error": "kms client not available"})
		return &EnclaveMessage{Type: EnclaveMessageTypePCRSigningKeySignResponse, Payload: errBody}
	}
	var req struct {
		Digest []byte `json:"digest"`
	}
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		errBody, _ := json.Marshal(map[string]string{"error": "invalid payload"})
		return &EnclaveMessage{Type: EnclaveMessageTypePCRSigningKeySignResponse, Payload: errBody}
	}
	sig, err := p.kmsClient.SignWithPCRSigningKey(ctx, req.Digest)
	if err != nil {
		log.Error().Err(err).Msg("Failed to sign with PCR signing key")
		errBody, _ := json.Marshal(map[string]string{"error": err.Error()})
		return &EnclaveMessage{Type: EnclaveMessageTypePCRSigningKeySignResponse, Payload: errBody}
	}
	body, _ := json.Marshal(map[string][]byte{"signature": sig})
	return &EnclaveMessage{Type: EnclaveMessageTypePCRSigningKeySignResponse, Payload: body}
}
