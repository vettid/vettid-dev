package main

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/rs/zerolog/log"
)

// KMSClient handles KMS operations with Nitro attestation support
type KMSClient struct {
	client        *kms.Client
	sealingKeyARN string
}

// NewKMSClient creates a new KMS client
func NewKMSClient(cfg KMSConfig) (*KMSClient, error) {
	if cfg.SealingKeyARN == "" {
		log.Warn().Msg("KMS sealing key ARN not configured - sealing operations will fail")
	}

	awsCfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(cfg.Region),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	return &KMSClient{
		client:        kms.NewFromConfig(awsCfg),
		sealingKeyARN: cfg.SealingKeyARN,
	}, nil
}

// Encrypt encrypts data using the sealing key
// This is used to encrypt the DEK (Data Encryption Key) for envelope encryption
// No attestation needed for encrypt - anyone can encrypt data to the key
func (k *KMSClient) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	if k.sealingKeyARN == "" {
		return nil, fmt.Errorf("KMS sealing key ARN not configured")
	}

	result, err := k.client.Encrypt(ctx, &kms.EncryptInput{
		KeyId:     &k.sealingKeyARN,
		Plaintext: plaintext,
	})
	if err != nil {
		return nil, fmt.Errorf("KMS encrypt failed: %w", err)
	}

	log.Debug().
		Int("plaintext_len", len(plaintext)).
		Int("ciphertext_len", len(result.CiphertextBlob)).
		Msg("KMS encrypt successful")

	return result.CiphertextBlob, nil
}

// DecryptWithAttestation decrypts data using the sealing key with attestation
// The attestation document must contain PCR values that match the key policy
// This is the core of Nitro attestation-based sealing
func (k *KMSClient) DecryptWithAttestation(ctx context.Context, ciphertext []byte, attestation []byte) ([]byte, error) {
	if k.sealingKeyARN == "" {
		return nil, fmt.Errorf("KMS sealing key ARN not configured")
	}

	// Build the Recipient structure for Nitro attestation
	// This tells KMS to validate the attestation document
	// and only decrypt if PCRs match the key policy
	recipient := &types.RecipientInfo{
		AttestationDocument: attestation,
		// AWS will return the plaintext encrypted to the enclave's public key
		// that was embedded in the attestation document
		KeyEncryptionAlgorithm: types.KeyEncryptionMechanismRsaesOaepSha256,
	}

	result, err := k.client.Decrypt(ctx, &kms.DecryptInput{
		KeyId:          &k.sealingKeyARN,
		CiphertextBlob: ciphertext,
		Recipient:      recipient,
	})
	if err != nil {
		return nil, fmt.Errorf("KMS decrypt with attestation failed: %w", err)
	}

	// When using Recipient, the plaintext is encrypted to the enclave's public key
	// The enclave must decrypt it with its private key
	// The CiphertextForRecipient contains the encrypted plaintext
	if result.CiphertextForRecipient != nil {
		log.Debug().
			Int("ciphertext_len", len(ciphertext)).
			Int("recipient_ciphertext_len", len(result.CiphertextForRecipient)).
			Msg("KMS decrypt with attestation successful (recipient mode)")
		return result.CiphertextForRecipient, nil
	}

	// If no Recipient was used (shouldn't happen in this flow)
	if result.Plaintext != nil {
		log.Debug().
			Int("ciphertext_len", len(ciphertext)).
			Int("plaintext_len", len(result.Plaintext)).
			Msg("KMS decrypt successful (direct mode)")
		return result.Plaintext, nil
	}

	return nil, fmt.Errorf("KMS decrypt returned no data")
}

// GenerateDataKey generates a new data encryption key (DEK)
// Returns both plaintext and encrypted DEK
// This is used for envelope encryption: encrypt data with DEK, store encrypted DEK
func (k *KMSClient) GenerateDataKey(ctx context.Context) (plaintext, ciphertext []byte, err error) {
	if k.sealingKeyARN == "" {
		return nil, nil, fmt.Errorf("KMS sealing key ARN not configured")
	}

	result, err := k.client.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
		KeyId:   &k.sealingKeyARN,
		KeySpec: types.DataKeySpecAes256,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("KMS generate data key failed: %w", err)
	}

	log.Debug().
		Int("plaintext_len", len(result.Plaintext)).
		Int("ciphertext_len", len(result.CiphertextBlob)).
		Msg("KMS generate data key successful")

	return result.Plaintext, result.CiphertextBlob, nil
}

// GenerateDataKeyWithAttestation generates a DEK with attestation
// The plaintext is encrypted to the enclave's public key in the attestation
// Only an enclave with matching PCRs can get the plaintext
func (k *KMSClient) GenerateDataKeyWithAttestation(ctx context.Context, attestation []byte) (ciphertextForRecipient, ciphertextBlob []byte, err error) {
	if k.sealingKeyARN == "" {
		return nil, nil, fmt.Errorf("KMS sealing key ARN not configured")
	}

	recipient := &types.RecipientInfo{
		AttestationDocument:    attestation,
		KeyEncryptionAlgorithm: types.KeyEncryptionMechanismRsaesOaepSha256,
	}

	result, err := k.client.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
		KeyId:     &k.sealingKeyARN,
		KeySpec:   types.DataKeySpecAes256,
		Recipient: recipient,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("KMS generate data key with attestation failed: %w", err)
	}

	if result.CiphertextForRecipient == nil {
		return nil, nil, fmt.Errorf("KMS did not return CiphertextForRecipient")
	}

	log.Debug().
		Int("recipient_ciphertext_len", len(result.CiphertextForRecipient)).
		Int("ciphertext_blob_len", len(result.CiphertextBlob)).
		Msg("KMS generate data key with attestation successful")

	return result.CiphertextForRecipient, result.CiphertextBlob, nil
}
