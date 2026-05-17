package main

// Migration-config helpers: build a SignedPCRConfig pointing OLD→NEW
// PCR0s, sign it with the LocalStack KMS PCR-signing key, and PUT the
// result to S3 at `_migration/config.json`. The supervisor's
// fetchMigrationConfig sealer op reads from this same key.
//
// The canonical signing format MUST match enclave/migration/pcr_config.go's
// `signedPayload()` exactly — alphabetically-sorted top-level keys,
// omit zero-time fields entirely (no phantom "0001-01-01" emissions).
// Drift breaks the vault-manager verifier and migrate_consent silently
// no-ops. Keep this in lock-step with that file.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// migrationConfigKey is the S3 key the supervisor's
// fetchMigrationConfig reads from. Hardcoded in sealer_handler.go;
// any change here must match there.
const migrationConfigKey = "_migration/config.json"

// publishMigrationConfig builds a SignedPCRConfig pointing oldPCR0 →
// newPCR0, signs the canonical bytes with the LocalStack KMS
// ECDSA-P256 PCR-signing key, then PUTs it to S3 at
// `_migration/config.json`. Returns the version string the supervisor
// will see and the canonical signed bytes (handy for assertions /
// debugging when a verifier rejects).
//
// pcr1/pcr2 are fixed to 96 zeros — the validator only requires 96
// hex chars; the running enclave's NSM-reported PCR1/PCR2 aren't
// checked when the verifier is built via NewSignatureOnlyVerifier
// (which vault-manager uses). The harness's FAKE_PCR0_HEX env var
// only carries PCR0; PCR1/PCR2 are out of scope for migration.
func (h *Harness) publishMigrationConfig(
	ctx context.Context,
	oldPCR0, newPCR0 string,
	version string,
) ([]byte, error) {
	awsCfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("us-east-1"),
		config.WithCredentialsProvider(staticCreds{}),
	)
	if err != nil {
		return nil, fmt.Errorf("load aws cfg: %w", err)
	}

	kmsClient := kms.NewFromConfig(awsCfg, func(o *kms.Options) {
		o.BaseEndpoint = aws.String(h.LocalStackURL)
	})
	s3Client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(h.LocalStackURL)
		o.UsePathStyle = true
	})

	signingKeyARN, err := lookupPCRSigningKeyARN(ctx, awsCfg, h.LocalStackURL)
	if err != nil {
		return nil, fmt.Errorf("lookup PCR signing key ARN: %w", err)
	}

	// Build the same canonical map signedPayload() emits. Time fields
	// are populated rather than omitted because the harness wants a
	// definite valid_from/expires_at window; the canonical encoder
	// includes them when non-zero.
	zeroPCRHex := "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	now := time.Now().UTC()
	payload := map[string]interface{}{
		"new_pcrs": map[string]string{
			"pcr0": newPCR0,
			"pcr1": zeroPCRHex,
			"pcr2": zeroPCRHex,
		},
		"old_pcrs": map[string]string{
			"pcr0": oldPCR0,
			"pcr1": zeroPCRHex,
			"pcr2": zeroPCRHex,
		},
		"valid_from":   now.Add(-time.Minute), // already valid
		"expires_at":   now.Add(24 * time.Hour),
		"version":      version,
		"published_at": now,
	}
	canonical, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal canonical: %w", err)
	}

	// LocalStack KMS Sign with ECDSA_SHA_256: digest the canonical
	// bytes ourselves (SHA-256) and pass MessageType=DIGEST so KMS
	// signs that 32-byte hash directly.
	digest := sha256.Sum256(canonical)
	signOut, err := kmsClient.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(signingKeyARN),
		Message:          digest[:],
		MessageType:      kmstypes.MessageTypeDigest,
		SigningAlgorithm: kmstypes.SigningAlgorithmSpecEcdsaSha256,
	})
	if err != nil {
		return nil, fmt.Errorf("kms sign: %w", err)
	}

	// AWS KMS returns ASN.1 DER ECDSA signatures. The verifier accepts
	// that format directly via ecdsa.VerifyASN1 in pcr_config.go.
	sigB64 := base64.StdEncoding.EncodeToString(signOut.Signature)

	// Final published JSON includes the signature field. The verifier
	// excludes it before recomputing the canonical bytes.
	final := map[string]interface{}{}
	if err := json.Unmarshal(canonical, &final); err != nil {
		return nil, fmt.Errorf("rehydrate canonical: %w", err)
	}
	final["signature"] = sigB64
	finalBytes, err := json.Marshal(final)
	if err != nil {
		return nil, fmt.Errorf("marshal final: %w", err)
	}

	bucket := "vettid-vault-data-test"
	if _, err := s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(bucket),
		Key:         aws.String(migrationConfigKey),
		Body:        bytes.NewReader(finalBytes),
		ContentType: aws.String("application/json"),
	}); err != nil {
		return nil, fmt.Errorf("s3 put migration config: %w", err)
	}

	// Self-check: re-fetch the public key and verify the signature
	// canonicals locally so a publish bug is caught before any
	// scenario asserts on supervisor-side behaviour.
	pubOut, err := kmsClient.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: aws.String(signingKeyARN),
	})
	if err != nil {
		return nil, fmt.Errorf("kms get public key (self-check): %w", err)
	}
	parsed, err := x509.ParsePKIXPublicKey(pubOut.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse public key (self-check): %w", err)
	}
	ecKey, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not ECDSA (got %T)", parsed)
	}
	if !ecdsa.VerifyASN1(ecKey, digest[:], signOut.Signature) {
		return nil, fmt.Errorf("self-check: ECDSA verify failed — canonical drift or KMS misconfig")
	}
	return canonical, nil
}

// lookupPCRSigningKeyARN reads the ARN from the env. localstack-init
// writes it to /shared/arns.env; run.sh propagates KMS_PCR_SIGNING_KEY_ARN
// into the driver's environment via the parent containers' shared
// volume. The production parent reads it from SSM; mirroring that
// here would add an SSM import for one value already exposed by env.
func lookupPCRSigningKeyARN(ctx context.Context, awsCfg aws.Config, endpoint string) (string, error) {
	arn := os.Getenv("KMS_PCR_SIGNING_KEY_ARN")
	if arn == "" {
		return "", fmt.Errorf("KMS_PCR_SIGNING_KEY_ARN env var not set — run via run.sh")
	}
	return arn, nil
}

// staticCreds is the minimal credential provider LocalStack needs.
// Any non-empty string works; the values aren't checked.
type staticCreds struct{}

func (staticCreds) Retrieve(ctx context.Context) (aws.Credentials, error) {
	return aws.Credentials{
		AccessKeyID:     "test",
		SecretAccessKey: "test",
		Source:          "harness",
	}, nil
}

