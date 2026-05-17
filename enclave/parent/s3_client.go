package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/rs/zerolog/log"
)

// S3Client wraps an S3 client for vault data storage
type S3Client struct {
	client *s3.Client
	bucket string
	config S3Config
}

// NewS3Client creates a new S3 client
func NewS3Client(cfg S3Config) (*S3Client, error) {
	// Load AWS configuration
	awsCfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(cfg.Region),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// In production, Endpoint is empty and the SDK picks the standard
	// regional endpoint with virtual-host addressing. The Tier-2 harness
	// sets Endpoint to LocalStack and we flip on path-style addressing
	// so bucket goes in the path, not as a subdomain of the host that
	// LocalStack's DNS doesn't expose.
	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
			o.UsePathStyle = true
		}
	})

	return &S3Client{
		client: client,
		bucket: cfg.Bucket,
		config: cfg,
	}, nil
}

// Get retrieves an object from S3
func (c *S3Client) Get(ctx context.Context, key string) ([]byte, error) {
	log.Debug().
		Str("bucket", c.bucket).
		Str("key", key).
		Msg("S3 GET")

	result, err := c.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &c.bucket,
		Key:    &key,
	})
	if err != nil {
		return nil, fmt.Errorf("S3 GetObject failed: %w", err)
	}
	defer result.Body.Close()

	data, err := io.ReadAll(result.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read S3 object: %w", err)
	}

	return data, nil
}

// Put stores an object in S3
func (c *S3Client) Put(ctx context.Context, key string, data []byte) error {
	log.Debug().
		Str("bucket", c.bucket).
		Str("key", key).
		Int("size", len(data)).
		Msg("S3 PUT")

	_, err := c.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &c.bucket,
		Key:    &key,
		Body:   bytes.NewReader(data),
	})
	if err != nil {
		return fmt.Errorf("S3 PutObject failed: %w", err)
	}

	return nil
}

// GetWithETag retrieves an object and its ETag from S3. The ETag is
// returned with quotes stripped, ready for an IfMatch on the next
// conditional PutConditional call. Used by the vault_state.enc D3
// split-brain guard: the loaded ETag flows back to the next store so
// the supervisor can refuse a write that races a different writer's
// update.
func (c *S3Client) GetWithETag(ctx context.Context, key string) ([]byte, string, error) {
	log.Debug().
		Str("bucket", c.bucket).
		Str("key", key).
		Msg("S3 GET (with ETag)")

	result, err := c.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &c.bucket,
		Key:    &key,
	})
	if err != nil {
		return nil, "", fmt.Errorf("S3 GetObject failed: %w", err)
	}
	defer result.Body.Close()

	data, err := io.ReadAll(result.Body)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read S3 object: %w", err)
	}

	etag := ""
	if result.ETag != nil {
		etag = strings.Trim(*result.ETag, "\"")
	}
	return data, etag, nil
}

// PutConditional stores an object in S3 with optional compare-and-swap
// preconditions. Exactly one of (ifMatch, ifNoneMatch) should be set;
// pass nil for both to behave like Put. Returns the new object's ETag
// (quotes stripped) on success and conflict=true when S3 returns 412
// PreconditionFailed — the latter means another writer beat us to the
// object and the caller must NOT retry blindly (D3 split-brain guard
// on vault_state.enc).
//
// ifNoneMatch is intended for first-writes only: pass "*" to require
// the object not exist. ifMatch should be the ETag from the previous
// GetWithETag.
func (c *S3Client) PutConditional(ctx context.Context, key string, data []byte, ifMatch, ifNoneMatch *string) (string, bool, error) {
	log.Debug().
		Str("bucket", c.bucket).
		Str("key", key).
		Int("size", len(data)).
		Bool("if_match", ifMatch != nil).
		Bool("if_none_match", ifNoneMatch != nil).
		Msg("S3 PUT (conditional)")

	in := &s3.PutObjectInput{
		Bucket: &c.bucket,
		Key:    &key,
		Body:   bytes.NewReader(data),
	}
	if ifMatch != nil && *ifMatch != "" {
		in.IfMatch = aws.String(*ifMatch)
	}
	if ifNoneMatch != nil && *ifNoneMatch != "" {
		in.IfNoneMatch = aws.String(*ifNoneMatch)
	}

	result, err := c.client.PutObject(ctx, in)
	if err != nil {
		if isPreconditionFailed(err) {
			return "", true, nil
		}
		return "", false, fmt.Errorf("S3 PutObject failed: %w", err)
	}

	etag := ""
	if result.ETag != nil {
		etag = strings.Trim(*result.ETag, "\"")
	}
	return etag, false, nil
}

// isPreconditionFailed detects the 412 PreconditionFailed response that
// S3 returns when IfMatch / IfNoneMatch evaluates false. The aws-sdk-go-v2
// surface for conditional-put failures is HTTP-only — there's no typed
// error to errors.As against — so we unwrap to the underlying smithy
// HTTP response and check the status code.
func isPreconditionFailed(err error) bool {
	var resp *smithyhttp.ResponseError
	if errors.As(err, &resp) {
		return resp.HTTPStatusCode() == 412
	}
	return false
}

// Delete removes an object from S3
func (c *S3Client) Delete(ctx context.Context, key string) error {
	log.Debug().
		Str("bucket", c.bucket).
		Str("key", key).
		Msg("S3 DELETE")

	_, err := c.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &c.bucket,
		Key:    &key,
	})
	if err != nil {
		return fmt.Errorf("S3 DeleteObject failed: %w", err)
	}

	return nil
}

// List lists objects with a prefix
func (c *S3Client) List(ctx context.Context, prefix string) ([]string, error) {
	log.Debug().
		Str("bucket", c.bucket).
		Str("prefix", prefix).
		Msg("S3 LIST")

	var keys []string
	paginator := s3.NewListObjectsV2Paginator(c.client, &s3.ListObjectsV2Input{
		Bucket: &c.bucket,
		Prefix: &prefix,
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("S3 ListObjects failed: %w", err)
		}

		for _, obj := range page.Contents {
			keys = append(keys, *obj.Key)
		}
	}

	return keys, nil
}

// Exists checks if an object exists
func (c *S3Client) Exists(ctx context.Context, key string) (bool, error) {
	_, err := c.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: &c.bucket,
		Key:    &key,
	})
	if err != nil {
		// Check if it's a "not found" error (returns 404 for missing objects)
		var notFound *types.NotFound
		if errors.As(err, &notFound) {
			return false, nil
		}
		// Also check for NoSuchKey which some operations return
		var noSuchKey *types.NoSuchKey
		if errors.As(err, &noSuchKey) {
			return false, nil
		}
		// For any other error, return it
		return false, fmt.Errorf("S3 HeadObject failed: %w", err)
	}
	return true, nil
}
