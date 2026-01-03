package main

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
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

	client := s3.NewFromConfig(awsCfg)

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
		// Check if it's a "not found" error
		// TODO: Properly check error type
		return false, nil
	}
	return true, nil
}
