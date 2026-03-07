package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamodbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/rs/zerolog/log"
)

// DynamoDBClient handles DynamoDB operations for the parent process
type DynamoDBClient struct {
	client    *dynamodb.Client
	kmsClient *kms.Client
	config    DynamoDBConfig
	kmsConfig KMSConfig

	// Cache account seeds per owner_space
	seedCache   map[string]string
	seedCacheMu sync.RWMutex
}

// NewDynamoDBClient creates a new DynamoDB client
func NewDynamoDBClient(cfg DynamoDBConfig, kmsCfg KMSConfig) (*DynamoDBClient, error) {
	region := cfg.Region
	if region == "" {
		region = kmsCfg.Region
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion(region),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	return &DynamoDBClient{
		client:    dynamodb.NewFromConfig(awsCfg),
		kmsClient: kms.NewFromConfig(awsCfg),
		config:    cfg,
		kmsConfig: kmsCfg,
		seedCache: make(map[string]string),
	}, nil
}

// GetAccountSeed fetches and decrypts the NATS account seed for an owner_space.
// Results are cached per owner_space.
func (d *DynamoDBClient) GetAccountSeed(ctx context.Context, ownerSpace string) (string, error) {
	// Check cache first
	d.seedCacheMu.RLock()
	if seed, ok := d.seedCache[ownerSpace]; ok {
		d.seedCacheMu.RUnlock()
		return seed, nil
	}
	d.seedCacheMu.RUnlock()

	// Fetch from DynamoDB
	// The user_guid is the owner_space (without any prefix)
	userGuid := ownerSpace

	result, err := d.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(d.config.NatsAccountsTable),
		Key: map[string]dynamodbtypes.AttributeValue{
			"user_guid": &dynamodbtypes.AttributeValueMemberS{Value: userGuid},
		},
		ProjectionExpression: aws.String("account_seed_encrypted"),
	})
	if err != nil {
		return "", fmt.Errorf("failed to get NATS account from DynamoDB: %w", err)
	}

	if result.Item == nil {
		return "", fmt.Errorf("NATS account not found for owner_space: %s", ownerSpace)
	}

	// Extract encrypted seed
	seedAttr, ok := result.Item["account_seed_encrypted"]
	if !ok {
		return "", fmt.Errorf("account_seed_encrypted not found in DynamoDB record")
	}
	seedStr, ok := seedAttr.(*dynamodbtypes.AttributeValueMemberS)
	if !ok {
		return "", fmt.Errorf("account_seed_encrypted is not a string")
	}

	// Decode base64
	encryptedSeed, err := base64.StdEncoding.DecodeString(seedStr.Value)
	if err != nil {
		return "", fmt.Errorf("failed to decode encrypted seed: %w", err)
	}

	// Decrypt via KMS
	decryptResult, err := d.kmsClient.Decrypt(ctx, &kms.DecryptInput{
		KeyId:          aws.String(d.kmsConfig.NatsSeedKeyARN),
		CiphertextBlob: encryptedSeed,
		EncryptionContext: map[string]string{
			"user_guid": userGuid,
			"purpose":   "nats_account_seed",
		},
	})
	if err != nil {
		return "", fmt.Errorf("failed to decrypt account seed via KMS: %w", err)
	}

	seed := string(decryptResult.Plaintext)
	if seed == "" {
		return "", fmt.Errorf("KMS returned empty plaintext")
	}

	// Cache the result
	d.seedCacheMu.Lock()
	d.seedCache[ownerSpace] = seed
	d.seedCacheMu.Unlock()

	log.Info().Str("owner_space", ownerSpace).Msg("NATS account seed fetched and cached")
	return seed, nil
}
