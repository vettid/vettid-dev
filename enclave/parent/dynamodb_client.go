package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
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

// ListProposals scans the proposals table for active, upcoming, and published proposals.
// Returns all matching proposals as JSON bytes in the format: {"proposals": [...], "total": N}
func (d *DynamoDBClient) ListProposals(ctx context.Context) ([]byte, error) {
	if d.config.ProposalsTable == "" {
		return nil, fmt.Errorf("proposals table not configured")
	}

	// Filter for status IN (active, upcoming, published) - skip cancelled/draft
	filterExpr := "#s IN (:s1, :s2, :s3)"
	exprAttrNames := map[string]string{
		"#s": "status", // "status" is a reserved word in DynamoDB
	}
	exprAttrValues := map[string]dynamodbtypes.AttributeValue{
		":s1": &dynamodbtypes.AttributeValueMemberS{Value: "active"},
		":s2": &dynamodbtypes.AttributeValueMemberS{Value: "upcoming"},
		":s3": &dynamodbtypes.AttributeValueMemberS{Value: "published"},
	}

	// Project only the fields we need
	projExpr := "proposal_id, proposal_number, proposal_title, proposal_text, #s, category, opens_at, closes_at, created_at, quorum_type, quorum_value, choices, signed_payload, org_signature"

	result, err := d.client.Scan(ctx, &dynamodb.ScanInput{
		TableName:                 aws.String(d.config.ProposalsTable),
		FilterExpression:          aws.String(filterExpr),
		ExpressionAttributeNames:  exprAttrNames,
		ExpressionAttributeValues: exprAttrValues,
		ProjectionExpression:      aws.String(projExpr),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to scan proposals table: %w", err)
	}

	// Convert DynamoDB items to generic maps for JSON serialization
	proposals := make([]map[string]interface{}, 0, len(result.Items))
	for _, item := range result.Items {
		proposal := make(map[string]interface{})
		for k, v := range item {
			switch attr := v.(type) {
			case *dynamodbtypes.AttributeValueMemberS:
				proposal[k] = attr.Value
			case *dynamodbtypes.AttributeValueMemberN:
				proposal[k] = attr.Value // Keep as string - client can parse
			case *dynamodbtypes.AttributeValueMemberL:
				// Convert list items (e.g., choices) to string slice
				items := make([]interface{}, 0, len(attr.Value))
				for _, listItem := range attr.Value {
					switch li := listItem.(type) {
					case *dynamodbtypes.AttributeValueMemberS:
						items = append(items, li.Value)
					case *dynamodbtypes.AttributeValueMemberM:
						m := make(map[string]interface{})
						for mk, mv := range li.Value {
							if sv, ok := mv.(*dynamodbtypes.AttributeValueMemberS); ok {
								m[mk] = sv.Value
							} else if nv, ok := mv.(*dynamodbtypes.AttributeValueMemberN); ok {
								m[mk] = nv.Value
							}
						}
						items = append(items, m)
					}
				}
				proposal[k] = items
			case *dynamodbtypes.AttributeValueMemberBOOL:
				proposal[k] = attr.Value
			}
		}
		proposals = append(proposals, proposal)
	}

	response := map[string]interface{}{
		"proposals": proposals,
		"total":     len(proposals),
	}

	data, err := json.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal proposals response: %w", err)
	}

	log.Info().Int("count", len(proposals)).Msg("Listed proposals from DynamoDB")
	return data, nil
}

// PutOrgAuditEvent writes an org vault audit event to the orgAudit table.
//
// SECURITY: Audit writes are non-blocking from the caller's perspective.
// The originating credential proxy operation does not fail if this write fails;
// failures are logged but the operation succeeds. Audit events are also
// streamed via NATS as a redundant delivery channel.
func (d *DynamoDBClient) PutOrgAuditEvent(ctx context.Context, event map[string]interface{}) error {
	if d.config.OrgAuditTable == "" {
		return fmt.Errorf("org_audit_table not configured")
	}

	item, err := marshalDynamoDBItem(event)
	if err != nil {
		return fmt.Errorf("failed to marshal audit event: %w", err)
	}

	_, err = d.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(d.config.OrgAuditTable),
		Item:      item,
	})
	if err != nil {
		return fmt.Errorf("failed to put audit event: %w", err)
	}

	if eventID, ok := event["event_id"].(string); ok {
		log.Debug().Str("event_id", eventID).Msg("Audit event persisted to DynamoDB")
	}
	return nil
}

// marshalDynamoDBItem converts a generic map[string]interface{} to a DynamoDB
// AttributeValue map. Supports the field types used in OrgAuditEvent:
// strings, numbers (float64 from json decoding), and ints.
func marshalDynamoDBItem(event map[string]interface{}) (map[string]dynamodbtypes.AttributeValue, error) {
	item := make(map[string]dynamodbtypes.AttributeValue, len(event))
	for k, v := range event {
		if v == nil {
			continue
		}
		switch val := v.(type) {
		case string:
			if val == "" {
				continue
			}
			item[k] = &dynamodbtypes.AttributeValueMemberS{Value: val}
		case float64:
			// Use 'f' format with -1 precision to avoid scientific notation
			// (timestamps would otherwise become "1.7449e+12")
			if val == float64(int64(val)) {
				item[k] = &dynamodbtypes.AttributeValueMemberN{Value: fmt.Sprintf("%d", int64(val))}
			} else {
				item[k] = &dynamodbtypes.AttributeValueMemberN{Value: strconv.FormatFloat(val, 'f', -1, 64)}
			}
		case int:
			item[k] = &dynamodbtypes.AttributeValueMemberN{Value: fmt.Sprintf("%d", val)}
		case int64:
			item[k] = &dynamodbtypes.AttributeValueMemberN{Value: fmt.Sprintf("%d", val)}
		case bool:
			item[k] = &dynamodbtypes.AttributeValueMemberBOOL{Value: val}
		default:
			// Fall back to JSON-encoded string for complex types
			b, err := json.Marshal(v)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal field %s: %w", k, err)
			}
			item[k] = &dynamodbtypes.AttributeValueMemberS{Value: string(b)}
		}
	}
	return item, nil
}
