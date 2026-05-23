package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamodbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/rs/zerolog/log"
)

// ErrAlreadyVoted is returned when SubmitSignedVote sees a duplicate
// (proposal_id, voting_public_key). Callers can treat it as success-equivalent
// for resubmit/idempotent flows.
var ErrAlreadyVoted = errors.New("already voted")

// DynamoDBClient handles DynamoDB operations for the parent process
type DynamoDBClient struct {
	client    *dynamodb.Client
	kmsClient *kms.Client
	s3Client  *s3.Client
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
		s3Client:  s3.NewFromConfig(awsCfg),
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

// ListProposals scans the proposals table for upcoming, active, and closed
// proposals. Closed proposals are included so the app can render results;
// cancelled/draft are still filtered out.
//
// Returns all matching proposals as JSON bytes in the format: {"proposals": [...], "total": N}
func (d *DynamoDBClient) ListProposals(ctx context.Context) ([]byte, error) {
	if d.config.ProposalsTable == "" {
		return nil, fmt.Errorf("proposals table not configured")
	}

	filterExpr := "#s IN (:s1, :s2, :s3)"
	exprAttrNames := map[string]string{
		"#s": "status", // "status" is a reserved word in DynamoDB
	}
	exprAttrValues := map[string]dynamodbtypes.AttributeValue{
		":s1": &dynamodbtypes.AttributeValueMemberS{Value: "upcoming"},
		":s2": &dynamodbtypes.AttributeValueMemberS{Value: "active"},
		":s3": &dynamodbtypes.AttributeValueMemberS{Value: "closed"},
	}

	// Project metadata + result fields written by closeExpiredProposals.
	projExpr := "proposal_id, proposal_number, proposal_title, proposal_text, #s, category, opens_at, closes_at, created_at, closed_at, quorum_type, quorum_value, choices, signed_payload, org_signature, kms_signature, kms_key_id, signing_payload, merkle_root, results_published_at, vote_counts, final_yes, final_no, final_abstain, final_total, eligible_voters, quorum_met, passed"

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
		proposals = append(proposals, ddbItemToMap(item))
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

// PutLeashAttestKey writes the user's published Ed25519 attestation
// pubkey to the LeashAttestKeys table. The payload arrives as
// pre-marshalled JSON from the vault — we don't sign/seal it (it's a
// public key); the vault is the trust anchor.
//
// Schema: pk=user_guid, sk=kid. Idempotent — re-publishing the same
// (user_guid, kid) overwrites the row, which is fine since the row
// content is fully determined by those keys.
func (d *DynamoDBClient) PutLeashAttestKey(ctx context.Context, payload []byte) error {
	if d.config.LeashAttestKeysTable == "" {
		return fmt.Errorf("leash_attest_keys_table not configured")
	}

	var row map[string]interface{}
	if err := json.Unmarshal(payload, &row); err != nil {
		return fmt.Errorf("decode leash attest key payload: %w", err)
	}
	if _, ok := row["user_guid"].(string); !ok {
		return fmt.Errorf("user_guid missing from leash attest key payload")
	}
	if _, ok := row["kid"].(string); !ok {
		return fmt.Errorf("kid missing from leash attest key payload")
	}

	item, err := marshalDynamoDBItem(row)
	if err != nil {
		return fmt.Errorf("marshal leash attest key: %w", err)
	}
	if _, err := d.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(d.config.LeashAttestKeysTable),
		Item:      item,
	}); err != nil {
		return fmt.Errorf("put leash attest key: %w", err)
	}
	return nil
}

// PutLeashIssued writes a leash issuance record to the LeashIssued
// table. Used by the public revocation status endpoint.
//
// Schema: pk=jti. Idempotent — re-publishing the same jti updates
// the row (used by revocation to flip `revoked` from false to true).
// `expires_at_ttl` is set to expires_at so DynamoDB TTL auto-prunes
// expired rows.
func (d *DynamoDBClient) PutLeashIssued(ctx context.Context, payload []byte) error {
	if d.config.LeashIssuedTable == "" {
		return fmt.Errorf("leash_issued_table not configured")
	}

	var row map[string]interface{}
	if err := json.Unmarshal(payload, &row); err != nil {
		return fmt.Errorf("decode leash issued payload: %w", err)
	}
	if _, ok := row["jti"].(string); !ok {
		return fmt.Errorf("jti missing from leash issued payload")
	}

	// Mirror `expires_at` into the TTL attribute. Vault sends both for
	// clarity but if it omitted the TTL field, derive it here so
	// DynamoDB can auto-prune.
	if _, ok := row["expires_at_ttl"]; !ok {
		if exp, ok := row["expires_at"].(float64); ok {
			row["expires_at_ttl"] = exp
		}
	}

	item, err := marshalDynamoDBItem(row)
	if err != nil {
		return fmt.Errorf("marshal leash issued: %w", err)
	}
	if _, err := d.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(d.config.LeashIssuedTable),
		Item:      item,
	}); err != nil {
		return fmt.Errorf("put leash issued: %w", err)
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

// ddbItemToMap recursively converts a DynamoDB item into a JSON-friendly map.
// Used by ListProposals to surface nested maps (e.g. vote_counts) and lists of
// maps (e.g. choices).
func ddbItemToMap(item map[string]dynamodbtypes.AttributeValue) map[string]interface{} {
	out := make(map[string]interface{}, len(item))
	for k, v := range item {
		if val, ok := ddbValueToInterface(v); ok {
			out[k] = val
		}
	}
	return out
}

func ddbValueToInterface(v dynamodbtypes.AttributeValue) (interface{}, bool) {
	switch attr := v.(type) {
	case *dynamodbtypes.AttributeValueMemberS:
		return attr.Value, true
	case *dynamodbtypes.AttributeValueMemberN:
		return attr.Value, true
	case *dynamodbtypes.AttributeValueMemberBOOL:
		return attr.Value, true
	case *dynamodbtypes.AttributeValueMemberM:
		m := make(map[string]interface{}, len(attr.Value))
		for mk, mv := range attr.Value {
			if mvv, ok := ddbValueToInterface(mv); ok {
				m[mk] = mvv
			}
		}
		return m, true
	case *dynamodbtypes.AttributeValueMemberL:
		items := make([]interface{}, 0, len(attr.Value))
		for _, li := range attr.Value {
			if lv, ok := ddbValueToInterface(li); ok {
				items = append(items, lv)
			}
		}
		return items, true
	case *dynamodbtypes.AttributeValueMemberNULL:
		return nil, false
	}
	return nil, false
}

// SubmitSignedVote validates a vault-signed vote and writes it to DynamoDB.
//
// The payload is the same JSON shape that the deprecated POST
// /member/votes/signed Lambda accepted. We validate Ed25519 + payload format
// here in the parent, then write to the votes table with a conditional
// expression so a duplicate (proposal_id, voting_public_key) returns
// ErrAlreadyVoted (caller treats it as success-equivalent for idempotency).
//
// maxAge=0 disables timestamp window checks (used for resubmits of receipts
// that may have been queued offline for arbitrary duration).
func (d *DynamoDBClient) SubmitSignedVote(ctx context.Context, payload []byte, maxAge time.Duration) error {
	if d.config.VotesTable == "" {
		return fmt.Errorf("votes table not configured")
	}
	if d.config.ProposalsTable == "" {
		return fmt.Errorf("proposals table not configured")
	}

	sub, err := ValidateSignedVote(payload, maxAge)
	if err != nil {
		return fmt.Errorf("vote validation failed: %w", err)
	}

	// Confirm proposal exists and the voting window covers voted_at. We
	// allow voted_at within [opens_at, closes_at]; the receipt timestamp
	// (not "now") is what matters so resubmitted offline votes don't get
	// rejected just because the proposal already closed.
	getResult, err := d.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:            aws.String(d.config.ProposalsTable),
		Key:                  map[string]dynamodbtypes.AttributeValue{"proposal_id": &dynamodbtypes.AttributeValueMemberS{Value: sub.ProposalID}},
		ProjectionExpression: aws.String("proposal_id, opens_at, closes_at, choices"),
	})
	if err != nil {
		return fmt.Errorf("failed to load proposal: %w", err)
	}
	if getResult.Item == nil {
		return fmt.Errorf("proposal not found: %s", sub.ProposalID)
	}

	prop := ddbItemToMap(getResult.Item)
	opensAtStr, _ := prop["opens_at"].(string)
	closesAtStr, _ := prop["closes_at"].(string)

	votedAt, err := time.Parse(time.RFC3339, sub.VotedAt)
	if err != nil {
		return fmt.Errorf("voted_at parse: %w", err)
	}
	if opensAtStr != "" {
		if opensAt, err := time.Parse(time.RFC3339, opensAtStr); err == nil && votedAt.Before(opensAt) {
			return fmt.Errorf("voted_at before voting opens (%s < %s)", votedAt, opensAt)
		}
	}
	if closesAtStr != "" {
		if closesAt, err := time.Parse(time.RFC3339, closesAtStr); err == nil && votedAt.After(closesAt) {
			return fmt.Errorf("voted_at after voting closes (%s > %s)", votedAt, closesAt)
		}
	}

	// Validate vote choice ID against the proposal's choices.
	if choicesAny, ok := prop["choices"].([]interface{}); ok && len(choicesAny) > 0 {
		valid := false
		for _, ci := range choicesAny {
			if cm, ok := ci.(map[string]interface{}); ok {
				if id, _ := cm["id"].(string); id == sub.Vote {
					valid = true
					break
				}
			}
		}
		if !valid {
			return fmt.Errorf("vote choice %q not in proposal choices", sub.Vote)
		}
	}

	// Mirror the existing schema: user_guid is sort key. For vault-signed
	// votes we use VAULT:<voting_public_key> as the sort key — this prevents
	// the same derived key from voting twice while not storing the actual
	// user_guid, preserving voter anonymity at the row level.
	voteRecord := map[string]dynamodbtypes.AttributeValue{
		"proposal_id":       &dynamodbtypes.AttributeValueMemberS{Value: sub.ProposalID},
		"user_guid":         &dynamodbtypes.AttributeValueMemberS{Value: "VAULT:" + sub.VotingPublicKey},
		"vote":              &dynamodbtypes.AttributeValueMemberS{Value: sub.Vote},
		"voted_at":          &dynamodbtypes.AttributeValueMemberS{Value: sub.VotedAt},
		"voting_public_key": &dynamodbtypes.AttributeValueMemberS{Value: sub.VotingPublicKey},
		"vote_signature":    &dynamodbtypes.AttributeValueMemberS{Value: sub.VoteSignature},
		"signed_payload":    &dynamodbtypes.AttributeValueMemberS{Value: sub.SignedPayload},
		"vote_source":       &dynamodbtypes.AttributeValueMemberS{Value: "vault"},
	}

	_, err = d.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(d.config.VotesTable),
		Item:                voteRecord,
		ConditionExpression: aws.String("attribute_not_exists(proposal_id) AND attribute_not_exists(user_guid)"),
	})
	if err != nil {
		var ccfe *dynamodbtypes.ConditionalCheckFailedException
		if errors.As(err, &ccfe) {
			return ErrAlreadyVoted
		}
		return fmt.Errorf("failed to put vote: %w", err)
	}

	log.Info().
		Str("proposal_id", sub.ProposalID).
		Str("voting_pk_prefix", sub.VotingPublicKey[:min(16, len(sub.VotingPublicKey))]+"...").
		Msg("Signed vote submitted to DynamoDB")
	return nil
}

// VoteProofResponse mirrors the JSON the vault-manager expects when verifying
// a vote receipt. Fields match getVoteMerkleProof.ts so the existing client
// logic can be ported directly.
type VoteProofResponse struct {
	ProposalID  string                   `json:"proposal_id"`
	MerkleRoot  string                   `json:"merkle_root"`
	LeafHash    string                   `json:"leaf_hash"`
	LeafIndex   int                      `json:"leaf_index"`
	Total       int                      `json:"total"`
	ProofPath   []map[string]interface{} `json:"proof_path"`
	Verified    bool                     `json:"verified"` // computed server-side as a sanity check
	Vote        map[string]interface{}   `json:"vote"`
	PublishedAt string                   `json:"published_at,omitempty"`
}

// GetVoteProof reads the Merkle artifacts published by closeExpiredProposals
// (or the legacy admin publish endpoint) and returns an inclusion proof for
// the given voting_public_key. Mirrors getVoteMerkleProof.ts but runs in the
// parent so the vault can verify without the app touching backend HTTP.
func (d *DynamoDBClient) GetVoteProof(ctx context.Context, proposalID, votingPublicKey string) ([]byte, error) {
	if d.config.PublishedVotesBucket == "" {
		return nil, fmt.Errorf("published votes bucket not configured")
	}
	if proposalID == "" || votingPublicKey == "" {
		return nil, fmt.Errorf("proposal_id and voting_public_key required")
	}

	// Confirm proposal has results published.
	gp, err := d.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:            aws.String(d.config.ProposalsTable),
		Key:                  map[string]dynamodbtypes.AttributeValue{"proposal_id": &dynamodbtypes.AttributeValueMemberS{Value: proposalID}},
		ProjectionExpression: aws.String("proposal_id, merkle_root, results_published_at"),
	})
	if err != nil {
		return nil, fmt.Errorf("get proposal: %w", err)
	}
	if gp.Item == nil {
		return nil, fmt.Errorf("proposal not found")
	}
	prop := ddbItemToMap(gp.Item)
	publishedAt, _ := prop["results_published_at"].(string)
	if publishedAt == "" {
		return nil, fmt.Errorf("results not yet published for proposal")
	}
	expectedRoot, _ := prop["merkle_root"].(string)

	votesJSON, err := d.s3GetJSON(ctx, proposalID+"/votes.json")
	if err != nil {
		return nil, fmt.Errorf("fetch votes.json: %w", err)
	}
	merkleJSON, err := d.s3GetJSON(ctx, proposalID+"/merkle.json")
	if err != nil {
		return nil, fmt.Errorf("fetch merkle.json: %w", err)
	}

	votes, _ := votesJSON["votes"].([]interface{})
	leaves, _ := merkleJSON["leaves"].([]interface{})
	tree, _ := merkleJSON["tree"].([]interface{})

	// Find the vote with matching voting_public_key.
	leafIndex := -1
	var matched map[string]interface{}
	for i, vAny := range votes {
		v, _ := vAny.(map[string]interface{})
		if v == nil {
			continue
		}
		if vk, _ := v["voting_public_key"].(string); vk == votingPublicKey {
			leafIndex = i
			matched = v
			break
		}
	}
	if leafIndex < 0 {
		return nil, fmt.Errorf("voting_public_key not found in published votes")
	}

	leafData := fmt.Sprintf("%s|%s|%s",
		matched["voting_public_key"], matched["vote"], matched["vote_signature"])
	leafHash := sha256Hex(leafData)
	if storedLeaf, _ := leaves[leafIndex].(string); storedLeaf != leafHash {
		return nil, fmt.Errorf("leaf hash mismatch (data integrity error)")
	}

	proofPath := buildMerkleProofPath(tree, leafIndex)
	verified := verifyMerklePath(leafHash, proofPath, expectedRoot)

	out := VoteProofResponse{
		ProposalID:  proposalID,
		MerkleRoot:  expectedRoot,
		LeafHash:    leafHash,
		LeafIndex:   leafIndex,
		Total:       len(votes),
		ProofPath:   proofPath,
		Verified:    verified,
		Vote:        matched,
		PublishedAt: publishedAt,
	}
	return json.Marshal(out)
}

func (d *DynamoDBClient) s3GetJSON(ctx context.Context, key string) (map[string]interface{}, error) {
	out, err := d.s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(d.config.PublishedVotesBucket),
		Key:    aws.String(key),
	})
	if err != nil {
		var nsk *s3types.NoSuchKey
		if errors.As(err, &nsk) {
			return nil, fmt.Errorf("not found: %s", key)
		}
		return nil, err
	}
	defer out.Body.Close()
	body, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, err
	}
	var m map[string]interface{}
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", key, err)
	}
	return m, nil
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func buildMerkleProofPath(tree []interface{}, leafIndex int) []map[string]interface{} {
	proof := []map[string]interface{}{}
	currentIndex := leafIndex
	for level := 0; level < len(tree)-1; level++ {
		levelNodes, _ := tree[level].([]interface{})
		if len(levelNodes) == 0 {
			break
		}
		isLeft := currentIndex%2 == 0
		siblingIndex := currentIndex + 1
		if !isLeft {
			siblingIndex = currentIndex - 1
		}
		var sibling string
		if siblingIndex < len(levelNodes) {
			sibling, _ = levelNodes[siblingIndex].(string)
		} else {
			// Odd-node level: sibling is the node itself (matches publishResults.ts).
			sibling, _ = levelNodes[currentIndex].(string)
		}
		dir := "right"
		if !isLeft {
			dir = "left"
		}
		proof = append(proof, map[string]interface{}{
			"hash":      sibling,
			"direction": dir,
		})
		currentIndex /= 2
	}
	return proof
}

func verifyMerklePath(leafHash string, proof []map[string]interface{}, root string) bool {
	cur := leafHash
	for _, step := range proof {
		h, _ := step["hash"].(string)
		dir, _ := step["direction"].(string)
		if dir == "left" {
			cur = sha256Hex(h + cur)
		} else {
			cur = sha256Hex(cur + h)
		}
	}
	return cur == root
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
