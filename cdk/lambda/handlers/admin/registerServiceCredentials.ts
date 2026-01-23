import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import {
  DynamoDBClient,
  PutItemCommand,
  GetItemCommand,
  QueryCommand,
} from '@aws-sdk/client-dynamodb';
import { KMSClient, EncryptCommand } from '@aws-sdk/client-kms';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  created,
  badRequest,
  notFound,
  conflict,
  internalError,
  requireAdminGroup,
  getAdminEmail,
  parseJsonBody,
  putAudit,
} from '../../common/util';
import { generateServiceAccountCredentials } from '../../common/nats-jwt';

const ddb = new DynamoDBClient({});
const kms = new KMSClient({});

const TABLE_SUPPORTED_SERVICES = process.env.TABLE_SUPPORTED_SERVICES!;
const TABLE_SERVICE_REGISTRY = process.env.TABLE_SERVICE_REGISTRY!;
const NATS_SEED_KMS_KEY_ID = process.env.NATS_SEED_KMS_KEY_ID!;

interface RegisterServiceRequest {
  service_id: string;
  domain: string;
  public_key: string;        // Ed25519 public key (base64)
  encryption_key: string;    // X25519 public key (base64)
  webhook_url?: string;
  rate_limit?: number;       // Messages per second (default 100)
}

/**
 * POST /admin/service-registry
 *
 * Register NATS credentials for an existing supported service.
 * This creates the service's NATS account and issues initial credentials.
 *
 * SECURITY: The NATS account seed is encrypted with KMS before storage.
 * The seed is only returned once - services must store it securely.
 *
 * Prerequisites:
 * - Service must exist in supportedServices table
 * - Domain must be unique across all registered services
 *
 * Requires admin JWT authentication.
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  try {
    // Validate admin authentication
    const adminCheck = requireAdminGroup(event);
    if (adminCheck) return adminCheck;

    const adminEmail = getAdminEmail(event);

    // Parse request body
    let body: RegisterServiceRequest;
    try {
      body = parseJsonBody<RegisterServiceRequest>(event);
    } catch (e: any) {
      return badRequest(e.message);
    }

    // Validate required fields
    if (!body.service_id || !body.domain || !body.public_key || !body.encryption_key) {
      return badRequest('service_id, domain, public_key, and encryption_key are required.');
    }

    // Validate domain format
    if (!/^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$/i.test(body.domain)) {
      return badRequest('Invalid domain format.');
    }

    // Validate key formats (base64)
    try {
      const pubKeyBytes = Buffer.from(body.public_key, 'base64');
      const encKeyBytes = Buffer.from(body.encryption_key, 'base64');
      if (pubKeyBytes.length !== 32) {
        return badRequest('public_key must be a 32-byte Ed25519 public key (base64 encoded).');
      }
      if (encKeyBytes.length !== 32) {
        return badRequest('encryption_key must be a 32-byte X25519 public key (base64 encoded).');
      }
    } catch {
      return badRequest('Keys must be valid base64-encoded 32-byte values.');
    }

    // Verify service exists in supportedServices
    const serviceResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_SUPPORTED_SERVICES,
      Key: marshall({ service_id: body.service_id }),
    }));

    if (!serviceResult.Item) {
      return notFound(`Service '${body.service_id}' not found in supported services.`);
    }

    const supportedService = unmarshall(serviceResult.Item);

    // Check if service already has registry entry
    const existingRegistry = await ddb.send(new GetItemCommand({
      TableName: TABLE_SERVICE_REGISTRY,
      Key: marshall({ service_id: body.service_id }),
    }));

    if (existingRegistry.Item) {
      return conflict(`Service '${body.service_id}' is already registered. Use update endpoint to modify.`);
    }

    // Check domain uniqueness
    const domainCheck = await ddb.send(new QueryCommand({
      TableName: TABLE_SERVICE_REGISTRY,
      IndexName: 'domain-index',
      KeyConditionExpression: '#domain = :domain',
      ExpressionAttributeNames: { '#domain': 'domain' },
      ExpressionAttributeValues: { ':domain': { S: body.domain.toLowerCase() } },
    }));

    if (domainCheck.Items && domainCheck.Items.length > 0) {
      return conflict(`Domain '${body.domain}' is already registered to another service.`);
    }

    // Generate NATS account credentials
    const natsCredentials = await generateServiceAccountCredentials(
      body.service_id,
      supportedService.name
    );

    // Encrypt the NATS seed with KMS
    const encryptResult = await kms.send(new EncryptCommand({
      KeyId: NATS_SEED_KMS_KEY_ID,
      Plaintext: Buffer.from(natsCredentials.seed),
      EncryptionContext: {
        service_id: body.service_id,
        purpose: 'nats_account_seed',
      },
    }));

    const encryptedSeed = Buffer.from(encryptResult.CiphertextBlob!).toString('base64');
    const now = new Date().toISOString();

    // Create service registry entry
    const registryItem = {
      service_id: body.service_id,
      status: 'pending', // Requires attestation to become active
      domain: body.domain.toLowerCase(),
      public_key: body.public_key,
      encryption_key: body.encryption_key,
      nats_account_public_key: natsCredentials.publicKey,
      nats_account_seed_encrypted: encryptedSeed,
      webhook_url: body.webhook_url || null,
      rate_limit: body.rate_limit ?? 100,
      attestations: [],
      created_at: now,
      created_by: adminEmail,
      updated_at: now,
    };

    await ddb.send(new PutItemCommand({
      TableName: TABLE_SERVICE_REGISTRY,
      Item: marshall(registryItem, { removeUndefinedValues: true }),
    }));

    // Audit log
    await putAudit({
      type: 'service_registered',
      admin_email: adminEmail,
      service_id: body.service_id,
      domain: body.domain,
      nats_account_public_key: natsCredentials.publicKey,
    });

    // SECURITY: Return credentials only once - service must store securely
    return created({
      service_id: body.service_id,
      status: 'pending',
      domain: body.domain,
      nats_account_public_key: natsCredentials.publicKey,
      // SECURITY: This is the only time the seed is returned
      // Service must store it securely - it cannot be retrieved again
      nats_account_seed: natsCredentials.seed,
      nats_account_jwt: natsCredentials.accountJwt,
      message: 'Service registered. Complete domain attestation to activate. Store credentials securely - the seed cannot be retrieved again.',
    });

  } catch (error: any) {
    console.error('Register service credentials error:', error);
    return internalError('Failed to register service credentials.');
  }
};
