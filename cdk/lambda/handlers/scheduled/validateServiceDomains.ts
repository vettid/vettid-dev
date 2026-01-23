import {
  DynamoDBClient,
  ScanCommand,
  UpdateItemCommand,
} from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import { createHash } from 'crypto';
import * as dns from 'dns/promises';
import { putAudit } from '../../common/util';

const ddb = new DynamoDBClient({});

const TABLE_SERVICE_REGISTRY = process.env.TABLE_SERVICE_REGISTRY!;

// Maximum consecutive failures before suspension
const MAX_CONSECUTIVE_FAILURES = 3;

// DEV-014: Periodic domain validation for registered services
// Ensures services maintain control of their registered domains
// Runs on schedule (e.g., daily) to detect domain changes/expirations

/**
 * Scheduled Lambda to validate service domain ownership
 * - Checks DNS TXT records for all active services
 * - Suspends services after MAX_CONSECUTIVE_FAILURES
 * - Creates audit trail of validation attempts
 *
 * Triggered by EventBridge scheduled rule (daily at 3 AM UTC)
 */
export const handler = async (): Promise<void> => {
  console.log('Starting service domain validation job');

  const now = new Date().toISOString();

  try {
    // Scan for active services
    const scanResult = await ddb.send(new ScanCommand({
      TableName: TABLE_SERVICE_REGISTRY,
      FilterExpression: '#status = :active',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':active': 'active',
      }),
    }));

    if (!scanResult.Items || scanResult.Items.length === 0) {
      console.log('No active services found');
      return;
    }

    const services = scanResult.Items.map(item => unmarshall(item));
    console.log(`Found ${services.length} active services to validate`);

    let validatedCount = 0;
    let failedCount = 0;
    let suspendedCount = 0;

    for (const service of services) {
      const result = await validateServiceDomain(service, now);

      if (result.validated) {
        validatedCount++;
      } else {
        failedCount++;
        if (result.suspended) {
          suspendedCount++;
        }
      }
    }

    console.log(`Domain validation complete: ${validatedCount} valid, ${failedCount} failed, ${suspendedCount} suspended`);

  } catch (error: any) {
    console.error('Error in domain validation job:', error);
    throw error;
  }
};

/**
 * Validate a single service's domain ownership
 */
async function validateServiceDomain(
  service: Record<string, any>,
  now: string
): Promise<{ validated: boolean; suspended: boolean }> {
  const serviceId = service.service_id;
  const domain = service.domain;

  console.log(`Validating domain for service: ${serviceId} (${domain})`);

  // Verify DNS TXT record
  const verifyResult = await verifyDnsTxt(serviceId, domain);

  if (verifyResult.success) {
    // Reset failure count on success
    await updateValidationSuccess(serviceId, now);

    await putAudit({
      type: 'service_domain_validation_success',
      service_id: serviceId,
      domain,
      details: verifyResult.details,
    });

    return { validated: true, suspended: false };
  }

  // Validation failed - increment failure count
  const currentFailures = (service.validation_failures || 0) + 1;

  console.warn(`Domain validation failed for ${serviceId}: ${verifyResult.details} (failure ${currentFailures}/${MAX_CONSECUTIVE_FAILURES})`);

  await putAudit({
    type: 'service_domain_validation_failed',
    service_id: serviceId,
    domain,
    failure_count: currentFailures,
    details: verifyResult.details,
  });

  if (currentFailures >= MAX_CONSECUTIVE_FAILURES) {
    // Suspend the service
    await suspendService(serviceId, now, verifyResult.details);

    await putAudit({
      type: 'service_suspended',
      service_id: serviceId,
      domain,
      reason: `Domain validation failed ${currentFailures} consecutive times`,
      details: verifyResult.details,
    });

    console.warn(`Service ${serviceId} suspended after ${currentFailures} consecutive validation failures`);
    return { validated: false, suspended: true };
  }

  // Update failure count but don't suspend yet
  await updateValidationFailure(serviceId, now, currentFailures, verifyResult.details);

  return { validated: false, suspended: false };
}

/**
 * Verify DNS TXT record for domain ownership
 * Same logic as initial attestation verification
 */
async function verifyDnsTxt(
  serviceId: string,
  domain: string
): Promise<{ success: boolean; details: string }> {
  const expectedToken = generateDnsToken(serviceId);
  const txtHost = `_vettid-verify.${domain}`;

  try {
    const records = await dns.resolveTxt(txtHost);
    const flatRecords = records.map(r => r.join(''));

    for (const record of flatRecords) {
      if (record.includes(`vettid-verify=${expectedToken}`)) {
        return {
          success: true,
          details: `DNS TXT record verified at ${txtHost}`,
        };
      }
    }

    return {
      success: false,
      details: `Expected token not found. Found: ${flatRecords.join(', ') || 'none'}`,
    };
  } catch (error: any) {
    if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') {
      return {
        success: false,
        details: `No TXT record found at ${txtHost}`,
      };
    }
    // DNS resolution error - don't count as failure
    return {
      success: false,
      details: `DNS resolution error: ${error.message}`,
    };
  }
}

/**
 * Generate deterministic DNS verification token
 */
function generateDnsToken(serviceId: string): string {
  const hash = createHash('sha256')
    .update(`vettid-dns-verify:${serviceId}`)
    .digest('hex')
    .substring(0, 32);
  return hash;
}

/**
 * Update service record on successful validation
 */
async function updateValidationSuccess(serviceId: string, now: string): Promise<void> {
  await ddb.send(new UpdateItemCommand({
    TableName: TABLE_SERVICE_REGISTRY,
    Key: marshall({ service_id: serviceId }),
    UpdateExpression: 'SET last_validated_at = :validated_at, validation_failures = :zero, updated_at = :updated_at',
    ExpressionAttributeValues: marshall({
      ':validated_at': now,
      ':zero': 0,
      ':updated_at': now,
    }),
  }));
}

/**
 * Update service record on failed validation (not yet suspended)
 */
async function updateValidationFailure(
  serviceId: string,
  now: string,
  failureCount: number,
  details: string
): Promise<void> {
  await ddb.send(new UpdateItemCommand({
    TableName: TABLE_SERVICE_REGISTRY,
    Key: marshall({ service_id: serviceId }),
    UpdateExpression: 'SET validation_failures = :failures, last_validation_error = :error, last_validation_attempt = :attempt, updated_at = :updated_at',
    ExpressionAttributeValues: marshall({
      ':failures': failureCount,
      ':error': details,
      ':attempt': now,
      ':updated_at': now,
    }),
  }));
}

/**
 * Suspend a service due to validation failures
 */
async function suspendService(serviceId: string, now: string, reason: string): Promise<void> {
  await ddb.send(new UpdateItemCommand({
    TableName: TABLE_SERVICE_REGISTRY,
    Key: marshall({ service_id: serviceId }),
    UpdateExpression: 'SET #status = :suspended, suspended_at = :suspended_at, suspension_reason = :reason, updated_at = :updated_at',
    ExpressionAttributeNames: {
      '#status': 'status',
    },
    ExpressionAttributeValues: marshall({
      ':suspended': 'suspended',
      ':suspended_at': now,
      ':reason': `Domain validation failed: ${reason}`,
      ':updated_at': now,
    }),
  }));
}
