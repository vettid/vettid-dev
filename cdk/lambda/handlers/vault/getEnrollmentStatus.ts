import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, QueryCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  notFound,
  internalError,
  getRequestId,
  requireUserClaims,
} from '../../common/util';

const ddb = new DynamoDBClient({});

const TABLE_ENROLLMENT_SESSIONS = process.env.TABLE_ENROLLMENT_SESSIONS!;

/**
 * Enrollment phase descriptions for UI display
 */
const PHASE_DESCRIPTIONS: Record<string, { step: number; label: string; description: string }> = {
  'WEB_INITIATED': {
    step: 1,
    label: 'Session Created',
    description: 'QR code ready - waiting for mobile app to scan',
  },
  'AUTHENTICATED': {
    step: 2,
    label: 'App Connected',
    description: 'Mobile app scanned QR code and authenticated',
  },
  'NATS_CONNECTED': {
    step: 3,
    label: 'Secure Channel',
    description: 'Connected to vault infrastructure',
  },
  'ATTESTATION_VERIFIED': {
    step: 4,
    label: 'Enclave Verified',
    description: 'Hardware attestation verified - enclave identity confirmed',
  },
  'PIN_SET': {
    step: 5,
    label: 'PIN Created',
    description: 'Vault PIN has been set up',
  },
  'PASSWORD_SET': {
    step: 6,
    label: 'Credential Created',
    description: 'Vault credential has been created',
  },
  'COMPLETED': {
    step: 7,
    label: 'Complete',
    description: 'Enrollment complete - vault is ready to use',
  },
  'CANCELLED': {
    step: -1,
    label: 'Cancelled',
    description: 'Enrollment was cancelled',
  },
  'EXPIRED': {
    step: -1,
    label: 'Expired',
    description: 'Enrollment session expired',
  },
};

const TOTAL_STEPS = 7;

/**
 * GET /vault/enroll/status
 *
 * Get the current enrollment status for the authenticated user.
 * Used by Account Portal to show enrollment progress.
 *
 * Returns:
 * - Current phase and progress
 * - Timestamps for each completed phase
 * - Human-readable status for UI display
 *
 * Requires member JWT authentication.
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);
  const origin = event.headers?.origin;

  try {
    // Validate member authentication
    const claimsResult = requireUserClaims(event);
    if ('error' in claimsResult) {
      return claimsResult.error;
    }
    const { claims } = claimsResult;
    const userGuid = claims.user_guid;

    // Get most recent enrollment session for this user
    const sessionResult = await ddb.send(new QueryCommand({
      TableName: TABLE_ENROLLMENT_SESSIONS,
      IndexName: 'user-index',
      KeyConditionExpression: 'user_guid = :guid',
      ExpressionAttributeValues: marshall({
        ':guid': userGuid,
      }),
      ScanIndexForward: false, // Most recent first
      Limit: 1,
    }));

    if (!sessionResult.Items || sessionResult.Items.length === 0) {
      return notFound('No enrollment session found', origin);
    }

    const session = unmarshall(sessionResult.Items[0]);

    // Check if session has expired (but hasn't been marked as such)
    const expiresAt = typeof session.expires_at === 'number'
      ? session.expires_at
      : new Date(session.expires_at).getTime();

    const isExpired = expiresAt < Date.now() && session.status !== 'COMPLETED' && session.status !== 'CANCELLED';

    const currentStatus = isExpired ? 'EXPIRED' : session.status;
    const phaseInfo = PHASE_DESCRIPTIONS[currentStatus] || {
      step: 0,
      label: 'Unknown',
      description: 'Unknown status',
    };

    // Build timeline of completed phases
    const timeline: Array<{
      phase: string;
      label: string;
      completed: boolean;
      timestamp?: string;
    }> = [];

    const phases = ['WEB_INITIATED', 'AUTHENTICATED', 'NATS_CONNECTED', 'ATTESTATION_VERIFIED', 'PIN_SET', 'PASSWORD_SET', 'COMPLETED'];

    for (const phase of phases) {
      const phaseKey = phase.toLowerCase() + '_at';
      const timestamp = session[phaseKey] || session[phase.toLowerCase().replace(/_/g, '') + '_at'];

      // Determine if this phase is completed based on current status
      const currentPhaseIndex = phases.indexOf(currentStatus);
      const thisPhaseIndex = phases.indexOf(phase);
      const isCompleted = thisPhaseIndex <= currentPhaseIndex && currentStatus !== 'CANCELLED' && currentStatus !== 'EXPIRED';

      timeline.push({
        phase,
        label: PHASE_DESCRIPTIONS[phase]?.label || phase,
        completed: isCompleted,
        timestamp: timestamp || undefined,
      });
    }

    // Calculate progress percentage
    const progressPercent = phaseInfo.step > 0
      ? Math.round((phaseInfo.step / TOTAL_STEPS) * 100)
      : 0;

    return ok({
      session_id: session.session_id,
      user_guid: userGuid,
      status: currentStatus,
      step: phaseInfo.step,
      total_steps: TOTAL_STEPS,
      progress_percent: progressPercent,
      label: phaseInfo.label,
      description: phaseInfo.description,
      timeline,
      device_type: session.device_type,
      created_at: session.created_at_iso || session.created_at,
      expires_at: session.expires_at_iso || new Date(session.expires_at).toISOString(),
      is_expired: isExpired,
      is_complete: currentStatus === 'COMPLETED',
      can_continue: !isExpired && currentStatus !== 'COMPLETED' && currentStatus !== 'CANCELLED',
    }, origin);

  } catch (error: any) {
    console.error('Get enrollment status error:', error);
    return internalError('Failed to get enrollment status', origin);
  }
};
