/**
 * DEPRECATED: Agent shortlink creation is no longer needed.
 *
 * Agents and devices now use the standard connection.create-invite flow
 * via NATS, which publishes invitations to the broker stream. The invite
 * code is resolved via the same endpoint as peer connections (GET https://vett.id/{code}).
 *
 * This Lambda handler is retained for API compatibility during transition
 * but returns a deprecation notice.
 */
import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';

export async function handler(
  _event: APIGatewayProxyEventV2
): Promise<APIGatewayProxyResultV2> {
  return {
    statusCode: 410,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      error: 'This endpoint is deprecated. Use connection.create-invite via NATS instead.',
      migration: 'Agents and devices now use the same invite flow as peer connections.',
    }),
  };
}
