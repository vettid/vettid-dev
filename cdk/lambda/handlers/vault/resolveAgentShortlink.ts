/**
 * DEPRECATED: Agent shortlink resolution is no longer needed.
 *
 * Agents and devices now resolve invite codes via the same broker endpoint
 * as peer connections (GET https://vett.id/{code}). The invite code is
 * published to the NATS broker stream by the vault during connection.create-invite.
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
      error: 'This endpoint is deprecated. Resolve invite codes via GET https://vett.id/{code} instead.',
      migration: 'Agents and devices now use the same invite broker as peer connections.',
    }),
  };
}
