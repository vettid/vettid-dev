// testApiKey.ts — shared lazy loader for the test-harness shared
// secret. Each test handler imports loadTestApiKey() and awaits it
// before comparing against the inbound x-test-api-key header. The
// secret value lives in Secrets Manager (ARN passed via env) so it
// rotates without a redeploy and never lands in CloudWatch logs.

import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';

const sm = new SecretsManagerClient({});

let cached: Promise<string | null> | null = null;

/**
 * Returns the test API key string, fetched lazily from Secrets Manager
 * on first call and cached for the lifetime of the Lambda container.
 *
 * Returns null when the secret ARN env var is unset (test endpoints
 * were deployed without their secret — refuse all traffic) or when the
 * SDK call fails (cache cleared so the next request can retry).
 */
export function loadTestApiKey(): Promise<string | null> {
  if (cached) return cached;

  const arn = process.env.TEST_API_KEY_SECRET_ARN;
  if (!arn) {
    cached = Promise.resolve(null);
    return cached;
  }

  cached = sm.send(new GetSecretValueCommand({ SecretId: arn }))
    .then((r) => r.SecretString ?? null)
    .catch((err) => {
      console.error('test api key secret load failed', err);
      // Drop the cached rejection so the next request can retry the
      // fetch instead of permanently failing.
      cached = null;
      return null;
    });
  return cached;
}
