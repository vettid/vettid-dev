// Shared fixtures for the LEASH demo on vettid.dev. The values here
// are stable + public — they're the identifiers the gamified page
// hardcodes for Demo Alice and her agent. Real-user GUIDs never
// reach this code path.
//
// Fixture attestation keypair lives in Secrets Manager under
// `vettid/leash-demo-alice-attest`. The demoMintLeash Lambda
// generates it on first run and publishes Alice's pubkey to the
// LeashAttestKeys table so the public verifier can resolve her by kid.

export const DEMO_ALICE_USER_GUID = 'demo-alice-vettid';
export const DEMO_ALICE_AGENT_CONN_ID = 'demo-alice-agent';
export const DEMO_ALICE_KID = `leash-attest-${DEMO_ALICE_USER_GUID}-v1`;
export const DEMO_ALICE_DISPLAY = 'Demo Alice';
export const DEMO_ALICE_AGENT_DISPLAY = 'Demo Alice\'s AI';

export const DEMO_ATTEST_SECRET_NAME = 'vettid/leash-demo-alice-attest';

// Cap on the duration the demo page is allowed to mint. Real LEASHes
// from the production vault top out at 24h; demos use much shorter
// windows so the countdown timer is observable in real time.
export const DEMO_MAX_DURATION_SECS = 600; // 10 min

// Default duration when the page doesn't specify one. Long enough
// to read the JWT and click a few red-team buttons; short enough to
// see expire mid-demo if a viewer waits.
export const DEMO_DEFAULT_DURATION_SECS = 120; // 2 min

// Scope tokens the demo lets you toggle. Mirrors the spec grammar
// (resource:action[:qualifier]).
export const DEMO_SCOPE_OPTIONS: string[] = [
  'profile.email:read',
  'profile.phone:read',
  'profile.name:read',
  'credential.sign:cred-demo-1',
  'wallet.balance:read',
  'message:send',
];

/**
 * Guard for revoke + mint endpoints — refuse to touch any LEASH whose
 * issuer isn't Demo Alice. Prevents the public demo endpoints from
 * being used to revoke real-user LEASHes or mint impersonations.
 */
export function isDemoIssuer(iss: string | undefined | null): boolean {
  return iss === `did:vettid:${DEMO_ALICE_USER_GUID}`;
}
