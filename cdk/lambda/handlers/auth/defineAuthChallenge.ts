// lambda/handlers/auth/defineAuthChallenge.ts
import { DefineAuthChallengeTriggerHandler } from 'aws-lambda';
import { createHash } from 'crypto';

/**
 * Hash identifier for safe logging (no PII in logs)
 */
function hashForLog(value: string): string {
  return createHash('sha256').update(value.toLowerCase().trim()).digest('hex').substring(0, 12);
}

/**
 * Cognito DefineAuthChallenge trigger
 * Determines the authentication flow based on the user's session
 */
export const handler: DefineAuthChallengeTriggerHandler = async (event) => {
  // SECURITY: Only log session length and user existence, not full event with PII
  const userEmail = event.request.userAttributes?.email;
  console.log('DefineAuthChallenge: user_hash=%s, session_length=%d, user_not_found=%s',
    userEmail ? hashForLog(userEmail) : 'unknown',
    event.request.session?.length || 0,
    event.request.userNotFound || false
  );

  const { request } = event;

  // Log session details when we have a session (helps debug auth failures)
  if (request.session && request.session.length > 0) {
    console.log('DefineAuthChallenge session details: challengeName=%s, challengeResult=%s',
      request.session[0].challengeName,
      request.session[0].challengeResult
    );
  }

  // If user doesn't exist, fail auth
  if (!event.request.userNotFound) {
    // First step: send custom challenge (magic link)
    if (request.session.length === 0) {
      event.response.issueTokens = false;
      event.response.failAuthentication = false;
      event.response.challengeName = 'CUSTOM_CHALLENGE';
    }
    // Second step: verify the magic link token
    else if (
      request.session.length === 1 &&
      request.session[0].challengeName === 'CUSTOM_CHALLENGE' &&
      request.session[0].challengeResult === true
    ) {
      event.response.issueTokens = true;
      event.response.failAuthentication = false;
    }
    // If verification failed
    else {
      event.response.issueTokens = false;
      event.response.failAuthentication = true;
    }
  } else {
    // User doesn't exist
    event.response.issueTokens = false;
    event.response.failAuthentication = true;
  }

  // SECURITY: Only log response flags, not full response object
  console.log('DefineAuthChallenge response: issueTokens=%s, failAuth=%s, challenge=%s',
    event.response.issueTokens,
    event.response.failAuthentication,
    event.response.challengeName || 'none'
  );
  return event;
};
