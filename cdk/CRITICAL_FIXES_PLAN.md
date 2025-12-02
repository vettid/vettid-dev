# Critical Issues Fix Plan

## Issue 1: DynamoDB Subscriptions Table Key Design

### Current Problem
The Subscriptions table uses `user_guid` as the partition key with no sort key. This means each user can only have one subscription record - creating a new subscription overwrites the previous one.

### Analysis
Looking at the current usage, it appears the system is designed for **one active subscription per user** (not subscription history). The handlers:
- `createSubscription.ts` - Creates/updates subscription for user
- `getSubscriptionStatus.ts` - Gets current subscription status
- `cancelSubscription.ts` - Cancels subscription (sets status to cancelled)

### Decision Point
**Option A**: Keep single-subscription design (current behavior is intentional)
- Add documentation clarifying this is by design
- Add validation to prevent accidental overwrites
- Ensure old subscription data is preserved in audit log before overwrite

**Option B**: Support subscription history
- Change partition key to `subscription_id`
- Add GSI on `user_guid` to query user's subscriptions
- Update all handlers to work with multiple subscriptions
- Add logic to determine "active" subscription

### Recommended Fix: Option A (Minimal Change)
The single-subscription model seems intentional. We should:
1. Add audit logging before any subscription update/create to preserve history
2. Add a check in `createSubscription.ts` to warn/confirm if overwriting an active subscription
3. Document the single-subscription-per-user constraint in CLAUDE.md

### Files to Modify
- `cdk/lambda/handlers/member/createSubscription.ts` - Add audit logging and overwrite protection
- `cdk/CLAUDE.md` - Document the design decision

---

## Issue 2: Race Condition in Membership Request Approval

### Current Problem
In `requestMembership.ts`, the flow is:
1. Add user to Cognito `member` group
2. Update DynamoDB registration status to `member`

If step 1 succeeds but step 2 fails, the user is in the `member` group in Cognito but their registration record still shows `registered` status, causing inconsistent authorization.

### Recommended Fix
Reverse the order and use conditional updates:
1. First, update DynamoDB with a conditional expression (only if current status allows)
2. If DynamoDB succeeds, then add to Cognito group
3. If Cognito fails, rollback the DynamoDB change

### Files to Modify
- `cdk/lambda/handlers/member/requestMembership.ts`

### Implementation
```typescript
// Step 1: Update DynamoDB first (with condition to prevent race)
const updateResult = await ddb.send(new UpdateItemCommand({
  TableName: TABLES.registrations,
  Key: marshall({ registration_id }),
  UpdateExpression: 'SET #status = :newStatus, membership_approved_at = :now',
  ConditionExpression: '#status = :currentStatus',
  ExpressionAttributeNames: { '#status': 'status' },
  ExpressionAttributeValues: marshall({
    ':newStatus': 'member',
    ':currentStatus': 'registered',
    ':now': new Date().toISOString()
  })
}));

// Step 2: Add to Cognito group
try {
  await cognito.send(new AdminAddUserToGroupCommand({...}));
} catch (cognitoError) {
  // Rollback DynamoDB change
  await ddb.send(new UpdateItemCommand({
    TableName: TABLES.registrations,
    Key: marshall({ registration_id }),
    UpdateExpression: 'SET #status = :oldStatus, membership_approved_at = :null',
    ExpressionAttributeNames: { '#status': 'status' },
    ExpressionAttributeValues: marshall({
      ':oldStatus': 'registered',
      ':null': null
    })
  }));
  throw cognitoError;
}
```

---

## Issue 3: Unchecked Token Claims

### Current Problem
Multiple handlers access JWT claims like `custom:user_guid` without proper validation. While most have a null check, the pattern is fragile and inconsistent.

### Files Affected
- `cdk/lambda/handlers/member/submitVote.ts`
- `cdk/lambda/handlers/member/requestMembership.ts`
- `cdk/lambda/handlers/member/createSubscription.ts`
- `cdk/lambda/handlers/member/getSubscriptionStatus.ts`
- `cdk/lambda/handlers/member/cancelSubscription.ts`
- And others...

### Recommended Fix
Create a standardized utility function in `common/util.ts`:

```typescript
export interface UserClaims {
  user_guid: string;
  email: string;
  groups: string[];
}

export function extractUserClaims(event: APIGatewayProxyEventV2): UserClaims | null {
  const claims = (event.requestContext as any)?.authorizer?.jwt?.claims;

  const user_guid = claims?.['custom:user_guid'];
  const email = claims?.email;
  const groups = claims?.['cognito:groups'] || [];

  if (!user_guid || !email) {
    return null;
  }

  return { user_guid, email, groups };
}

export function requireUserClaims(event: APIGatewayProxyEventV2):
  { claims: UserClaims } | { error: APIGatewayProxyResultV2 } {
  const claims = extractUserClaims(event);
  if (!claims) {
    return {
      error: badRequest('Invalid token: missing required claims (user_guid or email)')
    };
  }
  return { claims };
}
```

Then update handlers to use:
```typescript
const result = requireUserClaims(event);
if ('error' in result) return result.error;
const { user_guid, email } = result.claims;
```

### Files to Modify
- `cdk/lambda/common/util.ts` - Add new utility functions
- All member handlers - Update to use new utility

---

## Issue 4: GUID Mismatch on User Recreation

### Current Problem
In `approveRegistration.ts`, when a Cognito user already exists:
1. Handler catches `UsernameExistsException`
2. Fetches the existing user to get their GUID
3. If `custom:user_guid` attribute is missing, generates a NEW GUID
4. This new GUID won't match what's in DynamoDB

### Recommended Fix
1. Never generate a new GUID for existing users
2. If existing user lacks `custom:user_guid`, treat as an error condition
3. Admin must manually resolve (delete and recreate user, or set attribute)

### Implementation
```typescript
} catch (createError: any) {
  if (createError.name === 'UsernameExistsException') {
    // User exists - get their existing GUID
    const existingUser = await cognito.send(new AdminGetUserCommand({
      UserPoolId: USER_POOL_ID,
      Username: email
    }));

    const guidAttr = existingUser.UserAttributes?.find(a => a.Name === 'custom:user_guid');

    if (!guidAttr?.Value) {
      // Critical: existing user has no GUID - cannot proceed safely
      await putAudit({
        type: 'approval_error_missing_guid',
        email,
        registration_id,
        error: 'Existing Cognito user missing custom:user_guid attribute'
      });

      return {
        statusCode: 500,
        body: JSON.stringify({
          error: 'User exists but is missing required attributes. Please contact support.'
        })
      };
    }

    userGuid = guidAttr.Value;
  } else {
    throw createError;
  }
}
```

### Files to Modify
- `cdk/lambda/handlers/admin/approveRegistration.ts`

---

## Summary of Changes

| Issue | Files to Modify | Estimated Complexity |
|-------|-----------------|---------------------|
| 1. Subscription Key Design | createSubscription.ts, CLAUDE.md | Low |
| 2. Race Condition | requestMembership.ts | Medium |
| 3. Token Claims | util.ts, ~15 member handlers | Medium |
| 4. GUID Mismatch | approveRegistration.ts | Low |

## Implementation Order

1. **Issue 3 (Token Claims)** - Fix util.ts first since other fixes may depend on it
2. **Issue 4 (GUID Mismatch)** - Quick fix, prevents data corruption
3. **Issue 2 (Race Condition)** - Important for data consistency
4. **Issue 1 (Subscription Design)** - Document and add safeguards

## Testing Plan

After implementing:
1. Test membership request flow end-to-end
2. Test subscription creation/update flow
3. Test approval of existing vs new users
4. Verify audit logs are created correctly
5. Test error cases (missing claims, failed Cognito calls, etc.)

---

## Implementation Status

All critical issues have been implemented:

### Issue 1: Subscription Key Design - ✅ COMPLETED
- Added audit logging in `createSubscription.ts` to log previous subscription before overwrite (`subscription_replaced` action)
- Added detailed documentation in `infrastructure-stack.ts` explaining the single-subscription-per-user design decision
- Previous subscriptions are now preserved in the Audit table for historical reference

### Issue 2: Race Condition - ✅ COMPLETED
- Reversed operation order in `requestMembership.ts`: DynamoDB first, then Cognito
- Added conditional expression to prevent race conditions (`ConditionalCheckFailedException` handling)
- Added rollback logic if Cognito fails after DynamoDB succeeds
- Added audit logging for rollback failures (`membership_rollback_failed`)

### Issue 3: Token Claims Validation - ✅ COMPLETED
- Added `UserClaims` interface to `util.ts`
- Added `extractUserClaims()` function with proper null/type validation
- Added `requireUserClaims()` function returning discriminated union for clean error handling
- Updated handlers: `submitVote.ts`, `createSubscription.ts`, `getSubscriptionStatus.ts`, `cancelSubscription.ts`, `cancelAccount.ts`, `listEnabledSubscriptionTypes.ts`, `requestMembership.ts`

### Issue 4: GUID Mismatch - ✅ COMPLETED
- Modified `approveRegistration.ts` to return an error if existing Cognito user lacks `custom:user_guid`
- Added audit logging for this error case (`approval_error_missing_guid`)
- Removed dangerous fallback that would generate a new GUID for existing users
