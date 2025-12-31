# VettID Security Backlog

This file tracks security issues identified during the security audit that need to be addressed in future work.

## High Priority Issues

### Infrastructure (CDK)

1. ~~**Audit table missing PITR** - `infrastructure-stack.ts:100-104`~~ ✅ FIXED
   - ~~Enable point-in-time recovery for critical audit logs~~
   - ~~Fix: Add `pointInTimeRecovery: true` to Audit table~~

2. ~~**System monitoring Lambda wildcards** - `admin-stack.ts:771-787`~~ ✅ FIXED
   - ~~`getSystemHealth` and `getSystemLogs` can access ANY resource in account~~
   - ~~Fix: Scoped to VettID-specific resources only~~

3. ~~**IDOR in getAuditLog** - `getAuditLog.ts:27-46`~~ ✅ ALREADY FIXED
   - ~~Already restricted to admin_type='admin' with rate limiting~~

4. ~~**IDOR in getSystemLogs** - `getSystemLogs.ts:30-127`~~ ✅ ALREADY FIXED
   - ~~Already restricted to admin_type='admin' with audit logging~~

5. ~~**Bulk email content validation** - `sendBulkEmail.ts:166-183`~~ ✅ FIXED
   - ~~Added comprehensive content validation (JS, forms, external links, phishing keywords)~~

6. ~~**DynamoDB Scan instead of Query** - `createAuthChallenge.ts:64-74`~~ ✅ FIXED
   - ~~Uses Scan to find PIN status instead of Query with GSI~~
   - ~~Performance DoS vector - will scan entire table on high-user systems~~
   - ~~Fix: Use email-index GSI with QueryCommand instead of ScanCommand~~

7. ~~**Missing API Gateway logging** - `vettid-stack.ts:237-249`~~ ✅ FIXED
   - ~~No CloudWatch logging for API access patterns~~
   - ~~Fix: Enable access logging for audit trail~~

8. **CSP allows unsafe-inline** - `vettid-stack.ts:252-293`
   - `script-src 'unsafe-inline'` weakens XSS protection
   - Fix: Move inline scripts to external files, use nonces
   - Note: Requires significant frontend refactoring

### Frontend

9. **Token storage in localStorage** - `auth.js:51-65`
   - Tokens vulnerable to XSS attacks
   - Fix: Consider httpOnly cookies (requires backend changes)
   - Note: Requires significant architecture changes

10. **Missing CSP headers** - All frontend HTML files
    - Note: CSP is added at CloudFront level, not individual HTML files

11. ~~**Weak PKCE entropy** - `auth.js:19-24`~~ ✅ FIXED
    - ~~Modulo bias in `randomString()` reduces entropy~~
    - ~~Fix: Now uses proper base64url encoding~~

12. ~~**No JWT signature verification** - `jwt.js:11-27`~~ ✅ ALREADY FIXED
    - ~~Frontend has security comment noting JWT validation is server-side~~
    - ~~API Gateway Cognito authorizer validates signatures~~

## Medium Priority Issues

### Infrastructure

13. ~~**Log bucket encryption not explicit** - `vettid-stack.ts:53-70`~~ ✅ ALREADY FIXED
    - ~~Already has `encryption: s3.BucketEncryption.S3_MANAGED`~~

14. **Lambda functions without VPC** - All Lambda definitions
    - Lower defense-in-depth posture
    - Note: Trade-off between security and cold start latency

15. **API Gateway throttling review** - `vettid-stack.ts:940-949`
    - Current limits may allow single attacker to consume capacity

16. **Cognito missing password history** - `infrastructure-stack.ts:428-467`
    - Users can reuse previous passwords
    - Note: Not natively supported in Cognito CDK L2

17. **Member pool missing account lockout** - `infrastructure-stack.ts:700-770`
    - advancedSecurityMode requires Cognito Plus tier (currently on Essentials)
    - Note: Would need application-layer lockout or upgrade to Plus tier

18. **Broad SES permissions** - `infrastructure-stack.ts:755-761`
    - SES permission includes `identity/*` - allows sending from ANY identity
    - Fix: Scope to specific sender ARNs (`no-reply@auth.vettid.dev`)

### Lambda Handlers

19. ~~**Missing rate limiting on audit queries** - `getAuditLog.ts`~~ ✅ ALREADY FIXED
    - ~~Already has checkRateLimit() with 30 req/min~~

20. ~~**Weak timing-safe comparison (50ms)** - `util.ts:743`~~ ✅ FIXED
    - ~~Increased from 50ms to 200ms for better protection~~

21. **Missing CSRF token validation** - Frontend API requests
    - Relies solely on JWT Bearer token
    - Note: JWT in Authorization header provides CSRF protection

22. ~~**CORS fallback to hardcoded domain** - `util.ts:528`~~ ✅ FIXED
    - ~~Now throws error if no valid origins configured~~

23. **No rate limiting on admin endpoints** - Admin handlers
    - Compromised token could perform unlimited operations
    - Note: Several critical endpoints already have rate limiting

24. ~~**Weak PIN validation (allows 1111)** - `verifyPin.ts`, `updatePin.ts`~~ ✅ ALREADY FIXED
    - ~~isWeakPin() already checks for 1111, 1234, 1357, 2468, etc.~~

25. **Error message disclosure** - Multiple handlers
    - Raw `error.message` returned to clients
    - Fix: Use `sanitizeErrorForClient()` utility

26. ~~**Race condition in approveRegistration** - `approveRegistration.ts:78-105`~~ ✅ FIXED
    - ~~DynamoDB now updated BEFORE Cognito user creation~~
    - ~~Rollback on Cognito failure~~

## Low Priority Issues

27. ~~**Weak default pagination (50)** - `listRegistrations.ts:10-12`~~ ✅ FIXED
    - ~~Reduced to 20 across all list endpoints~~

28. **Missing SRI on external resources** - `admin/index.html:10-12`
    - Add integrity attribute to external scripts/styles

29. **Verbose console errors** - Multiple files
    - Sanitize console output in production

30. **No frontend rate limiting** - `register/index.html:134`
    - Add client-side throttling

31. **Silent audit trail failures** - `util.ts:181`
    - Consider failing operation if audit fails

32. **Outdated AWS SDK versions** - `package.json`
    - Run `npm update` for latest patches

33. **Missing request size limits in WAF** - `vettid-stack.ts`
    - Add WAF rule to limit payload sizes

34. **CSV injection risk in logs** - `sendBulkEmail.ts:227`
    - Hash email addresses in logs

35. **Deploy custom domain api.vettid.dev** - Infrastructure
    - Required for certificate pinning in mobile apps
    - Current AWS API Gateway uses rotating certificates

36. **Implement explicit KMS encryption** - DynamoDB and S3
    - Currently using default AWS-managed encryption
    - Consider customer-managed keys for sensitive data

---

## Completed Fixes (This Session)

1. ✅ **S3 log bucket ACL misconfiguration** - Changed to `BLOCK_ALL`
2. ✅ **SES wildcard permissions** - Scoped to specific identity ARNs
3. ✅ **XSS in email templates** - Added `escapeHtml()` to user inputs
4. ✅ **sanitizeInput() HTML entity bypass** - Removed entity decoding, added encoded pattern detection
5. ✅ **DOM XSS in account portal** - Used `textContent`, added URL validation
6. ✅ **Source maps in production** - Disabled in tsconfig.json
7. ✅ **Audit table PITR** - Enabled `pointInTimeRecovery: true` for critical audit logs
8. ✅ **DynamoDB Scan DoS** - Replaced Scan with Query using email-index GSI in createAuthChallenge
9. ✅ **API Gateway access logging** - Added CloudWatch log group with 1-year retention
10. ✅ **System monitoring Lambda permissions** - Scoped to VettID-specific resources
11. ✅ **Bulk email content validation** - Added phishing prevention (JS, forms, external links blocked)
12. ✅ **PKCE entropy** - Fixed modulo bias with proper base64url encoding
13. ✅ **Timing-safe comparison** - Increased from 50ms to 200ms
14. ✅ **CORS fallback** - Now throws error instead of silent fallback
15. ✅ **Race condition in approveRegistration** - Reordered DynamoDB before Cognito with rollback
16. ✅ **Default pagination** - Reduced from 50 to 20 across all list endpoints

---

*Last Updated: 2025-12-30*
*Initial Audit: 2025-12-03*
*Audit performed by: Claude Code*
