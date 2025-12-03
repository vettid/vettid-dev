# VettID Security Backlog

This file tracks security issues identified during the security audit that need to be addressed in future work.

## High Priority Issues

### Infrastructure (CDK)

1. **Audit table missing PITR** - `infrastructure-stack.ts:100-104`
   - Enable point-in-time recovery for critical audit logs
   - Fix: Add `pointInTimeRecovery: true` to Audit table

2. **System monitoring Lambda wildcards** - `admin-stack.ts:771-787`
   - `getSystemHealth` and `getSystemLogs` can access ANY resource in account
   - Fix: Scope to VettID-specific resources only

3. **IDOR in getAuditLog** - `getAuditLog.ts:27-46`
   - Any admin can query ANY email's audit logs
   - Fix: Restrict to own email or add role-based access control

4. **IDOR in getSystemLogs** - `getSystemLogs.ts:30-127`
   - All admins can access ALL system logs
   - Fix: Implement role-based access for security-sensitive logs

5. **Bulk email content validation** - `sendBulkEmail.ts:166-183`
   - Minimal validation on body_html - potential phishing risk
   - Fix: Add content restrictions or require pre-approved templates

6. **Missing API Gateway logging** - `vettid-stack.ts:237-249`
   - No CloudWatch logging for API access patterns
   - Fix: Enable access logging for audit trail

7. **CSP allows unsafe-inline** - `vettid-stack.ts:252-293`
   - `script-src 'unsafe-inline'` weakens XSS protection
   - Fix: Move inline scripts to external files, use nonces

### Frontend

8. **Token storage in localStorage** - `auth.js:51-65`
   - Tokens vulnerable to XSS attacks
   - Fix: Consider httpOnly cookies (requires backend changes)

9. **Missing CSP headers** - All frontend HTML files
   - No Content-Security-Policy configured
   - Fix: Add CSP at CloudFront level

10. **Weak PKCE entropy** - `auth.js:19-24`
    - Modulo bias in `randomString()` reduces entropy
    - Fix: Use proper base64url encoding

11. **No JWT signature verification** - `jwt.js:11-27`
    - Frontend parses JWT without signature validation
    - Fix: Only use JWT for UI state, never for authorization

## Medium Priority Issues

### Infrastructure

12. **Log bucket encryption not explicit** - `vettid-stack.ts:53-70`
    - Should explicitly enable S3 encryption

13. **Lambda functions without VPC** - All Lambda definitions
    - Lower defense-in-depth posture

14. **API Gateway throttling review** - `vettid-stack.ts:940-949`
    - Current limits may allow single attacker to consume capacity

15. **Cognito missing password history** - `infrastructure-stack.ts:428-467`
    - Users can reuse previous passwords

16. **Member pool missing account lockout** - `infrastructure-stack.ts:425-450`
    - No brute-force protection at Cognito level

### Lambda Handlers

17. **Missing rate limiting on audit queries** - `getAuditLog.ts`
    - Admin could hammer the endpoint

18. **Weak timing-safe comparison (50ms)** - `util.ts:743`
    - Increase to 200-500ms for better protection

19. **Missing CSRF token validation** - Frontend API requests
    - Relies solely on JWT Bearer token

20. **CORS fallback to hardcoded domain** - `util.ts:528`
    - Should throw error instead of fallback

21. **No rate limiting on admin endpoints** - Admin handlers
    - Compromised token could perform unlimited operations

22. **Weak PIN validation (allows 1111)** - `verifyPin.ts`, `updatePin.ts`
    - Reject sequential/repeated PINs

23. **Error message disclosure** - Multiple handlers
    - Raw `error.message` returned to clients
    - Fix: Use `sanitizeErrorForClient()` utility

24. **Race condition in approveRegistration** - `approveRegistration.ts:78-105`
    - Cognito user created before conditional update

## Low Priority Issues

25. **Weak default pagination (50)** - `listRegistrations.ts:10-12`
    - Should be 10-20 for performance

26. **Missing SRI on external resources** - `admin/index.html:10-12`
    - Add integrity attribute to external scripts/styles

27. **Verbose console errors** - Multiple files
    - Sanitize console output in production

28. **No frontend rate limiting** - `register/index.html:134`
    - Add client-side throttling

29. **Silent audit trail failures** - `util.ts:181`
    - Consider failing operation if audit fails

30. **Outdated AWS SDK versions** - `package.json`
    - Run `npm update` for latest patches

31. **Missing request size limits in WAF** - `vettid-stack.ts`
    - Add WAF rule to limit payload sizes

32. **CSV injection risk in logs** - `sendBulkEmail.ts:227`
    - Hash email addresses in logs

---

## Completed Fixes (This Session)

1. ✅ **S3 log bucket ACL misconfiguration** - Changed to `BLOCK_ALL`
2. ✅ **SES wildcard permissions** - Scoped to specific identity ARNs
3. ✅ **XSS in email templates** - Added `escapeHtml()` to user inputs
4. ✅ **sanitizeInput() HTML entity bypass** - Removed entity decoding, added encoded pattern detection
5. ✅ **DOM XSS in account portal** - Used `textContent`, added URL validation
6. ✅ **Source maps in production** - Disabled in tsconfig.json

---

*Generated: 2025-12-03*
*Audit performed by: Claude Code*
