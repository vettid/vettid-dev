# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

VettID Scaffold is a serverless invite-based registration system built with AWS CDK. It implements an approval workflow where users register using invite codes, admins review registrations via a PKCE-secured admin UI, and lifecycle emails are sent via DynamoDB Streams + SES.

**Tech Stack:**
- AWS CDK (TypeScript) for infrastructure
- Lambda (Node.js 20, TypeScript) for serverless handlers
- DynamoDB for data storage with streams
- Cognito User Pool for authentication (PKCE/Authorization Code flow)
- API Gateway (HTTP API) with Cognito JWT authorizer
- CloudFront + S3 for static site hosting
- SES for templated transactional emails
- Route 53 + ACM for custom domains

## Common Commands

All commands should be run from the `cdk/` directory:

```bash
cd cdk

# Install dependencies
npm i

# Build TypeScript (compiles bin/, lib/, lambda/ to dist/)
npm run build

# Watch mode for development
npm run watch

# Bootstrap CDK (one-time setup per AWS account/region)
npm run bootstrap

# Deploy all stacks
npm run deploy

# Synthesize CloudFormation template
npm run synth

# Destroy all stacks
npm run destroy
```

### AWS CLI Commands

```bash
# Create admin user in Cognito
aws cognito-idp admin-create-user \
  --user-pool-id <POOL_ID> \
  --username admin@vettid.dev \
  --user-attributes Name=email,Value=admin@vettid.dev

# Add user to admin group
aws cognito-idp admin-add-user-to-group \
  --user-pool-id <POOL_ID> \
  --username admin@vettid.dev \
  --group-name admin

# Create SES email templates (required for stream processor)
aws ses create-template --cli-input-json file://template-pending.json
aws ses create-template --cli-input-json file://template-approved.json
aws ses create-template --cli-input-json file://template-rejected.json
```

## Architecture

### Infrastructure (CDK Stack)

**Main Stack:** `lib/vettid-stack.ts` - Single CDK stack (`VettIdStack`) that provisions all resources:

1. **DynamoDB Tables** (PAY_PER_REQUEST, PITR enabled):
   - `Invites` - PK: `code` (STRING)
   - `Registrations` - PK: `registration_id` (STRING), GSI: `status-index` (PK: `status`, SK: `created_at`)
   - `Audit` - PK: `id` (STRING)

2. **Cognito:**
   - User Pool with email sign-in, strict password policy
   - Two separate app clients for RBAC:
     - Admin app client: `admin.vettid.dev/admin.html` (for admin group)
     - Member app client: `account.vettid.dev/index.html` (for member group)
   - Both use Authorization Code + PKCE (no client secret)
   - Groups: `admin`, `member`
   - Hosted UI domain (auto-generated prefix)

3. **API Gateway (HTTP API):**
   - `/register` (POST) - Public endpoint for registration submission
   - `/admin/registrations` (GET) - List registrations (authorized)
   - `/admin/registrations/{id}/approve` (POST) - Approve registration (authorized)
   - `/admin/registrations/{id}/reject` (POST) - Reject registration (authorized)
   - `/admin/invites` (POST) - Create invite code (authorized)
   - CORS enabled for `*` (should be pinned to specific domains in production)
   - JWT authorizer validates Cognito tokens for `/admin/*` routes

4. **Lambda Functions:**
   - Built with `NodejsFunction` (uses esbuild for bundling)
   - Runtime: Node.js 20
   - All handlers are in `lambda/handlers/{public|admin|streams}/`

5. **CloudFront + S3:**
   - Five distributions with custom domains:
     - `register.vettid.dev` - Public registration form
     - `account.vettid.dev` - Member portal (member group access)
     - `admin.vettid.dev` - Admin portal (admin group access)
     - `vettid.dev` - Apex/root site
     - `www.vettid.dev` - Redirects to apex via CloudFront Function
   - OAC (Origin Access Control) for secure S3 access
   - Custom certificate from ACM (us-east-1) with DNS validation
   - Route 53 A and AAAA records for all subdomains

### Lambda Handlers

**Directory structure:**
```
lambda/
├── common/
│   └── util.ts          # Shared utilities (DDB/SES clients, CORS, audit)
└── handlers/
    ├── public/
    │   └── submitRegistration.ts
    ├── admin/
    │   ├── listRegistrations.ts
    │   ├── approveRegistration.ts
    │   ├── rejectRegistration.ts
    │   └── createInvite.ts
    └── streams/
        └── registrationStream.ts
```

**Common utilities** (`lambda/common/util.ts`):
- `ddb` - DynamoDB client
- `ses` - SES client
- `TABLES` - Object with table name constants from env vars
- `putAudit(entry)` - Writes audit log to DynamoDB
- `sendTemplateEmail(to, template, data)` - Sends SES templated email
- `ok(body)`, `badRequest(msg)`, `forbidden(msg)` - Response helpers with CORS

**Registration Flow:**
1. User submits registration with invite code → `submitRegistration.ts`
   - Validates invite (not expired, not exhausted, status is active/new)
   - Creates `Registrations` record with `status=pending`
   - Increments invite usage counter, marks as `exhausted` if max uses reached
   - Writes audit log
2. Stream fires on INSERT → `registrationStream.ts` sends `RegistrationPending` email
3. Admin approves via UI → `approveRegistration.ts`
   - Updates `status=approved` in DynamoDB
   - Creates Cognito user (or gets existing)
   - Adds user to `member` group
   - Writes audit log
4. Stream fires on MODIFY → `registrationStream.ts` sends `RegistrationApproved` email

**Rejection Flow:**
- Admin rejects via UI → `rejectRegistration.ts`
- Sets `status=rejected`, stores `rejection_reason`, `rejected_at`, `rejected_by`
- Stream processor sends `RegistrationRejected` email with reason

**Performance Note:**
- `listRegistrations` uses GSI (`status-index`) to query by status instead of table scan
- Index has ALL projection type for full item retrieval

### Frontend

Static HTML/JS files in `cdk/frontend/`:
- `register/` - Public registration form (no authentication)
- `account/` - Member portal (PKCE authentication, member group only)
- `admin/` - Admin portal (PKCE authentication, admin group only)
- `shared/config.js` - Shared configuration with build-time placeholder injection

**Automated Deployment (Recommended):**

Use the deployment script for automatic configuration injection:

```bash
cd cdk
./scripts/deploy-frontend.sh
```

This script:
1. Fetches CDK stack outputs (API URL, Cognito domains, client IDs, etc.)
2. Replaces placeholders in `shared/config.js` with actual values
3. Uploads to S3 with proper content types and cache headers
4. Invalidates CloudFront caches

**Build-time Configuration:**

The `frontend/shared/config.js` uses placeholders that are replaced during deployment:
- `__API_URL__` → API Gateway URL
- `__REGION__` → AWS Region
- `__ADMIN_USER_POOL_ID__` → Admin Cognito User Pool ID
- `__MEMBER_USER_POOL_ID__` → Member Cognito User Pool ID
- `__ADMIN_COGNITO_DOMAIN__` → Admin Cognito Domain
- `__ADMIN_CLIENT_ID__` → Admin App Client ID
- `__MEMBER_COGNITO_DOMAIN__` → Member Cognito Domain
- `__MEMBER_CLIENT_ID__` → Member App Client ID

The config is frozen with `Object.freeze()` to prevent XSS modification at runtime.

**Manual Deployment (Alternative):**

1. **Register site** (`register.vettid.dev`):
   - Edit `frontend/register/index.html`
   - Replace `REPLACE_WITH_API_URL` → `ApiUrl` output
   - Upload all files from `frontend/register/` to **RegisterSiteBucket**

2. **Member portal** (`account.vettid.dev`):
   - Edit `frontend/account/index.html`
   - Replace placeholders:
     - `REPLACE_COGNITO_DOMAIN` → `CognitoDomain` output
     - `REPLACE_CLIENT_ID` → `MemberClientId` output
     - `REPLACE_REDIRECT_URI` → `https://account.vettid.dev/index.html`
   - Upload all files from `frontend/account/` to **AccountSiteBucket**
   - Note: DO NOT upload admin.html to account site

3. **Admin portal** (`admin.vettid.dev`):
   - Edit `frontend/admin/admin.html`
   - Replace placeholders:
     - `REPLACE_COGNITO_DOMAIN` → `CognitoDomain` output
     - `REPLACE_CLIENT_ID` → `AdminClientId` output
     - `REPLACE_REDIRECT_URI` → `https://admin.vettid.dev/admin.html`
     - `REPLACE_API_URL` → `ApiUrl` output
   - Upload all files from `frontend/admin/` to **AdminSiteBucket**

4. Invalidate CloudFront distributions if needed:
   ```bash
   aws cloudfront create-invalidation --distribution-id <ID> --paths "/*"
   ```

**RBAC via separate app clients:**
- Admin users must use `admin.vettid.dev` with the admin app client
- Member users must use `account.vettid.dev` with the member app client
- Both sites use the same User Pool but different callback URLs and client IDs
- API Gateway accepts tokens from both app clients for `/admin/*` routes (but should validate group membership in production)

### Security Considerations

**Implemented Security Features:**
- ✅ CORS pinned to explicit domains (vettid.dev, admin.vettid.dev, account.vettid.dev, register.vettid.dev, www.vettid.dev)
- ✅ Security headers on all API responses:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `X-Permitted-Cross-Domain-Policies: none`
  - `Referrer-Policy: strict-origin-when-cross-origin`
  - `Content-Language: en`
- ✅ Rate limiting with atomic DynamoDB counters (prevents TOCTOU attacks)
- ✅ Full SHA-256 hash for rate limit identifiers (collision resistant)
- ✅ Timing-safe email enumeration protection (consistent response times)
- ✅ Input validation functions for strings, UUIDs, and path parameters
- ✅ Error sanitization to prevent stack trace leakage
- ✅ CSRF protection via origin validation
- ✅ Admin group membership validation on all admin endpoints
- ✅ Audit logging for security-sensitive operations (PIN failures, auth failures)
- ✅ Build-time config injection for frontend (no hardcoded secrets)
- ✅ Object.freeze() on frontend config to prevent XSS modification
- ✅ Magic link tokens with reduced reuse window (30s)
- ✅ SES verification status checking with retry for sandbox mode
- ✅ OAC for S3 origins
- ✅ GSI queries instead of table scans
- ✅ Route 53 + ACM for custom domains

**Remaining hardening (optional):**
- Add WAF to CloudFront distributions
- Reduce IAM permissions to least privilege
- Pin SES to template ARNs instead of `*`

### DynamoDB Stream Processing

**Pattern:** `registrations` table has stream enabled (`NEW_AND_OLD_IMAGES`)
- Lambda (`registrationStream.ts`) triggers on batch of up to 10 records
- Bisect batch on error enabled for fault isolation
- Max 3 retry attempts

**Email triggers:**
- INSERT with `status=pending` → `RegistrationPending`
- MODIFY with status change to `approved` → `RegistrationApproved`
- MODIFY with status change to `rejected` → `RegistrationRejected`

**SES Templates required:**
- `RegistrationPending` - Variables: `first_name`, `last_name`, `email`, `invite_code`
- `RegistrationApproved` - Variables: `first_name`, `last_name`, `email`
- `RegistrationRejected` - Variables: `first_name`, `last_name`, `email`, `reason`

Templates must be created manually via AWS CLI or console.

## Development Notes

- Lambda handlers use `NodejsFunction` construct which bundles with esbuild automatically
- All TypeScript must be compiled before CDK commands (`npm run build` or watch mode)
- TypeScript config (`tsconfig.json`) targets ES2020, CommonJS modules, outputs to `dist/`
- CDK context is stored in `cdk.context.json` (gitignored in most setups)
- Stack defaults to `us-east-1` if `CDK_DEFAULT_REGION` not set (see `bin/app.ts:8`)

### Invite Code System

**Invite properties:**
- `code` (PK) - Case-sensitive invite code
- `status` - "active", "new", or "exhausted"
- `expires_at` - Unix timestamp (seconds or milliseconds)
- `max_uses` - Maximum number of registrations allowed
- `used` - Current usage count

**Validation logic** (in `submitRegistration.ts`):
- Handles both seconds and milliseconds timestamps (auto-detects by magnitude)
- Normalizes field name variations (`max_uses`/`maxUses`/`limit`, `used`/`uses`/`used_count`)
- Atomically increments usage and updates status to "exhausted" when limit reached

### Cognito PKCE Flow

**Authentication flow (same for both admin and member portals):**
1. User clicks login → redirected to Cognito Hosted UI
2. User authenticates → redirected to `callbackUrls` with authorization code
3. Frontend exchanges code for tokens (PKCE code verifier/challenge)
4. ID token contains JWT with user claims (email, groups)
5. Access token sent in `Authorization: Bearer <token>` header to `/admin/*` endpoints
6. API Gateway validates JWT against Cognito User Pool

**Separate app clients for RBAC:**
- Admin portal (`admin.vettid.dev`) uses `AdminWebClient`
  - Callback URL: `https://admin.vettid.dev/admin.html`
  - Intended for users in `admin` group
- Member portal (`account.vettid.dev`) uses `MemberWebClient`
  - Callback URL: `https://account.vettid.dev/index.html`
  - Intended for users in `member` group

**No client secret** - Both app clients are public (SPA), rely on PKCE for security.

### Stack Outputs

After deployment, CDK outputs provide:
- `ApiUrl` - HTTP API endpoint
- `CognitoDomain` - Hosted UI base URL
- `CognitoUserPoolId` - For AWS CLI operations
- `AdminClientId` - Admin app client ID (for admin.vettid.dev)
- `MemberClientId` - Member app client ID (for account.vettid.dev)
- `RegisterSiteBucket` - S3 bucket for registration site
- `AccountSiteBucket` - S3 bucket for member portal
- `AdminSiteBucket` - S3 bucket for admin portal
- `RegisterDistributionId` - CloudFront distribution ID for register site
- `AccountDistributionId` - CloudFront distribution ID for account site
- `AdminDistributionId` - CloudFront distribution ID for admin site
- `RegisterUrl` - `https://register.vettid.dev`
- `AccountUrl` - `https://account.vettid.dev`
- `AdminUrl` - `https://admin.vettid.dev`
- `RootUrl` - `https://vettid.dev`
- `WwwUrl` - `https://www.vettid.dev`
- `CertValidationStatus` - ACM certificate status

Use these values to configure frontends. Cognito callback URLs are pre-configured in the stack.
