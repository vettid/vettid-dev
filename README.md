# VettID Scaffold (Serverless, AWS CDK) — PKCE + Admin + Streams

This scaffold stands up:
- API Gateway (HTTP API) + Lambda handlers
- DynamoDB tables: **Invites**, **Registrations** (with stream), **Audit**
- CloudFront + S3 for `register` and `account` sites
- Cognito User Pool + Hosted UI + SPA app client (Authorization Code + PKCE) + `admin` group
- Admin UI (`frontend/account/admin.html`) that signs in via PKCE and manages invites/approvals
- **Approval Lambda** that creates/updates the user in Cognito and adds them to `member`
- **Stream processor** that emails users on registration lifecycle changes via SES templates

## Quick start
```bash
cd cdk
npm i
npm run bootstrap
npm run deploy
```
Outputs: `ApiUrl`, `CognitoDomain`, `CognitoClientId`, CloudFront Distribution IDs, bucket names.

### Frontends
- Edit `frontend/register/index.html` → replace `REPLACE_WITH_API_URL` with `ApiUrl` and upload to **RegisterSite** bucket.
- Edit `frontend/account/admin.html` constants:
  - `REPLACE_COGNITO_DOMAIN` → output `CognitoDomain`
  - `REPLACE_CLIENT_ID` → `CognitoClientId`
  - `REPLACE_REDIRECT_URI` → your Account CF URL ending with `/admin.html`
  - `REPLACE_API_URL` → `ApiUrl`
- Upload `admin.html` and `index.html` in `frontend/account/` to **AccountSite** bucket.

Update Cognito Hosted UI: add your final `/admin.html` URL to Callback and Sign-out URLs.

### SES Templates
Create templates (names must match):
- `RegistrationPending`
- `RegistrationApproved`
- `RegistrationRejected`

Variables available: `first_name`, `last_name`, `email`, `invite_code`, `reason`.

### Admin user
```bash
aws cognito-idp admin-create-user --user-pool-id <POOL_ID> --username admin@vettid.dev --user-attributes Name=email,Value=admin@vettid.dev
aws cognito-idp admin-add-user-to-group --user-pool-id <POOL_ID> --username admin@vettid.dev --group-name admin
```

### Security hardening (next)
- Pin CORS to exact domains, add **WAF** to CloudFront, use **OAC** for S3 origins.
- Replace Scan with GSI for `status` in Registrations for efficiency.
- Reduce IAM permissions to least privilege; pin SES to template ARNs.
- Add Route 53 + ACM for `register.vettid.dev` / `account.vettid.dev`.


## Rejection workflow
- New API: `POST /admin/registrations/{id}/reject` with JSON body `{ "reason": "optional string" }`.
- Admin UI now has a **Reject** button that prompts for a reason.
- The Lambda sets `status=rejected`, stores `rejection_reason`, `rejected_at`, `rejected_by`, and writes an audit entry.
- The existing stream processor will send the `RegistrationRejected` SES template automatically when the status flips to `rejected`.


## Performance: status index
Added a GSI on `Registrations`:
- **Index name:** `status-index`
- **PK:** `status` (STRING)
- **SK:** `created_at` (STRING)
- **Projection:** ALL

The admin `listRegistrations` endpoint now performs a **Query** against this index (newest first) instead of a table scan.
