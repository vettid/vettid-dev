# Security Notice

## Configuration Required After Clone

This repository contains hardcoded values specific to the original deployment. Before deploying your own instance, you **MUST** update the following:

### Frontend Files

**1. Account Page** (`frontend/account/index.html` line 53-56)
```javascript
const COGNITO_DOMAIN = "YOUR_COGNITO_DOMAIN_HERE";
const CLIENT_ID = "YOUR_MEMBER_CLIENT_ID_HERE";
const REDIRECT_URI = "https://vettid.dev/account/index.html";  // Update with your domain
const API_URL = "YOUR_API_GATEWAY_URL_HERE";
```

**2. Admin Page** (`frontend/admin/admin.html` line 175-178)
```javascript
const COGNITO_DOMAIN = "YOUR_COGNITO_DOMAIN_HERE";
const CLIENT_ID = "YOUR_ADMIN_CLIENT_ID_HERE";
const REDIRECT_URI = "https://vettid.dev/admin/admin.html";  // Update with your domain
const API_URL = "YOUR_API_GATEWAY_URL_HERE";
```

**3. Register Page** (`frontend/register/index.html` line 43)
```javascript
const API = "YOUR_API_GATEWAY_URL_HERE";
```

### Getting Your Values

After deploying with `cdk deploy`, you'll receive outputs containing:
- `ApiUrl` - Your API Gateway endpoint
- `CognitoDomain` - Your Cognito domain
- `AdminClientId` - Admin app client ID
- `MemberClientId` - Member app client ID

Update the frontend files with these values and re-upload them to S3.

## AWS Account IDs

The `cdk.context.json` file will contain your AWS account ID after synthesis. This is normal for CDK projects and not a security risk, but be aware of it.

## What's Safe to Commit

✅ Lambda function code (no secrets)
✅ CDK infrastructure code
✅ Frontend HTML/CSS/JS (after removing deployment-specific values)
✅ TypeScript configuration files

## What Should NOT Be Committed

❌ AWS access keys or secret keys
❌ `.env` files with credentials
❌ `node_modules/`
❌ `cdk.out/` directory
❌ `cdk.context.json` (contains AWS account IDs)

## Recommended: Use Environment Variables

For production deployments, consider using AWS Systems Manager Parameter Store or AWS Secrets Manager to manage configuration values instead of hardcoding them in frontend files.

---

## Security Audit Recommendations (January 2026)

The following recommendations were identified during a comprehensive security audit and should be addressed before production deployment.

### Required: Environment Variables for Deployment

The following secrets **must** be set before deploying. The system will fail to start without them:

```bash
# Attestation secrets (generate unique values for each environment)
export DEVICE_ATTESTATION_SECRET=$(openssl rand -hex 32)
export ATTESTATION_BINDING_SECRET=$(openssl rand -hex 32)
```

### Required: Vsock Secret File for Enclave Communication

The enclave parent process and supervisor require a shared secret file for mutual authentication. Create this file before starting the enclave:

**Production** (`/etc/vettid/vsock-secret`):
```bash
# Create directory with restricted permissions
sudo mkdir -p /etc/vettid
sudo chmod 700 /etc/vettid

# Generate and store secret (64 hex characters = 32 bytes)
openssl rand -hex 32 | sudo tee /etc/vettid/vsock-secret > /dev/null
sudo chmod 400 /etc/vettid/vsock-secret
```

**Development** (`/tmp/vettid-vsock-secret`):
```bash
openssl rand -hex 32 > /tmp/vettid-vsock-secret
chmod 400 /tmp/vettid-vsock-secret
```

### Recommended: Upgrade Go Runtime

The enclave currently uses Go 1.24.0. Several standard library vulnerabilities have been fixed in recent Go releases:

| Vulnerability | Description | Status |
|--------------|-------------|--------|
| GO-2025-4175 | crypto/x509 wildcard DNS handling | Fixed in Go 1.24.2+ |
| GO-2025-4155 | crypto/x509 excessive resource consumption | Fixed in Go 1.24.2+ |
| GO-2025-3563 | net/http request smuggling | Fixed in Go 1.24.1+ |

**Action:** Update Go toolchain to latest 1.24.x:
```bash
go install golang.org/dl/go1.24.12@latest
go1.24.12 download
```

### Recommended: Dependency Update Schedule

Maintain a regular dependency update schedule:

| Frequency | Components |
|-----------|------------|
| Weekly | `npm audit` check |
| Monthly | Go modules (`go get -u ./...`) |
| Quarterly | Major version updates (after testing) |

**Automated checks:**
```bash
# NPM vulnerabilities
cd cdk && npm audit

# Go vulnerabilities (if govulncheck installed)
cd enclave && govulncheck ./...
```

### Email Configuration

Email addresses are now managed via CDK context in `cdk/cdk.json`. Override for different environments:

```bash
# Override at deploy time
cdk deploy -c vettid:sesFromEmail=no-reply@yourdomain.com \
           -c vettid:adminNotificationEmail=admin@yourdomain.com
```

Available context keys:
- `vettid:emailDomain` - Base domain for emails
- `vettid:sesFromEmail` - Default sender address
- `vettid:sesFromAuthEmail` - Auth-related sender address
- `vettid:adminNotificationEmail` - Admin notification recipient
- `vettid:securityContactEmail` - Security contact
- `vettid:supportEmail` - Support contact

### Security Audit Checklist

Before production deployment, verify:

- [ ] `DEVICE_ATTESTATION_SECRET` environment variable is set (not default)
- [ ] `ATTESTATION_BINDING_SECRET` environment variable is set (not default)
- [ ] Vsock secret file exists at `/etc/vettid/vsock-secret` with 0400 permissions
- [ ] Go runtime is updated to latest patch version
- [ ] `npm audit` shows no high/critical vulnerabilities
- [ ] `govulncheck` shows no exploitable vulnerabilities
- [ ] Email configuration is updated for your domain
- [ ] API Gateway URLs in documentation are updated
- [ ] Frontend configuration points to correct API endpoints
