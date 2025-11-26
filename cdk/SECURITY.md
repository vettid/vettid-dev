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
