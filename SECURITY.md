# Security Policy

## Reporting Security Vulnerabilities

VettID takes security seriously. If you discover a security vulnerability, please report it responsibly.

### Contact

**Email:** security@vettid.dev

**Response Times:**
- Initial acknowledgment: Within 24 hours
- Severity assessment: Within 72 hours
- Resolution timeline: Provided within 7 days

### Responsible Disclosure Process

1. **Report**: Send details to security@vettid.dev
2. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Your contact information (optional, for updates)
3. **Wait**: Allow us reasonable time to investigate and patch
4. **Coordinate**: Work with us on public disclosure timing

### What to Report

- Authentication or authorization bypasses
- Data exposure vulnerabilities
- Injection attacks (SQL, XSS, command injection)
- Cryptographic weaknesses
- Access control issues
- Sensitive data leakage

### What NOT to Report

- Denial of service attacks
- Social engineering attempts
- Physical security issues
- Issues in third-party dependencies (report to upstream)

### Safe Harbor

We will not pursue legal action against researchers who:
- Act in good faith
- Avoid privacy violations and data destruction
- Do not exploit vulnerabilities beyond proof of concept
- Report findings privately before disclosure

## Security Architecture

### Infrastructure Security

- **AWS Nitro Enclave**: Cryptographic operations run in isolated enclaves with PCR-based attestation
- **KMS Encryption**: All sensitive data encrypted at rest using AWS KMS with strict key policies
- **VPC Isolation**: Backend services run in private subnets with no direct internet access
- **WAF Protection**: CloudFront distributions protected by AWS WAF with managed rule sets

### Authentication

- **Cognito PKCE**: OAuth 2.0 Authorization Code flow with PKCE (no client secrets)
- **JWT Validation**: API Gateway validates JWTs against Cognito User Pools
- **NATS JWT Auth**: Ed25519 nkey-based authentication with short-lived tokens

### Data Protection

- **Envelope Encryption**: Credentials sealed with KMS-encrypted data keys
- **Context Binding**: Encryption contexts prevent cross-user key misuse
- **Audit Logging**: All security events logged to DynamoDB with retention policies

## Security Headers

All HTTP responses include:
- `Content-Security-Policy`: Restricts resource loading
- `Strict-Transport-Security`: Enforces HTTPS
- `X-Frame-Options: DENY`: Prevents clickjacking
- `X-Content-Type-Options: nosniff`: Prevents MIME sniffing
- `Referrer-Policy: strict-origin-when-cross-origin`

## Incident Response

### Classification

| Severity | Description | Response Time |
|----------|-------------|---------------|
| Critical | Active exploitation, data breach | Immediate |
| High | Exploitable vulnerability, no active exploit | 24 hours |
| Medium | Requires specific conditions to exploit | 7 days |
| Low | Minimal impact, defense in depth | 30 days |

### Contacts

- **Security Lead**: security@vettid.dev
- **On-Call Escalation**: Available 24/7 for critical issues

## Key Rotation Procedures

### NATS Operator Keys
1. Generate new operator keypair in Secrets Manager
2. Update system account JWT
3. Re-sign all account JWTs with new operator
4. Deploy to NATS cluster
5. Verify connectivity

### KMS Keys
- Automatic rotation enabled (365 days)
- Manual rotation available via AWS Console
- Re-encrypt existing data after rotation

### Cognito Keys
- Managed automatically by AWS Cognito
- Token signing keys rotate periodically

## Configuration After Clone

See [cdk/SECURITY.md](cdk/SECURITY.md) for deployment-specific configuration requirements.
