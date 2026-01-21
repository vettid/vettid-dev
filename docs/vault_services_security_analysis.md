# Vault Services Security Analysis

**Document Version:** 1.1
**Analysis Date:** December 6, 2024 (Updated: January 21, 2026)
**Analyzed Document:** Vault Services Architecture v3.3

> **Implementation Note (2026-01-21):** The production implementation uses **native Go handlers** rather than WASM sandboxing. Handler isolation is achieved through the Nitro Enclave's hardware isolation and per-user vault-manager processes with separate SQLite databases.

---

## Executive Summary

The Vault Services architecture demonstrates strong security fundamentals with defense-in-depth layering, proper credential separation, and a well-thought-out trust boundary model. The "no direct access" model for vault instances significantly reduces attack surface. However, several areas warrant additional consideration before implementation.

**Overall Assessment:** The architecture is sound for the stated security goals. The identified issues are primarily edge cases, implementation considerations, and areas where additional specification would strengthen the design.

---

## 1. Critical Considerations

### 1.1 Mobile Device as Single Point of Trust

**Observation:** The mobile device holds both credentials (Vault Services and Vault Credential) and is the sole interface for vault operations. Loss or compromise of the device is the primary threat vector.

**Current Mitigations:**
- Single device policy limits exposure
- Credential Backup Service (optional) with recovery phrase
- Native device backup support

**Potential Vulnerabilities:**
| Risk | Severity | Notes |
|------|----------|-------|
| Device theft with unlocked phone | High | Attacker has full vault access until device is remotely wiped |
| Malware on mobile device | High | Could intercept credentials, exfiltrate secrets during authentication |
| Shoulder surfing of password/recovery phrase | Medium | Recovery phrase grants full credential recovery |
| SIM swapping (if SMS used anywhere) | Medium | Document doesn't mention SMS but should explicitly exclude it |

**Recommendations:**
1. **Add device-level session controls** - Require re-authentication for sensitive operations (e.g., backup passphrase viewing, termination, large transactions)
2. **Implement remote credential revocation** - Allow members to invalidate all credentials from web portal (separate from device)
3. **Add biometric binding** - Tie credential decryption to device biometrics where available
4. **Document session timeout policy** - How long can the app remain authenticated before re-prompting?

### 1.2 Credential Backup Service Security

**Observation:** The Credential Backup Service stores encrypted credentials in Vault Services, decryptable only with the recovery phrase.

**Current Mitigations:**
- Client-side encryption before upload
- Recovery phrase never transmitted
- Time-limited, single-use download token

**Potential Vulnerabilities:**
| Risk | Severity | Notes |
|------|----------|-------|
| Weak recovery phrase selection | High | Users may choose weak phrases; no enforcement mentioned |
| Brute-force attack on stored credentials | Medium | If attacker obtains encrypted blob, offline attack possible |
| Recovery phrase phishing | Medium | Attacker creates fake VettID recovery page |
| No rate limiting on recovery attempts | Medium | Could allow credential enumeration |

**Recommendations:**
1. **Enforce recovery phrase strength** - Minimum entropy requirements, possibly BIP-39 mnemonic
2. **Use memory-hard KDF** - Argon2id with aggressive parameters for phrase→key derivation
3. **Add recovery attempt rate limiting** - Lock account after N failed attempts
4. **Implement recovery notifications** - Alert member (via email/existing device) when recovery is attempted
5. **Consider requiring web authentication** - Login to vettid.dev before recovery should use 2FA

### 1.3 Vault Services API as Trusted Intermediary

**Observation:** The Vault Services API can "read secrets after user authenticates (for use in vault actions)" per the Trust Boundaries section.

**Potential Vulnerabilities:**
| Risk | Severity | Notes |
|------|----------|-------|
| Insider threat at VettID | High | Staff with API access could potentially access member secrets |
| API compromise | Critical | Full access to all secrets of authenticated users |
| Insufficient audit logging | Medium | Document mentions logging but no details on secret access logging |

**Recommendations:**
1. **Clarify secret access scope** - Document exactly which operations require secret access and for how long
2. **Implement secret access logging** - Log every secret access with user, timestamp, purpose, accessor identity
3. **Consider hardware security modules** - Use HSMs for any server-side secret operations
4. **Minimize secret exposure window** - Secrets should be in memory only for the minimum required time
5. **Add anomaly detection** - Alert on unusual patterns of secret access

---

## 2. Handler/Supply Chain Security

### 2.1 Handler Package Verification

**Observation:** Handlers are WASM packages signed by the registry or third-party publishers.

**Current Mitigations:**
- Ed25519 signatures on all packages
- Registry private key in KMS
- Hash verification (manifest.wasm_hash)
- WASM sandboxing

**Potential Vulnerabilities:**
| Risk | Severity | Notes |
|------|----------|-------|
| Compromised registry signing key | Critical | All handlers could be replaced with malicious versions |
| Malicious third-party handler | High | Publisher could create handler that exfiltrates data via allowed egress |
| Handler update TOCTOU | Medium | Race between verification and installation |
| Overly broad egress permissions | Medium | Handler could send data to subdomains or path-differentiated endpoints |

**Recommendations:**
1. **Implement handler code review for third-parties** - Require review before registry listing
2. **Add egress domain restrictions** - Consider exact domain matching, not just domain allowlisting
3. **Implement handler behavior monitoring** - Track data volume sent to egress destinations
4. **Add handler rollback capability** - Quick revert if malicious behavior detected
5. **Consider reproducible builds** - Allow verification that source matches compiled WASM
6. **Implement key rotation plan for registry** - Document process if signing key is compromised

### 2.2 Third-Party Authorization Tokens

**Observation:** Publishers issue authorization tokens signed with their private key, stored in member's vault.

**Potential Vulnerabilities:**
| Risk | Severity | Notes |
|------|----------|-------|
| Publisher key compromise | High | Attacker could forge tokens for any user |
| Token theft from vault | Medium | Tokens stored in handler_data, not in encrypted secrets |
| No token scope limitations | Medium | Token grants full handler access, no per-operation granularity |

**Recommendations:**
1. **Document publisher key rotation** - How do publishers rotate keys? What happens to existing tokens?
2. **Consider storing tokens as secrets** - Higher protection than handler_data
3. **Add token binding** - Bind token to specific vault/member ID to prevent replay

---

## 3. Network & Communication Security

### 3.1 NATS Security

**Observation:** NATS provides the communication backbone with namespace isolation and JWT-based access control.

**Current Mitigations:**
- TLS for all NATS connections
- Namespace isolation per member
- Scoped JWT permissions
- Time-limited tokens

**Potential Vulnerabilities:**
| Risk | Severity | Notes |
|------|----------|-------|
| JWT token theft | High | If token exfiltrated, attacker has scoped access until expiry |
| Central NATS compromise | Critical | All member communications exposed |
| MessageSpace token sharing | Medium | Connections receive tokens valid for 168 hours (7 days) |

**Recommendations:**
1. **Implement token binding** - Tie tokens to client certificates or other identifiers
2. **Reduce token lifetimes** - 168 hours is long; consider shorter for high-security scenarios
3. **Add token revocation lists** - Currently revocation waits for token expiry or explicit invalidation
4. **Monitor for token reuse from multiple IPs** - Could indicate theft

### 3.2 Control Topic Security

**Observation:** Vault Services Lambda uses operator-signed JWT to write to control topic.

**Current Mitigations:**
- Operator-signed JWT required
- Write-only access (cannot read member data)
- All commands auditable

**Potential Vulnerabilities:**
| Risk | Severity | Notes |
|------|----------|-------|
| Control topic command injection | High | If attacker forges command, could trigger backup/shutdown |
| Command replay | Medium | No mention of nonces or sequence numbers |
| Lambda compromise | High | Access to operator signing capability |

**Recommendations:**
1. **Add command signatures** - Each command should include timestamp and nonce to prevent replay
2. **Implement command rate limiting** - Limit commands per vault per time period
3. **Add member notification for sensitive commands** - Notify on backup, shutdown, etc.
4. **Secure Lambda signing capability** - Document how operator key is protected in Lambda

---

## 4. Backup Security

### 4.1 Backup Encryption

**Observation:** Backups encrypted with member's backup public key (asymmetric) or custom password.

**Current Mitigations:**
- Asymmetric encryption (only member can decrypt)
- Two-key model (active + previous)
- 90-day key rotation

**Potential Vulnerabilities:**
| Risk | Severity | Notes |
|------|----------|-------|
| Weak custom password | High | Member-chosen passwords may be weak |
| Backup key in credential blob | Medium | If credential exfiltrated, backups can be decrypted |
| No backup integrity verification mentioned | Medium | Could restore corrupted backup |
| S3 access misconfiguration | Medium | Backup access controls must be precise |

**Recommendations:**
1. **Enforce custom password strength** - If members choose password, require minimum entropy
2. **Add backup integrity signatures** - Sign backup contents to detect tampering
3. **Implement backup encryption verification** - Test decryption before confirming backup success
4. **Document S3 bucket policies** - Ensure write-only for vault, managed access for restore

### 4.2 Local Backup (Appliance)

**Observation:** Local backups written to SD card/USB with confirmation code flow.

**Potential Vulnerabilities:**
| Risk | Severity | Notes |
|------|----------|-------|
| Unencrypted storage device reuse | Medium | Formatting may not securely erase |
| Backup code brute-force | Low | Codes are 6-8 digits typically; limited attempts? |
| Physical access to backup media | Medium | If attacker has device, offline attack on password |

**Recommendations:**
1. **Implement secure erase for storage devices** - Use secure wipe, not just format
2. **Rate limit backup code attempts** - Lock after N failures
3. **Consider backup expiration** - Local backups don't rotate; old backups may have old credentials

---

## 5. Home Appliance Security

### 5.1 Physical Security

**Observation:** Home appliances are physically in member's control but also physically accessible.

**Current Mitigations:**
- TPM for key storage
- Encrypted storage
- No direct access (same as cloud)

**Potential Vulnerabilities:**
| Risk | Severity | Notes |
|------|----------|-------|
| Physical device theft | High | Attacker has unlimited time for offline attacks |
| Evil maid attack | High | Physical access allows hardware tampering |
| Side-channel attacks | Medium | Physical access enables power analysis, etc. |
| Firmware tampering | High | Modified firmware could exfiltrate data |

**Recommendations:**
1. **Implement secure boot** - Verify firmware integrity on startup
2. **Add tamper detection** - Physical tamper-evident seals or electronic detection
3. **Consider remote attestation** - Prove device integrity to Vault Services
4. **Document data-at-rest encryption details** - What algorithm, key derivation, etc.?

### 5.2 Network Security (Appliance)

**Observation:** Appliances connect from home networks which may be less secure.

**Potential Vulnerabilities:**
| Risk | Severity | Notes |
|------|----------|-------|
| Compromised home router | High | MITM on appliance traffic |
| DNS hijacking | Medium | Could redirect appliance to fake NATS servers |
| Local network attacks | Medium | Other devices on network could attack appliance |

**Recommendations:**
1. **Implement certificate pinning** - Pin NATS server certificates
2. **Consider DNS-over-HTTPS** - Prevent DNS manipulation
3. **Add network isolation recommendations** - Document VLAN setup for security-conscious users
4. **Implement firewall on appliance** - Only allow necessary outbound connections

---

## 6. Operational Security

### 6.1 Credential Rotation

**Observation:** Document mentions 90-day backup key rotation but doesn't specify rotation for other credentials.

**Gaps:**
- No mention of NATS NKey rotation for vaults
- No mention of connection key rotation
- No mention of Vault Credential rotation

**Recommendations:**
1. **Document rotation policy for all credential types**
2. **Implement automated rotation with notification**
3. **Add rotation audit logging**

### 6.2 Audit Logging

**Observation:** Audit logging is mentioned but not detailed.

**Gaps:**
- What events are logged?
- How long are logs retained?
- Who has access to logs?
- How are logs protected from tampering?

**Recommendations:**
1. **Define comprehensive audit event list**
2. **Implement log integrity protection** (hash chains, etc.)
3. **Document log retention policy**
4. **Restrict log access with its own authorization**

### 6.3 Incident Response

**Observation:** No incident response procedures documented.

**Gaps:**
- How does VettID respond to a breach?
- How are members notified?
- What is the compromise recovery procedure?

**Recommendations:**
1. **Document incident response plan**
2. **Define member notification procedures**
3. **Create runbooks for common scenarios** (key compromise, member report of unauthorized access, etc.)

---

## 7. Data Protection

### 7.1 Secret Classification

**Observation:** Secrets in credential blob vs. private data in NATS datastore.

**Potential Issues:**
| Item | Concern |
|------|---------|
| Classification criteria | Who decides what's a "secret" vs. "private data"? |
| Data leakage between categories | Could private data be promoted to secret? |
| Handler access to secrets | Handlers receive secrets via stdin—secure disposal? |

**Recommendations:**
1. **Define clear classification criteria** - Document what qualifies as secret vs. private
2. **Implement secret access audit** - Log every secret access with justification
3. **Ensure secure memory handling** - Document how handlers and Vault Manager handle secrets in memory

### 7.2 Data Retention

**Observation:** Revoked connections retain identifier data; 30-day backup retention after expiry.

**Potential Issues:**
- No mention of data purge procedures
- Connection history may accumulate indefinitely
- handler_data retention not specified

**Recommendations:**
1. **Define data retention limits** - Maximum age for connection history, feed events, etc.
2. **Implement member data purge** - Allow members to request history deletion
3. **Document handler_data lifecycle** - When is old handler data cleaned up?

---

## 8. Specific Technical Concerns

### 8.1 QR Code Security

**Observation:** QR codes used for enrollment and credential recovery.

**Potential Vulnerabilities:**
- QR code photographed by attacker
- Screen recording during QR display
- QR code remaining on screen after use

**Recommendations:**
1. **Implement QR code timeout** - Short expiration (30-60 seconds)
2. **Add QR code single-use enforcement** - Invalidate after first scan
3. **Clear QR from screen after scan** - Immediate removal
4. **Consider QR code confirmation** - Both sides confirm match

### 8.2 Recovery Phrase UX

**Observation:** Recovery phrase provided by member during Credential Backup Service setup.

**Potential Vulnerabilities:**
- Users may store phrase insecurely (screenshot, notes app)
- Phrase entry may be logged/cached by keyboard
- Phishing for recovery phrase

**Recommendations:**
1. **Provide secure storage guidance** - Recommend password manager or physical storage
2. **Use secure text input** - Disable keyboard caching for phrase entry
3. **Add recovery phrase verification** - Require re-entry to confirm understanding

### 8.3 Subscription Expiry Race Condition

**Observation:** 2-day grace period before backup and termination.

**Potential Vulnerability:**
- If member renews at Day 1.9, is the backup process already initiated?
- Could lead to race conditions in state

**Recommendations:**
1. **Document exact state transitions** - What happens if renewal during grace period?
2. **Implement idempotent renewal** - Safe to renew at any point in lifecycle

---

## 9. Missing Security Specifications

The following areas would benefit from additional documentation:

| Area | Current Gap |
|------|-------------|
| **Password Policy** | No specifications for user passwords, recovery phrases |
| **Session Management** | No details on session timeout, concurrent sessions |
| **Rate Limiting** | Mentioned in passing but no specifications |
| **Cryptographic Specifications** | Algorithms mentioned but not detailed (key sizes, modes, etc.) |
| **TLS Configuration** | No mention of minimum version, cipher suites |
| **API Input Validation** | No specification of validation/sanitization |
| **Error Handling** | No specification of error messages (information leakage) |
| **Logging Standards** | No specification of what's logged, format, retention |

---

## 10. Summary of Recommendations by Priority

### Critical (Address Before Production)
1. Document and implement remote credential revocation
2. Define comprehensive audit logging with integrity protection
3. Specify cryptographic parameters (algorithms, key sizes, modes)
4. Implement handler code review process for third-party handlers
5. Add rate limiting specifications for authentication endpoints

### High Priority
1. Enforce recovery phrase strength requirements
2. Add device session controls for sensitive operations
3. Implement backup integrity verification
4. Document incident response procedures
5. Add certificate pinning for appliances

### Medium Priority
1. Define all credential rotation policies
2. Implement handler behavior monitoring
3. Add data retention limits and purge procedures
4. Document secure memory handling for secrets
5. Add QR code security measures

### Low Priority (Enhancements)
1. Consider reproducible builds for handlers
2. Add network isolation recommendations for appliances
3. Implement anomaly detection for secret access
4. Add recovery attempt notifications

---

## Conclusion

The Vault Services architecture provides a strong security foundation with appropriate defense-in-depth. The "no direct access" model, proper credential separation, and WASM sandboxing are particularly well-designed. The primary areas for improvement are:

1. **Specification completeness** - Adding detailed cryptographic and operational security specifications
2. **Mobile device security** - Additional controls for the single point of trust
3. **Supply chain security** - Stronger controls for third-party handlers
4. **Operational security** - Incident response, audit logging, and rotation policies

None of the identified issues are architectural flaws requiring redesign. They are primarily areas where additional specification and controls would strengthen the implementation.
