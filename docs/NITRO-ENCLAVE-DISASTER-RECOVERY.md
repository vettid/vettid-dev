# VettID Nitro Enclave Disaster Recovery Procedures

## Document Information

| Field | Value |
|-------|-------|
| Version | 1.0 |
| Date | 2026-01-06 |
| Author | Operations Team |
| Companion Doc | [Operations Runbook](./NITRO-ENCLAVE-OPERATIONS-RUNBOOK.md) |

---

## Table of Contents

1. [Recovery Objectives](#1-recovery-objectives)
2. [Data Protection](#2-data-protection)
3. [Failure Scenarios](#3-failure-scenarios)
4. [Recovery Procedures](#4-recovery-procedures)
5. [Cross-Region DR](#5-cross-region-dr)
6. [PCR Rotation](#6-pcr-rotation)
7. [Testing DR Procedures](#7-testing-dr-procedures)

---

## 1. Recovery Objectives

### Service Level Objectives

| Metric | Target | Notes |
|--------|--------|-------|
| **RTO** (Recovery Time Objective) | 15 minutes | Time to restore service |
| **RPO** (Recovery Point Objective) | 0 (zero data loss) | All data encrypted and persisted |
| **MTTR** (Mean Time to Recovery) | < 30 minutes | Including diagnosis |

### Critical Components Priority

| Priority | Component | RTO | Impact if Down |
|----------|-----------|-----|----------------|
| P1 | Nitro Enclave ASG | 5 min | No vault operations |
| P1 | NATS Cluster | 5 min | No enclave communication |
| P2 | KMS Sealing Key | 15 min | Cannot unseal new data |
| P2 | S3 Vault Data | 15 min | Data unavailable |
| P3 | CloudWatch Monitoring | 30 min | No visibility |

---

## 2. Data Protection

### 2.1 Encrypted Vault Data (S3)

**Bucket:** `vettid-vault-data-*`

**Protection Mechanisms:**
- Server-side encryption with KMS (SSE-KMS)
- Versioning enabled (recover from accidental deletion)
- Cross-region replication to `us-west-2` (if configured)
- Point-in-time recovery via versioning

**Backup Verification:**
```bash
# List bucket versioning status
aws s3api get-bucket-versioning --bucket vettid-vault-data-<account-id>

# List object versions for a specific vault
aws s3api list-object-versions \
  --bucket vettid-vault-data-<account-id> \
  --prefix vaults/<vault-id>/

# Verify cross-region replication (if enabled)
aws s3api get-bucket-replication --bucket vettid-vault-data-<account-id>
```

### 2.2 DynamoDB Tables

**Tables with Vault Data:**
- `VettID-Vault-EnrollmentSessions` - Temporary enrollment state
- `VettID-Ledger-Credentials` - Credential metadata
- `VettID-Ledger-TransactionKeys` - Transaction key tracking

**Protection Mechanisms:**
- Point-in-Time Recovery (PITR) enabled
- On-demand backups before major changes
- Automatic backups retained for 35 days

**Backup Commands:**
```bash
# Create on-demand backup
aws dynamodb create-backup \
  --table-name VettID-Vault-EnrollmentSessions \
  --backup-name "pre-change-$(date +%Y%m%d-%H%M%S)"

# List available backups
aws dynamodb list-backups --table-name VettID-Vault-EnrollmentSessions

# Restore from PITR
aws dynamodb restore-table-to-point-in-time \
  --source-table-name VettID-Vault-EnrollmentSessions \
  --target-table-name VettID-Vault-EnrollmentSessions-restored \
  --use-latest-restorable-time
```

### 2.3 SSM Parameters (Secrets)

**Critical Parameters:**
```
/vettid/nitro/parent-nats-creds     # NATS authentication credentials
/vettid/nitro-enclave/current-ami   # Current enclave AMI ID
/vettid/nitro-enclave/latest-ami    # Latest available AMI ID
/vettid/nitro/sealing-key-arn       # KMS key ARN for envelope encryption
```

**Backup Commands:**
```bash
# Export all VettID parameters to JSON
aws ssm get-parameters-by-path \
  --path /vettid/ \
  --recursive \
  --with-decryption \
  --query "Parameters[].{Name:Name,Value:Value,Type:Type}" \
  > vettid-ssm-backup-$(date +%Y%m%d).json

# Store backup securely (encrypted)
aws s3 cp vettid-ssm-backup-*.json s3://vettid-dr-backups/ssm/ --sse aws:kms
rm vettid-ssm-backup-*.json  # Remove local copy
```

### 2.4 KMS Keys

**Sealing Key:** Used for envelope encryption of vault data

**Protection:**
- Key policy requires MFA for deletion
- Multi-region key enabled (if configured)
- Key material cannot be exported (AWS-managed)

**Recovery:**
```bash
# Check key status
aws kms describe-key --key-id $(aws ssm get-parameter \
  --name /vettid/nitro/sealing-key-arn --query Parameter.Value --output text)

# If key is scheduled for deletion, cancel it
aws kms cancel-key-deletion --key-id <key-id>

# Re-enable if disabled
aws kms enable-key --key-id <key-id>
```

---

## 3. Failure Scenarios

### 3.1 Single Instance Failure

**Symptoms:**
- One enclave instance unhealthy
- Some requests timing out

**Impact:** Minimal - other instances handle traffic

**Auto-Recovery:** ASG replaces unhealthy instance within 5 minutes

**Manual Intervention (if needed):**
```bash
# Force terminate unhealthy instance
aws autoscaling terminate-instance-in-auto-scaling-group \
  --instance-id <instance-id> \
  --should-decrement-desired-capacity false
```

### 3.2 All Enclave Instances Down

**Symptoms:**
- VettID-Enclave-NoInstances alarm
- All vault operations return 500
- NATS "No Responders" errors in Lambda logs

**Impact:** CRITICAL - No vault operations possible

**Recovery:** See [Section 4.1](#41-complete-enclave-failure)

### 3.3 NATS Cluster Failure

**Symptoms:**
- VettID-NATS-NoHealthyInstances alarm
- Connection timeouts in Lambda logs
- Enclaves cannot communicate

**Impact:** CRITICAL - Even healthy enclaves can't receive requests

**Recovery:** See [Section 4.2](#42-nats-cluster-failure)

### 3.4 KMS Key Unavailable

**Symptoms:**
- `KMSAccessDenied` or `KMSKeyDisabled` errors
- Cannot seal/unseal vault data
- New enrollments fail

**Impact:** CRITICAL - Cannot decrypt existing or encrypt new data

**Recovery:** See [Section 4.3](#43-kms-key-recovery)

### 3.5 S3 Data Corruption/Deletion

**Symptoms:**
- `NoSuchKey` errors for vault data
- Partial vault data available
- User reports missing credentials

**Impact:** HIGH - User data unavailable

**Recovery:** See [Section 4.4](#44-s3-data-recovery)

### 3.6 Region-Wide Outage

**Symptoms:**
- AWS status page shows us-east-1 issues
- Multiple services failing simultaneously
- Cannot access AWS console

**Impact:** CRITICAL - Complete service outage

**Recovery:** See [Section 5](#5-cross-region-dr)

---

## 4. Recovery Procedures

### 4.1 Complete Enclave Failure

**Diagnosis:**
```bash
# Check ASG state
aws autoscaling describe-auto-scaling-groups \
  --auto-scaling-group-names $(aws cloudformation describe-stacks \
    --stack-name VettID-Nitro \
    --query "Stacks[0].Outputs[?OutputKey=='EnclaveASGName'].OutputValue" \
    --output text) \
  --query "AutoScalingGroups[0].{Desired:DesiredCapacity,Running:Instances[?LifecycleState=='InService']|length(@)}"

# Check recent scaling activities
aws autoscaling describe-scaling-activities \
  --auto-scaling-group-name $ASG_NAME \
  --max-items 5 \
  --query "Activities[].{Time:StartTime,Status:StatusCode,Cause:Cause}"
```

**Recovery Steps:**

1. **If instances failing to launch:**
   ```bash
   # Check launch template
   aws ec2 describe-launch-template-versions \
     --launch-template-id $(aws autoscaling describe-auto-scaling-groups \
       --auto-scaling-group-names $ASG_NAME \
       --query "AutoScalingGroups[0].LaunchTemplate.LaunchTemplateId" \
       --output text)

   # Verify AMI exists
   aws ec2 describe-images --image-ids $(aws ssm get-parameter \
     --name /vettid/nitro-enclave/current-ami --query Parameter.Value --output text)
   ```

2. **If AMI corrupted/deleted:**
   ```bash
   # Roll back to previous known-good AMI
   aws ssm put-parameter \
     --name /vettid/nitro-enclave/current-ami \
     --value <previous-ami-id> \
     --overwrite

   # Trigger instance refresh
   aws autoscaling start-instance-refresh --auto-scaling-group-name $ASG_NAME
   ```

3. **If VPC/networking issue:**
   ```bash
   # Check security groups
   aws ec2 describe-security-groups --group-ids <sg-id>

   # Check VPC peering (if separate VPCs)
   aws ec2 describe-vpc-peering-connections

   # Check route tables
   aws ec2 describe-route-tables --filters "Name=vpc-id,Values=<vpc-id>"
   ```

4. **Force new instances:**
   ```bash
   # Set capacity to 0, then back up
   aws autoscaling set-desired-capacity --auto-scaling-group-name $ASG_NAME --desired-capacity 0
   sleep 60
   aws autoscaling set-desired-capacity --auto-scaling-group-name $ASG_NAME --desired-capacity 2
   ```

### 4.2 NATS Cluster Failure

**Diagnosis:**
```bash
# Check NATS target group health
NATS_TG_ARN=$(aws elbv2 describe-target-groups \
  --query "TargetGroups[?contains(TargetGroupName, 'nats')].TargetGroupArn" \
  --output text)

aws elbv2 describe-target-health --target-group-arn $NATS_TG_ARN

# Check NATS instances
aws ec2 describe-instances \
  --filters "Name=tag:Application,Values=vettid-nats" \
  --query "Reservations[].Instances[].{ID:InstanceId,State:State.Name}"
```

**Recovery Steps:**

1. **If NATS process crashed:**
   ```bash
   # Restart NATS on all instances via SSM
   for instance in $(aws ec2 describe-instances \
     --filters "Name=tag:Application,Values=vettid-nats" "Name=instance-state-name,Values=running" \
     --query "Reservations[].Instances[].InstanceId" --output text); do
     aws ssm send-command \
       --instance-ids $instance \
       --document-name "AWS-RunShellScript" \
       --parameters 'commands=["sudo systemctl restart nats-server"]'
   done
   ```

2. **If instances unhealthy:**
   ```bash
   # Force replace via ASG (if using ASG for NATS)
   aws autoscaling set-instance-health \
     --instance-id <unhealthy-instance-id> \
     --health-status Unhealthy
   ```

3. **If cluster cannot form quorum:**
   ```bash
   # Check NATS cluster state
   aws ssm start-session --target <nats-instance-id>
   # On instance:
   nats-server --signal ldm  # List data messages
   ```

### 4.3 KMS Key Recovery

**Diagnosis:**
```bash
# Get key ID
KEY_ARN=$(aws ssm get-parameter --name /vettid/nitro/sealing-key-arn --query Parameter.Value --output text)
KEY_ID=$(echo $KEY_ARN | cut -d'/' -f2)

# Check key state
aws kms describe-key --key-id $KEY_ID --query "KeyMetadata.{State:KeyState,Enabled:Enabled}"
```

**Recovery Steps:**

1. **If key disabled:**
   ```bash
   aws kms enable-key --key-id $KEY_ID
   ```

2. **If key scheduled for deletion:**
   ```bash
   aws kms cancel-key-deletion --key-id $KEY_ID
   aws kms enable-key --key-id $KEY_ID
   ```

3. **If key deleted (CRITICAL - may be unrecoverable):**
   - Keys can only be recovered within 7-30 day waiting period
   - If truly deleted, vault data is **permanently unrecoverable**
   - Contact AWS Support immediately
   - Begin user notification process

### 4.4 S3 Data Recovery

**Diagnosis:**
```bash
# Check if object exists
aws s3api head-object \
  --bucket vettid-vault-data-<account-id> \
  --key vaults/<vault-id>/data.enc

# List deleted objects (if versioning enabled)
aws s3api list-object-versions \
  --bucket vettid-vault-data-<account-id> \
  --prefix vaults/<vault-id>/ \
  --query "DeleteMarkers[].{Key:Key,VersionId:VersionId,DeletedTime:LastModified}"
```

**Recovery Steps:**

1. **Recover accidentally deleted object:**
   ```bash
   # Remove delete marker to restore
   aws s3api delete-object \
     --bucket vettid-vault-data-<account-id> \
     --key vaults/<vault-id>/data.enc \
     --version-id <delete-marker-version-id>
   ```

2. **Restore previous version:**
   ```bash
   # List versions
   aws s3api list-object-versions \
     --bucket vettid-vault-data-<account-id> \
     --key vaults/<vault-id>/data.enc

   # Copy old version to current
   aws s3api copy-object \
     --bucket vettid-vault-data-<account-id> \
     --key vaults/<vault-id>/data.enc \
     --copy-source "vettid-vault-data-<account-id>/vaults/<vault-id>/data.enc?versionId=<old-version-id>"
   ```

3. **Restore from cross-region replica:**
   ```bash
   # Copy from DR region
   aws s3 cp \
     s3://vettid-vault-data-dr-<account-id>/vaults/<vault-id>/ \
     s3://vettid-vault-data-<account-id>/vaults/<vault-id>/ \
     --recursive \
     --source-region us-west-2
   ```

---

## 5. Cross-Region DR

### 5.1 DR Architecture (if configured)

```
Primary Region (us-east-1)          DR Region (us-west-2)
┌──────────────────────┐            ┌──────────────────────┐
│  Nitro Enclave ASG   │            │  (Standby ASG)       │
│  NATS Cluster        │     →      │  (Standby NATS)      │
│  S3 Vault Data       │  ═══════>  │  S3 Replica          │
│  DynamoDB Tables     │  ═══════>  │  Global Tables       │
│  KMS Multi-Region    │  ═══════>  │  KMS Replica         │
└──────────────────────┘            └──────────────────────┘
```

### 5.2 Failover Procedure

**Pre-requisites:**
- Cross-region replication enabled for S3
- DynamoDB Global Tables configured
- Multi-region KMS key enabled
- DR AMI replicated to us-west-2
- Route 53 health checks configured

**Failover Steps:**

1. **Activate DR region:**
   ```bash
   # Switch to DR region
   export AWS_DEFAULT_REGION=us-west-2

   # Scale up standby ASG
   aws autoscaling set-desired-capacity \
     --auto-scaling-group-name VettID-Nitro-DR-EnclaveASG \
     --desired-capacity 2
   ```

2. **Update DNS:**
   ```bash
   # Update Route 53 to point to DR region
   aws route53 change-resource-record-sets \
     --hosted-zone-id <zone-id> \
     --change-batch file://dr-failover-records.json
   ```

3. **Verify DR services:**
   ```bash
   # Test enrollment endpoint in DR region
   curl -X POST "https://api-dr.vettid.dev/vault/enroll/start-direct" \
     -H "Content-Type: application/json" \
     -d '{"device_id":"dr-test","device_type":"android","invitation_code":"DR-TEST"}'
   ```

4. **Notify mobile app users:**
   - Push notification about service restoration
   - May need app config update if API endpoint changed

### 5.3 Failback Procedure

1. **Verify primary region recovered:**
   ```bash
   export AWS_DEFAULT_REGION=us-east-1
   # Run health checks
   ```

2. **Sync any DR-region changes back:**
   ```bash
   # S3 reverse replication (if needed)
   aws s3 sync \
     s3://vettid-vault-data-dr-<account-id>/ \
     s3://vettid-vault-data-<account-id>/ \
     --source-region us-west-2
   ```

3. **Scale up primary, scale down DR:**
   ```bash
   # Primary
   export AWS_DEFAULT_REGION=us-east-1
   aws autoscaling set-desired-capacity \
     --auto-scaling-group-name VettID-Nitro-EnclaveASG \
     --desired-capacity 2

   # DR (after primary healthy)
   export AWS_DEFAULT_REGION=us-west-2
   aws autoscaling set-desired-capacity \
     --auto-scaling-group-name VettID-Nitro-DR-EnclaveASG \
     --desired-capacity 0
   ```

4. **Update DNS back to primary**

---

## 6. PCR Rotation

### 6.1 Understanding PCR Changes

**What causes PCR changes:**
- Enclave code updates
- Enclave OS updates
- Signing key rotation
- Build environment changes

**PCR Meanings:**
- **PCR0:** Enclave image hash (code + data)
- **PCR1:** Linux kernel and boot parameters
- **PCR2:** Application binary hash

### 6.2 Planned PCR Rotation

**Process:**

1. **Build new enclave image:**
   ```bash
   # Build produces new AMI and PCR values
   ./scripts/build-enclave.sh
   # Outputs: New AMI ID and PCR0/1/2 values
   ```

2. **Update SSM parameters:**
   ```bash
   aws ssm put-parameter \
     --name /vettid/nitro-enclave/latest-ami \
     --value <new-ami-id> \
     --overwrite
   ```

3. **Update mobile apps FIRST:**
   - iOS: Update `expected_pcrs.json` with new PCR set
   - Android: Update `expected_pcrs.json` with new PCR set
   - Add new PCRs as additional valid set (keep old ones)
   - Release app update
   - Wait for sufficient adoption (>80%)

4. **Deploy new enclave AMI:**
   ```bash
   aws ssm put-parameter \
     --name /vettid/nitro-enclave/current-ami \
     --value <new-ami-id> \
     --overwrite

   # Rolling update
   aws autoscaling start-instance-refresh \
     --auto-scaling-group-name $ASG_NAME \
     --preferences '{"MinHealthyPercentage": 50}'
   ```

5. **Deprecate old PCRs (after 30+ days):**
   - Update mobile apps to remove old PCR set
   - Mark old set with `valid_until` date

### 6.3 Emergency PCR Rollback

**If new enclave has issues:**

1. **Rollback AMI:**
   ```bash
   aws ssm put-parameter \
     --name /vettid/nitro-enclave/current-ami \
     --value <previous-ami-id> \
     --overwrite

   aws autoscaling start-instance-refresh \
     --auto-scaling-group-name $ASG_NAME
   ```

2. **Mobile apps should still work:**
   - If they have both old and new PCR sets, rollback is transparent
   - If only new PCRs, users with old app versions may have issues

---

## 7. Testing DR Procedures

### 7.1 Monthly DR Tests

**Test Checklist:**

- [ ] Verify S3 cross-region replication lag < 15 minutes
- [ ] Test DynamoDB global table consistency
- [ ] Verify KMS key accessible in DR region
- [ ] Test SSM parameter backup restoration
- [ ] Simulate single instance failure and recovery
- [ ] Test alarm escalation path

### 7.2 Quarterly Failover Test

**Procedure:**

1. Schedule maintenance window
2. Notify users of potential brief disruption
3. Execute failover to DR region
4. Run smoke tests in DR region
5. Execute failback to primary
6. Document any issues and update runbooks

### 7.3 Annual Full DR Exercise

**Scope:**
- Complete regional failover
- 4-hour operation in DR region
- Include on-call team participation
- Test communication procedures
- Update RTO/RPO based on actual times

---

## Appendix: Emergency Contacts

### Escalation Path

| Level | Contact | When |
|-------|---------|------|
| L1 | On-call engineer | First response |
| L2 | Team lead | > 30 min or P1 |
| L3 | Platform architect | Data loss risk |
| L4 | Executive | User-facing outage > 1 hour |

### AWS Support

- **Case Severity:** Critical (if production down)
- **Service:** EC2 Nitro Enclaves, KMS, S3
- **Support Plan:** Business or Enterprise required for < 1 hour response

### Communication Templates

**User Notification (Service Degraded):**
```
VettID is currently experiencing intermittent issues with vault
operations. Our team is actively working to resolve this.
We apologize for any inconvenience.
```

**User Notification (Service Restored):**
```
VettID services have been fully restored. All vault operations
are functioning normally. Thank you for your patience.
```

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-06 | Operations Team | Initial version |
