# Enclave Update Runbook

## Overview

This runbook covers the procedure for updating the Nitro Enclave code. Updates change the PCR0 value (enclave image hash), which requires coordinated updates to the KMS key policy.

## Prerequisites

- AWS CLI configured with appropriate permissions
- Access to the enclave source code
- CDK deployment access

## Update Types

| Type | PCR0 Change | KMS Update | Downtime |
|------|-------------|------------|----------|
| Code changes | Yes | Required | Rolling |
| Configuration | Maybe | Check | Rolling |
| Security patch | Yes | Required | Rolling |

## Procedure

### Step 1: Build New Enclave Image

```bash
cd /home/al/Projects/VettID/vettid-dev/enclave

# Run the deployment script (builds EIF, creates AMI, triggers refresh)
./scripts/deploy-enclave.sh
```

The script will output:
- New AMI ID: `ami-xxxxxxxxx`
- New PCR0 value: `e602...` (96 hex characters)

### Step 2: Update KMS Key Policy

The KMS key policy must include the new PCR0 before instances can seal/unseal data.

```bash
cd /home/al/Projects/VettID/vettid-dev/cdk

# CDK will update the KMS policy with the new PCR0 from SSM
npm run deploy -- VettID-Nitro
```

### Step 3: Monitor Instance Refresh

```bash
ASG_NAME=$(aws autoscaling describe-auto-scaling-groups \
  --query "AutoScalingGroups[?contains(AutoScalingGroupName, 'VettID-Nitro')].AutoScalingGroupName" \
  --output text)

# Check refresh status
watch -n 10 'aws autoscaling describe-instance-refreshes \
  --auto-scaling-group-name "'$ASG_NAME'" \
  --query "InstanceRefreshes[0]" \
  --output table'
```

### Step 4: Verify New Instances

```bash
# Get new instance ID
NEW_INSTANCE=$(aws autoscaling describe-auto-scaling-groups \
  --auto-scaling-group-name "$ASG_NAME" \
  --query "AutoScalingGroups[0].Instances[0].InstanceId" \
  --output text)

# Verify enclave is running
aws ssm send-command \
  --instance-ids "$NEW_INSTANCE" \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["nitro-cli describe-enclaves"]'
```

### Step 5: Test Functionality

```bash
# Test health endpoint
curl -s https://api.vettid.dev/vault/health | jq

# Test PIN flow (using test user)
# See testing documentation for full test procedure
```

## PCR0 Transition Period

During updates, both old and new PCR0 values must be valid:

1. **Before deploy:** Only old PCR0 in KMS policy
2. **During deploy:** Both PCR0 values in KMS policy (handled by CDK)
3. **After complete:** Only new PCR0 in KMS policy

The CDK stack manages this automatically via SSM parameters.

## Rollback Procedure

If the update fails:

### Option A: Cancel Instance Refresh

```bash
aws autoscaling cancel-instance-refresh \
  --auto-scaling-group-name "$ASG_NAME"
```

### Option B: Revert to Previous AMI

```bash
# Get previous AMI ID from SSM parameter history
aws ssm get-parameter-history \
  --name /vettid/enclave/ami-id \
  --query "Parameters[-2].Value" \
  --output text

# Update SSM parameter to previous AMI
aws ssm put-parameter \
  --name /vettid/enclave/ami-id \
  --value "ami-PREVIOUS_ID" \
  --type String \
  --overwrite

# Trigger new instance refresh with old AMI
aws autoscaling start-instance-refresh \
  --auto-scaling-group-name "$ASG_NAME"
```

## Verification Checklist

- [ ] New AMI built successfully
- [ ] PCR0 updated in SSM parameter
- [ ] KMS key policy updated
- [ ] Instance refresh completed
- [ ] Health check passes
- [ ] PIN setup test passes
- [ ] PIN unlock test passes
- [ ] CloudWatch metrics normal

## Common Issues

### Issue: KMS Decrypt Failed
**Symptom:** Vault cannot unseal credentials
**Cause:** PCR0 in KMS policy doesn't match running enclave
**Fix:** Verify PCR0 in SSM matches deployed enclave, redeploy CDK

### Issue: Instance Refresh Stuck
**Symptom:** Refresh at 0% for extended time
**Cause:** New instances failing health checks
**Fix:** Check CloudWatch logs, may need to cancel and investigate

### Issue: Enclave Won't Start
**Symptom:** nitro-cli describe-enclaves shows no enclaves
**Cause:** EIF build issue or memory allocation
**Fix:** Check instance type, verify EIF file integrity
