# VettID Nitro Enclave Operations Runbook

## Document Information

| Field | Value |
|-------|-------|
| Version | 1.0 |
| Date | 2026-01-06 |
| Author | Operations Team |

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Monitoring & Dashboards](#2-monitoring--dashboards)
3. [Health Checks](#3-health-checks)
4. [Common Operations](#4-common-operations)
5. [Troubleshooting](#5-troubleshooting)
6. [Incident Response](#6-incident-response)
7. [Scaling Operations](#7-scaling-operations)
8. [AMI Updates](#8-ami-updates)

---

## 1. Architecture Overview

### Components

```
┌─────────────────────────────────────────────────────────────────┐
│                        AWS Infrastructure                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
│  │   Lambda    │    │   Lambda    │    │   Lambda    │         │
│  │ enrollStart │    │enrollFinalize│   │  vaultHealth│         │
│  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘         │
│         │                  │                  │                 │
│         └──────────────────┼──────────────────┘                 │
│                            │                                    │
│                            ▼                                    │
│                 ┌─────────────────────┐                         │
│                 │   NATS Cluster      │                         │
│                 │   (3 instances)     │                         │
│                 │   nats.internal     │                         │
│                 └──────────┬──────────┘                         │
│                            │                                    │
│         ┌──────────────────┼──────────────────┐                 │
│         │                  │                  │                 │
│         ▼                  ▼                  ▼                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
│  │  Nitro EC2  │    │  Nitro EC2  │    │  Nitro EC2  │         │
│  │  (Enclave)  │    │  (Enclave)  │    │  (Enclave)  │         │
│  │   Parent    │    │   Parent    │    │   Parent    │         │
│  └─────────────┘    └─────────────┘    └─────────────┘         │
│         │                  │                  │                 │
│         └──────────────────┼──────────────────┘                 │
│                            │                                    │
│                            ▼                                    │
│                 ┌─────────────────────┐                         │
│                 │   S3 Vault Data     │                         │
│                 │   (Encrypted)       │                         │
│                 └─────────────────────┘                         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Key Resources

| Resource | Name/ARN | Purpose |
|----------|----------|---------|
| ASG | VettID-Nitro-EnclaveASG | Manages enclave EC2 instances |
| NATS NLB | VettID-NATS-* | Load balances NATS cluster |
| S3 | vettid-vault-data-* | Encrypted vault storage |
| SSM Param | /vettid/nitro/parent-nats-creds | NATS credentials |
| SSM Param | /vettid/nitro-enclave/current-ami | Current enclave AMI |
| SSM Param | /vettid/nitro-enclave/latest-ami | Latest available AMI |

---

## 2. Monitoring & Dashboards

### CloudWatch Dashboards

| Dashboard | URL | Purpose |
|-----------|-----|---------|
| VettID-Nitro-Enclave | [Console Link](https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#dashboards:name=VettID-Nitro-Enclave) | Enclave health & scaling |
| VettID-Operations | [Console Link](https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#dashboards:name=VettID-Operations) | Overall system health |

### Key Metrics to Monitor

| Metric | Namespace | Threshold | Alert |
|--------|-----------|-----------|-------|
| GroupInServiceInstances | AWS/AutoScaling | < 1 | Critical |
| CPUUtilization | AWS/EC2 | > 80% | Warning |
| NetworkIn/Out | AWS/EC2 | > 50 MB/s | Scale trigger |
| 5XX Errors | AWS/ApiGateway | > 10/5min | Critical |

### Alarms

| Alarm Name | Condition | Action |
|------------|-----------|--------|
| VettID-Enclave-NoInstances | InService < 1 for 10 min | Page on-call |
| VettID-Enclave-HighCPU | CPU > 80% for 15 min | Auto-scale + notify |
| VettID-NATS-NoHealthyInstances | Healthy < 1 | Page on-call |

---

## 3. Health Checks

### System Health API

```bash
# Get overall system health (requires admin token)
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  https://${API_GATEWAY_ID}.execute-api.${AWS_REGION}.amazonaws.com/admin/system-health
```

**Response includes:**
- `nitro.status`: healthy/degraded/unhealthy
- `nitro.runningInstances`: Current count
- `nitro.healthyInstances`: Healthy count
- `nitro.amiUpToDate`: Whether running latest AMI
- `nats.status`: NATS cluster health
- `nats.healthyNodes`: Healthy NATS nodes

### Manual Health Checks

```bash
# Check ASG status
aws autoscaling describe-auto-scaling-groups \
  --auto-scaling-group-names $(aws cloudformation describe-stacks \
    --stack-name VettID-Nitro \
    --query "Stacks[0].Outputs[?OutputKey=='EnclaveASGName'].OutputValue" \
    --output text)

# Check NATS cluster
aws elbv2 describe-target-health \
  --target-group-arn $(aws elbv2 describe-target-groups \
    --query "TargetGroups[?contains(TargetGroupName, 'nats')].TargetGroupArn" \
    --output text)

# Check enclave attestation
curl -s -X POST "https://${API_GATEWAY_ID}.execute-api.${AWS_REGION}.amazonaws.com/vault/enroll/start-direct" \
  -H "Content-Type: application/json" \
  -d '{"device_id":"health-check","device_type":"android","invitation_code":"HEALTH-CHECK"}' \
  | jq '.enclave_attestation | keys'
# Should return: ["attestation_document", "enclave_public_key", "expected_pcrs", "nonce"]
```

---

## 4. Common Operations

### 4.1 View Enclave Instances

```bash
# List all enclave instances
aws ec2 describe-instances \
  --filters "Name=tag:Application,Values=vettid-enclave" \
  --query "Reservations[].Instances[].{ID:InstanceId,State:State.Name,IP:PrivateIpAddress,AZ:Placement.AvailabilityZone}" \
  --output table
```

### 4.2 Connect to Instance (SSM)

```bash
# Start SSM session
aws ssm start-session --target <instance-id>

# Once connected:
sudo systemctl status vettid-enclave
sudo systemctl status vettid-parent
sudo journalctl -u vettid-parent -f
```

### 4.3 View Enclave Logs

```bash
# On the instance via SSM:
sudo journalctl -u vettid-enclave --since "1 hour ago"
sudo journalctl -u vettid-parent --since "1 hour ago"

# Check enclave console
sudo nitro-cli console --enclave-id $(sudo nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')
```

### 4.4 Manually Scale ASG

```bash
# Get ASG name
ASG_NAME=$(aws cloudformation describe-stacks --stack-name VettID-Nitro \
  --query "Stacks[0].Outputs[?OutputKey=='EnclaveASGName'].OutputValue" --output text)

# Scale to 2 instances
aws autoscaling set-desired-capacity \
  --auto-scaling-group-name $ASG_NAME \
  --desired-capacity 2

# Scale to 3 instances (max)
aws autoscaling set-desired-capacity \
  --auto-scaling-group-name $ASG_NAME \
  --desired-capacity 3

# Scale back to 1
aws autoscaling set-desired-capacity \
  --auto-scaling-group-name $ASG_NAME \
  --desired-capacity 1
```

### 4.5 Terminate Unhealthy Instance

```bash
# Terminate specific instance (ASG will replace it)
aws autoscaling terminate-instance-in-auto-scaling-group \
  --instance-id <instance-id> \
  --should-decrement-desired-capacity false
```

---

## 5. Troubleshooting

### 5.1 Enrollment Returns HTTP 500

**Symptoms:**
- `/vault/enroll/start-direct` returns `{"message":"Failed to start enrollment"}`

**Check:**
```bash
# Check Lambda logs
aws logs tail /aws/lambda/VettID-Vault-EnrollStartFn* --since 1h --format short

# Look for NATS errors (503 = no responders)
aws logs filter-log-events \
  --log-group-name /aws/lambda/VettID-Vault-EnrollStartFn* \
  --filter-pattern "ERROR" \
  --start-time $(($(date +%s) - 3600))000
```

**Common causes:**
1. **NATS 503 "No Responders"**: Enclave not running or not subscribed
   - Check enclave instances are running
   - Check `vettid-parent` service on instances
2. **NATS connection timeout**: Network issue
   - Check VPC peering between Nitro VPC and NATS VPC
   - Check security groups allow port 4222

**Fix:**
```bash
# Restart parent process on all instances
for instance in $(aws ec2 describe-instances --filters "Name=tag:Application,Values=vettid-enclave" "Name=instance-state-name,Values=running" --query "Reservations[].Instances[].InstanceId" --output text); do
  aws ssm send-command \
    --instance-ids $instance \
    --document-name "AWS-RunShellScript" \
    --parameters 'commands=["sudo systemctl restart vettid-parent"]'
done
```

### 5.2 High CPU on Enclave Instances

**Symptoms:**
- VettID-Enclave-HighCPU alarm firing
- Slow enrollment/vault operations

**Check:**
```bash
# Check CPU per instance
aws cloudwatch get-metric-statistics \
  --namespace AWS/EC2 \
  --metric-name CPUUtilization \
  --dimensions Name=AutoScalingGroupName,Value=$ASG_NAME \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%SZ) \
  --period 300 \
  --statistics Average
```

**Fix:**
- Auto-scaling should handle this automatically (target: 70% CPU)
- If not scaling, manually increase desired capacity
- If consistently high, consider increasing instance size

### 5.3 NATS Cluster Degraded

**Symptoms:**
- `nats.status: degraded` in system health
- Some vault operations failing

**Check:**
```bash
# Check NATS target health
aws elbv2 describe-target-health \
  --target-group-arn $(aws elbv2 describe-target-groups \
    --query "TargetGroups[?contains(TargetGroupName, 'nats')].TargetGroupArn" \
    --output text) \
  --query "TargetHealthDescriptions[].{Target:Target.Id,Health:TargetHealth.State}"
```

**Fix:**
- If one node unhealthy: It will be replaced automatically
- If multiple nodes: Check EC2 instance status, restart NATS service

### 5.4 Attestation Verification Failing

**Symptoms:**
- Mobile apps failing to verify attestation
- PCR mismatch errors

**Check:**
- Verify PCR values match between server and mobile app
- Check if enclave AMI was recently updated

**Fix:**
- Update mobile app PCR configuration
- Or roll back enclave AMI if unintended

---

## 6. Incident Response

### Severity Levels

| Level | Description | Response Time | Example |
|-------|-------------|---------------|---------|
| P1 | Service down | 15 min | No enclave instances |
| P2 | Degraded | 1 hour | High error rate |
| P3 | Minor issue | 4 hours | Single instance unhealthy |
| P4 | Informational | Next business day | AMI update available |

### P1: No Enclave Instances

1. **Verify alarm**: Check CloudWatch dashboard
2. **Check ASG**: `aws autoscaling describe-auto-scaling-groups`
3. **Check EC2**: Any instances in `pending` or `terminated`?
4. **Check launch issues**: ASG activity history
5. **Manual intervention**: Set desired capacity manually
6. **Escalate**: If instances won't launch, check AMI/launch template

### P2: High Error Rate

1. **Identify error type**: Check Lambda logs
2. **Check dependencies**: NATS, DynamoDB, S3
3. **Scale if needed**: Increase enclave capacity
4. **Rollback if needed**: If recent deployment caused issue

---

## 7. Scaling Operations

### Auto-Scaling Configuration

| Parameter | Value | Notes |
|-----------|-------|-------|
| Min Capacity | 1 | Single instance for dev |
| Max Capacity | 3 | Scale up for load |
| Target CPU | 70% | Scale out above this |
| Cooldown | 5 min | Between scaling actions |
| Warmup | 3 min | Before instance serves traffic |

### Manual Scaling Commands

```bash
# View current scaling policies
aws autoscaling describe-policies --auto-scaling-group-name $ASG_NAME

# View scaling activities
aws autoscaling describe-scaling-activities \
  --auto-scaling-group-name $ASG_NAME \
  --max-items 10
```

### Capacity Planning

| Users | Recommended Min | Recommended Max |
|-------|-----------------|-----------------|
| < 100 | 1 | 2 |
| 100-500 | 2 | 3 |
| 500-1000 | 3 | 5 |
| > 1000 | Contact team | Contact team |

---

## 8. AMI Updates

### Check for Updates

```bash
# Compare current vs latest AMI
CURRENT=$(aws ssm get-parameter --name /vettid/nitro-enclave/current-ami --query Parameter.Value --output text)
LATEST=$(aws ssm get-parameter --name /vettid/nitro-enclave/latest-ami --query Parameter.Value --output text)
echo "Current: $CURRENT"
echo "Latest:  $LATEST"
```

### Trigger Instance Refresh

```bash
# Start rolling update to new AMI
aws autoscaling start-instance-refresh \
  --auto-scaling-group-name $ASG_NAME \
  --preferences '{"MinHealthyPercentage": 50, "InstanceWarmup": 180}'

# Monitor refresh progress
aws autoscaling describe-instance-refreshes \
  --auto-scaling-group-name $ASG_NAME \
  --query "InstanceRefreshes[0].{Status:Status,Progress:PercentageComplete}"
```

### Rollback AMI

```bash
# Update launch template to previous AMI
aws ssm put-parameter \
  --name /vettid/nitro-enclave/current-ami \
  --value $PREVIOUS_AMI \
  --overwrite

# Trigger refresh to rollback
aws autoscaling start-instance-refresh \
  --auto-scaling-group-name $ASG_NAME
```

---

## Appendix: Quick Reference

### Important URLs

- CloudWatch Dashboard: `https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#dashboards:name=VettID-Nitro-Enclave`
- ASG Console: `https://console.aws.amazon.com/ec2autoscaling/home?region=us-east-1#/details/VettID-Nitro-EnclaveASG`
- API Gateway: `https://${API_GATEWAY_ID}.execute-api.${AWS_REGION}.amazonaws.com`

### Key SSM Parameters

```
/vettid/nitro/parent-nats-creds     # NATS credentials
/vettid/nitro-enclave/current-ami   # Current AMI ID
/vettid/nitro-enclave/latest-ami    # Latest AMI ID
/vettid/nitro/sealing-key-arn       # KMS key for sealing
```

### Contact

- On-call: Check PagerDuty rotation
- Escalation: #vettid-incidents Slack channel
