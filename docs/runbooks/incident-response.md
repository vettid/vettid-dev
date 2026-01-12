# Enclave Incident Response Runbook

## Overview

This runbook provides procedures for responding to incidents involving the Nitro Enclave infrastructure.

## Incident Classification

| Severity | Description | Response Time | Examples |
|----------|-------------|---------------|----------|
| P1 Critical | Complete service outage | Immediate | All vaults inaccessible |
| P2 High | Degraded service | < 15 min | Intermittent failures, high latency |
| P3 Medium | Minor issues | < 1 hour | Single user affected, non-blocking |
| P4 Low | Informational | Next business day | Warnings, capacity concerns |

## Detection

### Automated Alerts

- **CloudWatch Alarms:** TargetResponseTime, HealthyHostCount
- **NATS Monitoring:** Connection failures, message backlogs
- **API Gateway:** 5xx error rate

### Manual Checks

```bash
# Quick health check
curl -s https://api.vettid.dev/vault/health | jq

# ASG instance health
aws autoscaling describe-auto-scaling-groups \
  --query "AutoScalingGroups[?contains(AutoScalingGroupName, 'VettID-Nitro')].Instances[*].[InstanceId,HealthStatus]" \
  --output table
```

## Response Procedures

### P1: Complete Outage

**Immediate Actions (0-5 minutes):**

1. Acknowledge the incident
2. Check AWS Health Dashboard for regional issues
3. Verify ASG has running instances:
   ```bash
   aws autoscaling describe-auto-scaling-groups \
     --query "AutoScalingGroups[?contains(AutoScalingGroupName, 'VettID-Nitro')]"
   ```

**Diagnosis (5-15 minutes):**

4. Check if instances are healthy:
   ```bash
   # Get instance IDs
   INSTANCES=$(aws autoscaling describe-auto-scaling-groups \
     --query "AutoScalingGroups[?contains(AutoScalingGroupName, 'VettID-Nitro')].Instances[*].InstanceId" \
     --output text)

   # Check each instance
   for i in $INSTANCES; do
     echo "=== $i ==="
     aws ssm send-command \
       --instance-ids "$i" \
       --document-name "AWS-RunShellScript" \
       --parameters 'commands=["systemctl status nitro-enclave --no-pager"]'
   done
   ```

5. Check NATS connectivity:
   ```bash
   aws ssm send-command \
     --instance-ids "$INSTANCE_ID" \
     --document-name "AWS-RunShellScript" \
     --parameters 'commands=["nats server ping -s nats://nats.internal.vettid.dev:4222"]'
   ```

**Recovery (15+ minutes):**

6. If enclave not running, restart:
   ```bash
   aws ssm send-command \
     --instance-ids "$INSTANCE_ID" \
     --document-name "AWS-RunShellScript" \
     --parameters 'commands=["sudo systemctl restart nitro-enclave"]'
   ```

7. If instance unhealthy, trigger instance refresh:
   ```bash
   aws autoscaling start-instance-refresh \
     --auto-scaling-group-name "$ASG_NAME" \
     --preferences '{"MinHealthyPercentage": 0}'
   ```

### P2: Degraded Service

1. Identify affected component (NATS, enclave, parent process)
2. Check CloudWatch metrics for anomalies
3. Review recent deployments
4. If memory pressure, consider scaling out

### P3: Single User Affected

1. Collect user GUID and error details
2. Check if vault process is running for that user:
   ```bash
   aws ssm send-command \
     --instance-ids "$INSTANCE_ID" \
     --document-name "AWS-RunShellScript" \
     --parameters 'commands=["ps aux | grep vault-manager"]'
   ```
3. Check vault-manager logs for user
4. If stuck, the vault will be evicted after inactivity timeout

## Common Issues

### Issue: High Memory Usage

**Detection:**
```bash
aws cloudwatch get-metric-statistics \
  --namespace AWS/EC2 \
  --metric-name MemoryUtilization \
  --dimensions Name=AutoScalingGroupName,Value="$ASG_NAME" \
  --start-time $(date -d '1 hour ago' --iso-8601=seconds) \
  --end-time $(date --iso-8601=seconds) \
  --period 300 \
  --statistics Average
```

**Resolution:**
- Check for vault memory leaks
- Consider increasing instance type
- Review LRU eviction policy

### Issue: KMS Throttling

**Detection:** CloudWatch KMS metrics show throttling

**Resolution:**
- Reduce attestation frequency
- Request KMS limit increase
- Enable KMS key caching in supervisor

### Issue: NATS Disconnection

**Detection:** Parent process logs show reconnection attempts

**Resolution:**
- Check NATS cluster health
- Verify security group rules
- Check VPC peering connectivity

## Post-Incident

1. Document timeline and actions taken
2. Identify root cause
3. Create follow-up tasks to prevent recurrence
4. Update runbooks if needed
5. Schedule post-mortem if P1/P2

## Escalation Contacts

| Role | Contact | When |
|------|---------|------|
| On-call Engineer | PagerDuty | All P1/P2 |
| Security Team | security@vettid.dev | Security incidents |
| AWS Support | AWS Console | Infrastructure issues |
