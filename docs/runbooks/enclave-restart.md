# Enclave Restart Runbook

## Overview

This runbook covers how to restart the Nitro Enclave when needed. Restarts may be required after configuration changes, to recover from failures, or as part of troubleshooting.

## Prerequisites

- AWS CLI configured with appropriate permissions
- SSH access via SSM Session Manager
- Knowledge of current ASG name: `VettID-Nitro-EnclaveASG*`

## When to Restart

- Enclave is unresponsive (health checks failing)
- Memory exhaustion (supervisor OOM)
- Configuration changes that require restart
- Debugging/troubleshooting

## Procedure

### Option 1: Restart Single Instance (Minimal Impact)

1. **Identify the target instance:**
   ```bash
   aws autoscaling describe-auto-scaling-groups \
     --auto-scaling-group-names "$(aws autoscaling describe-auto-scaling-groups \
       --query "AutoScalingGroups[?contains(AutoScalingGroupName, 'VettID-Nitro')].AutoScalingGroupName" \
       --output text)" \
     --query "AutoScalingGroups[0].Instances[*].[InstanceId,HealthStatus,LifecycleState]" \
     --output table
   ```

2. **Connect via SSM and restart enclave service:**
   ```bash
   INSTANCE_ID="i-xxxxxxxxx"

   aws ssm send-command \
     --instance-ids "$INSTANCE_ID" \
     --document-name "AWS-RunShellScript" \
     --parameters 'commands=["sudo systemctl restart nitro-enclave"]' \
     --output text --query "Command.CommandId"
   ```

3. **Verify restart:**
   ```bash
   aws ssm send-command \
     --instance-ids "$INSTANCE_ID" \
     --document-name "AWS-RunShellScript" \
     --parameters 'commands=["sudo systemctl status nitro-enclave --no-pager"]' \
     --output text --query "Command.CommandId"
   ```

### Option 2: Instance Refresh (Rolling Restart)

For a complete refresh of all instances:

```bash
ASG_NAME=$(aws autoscaling describe-auto-scaling-groups \
  --query "AutoScalingGroups[?contains(AutoScalingGroupName, 'VettID-Nitro')].AutoScalingGroupName" \
  --output text)

aws autoscaling start-instance-refresh \
  --auto-scaling-group-name "$ASG_NAME" \
  --preferences '{
    "MinHealthyPercentage": 50,
    "InstanceWarmup": 120
  }'
```

Monitor progress:
```bash
aws autoscaling describe-instance-refreshes \
  --auto-scaling-group-name "$ASG_NAME" \
  --query "InstanceRefreshes[0].[Status,PercentageComplete,StatusReason]" \
  --output table
```

### Option 3: Terminate and Replace (Emergency)

If an instance is completely unrecoverable:

```bash
INSTANCE_ID="i-xxxxxxxxx"

aws ec2 terminate-instances --instance-ids "$INSTANCE_ID"
```

The ASG will automatically launch a replacement.

## Verification

After restart, verify:

1. **Health check passes:**
   ```bash
   curl -s https://api.vettid.dev/vault/health | jq
   ```

2. **Enclave is running:**
   ```bash
   aws ssm send-command \
     --instance-ids "$INSTANCE_ID" \
     --document-name "AWS-RunShellScript" \
     --parameters 'commands=["nitro-cli describe-enclaves"]'
   ```

3. **Supervisor logs are clean:**
   ```bash
   aws ssm send-command \
     --instance-ids "$INSTANCE_ID" \
     --document-name "AWS-RunShellScript" \
     --parameters 'commands=["journalctl -u nitro-enclave -n 50 --no-pager"]'
   ```

## Impact

- **Service Continuity:** Active vault sessions will be terminated
- **User Experience:** Users with active sessions will need to re-authenticate
- **Data Safety:** No data loss - all vault data is persisted in S3

## Rollback

If the restart causes issues:
1. Check CloudWatch logs for errors
2. Revert to previous AMI if needed (see enclave-update.md)
3. Contact on-call if unable to resolve
