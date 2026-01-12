# Capacity Planning Runbook

## Overview

This runbook covers capacity planning for the Nitro Enclave infrastructure, including when to scale, how to scale, and cost optimization.

## Current Configuration

| Component | Setting | Notes |
|-----------|---------|-------|
| Instance Type | c6a.xlarge | 4 vCPU, 8GB RAM |
| Enclave Memory | 6GB | Allocated to enclave |
| Max Vaults/Instance | ~160 | ~40MB per vault process |
| ASG Min | 1 | Minimum instances |
| ASG Max | 3 | Maximum instances |
| ASG Desired | 1 | Current target |

## Capacity Metrics

### Key CloudWatch Metrics

```bash
# Memory utilization across ASG
aws cloudwatch get-metric-statistics \
  --namespace CWAgent \
  --metric-name mem_used_percent \
  --dimensions Name=AutoScalingGroupName,Value="$ASG_NAME" \
  --start-time $(date -d '24 hours ago' --iso-8601=seconds) \
  --end-time $(date --iso-8601=seconds) \
  --period 3600 \
  --statistics Average,Maximum

# Active vault count (custom metric from supervisor)
aws cloudwatch get-metric-statistics \
  --namespace VettID/Enclave \
  --metric-name ActiveVaults \
  --start-time $(date -d '24 hours ago' --iso-8601=seconds) \
  --end-time $(date --iso-8601=seconds) \
  --period 3600 \
  --statistics Average,Maximum
```

### Scaling Thresholds

| Metric | Scale Out | Scale In | Notes |
|--------|-----------|----------|-------|
| Memory % | > 75% | < 40% | 5 min sustained |
| Active Vaults | > 120 | < 50 | Per instance |
| CPU % | > 70% | < 30% | 5 min sustained |

## Scaling Procedures

### Manual Scale Out

```bash
ASG_NAME=$(aws autoscaling describe-auto-scaling-groups \
  --query "AutoScalingGroups[?contains(AutoScalingGroupName, 'VettID-Nitro')].AutoScalingGroupName" \
  --output text)

# Increase desired capacity
aws autoscaling set-desired-capacity \
  --auto-scaling-group-name "$ASG_NAME" \
  --desired-capacity 2
```

### Automatic Scaling (CDK Configuration)

Add target tracking scaling policy:

```typescript
// In nitro-stack.ts
asg.scaleOnMetric('ScaleOnMemory', {
  metric: new cloudwatch.Metric({
    namespace: 'CWAgent',
    metricName: 'mem_used_percent',
    dimensionsMap: {
      AutoScalingGroupName: asg.autoScalingGroupName,
    },
    statistic: 'Average',
  }),
  scalingSteps: [
    { upper: 40, change: -1 },
    { lower: 75, change: +1 },
  ],
  adjustmentType: autoscaling.AdjustmentType.CHANGE_IN_CAPACITY,
});
```

### Scale to Zero (Cost Savings)

For non-production environments:

```bash
# Scale to 0 (off-hours)
aws autoscaling update-auto-scaling-group \
  --auto-scaling-group-name "$ASG_NAME" \
  --min-size 0 \
  --desired-capacity 0

# Scale back up
aws autoscaling update-auto-scaling-group \
  --auto-scaling-group-name "$ASG_NAME" \
  --min-size 1 \
  --desired-capacity 1
```

## Instance Type Selection

### Recommended Instance Types

| Instance | vCPU | RAM | Enclave RAM | Max Vaults | Cost/Month |
|----------|------|-----|-------------|------------|------------|
| c6a.large | 2 | 4GB | 3GB | ~75 | ~$65 |
| c6a.xlarge | 4 | 8GB | 6GB | ~160 | ~$125 |
| c6a.2xlarge | 8 | 16GB | 14GB | ~350 | ~$250 |
| c6a.4xlarge | 16 | 32GB | 30GB | ~750 | ~$500 |

### Changing Instance Type

1. Update CDK stack:
   ```typescript
   instanceType: ec2.InstanceType.of(ec2.InstanceClass.C6A, ec2.InstanceSize.XLARGE2),
   ```

2. Deploy:
   ```bash
   npm run deploy -- VettID-Nitro
   ```

3. Trigger instance refresh to apply changes.

## Cost Optimization

### Current Monthly Cost (Estimate)

| Component | Units | Unit Cost | Monthly |
|-----------|-------|-----------|---------|
| c6a.xlarge | 1 | $0.17/hr | ~$125 |
| EBS (gp3) | 50GB | $0.08/GB | ~$4 |
| Data Transfer | Variable | $0.09/GB | ~$10 |
| **Total** | | | **~$140** |

### Cost Comparison: EC2-per-user vs Nitro

| Users | EC2-per-user | Nitro (1 instance) | Savings |
|-------|--------------|---------------------|---------|
| 10 | ~$250/mo | ~$140/mo | 44% |
| 50 | ~$1,250/mo | ~$140/mo | 89% |
| 100 | ~$2,500/mo | ~$140/mo | 94% |
| 160 | ~$4,000/mo | ~$140/mo | 96% |

### Reserved Instances

For production, consider 1-year reserved instances:

| Term | Payment | Effective Rate | Savings |
|------|---------|----------------|---------|
| On-demand | N/A | $0.17/hr | 0% |
| 1yr No Upfront | None | $0.11/hr | 35% |
| 1yr All Upfront | $900 | $0.10/hr | 41% |

## Capacity Planning Checklist

### Weekly Review
- [ ] Check memory utilization trends
- [ ] Review active vault counts
- [ ] Check for capacity alerts

### Monthly Review
- [ ] Analyze growth rate
- [ ] Project capacity needs for next quarter
- [ ] Review cost optimization opportunities

### Quarterly Review
- [ ] Consider instance type changes
- [ ] Evaluate reserved instance purchases
- [ ] Review scaling policies

## Growth Projections

### Capacity Requirements by User Count

| Active Users | Instances Needed | Est. Cost/Month |
|--------------|------------------|-----------------|
| 1-150 | 1 x c6a.xlarge | $125 |
| 150-300 | 2 x c6a.xlarge | $250 |
| 300-500 | 1 x c6a.2xlarge | $250 |
| 500-1000 | 2 x c6a.2xlarge | $500 |

### Scaling Timeline

When approaching capacity limits:

1. **75% utilized:** Alert, prepare to scale
2. **85% utilized:** Scale out immediately
3. **95% utilized:** Emergency scaling, review architecture
