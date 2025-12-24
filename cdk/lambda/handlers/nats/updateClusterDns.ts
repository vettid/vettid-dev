/**
 * NATS Cluster DNS Update Lambda
 *
 * Updates Route 53 DNS records when NATS cluster instances are launched or terminated.
 * This enables DNS-based route discovery for NATS cluster nodes.
 *
 * Triggered by:
 * - EC2 Instance State-change Notification (running, terminated)
 * - Auto Scaling EC2 Instance Launch/Terminate events
 */

import {
  Route53Client,
  ChangeResourceRecordSetsCommand,
} from '@aws-sdk/client-route-53';
import {
  EC2Client,
  DescribeInstancesCommand,
} from '@aws-sdk/client-ec2';
import {
  AutoScalingClient,
  DescribeAutoScalingGroupsCommand,
  Instance as ASGInstance,
} from '@aws-sdk/client-auto-scaling';

const route53 = new Route53Client({});
const ec2 = new EC2Client({});
const autoscaling = new AutoScalingClient({});

const HOSTED_ZONE_ID = process.env.HOSTED_ZONE_ID!;
const CLUSTER_DNS_NAME = process.env.CLUSTER_DNS_NAME!;
const ASG_NAME = process.env.ASG_NAME!;
const DNS_TTL = 30; // Short TTL for quick failover

interface ASGEvent {
  source: string;
  'detail-type': string;
  detail: {
    AutoScalingGroupName?: string;
    EC2InstanceId?: string;
    LifecycleTransition?: string;
    instance?: string;
    state?: string;
  };
}

export const handler = async (event: ASGEvent): Promise<void> => {
  console.log('Received event:', JSON.stringify(event, null, 2));

  try {
    // Get all running instances in the ASG
    const asgResponse = await autoscaling.send(new DescribeAutoScalingGroupsCommand({
      AutoScalingGroupNames: [ASG_NAME],
    }));

    const asg = asgResponse.AutoScalingGroups?.[0];
    if (!asg) {
      console.error(`ASG ${ASG_NAME} not found`);
      return;
    }

    // Get instance IDs that are InService
    const instanceIds = asg.Instances
      ?.filter((i: ASGInstance) => i.LifecycleState === 'InService' && i.HealthStatus === 'Healthy')
      .map((i: ASGInstance) => i.InstanceId!)
      .filter(Boolean) || [];

    console.log(`Found ${instanceIds.length} healthy instances in ASG:`, instanceIds);

    if (instanceIds.length === 0) {
      console.log('No healthy instances found, skipping DNS update');
      return;
    }

    // Get private IPs for these instances
    const ec2Response = await ec2.send(new DescribeInstancesCommand({
      InstanceIds: instanceIds,
    }));

    const privateIps: string[] = [];
    for (const reservation of ec2Response.Reservations || []) {
      for (const instance of reservation.Instances || []) {
        if (instance.PrivateIpAddress && instance.State?.Name === 'running') {
          privateIps.push(instance.PrivateIpAddress);
        }
      }
    }

    console.log(`Found ${privateIps.length} private IPs:`, privateIps);

    if (privateIps.length === 0) {
      console.log('No running instances with private IPs, skipping DNS update');
      return;
    }

    // Create resource records for each IP
    const resourceRecords = privateIps.map(ip => ({ Value: ip }));

    // Update the DNS record
    const changeParams = {
      HostedZoneId: HOSTED_ZONE_ID,
      ChangeBatch: {
        Comment: `Update NATS cluster DNS - ${new Date().toISOString()}`,
        Changes: [
          {
            Action: 'UPSERT' as const,
            ResourceRecordSet: {
              Name: CLUSTER_DNS_NAME,
              Type: 'A' as const,
              TTL: DNS_TTL,
              ResourceRecords: resourceRecords,
            },
          },
        ],
      },
    };

    console.log('Updating DNS with:', JSON.stringify(changeParams, null, 2));

    const result = await route53.send(new ChangeResourceRecordSetsCommand(changeParams));
    console.log('DNS update result:', result.ChangeInfo?.Status);

  } catch (error) {
    console.error('Error updating cluster DNS:', error);
    throw error;
  }
};
