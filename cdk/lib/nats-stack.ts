import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import {
  aws_ec2 as ec2,
  aws_elasticloadbalancingv2 as elbv2,
  aws_certificatemanager as acm,
  aws_route53 as route53,
  aws_route53_targets as targets,
  aws_secretsmanager as secretsmanager,
  aws_iam as iam,
  aws_autoscaling as autoscaling,
} from 'aws-cdk-lib';

export interface NatsStackProps extends cdk.StackProps {
  /**
   * The domain name for the NATS cluster endpoint (e.g., nats.vettid.dev)
   */
  domainName: string;

  /**
   * The zone name (e.g., vettid.dev)
   */
  zoneName: string;

  /**
   * The API Gateway URL for the account JWT resolver endpoint
   * Used by NATS server to fetch account JWTs dynamically
   */
  accountResolverUrl?: string;
}

/**
 * VettID NATS Stack
 *
 * Deploys a 3-node NATS cluster with JetStream for the Vault Services messaging infrastructure:
 * - Dedicated VPC with public/private subnets
 * - 3x t4g.small EC2 instances (ARM64) running NATS
 * - Network Load Balancer with ACM certificate for external TLS
 * - Self-signed certificates for internal cluster communication
 * - Secrets Manager for operator keys and internal CA
 *
 * Architecture:
 *   Clients -> NLB (TLS/ACM) -> NATS Cluster (internal TLS/self-signed)
 */
export class NatsStack extends cdk.Stack {
  /**
   * The VPC containing the NATS cluster
   */
  public readonly vpc: ec2.Vpc;

  /**
   * The Network Load Balancer endpoint for NATS clients
   */
  public readonly nlbEndpoint: string;

  /**
   * The domain name for the NATS cluster
   */
  public readonly natsDomain: string;

  /**
   * Secret containing the NATS operator signing key
   */
  public readonly operatorSecret: secretsmanager.Secret;

  /**
   * Secret containing the internal CA for cluster TLS
   */
  public readonly internalCaSecret: secretsmanager.Secret;

  /**
   * Security group for NATS instances
   */
  public readonly natsSecurityGroup: ec2.SecurityGroup;

  constructor(scope: Construct, id: string, props: NatsStackProps) {
    super(scope, id, props);

    this.natsDomain = props.domainName;

    // ===== VPC =====

    this.vpc = new ec2.Vpc(this, 'NatsVpc', {
      maxAzs: 3,
      natGateways: 1, // Single NAT for cost savings, can increase for HA
      ipAddresses: ec2.IpAddresses.cidr('10.10.0.0/16'),
      subnetConfiguration: [
        {
          name: 'Public',
          subnetType: ec2.SubnetType.PUBLIC,
          cidrMask: 24,
        },
        {
          name: 'Private',
          subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
          cidrMask: 24,
        },
      ],
      // Enable DNS support for internal resolution
      enableDnsHostnames: true,
      enableDnsSupport: true,
    });

    // ===== SECRETS =====

    // NATS Operator signing key (for JWT-based auth)
    this.operatorSecret = new secretsmanager.Secret(this, 'NatsOperatorSecret', {
      secretName: 'vettid/nats/operator-key',
      description: 'NATS operator signing key for JWT-based authentication',
      generateSecretString: {
        secretStringTemplate: JSON.stringify({
          description: 'NATS operator key - will be populated by initialization script',
        }),
        generateStringKey: 'placeholder',
      },
    });

    // Internal CA for cluster TLS
    this.internalCaSecret = new secretsmanager.Secret(this, 'NatsInternalCaSecret', {
      secretName: 'vettid/nats/internal-ca',
      description: 'Internal CA for NATS cluster TLS communication',
      generateSecretString: {
        secretStringTemplate: JSON.stringify({
          description: 'Internal CA - will be populated by initialization script',
        }),
        generateStringKey: 'placeholder',
      },
    });

    // ===== SECURITY GROUPS =====

    this.natsSecurityGroup = new ec2.SecurityGroup(this, 'NatsSecurityGroup', {
      vpc: this.vpc,
      description: 'Security group for NATS cluster nodes',
      allowAllOutbound: true,
    });

    // NATS client port (from NLB)
    this.natsSecurityGroup.addIngressRule(
      ec2.Peer.ipv4(this.vpc.vpcCidrBlock),
      ec2.Port.tcp(4222),
      'NATS client connections from VPC'
    );

    // NATS cluster routing port (node-to-node)
    this.natsSecurityGroup.addIngressRule(
      this.natsSecurityGroup,
      ec2.Port.tcp(6222),
      'NATS cluster routing between nodes'
    );

    // NATS monitoring port (internal only)
    this.natsSecurityGroup.addIngressRule(
      ec2.Peer.ipv4(this.vpc.vpcCidrBlock),
      ec2.Port.tcp(8222),
      'NATS monitoring endpoint'
    );

    // ===== ACM CERTIFICATE =====

    // Use fromLookup to automatically find and cache the hosted zone ID
    const hostedZone = route53.HostedZone.fromLookup(this, 'HostedZone', {
      domainName: props.zoneName,
    });

    const certificate = new acm.Certificate(this, 'NatsCertificate', {
      domainName: props.domainName,
      validation: acm.CertificateValidation.fromDns(hostedZone),
    });

    // ===== LAUNCH TEMPLATE =====

    // IAM role for NATS instances
    const natsRole = new iam.Role(this, 'NatsInstanceRole', {
      assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMManagedInstanceCore'),
      ],
    });

    // Grant access to secrets
    this.operatorSecret.grantRead(natsRole);
    this.internalCaSecret.grantRead(natsRole);

    // Grant permissions to discover cluster peers
    natsRole.addToPolicy(new iam.PolicyStatement({
      actions: [
        'ec2:DescribeInstances',
        'autoscaling:DescribeAutoScalingInstances',
      ],
      resources: ['*'],
    }));

    // User data script to install and configure NATS
    const userData = ec2.UserData.forLinux();
    userData.addCommands(
      '#!/bin/bash',
      'set -e',
      '',
      '# Install dependencies',
      'dnf install -y jq awscli',
      '',
      '# Create nats user',
      'useradd -r -s /sbin/nologin nats || true',
      '',
      '# Download and install NATS server',
      'NATS_VERSION="2.10.24"',
      'cd /tmp',
      'curl -L -o nats-server.tar.gz "https://github.com/nats-io/nats-server/releases/download/v${NATS_VERSION}/nats-server-v${NATS_VERSION}-linux-arm64.tar.gz"',
      'tar -xzf nats-server.tar.gz',
      'mv nats-server-v${NATS_VERSION}-linux-arm64/nats-server /usr/local/bin/',
      'chmod +x /usr/local/bin/nats-server',
      '',
      '# Create directories',
      'mkdir -p /etc/nats/certs /var/lib/nats/jetstream /var/log/nats',
      'chown -R nats:nats /var/lib/nats /var/log/nats',
      '',
      '# Get instance metadata',
      'TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")',
      'INSTANCE_ID=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)',
      'PRIVATE_IP=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4)',
      'AZ=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone)',
      '',
      '# Fetch internal CA from Secrets Manager',
      `CA_SECRET=$(aws secretsmanager get-secret-value --secret-id ${this.internalCaSecret.secretName} --region ${this.region} --query SecretString --output text)`,
      'echo "$CA_SECRET" | jq -r \'.ca_cert // empty\' > /etc/nats/certs/ca.crt',
      'echo "$CA_SECRET" | jq -r \'.ca_key // empty\' > /etc/nats/certs/ca.key',
      '',
      '# Fetch NATS operator keys from Secrets Manager for JWT authentication',
      `OPERATOR_SECRET=$(aws secretsmanager get-secret-value --secret-id ${this.operatorSecret.secretName} --region ${this.region} --query SecretString --output text)`,
      'OPERATOR_JWT=$(echo "$OPERATOR_SECRET" | jq -r \'.operator_jwt // empty\')',
      'SYSTEM_ACCOUNT_PUBLIC_KEY=$(echo "$OPERATOR_SECRET" | jq -r \'.system_account_public_key // empty\')',
      '',
      '# Save operator JWT to file (NATS expects file path or inline JWT)',
      'echo "$OPERATOR_JWT" > /etc/nats/operator.jwt',
      'chmod 644 /etc/nats/operator.jwt',
      'chown nats:nats /etc/nats/operator.jwt',
      '',
      '# Generate node certificate signed by internal CA (if CA exists)',
      'if [ -s /etc/nats/certs/ca.crt ]; then',
      '  # Generate node key',
      '  openssl genrsa -out /etc/nats/certs/node.key 2048',
      '  ',
      '  # Generate CSR',
      '  openssl req -new -key /etc/nats/certs/node.key -out /etc/nats/certs/node.csr \\',
      '    -subj "/CN=nats-${INSTANCE_ID}/O=VettID"',
      '  ',
      '  # Sign with CA',
      '  openssl x509 -req -in /etc/nats/certs/node.csr \\',
      '    -CA /etc/nats/certs/ca.crt -CAkey /etc/nats/certs/ca.key \\',
      '    -CAcreateserial -out /etc/nats/certs/node.crt -days 365 \\',
      '    -extfile <(printf "subjectAltName=IP:${PRIVATE_IP},DNS:nats-${INSTANCE_ID}")',
      '  ',
      '  rm /etc/nats/certs/ca.key /etc/nats/certs/node.csr',
      '  TLS_CONFIG="tls { cert_file: /etc/nats/certs/node.crt; key_file: /etc/nats/certs/node.key; ca_file: /etc/nats/certs/ca.crt; verify: true }"',
      '  CLUSTER_TLS_CONFIG="tls { cert_file: /etc/nats/certs/node.crt; key_file: /etc/nats/certs/node.key; ca_file: /etc/nats/certs/ca.crt; verify: true }"',
      'else',
      '  TLS_CONFIG=""',
      '  CLUSTER_TLS_CONFIG=""',
      '  echo "WARNING: Internal CA not found, running without TLS"',
      'fi',
      '',
      '# Set permissions',
      'chmod 600 /etc/nats/certs/*.key 2>/dev/null || true',
      'chmod 644 /etc/nats/certs/*.crt 2>/dev/null || true',
      'chown -R nats:nats /etc/nats',
      '',
      '# Discover cluster peers via ASG',
      'REGION=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)',
      '',
      '# Find ASG name',
      'ASG_NAME=$(aws autoscaling describe-auto-scaling-instances --instance-ids $INSTANCE_ID --region $REGION --query "AutoScalingInstances[0].AutoScalingGroupName" --output text)',
      '',
      '# Get all peer IPs (excluding self)',
      'PEER_IPS=$(aws ec2 describe-instances \\',
      '  --filters "Name=tag:aws:autoscaling:groupName,Values=$ASG_NAME" "Name=instance-state-name,Values=running" \\',
      '  --region $REGION \\',
      '  --query "Reservations[*].Instances[?PrivateIpAddress!=\\`$PRIVATE_IP\\`].PrivateIpAddress" \\',
      '  --output text)',
      '',
      '# Build routes array',
      'ROUTES=""',
      'for IP in $PEER_IPS; do',
      '  if [ -n "$IP" ]; then',
      '    ROUTES="${ROUTES}    nats-route://${IP}:6222\\n"',
      '  fi',
      'done',
      '',
      '# Create NATS configuration',
      'cat > /etc/nats/nats.conf << EOF',
      '# NATS Server Configuration',
      'server_name: nats-${INSTANCE_ID}',
      '',
      '# Client connections',
      'port: 4222',
      'host: 0.0.0.0',
      '',
      '# Monitoring',
      'http_port: 8222',
      '',
      '# JWT Authentication (operator mode)',
      'operator: /etc/nats/operator.jwt',
      'system_account: ${SYSTEM_ACCOUNT_PUBLIC_KEY}',
      '',
      '# Account resolver - fetch account JWTs from API Gateway',
      `resolver: URL("${props.accountResolverUrl || 'https://tiqpij5mue.execute-api.us-east-1.amazonaws.com'}/nats/jwt/v1/accounts/")`,
      '',
      '# JetStream',
      'jetstream {',
      '  store_dir: /var/lib/nats/jetstream',
      '  max_mem: 256MB',
      '  max_file: 1GB',
      '}',
      '',
      '# Cluster configuration',
      'cluster {',
      '  name: vettid-nats',
      '  port: 6222',
      '  listen: 0.0.0.0:6222',
      '  ${CLUSTER_TLS_CONFIG}',
      '',
      '  routes: [',
      '$(echo -e "$ROUTES")  ]',
      '}',
      '',
      '# Logging',
      'logfile: /var/log/nats/nats.log',
      'logfile_size_limit: 100MB',
      'debug: false',
      'trace: false',
      'EOF',
      '',
      '# Create systemd service',
      'cat > /etc/systemd/system/nats.service << EOF',
      '[Unit]',
      'Description=NATS Server',
      'After=network.target',
      '',
      '[Service]',
      'Type=simple',
      'User=nats',
      'Group=nats',
      'ExecStart=/usr/local/bin/nats-server -c /etc/nats/nats.conf',
      'ExecReload=/bin/kill -HUP \\$MAINPID',
      'Restart=always',
      'RestartSec=5',
      'LimitNOFILE=65536',
      '',
      '[Install]',
      'WantedBy=multi-user.target',
      'EOF',
      '',
      '# Enable and start NATS',
      'systemctl daemon-reload',
      'systemctl enable nats',
      'systemctl start nats',
      '',
      'echo "NATS server installation complete"'
    );

    const launchTemplate = new ec2.LaunchTemplate(this, 'NatsLaunchTemplate', {
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T4G, ec2.InstanceSize.SMALL),
      machineImage: ec2.MachineImage.latestAmazonLinux2023({
        cpuType: ec2.AmazonLinuxCpuType.ARM_64,
      }),
      role: natsRole,
      securityGroup: this.natsSecurityGroup,
      userData,
      blockDevices: [
        {
          deviceName: '/dev/xvda',
          volume: ec2.BlockDeviceVolume.ebs(20, {
            volumeType: ec2.EbsDeviceVolumeType.GP3,
            encrypted: true,
          }),
        },
      ],
    });

    // ===== AUTO SCALING GROUP =====

    const asg = new autoscaling.AutoScalingGroup(this, 'NatsAsg', {
      vpc: this.vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      launchTemplate,
      minCapacity: 3,
      maxCapacity: 3,
      desiredCapacity: 3,
      healthCheck: autoscaling.HealthCheck.elb({
        grace: cdk.Duration.minutes(5),
      }),
      updatePolicy: autoscaling.UpdatePolicy.rollingUpdate({
        maxBatchSize: 1,
        minInstancesInService: 2,
        pauseTime: cdk.Duration.minutes(5),
      }),
    });

    // Tag instances for identification
    cdk.Tags.of(asg).add('vettid:component', 'nats-cluster');
    cdk.Tags.of(asg).add('Name', 'VettID-NATS');

    // ===== NETWORK LOAD BALANCER =====

    const nlb = new elbv2.NetworkLoadBalancer(this, 'NatsNlb', {
      vpc: this.vpc,
      internetFacing: true,
      crossZoneEnabled: true,
    });

    // TLS listener with ACM certificate
    const listener = nlb.addListener('NatsListener', {
      port: 4222,
      protocol: elbv2.Protocol.TLS,
      certificates: [certificate],
      sslPolicy: elbv2.SslPolicy.TLS12,
    });

    // Target group for NATS instances
    const targetGroup = new elbv2.NetworkTargetGroup(this, 'NatsTargetGroup', {
      vpc: this.vpc,
      port: 4222,
      protocol: elbv2.Protocol.TCP,
      targetType: elbv2.TargetType.INSTANCE,
      healthCheck: {
        enabled: true,
        port: '8222',
        protocol: elbv2.Protocol.HTTP,
        path: '/healthz',
        healthyThresholdCount: 2,
        unhealthyThresholdCount: 2,
        interval: cdk.Duration.seconds(10),
      },
    });

    listener.addTargetGroups('NatsTargets', targetGroup);
    asg.attachToNetworkTargetGroup(targetGroup);

    // Allow NLB to reach NATS instances
    this.natsSecurityGroup.addIngressRule(
      ec2.Peer.anyIpv4(),
      ec2.Port.tcp(4222),
      'NATS client connections from NLB'
    );

    // ===== DNS RECORD =====

    new route53.ARecord(this, 'NatsDnsRecord', {
      zone: hostedZone,
      recordName: props.domainName,
      target: route53.RecordTarget.fromAlias(new targets.LoadBalancerTarget(nlb)),
    });

    this.nlbEndpoint = nlb.loadBalancerDnsName;

    // ===== OUTPUTS =====

    new cdk.CfnOutput(this, 'NatsEndpoint', {
      value: `nats://${props.domainName}:4222`,
      description: 'NATS cluster endpoint (TLS)',
    });

    new cdk.CfnOutput(this, 'NatsVpcId', {
      value: this.vpc.vpcId,
      description: 'VPC ID for NATS cluster',
    });

    new cdk.CfnOutput(this, 'NatsOperatorSecretArn', {
      value: this.operatorSecret.secretArn,
      description: 'ARN of the NATS operator signing key secret',
    });

    new cdk.CfnOutput(this, 'NatsInternalCaSecretArn', {
      value: this.internalCaSecret.secretArn,
      description: 'ARN of the internal CA secret for cluster TLS',
    });
  }
}
