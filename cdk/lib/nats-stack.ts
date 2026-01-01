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
  aws_lambda as lambda,
  aws_lambda_nodejs as nodejs,
  aws_events as events,
  aws_events_targets as eventTargets,
} from 'aws-cdk-lib';
import * as path from 'path';

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

  /**
   * Optional VPC from Vault infrastructure to peer with.
   * When provided, creates VPC peering to allow vault instances to connect to NATS.
   */
  vaultVpc?: ec2.IVpc;

  /**
   * CIDR block of the Vault VPC for security group rules.
   * Required when vaultVpc is provided.
   */
  vaultVpcCidr?: string;
}

/**
 * VettID NATS Stack
 *
 * Deploys a 3-node NATS cluster with JetStream for the Vault Services messaging infrastructure:
 * - Dedicated VPC with public/private subnets
 * - 3x t4g.micro EC2 instances (ARM64) running NATS
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

  /**
   * Private hosted zone for internal cluster discovery
   */
  public readonly privateHostedZone: route53.PrivateHostedZone;

  /**
   * Internal DNS name for cluster routing (e.g., cluster.internal.vettid.dev)
   */
  public readonly clusterDnsName: string;

  /**
   * Internal NLB endpoint for vault-to-NATS communication (via VPC peering)
   * Uses plain TCP - no TLS needed for internal traffic
   */
  public readonly internalNlbEndpoint: string;

  /**
   * Internal NATS domain name (e.g., nats.internal.vettid.dev)
   */
  public readonly internalNatsDomain: string;

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

    // ===== PRIVATE HOSTED ZONE FOR CLUSTER DISCOVERY =====

    // Create private hosted zone for internal cluster DNS
    this.privateHostedZone = new route53.PrivateHostedZone(this, 'NatsPrivateZone', {
      zoneName: `internal.${props.zoneName}`,
      vpc: this.vpc,
      comment: 'Private zone for NATS cluster internal discovery',
    });

    this.clusterDnsName = `cluster.internal.${props.zoneName}`;

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

    // ===== VPC PEERING WITH VAULT VPC =====
    // This allows vault EC2 instances to connect to the NATS cluster

    if (props.vaultVpc && props.vaultVpcCidr) {
      // Create VPC peering connection
      const peeringConnection = new ec2.CfnVPCPeeringConnection(this, 'VaultNatsPeering', {
        vpcId: this.vpc.vpcId,
        peerVpcId: props.vaultVpc.vpcId,
        tags: [
          { key: 'Name', value: 'VettID-Vault-NATS-Peering' },
          { key: 'Purpose', value: 'Allow vault instances to connect to NATS cluster' },
        ],
      });

      // Add routes in NATS VPC to reach Vault VPC
      // Routes need to be added to all route tables (public and private subnets)
      this.vpc.privateSubnets.forEach((subnet, index) => {
        new ec2.CfnRoute(this, `NatsToVaultRoutePrivate${index}`, {
          routeTableId: subnet.routeTable.routeTableId,
          destinationCidrBlock: props.vaultVpcCidr,
          vpcPeeringConnectionId: peeringConnection.ref,
        });
      });

      this.vpc.publicSubnets.forEach((subnet, index) => {
        new ec2.CfnRoute(this, `NatsToVaultRoutePublic${index}`, {
          routeTableId: subnet.routeTable.routeTableId,
          destinationCidrBlock: props.vaultVpcCidr,
          vpcPeeringConnectionId: peeringConnection.ref,
        });
      });

      // Add routes in Vault VPC to reach NATS VPC
      // Need to add to all subnets in the Vault VPC
      props.vaultVpc.privateSubnets.forEach((subnet, index) => {
        new ec2.CfnRoute(this, `VaultToNatsRoutePrivate${index}`, {
          routeTableId: subnet.routeTable.routeTableId,
          destinationCidrBlock: this.vpc.vpcCidrBlock,
          vpcPeeringConnectionId: peeringConnection.ref,
        });
      });

      props.vaultVpc.publicSubnets.forEach((subnet, index) => {
        new ec2.CfnRoute(this, `VaultToNatsRoutePublic${index}`, {
          routeTableId: subnet.routeTable.routeTableId,
          destinationCidrBlock: this.vpc.vpcCidrBlock,
          vpcPeeringConnectionId: peeringConnection.ref,
        });
      });

      // Allow NATS connections from Vault VPC CIDR
      this.natsSecurityGroup.addIngressRule(
        ec2.Peer.ipv4(props.vaultVpcCidr),
        ec2.Port.tcp(4222),
        'NATS client connections from Vault VPC'
      );

      // Associate the private hosted zone with Vault VPC
      // This allows vault instances to resolve cluster.internal.vettid.dev
      this.privateHostedZone.addVpc(props.vaultVpc);

      // Output peering connection ID for reference
      new cdk.CfnOutput(this, 'VpcPeeringConnectionId', {
        value: peeringConnection.ref,
        description: 'VPC peering connection ID between Vault and NATS VPCs',
      });
    }

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
    this.internalCaSecret.grantWrite(natsRole); // Allow first instance to generate and store CA

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
      'mkdir -p /etc/nats/certs /var/lib/nats/jetstream /var/lib/nats/resolver /var/log/nats',
      'chown -R nats:nats /var/lib/nats /var/log/nats',
      '',
      '# Get instance metadata',
      'TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")',
      'INSTANCE_ID=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)',
      'PRIVATE_IP=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4)',
      'AZ=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone)',
      '',
      '# Fetch internal CA from Secrets Manager (or generate if not exists)',
      `CA_SECRET=$(aws secretsmanager get-secret-value --secret-id ${this.internalCaSecret.secretName} --region ${this.region} --query SecretString --output text)`,
      'CA_CERT=$(echo "$CA_SECRET" | jq -r \'.ca_cert // empty\')',
      '',
      '# If CA doesn\'t exist, generate it and store in Secrets Manager',
      'if [ -z "$CA_CERT" ] || [ "$CA_CERT" = "null" ]; then',
      '  echo "Generating new internal CA..."',
      '  ',
      '  # Generate CA private key',
      '  openssl genrsa -out /tmp/ca.key 4096',
      '  ',
      '  # Generate CA certificate (10 year validity)',
      '  openssl req -new -x509 -days 3650 -key /tmp/ca.key -out /tmp/ca.crt \\',
      '    -subj "/CN=VettID NATS Internal CA/O=VettID/C=US"',
      '  ',
      '  # Store in Secrets Manager',
      '  # Create JSON with proper escaping for multi-line PEM content',
      '  jq -n --rawfile cert /tmp/ca.crt --rawfile key /tmp/ca.key \\',
      '    \'{ca_cert: $cert, ca_key: $key}\' > /tmp/ca_secret.json',
      '  aws secretsmanager put-secret-value \\',
      `    --secret-id ${this.internalCaSecret.secretName} \\`,
      `    --region ${this.region} \\`,
      '    --secret-string file:///tmp/ca_secret.json',
      '  rm /tmp/ca_secret.json',
      '  ',
      '  echo "Internal CA generated and stored in Secrets Manager"',
      '  mv /tmp/ca.crt /etc/nats/certs/ca.crt',
      '  mv /tmp/ca.key /etc/nats/certs/ca.key',
      'else',
      '  echo "$CA_CERT" > /etc/nats/certs/ca.crt',
      '  echo "$CA_SECRET" | jq -r \'.ca_key // empty\' > /etc/nats/certs/ca.key',
      'fi',
      '',
      '# Fetch NATS operator keys from Secrets Manager for JWT authentication',
      `OPERATOR_SECRET=$(aws secretsmanager get-secret-value --secret-id ${this.operatorSecret.secretName} --region ${this.region} --query SecretString --output text)`,
      'OPERATOR_JWT=$(echo "$OPERATOR_SECRET" | jq -r \'.operator_jwt // empty\')',
      'SYSTEM_ACCOUNT_PUBLIC_KEY=$(echo "$OPERATOR_SECRET" | jq -r \'.system_account_public_key // empty\')',
      'SYSTEM_ACCOUNT_JWT=$(echo "$OPERATOR_SECRET" | jq -r \'.system_account_jwt // empty\')',
      '',
      '# Account resolver URL (for fetching member account JWTs)',
      `ACCOUNT_RESOLVER_URL="${props.accountResolverUrl || ''}"`,
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
      '  # Sign with CA (include nats.vettid.dev for client TLS)',
      '  openssl x509 -req -in /etc/nats/certs/node.csr \\',
      '    -CA /etc/nats/certs/ca.crt -CAkey /etc/nats/certs/ca.key \\',
      '    -CAcreateserial -out /etc/nats/certs/node.crt -days 365 \\',
      `    -extfile <(printf "subjectAltName=IP:\${PRIVATE_IP},DNS:nats-\${INSTANCE_ID},DNS:nats.vettid.dev,DNS:${this.clusterDnsName}")`,
      '  ',
      '  rm /etc/nats/certs/ca.key /etc/nats/certs/node.csr',
      '  # Client TLS: NOT needed - NLB terminates TLS with ACM certificate',
      '  # Cluster TLS - mutual TLS between NATS nodes (internal CA)',
      '  CLUSTER_TLS_CONFIG="tls { cert_file: /etc/nats/certs/node.crt; key_file: /etc/nats/certs/node.key; ca_file: /etc/nats/certs/ca.crt; verify: true }"',
      'else',
      '  CLUSTER_TLS_CONFIG=""',
      '  echo "WARNING: Internal CA not found, cluster routing will not use TLS"',
      'fi',
      '',
      '# Set permissions',
      'chmod 600 /etc/nats/certs/*.key 2>/dev/null || true',
      'chmod 644 /etc/nats/certs/*.crt 2>/dev/null || true',
      'chown -R nats:nats /etc/nats',
      '',
      '# DNS-based cluster discovery - uses Route 53 private hosted zone',
      '# The Lambda updates DNS records when instances launch/terminate',
      `CLUSTER_DNS="${this.clusterDnsName}"`,
      '',
      '# Create NATS configuration',
      'cat > /etc/nats/nats.conf << EOF',
      '# NATS Server Configuration',
      'server_name: nats-${INSTANCE_ID}',
      '',
      '# Client connections (plain TCP - NLB terminates TLS with ACM certificate)',
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
      '# Account resolver - URL resolver fetches from HTTP endpoint',
      '# System account is pre-seeded in resolver dir before NATS starts',
      'resolver: URL(${ACCOUNT_RESOLVER_URL})',
      '',
      '# Pre-seed system account for JetStream cluster (before NATS starts)',
      '# System account JWT file is written by cloud-init before this config is used',
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
      '  # DNS-based route discovery - resolves to all cluster node IPs',
      '  routes: [',
      '    nats-route://${CLUSTER_DNS}:6222',
      '  ]',
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
      '# Pre-fetch system account JWT before starting NATS',
      '# This ensures JetStream cluster can form on first boot',
      'echo "Pre-fetching system account JWT..."',
      'PREFETCH_URL="${ACCOUNT_RESOLVER_URL}${SYSTEM_ACCOUNT_PUBLIC_KEY}"',
      'PREFETCH_RESULT=$(curl -sf "$PREFETCH_URL" 2>/dev/null || echo "")',
      'if [ -n "$PREFETCH_RESULT" ]; then',
      '  echo "System account JWT fetched successfully"',
      'else',
      '  echo "Warning: Could not pre-fetch system account JWT from $PREFETCH_URL"',
      'fi',
      '',
      '# Enable and start NATS',
      'systemctl daemon-reload',
      'systemctl enable nats',
      'systemctl start nats',
      '',
      '# Wait for NATS to be ready',
      'echo "Waiting for NATS to start..."',
      'for i in {1..30}; do',
      '  if curl -sf http://127.0.0.1:8222/healthz > /dev/null 2>&1; then',
      '    echo "NATS is ready"',
      '    break',
      '  fi',
      '  sleep 1',
      'done',
      '',
      '# Download NATS CLI for administration',
      'curl -L -o /tmp/nats-cli.tar.gz "https://github.com/nats-io/natscli/releases/download/v0.1.5/nats-0.1.5-linux-arm64.tar.gz"',
      'tar -xzf /tmp/nats-cli.tar.gz -C /tmp',
      'mv /tmp/nats-0.1.5-linux-arm64/nats /usr/local/bin/',
      'chmod +x /usr/local/bin/nats',
      '',
      'echo "NATS server installation complete"'
    );

    const launchTemplate = new ec2.LaunchTemplate(this, 'NatsLaunchTemplate', {
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T4G, ec2.InstanceSize.MICRO),
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

    // ===== DNS UPDATE LAMBDA =====

    // Lambda to update cluster DNS when instances change
    const dnsUpdateLambda = new nodejs.NodejsFunction(this, 'ClusterDnsUpdateFn', {
      entry: 'lambda/handlers/nats/updateClusterDns.ts',
      handler: 'handler',
      runtime: lambda.Runtime.NODEJS_22_X,
      architecture: lambda.Architecture.ARM_64,
      timeout: cdk.Duration.seconds(30),
      environment: {
        HOSTED_ZONE_ID: this.privateHostedZone.hostedZoneId,
        CLUSTER_DNS_NAME: this.clusterDnsName,
        ASG_NAME: asg.autoScalingGroupName,
      },
    });

    // Grant Lambda permissions to update Route 53
    dnsUpdateLambda.addToRolePolicy(new iam.PolicyStatement({
      actions: ['route53:ChangeResourceRecordSets'],
      resources: [this.privateHostedZone.hostedZoneArn],
    }));

    // Grant Lambda permissions to describe ASG and EC2 instances
    dnsUpdateLambda.addToRolePolicy(new iam.PolicyStatement({
      actions: [
        'autoscaling:DescribeAutoScalingGroups',
        'ec2:DescribeInstances',
      ],
      resources: ['*'],
    }));

    // EventBridge rule to trigger on ASG lifecycle events
    const asgEventRule = new events.Rule(this, 'NatsAsgEventRule', {
      eventPattern: {
        source: ['aws.autoscaling'],
        detailType: [
          'EC2 Instance Launch Successful',
          'EC2 Instance Terminate Successful',
        ],
        detail: {
          AutoScalingGroupName: [asg.autoScalingGroupName],
        },
      },
    });

    asgEventRule.addTarget(new eventTargets.LambdaFunction(dnsUpdateLambda));

    // Also trigger on EC2 state changes (backup mechanism)
    const ec2EventRule = new events.Rule(this, 'NatsEc2EventRule', {
      eventPattern: {
        source: ['aws.ec2'],
        detailType: ['EC2 Instance State-change Notification'],
        detail: {
          state: ['running', 'terminated'],
        },
      },
    });

    ec2EventRule.addTarget(new eventTargets.LambdaFunction(dnsUpdateLambda));

    // ===== NETWORK LOAD BALANCER =====

    const nlb = new elbv2.NetworkLoadBalancer(this, 'NatsNlb', {
      vpc: this.vpc,
      internetFacing: true,
      crossZoneEnabled: true,
    });

    // TLS termination at NLB with ACM certificate (publicly trusted)
    // NLB → NATS uses plain TCP within VPC (protected by network isolation)
    // Application-layer encryption handles sensitive message content
    const listener = nlb.addListener('NatsListener', {
      port: 4222,
      protocol: elbv2.Protocol.TLS,
      certificates: [certificate],
      // Use TLS 1.2+ for security
      sslPolicy: elbv2.SslPolicy.TLS12,
    });

    // Target group for NATS instances (plain TCP, no TLS)
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

    // ===== INTERNAL NETWORK LOAD BALANCER (for vault-to-NATS via VPC peering) =====

    // Internal NLB for vault instances to connect via VPC peering
    // Uses plain TCP - no TLS needed for internal traffic within VPC peering
    const internalNlb = new elbv2.NetworkLoadBalancer(this, 'NatsInternalNlb', {
      vpc: this.vpc,
      internetFacing: false, // Internal only
      crossZoneEnabled: true,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    });

    // Plain TCP listener for internal traffic (no TLS termination needed)
    const internalListener = internalNlb.addListener('NatsInternalListener', {
      port: 4222,
      protocol: elbv2.Protocol.TCP,
    });

    // Internal target group (same NATS instances, plain TCP)
    const internalTargetGroup = new elbv2.NetworkTargetGroup(this, 'NatsInternalTargetGroup', {
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

    internalListener.addTargetGroups('NatsInternalTargets', internalTargetGroup);
    asg.attachToNetworkTargetGroup(internalTargetGroup);

    // Store internal NLB endpoint
    this.internalNlbEndpoint = internalNlb.loadBalancerDnsName;
    this.internalNatsDomain = `nats.internal.${props.zoneName}`;

    // Add DNS record in private hosted zone for internal NATS access
    new route53.ARecord(this, 'NatsInternalDnsRecord', {
      zone: this.privateHostedZone,
      recordName: 'nats', // nats.internal.vettid.dev
      target: route53.RecordTarget.fromAlias(new targets.LoadBalancerTarget(internalNlb)),
    });

    // ===== DNS RECORD =====

    new route53.ARecord(this, 'NatsDnsRecord', {
      zone: hostedZone,
      recordName: props.domainName,
      target: route53.RecordTarget.fromAlias(new targets.LoadBalancerTarget(nlb)),
    });

    this.nlbEndpoint = nlb.loadBalancerDnsName;

    // ===== OUTPUTS =====

    new cdk.CfnOutput(this, 'NatsEndpoint', {
      value: `tls://${props.domainName}:4222`,
      description: 'NATS cluster endpoint (TLS terminated at NLB with ACM certificate)',
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

    new cdk.CfnOutput(this, 'NatsClusterDnsName', {
      value: this.clusterDnsName,
      description: 'Internal DNS name for cluster routing (private zone)',
    });

    new cdk.CfnOutput(this, 'NatsPrivateZoneId', {
      value: this.privateHostedZone.hostedZoneId,
      description: 'Route 53 private hosted zone ID for internal discovery',
    });

    new cdk.CfnOutput(this, 'NatsInternalEndpoint', {
      value: `nats://${this.internalNatsDomain}:4222`,
      description: 'Internal NATS endpoint for vault-to-NATS communication (plain TCP via VPC peering)',
      exportName: 'NatsInternalEndpoint',
    });

    new cdk.CfnOutput(this, 'NatsInternalNlbDns', {
      value: this.internalNlbEndpoint,
      description: 'Internal NLB DNS name for NATS',
    });
  }
}
