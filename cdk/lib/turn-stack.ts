import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as route53 from 'aws-cdk-lib/aws-route53';
import * as logs from 'aws-cdk-lib/aws-logs';
import { Construct } from 'constructs';
import * as fs from 'fs';
import * as path from 'path';

export interface TurnStackProps extends cdk.StackProps {
  /** DNS name where clients reach the TURN server (e.g. `turn.vettid.dev`). */
  readonly hostname: string;
  /** Parent zone in Route53 (e.g. `vettid.dev`). */
  readonly zoneName: string;
}

/**
 * VettID TURN relay infrastructure.
 *
 * - Single EC2 instance running coturn in HMAC-auth mode
 * - Elastic IP + Route53 record so clients can connect to a stable hostname
 * - TURNS on 5349 and 443 (TLS, public-cert via Let's Encrypt)
 * - Plain TURN on 3478 (UDP+TCP) for STUN / fallback
 * - HMAC shared secret in Secrets Manager; enclave parent generates
 *   short-lived credentials locally (no API round-trip)
 *
 * Privacy-first: clients are configured to force relay-only, so peer IPs
 * never cross the wire. The server never sees any plaintext media — media is
 * DTLS-SRTP + our own frame-level E2EE on top.
 */
export class TurnStack extends cdk.Stack {
  /** Shared HMAC secret — parent reads this to mint credentials. */
  public readonly sharedSecret: secretsmanager.Secret;
  public readonly hostname: string;

  constructor(scope: Construct, id: string, props: TurnStackProps) {
    super(scope, id, props);

    this.hostname = props.hostname;

    // -------------------------------------------------------------------- //
    // Shared HMAC secret. Enclave parent reads this to generate per-call
    // credentials. Clients never see it.
    // -------------------------------------------------------------------- //
    this.sharedSecret = new secretsmanager.Secret(this, 'TurnSharedSecret', {
      secretName: 'vettid/turn-shared-secret',
      description: 'HMAC secret for VettID coturn long-term-credential auth',
      generateSecretString: {
        passwordLength: 64,
        excludePunctuation: true,
        excludeCharacters: '"\\\'`',
      },
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // -------------------------------------------------------------------- //
    // Dedicated VPC — keep the TURN relay isolated from the vault VPC so a
    // compromise of the public-facing coturn can't reach enclave/NATS infra.
    // Single AZ, single public subnet — we're running one instance.
    // -------------------------------------------------------------------- //
    const vpc = new ec2.Vpc(this, 'TurnVpc', {
      ipAddresses: ec2.IpAddresses.cidr('10.60.0.0/16'),
      maxAzs: 1,
      natGateways: 0,
      subnetConfiguration: [
        { name: 'public', subnetType: ec2.SubnetType.PUBLIC, cidrMask: 24 },
      ],
    });

    // -------------------------------------------------------------------- //
    // Security group — open the TURN/TURNS ports plus :80 for Let's Encrypt
    // HTTP-01 and :443 for TURNS fallback. Outbound all (needed for cert
    // renewal + Cloudflare-style reachability checks).
    // -------------------------------------------------------------------- //
    const sg = new ec2.SecurityGroup(this, 'TurnSg', {
      vpc,
      description: 'VettID TURN relay — STUN/TURN/TURNS',
      allowAllOutbound: true,
    });
    sg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.udp(3478), 'TURN/UDP');
    sg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(3478), 'TURN/TCP');
    sg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(5349), 'TURNS/TCP');
    sg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(443),  'TURNS/TCP (alt, for restrictive nets)');
    sg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(80),   'Let\'s Encrypt HTTP-01');
    // Relay allocation range — coturn picks a UDP port here per allocation.
    sg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.udpRange(49152, 65535), 'TURN relay range');

    // -------------------------------------------------------------------- //
    // IAM role. Read-only on the shared secret, plus CloudWatch logs.
    // -------------------------------------------------------------------- //
    const role = new iam.Role(this, 'TurnInstanceRole', {
      assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
      description: 'VettID TURN instance — Secrets Manager read + CloudWatch',
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMManagedInstanceCore'),
        iam.ManagedPolicy.fromAwsManagedPolicyName('CloudWatchAgentServerPolicy'),
      ],
    });
    this.sharedSecret.grantRead(role);

    // -------------------------------------------------------------------- //
    // Log group for coturn output. 30 days retention is enough for incident
    // review without piling up PII.
    // -------------------------------------------------------------------- //
    new logs.LogGroup(this, 'TurnLogs', {
      logGroupName: 'vettid-turn',
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // -------------------------------------------------------------------- //
    // User-data: read bootstrap.sh, substitute placeholders, run on boot.
    // __dirname resolves under dist/ after tsc, so walk back to the source
    // tree (cdk/lib/turn/bootstrap.sh) — the file isn't copied to dist.
    // -------------------------------------------------------------------- //
    const bootstrapPath = [
      path.join(__dirname, 'turn', 'bootstrap.sh'),                         // if run from source
      path.join(__dirname, '..', '..', 'lib', 'turn', 'bootstrap.sh'),      // if run from dist/lib
    ].find((p) => fs.existsSync(p));
    if (!bootstrapPath) {
      throw new Error('Could not locate cdk/lib/turn/bootstrap.sh');
    }
    const bootstrapTemplate = fs.readFileSync(bootstrapPath, 'utf-8');
    const bootstrap = bootstrapTemplate
      .replace('__REALM__', this.hostname)
      .replace('__SECRET_ARN__', this.sharedSecret.secretArn)
      .replace('__REGION__', this.region);
    const userData = ec2.UserData.forLinux();
    userData.addCommands(bootstrap);

    // -------------------------------------------------------------------- //
    // Instance — Amazon Linux 2023, t3.micro for 1:1 voice-only scale.
    // -------------------------------------------------------------------- //
    const instance = new ec2.Instance(this, 'TurnInstance', {
      vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PUBLIC },
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
      machineImage: ec2.MachineImage.latestAmazonLinux2023(),
      securityGroup: sg,
      role,
      userData,
      userDataCausesReplacement: true,
      blockDevices: [{
        deviceName: '/dev/xvda',
        volume: ec2.BlockDeviceVolume.ebs(8, {
          volumeType: ec2.EbsDeviceVolumeType.GP3,
          encrypted: true,
        }),
      }],
    });

    // Tag so we can find the instance from scripts quickly.
    cdk.Tags.of(instance).add('VettidComponent', 'turn');

    // -------------------------------------------------------------------- //
    // Elastic IP. Must be stable across restarts — Let's Encrypt validation
    // points at the hostname's DNS A record, which points at this EIP.
    // -------------------------------------------------------------------- //
    const eip = new ec2.CfnEIP(this, 'TurnEip', {
      domain: 'vpc',
      tags: [{ key: 'Name', value: 'vettid-turn' }],
    });
    new ec2.CfnEIPAssociation(this, 'TurnEipAssoc', {
      eip: eip.ref,
      instanceId: instance.instanceId,
    });

    // -------------------------------------------------------------------- //
    // Route53 A record. The hosted zone already exists for vettid.dev.
    // -------------------------------------------------------------------- //
    const hostedZone = route53.HostedZone.fromLookup(this, 'HostedZone', {
      domainName: props.zoneName,
    });
    new route53.ARecord(this, 'TurnDnsRecord', {
      zone: hostedZone,
      recordName: this.hostname,
      target: route53.RecordTarget.fromIpAddresses(eip.ref),
      ttl: cdk.Duration.minutes(5),
      comment: 'VettID TURN relay',
    });

    // -------------------------------------------------------------------- //
    // Exports — consumed by NitroStack so the parent IAM role gets read
    // access on the same secret.
    // -------------------------------------------------------------------- //
    new cdk.CfnOutput(this, 'TurnHostname', {
      value: this.hostname,
      description: 'TURN server public hostname',
    });
    new cdk.CfnOutput(this, 'TurnSharedSecretArn', {
      value: this.sharedSecret.secretArn,
      description: 'ARN of the HMAC shared secret for TURN credential generation',
    });
    new cdk.CfnOutput(this, 'TurnPublicIp', {
      value: eip.ref,
      description: 'Elastic IP of the TURN instance',
    });
  }
}
