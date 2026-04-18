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
  /**
   * DNS names for the TURN relay instances. One EC2 + EIP + Route53 A
   * record + CAA record + Lets Encrypt cert is provisioned per hostname.
   * We deploy at least two so that same-server-relay is never the only
   * option during a call: when two peers both end up on mobile networks
   * with symmetric NAT, relay-to-relay is the only workable ICE pair,
   * and libwebrtc's CREATE_PERMISSION sends peer_addr=0.0.0.0 (which
   * coturn rejects with 403) when both peers terminate on the same
   * coturn. Using multiple servers lets the cross-server relay pair
   * succeed without any coturn patches.
   */
  readonly hostnames: string[];
  /** Parent zone in Route53 (e.g. `vettid.dev`). */
  readonly zoneName: string;
}

/**
 * VettID TURN relay infrastructure.
 *
 * - Multiple EC2 instances running coturn in HMAC-auth mode, one per hostname
 * - Elastic IP + Route53 A record per instance so clients can connect to a
 *   stable hostname
 * - TURNS on 5349 (TLS) and 443 (TLS via iptables redirect) per instance
 * - Plain TURN on 3478 (UDP+TCP) for STUN / fallback
 * - All instances share a single HMAC secret, so credentials minted by the
 *   enclave parent are valid on any of them
 *
 * Privacy-first: clients gather srflx (public-IP) and relay candidates only
 * (no LAN host leak), and media is DTLS-SRTP + our own frame-level E2EE on
 * top — the TURN server never sees plaintext media.
 */
export class TurnStack extends cdk.Stack {
  /** Shared HMAC secret — parent reads this to mint credentials. */
  public readonly sharedSecret: secretsmanager.Secret;
  public readonly hostnames: string[];

  constructor(scope: Construct, id: string, props: TurnStackProps) {
    super(scope, id, props);

    if (props.hostnames.length < 1) {
      throw new Error('TurnStack: at least one hostname required');
    }
    this.hostnames = props.hostnames;

    // -------------------------------------------------------------------- //
    // Shared HMAC secret. Enclave parent reads this to generate per-call
    // credentials. All TURN instances trust the same secret, so creds are
    // portable across them. Clients never see it.
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
    // Two AZs so we can spread instances for fault isolation (mobile carrier
    // routing differs between AZs too, which helps path diversity).
    // -------------------------------------------------------------------- //
    const vpc = new ec2.Vpc(this, 'TurnVpc', {
      ipAddresses: ec2.IpAddresses.cidr('10.60.0.0/16'),
      maxAzs: 2,
      natGateways: 0,
      subnetConfiguration: [
        { name: 'public', subnetType: ec2.SubnetType.PUBLIC, cidrMask: 24 },
      ],
    });

    // -------------------------------------------------------------------- //
    // Security group — open the TURN/TURNS ports plus :80 for Lets Encrypt
    // HTTP-01 and :443 for TURNS fallback. Outbound all (needed for cert
    // renewal + reachability checks).
    // -------------------------------------------------------------------- //
    const sg = new ec2.SecurityGroup(this, 'TurnSg', {
      vpc,
      description: 'VettID TURN relay - STUN/TURN/TURNS',
      allowAllOutbound: true,
    });
    sg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.udp(3478), 'TURN/UDP');
    sg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(3478), 'TURN/TCP');
    sg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(5349), 'TURNS/TCP');
    sg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(443),  'TURNS/TCP (alt, for restrictive nets)');
    sg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(80),   'Lets Encrypt HTTP-01');
    sg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.udpRange(49152, 65535), 'TURN relay range');

    // -------------------------------------------------------------------- //
    // IAM role, shared across instances. Read-only on the HMAC secret, plus
    // SSM + CloudWatch.
    // -------------------------------------------------------------------- //
    const role = new iam.Role(this, 'TurnInstanceRole', {
      assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
      description: 'VettID TURN instance - Secrets Manager read + CloudWatch',
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMManagedInstanceCore'),
        iam.ManagedPolicy.fromAwsManagedPolicyName('CloudWatchAgentServerPolicy'),
      ],
    });
    this.sharedSecret.grantRead(role);

    // -------------------------------------------------------------------- //
    // Log group for coturn output. Shared — streams tagged per-instance.
    // -------------------------------------------------------------------- //
    new logs.LogGroup(this, 'TurnLogs', {
      logGroupName: 'vettid-turn',
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // -------------------------------------------------------------------- //
    // Bootstrap template. __dirname resolves under dist/ after tsc, so walk
    // back to the source tree (cdk/lib/turn/bootstrap.sh) — the file isn't
    // copied to dist.
    // -------------------------------------------------------------------- //
    const bootstrapPath = [
      path.join(__dirname, 'turn', 'bootstrap.sh'),                         // if run from source
      path.join(__dirname, '..', '..', 'lib', 'turn', 'bootstrap.sh'),      // if run from dist/lib
    ].find((p) => fs.existsSync(p));
    if (!bootstrapPath) {
      throw new Error('Could not locate cdk/lib/turn/bootstrap.sh');
    }
    const bootstrapTemplate = fs.readFileSync(bootstrapPath, 'utf-8');

    const hostedZone = route53.HostedZone.fromLookup(this, 'HostedZone', {
      domainName: props.zoneName,
    });

    // -------------------------------------------------------------------- //
    // Per-instance resources. Deploying identical coturn instances on
    // separate hostnames (turn-a.vettid.dev, turn-b.vettid.dev, …) lets
    // clients allocate on both and ICE pick a cross-server relay pair when
    // needed — sidestepping the libwebrtc same-server CREATE_PERMISSION bug.
    // -------------------------------------------------------------------- //
    const safeId = (h: string) => h.replace(/[^A-Za-z0-9]/g, '');
    props.hostnames.forEach((hostname, idx) => {
      const id = safeId(hostname); // e.g. "turnavettiddev"

      // Spread instances round-robin across the AZs the VPC surfaced.
      const azPick = vpc.availabilityZones[idx % vpc.availabilityZones.length];
      const subnet = vpc.publicSubnets.find((s) => s.availabilityZone === azPick)
                     ?? vpc.publicSubnets[0];

      // Substitute placeholders per instance. .replace(str, str) only swaps
      // the first occurrence and caught the top-of-file comment block when
      // we first wrote this — using a global regex fixes that for every
      // REGION / REALM / SECRET_ARN line.
      const bootstrap = bootstrapTemplate
        .replace(/__REALM__/g, hostname)
        .replace(/__SECRET_ARN__/g, this.sharedSecret.secretArn)
        .replace(/__REGION__/g, this.region);
      const userData = ec2.UserData.forLinux();
      userData.addCommands(bootstrap);

      const instance = new ec2.Instance(this, `TurnInstance${id}`, {
        vpc,
        vpcSubnets: { subnets: [subnet] },
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
      cdk.Tags.of(instance).add('VettidComponent', 'turn');
      cdk.Tags.of(instance).add('VettidTurnHostname', hostname);

      const eip = new ec2.CfnEIP(this, `TurnEip${id}`, {
        domain: 'vpc',
        tags: [{ key: 'Name', value: `vettid-turn-${hostname}` }],
      });
      new ec2.CfnEIPAssociation(this, `TurnEipAssoc${id}`, {
        eip: eip.ref,
        instanceId: instance.instanceId,
      });

      new route53.ARecord(this, `TurnDns${id}`, {
        zone: hostedZone,
        recordName: hostname,
        target: route53.RecordTarget.fromIpAddresses(eip.ref),
        ttl: cdk.Duration.minutes(5),
        comment: `VettID TURN relay ${hostname}`,
        // deleteExisting lets us rename the resource (the logical ID changed
        // when we went from one-instance to per-hostname naming) without
        // tripping CFN's "RRSet already exists" conflict.
        deleteExisting: true,
      });

      // Scope a CAA record to each FQDN so Lets Encrypt can issue despite
      // the parent zone's `0 issue "amazon.com"` lock.
      new route53.CaaRecord(this, `TurnCaa${id}`, {
        zone: hostedZone,
        recordName: hostname,
        values: [{
          flag: 0,
          tag: route53.CaaTag.ISSUE,
          value: 'letsencrypt.org',
        }],
        ttl: cdk.Duration.minutes(5),
        comment: `Allow Lets Encrypt to issue for ${hostname}`,
        deleteExisting: true,
      });

      new cdk.CfnOutput(this, `TurnHostname${id}`, {
        value: hostname,
        description: `TURN server public hostname (#${idx + 1})`,
      });
      new cdk.CfnOutput(this, `TurnPublicIp${id}`, {
        value: eip.ref,
        description: `Elastic IP of TURN instance ${hostname}`,
      });
    });

    new cdk.CfnOutput(this, 'TurnSharedSecretArn', {
      value: this.sharedSecret.secretArn,
      description: 'ARN of the HMAC shared secret for TURN credential generation',
    });
    new cdk.CfnOutput(this, 'TurnHostnames', {
      value: props.hostnames.join(','),
      description: 'All TURN hostnames deployed by this stack',
    });
  }
}
