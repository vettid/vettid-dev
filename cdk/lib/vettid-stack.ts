import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import {
  aws_dynamodb as dynamodb,
  aws_lambda_nodejs as lambdaNode,
  aws_lambda as lambda,
  aws_apigatewayv2 as apigw,
  aws_apigatewayv2_integrations as integrations,
  aws_apigatewayv2_authorizers as authorizers,
  aws_iam as iam,
  aws_s3 as s3,
  aws_cognito as cognito,
  aws_lambda_event_sources as lambdaEventSources,
  aws_cloudfront as cloudfront,
  aws_cloudfront_origins as origins,
  aws_certificatemanager as acm,
  aws_route53 as route53,
  aws_route53_targets as targets,
  aws_glue as glue,
  aws_wafv2 as wafv2,
  aws_cloudwatch as cloudwatch,
  aws_cloudwatch_actions as cw_actions,
  aws_sns as sns,
  aws_events as events,
  aws_events_targets as targets_events,
  custom_resources as cr,
} from 'aws-cdk-lib';
export class VettIdStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    



// CloudFront Function: redirect www.vettid.dev -> https://vettid.dev (preserve path and query)
const wwwRedirectFn = new cloudfront.Function(this, 'WwwRedirectFn', {
  code: cloudfront.FunctionCode.fromInline(`
function handler(event) {
  var req = event.request;
  var uri = req.uri || '';
  var qs = '';
  if (req.querystring) {
    var parts = [];
    for (var k in req.querystring) {
      if (req.querystring[k] && req.querystring[k].value !== undefined) {
        parts.push(encodeURIComponent(k) + '=' + encodeURIComponent(req.querystring[k].value));
      }
    }
    if (parts.length > 0) qs = '?' + parts.join('&');
  }
  return {
    statusCode: 301,
    statusDescription: 'Moved Permanently',
    headers: { location: { value: 'https://vettid.dev' + uri + qs } }
  };
}
  `),
});

// CloudFront Function: clean URL rewrite for apex (e.g. /foo -> /foo/index.html)
const htmlRewriteFn = new cloudfront.Function(this, 'HtmlRewriteFn', {
  code: cloudfront.FunctionCode.fromInline(`
function handler(event) {
  var request = event.request;
  var uri = request.uri;

  // If URI ends with a slash, append index.html
  if (uri.endsWith('/')) {
    request.uri = uri + 'index.html';
  } else if (!uri.includes('.')) {
    // If URI has no file extension, treat as directory and append /index.html
    request.uri = uri + '/index.html';
  }

  return request;
}
`),
});

// CloudFront Function: Add security headers to all responses
const securityHeadersFn = new cloudfront.Function(this, 'SecurityHeadersFn', {
  code: cloudfront.FunctionCode.fromInline(`
function handler(event) {
  var response = event.response;
  var headers = response.headers;

  // Content Security Policy - restricts resource loading
  // Note: 'unsafe-inline' for scripts is needed for inline JS in HTML files
  // TODO: Migrate inline scripts to external files for better security
  // TODO: Bundle amazon-cognito-identity-js locally to remove cdn.jsdelivr.net dependency
  // SECURITY NOTE: cdn.jsdelivr.net is temporarily allowed for Cognito library
  // This should be replaced with local bundling in production
  // Allow resources from vettid.dev and all subdomains for cross-subdomain asset loading
  headers['content-security-policy'] = {
    value: "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://vettid.dev https://*.vettid.dev; style-src 'self' 'unsafe-inline' https://vettid.dev https://*.vettid.dev; img-src 'self' data: https://vettid.dev https://*.vettid.dev; font-src 'self' https://vettid.dev https://*.vettid.dev; connect-src 'self' https://cgccjd4djg.execute-api.us-east-1.amazonaws.com https://*.amazoncognito.com https://cognito-idp.us-east-1.amazonaws.com; frame-ancestors 'none'; form-action 'self' https://*.amazoncognito.com; base-uri 'self'; object-src 'none'; upgrade-insecure-requests;"
  };

  // Prevent clickjacking
  headers['x-frame-options'] = { value: 'DENY' };

  // Prevent MIME type sniffing
  headers['x-content-type-options'] = { value: 'nosniff' };

  // Control referrer information
  headers['referrer-policy'] = { value: 'strict-origin-when-cross-origin' };

  // Enable browser XSS protection
  headers['x-xss-protection'] = { value: '1; mode=block' };

  // Enforce HTTPS
  headers['strict-transport-security'] = { value: 'max-age=31536000; includeSubDomains; preload' };

  // Permissions Policy - restrict browser features
  // Disables camera, microphone, geolocation, etc. as they're not needed
  headers['permissions-policy'] = { value: 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()' };

  return response;
}
`),
});


// Route 53 hosted zone (existing)
const zone = route53.HostedZone.fromLookup(this, 'VettIdZone', { domainName: 'vettid.dev' });



// ACM certificate in us-east-1 for CloudFront (create via DNS validation)
// Note: Certificates in us-east-1 are required for CloudFront
const cert = new acm.Certificate(this, 'VettIdCert2025', {
  domainName: 'vettid.dev',
  subjectAlternativeNames: ['www.vettid.dev', 'admin.vettid.dev'],
  validation: acm.CertificateValidation.fromDns(zone),
});

// S3 bucket for CloudFront access logs with 90-day retention
// CloudFront requires ACL access to write logs
const logBucket = new s3.Bucket(this, 'CloudFrontLogBucket', {
  blockPublicAccess: new s3.BlockPublicAccess({
    blockPublicAcls: false,
    blockPublicPolicy: true,
    ignorePublicAcls: false,
    restrictPublicBuckets: true,
  }),
  objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_PREFERRED,
  lifecycleRules: [
    {
      id: 'DeleteOldLogs',
      enabled: true,
      expiration: cdk.Duration.days(90), // Increased from 30 to 90 days for better forensics and compliance
    },
  ],
  removalPolicy: cdk.RemovalPolicy.DESTROY,
  autoDeleteObjects: true,
});

// Single site bucket for all content (vettid.dev)
// Files will be organized by path: /register/*, /account/*, /admin/*
const siteBucket = new s3.Bucket(this, 'SiteBucket', {
  blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
});
const siteOrigin = origins.S3BucketOrigin.withOriginAccessControl(siteBucket);
const adminOrigin = origins.S3BucketOrigin.withOriginAccessControl(siteBucket, {
  originPath: '/admin',
});

// WAF Web ACL for CloudFront protection against scanning and probing
// IMPORTANT: Must be created in us-east-1 (CLOUDFRONT scope)
const webAcl = new wafv2.CfnWebACL(this, 'WebAcl', {
  scope: 'CLOUDFRONT',
  defaultAction: { allow: {} },
  visibilityConfig: {
    cloudWatchMetricsEnabled: true,
    metricName: 'VettIDWebAcl',
    sampledRequestsEnabled: true,
  },
  rules: [
    // Rate limiting: 100 requests per 5 minutes per IP
    {
      name: 'RateLimitRule',
      priority: 1,
      statement: {
        rateBasedStatement: {
          limit: 100,
          aggregateKeyType: 'IP',
        },
      },
      action: { block: {} },
      visibilityConfig: {
        cloudWatchMetricsEnabled: true,
        metricName: 'RateLimitRule',
        sampledRequestsEnabled: true,
      },
    },
    // AWS Managed Rules: Core Rule Set (OWASP Top 10 protection)
    {
      name: 'AWSManagedRulesCommonRuleSet',
      priority: 2,
      statement: {
        managedRuleGroupStatement: {
          vendorName: 'AWS',
          name: 'AWSManagedRulesCommonRuleSet',
        },
      },
      overrideAction: { none: {} },
      visibilityConfig: {
        cloudWatchMetricsEnabled: true,
        metricName: 'AWSManagedRulesCommonRuleSet',
        sampledRequestsEnabled: true,
      },
    },
    // AWS Managed Rules: Known Bad Inputs
    {
      name: 'AWSManagedRulesKnownBadInputsRuleSet',
      priority: 3,
      statement: {
        managedRuleGroupStatement: {
          vendorName: 'AWS',
          name: 'AWSManagedRulesKnownBadInputsRuleSet',
        },
      },
      overrideAction: { none: {} },
      visibilityConfig: {
        cloudWatchMetricsEnabled: true,
        metricName: 'AWSManagedRulesKnownBadInputsRuleSet',
        sampledRequestsEnabled: true,
      },
    },
    // AWS Managed Rules: IP Reputation List (known malicious IPs)
    {
      name: 'AWSManagedRulesAmazonIpReputationList',
      priority: 4,
      statement: {
        managedRuleGroupStatement: {
          vendorName: 'AWS',
          name: 'AWSManagedRulesAmazonIpReputationList',
        },
      },
      overrideAction: { none: {} },
      visibilityConfig: {
        cloudWatchMetricsEnabled: true,
        metricName: 'AWSManagedRulesAmazonIpReputationList',
        sampledRequestsEnabled: true,
      },
    },
  ],
});

// CloudFront distribution for vettid.dev with path-based routing
const rootDist = new cloudfront.Distribution(this, 'RootDist', {
  webAclId: webAcl.attrArn,
  domainNames: ['vettid.dev'],
  certificate: cert,
  defaultRootObject: 'index.html',
  defaultBehavior: {
    origin: siteOrigin,
    functionAssociations: [
      { eventType: cloudfront.FunctionEventType.VIEWER_REQUEST, function: htmlRewriteFn },
      { eventType: cloudfront.FunctionEventType.VIEWER_RESPONSE, function: securityHeadersFn }
    ],
  },
  enableLogging: true,
  logBucket: logBucket,
  logFilePrefix: 'cloudfront-logs/root/',
  logIncludesCookies: true,
});

// CloudFront distribution for www that issues a 301 redirect to apex
const wwwDist = new cloudfront.Distribution(this, 'WwwDist', {
  webAclId: webAcl.attrArn,
  domainNames: ['www.vettid.dev'],
  certificate: cert,
  defaultBehavior: {
    origin: siteOrigin, // never reached; redirect happens at viewer request
    viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
    functionAssociations: [
      { eventType: cloudfront.FunctionEventType.VIEWER_REQUEST, function: wwwRedirectFn }
    ],
  },
  // No defaultRootObject since we're redirecting everything
  enableLogging: true,
  logBucket: logBucket,
  logFilePrefix: 'cloudfront-logs/www/',
  logIncludesCookies: true,
});

// CloudFront distribution for admin.vettid.dev (secure admin subdomain)
const adminDist = new cloudfront.Distribution(this, 'AdminDist', {
  webAclId: webAcl.attrArn,
  domainNames: ['admin.vettid.dev'],
  certificate: cert,
  defaultRootObject: 'index.html',
  defaultBehavior: {
    origin: adminOrigin,
    viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
    cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED, // No caching for admin for security
    originRequestPolicy: cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
    functionAssociations: [
      { eventType: cloudfront.FunctionEventType.VIEWER_RESPONSE, function: securityHeadersFn }
    ],
  },
  enableLogging: true,
  logBucket: logBucket,
  logFilePrefix: 'cloudfront-logs/admin/',
  logIncludesCookies: true,
});


// Route53 aliases for apex and www
new route53.ARecord(this, 'ApexAliasA', {
  zone, recordName: '',
  target: route53.RecordTarget.fromAlias(new targets.CloudFrontTarget(rootDist)),
});
new route53.AaaaRecord(this, 'ApexAliasAAAA', {
  zone, recordName: '',
  target: route53.RecordTarget.fromAlias(new targets.CloudFrontTarget(rootDist)),
});
new route53.ARecord(this, 'WwwAliasA', {
  zone, recordName: 'www',
  target: route53.RecordTarget.fromAlias(new targets.CloudFrontTarget(wwwDist)),
});
new route53.AaaaRecord(this, 'WwwAliasAAAA', {
  zone, recordName: 'www',
  target: route53.RecordTarget.fromAlias(new targets.CloudFrontTarget(wwwDist)),
});
new route53.ARecord(this, 'AdminAliasA', {
  zone, recordName: 'admin',
  target: route53.RecordTarget.fromAlias(new targets.CloudFrontTarget(adminDist)),
});
new route53.AaaaRecord(this, 'AdminAliasAAAA', {
  zone, recordName: 'admin',
  target: route53.RecordTarget.fromAlias(new targets.CloudFrontTarget(adminDist)),
});

// Note: Subdomain records (register, account) are served from vettid.dev with path-based routing
// Admin has been moved to admin.vettid.dev for improved security

// Athena/Glue database and table for querying CloudFront logs
const glueDatabase = new glue.CfnDatabase(this, 'LogsDatabase', {
  catalogId: this.account,
  databaseInput: {
    name: 'cloudfront_logs',
    description: 'Database for CloudFront access logs',
  },
});

// CloudFront standard log format table
// See: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html
new glue.CfnTable(this, 'CloudFrontLogsTable', {
  catalogId: this.account,
  databaseName: glueDatabase.ref,
  tableInput: {
    name: 'access_logs',
    description: 'CloudFront access logs',
    tableType: 'EXTERNAL_TABLE',
    parameters: {
      'skip.header.line.count': '2',
    },
    storageDescriptor: {
      columns: [
        { name: 'request_date', type: 'date' },
        { name: 'time', type: 'string' },
        { name: 'location', type: 'string' },
        { name: 'bytes', type: 'bigint' },
        { name: 'request_ip', type: 'string' },
        { name: 'method', type: 'string' },
        { name: 'host', type: 'string' },
        { name: 'uri', type: 'string' },
        { name: 'status', type: 'int' },
        { name: 'referrer', type: 'string' },
        { name: 'user_agent', type: 'string' },
        { name: 'query_string', type: 'string' },
        { name: 'cookie', type: 'string' },
        { name: 'result_type', type: 'string' },
        { name: 'request_id', type: 'string' },
        { name: 'host_header', type: 'string' },
        { name: 'request_protocol', type: 'string' },
        { name: 'request_bytes', type: 'bigint' },
        { name: 'time_taken', type: 'float' },
        { name: 'xforwarded_for', type: 'string' },
        { name: 'ssl_protocol', type: 'string' },
        { name: 'ssl_cipher', type: 'string' },
        { name: 'response_result_type', type: 'string' },
        { name: 'http_version', type: 'string' },
        { name: 'fle_status', type: 'string' },
        { name: 'fle_encrypted_fields', type: 'int' },
        { name: 'c_port', type: 'int' },
        { name: 'time_to_first_byte', type: 'float' },
        { name: 'x_edge_detailed_result_type', type: 'string' },
        { name: 'sc_content_type', type: 'string' },
        { name: 'sc_content_len', type: 'bigint' },
        { name: 'sc_range_start', type: 'bigint' },
        { name: 'sc_range_end', type: 'bigint' },
      ],
      location: `s3://${logBucket.bucketName}/cloudfront-logs/`,
      inputFormat: 'org.apache.hadoop.mapred.TextInputFormat',
      outputFormat: 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat',
      compressed: false,
      serdeInfo: {
        serializationLibrary: 'org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe',
        parameters: {
          'field.delim': '\t',
          'serialization.format': '\t',
        },
      },
    },
  },
});

// DynamoDB tables
    const invites = new dynamodb.Table(this, 'Invites', {
      partitionKey: { name: 'code', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
removalPolicy: cdk.RemovalPolicy.DESTROY,
    });
    
// Enable PITR via L1 for invites
(invites.node.defaultChild as dynamodb.CfnTable).pointInTimeRecoverySpecification = {
  pointInTimeRecoveryEnabled: true,
};
const registrations = new dynamodb.Table(this, 'Registrations', {
      partitionKey: { name: 'registration_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
stream: dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });
    
// Enable PITR via L1 for registrations
(registrations.node.defaultChild as dynamodb.CfnTable).pointInTimeRecoverySpecification = {
  pointInTimeRecoveryEnabled: true,
};
registrations.addGlobalSecondaryIndex({
      indexName: 'status-index',
      partitionKey: { name: 'status', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'created_at', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });
    registrations.addGlobalSecondaryIndex({
      indexName: 'email-index',
      partitionKey: { name: 'email', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });
    const audit = new dynamodb.Table(this, 'Audit', {
      partitionKey: { name: 'id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // Waitlist table for managing waitlist signups
    const waitlist = new dynamodb.Table(this, 'Waitlist', {
      partitionKey: { name: 'waitlist_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
    });

    // Add GSI for email lookups to prevent duplicate waitlist entries
    waitlist.addGlobalSecondaryIndex({
      indexName: 'email-index',
      partitionKey: { name: 'email', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // Magic link tokens table for passwordless auth
    const magicLinkTokens = new dynamodb.Table(this, 'MagicLinkTokens', {
      partitionKey: { name: 'token', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: 'expiresAt',
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // Add GSI for email lookups to enable efficient rate limiting queries
    magicLinkTokens.addGlobalSecondaryIndex({
      indexName: 'email-index',
      partitionKey: { name: 'email', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'createdAtTimestamp', type: dynamodb.AttributeType.NUMBER },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // Membership terms table for storing terms of service versions
    const membershipTerms = new dynamodb.Table(this, 'MembershipTerms', {
      partitionKey: { name: 'version_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
    });

    // Add GSI for getting current version
    membershipTerms.addGlobalSecondaryIndex({
      indexName: 'current-index',
      partitionKey: { name: 'is_current', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'created_at', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // S3 bucket for membership terms PDFs
    const termsBucket = new s3.Bucket(this, 'MembershipTermsBucket', {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      versioned: true,
      encryption: s3.BucketEncryption.S3_MANAGED,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
    });

    // Subscriptions table for managing user subscriptions
    const subscriptions = new dynamodb.Table(this, 'Subscriptions', {
      partitionKey: { name: 'user_guid', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
    });

    // Add GSI for status queries
    subscriptions.addGlobalSecondaryIndex({
      indexName: 'status-index',
      partitionKey: { name: 'status', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'expires_at', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // Proposals table for voting/governance
    const proposals = new dynamodb.Table(this, 'Proposals', {
      partitionKey: { name: 'proposal_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
      stream: dynamodb.StreamViewType.NEW_AND_OLD_IMAGES, // Enable streams for proposal notifications
    });

    // Add GSI for status queries
    proposals.addGlobalSecondaryIndex({
      indexName: 'status-index',
      partitionKey: { name: 'status', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'opens_at', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // Votes table for storing user votes on proposals
    const votes = new dynamodb.Table(this, 'Votes', {
      partitionKey: { name: 'vote_id', type: dynamodb.AttributeType.STRING }, // composite: user_guid#proposal_id
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
    });

    // GSI for querying votes by user
    votes.addGlobalSecondaryIndex({
      indexName: 'user-votes-index',
      partitionKey: { name: 'user_guid', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'voted_at', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // GSI for querying votes by proposal
    votes.addGlobalSecondaryIndex({
      indexName: 'proposal-votes-index',
      partitionKey: { name: 'proposal_id', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // Subscription Types table for managing subscription offerings
    const subscriptionTypes = new dynamodb.Table(this, 'SubscriptionTypes', {
      partitionKey: { name: 'subscription_type_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
    });

    // ===== VAULT SERVICES TABLES =====

    // Credentials table - stores encrypted credential blobs and metadata
    // This is the core table for the Protean Credential system
    const credentials = new dynamodb.Table(this, 'Credentials', {
      partitionKey: { name: 'user_guid', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
    });

    // Credential Encryption Keys (CEK) - stores encrypted private keys for credential encryption
    // Ledger owns these keys; mobile cannot decrypt credentials
    const credentialKeys = new dynamodb.Table(this, 'CredentialKeys', {
      partitionKey: { name: 'user_guid', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'version', type: dynamodb.AttributeType.NUMBER },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
    });

    // Transaction Keys - stores LTK (private) and UTK (public) pairs
    // LTK stays on ledger, UTK sent to mobile for encrypting password hashes
    const transactionKeys = new dynamodb.Table(this, 'TransactionKeys', {
      partitionKey: { name: 'user_guid', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'key_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
    });

    // GSI for finding unused keys
    transactionKeys.addGlobalSecondaryIndex({
      indexName: 'status-index',
      partitionKey: { name: 'user_guid', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'status', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // Ledger Auth Tokens (LAT) - for mutual authentication / phishing protection
    const ledgerAuthTokens = new dynamodb.Table(this, 'LedgerAuthTokens', {
      partitionKey: { name: 'user_guid', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'version', type: dynamodb.AttributeType.NUMBER },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
    });

    // Action Tokens - tracks single-use scoped action tokens
    const actionTokens = new dynamodb.Table(this, 'ActionTokens', {
      partitionKey: { name: 'token_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: 'expires_at_ttl',
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // GSI for querying tokens by user
    actionTokens.addGlobalSecondaryIndex({
      indexName: 'user-index',
      partitionKey: { name: 'user_guid', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'issued_at', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // Enrollment Sessions - tracks multi-step enrollment progress
    const enrollmentSessions = new dynamodb.Table(this, 'EnrollmentSessions', {
      partitionKey: { name: 'session_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: 'expires_at_ttl',
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // GSI for querying sessions by invitation code
    enrollmentSessions.addGlobalSecondaryIndex({
      indexName: 'invitation-index',
      partitionKey: { name: 'invitation_code', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

// Enable PITR via L1 for audit
(audit.node.defaultChild as dynamodb.CfnTable).pointInTimeRecoverySpecification = {
  pointInTimeRecoveryEnabled: true,
};

    // Custom auth Lambda functions for passwordless magic link authentication
    // These must be created before the user pool that references them
    const defineAuthChallenge = new lambdaNode.NodejsFunction(this, 'DefineAuthChallengeFn', {
      entry: 'lambda/handlers/auth/defineAuthChallenge.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      timeout: cdk.Duration.seconds(10),
    });

    const createAuthChallenge = new lambdaNode.NodejsFunction(this, 'CreateAuthChallengeFn', {
      entry: 'lambda/handlers/auth/createAuthChallenge.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        MAGIC_LINK_TABLE: magicLinkTokens.tableName,
        REGISTRATIONS_TABLE: registrations.tableName,
        MAGIC_LINK_URL: 'https://vettid.dev/auth',
        SES_FROM: 'no-reply@auth.vettid.dev',
      },
      timeout: cdk.Duration.seconds(10),
    });

    const verifyAuthChallenge = new lambdaNode.NodejsFunction(this, 'VerifyAuthChallengeFn', {
      entry: 'lambda/handlers/auth/verifyAuthChallenge.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        MAGIC_LINK_TABLE: magicLinkTokens.tableName,
        REGISTRATIONS_TABLE: registrations.tableName,
      },
      timeout: cdk.Duration.seconds(10),
    });

    // PreTokenGeneration trigger for admin user pool - adds custom:admin_type to ID token
    const preTokenGeneration = new lambdaNode.NodejsFunction(this, 'PreTokenGenerationFn', {
      entry: 'lambda/triggers/preTokenGeneration.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      timeout: cdk.Duration.seconds(10),
    });

    // Grant permissions to auth Lambda functions
    magicLinkTokens.grantReadWriteData(createAuthChallenge);
    magicLinkTokens.grantReadWriteData(verifyAuthChallenge);
    registrations.grantReadData(createAuthChallenge); // For PIN status check
    registrations.grantReadData(verifyAuthChallenge); // For PIN validation

    // Grant CloudWatch metrics permissions to verifyAuthChallenge for failed login tracking
    verifyAuthChallenge.addToRolePolicy(new iam.PolicyStatement({
      actions: ['cloudwatch:PutMetricData'],
      resources: ['*'], // CloudWatch PutMetricData doesn't support resource-level permissions
      conditions: {
        StringEquals: {
          'cloudwatch:namespace': 'VettID/Authentication'
        }
      }
    }));

    // Grant SES permissions to createAuthChallenge
    // Note: Using wildcard for identities to support SES sandbox mode (requires verified recipients)
    // In production mode, only FROM address needs to be verified
    createAuthChallenge.addToRolePolicy(new iam.PolicyStatement({
      actions: ['ses:SendEmail', 'ses:SendRawEmail'],
      resources: [`arn:aws:ses:${this.region}:${this.account}:identity/*`],
    }));

// Cognito User Pools (separate pools for admins and members)

    // Member user pool - for VettID members accessing vettid.dev/account
    // Uses passwordless magic link authentication via custom auth flow
    const memberUserPool = new cognito.UserPool(this, 'MemberUserPool', {
      selfSignUpEnabled: false,
      signInAliases: { email: true },
      passwordPolicy: {
        minLength: 12,
        requireDigits: true,
        requireLowercase: true,
        requireUppercase: true,
        requireSymbols: true,
      },
      email: cognito.UserPoolEmail.withSES({
        fromEmail: 'no-reply@auth.vettid.dev',
        fromName: 'VettID',
        sesRegion: 'us-east-1',
        sesVerifiedDomain: 'auth.vettid.dev',
      }),
      customAttributes: {
        'user_guid': new cognito.StringAttribute({ minLen: 36, maxLen: 36, mutable: false }),
      },
      lambdaTriggers: {
        defineAuthChallenge: defineAuthChallenge,
        createAuthChallenge: createAuthChallenge,
        verifyAuthChallengeResponse: verifyAuthChallenge,
      },
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });
    const memberDomainPrefix = `vettid-members-${cdk.Names.uniqueId(this).toLowerCase().slice(0, 10)}`.replace(/[^a-z0-9-]/g, '');
    const memberPoolDomain = memberUserPool.addDomain('MemberCognitoDomain', { cognitoDomain: { domainPrefix: memberDomainPrefix } });
    new cognito.CfnUserPoolGroup(this, 'RegisteredGroup', { userPoolId: memberUserPool.userPoolId, groupName: 'registered' });
    new cognito.CfnUserPoolGroup(this, 'MemberGroup', { userPoolId: memberUserPool.userPoolId, groupName: 'member' });

    // Admin user pool - for VettID administrators accessing admin.vettid.dev
    const adminUserPool = new cognito.UserPool(this, 'AdminUserPool', {
      selfSignUpEnabled: false,
      signInAliases: { email: true },
      passwordPolicy: {
        minLength: 12,
        requireDigits: true,
        requireLowercase: true,
        requireUppercase: true,
        requireSymbols: true,
      },
      email: cognito.UserPoolEmail.withSES({
        fromEmail: 'no-reply@auth.vettid.dev',
        fromName: 'VettID Admin',
        sesRegion: 'us-east-1',
        sesVerifiedDomain: 'auth.vettid.dev',
      }),
      customAttributes: {
        'admin_type': new cognito.StringAttribute({ minLen: 1, maxLen: 50, mutable: true }),
      },
      lambdaTriggers: {
        preTokenGeneration: preTokenGeneration,
      },
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });
    const adminDomainPrefix = `vettid-admin-${cdk.Names.uniqueId(this).toLowerCase().slice(0, 10)}`.replace(/[^a-z0-9-]/g, '');
    const adminPoolDomain = adminUserPool.addDomain('AdminCognitoDomain', { cognitoDomain: { domainPrefix: adminDomainPrefix } });
    new cognito.CfnUserPoolGroup(this, 'AdminGroup', { userPoolId: adminUserPool.userPoolId, groupName: 'admin' });

    // Custom UI for admin Cognito hosted UI - matches VettID branding
    // Note: Cognito only allows specific CSS classes without pseudo-selectors
    const cognitoCustomCSS = `
      .logo-customizable {
        max-width: 100%;
        max-height: 100px;
      }
      .banner-customizable {
        padding: 25px 0px 25px 0px;
        background: linear-gradient(135deg, #1a1a1a 0%, #0a0a0a 100%);
      }
      .submitButton-customizable {
        font-size: 14px;
        font-weight: bold;
        margin: 20px 0px 10px 0px;
        height: 40px;
        padding: 0px;
        border-radius: 2px;
        color: #000;
        background: linear-gradient(135deg, #ffc125 0%, #e0a800 100%);
        border: none;
        box-shadow: 0 4px 14px rgba(255, 193, 37, 0.5);
      }
      .inputField-customizable {
        font-size: 14px;
        height: 40px;
        padding: 0.6rem;
        border-radius: 2px;
        border: 1px solid #333;
        background: #050505;
        color: #e0e0e0;
      }
      .background-customizable {
        background: #000;
      }
      .textDescription-customizable {
        padding-top: 10px;
        padding-bottom: 10px;
        display: block;
        font-size: 16px;
        color: #e0e0e0;
      }
      .idpDescription-customizable {
        padding-top: 10px;
        padding-bottom: 10px;
        display: block;
        font-size: 16px;
        color: #e0e0e0;
      }
      .legalText-customizable {
        color: #999;
        font-size: 11px;
      }
      .errorMessage-customizable {
        padding: 5px;
        font-size: 14px;
        width: 100%;
        background: #1a0505;
        border: 2px solid #dc2626;
        color: #fecaca;
        border-radius: 4px;
      }
      .socialButton-customizable {
        height: 40px;
        text-align: left;
        width: 100%;
        border-radius: 2px;
        background: #0a0a0a;
        border: 1px solid #333;
        color: #e0e0e0;
      }
    `;

    // Admin app client - for admin.vettid.dev (uses adminUserPool)
    const adminAppClient = new cognito.UserPoolClient(this, 'AdminWebClient', {
      userPool: adminUserPool,
      authFlows: { userPassword: false, userSrp: false, adminUserPassword: false },
      oAuth: {
        flows: { authorizationCodeGrant: true },
        scopes: [cognito.OAuthScope.OPENID, cognito.OAuthScope.EMAIL, cognito.OAuthScope.PROFILE],
        callbackUrls: ['https://admin.vettid.dev/index.html'],
        logoutUrls: ['https://admin.vettid.dev/index.html'],
      },
      generateSecret: false,
      preventUserExistenceErrors: true,
      enableTokenRevocation: true,
      refreshTokenValidity: cdk.Duration.days(30),
      readAttributes: new cognito.ClientAttributes()
        .withStandardAttributes({ email: true, emailVerified: true, givenName: true, familyName: true })
        .withCustomAttributes('admin_type'),
      writeAttributes: new cognito.ClientAttributes()
        .withStandardAttributes({ givenName: true, familyName: true })
        .withCustomAttributes('admin_type'),
    });

    // Apply VettID branding CSS to Cognito hosted UI
    // Note: Logo must be uploaded separately via AWS CLI (see deployment instructions)
    new cognito.CfnUserPoolUICustomizationAttachment(this, 'AdminUICustomization', {
      userPoolId: adminUserPool.userPoolId,
      clientId: adminAppClient.userPoolClientId,
      css: cognitoCustomCSS,
    });

    // Member app client - for vettid.dev/account (uses memberUserPool with magic link auth)
    const memberAppClient = new cognito.UserPoolClient(this, 'MemberWebClient', {
      userPool: memberUserPool,
      authFlows: {
        userPassword: false,
        userSrp: false,
        adminUserPassword: false,
        custom: true, // Enable custom auth flow for magic links
      },
      generateSecret: false,
      preventUserExistenceErrors: true,
      enableTokenRevocation: true,
      refreshTokenValidity: cdk.Duration.days(30),
    });

    // Lambda env
    const defaultEnv = {
      TABLE_INVITES: invites.tableName,
      TABLE_REGISTRATIONS: registrations.tableName,
      TABLE_AUDIT: audit.tableName,
      TABLE_MEMBERSHIP_TERMS: membershipTerms.tableName,
      TABLE_SUBSCRIPTIONS: subscriptions.tableName,
      TABLE_PROPOSALS: proposals.tableName,
      TABLE_VOTES: votes.tableName,
      TABLE_SUBSCRIPTION_TYPES: subscriptionTypes.tableName,
      TERMS_BUCKET: termsBucket.bucketName,
      SES_FROM: 'no-reply@auth.vettid.dev',
      CORS_ORIGIN: 'https://vettid.dev,https://www.vettid.dev,https://admin.vettid.dev,https://account.vettid.dev,https://register.vettid.dev',
      ALLOWED_ORIGINS: 'https://vettid.dev,https://www.vettid.dev,https://admin.vettid.dev,https://account.vettid.dev,https://register.vettid.dev',
    };

    // Vault services environment variables
    const vaultEnv = {
      ...defaultEnv,
      TABLE_CREDENTIALS: credentials.tableName,
      TABLE_CREDENTIAL_KEYS: credentialKeys.tableName,
      TABLE_TRANSACTION_KEYS: transactionKeys.tableName,
      TABLE_LEDGER_AUTH_TOKENS: ledgerAuthTokens.tableName,
      TABLE_ACTION_TOKENS: actionTokens.tableName,
      TABLE_ENROLLMENT_SESSIONS: enrollmentSessions.tableName,
    };

    // Lambdas
    const submitRegistration = new lambdaNode.NodejsFunction(this, 'SubmitRegistrationFn', {
      entry: 'lambda/handlers/public/submitRegistration.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: { ...defaultEnv, USER_POOL_ID: memberUserPool.userPoolId, MEMBER_GROUP: 'member' },
      timeout: cdk.Duration.seconds(10), // Prevent long-running requests
    });
    const submitWaitlist = new lambdaNode.NodejsFunction(this, 'SubmitWaitlistFn', {
      entry: 'lambda/handlers/public/submitWaitlist.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: { ...defaultEnv, TABLE_WAITLIST: waitlist.tableName },
      timeout: cdk.Duration.seconds(10),
    });
    const listRegistrations = new lambdaNode.NodejsFunction(this, 'ListRegistrationsFn', {
      entry: 'lambda/handlers/admin/listRegistrations.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: { ...defaultEnv, USER_POOL_ID: memberUserPool.userPoolId },
    });
    const registrationStreamFn = new lambdaNode.NodejsFunction(this, 'RegistrationStreamFn', {
      entry: 'lambda/handlers/streams/registrationStream.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
    });
    const proposalStreamFn = new lambdaNode.NodejsFunction(this, 'ProposalStreamFn', {
      entry: 'lambda/handlers/streams/proposalStream.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        TABLE_SUBSCRIPTIONS: subscriptions.tableName,
        TABLE_REGISTRATIONS: registrations.tableName,
      },
      timeout: cdk.Duration.seconds(60), // Allow time to send multiple emails
    });
    const approveRegistration = new lambdaNode.NodejsFunction(this, 'ApproveRegistrationFn', {
      entry: 'lambda/handlers/admin/approveRegistration.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: { ...defaultEnv, USER_POOL_ID: memberUserPool.userPoolId, MEMBER_GROUP: 'member' },
      timeout: cdk.Duration.seconds(30), // Cognito operations can take time
    });
    const createInvite = new lambdaNode.NodejsFunction(this, 'CreateInviteFn', {
      entry: 'lambda/handlers/admin/createInvite.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
    });
    const listInvites = new lambdaNode.NodejsFunction(this, 'ListInvitesFn', {
      entry: 'lambda/handlers/admin/listInvites.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
    });
    const expireInvite = new lambdaNode.NodejsFunction(this, 'ExpireInviteFn', {
      entry: 'lambda/handlers/admin/expireInvite.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
    });
    const rejectRegistration = new lambdaNode.NodejsFunction(this, 'RejectRegistrationFn', {
      entry: 'lambda/handlers/admin/rejectRegistration.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
    });
    const disableUser = new lambdaNode.NodejsFunction(this, 'DisableUserFn', {
      entry: 'lambda/handlers/admin/disableUser.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: { ...defaultEnv, USER_POOL_ID: memberUserPool.userPoolId },
      timeout: cdk.Duration.seconds(30), // Cognito operations can take time
    });
    const deleteUser = new lambdaNode.NodejsFunction(this, 'DeleteUserFn', {
      entry: 'lambda/handlers/admin/deleteUser.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: { ...defaultEnv, USER_POOL_ID: memberUserPool.userPoolId },
      timeout: cdk.Duration.seconds(30), // Cognito operations can take time
    });
    const enableUser = new lambdaNode.NodejsFunction(this, 'EnableUserFn', {
      entry: 'lambda/handlers/admin/enableUser.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: { ...defaultEnv, USER_POOL_ID: memberUserPool.userPoolId },
      timeout: cdk.Duration.seconds(30), // Cognito operations can take time
    });
    const permanentlyDeleteUser = new lambdaNode.NodejsFunction(this, 'PermanentlyDeleteUserFn', {
      entry: 'lambda/handlers/admin/permanentlyDeleteUser.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: { ...defaultEnv, USER_POOL_ID: memberUserPool.userPoolId, TABLE_SUBSCRIPTIONS: subscriptions.tableName },
      timeout: cdk.Duration.seconds(30), // Cognito operations can take time
    });
    const deleteInvite = new lambdaNode.NodejsFunction(this, 'DeleteInviteFn', {
      entry: 'lambda/handlers/admin/deleteInvite.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
    });
    const listAdmins = new lambdaNode.NodejsFunction(this, 'ListAdminsFn', {
      entry: 'lambda/handlers/admin/listAdmins.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: { ...defaultEnv, USER_POOL_ID: adminUserPool.userPoolId, ADMIN_GROUP: 'admin' },
    });
    const addAdmin = new lambdaNode.NodejsFunction(this, 'AddAdminFn', {
      entry: 'lambda/handlers/admin/addAdmin.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: { ...defaultEnv, USER_POOL_ID: adminUserPool.userPoolId, ADMIN_GROUP: 'admin' },
    });
    const removeAdmin = new lambdaNode.NodejsFunction(this, 'RemoveAdminFn', {
      entry: 'lambda/handlers/admin/removeAdmin.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: { ...defaultEnv, USER_POOL_ID: adminUserPool.userPoolId, ADMIN_GROUP: 'admin' },
    });
    const disableAdmin = new lambdaNode.NodejsFunction(this, 'DisableAdminFn', {
      entry: 'lambda/handlers/admin/disableAdmin.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: { ...defaultEnv, USER_POOL_ID: adminUserPool.userPoolId },
    });
    const enableAdmin = new lambdaNode.NodejsFunction(this, 'EnableAdminFn', {
      entry: 'lambda/handlers/admin/enableAdmin.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: { ...defaultEnv, USER_POOL_ID: adminUserPool.userPoolId },
    });
    const updateAdminType = new lambdaNode.NodejsFunction(this, 'UpdateAdminTypeFn', {
      entry: 'lambda/handlers/admin/updateAdminType.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: { ...defaultEnv, USER_POOL_ID: adminUserPool.userPoolId },
    });
    const changePassword = new lambdaNode.NodejsFunction(this, 'ChangePasswordFn', {
      entry: 'lambda/handlers/admin/changePassword.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        USER_POOL_ID: adminUserPool.userPoolId,
        CLIENT_ID: adminAppClient.userPoolClientId
      },
    });
    const resetAdminPassword = new lambdaNode.NodejsFunction(this, 'ResetAdminPasswordFn', {
      entry: 'lambda/handlers/admin/resetAdminPassword.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: { ...defaultEnv, USER_POOL_ID: adminUserPool.userPoolId },
    });
    const cancelAccount = new lambdaNode.NodejsFunction(this, 'CancelAccountFn', {
      entry: 'lambda/handlers/member/cancelAccount.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: { ...defaultEnv, USER_POOL_ID: memberUserPool.userPoolId, TABLE_SUBSCRIPTIONS: subscriptions.tableName },
    });
    const cleanupExpiredAccounts = new lambdaNode.NodejsFunction(this, 'CleanupExpiredAccountsFn', {
      entry: 'lambda/handlers/scheduled/cleanupExpiredAccounts.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: { ...defaultEnv, USER_POOL_ID: memberUserPool.userPoolId },
      timeout: cdk.Duration.minutes(5), // Allow more time for batch deletions
    });
    const enablePin = new lambdaNode.NodejsFunction(this, 'EnablePinFn', {
      entry: 'lambda/handlers/member/enablePin.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
    });
    const disablePin = new lambdaNode.NodejsFunction(this, 'DisablePinFn', {
      entry: 'lambda/handlers/member/disablePin.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
    });
    const updatePin = new lambdaNode.NodejsFunction(this, 'UpdatePinFn', {
      entry: 'lambda/handlers/member/updatePin.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
    });
    const getPinStatus = new lambdaNode.NodejsFunction(this, 'GetPinStatusFn', {
      entry: 'lambda/handlers/member/getPinStatus.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
    });
    const getEmailPreferences = new lambdaNode.NodejsFunction(this, 'GetEmailPreferencesFn', {
      entry: 'lambda/handlers/member/getEmailPreferences.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
    });
    const updateEmailPreferences = new lambdaNode.NodejsFunction(this, 'UpdateEmailPreferencesFn', {
      entry: 'lambda/handlers/member/updateEmailPreferences.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
    });
    const requestMembership = new lambdaNode.NodejsFunction(this, 'RequestMembershipFn', {
      entry: 'lambda/handlers/member/requestMembership.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: { ...defaultEnv, USER_POOL_ID: memberUserPool.userPoolId },
    });
    const getMembershipStatus = new lambdaNode.NodejsFunction(this, 'GetMembershipStatusFn', {
      entry: 'lambda/handlers/member/getMembershipStatus.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
    });
    const getMembershipTerms = new lambdaNode.NodejsFunction(this, 'GetMembershipTermsFn', {
      entry: 'lambda/handlers/member/getMembershipTerms.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
    });
    const createSubscription = new lambdaNode.NodejsFunction(this, 'CreateSubscriptionFn', {
      entry: 'lambda/handlers/member/createSubscription.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
    });
    const getSubscriptionStatus = new lambdaNode.NodejsFunction(this, 'GetSubscriptionStatusFn', {
      entry: 'lambda/handlers/member/getSubscriptionStatus.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
    });
    const cancelSubscription = new lambdaNode.NodejsFunction(this, 'CancelSubscriptionFn', {
      entry: 'lambda/handlers/member/cancelSubscription.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
    });
    const listEnabledSubscriptionTypes = new lambdaNode.NodejsFunction(this, 'ListEnabledSubscriptionTypesFn', {
      entry: 'lambda/handlers/member/listEnabledSubscriptionTypes.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
    });
    const listMembershipRequests = new lambdaNode.NodejsFunction(this, 'ListMembershipRequestsFn', {
      entry: 'lambda/handlers/admin/listMembershipRequests.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
    });
    const approveMembership = new lambdaNode.NodejsFunction(this, 'ApproveMembershipFn', {
      entry: 'lambda/handlers/admin/approveMembership.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: { ...defaultEnv, USER_POOL_ID: memberUserPool.userPoolId },
      timeout: cdk.Duration.seconds(30), // Cognito operations can take time
    });
    const denyMembership = new lambdaNode.NodejsFunction(this, 'DenyMembershipFn', {
      entry: 'lambda/handlers/admin/denyMembership.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
    });
    const createProposal = new lambdaNode.NodejsFunction(this, 'CreateProposalFn', {
      entry: 'lambda/handlers/admin/createProposal.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
    });
    const listProposals = new lambdaNode.NodejsFunction(this, 'ListProposalsFn', {
      entry: 'lambda/handlers/admin/listProposals.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
    });
    const suspendProposal = new lambdaNode.NodejsFunction(this, 'SuspendProposalFn', {
      entry: 'lambda/handlers/admin/suspendProposal.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
    });
    const listSubscriptions = new lambdaNode.NodejsFunction(this, 'ListSubscriptionsFn', {
      entry: 'lambda/handlers/admin/listSubscriptions.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
    });
    const extendSubscription = new lambdaNode.NodejsFunction(this, 'ExtendSubscriptionFn', {
      entry: 'lambda/handlers/admin/extendSubscription.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
    });
    const reactivateSubscription = new lambdaNode.NodejsFunction(this, 'ReactivateSubscriptionFn', {
      entry: 'lambda/handlers/admin/reactivateSubscription.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
    });
    const createSubscriptionType = new lambdaNode.NodejsFunction(this, 'CreateSubscriptionTypeFn', {
      entry: 'lambda/handlers/admin/createSubscriptionType.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
    });
    const listSubscriptionTypes = new lambdaNode.NodejsFunction(this, 'ListSubscriptionTypesFn', {
      entry: 'lambda/handlers/admin/listSubscriptionTypes.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
    });
    const enableSubscriptionType = new lambdaNode.NodejsFunction(this, 'EnableSubscriptionTypeFn', {
      entry: 'lambda/handlers/admin/enableSubscriptionType.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
    });
    const disableSubscriptionType = new lambdaNode.NodejsFunction(this, 'DisableSubscriptionTypeFn', {
      entry: 'lambda/handlers/admin/disableSubscriptionType.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
    });
    const listWaitlist = new lambdaNode.NodejsFunction(this, 'ListWaitlistFn', {
      entry: 'lambda/handlers/admin/listWaitlist.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: { ...defaultEnv, TABLE_WAITLIST: waitlist.tableName },
    });
    const sendWaitlistInvites = new lambdaNode.NodejsFunction(this, 'SendWaitlistInvitesFn', {
      entry: 'lambda/handlers/admin/sendWaitlistInvites.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        TABLE_WAITLIST: waitlist.tableName,
        SES_FROM_EMAIL: 'noreply@vettid.dev',
      },
      timeout: cdk.Duration.seconds(30),
    });
    const deleteWaitlistEntries = new lambdaNode.NodejsFunction(this, 'DeleteWaitlistEntriesFn', {
      entry: 'lambda/handlers/admin/deleteWaitlistEntries.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: { ...defaultEnv, TABLE_WAITLIST: waitlist.tableName },
    });
    const submitVote = new lambdaNode.NodejsFunction(this, 'SubmitVoteFn', {
      entry: 'lambda/handlers/member/submitVote.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
    });
    const getVotingHistory = new lambdaNode.NodejsFunction(this, 'GetVotingHistoryFn', {
      entry: 'lambda/handlers/member/getVotingHistory.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
    });
    const getProposalResults = new lambdaNode.NodejsFunction(this, 'GetProposalResultsFn', {
      entry: 'lambda/handlers/member/getProposalResults.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
    });
    const getActiveProposals = new lambdaNode.NodejsFunction(this, 'GetActiveProposalsFn', {
      entry: 'lambda/handlers/member/getActiveProposals.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
    });
    const getAllProposals = new lambdaNode.NodejsFunction(this, 'GetAllProposalsFn', {
      entry: 'lambda/handlers/member/getAllProposals.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
    });
    const getMemberProposalVoteCounts = new lambdaNode.NodejsFunction(this, 'GetMemberProposalVoteCountsFn', {
      entry: 'lambda/handlers/member/getProposalVoteCounts.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
    });
    const getProposalVoteCounts = new lambdaNode.NodejsFunction(this, 'GetProposalVoteCountsFn', {
      entry: 'lambda/handlers/admin/getProposalVoteCounts.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
    });
    const closeExpiredProposals = new lambdaNode.NodejsFunction(this, 'CloseExpiredProposalsFn', {
      entry: 'lambda/handlers/scheduled/closeExpiredProposals.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(60), // Allow time for scanning and updating multiple proposals
    });
    const checkSubscriptionExpiry = new lambdaNode.NodejsFunction(this, 'CheckSubscriptionExpiryFn', {
      entry: 'lambda/handlers/admin/checkSubscriptionExpiry.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(60), // Allow time for processing multiple subscriptions
    });
    const createMembershipTerms = new lambdaNode.NodejsFunction(this, 'CreateMembershipTermsFn', {
      entry: 'lambda/handlers/admin/createMembershipTerms.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(30), // PDF generation may take some time
      bundling: {
        nodeModules: ['pdfkit'], // Include pdfkit in bundle
      },
    });
    const getCurrentMembershipTerms = new lambdaNode.NodejsFunction(this, 'GetCurrentMembershipTermsFn', {
      entry: 'lambda/handlers/admin/getCurrentMembershipTerms.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
    });
    const listMembershipTerms = new lambdaNode.NodejsFunction(this, 'ListMembershipTermsFn', {
      entry: 'lambda/handlers/admin/listMembershipTerms.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
    });

    // Custom resource to ensure default membership terms exist
    const ensureDefaultMembershipTerms = new lambdaNode.NodejsFunction(this, 'EnsureDefaultMembershipTermsFn', {
      entry: 'lambda/handlers/custom/ensureDefaultMembershipTerms.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      timeout: cdk.Duration.minutes(2), // PDF generation may take time
      environment: {
        TABLE_MEMBERSHIP_TERMS: membershipTerms.tableName,
        TERMS_BUCKET: termsBucket.bucketName,
      },
    });

    // Grant permissions for custom resource
    membershipTerms.grantReadWriteData(ensureDefaultMembershipTerms);
    termsBucket.grantReadWrite(ensureDefaultMembershipTerms);

    // Create custom resource provider
    const defaultTermsProvider = new cr.Provider(this, 'DefaultMembershipTermsProvider', {
      onEventHandler: ensureDefaultMembershipTerms,
    });

    // Trigger custom resource on stack create/update
    new cdk.CustomResource(this, 'DefaultMembershipTermsResource', {
      serviceToken: defaultTermsProvider.serviceToken,
      properties: {
        TableName: membershipTerms.tableName,
        BucketName: termsBucket.bucketName,
        // Update this timestamp to re-trigger the custom resource if needed
        Timestamp: new Date().toISOString(),
      },
    });

    // ===== VAULT SERVICE LAMBDAS =====

    // Enrollment endpoints (public - no auth required)
    const enrollStart = new lambdaNode.NodejsFunction(this, 'EnrollStartFn', {
      entry: 'lambda/handlers/vault/enrollStart.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: vaultEnv,
      timeout: cdk.Duration.seconds(30), // Key generation takes time
    });

    const enrollSetPassword = new lambdaNode.NodejsFunction(this, 'EnrollSetPasswordFn', {
      entry: 'lambda/handlers/vault/enrollSetPassword.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: vaultEnv,
      timeout: cdk.Duration.seconds(10),
    });

    const enrollFinalize = new lambdaNode.NodejsFunction(this, 'EnrollFinalizeFn', {
      entry: 'lambda/handlers/vault/enrollFinalize.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: vaultEnv,
      timeout: cdk.Duration.seconds(30), // Credential creation takes time
    });

    // Action request endpoint (member auth required)
    // Note: JWT_SIGNING_KEY should be set in the handler code itself from AWS Secrets Manager
    // The handler has a placeholder that should be replaced with Secrets Manager lookup in production
    const actionRequest = new lambdaNode.NodejsFunction(this, 'ActionRequestFn', {
      entry: 'lambda/handlers/vault/actionRequest.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: vaultEnv,
      timeout: cdk.Duration.seconds(10),
    });

    // Auth execute endpoint (action token auth - Bearer token)
    const authExecute = new lambdaNode.NodejsFunction(this, 'AuthExecuteFn', {
      entry: 'lambda/handlers/vault/authExecute.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: vaultEnv,
      timeout: cdk.Duration.seconds(30), // Credential rotation takes time
    });

    // Grants
    invites.grantReadWriteData(submitRegistration);
    invites.grantReadWriteData(createInvite);
    invites.grantReadData(listInvites);
    invites.grantReadWriteData(expireInvite);
    invites.grantReadWriteData(deleteInvite);
    registrations.grantReadWriteData(submitRegistration);
    registrations.grantReadWriteData(listRegistrations);
    waitlist.grantReadWriteData(submitWaitlist);
    registrations.grantReadWriteData(approveRegistration);
    registrations.grantReadWriteData(rejectRegistration);
    registrations.grantReadWriteData(disableUser);
    registrations.grantReadWriteData(deleteUser);
    registrations.grantReadWriteData(enableUser);
    registrations.grantReadWriteData(permanentlyDeleteUser);
    subscriptions.grantReadWriteData(permanentlyDeleteUser);
    registrations.grantReadWriteData(cancelAccount);
    subscriptions.grantReadWriteData(cancelAccount);
    registrations.grantReadWriteData(cleanupExpiredAccounts);
    registrations.grantReadWriteData(enablePin);
    registrations.grantReadWriteData(disablePin);
    registrations.grantReadWriteData(updatePin);
    registrations.grantReadData(getPinStatus);
    audit.grantReadData(getEmailPreferences);
    audit.grantReadWriteData(updateEmailPreferences);
    registrations.grantStreamRead(registrationStreamFn);
    proposals.grantStreamRead(proposalStreamFn); // Read proposal stream events
    subscriptions.grantReadData(proposalStreamFn); // Query active subscriptions
    registrations.grantReadData(proposalStreamFn); // Get user emails
    audit.grantReadData(proposalStreamFn); // Check email preferences
    audit.grantReadWriteData(submitRegistration);
    audit.grantReadWriteData(approveRegistration);
    audit.grantReadWriteData(createInvite);
    audit.grantReadWriteData(listRegistrations);
    audit.grantReadWriteData(registrationStreamFn);
    audit.grantReadWriteData(rejectRegistration);
    audit.grantReadWriteData(disableUser);
    audit.grantReadWriteData(deleteUser);
    audit.grantReadWriteData(enableUser);
    audit.grantReadWriteData(permanentlyDeleteUser);
    audit.grantReadWriteData(expireInvite);
    audit.grantReadWriteData(deleteInvite);
    audit.grantReadWriteData(addAdmin);
    audit.grantReadWriteData(removeAdmin);
    audit.grantReadWriteData(disableAdmin);
    audit.grantReadWriteData(enableAdmin);
    audit.grantReadWriteData(updateAdminType);
    audit.grantReadWriteData(cancelAccount);
    audit.grantReadWriteData(cleanupExpiredAccounts);
    audit.grantReadWriteData(enablePin);
    audit.grantReadWriteData(disablePin);
    audit.grantReadWriteData(updatePin);
    registrations.grantReadWriteData(requestMembership);
    registrations.grantReadData(getMembershipStatus);
    registrations.grantReadData(listMembershipRequests);
    registrations.grantReadWriteData(approveMembership);
    registrations.grantReadWriteData(denyMembership);
    audit.grantReadWriteData(requestMembership);
    audit.grantReadWriteData(approveMembership);
    audit.grantReadWriteData(denyMembership);
    membershipTerms.grantReadWriteData(createMembershipTerms);
    membershipTerms.grantReadData(getCurrentMembershipTerms);
    membershipTerms.grantReadData(listMembershipTerms);
    membershipTerms.grantReadData(getMembershipTerms);
    termsBucket.grantReadWrite(createMembershipTerms);
    termsBucket.grantRead(getCurrentMembershipTerms);
    termsBucket.grantRead(listMembershipTerms);
    termsBucket.grantRead(getMembershipTerms);
    subscriptions.grantReadWriteData(createSubscription);
    subscriptions.grantReadWriteData(getSubscriptionStatus);
    subscriptions.grantReadWriteData(cancelSubscription);
    subscriptionTypes.grantReadData(createSubscription);
    audit.grantReadWriteData(createSubscription);
    audit.grantReadWriteData(cancelSubscription);
    proposals.grantReadWriteData(createProposal);
    proposals.grantReadData(listProposals);
    proposals.grantReadWriteData(suspendProposal);
    audit.grantReadWriteData(createProposal);
    audit.grantReadWriteData(suspendProposal);
    subscriptions.grantReadData(listSubscriptions);
    registrations.grantReadData(listSubscriptions);
    audit.grantReadData(listSubscriptions);
    subscriptions.grantReadWriteData(extendSubscription);
    subscriptions.grantReadWriteData(reactivateSubscription);
    audit.grantReadWriteData(extendSubscription);
    audit.grantReadWriteData(reactivateSubscription);
    votes.grantReadWriteData(submitVote);
    proposals.grantReadData(submitVote);
    registrations.grantReadData(submitVote);
    audit.grantReadWriteData(submitVote);
    votes.grantReadData(getVotingHistory);
    proposals.grantReadData(getVotingHistory);
    registrations.grantReadData(getVotingHistory);
    votes.grantReadData(getProposalResults);
    proposals.grantReadData(getProposalResults);
    proposals.grantReadData(getActiveProposals);
    proposals.grantReadData(getAllProposals);
    votes.grantReadData(getMemberProposalVoteCounts);
    proposals.grantReadData(getMemberProposalVoteCounts);
    votes.grantReadData(getProposalVoteCounts);
    proposals.grantReadData(getProposalVoteCounts);
    proposals.grantReadWriteData(closeExpiredProposals); // Scheduled job to close expired proposals
    subscriptions.grantReadWriteData(checkSubscriptionExpiry); // For marking notifications sent
    registrations.grantReadData(checkSubscriptionExpiry); // For getting user details
    audit.grantReadWriteData(checkSubscriptionExpiry); // For checking email prefs and logging
    checkSubscriptionExpiry.addToRolePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['ses:SendTemplatedEmail'],
      resources: ['*'],
    }));
    subscriptionTypes.grantReadWriteData(createSubscriptionType);
    subscriptionTypes.grantReadData(listSubscriptionTypes);
    subscriptionTypes.grantReadData(listEnabledSubscriptionTypes);
    audit.grantReadData(listEnabledSubscriptionTypes);
    subscriptionTypes.grantReadWriteData(enableSubscriptionType);
    subscriptionTypes.grantReadWriteData(disableSubscriptionType);
    audit.grantReadWriteData(createSubscriptionType);
    audit.grantReadWriteData(enableSubscriptionType);
    audit.grantReadWriteData(disableSubscriptionType);
    waitlist.grantReadData(listWaitlist);
    waitlist.grantReadWriteData(sendWaitlistInvites);
    waitlist.grantReadWriteData(deleteWaitlistEntries);
    invites.grantReadWriteData(sendWaitlistInvites);
    audit.grantReadWriteData(sendWaitlistInvites);
    audit.grantReadWriteData(deleteWaitlistEntries);

    // ===== VAULT SERVICE GRANTS =====
    // enrollStart grants
    invites.grantReadWriteData(enrollStart);
    enrollmentSessions.grantReadWriteData(enrollStart);
    transactionKeys.grantReadWriteData(enrollStart);
    audit.grantReadWriteData(enrollStart);

    // enrollSetPassword grants
    enrollmentSessions.grantReadWriteData(enrollSetPassword);
    transactionKeys.grantReadWriteData(enrollSetPassword);
    audit.grantReadWriteData(enrollSetPassword);

    // enrollFinalize grants
    enrollmentSessions.grantReadWriteData(enrollFinalize);
    invites.grantReadWriteData(enrollFinalize);
    credentials.grantReadWriteData(enrollFinalize);
    credentialKeys.grantReadWriteData(enrollFinalize);
    ledgerAuthTokens.grantReadWriteData(enrollFinalize);
    transactionKeys.grantReadData(enrollFinalize);
    audit.grantReadWriteData(enrollFinalize);

    // actionRequest grants
    credentials.grantReadData(actionRequest);
    ledgerAuthTokens.grantReadData(actionRequest);
    transactionKeys.grantReadData(actionRequest);
    actionTokens.grantReadWriteData(actionRequest);
    audit.grantReadWriteData(actionRequest);

    // authExecute grants
    actionTokens.grantReadWriteData(authExecute);
    credentials.grantReadWriteData(authExecute);
    credentialKeys.grantReadWriteData(authExecute);
    transactionKeys.grantReadWriteData(authExecute);
    ledgerAuthTokens.grantReadWriteData(authExecute);
    audit.grantReadWriteData(authExecute);

    // SES permissions scoped to specific identity and region
    const sesIdentityArn = `arn:aws:ses:${this.region}:${this.account}:identity/*`;
    const sesConfigSetArn = `arn:aws:ses:${this.region}:${this.account}:configuration-set/*`;
    const sesTemplateArn = `arn:aws:ses:${this.region}:${this.account}:template/*`;

    [submitRegistration, listRegistrations, approveRegistration, createInvite, registrationStreamFn, sendWaitlistInvites].forEach((fn) => {
      fn.addToRolePolicy(new iam.PolicyStatement({
        actions: ['ses:SendTemplatedEmail', 'ses:SendEmail'],
        resources: [sesIdentityArn, sesTemplateArn, sesConfigSetArn]
      }));
    });
    // Cognito permissions scoped to specific User Pools
    const memberUserPoolArn = memberUserPool.userPoolArn;
    const adminUserPoolArn = adminUserPool.userPoolArn;

    submitRegistration.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['cognito-idp:AdminCreateUser', 'cognito-idp:AdminAddUserToGroup', 'cognito-idp:AdminGetUser', 'cognito-idp:AdminSetUserPassword'],
        resources: [memberUserPoolArn],
      }),
    );
    // SES permission to verify email identities for marketing consent
    submitRegistration.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['ses:VerifyEmailIdentity', 'ses:GetIdentityVerificationAttributes'],
        resources: ['*'], // These SES actions don't support resource-level permissions
      }),
    );
    // SES permission for waitlist email verification
    submitWaitlist.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['ses:VerifyEmailIdentity'],
        resources: ['*'], // VerifyEmailIdentity doesn't support resource-level permissions
      }),
    );
    approveRegistration.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['cognito-idp:AdminCreateUser', 'cognito-idp:AdminAddUserToGroup', 'cognito-idp:AdminGetUser', 'cognito-idp:AdminSetUserPassword'],
        resources: [memberUserPoolArn],
      }),
    );
    listRegistrations.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['cognito-idp:AdminGetUser', 'cognito-idp:AdminListGroupsForUser'],
        resources: [memberUserPoolArn],
      }),
    );
    requestMembership.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['cognito-idp:AdminAddUserToGroup', 'cognito-idp:AdminGetUser'],
        resources: [memberUserPoolArn],
      }),
    );
    approveMembership.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['cognito-idp:AdminAddUserToGroup'],
        resources: [memberUserPoolArn],
      }),
    );
    disableUser.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['cognito-idp:AdminDisableUser', 'cognito-idp:AdminGetUser'],
        resources: [memberUserPoolArn],
      }),
    );
    deleteUser.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['cognito-idp:AdminDeleteUser', 'cognito-idp:AdminDisableUser', 'cognito-idp:AdminGetUser'],
        resources: [memberUserPoolArn],
      }),
    );
    enableUser.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['cognito-idp:AdminEnableUser', 'cognito-idp:AdminGetUser'],
        resources: [memberUserPoolArn],
      }),
    );
    cancelAccount.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['cognito-idp:AdminDisableUser', 'cognito-idp:AdminGetUser'],
        resources: [memberUserPoolArn],
      }),
    );
    cleanupExpiredAccounts.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['cognito-idp:AdminDeleteUser'],
        resources: [memberUserPoolArn],
      }),
    );
    permanentlyDeleteUser.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['cognito-idp:AdminDeleteUser', 'cognito-idp:AdminGetUser'],
        resources: [memberUserPoolArn],
      }),
    );
    listAdmins.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['cognito-idp:ListUsersInGroup'],
        resources: [adminUserPoolArn],
      }),
    );
    addAdmin.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['cognito-idp:AdminCreateUser', 'cognito-idp:AdminAddUserToGroup', 'cognito-idp:AdminGetUser'],
        resources: [adminUserPoolArn],
      }),
    );
    removeAdmin.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['cognito-idp:AdminRemoveUserFromGroup', 'cognito-idp:AdminGetUser', 'cognito-idp:AdminDeleteUser'],
        resources: [adminUserPoolArn],
      }),
    );
    disableAdmin.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['cognito-idp:AdminDisableUser', 'cognito-idp:AdminGetUser'],
        resources: [adminUserPoolArn],
      }),
    );
    enableAdmin.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['cognito-idp:AdminEnableUser', 'cognito-idp:AdminGetUser'],
        resources: [adminUserPoolArn],
      }),
    );
    updateAdminType.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['cognito-idp:AdminUpdateUserAttributes', 'cognito-idp:AdminGetUser'],
        resources: [adminUserPoolArn],
      }),
    );
    changePassword.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['cognito-idp:AdminInitiateAuth'],
        resources: [adminUserPoolArn],
      }),
    );
    resetAdminPassword.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['cognito-idp:AdminSetUserPassword', 'cognito-idp:AdminGetUser'],
        resources: [adminUserPoolArn],
      }),
    );
    resetAdminPassword.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['ses:SendEmail'],
        resources: [sesIdentityArn],
      }),
    );

    // Streams → Lambda
    registrationStreamFn.addEventSource(
      new lambdaEventSources.DynamoEventSource(registrations, {
        startingPosition: lambda.StartingPosition.LATEST,
        batchSize: 10,
        bisectBatchOnError: true,
        retryAttempts: 3,
        reportBatchItemFailures: true, // Enable partial batch response for granular retry control
      }),
    );

    proposalStreamFn.addEventSource(
      new lambdaEventSources.DynamoEventSource(proposals, {
        startingPosition: lambda.StartingPosition.LATEST,
        batchSize: 10,
        bisectBatchOnError: true,
        retryAttempts: 3,
      }),
    );

    // API Gateway + authorizers
    const httpApi = new apigw.HttpApi(this, 'Api', {
      corsPreflight: {
        allowMethods: [apigw.CorsHttpMethod.GET, apigw.CorsHttpMethod.POST, apigw.CorsHttpMethod.PUT, apigw.CorsHttpMethod.DELETE, apigw.CorsHttpMethod.OPTIONS],
        allowOrigins: [
          'https://vettid.dev',
          'https://www.vettid.dev',
          'https://admin.vettid.dev',
          'https://account.vettid.dev',
          'https://register.vettid.dev'
        ],
        allowHeaders: ['Authorization', 'Content-Type', 'X-Amz-Date', 'X-Api-Key', 'X-Amz-Security-Token'],
      },
    });

    // Separate authorizers for admin and member user pools
    const adminAuthorizer = new authorizers.HttpUserPoolAuthorizer('AdminAuthorizer', adminUserPool, {
      userPoolClients: [adminAppClient]
    });
    const memberAuthorizer = new authorizers.HttpUserPoolAuthorizer('MemberAuthorizer', memberUserPool, {
      userPoolClients: [memberAppClient]
    });

    // Protection strategies implemented:
    // 1. WAF on CloudFront with rate limiting (100 req/5min), OWASP Top 10, IP reputation
    // 2. API Gateway throttling (200 burst, 100 RPS)
    // 3. Lambda timeout (10s) prevents long-running requests
    // 4. Email GSI prevents expensive table scans
    // 5. Cognito duplicate user check before registration
    // 6. CloudWatch alarms for monitoring suspicious activity

    // Add /register route
    httpApi.addRoutes({
      path: '/register',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('SubmitRegInt', submitRegistration),
    });

    // Add /waitlist route
    httpApi.addRoutes({
      path: '/waitlist',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('SubmitWaitlistInt', submitWaitlist),
    });

    httpApi.addRoutes({
      path: '/admin/registrations',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('ListRegsInt', listRegistrations),
      authorizer: adminAuthorizer,
    });
    httpApi.addRoutes({
      path: '/admin/registrations/{id}/approve',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('ApproveRegInt', approveRegistration),
      authorizer: adminAuthorizer,
    });
    httpApi.addRoutes({
      path: '/admin/registrations/{id}/reject',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('RejectRegInt', rejectRegistration),
      authorizer: adminAuthorizer,
    });
    httpApi.addRoutes({
      path: '/admin/invites',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('CreateInviteInt', createInvite),
      authorizer: adminAuthorizer,
    });
    httpApi.addRoutes({
      path: '/admin/invites',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('ListInvitesInt', listInvites),
      authorizer: adminAuthorizer,
    });
    httpApi.addRoutes({
      path: '/admin/invites/{code}/expire',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('ExpireInviteInt', expireInvite),
      authorizer: adminAuthorizer,
    });
    httpApi.addRoutes({
      path: '/admin/invites/{code}',
      methods: [apigw.HttpMethod.DELETE],
      integration: new integrations.HttpLambdaIntegration('DeleteInviteInt', deleteInvite),
      authorizer: adminAuthorizer,
    });
    httpApi.addRoutes({
      path: '/admin/users/{id}/disable',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('DisableUserInt', disableUser),
      authorizer: adminAuthorizer,
    });
    httpApi.addRoutes({
      path: '/admin/users/{id}',
      methods: [apigw.HttpMethod.DELETE],
      integration: new integrations.HttpLambdaIntegration('DeleteUserInt', deleteUser),
      authorizer: adminAuthorizer,
    });
    httpApi.addRoutes({
      path: '/admin/users/{id}/enable',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('EnableUserInt', enableUser),
      authorizer: adminAuthorizer,
    });
    httpApi.addRoutes({
      path: '/admin/users/{id}/permanently-delete',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('PermanentlyDeleteUserInt', permanentlyDeleteUser),
      authorizer: adminAuthorizer,
    });
    httpApi.addRoutes({
      path: '/admin/admins',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('ListAdminsInt', listAdmins),
      authorizer: adminAuthorizer,
    });
    httpApi.addRoutes({
      path: '/admin/admins',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('AddAdminInt', addAdmin),
      authorizer: adminAuthorizer,
    });
    httpApi.addRoutes({
      path: '/admin/admins/{email}',
      methods: [apigw.HttpMethod.DELETE],
      integration: new integrations.HttpLambdaIntegration('RemoveAdminInt', removeAdmin),
      authorizer: adminAuthorizer,
    });
    httpApi.addRoutes({
      path: '/admin/admins/{email}/disable',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('DisableAdminInt', disableAdmin),
      authorizer: adminAuthorizer,
    });
    httpApi.addRoutes({
      path: '/admin/admins/{email}/enable',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('EnableAdminInt', enableAdmin),
      authorizer: adminAuthorizer,
    });
    httpApi.addRoutes({
      path: '/admin/admins/{email}/type',
      methods: [apigw.HttpMethod.PUT],
      integration: new integrations.HttpLambdaIntegration('UpdateAdminTypeInt', updateAdminType),
      authorizer: adminAuthorizer,
    });
    httpApi.addRoutes({
      path: '/admin/change-password',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('ChangePasswordInt', changePassword),
      authorizer: adminAuthorizer,
    });
    httpApi.addRoutes({
      path: '/admin/admins/{email}/reset-password',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('ResetAdminPasswordInt', resetAdminPassword),
      authorizer: adminAuthorizer,
    });
    httpApi.addRoutes({
      path: '/account/cancel',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('CancelAccountInt', cancelAccount),
      authorizer: memberAuthorizer,
    });
    httpApi.addRoutes({
      path: '/account/security/pin/enable',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('EnablePinInt', enablePin),
      authorizer: memberAuthorizer,
    });
    httpApi.addRoutes({
      path: '/account/security/pin/disable',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('DisablePinInt', disablePin),
      authorizer: memberAuthorizer,
    });
    httpApi.addRoutes({
      path: '/account/security/pin/update',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('UpdatePinInt', updatePin),
      authorizer: memberAuthorizer,
    });
    httpApi.addRoutes({
      path: '/account/security/pin/status',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('GetPinStatusInt', getPinStatus),
      authorizer: memberAuthorizer,
    });
    httpApi.addRoutes({
      path: '/account/email-preferences',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('GetEmailPreferencesInt', getEmailPreferences),
      authorizer: memberAuthorizer,
    });
    httpApi.addRoutes({
      path: '/account/email-preferences',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('UpdateEmailPreferencesInt', updateEmailPreferences),
      authorizer: memberAuthorizer,
    });
    httpApi.addRoutes({
      path: '/account/membership/request',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('RequestMembershipInt', requestMembership),
      authorizer: memberAuthorizer,
    });
    httpApi.addRoutes({
      path: '/account/membership/status',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('GetMembershipStatusInt', getMembershipStatus),
      authorizer: memberAuthorizer,
    });
    httpApi.addRoutes({
      path: '/account/membership/terms',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('GetMembershipTermsInt', getMembershipTerms),
      authorizer: memberAuthorizer,
    });
    httpApi.addRoutes({
      path: '/account/subscriptions',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('CreateSubscriptionInt', createSubscription),
      authorizer: memberAuthorizer,
    });
    httpApi.addRoutes({
      path: '/account/subscriptions/status',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('GetSubscriptionStatusInt', getSubscriptionStatus),
      authorizer: memberAuthorizer,
    });
    httpApi.addRoutes({
      path: '/account/subscriptions/cancel',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('CancelSubscriptionInt', cancelSubscription),
      authorizer: memberAuthorizer,
    });
    httpApi.addRoutes({
      path: '/account/subscription-types',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('ListEnabledSubscriptionTypesInt', listEnabledSubscriptionTypes),
      authorizer: memberAuthorizer,
    });
    httpApi.addRoutes({
      path: '/admin/memberships',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('ListMembershipRequestsInt', listMembershipRequests),
      authorizer: adminAuthorizer,
    });
    httpApi.addRoutes({
      path: '/admin/memberships/{id}/approve',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('ApproveMembershipInt', approveMembership),
      authorizer: adminAuthorizer,
    });
    httpApi.addRoutes({
      path: '/admin/memberships/{id}/deny',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('DenyMembershipInt', denyMembership),
      authorizer: adminAuthorizer,
    });
    httpApi.addRoutes({
      path: '/admin/membership-terms',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('CreateMembershipTermsInt', createMembershipTerms),
      authorizer: adminAuthorizer,
    });
    httpApi.addRoutes({
      path: '/admin/membership-terms/current',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('GetCurrentMembershipTermsInt', getCurrentMembershipTerms),
      authorizer: adminAuthorizer,
    });
    httpApi.addRoutes({
      path: '/admin/membership-terms',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('ListMembershipTermsInt', listMembershipTerms),
      authorizer: adminAuthorizer,
    });
    httpApi.addRoutes({
      path: '/admin/proposals',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('CreateProposalInt', createProposal),
      authorizer: adminAuthorizer,
    });
    httpApi.addRoutes({
      path: '/admin/proposals',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('ListProposalsInt', listProposals),
      authorizer: adminAuthorizer,
    });
    httpApi.addRoutes({
      path: '/admin/proposals/{proposal_id}/suspend',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('SuspendProposalInt', suspendProposal),
      authorizer: adminAuthorizer,
    });
    httpApi.addRoutes({
      path: '/admin/proposals/{proposal_id}/votes',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('GetProposalVoteCountsInt', getProposalVoteCounts),
      authorizer: adminAuthorizer,
    });
    httpApi.addRoutes({
      path: '/admin/subscriptions',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('ListSubscriptionsInt', listSubscriptions),
      authorizer: adminAuthorizer,
    });
    httpApi.addRoutes({
      path: '/admin/subscription-types',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('CreateSubscriptionTypeInt', createSubscriptionType),
      authorizer: adminAuthorizer,
    });
    httpApi.addRoutes({
      path: '/admin/subscription-types',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('ListSubscriptionTypesInt', listSubscriptionTypes),
      authorizer: adminAuthorizer,
    });
    httpApi.addRoutes({
      path: '/admin/subscription-types/{subscription_type_id}/enable',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('EnableSubscriptionTypeInt', enableSubscriptionType),
      authorizer: adminAuthorizer,
    });
    httpApi.addRoutes({
      path: '/admin/subscription-types/{subscription_type_id}/disable',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('DisableSubscriptionTypeInt', disableSubscriptionType),
      authorizer: adminAuthorizer,
    });
    httpApi.addRoutes({
      path: '/admin/subscriptions/bulk-extend',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('BulkExtendSubscriptionsInt', extendSubscription),
      authorizer: adminAuthorizer,
    });
    httpApi.addRoutes({
      path: '/admin/subscriptions/{user_guid}/extend',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('ExtendSubscriptionInt', extendSubscription),
      authorizer: adminAuthorizer,
    });
    httpApi.addRoutes({
      path: '/admin/subscriptions/{user_guid}/reactivate',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('ReactivateSubscriptionInt', reactivateSubscription),
      authorizer: adminAuthorizer,
    });
    httpApi.addRoutes({
      path: '/admin/waitlist',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('ListWaitlistInt', listWaitlist),
      authorizer: adminAuthorizer,
    });
    httpApi.addRoutes({
      path: '/admin/waitlist/send-invites',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('SendWaitlistInvitesInt', sendWaitlistInvites),
      authorizer: adminAuthorizer,
    });
    httpApi.addRoutes({
      path: '/admin/waitlist/delete',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('DeleteWaitlistEntriesInt', deleteWaitlistEntries),
      authorizer: adminAuthorizer,
    });
    httpApi.addRoutes({
      path: '/votes',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('SubmitVoteInt', submitVote),
      authorizer: memberAuthorizer,
    });
    httpApi.addRoutes({
      path: '/votes/history',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('GetVotingHistoryInt', getVotingHistory),
      authorizer: memberAuthorizer,
    });
    httpApi.addRoutes({
      path: '/proposals/active',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('GetActiveProposalsInt', getActiveProposals),
      authorizer: memberAuthorizer,
    });
    httpApi.addRoutes({
      path: '/proposals',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('GetAllProposalsInt', getAllProposals),
      authorizer: memberAuthorizer,
    });
    httpApi.addRoutes({
      path: '/proposals/{proposal_id}/results',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('GetProposalResultsInt', getProposalResults),
      authorizer: memberAuthorizer,
    });
    httpApi.addRoutes({
      path: '/proposals/{proposal_id}/vote-counts',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('GetMemberProposalVoteCountsInt', getMemberProposalVoteCounts),
      authorizer: memberAuthorizer,
    });

    // ===== VAULT SERVICE ROUTES =====

    // Enrollment endpoints (public - no auth required for device enrollment)
    httpApi.addRoutes({
      path: '/api/v1/enroll/start',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('EnrollStartInt', enrollStart),
      // No authorizer - public endpoint for device enrollment with invitation code
    });
    httpApi.addRoutes({
      path: '/api/v1/enroll/set-password',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('EnrollSetPasswordInt', enrollSetPassword),
      // No authorizer - public endpoint, protected by enrollment session
    });
    httpApi.addRoutes({
      path: '/api/v1/enroll/finalize',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('EnrollFinalizeInt', enrollFinalize),
      // No authorizer - public endpoint, protected by enrollment session
    });

    // Action request endpoint (member auth required)
    httpApi.addRoutes({
      path: '/api/v1/action/request',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('ActionRequestInt', actionRequest),
      authorizer: memberAuthorizer,
    });

    // Auth execute endpoint (action token auth via Bearer token in header)
    httpApi.addRoutes({
      path: '/api/v1/auth/execute',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('AuthExecuteInt', authExecute),
      // No Cognito authorizer - uses scoped action token (Bearer) for auth
    });

    // API Gateway throttling (default stage)
    // Note: HTTP API v2 has account-level throttling by default (10,000 RPS burst, 5,000 RPS steady)
    // Additional per-route throttling can be configured via CfnStage
    const defaultStage = httpApi.defaultStage?.node.defaultChild as apigw.CfnStage;
    if (defaultStage) {
      defaultStage.defaultRouteSettings = {
        throttlingBurstLimit: 200,  // Max concurrent requests per IP
        throttlingRateLimit: 100,   // Max requests per second per IP
      };
    }

    // EventBridge scheduled rule to run cleanup Lambda daily at 2 AM UTC
    const cleanupRule = new events.Rule(this, 'DailyCleanupRule', {
      description: 'Daily cleanup of expired canceled accounts (7-day retention)',
      schedule: events.Schedule.cron({
        minute: '0',
        hour: '2', // 2 AM UTC
        day: '*',
        month: '*',
        year: '*'
      }),
    });
    cleanupRule.addTarget(new targets_events.LambdaFunction(cleanupExpiredAccounts));

    // EventBridge scheduled rule to close expired proposals every 15 minutes
    const closeProposalsRule = new events.Rule(this, 'CloseExpiredProposalsRule', {
      description: 'Close proposals that have passed their closes_at time',
      schedule: events.Schedule.rate(cdk.Duration.minutes(15)),
    });
    closeProposalsRule.addTarget(new targets_events.LambdaFunction(closeExpiredProposals));

    // EventBridge scheduled rule to check for subscriptions expiring in 48 hours - runs daily at 9 AM UTC
    const checkExpiryRule = new events.Rule(this, 'CheckSubscriptionExpiryRule', {
      description: 'Send notifications for subscriptions expiring in 48 hours',
      schedule: events.Schedule.cron({
        minute: '0',
        hour: '9', // 9 AM UTC
        day: '*',
        month: '*',
        year: '*'
      }),
    });
    checkExpiryRule.addTarget(new targets_events.LambdaFunction(checkSubscriptionExpiry));

    // SNS Topic for security alerts
    const securityAlertTopic = new sns.Topic(this, 'SecurityAlertTopic', {
      displayName: 'VettID Security Alerts',
      topicName: 'VettID-Security-Alerts',
    });

    // Output SNS topic ARN so admins can subscribe
    new cdk.CfnOutput(this, 'OutSecurityAlertTopicArn', {
      value: securityAlertTopic.topicArn,
      description: 'Subscribe to this SNS topic to receive security alerts',
    });

    // CloudWatch Alarms for security monitoring
    // Alarm: High rate of 4xx errors (could indicate scanning/probing)
    const highClientErrorsAlarm = new cloudwatch.Alarm(this, 'HighClientErrors', {
      alarmName: 'VettID-High-4xx-Errors',
      alarmDescription: 'Alert when 4xx error rate exceeds threshold (potential scanning activity)',
      metric: new cloudwatch.Metric({
        namespace: 'AWS/ApiGateway',
        metricName: '4XXError',
        dimensionsMap: {
          ApiId: httpApi.apiId,
        },
        statistic: 'Sum',
        period: cdk.Duration.minutes(5),
      }),
      threshold: 50,
      evaluationPeriods: 2,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
    });
    highClientErrorsAlarm.addAlarmAction(new cw_actions.SnsAction(securityAlertTopic));

    // Alarm: WAF blocked requests
    const wafBlockedAlarm = new cloudwatch.Alarm(this, 'WAFBlockedRequests', {
      alarmName: 'VettID-WAF-Blocked-Requests',
      alarmDescription: 'Alert when WAF blocks significant number of requests',
      metric: new cloudwatch.Metric({
        namespace: 'AWS/WAFV2',
        metricName: 'BlockedRequests',
        dimensionsMap: {
          WebACL: 'VettIDWebAcl',
          Region: 'CloudFront',
          Rule: 'ALL',
        },
        statistic: 'Sum',
        period: cdk.Duration.minutes(5),
      }),
      threshold: 100,
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
    });
    wafBlockedAlarm.addAlarmAction(new cw_actions.SnsAction(securityAlertTopic));

    // Alarm: Rate limit rule triggered
    const rateLimitAlarm = new cloudwatch.Alarm(this, 'RateLimitTriggered', {
      alarmName: 'VettID-Rate-Limit-Triggered',
      alarmDescription: 'Alert when rate limiting is blocking requests',
      metric: new cloudwatch.Metric({
        namespace: 'AWS/WAFV2',
        metricName: 'BlockedRequests',
        dimensionsMap: {
          WebACL: 'VettIDWebAcl',
          Region: 'CloudFront',
          Rule: 'RateLimitRule',
        },
        statistic: 'Sum',
        period: cdk.Duration.minutes(5),
      }),
      threshold: 10,
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
    });
    rateLimitAlarm.addAlarmAction(new cw_actions.SnsAction(securityAlertTopic));

    // Alarm: Failed login attempts
    const failedLoginAlarm = new cloudwatch.Alarm(this, 'FailedLoginAttempts', {
      alarmName: 'VettID-Failed-Login-Attempts',
      alarmDescription: 'Alert when failed magic link login attempts exceed threshold (potential attack)',
      metric: new cloudwatch.Metric({
        namespace: 'VettID/Authentication',
        metricName: 'FailedLoginAttempts',
        statistic: 'Sum',
        period: cdk.Duration.minutes(5),
      }),
      threshold: 10, // Alert if more than 10 failed login attempts in 5 minutes
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING, // No alarm if no failed attempts
    });
    failedLoginAlarm.addAlarmAction(new cw_actions.SnsAction(securityAlertTopic));

    // Outputs
    new cdk.CfnOutput(this, 'OutSiteBucket', { value: siteBucket.bucketName });
    new cdk.CfnOutput(this, 'OutLogBucket', { value: logBucket.bucketName });
    new cdk.CfnOutput(this, 'OutDistributionId', { value: rootDist.distributionId });
    new cdk.CfnOutput(this, 'OutAdminDistributionId', { value: adminDist.distributionId });
    new cdk.CfnOutput(this, 'OutApiUrl', { value: httpApi.apiEndpoint });

    // Member user pool outputs
    new cdk.CfnOutput(this, 'OutMemberCognitoDomain', { value: memberPoolDomain.baseUrl() });
    new cdk.CfnOutput(this, 'OutMemberUserPoolId', { value: memberUserPool.userPoolId });
    new cdk.CfnOutput(this, 'OutMemberClientId', { value: memberAppClient.userPoolClientId });

    // Admin user pool outputs
    new cdk.CfnOutput(this, 'OutAdminCognitoDomain', { value: adminPoolDomain.baseUrl() });
    new cdk.CfnOutput(this, 'OutAdminUserPoolId', { value: adminUserPool.userPoolId });
    new cdk.CfnOutput(this, 'OutAdminClientId', { value: adminAppClient.userPoolClientId });

    // URLs
    new cdk.CfnOutput(this, 'OutRegisterUrl', { value: 'https://vettid.dev/register' });
    new cdk.CfnOutput(this, 'OutAccountUrl', { value: 'https://vettid.dev/account' });
    new cdk.CfnOutput(this, 'OutAdminUrl', { value: 'https://admin.vettid.dev' });
  }
}

