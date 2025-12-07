import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import {
  aws_lambda_nodejs as lambdaNode,
  aws_lambda as lambda,
  aws_apigatewayv2 as apigw,
  aws_apigatewayv2_integrations as integrations,
  aws_iam as iam,
  aws_s3 as s3,
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
} from 'aws-cdk-lib';
import { InfrastructureStack } from './infrastructure-stack';

export interface VettIdStackProps extends cdk.StackProps {
  infrastructure: InfrastructureStack;
}

export class VettIdStack extends cdk.Stack {
  // Private properties for internal use
  private readonly httpApi: apigw.HttpApi;
  private readonly adminAuthorizer: apigw.IHttpRouteAuthorizer;
  private readonly memberAuthorizer: apigw.IHttpRouteAuthorizer;

  constructor(scope: Construct, id: string, props: VettIdStackProps) {
    super(scope, id, props);

    // Import resources from infrastructure stack
    const tables = props.infrastructure.tables;
    this.adminAuthorizer = props.infrastructure.adminAuthorizer;
    this.memberAuthorizer = props.infrastructure.memberAuthorizer;
    const adminUserPool = props.infrastructure.adminUserPool;
    const memberUserPool = props.infrastructure.memberUserPool;
    const adminAppClient = props.infrastructure.adminAppClient;
    const memberAppClient = props.infrastructure.memberAppClient;
    const memberPoolDomain = props.infrastructure.memberPoolDomain;
    const adminPoolDomain = props.infrastructure.adminPoolDomain;

    // ===== S3 BUCKETS =====

    // S3 bucket for CloudFront access logs with 90-day retention
    const logBucket = new s3.Bucket(this, 'CloudFrontLogBucket', {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_PREFERRED,
      encryption: s3.BucketEncryption.S3_MANAGED,
      lifecycleRules: [
        {
          id: 'DeleteOldLogs',
          enabled: true,
          expiration: cdk.Duration.days(90),
        },
      ],
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
    });

    // Main site bucket (CloudFront origin)
    const siteBucket = new s3.Bucket(this, 'SiteBucket', {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      versioned: true,
      encryption: s3.BucketEncryption.S3_MANAGED,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
    });

    // S3 buckets imported from infrastructure
    const termsBucket = props.infrastructure.termsBucket;

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
// Security headers function will be defined after HTTP API creation to inject specific API URL


// Route 53 hosted zone (existing)
const zone = route53.HostedZone.fromLookup(this, 'VettIdZone', { domainName: 'vettid.dev' });



// ACM certificate in us-east-1 for CloudFront (create via DNS validation)
// Note: Certificates in us-east-1 are required for CloudFront
const cert = new acm.Certificate(this, 'VettIdCert2025', {
  domainName: 'vettid.dev',
  subjectAlternativeNames: ['www.vettid.dev', 'admin.vettid.dev'],
  validation: acm.CertificateValidation.fromDns(zone),
});

// Use S3 buckets from infrastructure stack
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

    // ===== API GATEWAY (created early so security headers can reference endpoint) =====

    // HTTP API with CORS configuration
    this.httpApi = new apigw.HttpApi(this, 'Api', {
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

// CloudFront Function: Add security headers to all responses with specific API URL
const securityHeadersFn = new cloudfront.Function(this, 'SecurityHeadersFn', {
  code: cloudfront.FunctionCode.fromInline(`
// Version: 2025-11-29-20:40 - Force update to use current API endpoint
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
  // Specific API endpoint injected at synthesis time (no wildcard - security best practice)
  headers['content-security-policy'] = {
    value: "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://vettid.dev https://*.vettid.dev; style-src 'self' 'unsafe-inline' https://vettid.dev https://*.vettid.dev; img-src 'self' data: https://vettid.dev https://*.vettid.dev; font-src 'self' https://vettid.dev https://*.vettid.dev; connect-src 'self' ${this.httpApi.apiEndpoint} https://*.amazoncognito.com https://cognito-idp.us-east-1.amazonaws.com; frame-ancestors 'none'; form-action 'self' https://*.amazoncognito.com; base-uri 'self'; object-src 'none'; upgrade-insecure-requests;"
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


    // DynamoDB tables and S3 buckets are now imported from infrastructure stack
    // Access via: tables.invites, tables.registrations, etc.
    // Access via: siteBucket, logBucket, termsBucket
    // HTTP API is created early in the stack (before CloudFront) to allow CSP header injection

    // ===== LAMBDA FUNCTIONS =====

    // Lambda env
    const defaultEnv = {
      TABLE_INVITES: tables.invites.tableName,
      TABLE_REGISTRATIONS: tables.registrations.tableName,
      TABLE_AUDIT: tables.audit.tableName,
      TABLE_MEMBERSHIP_TERMS: tables.membershipTerms.tableName,
      TABLE_SUBSCRIPTIONS: tables.subscriptions.tableName,
      TABLE_PROPOSALS: tables.proposals.tableName,
      TABLE_VOTES: tables.votes.tableName,
      TABLE_SUBSCRIPTION_TYPES: tables.subscriptionTypes.tableName,
      TERMS_BUCKET: termsBucket.bucketName,
      SES_FROM: 'no-reply@auth.vettid.dev',
      CORS_ORIGIN: 'https://vettid.dev,https://www.vettid.dev,https://admin.vettid.dev,https://account.vettid.dev,https://register.vettid.dev',
      ALLOWED_ORIGINS: 'https://vettid.dev,https://www.vettid.dev,https://admin.vettid.dev,https://account.vettid.dev,https://register.vettid.dev',
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
      environment: {
        ...defaultEnv,
        TABLE_WAITLIST: tables.waitlist.tableName,
        TABLE_NOTIFICATION_PREFERENCES: tables.notificationPreferences.tableName,
        SES_FROM: 'no-reply@vettid.dev',
      },
      timeout: cdk.Duration.seconds(15), // Allow time for admin notifications
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
        TABLE_SUBSCRIPTIONS: tables.subscriptions.tableName,
        TABLE_REGISTRATIONS: tables.registrations.tableName,
      },
      timeout: cdk.Duration.seconds(60), // Allow time to send multiple emails
    });
    const cancelAccount = new lambdaNode.NodejsFunction(this, 'CancelAccountFn', {
      entry: 'lambda/handlers/member/cancelAccount.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: { ...defaultEnv, USER_POOL_ID: memberUserPool.userPoolId, TABLE_SUBSCRIPTIONS: tables.subscriptions.tableName },
      memorySize: 256,
      timeout: cdk.Duration.seconds(30),
      description: 'Cancel member account with 7-day grace period',
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
      memorySize: 256,
      timeout: cdk.Duration.seconds(30),
      description: 'Enable PIN for member account security',
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
    const verifyPin = new lambdaNode.NodejsFunction(this, 'VerifyPinFn', {
      entry: 'lambda/handlers/member/verifyPin.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      description: 'Verify PIN for member account login',
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
    const getGettingStartedPreference = new lambdaNode.NodejsFunction(this, 'GetGettingStartedPreferenceFn', {
      entry: 'lambda/handlers/member/getGettingStartedPreference.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
    });
    const updateGettingStartedPreference = new lambdaNode.NodejsFunction(this, 'UpdateGettingStartedPreferenceFn', {
      entry: 'lambda/handlers/member/updateGettingStartedPreference.ts',
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
    const closeExpiredProposals = new lambdaNode.NodejsFunction(this, 'CloseExpiredProposalsFn', {
      entry: 'lambda/handlers/scheduled/closeExpiredProposals.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(60), // Allow time for scanning and updating multiple proposals
    });

    // Grants
    tables.invites.grantReadWriteData(submitRegistration);
    tables.registrations.grantReadWriteData(submitRegistration);
    tables.waitlist.grantReadWriteData(submitWaitlist);
    tables.audit.grantReadWriteData(submitWaitlist); // For rate limiting
    tables.notificationPreferences.grantReadData(submitWaitlist); // For admin notifications
    tables.registrations.grantReadWriteData(cancelAccount);
    tables.subscriptions.grantReadWriteData(cancelAccount);
    tables.registrations.grantReadWriteData(cleanupExpiredAccounts);
    tables.registrations.grantReadWriteData(enablePin);
    tables.registrations.grantReadWriteData(disablePin);
    tables.registrations.grantReadWriteData(updatePin);
    tables.registrations.grantReadData(getPinStatus);
    tables.registrations.grantReadData(verifyPin);
    tables.audit.grantReadData(getEmailPreferences);
    tables.audit.grantReadWriteData(updateEmailPreferences);
    tables.audit.grantReadData(getGettingStartedPreference);
    tables.audit.grantReadWriteData(updateGettingStartedPreference);
    tables.registrations.grantStreamRead(registrationStreamFn);
    tables.proposals.grantStreamRead(proposalStreamFn); // Read proposal stream events
    tables.subscriptions.grantReadData(proposalStreamFn); // Query active subscriptions
    tables.registrations.grantReadData(proposalStreamFn); // Get user emails
    tables.audit.grantReadData(proposalStreamFn); // Check email preferences
    tables.audit.grantReadWriteData(submitRegistration);
    tables.audit.grantReadWriteData(registrationStreamFn);
    tables.audit.grantReadWriteData(cancelAccount);
    tables.audit.grantReadWriteData(cleanupExpiredAccounts);
    tables.audit.grantReadWriteData(enablePin);
    tables.audit.grantReadWriteData(disablePin);
    tables.audit.grantReadWriteData(updatePin);
    tables.audit.grantReadWriteData(verifyPin);
    tables.registrations.grantReadWriteData(requestMembership);
    tables.registrations.grantReadData(getMembershipStatus);
    tables.audit.grantReadWriteData(requestMembership);
    tables.membershipTerms.grantReadData(getMembershipTerms);
    termsBucket.grantRead(getMembershipTerms);
    tables.subscriptions.grantReadWriteData(createSubscription);
    tables.subscriptions.grantReadWriteData(getSubscriptionStatus);
    tables.subscriptions.grantReadWriteData(cancelSubscription);
    tables.subscriptionTypes.grantReadData(createSubscription);
    tables.registrations.grantReadData(createSubscription); // Validate membership status
    tables.audit.grantReadWriteData(createSubscription);
    tables.audit.grantReadWriteData(cancelSubscription);
    tables.votes.grantReadWriteData(submitVote);
    tables.proposals.grantReadData(submitVote);
    tables.registrations.grantReadData(submitVote);
    tables.audit.grantReadWriteData(submitVote);
    tables.votes.grantReadData(getVotingHistory);
    tables.proposals.grantReadData(getVotingHistory);
    tables.registrations.grantReadData(getVotingHistory);
    tables.votes.grantReadData(getProposalResults);
    tables.proposals.grantReadData(getProposalResults);
    tables.proposals.grantReadData(getActiveProposals);
    tables.proposals.grantReadData(getAllProposals);
    tables.votes.grantReadData(getMemberProposalVoteCounts);
    tables.proposals.grantReadData(getMemberProposalVoteCounts);
    tables.proposals.grantReadWriteData(closeExpiredProposals); // Scheduled job to close expired proposals
    tables.subscriptionTypes.grantReadData(listEnabledSubscriptionTypes);
    tables.audit.grantReadData(listEnabledSubscriptionTypes);

    // SES permissions scoped to specific identity and region
    const sesIdentityArn = `arn:aws:ses:${this.region}:${this.account}:identity/*`;
    const sesConfigSetArn = `arn:aws:ses:${this.region}:${this.account}:configuration-set/*`;
    const sesTemplateArn = `arn:aws:ses:${this.region}:${this.account}:template/*`;

    [submitRegistration, registrationStreamFn].forEach((fn) => {
      fn.addToRolePolicy(new iam.PolicyStatement({
        actions: ['ses:SendTemplatedEmail', 'ses:SendEmail'],
        resources: [sesIdentityArn, sesTemplateArn, sesConfigSetArn]
      }));
    });
    // Cognito permissions scoped to specific User Pools
    submitRegistration.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['cognito-idp:AdminCreateUser', 'cognito-idp:AdminAddUserToGroup', 'cognito-idp:AdminGetUser', 'cognito-idp:AdminSetUserPassword'],
        resources: [memberUserPool.userPoolArn],
      }),
    );
    // SES permission to verify email identities for marketing consent
    submitRegistration.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['ses:VerifyEmailIdentity', 'ses:GetIdentityVerificationAttributes'],
        resources: ['*'], // These SES actions don't support resource-level permissions
      }),
    );
    // SES permission for waitlist email verification and admin notifications
    submitWaitlist.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['ses:VerifyEmailIdentity', 'ses:SendEmail'],
        resources: ['*'], // VerifyEmailIdentity doesn't support resource-level permissions
      }),
    );
    requestMembership.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['cognito-idp:AdminAddUserToGroup', 'cognito-idp:AdminGetUser'],
        resources: [memberUserPool.userPoolArn],
      }),
    );
    cancelAccount.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['cognito-idp:AdminDisableUser', 'cognito-idp:AdminGetUser'],
        resources: [memberUserPool.userPoolArn],
      }),
    );
    cleanupExpiredAccounts.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['cognito-idp:AdminDeleteUser'],
        resources: [memberUserPool.userPoolArn],
      }),
    );

    // Streams → Lambda
    registrationStreamFn.addEventSource(
      new lambdaEventSources.DynamoEventSource(tables.registrations, {
        startingPosition: lambda.StartingPosition.LATEST,
        batchSize: 10,
        bisectBatchOnError: true,
        retryAttempts: 3,
        reportBatchItemFailures: true, // Enable partial batch response for granular retry control
      }),
    );

    proposalStreamFn.addEventSource(
      new lambdaEventSources.DynamoEventSource(tables.proposals, {
        startingPosition: lambda.StartingPosition.LATEST,
        batchSize: 10,
        bisectBatchOnError: true,
        retryAttempts: 3,
      }),
    );

    // Protection strategies implemented:
    // 1. WAF on CloudFront with rate limiting (100 req/5min), OWASP Top 10, IP reputation
    // 2. API Gateway throttling (200 burst, 100 RPS)
    // 3. Lambda timeout (10s) prevents long-running requests
    // 4. Email GSI prevents expensive table scans
    // 5. Cognito duplicate user check before registration
    // 6. CloudWatch alarms for monitoring suspicious activity

    // Add /register route
    this.httpApi.addRoutes({
      path: '/register',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('SubmitRegInt', submitRegistration),
    });

    // Add /waitlist route
    this.httpApi.addRoutes({
      path: '/waitlist',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('SubmitWaitlistInt', submitWaitlist),
    });

    this.httpApi.addRoutes({
      path: '/account/cancel',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('CancelAccountInt', cancelAccount),
      authorizer: this.memberAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/account/security/pin/enable',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('EnablePinInt', enablePin),
      authorizer: this.memberAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/account/security/pin/disable',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('DisablePinInt', disablePin),
      authorizer: this.memberAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/account/security/pin/update',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('UpdatePinInt', updatePin),
      authorizer: this.memberAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/account/security/pin/status',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('GetPinStatusInt', getPinStatus),
      authorizer: this.memberAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/account/security/pin/verify',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('VerifyPinInt', verifyPin),
      authorizer: this.memberAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/account/email-preferences',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('GetEmailPreferencesInt', getEmailPreferences),
      authorizer: this.memberAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/account/email-preferences',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('UpdateEmailPreferencesInt', updateEmailPreferences),
      authorizer: this.memberAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/account/getting-started-preference',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('GetGettingStartedPreferenceInt', getGettingStartedPreference),
      authorizer: this.memberAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/account/getting-started-preference',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('UpdateGettingStartedPreferenceInt', updateGettingStartedPreference),
      authorizer: this.memberAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/account/membership/request',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('RequestMembershipInt', requestMembership),
      authorizer: this.memberAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/account/membership/status',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('GetMembershipStatusInt', getMembershipStatus),
      authorizer: this.memberAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/account/membership/terms',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('GetMembershipTermsInt', getMembershipTerms),
      authorizer: this.memberAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/account/subscriptions',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('CreateSubscriptionInt', createSubscription),
      authorizer: this.memberAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/account/subscriptions/status',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('GetSubscriptionStatusInt', getSubscriptionStatus),
      authorizer: this.memberAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/account/subscriptions/cancel',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('CancelSubscriptionInt', cancelSubscription),
      authorizer: this.memberAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/account/subscription-types',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('ListEnabledSubscriptionTypesInt', listEnabledSubscriptionTypes),
      authorizer: this.memberAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/votes',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('SubmitVoteInt', submitVote),
      authorizer: this.memberAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/votes/history',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('GetVotingHistoryInt', getVotingHistory),
      authorizer: this.memberAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/proposals/active',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('GetActiveProposalsInt', getActiveProposals),
      authorizer: this.memberAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/proposals',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('GetAllProposalsInt', getAllProposals),
      authorizer: this.memberAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/proposals/{proposal_id}/results',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('GetProposalResultsInt', getProposalResults),
      authorizer: this.memberAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/proposals/{proposal_id}/vote-counts',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('GetMemberProposalVoteCountsInt', getMemberProposalVoteCounts),
      authorizer: this.memberAuthorizer,
    });

    // API Gateway throttling (default stage)
    // Note: HTTP API v2 has account-level throttling by default (10,000 RPS burst, 5,000 RPS steady)
    // Additional per-route throttling can be configured via CfnStage
    const defaultStage = this.httpApi.defaultStage?.node.defaultChild as apigw.CfnStage;
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
          ApiId: this.httpApi.apiId,
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
    new cdk.CfnOutput(this, 'OutApiUrl', { value: this.httpApi.apiEndpoint });

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
  /**
   * Add admin routes to the HTTP API
   * Called after AdminStack is instantiated to wire up admin Lambda functions
   */
  public addAdminRoutes(adminStack: any): void {
    // Registration Management
    this.httpApi.addRoutes({
      path: '/admin/registrations',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('ListRegistrationsInt', adminStack.listRegistrations),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/registrations/{registration_id}/approve',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('ApproveRegistrationInt', adminStack.approveRegistration),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/registrations/{registration_id}/reject',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('RejectRegistrationInt', adminStack.rejectRegistration),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/invites',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('CreateInviteInt', adminStack.createInvite),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/invites',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('ListInvitesInt', adminStack.listInvites),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/invites/{code}/expire',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('ExpireInviteInt', adminStack.expireInvite),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/invites/{code}',
      methods: [apigw.HttpMethod.DELETE],
      integration: new integrations.HttpLambdaIntegration('DeleteInviteInt', adminStack.deleteInvite),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/users/{user_id}/disable',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('DisableUserInt', adminStack.disableUser),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/users/{user_id}/enable',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('EnableUserInt', adminStack.enableUser),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/users/{user_id}',
      methods: [apigw.HttpMethod.DELETE],
      integration: new integrations.HttpLambdaIntegration('DeleteUserInt', adminStack.deleteUser),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/users/{user_id}/permanently-delete',
      methods: [apigw.HttpMethod.DELETE],
      integration: new integrations.HttpLambdaIntegration('PermanentlyDeleteUserInt', adminStack.permanentlyDeleteUser),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/admins',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('ListAdminsInt', adminStack.listAdmins),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/admins',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('AddAdminInt', adminStack.addAdmin),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/admins/{username}',
      methods: [apigw.HttpMethod.DELETE],
      integration: new integrations.HttpLambdaIntegration('RemoveAdminInt', adminStack.removeAdmin),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/admins/{username}/disable',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('DisableAdminInt', adminStack.disableAdmin),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/admins/{username}/enable',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('EnableAdminInt', adminStack.enableAdmin),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/admins/{username}/type',
      methods: [apigw.HttpMethod.PUT],
      integration: new integrations.HttpLambdaIntegration('UpdateAdminTypeInt', adminStack.updateAdminType),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/admins/{username}/reset-password',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('ResetAdminPasswordInt', adminStack.resetAdminPassword),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/change-password',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('ChangePasswordInt', adminStack.changePassword),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/mfa',
      methods: [apigw.HttpMethod.GET, apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('SetupMfaInt', adminStack.setupMfa),
      authorizer: this.adminAuthorizer,
    });

    // Pending Admin Invitation routes (2-step flow)
    this.httpApi.addRoutes({
      path: '/admin/pending-admins',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('ListPendingAdminsInt', adminStack.listPendingAdmins),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/pending-admins',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('InviteAdminInt', adminStack.inviteAdmin),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/pending-admins/{email}/activate',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('ActivateAdminInt', adminStack.activateAdmin),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/pending-admins/{email}',
      methods: [apigw.HttpMethod.DELETE],
      integration: new integrations.HttpLambdaIntegration('CancelPendingAdminInt', adminStack.cancelPendingAdmin),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/pending-admins/{email}/resend',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('ResendAdminVerificationInt', adminStack.resendAdminVerification),
      authorizer: this.adminAuthorizer,
    });

    // Membership request routes
    this.httpApi.addRoutes({
      path: '/admin/membership-requests',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('ListMembershipRequestsInt', adminStack.listMembershipRequests),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/membership-requests/{id}/approve',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('ApproveMembershipInt', adminStack.approveMembership),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/membership-requests/{id}/deny',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('DenyMembershipInt', adminStack.denyMembership),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/membership-terms',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('CreateMembershipTermsInt', adminStack.createMembershipTerms),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/membership-terms/current',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('GetCurrentMembershipTermsInt', adminStack.getCurrentMembershipTerms),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/membership-terms',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('ListMembershipTermsInt', adminStack.listMembershipTerms),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/membership-terms/{version_id}/download',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('GetTermsDownloadUrlInt', adminStack.getTermsDownloadUrl),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/proposals',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('CreateProposalInt', adminStack.createProposal),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/proposals',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('ListProposalsInt', adminStack.listProposals),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/proposals/{id}/suspend',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('SuspendProposalInt', adminStack.suspendProposal),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/proposals/{proposal_id}/vote-counts',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('GetProposalVoteCountsInt', adminStack.getProposalVoteCounts),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/subscriptions',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('ListSubscriptionsInt', adminStack.listSubscriptions),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/subscriptions/{id}/extend',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('ExtendSubscriptionInt', adminStack.extendSubscription),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/subscriptions/{id}/reactivate',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('ReactivateSubscriptionInt', adminStack.reactivateSubscription),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/subscription-types',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('CreateSubscriptionTypeInt', adminStack.createSubscriptionType),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/subscription-types',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('ListSubscriptionTypesInt', adminStack.listSubscriptionTypes),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/subscription-types/{id}/enable',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('EnableSubscriptionTypeInt', adminStack.enableSubscriptionType),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/subscription-types/{id}/disable',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('DisableSubscriptionTypeInt', adminStack.disableSubscriptionType),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/waitlist',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('ListWaitlistInt', adminStack.listWaitlist),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/waitlist/send-invites',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('SendWaitlistInvitesInt', adminStack.sendWaitlistInvites),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/waitlist',
      methods: [apigw.HttpMethod.DELETE],
      integration: new integrations.HttpLambdaIntegration('DeleteWaitlistEntriesInt', adminStack.deleteWaitlistEntries),
      authorizer: this.adminAuthorizer,
    });

    // System monitoring routes
    this.httpApi.addRoutes({
      path: '/admin/system-health',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('GetSystemHealthInt', adminStack.getSystemHealth),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/system-logs',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('GetSystemLogsInt', adminStack.getSystemLogs),
      authorizer: this.adminAuthorizer,
    });

    // Email management routes
    this.httpApi.addRoutes({
      path: '/admin/send-bulk-email',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('SendBulkEmailInt', adminStack.sendBulkEmail),
      authorizer: this.adminAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/admin/sent-emails',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('ListSentEmailsInt', adminStack.listSentEmails),
      authorizer: this.adminAuthorizer,
    });

    // Notification management routes
    new apigw.HttpRoute(this, 'GetNotificationsRoute', {
      httpApi: this.httpApi,
      routeKey: apigw.HttpRouteKey.with('/admin/notifications/{type}', apigw.HttpMethod.GET),
      integration: new integrations.HttpLambdaIntegration('GetNotificationsInt', adminStack.getNotifications),
      authorizer: this.adminAuthorizer,
    });
    new apigw.HttpRoute(this, 'AddNotificationRoute', {
      httpApi: this.httpApi,
      routeKey: apigw.HttpRouteKey.with('/admin/notifications/{type}', apigw.HttpMethod.POST),
      integration: new integrations.HttpLambdaIntegration('AddNotificationInt', adminStack.addNotification),
      authorizer: this.adminAuthorizer,
    });
    new apigw.HttpRoute(this, 'RemoveNotificationRoute', {
      httpApi: this.httpApi,
      routeKey: apigw.HttpRouteKey.with('/admin/notifications/{type}/{email}', apigw.HttpMethod.DELETE),
      integration: new integrations.HttpLambdaIntegration('RemoveNotificationInt', adminStack.removeNotification),
      authorizer: this.adminAuthorizer,
    });

    // Audit log route
    this.httpApi.addRoutes({
      path: '/admin/audit',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('GetAuditLogInt', adminStack.getAuditLog),
      authorizer: this.adminAuthorizer,
    });

    // NATS Control - Admin-only endpoint for issuing control tokens
    this.httpApi.addRoutes({
      path: '/admin/nats/control-token',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('GenerateNatsControlTokenInt', adminStack.generateNatsControlToken),
      authorizer: this.adminAuthorizer,
    });
  }

  /**
   * Add vault routes to the HTTP API
   * Called after VaultStack is instantiated to wire up vault Lambda functions
   */
  public addVaultRoutes(vaultStack: any): void {
    // Vault Enrollment
    this.httpApi.addRoutes({
      path: '/vault/enroll/start',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('EnrollStartInt', vaultStack.enrollStart),
      authorizer: this.memberAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/vault/enroll/set-password',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('EnrollSetPasswordInt', vaultStack.enrollSetPassword),
      authorizer: this.memberAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/vault/enroll/finalize',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('EnrollFinalizeInt', vaultStack.enrollFinalize),
      authorizer: this.memberAuthorizer,
    });

    // Vault Authentication
    this.httpApi.addRoutes({
      path: '/vault/action/request',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('ActionRequestInt', vaultStack.actionRequest),
      authorizer: this.memberAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/vault/auth/execute',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('AuthExecuteInt', vaultStack.authExecute),
      authorizer: this.memberAuthorizer,
    });

    // NATS Account Management
    this.httpApi.addRoutes({
      path: '/vault/nats/account',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('NatsCreateAccountInt', vaultStack.natsCreateAccount),
      authorizer: this.memberAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/vault/nats/token',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('NatsGenerateTokenInt', vaultStack.natsGenerateToken),
      authorizer: this.memberAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/vault/nats/token/revoke',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('NatsRevokeTokenInt', vaultStack.natsRevokeToken),
      authorizer: this.memberAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/vault/nats/status',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('NatsGetStatusInt', vaultStack.natsGetStatus),
      authorizer: this.memberAuthorizer,
    });
  }
}
