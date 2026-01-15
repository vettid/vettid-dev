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
  aws_logs as logs,
  aws_kms as kms,
} from 'aws-cdk-lib';
import { InfrastructureStack } from './infrastructure-stack';

export interface VettIdStackProps extends cdk.StackProps {
  infrastructure: InfrastructureStack;
}

export class VettIdStack extends cdk.Stack {
  // Private properties for internal use
  public readonly httpApi: apigw.HttpApi;
  public readonly adminAuthorizer: apigw.IHttpRouteAuthorizer;
  public readonly memberAuthorizer: apigw.IHttpRouteAuthorizer;

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

// API Gateway origin for same-origin API proxy (avoids cross-origin issues on privacy browsers)
const apiOrigin = new origins.HttpOrigin('api.vettid.dev', {
  protocolPolicy: cloudfront.OriginProtocolPolicy.HTTPS_ONLY,
});

// CloudFront Function to strip /api prefix from request URI
const apiProxyFn = new cloudfront.Function(this, 'ApiProxyFn', {
  code: cloudfront.FunctionCode.fromInline(`
function handler(event) {
  var request = event.request;
  // Strip /api prefix from URI (e.g., /api/account/... -> /account/...)
  if (request.uri.startsWith('/api')) {
    request.uri = request.uri.substring(4) || '/';
  }
  return request;
}
  `),
});

// Origin request policy to forward all headers to API Gateway (including Authorization)
// Using ALL_VIEWER policy which forwards all headers from the viewer request
const apiOriginRequestPolicy = cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER;

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
    // SECURITY: Strict rate limiting for authentication endpoints (20 req/5min)
    // Prevents brute force and credential stuffing attacks
    {
      name: 'AuthRateLimitRule',
      priority: 1,
      statement: {
        rateBasedStatement: {
          limit: 100, // AWS minimum is 100, evaluated per 5 minutes
          aggregateKeyType: 'IP',
          scopeDownStatement: {
            orStatement: {
              statements: [
                {
                  byteMatchStatement: {
                    searchString: '/vault/enroll',
                    fieldToMatch: { uriPath: {} },
                    textTransformations: [{ priority: 0, type: 'LOWERCASE' }],
                    positionalConstraint: 'STARTS_WITH',
                  },
                },
                {
                  byteMatchStatement: {
                    searchString: '/auth/',
                    fieldToMatch: { uriPath: {} },
                    textTransformations: [{ priority: 0, type: 'LOWERCASE' }],
                    positionalConstraint: 'CONTAINS',
                  },
                },
                {
                  byteMatchStatement: {
                    searchString: '/member/pin',
                    fieldToMatch: { uriPath: {} },
                    textTransformations: [{ priority: 0, type: 'LOWERCASE' }],
                    positionalConstraint: 'STARTS_WITH',
                  },
                },
              ],
            },
          },
        },
      },
      action: { block: {} },
      visibilityConfig: {
        cloudWatchMetricsEnabled: true,
        metricName: 'AuthRateLimitRule',
        sampledRequestsEnabled: true,
      },
    },
    // General rate limiting: 500 requests per 5 minutes per IP
    // Higher limit for normal API usage, auth endpoints have stricter limit above
    {
      name: 'GeneralRateLimitRule',
      priority: 2,
      statement: {
        rateBasedStatement: {
          limit: 500,
          aggregateKeyType: 'IP',
        },
      },
      action: { block: {} },
      visibilityConfig: {
        cloudWatchMetricsEnabled: true,
        metricName: 'GeneralRateLimitRule',
        sampledRequestsEnabled: true,
      },
    },
    // AWS Managed Rules: Core Rule Set (OWASP Top 10 protection)
    {
      name: 'AWSManagedRulesCommonRuleSet',
      priority: 3,
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
      priority: 4,
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
      priority: 5,
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
    // Request size limit: Block requests with body > 16KB
    // Protects against slow POST attacks and resource exhaustion
    {
      name: 'RequestSizeLimitRule',
      priority: 6,
      statement: {
        sizeConstraintStatement: {
          fieldToMatch: {
            body: {
              oversizeHandling: 'MATCH', // Treat oversized bodies as matching (block them)
            },
          },
          comparisonOperator: 'GT',
          size: 16384, // 16KB limit
          textTransformations: [{ priority: 0, type: 'NONE' }],
        },
      },
      action: { block: {} },
      visibilityConfig: {
        cloudWatchMetricsEnabled: true,
        metricName: 'RequestSizeLimitRule',
        sampledRequestsEnabled: true,
      },
    },
    // URI query string size limit: Block requests with query string > 4KB
    // Prevents oversized query string attacks
    {
      name: 'QueryStringSizeLimitRule',
      priority: 7,
      statement: {
        sizeConstraintStatement: {
          fieldToMatch: {
            queryString: {},
          },
          comparisonOperator: 'GT',
          size: 4096, // 4KB limit for query strings
          textTransformations: [{ priority: 0, type: 'NONE' }],
        },
      },
      action: { block: {} },
      visibilityConfig: {
        cloudWatchMetricsEnabled: true,
        metricName: 'QueryStringSizeLimitRule',
        sampledRequestsEnabled: true,
      },
    },
  ],
});

    // ===== API GATEWAY (created early so security headers can reference endpoint) =====

    // HTTP API with CORS configuration
    // SECURITY: allowCredentials enables httpOnly cookie-based authentication
    // This is required for the token-exchange endpoint to set cookies on mobile browsers
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
        allowCredentials: true,  // Required for httpOnly cookie authentication on mobile
      },
    });

    // ===== API GATEWAY CUSTOM DOMAIN (api.vettid.dev) =====

    // Look up the hosted zone for vettid.dev
    const vettidZone = route53.HostedZone.fromLookup(this, 'VettidZone', {
      domainName: 'vettid.dev',
    });

    // Import the ACM certificate for api.vettid.dev
    const apiCertificate = acm.Certificate.fromCertificateArn(
      this,
      'ApiCertificate',
      'arn:aws:acm:us-east-1:449757308783:certificate/832dc2d9-e8f9-41a1-b620-6664077dd5cd'
    );

    // Create custom domain for API Gateway
    const apiDomainName = new apigw.DomainName(this, 'ApiDomainName', {
      domainName: 'api.vettid.dev',
      certificate: apiCertificate,
    });

    // Map the custom domain to the HTTP API
    new apigw.ApiMapping(this, 'ApiMapping', {
      api: this.httpApi,
      domainName: apiDomainName,
    });

    // Create Route53 A record pointing to the API Gateway custom domain
    new route53.ARecord(this, 'ApiARecord', {
      zone: vettidZone,
      recordName: 'api',
      target: route53.RecordTarget.fromAlias(
        new targets.ApiGatewayv2DomainProperties(
          apiDomainName.regionalDomainName,
          apiDomainName.regionalHostedZoneId
        )
      ),
    });

    // Create Route53 AAAA record for IPv6
    new route53.AaaaRecord(this, 'ApiAAAARecord', {
      zone: vettidZone,
      recordName: 'api',
      target: route53.RecordTarget.fromAlias(
        new targets.ApiGatewayv2DomainProperties(
          apiDomainName.regionalDomainName,
          apiDomainName.regionalHostedZoneId
        )
      ),
    });

    // SECURITY: KMS key for encrypting API access logs at rest
    // CloudWatch Logs encryption protects audit trail from unauthorized access
    const apiLogsEncryptionKey = new kms.Key(this, 'ApiLogsEncryptionKey', {
      alias: 'vettid-api-logs',
      description: 'KMS key for encrypting API Gateway access logs',
      enableKeyRotation: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // Grant CloudWatch Logs permission to use the key
    apiLogsEncryptionKey.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'AllowCloudWatchLogs',
      effect: iam.Effect.ALLOW,
      principals: [new iam.ServicePrincipal(`logs.${this.region}.amazonaws.com`)],
      actions: [
        'kms:Encrypt',
        'kms:Decrypt',
        'kms:ReEncrypt*',
        'kms:GenerateDataKey*',
        'kms:DescribeKey',
      ],
      resources: ['*'],
      conditions: {
        ArnLike: {
          'kms:EncryptionContext:aws:logs:arn': `arn:aws:logs:${this.region}:${this.account}:log-group:/aws/apigateway/*`,
        },
      },
    }));

    // SECURITY: Enable API Gateway access logging for audit trail with encryption
    const apiAccessLogGroup = new logs.LogGroup(this, 'ApiAccessLogs', {
      logGroupName: '/aws/apigateway/vettid-api-access',
      retention: logs.RetentionDays.ONE_YEAR,
      removalPolicy: cdk.RemovalPolicy.RETAIN, // Retain logs for audit purposes
      encryptionKey: apiLogsEncryptionKey, // SECURITY: Encrypt logs at rest
    });

    // Configure access logging on the default stage using escape hatch
    const apiDefaultStage = this.httpApi.defaultStage?.node.defaultChild as apigw.CfnStage;
    if (apiDefaultStage) {
      apiDefaultStage.accessLogSettings = {
        destinationArn: apiAccessLogGroup.logGroupArn,
        format: JSON.stringify({
          requestId: '$context.requestId',
          ip: '$context.identity.sourceIp',
          requestTime: '$context.requestTime',
          httpMethod: '$context.httpMethod',
          routeKey: '$context.routeKey',
          status: '$context.status',
          protocol: '$context.protocol',
          responseLength: '$context.responseLength',
          integrationLatency: '$context.integrationLatency',
          userAgent: '$context.identity.userAgent',
          errorMessage: '$context.error.message',
        }),
      };
    }

    // NOTE: WAF v2 does NOT support HTTP API (API Gateway V2) directly.
    // It only supports REST APIs. To protect HTTP APIs with WAF, you would need to:
    // 1. Route API through CloudFront (which has WAF attached), OR
    // 2. Use an Application Load Balancer in front of the API
    // The API currently has protection via:
    // - API Gateway built-in throttling (configured below)
    // - Lambda-level rate limiting in handlers
    // - Input validation in Lambda handlers

// CloudFront Function: Add security headers to all responses with specific API URL
const securityHeadersFn = new cloudfront.Function(this, 'SecurityHeadersFn', {
  code: cloudfront.FunctionCode.fromInline(`
// Version: 2025-12-31-13:30 - Add CORS headers for cross-subdomain asset loading
function handler(event) {
  var request = event.request;
  var response = event.response;
  var headers = response.headers;

  // CORS: Allow cross-origin requests from vettid.dev subdomains
  // This enables admin.vettid.dev, account.vettid.dev, etc. to load fonts/styles from vettid.dev
  var origin = request.headers.origin ? request.headers.origin.value : '';
  if (origin.endsWith('.vettid.dev') || origin === 'https://vettid.dev') {
    headers['access-control-allow-origin'] = { value: origin };
    headers['access-control-allow-methods'] = { value: 'GET, HEAD, OPTIONS' };
    headers['access-control-allow-headers'] = { value: 'Origin, Content-Type, Accept' };
    headers['access-control-max-age'] = { value: '86400' };
  }

  // Content Security Policy - restricts resource loading
  // All scripts are now in external files - no 'unsafe-inline' needed
  // Cognito library is self-hosted in /shared/vendor/ - no CDN dependency
  // Allow resources from vettid.dev and all subdomains for cross-subdomain asset loading
  // Specific API endpoint injected at synthesis time (no wildcard - security best practice)
  headers['content-security-policy'] = {
    value: "default-src 'self'; script-src 'self' https://vettid.dev https://*.vettid.dev; style-src 'self' 'unsafe-inline' https://vettid.dev https://*.vettid.dev; img-src 'self' data: https://vettid.dev https://*.vettid.dev; font-src 'self' https://vettid.dev https://*.vettid.dev; connect-src 'self' https://vettid.dev https://*.vettid.dev ${this.httpApi.apiEndpoint} https://*.amazoncognito.com https://cognito-idp.us-east-1.amazonaws.com; frame-ancestors 'none'; form-action 'self' https://*.amazoncognito.com; base-uri 'self'; object-src 'none'; upgrade-insecure-requests;"
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

// Cache policy that varies on Origin header for proper CORS caching
// Without this, CloudFront serves cached responses with wrong CORS headers
const corsAwareCachePolicy = new cloudfront.CachePolicy(this, 'CorsAwareCachePolicy', {
  cachePolicyName: 'VettID-CorsAwareCachePolicy',
  comment: 'Cache policy that varies on Origin header for CORS support',
  defaultTtl: cdk.Duration.days(1),
  maxTtl: cdk.Duration.days(365),
  minTtl: cdk.Duration.seconds(0),
  headerBehavior: cloudfront.CacheHeaderBehavior.allowList('Origin'),
  queryStringBehavior: cloudfront.CacheQueryStringBehavior.none(),
  cookieBehavior: cloudfront.CacheCookieBehavior.none(),
  enableAcceptEncodingGzip: true,
  enableAcceptEncodingBrotli: true,
});

// CloudFront distribution for vettid.dev with path-based routing
const rootDist = new cloudfront.Distribution(this, 'RootDist', {
  webAclId: webAcl.attrArn,
  domainNames: ['vettid.dev'],
  certificate: cert,
  defaultRootObject: 'index.html',
  defaultBehavior: {
    origin: siteOrigin,
    cachePolicy: corsAwareCachePolicy,
    functionAssociations: [
      { eventType: cloudfront.FunctionEventType.VIEWER_REQUEST, function: htmlRewriteFn },
      { eventType: cloudfront.FunctionEventType.VIEWER_RESPONSE, function: securityHeadersFn }
    ],
  },
  additionalBehaviors: {
    // Enrollment deep link handler needs query strings forwarded
    // The ?data= parameter contains the enrollment session token
    // Note: Need both patterns - '/enroll' for exact match and '/enroll/*' for subpaths
    '/enroll': {
      origin: siteOrigin,
      cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
      functionAssociations: [
        { eventType: cloudfront.FunctionEventType.VIEWER_REQUEST, function: htmlRewriteFn },
        { eventType: cloudfront.FunctionEventType.VIEWER_RESPONSE, function: securityHeadersFn }
      ],
    },
    '/enroll/*': {
      origin: siteOrigin,
      cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
      functionAssociations: [
        { eventType: cloudfront.FunctionEventType.VIEWER_REQUEST, function: htmlRewriteFn },
        { eventType: cloudfront.FunctionEventType.VIEWER_RESPONSE, function: securityHeadersFn }
      ],
    },
    // API proxy - routes /api/* to api.vettid.dev (same-origin for privacy browsers)
    '/api/*': {
      origin: apiOrigin,
      cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
      originRequestPolicy: apiOriginRequestPolicy,
      allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
      viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.HTTPS_ONLY,
      functionAssociations: [
        { eventType: cloudfront.FunctionEventType.VIEWER_REQUEST, function: apiProxyFn },
      ],
    },
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

// ===== CERTIFICATE AUTHORITY AUTHORIZATION (CAA) =====
// SECURITY: CAA records restrict which Certificate Authorities can issue certificates
// for this domain, preventing unauthorized certificate issuance
new route53.CaaRecord(this, 'CaaRecord', {
  zone,
  values: [
    // Allow Amazon to issue certificates (for ACM)
    {
      flag: 0,
      tag: route53.CaaTag.ISSUE,
      value: 'amazon.com',
    },
    // Allow Amazon to issue wildcard certificates
    {
      flag: 0,
      tag: route53.CaaTag.ISSUEWILD,
      value: 'amazon.com',
    },
    // SECURITY: Report violations to security contact
    {
      flag: 0,
      tag: route53.CaaTag.IODEF,
      value: 'mailto:security@vettid.dev',
    },
  ],
  comment: 'SECURITY: Restricts certificate issuance to Amazon ACM only',
});

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
    // SECURITY: STAGE=prod ensures localhost origins are not allowed in CORS
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
      STAGE: 'prod',  // SECURITY: Ensures CORS excludes localhost origins
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
    const listPublicServices = new lambdaNode.NodejsFunction(this, 'ListPublicServicesFn', {
      entry: 'lambda/handlers/public/listPublicServices.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        TABLE_SUPPORTED_SERVICES: tables.supportedServices.tableName,
      },
      timeout: cdk.Duration.seconds(10),
      description: 'Public endpoint to list active supported services for mobile app',
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
      environment: {
        ...defaultEnv,
        TABLE_VOTES: tables.votes.tableName,
      },
      timeout: cdk.Duration.seconds(60), // Allow time for scanning and updating multiple proposals
    });
    const checkSubscriptionExpiry = new lambdaNode.NodejsFunction(this, 'CheckSubscriptionExpiryFn', {
      entry: 'lambda/handlers/admin/checkSubscriptionExpiry.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        SES_FROM: 'no-reply@vettid.dev',
      },
      timeout: cdk.Duration.minutes(2), // Allow time to scan subscriptions and send emails
      description: 'Check for subscriptions expiring in 48 hours and send warning emails',
    });
    const sendProposalReminders = new lambdaNode.NodejsFunction(this, 'SendProposalRemindersFn', {
      entry: 'lambda/handlers/scheduled/sendProposalReminders.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        TABLE_VOTES: tables.votes.tableName,
        SES_FROM: 'no-reply@vettid.dev',
      },
      timeout: cdk.Duration.minutes(5), // Allow time to send many reminder emails
      description: 'Send reminder emails for proposals closing soon',
    });

    // Token Exchange - stores JWT tokens in httpOnly cookies for XSS protection
    const tokenExchange = new lambdaNode.NodejsFunction(this, 'TokenExchangeFn', {
      entry: 'lambda/handlers/member/tokenExchange.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {},
      memorySize: 128,
      timeout: cdk.Duration.seconds(10),
      description: 'Exchange JWT tokens for httpOnly cookies',
    });

    // Token Clear - clears httpOnly cookies for logout
    const tokenClear = new lambdaNode.NodejsFunction(this, 'TokenClearFn', {
      entry: 'lambda/handlers/member/tokenClear.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {},
      memorySize: 128,
      timeout: cdk.Duration.seconds(10),
      description: 'Clear JWT tokens from httpOnly cookies',
    });

    // Session - exchanges refresh token from httpOnly cookie for fresh tokens
    const session = new lambdaNode.NodejsFunction(this, 'SessionFn', {
      entry: 'lambda/handlers/member/session.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        MEMBER_CLIENT_ID: memberAppClient.userPoolClientId,
      },
      memorySize: 128,
      timeout: cdk.Duration.seconds(10),
      description: 'Exchange httpOnly refresh token cookie for fresh tokens',
    });

    // Cookie-based Lambda Authorizer for member routes
    const cookieAuthorizer = new lambdaNode.NodejsFunction(this, 'CookieAuthorizerFn', {
      entry: 'lambda/handlers/auth/cookieAuthorizer.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        USER_POOL_ID: memberUserPool.userPoolId,
        CLIENT_ID: memberAppClient.userPoolClientId,
      },
      memorySize: 128,
      timeout: cdk.Duration.seconds(10),
      description: 'Authorizer that reads JWT from httpOnly cookies',
    });

    // Grants
    tables.invites.grantReadWriteData(submitRegistration);
    tables.registrations.grantReadWriteData(submitRegistration);
    tables.waitlist.grantReadWriteData(submitWaitlist);
    tables.audit.grantReadWriteData(submitWaitlist); // For rate limiting
    tables.notificationPreferences.grantReadData(submitWaitlist); // For admin notifications
    tables.supportedServices.grantReadData(listPublicServices); // Public services list
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
    tables.votes.grantReadData(closeExpiredProposals); // Read votes for quorum calculation
    tables.subscriptions.grantReadData(closeExpiredProposals); // Count eligible voters for quorum
    // Proposal reminder scheduled job
    tables.proposals.grantReadData(sendProposalReminders);
    tables.votes.grantReadData(sendProposalReminders);
    tables.subscriptions.grantReadData(sendProposalReminders);
    tables.registrations.grantReadData(sendProposalReminders);
    tables.audit.grantReadData(sendProposalReminders); // Check email preferences
    tables.subscriptionTypes.grantReadData(listEnabledSubscriptionTypes);
    tables.audit.grantReadData(listEnabledSubscriptionTypes);
    // Scheduled job to check for expiring subscriptions and send warning emails
    tables.subscriptions.grantReadWriteData(checkSubscriptionExpiry);
    tables.registrations.grantReadData(checkSubscriptionExpiry);
    tables.audit.grantReadWriteData(checkSubscriptionExpiry);

    // SECURITY: SES permissions with strict resource constraints
    // - Scoped to vettid.dev domain identity only
    // - Pinned to specific templates (no wildcards)
    // - Condition restricts FROM address to verified identity
    const sesIdentityArn = `arn:aws:ses:${this.region}:${this.account}:identity/vettid.dev`;
    // SECURITY: Pin to specific SES templates (no wildcards) to limit blast radius
    const sesTemplateArns = [
      `arn:aws:ses:${this.region}:${this.account}:template/RegistrationApproved`,
      `arn:aws:ses:${this.region}:${this.account}:template/RegistrationPending`,
      `arn:aws:ses:${this.region}:${this.account}:template/RegistrationRejected`,
      `arn:aws:ses:${this.region}:${this.account}:template/SubscriptionExpiryWarning`,
      `arn:aws:ses:${this.region}:${this.account}:template/ProposalVoteReminder`,
      `arn:aws:ses:${this.region}:${this.account}:template/NewProposalNotification`,
    ];

    // SECURITY: Lambdas that send templated emails ONLY (no raw SendEmail)
    // This prevents misuse for arbitrary email sending
    [submitRegistration, registrationStreamFn, checkSubscriptionExpiry, sendProposalReminders].forEach((fn) => {
      fn.addToRolePolicy(new iam.PolicyStatement({
        actions: ['ses:SendTemplatedEmail'], // SECURITY: Only templated emails, not raw SendEmail
        resources: [sesIdentityArn, ...sesTemplateArns],
        conditions: {
          // SECURITY: Only allow sending FROM our verified domain
          'StringLike': {
            'ses:FromAddress': '*@vettid.dev',
          },
        },
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
    // SES permission for waitlist email verification (doesn't support resource-level)
    submitWaitlist.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['ses:VerifyEmailIdentity'],
        resources: ['*'], // VerifyEmailIdentity doesn't support resource-level permissions
      }),
    );
    // SECURITY: SES SendEmail scoped to specific identity with FROM restriction
    submitWaitlist.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['ses:SendEmail'],
        resources: [sesIdentityArn],
        conditions: {
          // SECURITY: Only allow sending FROM our verified domain
          'StringLike': {
            'ses:FromAddress': '*@vettid.dev',
          },
        },
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

    // Add /services route (public - for mobile app)
    this.httpApi.addRoutes({
      path: '/services',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('ListPublicServicesInt', listPublicServices),
    });

    // Token exchange - stores JWT tokens in httpOnly cookies (public, no auth)
    // Note: Don't include OPTIONS - let API Gateway's corsPreflight handle it
    this.httpApi.addRoutes({
      path: '/auth/token-exchange',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('TokenExchangeInt', tokenExchange),
    });

    // Token clear - clears httpOnly cookies for logout (public, no auth)
    // Note: Don't include OPTIONS - let API Gateway's corsPreflight handle it
    this.httpApi.addRoutes({
      path: '/auth/token-clear',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('TokenClearInt', tokenClear),
    });

    // Session - exchanges refresh token from httpOnly cookie for fresh tokens (public, no auth)
    // Used on page load to restore authentication from httpOnly cookie
    this.httpApi.addRoutes({
      path: '/auth/session',
      methods: [apigw.HttpMethod.GET, apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('SessionInt', session),
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

    // NOTE: Profile handlers moved to VaultStack. Connection/messaging are vault-to-vault via NATS.

    // ===== BACKUP HANDLERS (Phase 8) =====

    const backupEnv = {
      ...defaultEnv,
      TABLE_BACKUPS: tables.backups.tableName,
      TABLE_CREDENTIAL_BACKUPS: tables.credentialBackups.tableName,
      TABLE_BACKUP_SETTINGS: tables.backupSettings.tableName,
      TABLE_PROFILES: tables.profiles.tableName,
      BACKUP_BUCKET: props.infrastructure.backupBucket.bucketName,
    };

    const triggerBackup = new lambdaNode.NodejsFunction(this, 'TriggerBackupFn', {
      entry: 'lambda/handlers/backup/triggerBackup.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: backupEnv,
      timeout: cdk.Duration.seconds(30),
      description: 'Trigger manual vault backup',
    });

    const listBackups = new lambdaNode.NodejsFunction(this, 'ListBackupsFn', {
      entry: 'lambda/handlers/backup/listBackups.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: backupEnv,
      timeout: cdk.Duration.seconds(10),
      description: 'List available backups',
    });

    const restoreBackup = new lambdaNode.NodejsFunction(this, 'RestoreBackupFn', {
      entry: 'lambda/handlers/backup/restoreBackup.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: backupEnv,
      timeout: cdk.Duration.seconds(60),
      description: 'Restore from backup',
    });

    const deleteBackup = new lambdaNode.NodejsFunction(this, 'DeleteBackupFn', {
      entry: 'lambda/handlers/backup/deleteBackup.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: backupEnv,
      timeout: cdk.Duration.seconds(10),
      description: 'Delete a backup',
    });

    const getBackupSettings = new lambdaNode.NodejsFunction(this, 'GetBackupSettingsFn', {
      entry: 'lambda/handlers/backup/getBackupSettings.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: backupEnv,
      timeout: cdk.Duration.seconds(10),
      description: 'Get backup settings',
    });

    const updateBackupSettings = new lambdaNode.NodejsFunction(this, 'UpdateBackupSettingsFn', {
      entry: 'lambda/handlers/backup/updateBackupSettings.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: backupEnv,
      timeout: cdk.Duration.seconds(10),
      description: 'Update backup settings',
    });

    const createCredentialBackup = new lambdaNode.NodejsFunction(this, 'CreateCredentialBackupFn', {
      entry: 'lambda/handlers/backup/createCredentialBackup.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: backupEnv,
      timeout: cdk.Duration.seconds(30),
      description: 'Create credential backup',
    });

    const downloadCredentialBackup = new lambdaNode.NodejsFunction(this, 'DownloadCredentialBackupFn', {
      entry: 'lambda/handlers/backup/downloadCredentialBackup.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: backupEnv,
      timeout: cdk.Duration.seconds(30),
      description: 'Download credential backup',
    });

    const getCredentialBackupStatus = new lambdaNode.NodejsFunction(this, 'GetCredentialBackupStatusFn', {
      entry: 'lambda/handlers/backup/getCredentialBackupStatus.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: backupEnv,
      timeout: cdk.Duration.seconds(10),
      description: 'Get credential backup status',
    });

    // Backup handler grants (connections/messages are vault-managed, not backed up via Lambda)
    tables.backups.grantReadWriteData(triggerBackup);
    tables.profiles.grantReadData(triggerBackup);
    props.infrastructure.backupBucket.grantReadWrite(triggerBackup);

    tables.backups.grantReadData(listBackups);

    tables.backups.grantReadWriteData(restoreBackup);
    tables.profiles.grantReadWriteData(restoreBackup);
    props.infrastructure.backupBucket.grantRead(restoreBackup);

    tables.backups.grantReadWriteData(deleteBackup);
    props.infrastructure.backupBucket.grantDelete(deleteBackup);

    tables.backupSettings.grantReadData(getBackupSettings);
    tables.backupSettings.grantReadWriteData(updateBackupSettings);

    tables.credentialBackups.grantReadWriteData(createCredentialBackup);
    props.infrastructure.backupBucket.grantReadWrite(createCredentialBackup);

    tables.credentialBackups.grantReadData(downloadCredentialBackup);
    props.infrastructure.backupBucket.grantRead(downloadCredentialBackup);

    tables.credentialBackups.grantReadData(getCredentialBackupStatus);

    // Backup API routes
    this.httpApi.addRoutes({
      path: '/member/backups/trigger',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('TriggerBackupInt', triggerBackup),
      authorizer: this.memberAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/member/backups',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('ListBackupsInt', listBackups),
      authorizer: this.memberAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/member/backups/{backupId}/restore',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('RestoreBackupInt', restoreBackup),
      authorizer: this.memberAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/member/backups/{backupId}',
      methods: [apigw.HttpMethod.DELETE],
      integration: new integrations.HttpLambdaIntegration('DeleteBackupInt', deleteBackup),
      authorizer: this.memberAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/member/backups/settings',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('GetBackupSettingsInt', getBackupSettings),
      authorizer: this.memberAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/member/backups/settings',
      methods: [apigw.HttpMethod.PUT],
      integration: new integrations.HttpLambdaIntegration('UpdateBackupSettingsInt', updateBackupSettings),
      authorizer: this.memberAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/member/backups/credentials',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('CreateCredentialBackupInt', createCredentialBackup),
      authorizer: this.memberAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/member/backups/credentials',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('DownloadCredentialBackupInt', downloadCredentialBackup),
      authorizer: this.memberAuthorizer,
    });
    this.httpApi.addRoutes({
      path: '/member/backups/credentials/status',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('GetCredentialBackupStatusInt', getCredentialBackupStatus),
      authorizer: this.memberAuthorizer,
    });

    // ===== CALLING HANDLERS (E2EE WebRTC) =====
    // Note: Call state and signaling is handled in user vaults via WASM handlers.
    // This Lambda only provides TURN credentials for WebRTC NAT traversal.

    const getTurnCredentials = new lambdaNode.NodejsFunction(this, 'GetTurnCredentialsFn', {
      entry: 'lambda/handlers/calls/getTurnCredentials.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        TURN_SECRET_NAME: 'vettid/cloudflare-turn',
      },
      timeout: cdk.Duration.seconds(10),
      description: 'Generate Cloudflare TURN credentials for WebRTC calls',
    });

    // Grant access to read TURN secret from Secrets Manager
    getTurnCredentials.addToRolePolicy(new iam.PolicyStatement({
      actions: ['secretsmanager:GetSecretValue'],
      resources: [`arn:aws:secretsmanager:${this.region}:${this.account}:secret:vettid/cloudflare-turn*`],
    }));

    // Grant audit table write access
    tables.audit.grantWriteData(getTurnCredentials);

    // TURN credentials API route
    this.httpApi.addRoutes({
      path: '/calls/turn-credentials',
      methods: [apigw.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('GetTurnCredentialsInt', getTurnCredentials),
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

    // EventBridge scheduled rule to check for expiring subscriptions every 6 hours
    const subscriptionExpiryRule = new events.Rule(this, 'SubscriptionExpiryCheckRule', {
      description: 'Check for subscriptions expiring in 48 hours and send warning emails',
      schedule: events.Schedule.rate(cdk.Duration.hours(6)),
    });
    subscriptionExpiryRule.addTarget(new targets_events.LambdaFunction(checkSubscriptionExpiry));

    // EventBridge scheduled rule to send proposal vote reminders every 6 hours
    const proposalReminderRule = new events.Rule(this, 'ProposalVoteReminderRule', {
      description: 'Send reminder emails for proposals closing soon',
      schedule: events.Schedule.rate(cdk.Duration.hours(6)),
    });
    proposalReminderRule.addTarget(new targets_events.LambdaFunction(sendProposalReminders));

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
}
