import * as iam from 'aws-cdk-lib/aws-iam';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';

/**
 * Grants append-only access to the audit table.
 *
 * SECURITY (infra-#4): the audit table records security-relevant
 * actions (admin operations, registration approvals, etc.). The
 * canonical CDK helper `grantReadWriteData` would let any one of the
 * ~106 Lambdas that write audit entries also DELETE or UPDATE those
 * entries — a compromised Lambda could erase its own footprints. This
 * helper grants only `dynamodb:PutItem` (and the inseparable
 * `DescribeTable` for SDK metadata) so the table is effectively
 * append-only from every writer.
 *
 * The handful of Lambdas that legitimately QUERY audit (admin views
 * like getAuditLog, getSecurityEvents, getSystemHealth) should pair
 * this with `auditTable.grantReadData(fn)` separately.
 */
export function grantAuditAppend(
  auditTable: dynamodb.ITable,
  grantee: iam.IGrantable,
): iam.Grant {
  return iam.Grant.addToPrincipal({
    grantee,
    actions: [
      'dynamodb:PutItem',
      'dynamodb:DescribeTable',
    ],
    resourceArns: [auditTable.tableArn],
  });
}

/**
 * Grants the per-action rate-limit counter UpdateItem on the audit
 * table, constrained to items whose primary key starts with
 * `RATELIMIT#`.
 *
 * Why this exists separately from grantAuditAppend:
 *   checkRateLimit() (lambda/common/util.ts) atomically increments a
 *   counter via UpdateItem + ConditionExpression. UpdateItem is NOT in
 *   grantAuditAppend (by design — that helper is append-only so a
 *   compromised audit writer can't tamper with prior entries). Without
 *   this grant, the conditional UpdateItem throws AccessDeniedException
 *   → checkRateLimit's catch fails-closed → every request hits 429.
 *   That's exactly the silent system-wide outage we shipped under
 *   SECURITY #29's fail-closed change.
 *
 * The IAM condition restricts UpdateItem to items keyed `RATELIMIT#*`
 * so a compromised rate-limit user still cannot touch real audit rows.
 */
export function grantRateLimitWrite(
  auditTable: dynamodb.ITable,
  grantee: iam.IGrantable,
): iam.Grant {
  return iam.Grant.addToPrincipal({
    grantee,
    actions: [
      'dynamodb:UpdateItem',
    ],
    resourceArns: [auditTable.tableArn],
    conditions: {
      'ForAllValues:StringLike': {
        'dynamodb:LeadingKeys': ['RATELIMIT#*'],
      },
    },
  });
}
