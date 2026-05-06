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
