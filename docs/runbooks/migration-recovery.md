# Migration Recovery Runbook

## Overview

This runbook covers diagnosis and recovery for the enclave migration
flow when something goes wrong mid-deploy. The migration redesign
(see `docs/MIGRATION-TARGET-ARCHITECTURE.md`) is largely self-healing
through F5 self-heal + Phase 4.6 routing reclaim, but a handful of
failure modes still require operator intervention. They're all
captured here.

**TL;DR decision tree:**

1. **Deploy finished but no markers landed for any user?** → "No markers"
   below. Usually means OLD's vault-manager can't verify the migration
   config (canonicalization bug, missing `pcr_signing_key_arn`).
2. **Markers landed for some users but not all?** → "Partial markers".
   The remaining users haven't been seen since the migration window
   opened. Wait for deadline or nudge them.
3. **OLD instance crash-looping after operator restarted vettid-parent?**
   → "Crashlooping OLD". The promoted SSM PCR0 doesn't match what
   the OLD enclave attests to. Don't touch it; terminate it.
4. **Auto-finalize never fires?** → "Auto-finalize stuck". Lambda
   logs in CloudWatch. Usually a markers count vs registrations count
   mismatch.
5. **Two distinct AMIs running, both healthy, but no traffic moving
   between them?** → "Stuck routing". Trigger the Phase 4.6
   force-reclaim endpoint manually.

---

## Common diagnostic commands

```bash
# Current migration config (or none)
aws s3 cp s3://vettid-vault-data-<ACCOUNT>/_migration/config.json - \
    --region us-east-1 | jq '{version, new_pcr0: .new_pcrs.pcr0, old_pcr0: .old_pcrs.pcr0, mandatory_after}'

# Markers landed for the current version
aws s3 ls s3://vettid-vault-data-<ACCOUNT>/_migration/completed/<VERSION>/ \
    --region us-east-1

# KMS policy — should be AnyOf [old, new] during migration window
aws kms get-key-policy --key-id alias/vettid-enclave-sealing \
    --policy-name default --region us-east-1 --query 'Policy' --output text \
    | jq '.Statement[] | select(.Sid=="AllowEnclaveDecrypt") | .Condition'

# ASG state — should be 2/2/2 during migration, 1/1/1 after finalize
aws autoscaling describe-auto-scaling-groups \
    --auto-scaling-group-names <ENCLAVE_ASG_NAME> --region us-east-1 \
    --query 'AutoScalingGroups[0].{Min:MinSize,Max:MaxSize,Desired:DesiredCapacity,Instances:Instances[*].{Id:InstanceId,AMI:LaunchTemplate.Version,Lifecycle:LifecycleState}}'

# Each instance's actual running PCR0 (via the enclave's nitro-cli)
aws ssm send-command --instance-ids <INSTANCE_ID> --document-name AWS-RunShellScript \
    --parameters 'commands=["nitro-cli describe-enclaves | jq -r .[0].Measurements.PCR0"]' \
    --region us-east-1 --query 'Command.CommandId' --output text
# wait ~5s, then:
aws ssm get-command-invocation --command-id <COMMAND_ID> --instance-id <INSTANCE_ID> \
    --region us-east-1 --query 'StandardOutputContent' --output text

# Migration / marker activity in the parent journal
aws ssm send-command --instance-ids <INSTANCE_ID> --document-name AWS-RunShellScript \
    --parameters 'commands=["journalctl -u vettid-parent --since \"15 minutes ago\" --no-pager | grep -iE \"marker|verification|migrate_consent|carve-outs|reseal\" | tail -40"]' \
    --region us-east-1 --query 'Command.CommandId' --output text
```

---

## Scenario: No markers

### Symptom

Both phones have accepted the migration prompt. App shows "unlocked"
fine. But `aws s3 ls _migration/completed/<VERSION>/` is empty for
more than 5 minutes after the unlock.

### Diagnosis

Look in the parent journal for the failure shape:

```bash
# On whichever instance handled the pin-unlock (usually OLD)
journalctl -u vettid-parent --since "15 minutes ago" --no-pager \
    | grep -iE "marker|verification|migrate_consent" | tail -30
```

Match against these patterns:

| Log line | Cause | Fix |
|---|---|---|
| `migrate_consent: config verification failed; treating as not_requested` + `PCR signing key ARN not configured` | `parent.yaml` is missing `kms.pcr_signing_key_arn`. The CDK user-data didn't fetch it. | Hot-patch parent.yaml on every running instance, restart vettid-parent. See "Hot-patch parent.yaml" below. |
| `Migration config rejected — signature/time-window verification failed` + `ECDSA signature does not match` | Canonicalization mismatch between signer (`jq -cS`) and verifier (Go). | Build issue; the vault-manager binary on this instance has the pre-2026-05-11 canonical bug. Need a fresh deploy. |
| `Failed to write migration marker ... AccessDeniedException ... kms:Sign` | Enclave instance role missing `kms:Sign` on the PCR signing key. | Update the KMS resource policy. See "Grant kms:Sign" below. |
| `migrate_consent: landed on OLD enclave; emitting routing handoff` (with no following NEW-side log) | OLD's M1 handoff fired but NEW didn't reclaim. Routing race or NATS issue. | Trigger Phase 4.6 reclaim manually. See "Force-reclaim routing" below. |

### Hot-patch parent.yaml (missing `pcr_signing_key_arn`)

```bash
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
PCR_SIGNING_KEY_ID=$(aws ssm get-parameter --name /vettid/attestation/pcr-signing-key-id \
    --region us-east-1 --query Parameter.Value --output text)
ARN="arn:aws:kms:us-east-1:${ACCOUNT}:key/${PCR_SIGNING_KEY_ID}"

# For each instance in the ASG:
for INST in $(aws autoscaling describe-auto-scaling-groups \
    --auto-scaling-group-names <ASG_NAME> --region us-east-1 \
    --query 'AutoScalingGroups[0].Instances[*].InstanceId' --output text); do
    aws ssm send-command --instance-ids "$INST" --document-name AWS-RunShellScript \
        --parameters "commands=[\"if grep -q pcr_signing_key_arn /etc/vettid/parent.yaml; then echo already-present; else sed -i '/^kms:/a\\\\  pcr_signing_key_arn: $ARN' /etc/vettid/parent.yaml; fi; systemctl restart vettid-parent\"]" \
        --region us-east-1 --query 'Command.CommandId' --output text
done
```

**WARNING:** if the live SSM PCR0 doesn't match the instance's actual
running enclave PCR0, the restart will crash-loop with a PCR0 mismatch
on the vsock handshake. Verify first:

```bash
# Compare SSM PCR0 to the actual running enclave PCR0
aws ssm get-parameter --name /vettid/enclave/pcr/pcr0 \
    --region us-east-1 --query Parameter.Value --output text
# vs the nitro-cli output from the diagnostic block above
```

If they don't match: do NOT restart that instance. See "Crashlooping
OLD" below.

The permanent fix is committed in CDK (`a53b6ef`, `nitro-stack.ts`
user-data templating). A `cdk deploy VettID-Nitro` updates the
launch template so future instances are self-sufficient.

### Grant kms:Sign

```bash
KEY_ID=<from /vettid/attestation/pcr-signing-key-id>
ROLE_ARN=$(aws iam get-role --role-name vettid-enclave-instance-role --query 'Role.Arn' --output text)

aws kms get-key-policy --key-id "$KEY_ID" --policy-name default \
    --region us-east-1 --query 'Policy' --output text \
    | jq '(.Statement[] | select(.Sid=="AllowEnclaveReadPublicKey") | .Action) += ["kms:Sign"]' \
    > /tmp/new-key-policy.json

aws kms put-key-policy --key-id "$KEY_ID" --policy-name default \
    --policy "$(cat /tmp/new-key-policy.json)" --region us-east-1
```

Permanent fix in `88824ff` (`nitro-stack.ts`); `cdk deploy VettID-Nitro`
to apply.

### Force-reclaim routing

```bash
NEW_INSTANCE_ID=<the new-AMI instance>
OLD_PCR0=$(aws s3 cp s3://vettid-vault-data-<ACCOUNT>/_migration/config.json - \
    --region us-east-1 | jq -r '.old_pcrs.pcr0')

aws ssm send-command --instance-ids "$NEW_INSTANCE_ID" --document-name AWS-RunShellScript \
    --parameters "commands=[\"curl -s 'http://127.0.0.1:8080/internal/reclaim-from-pcr0?pcr0=$OLD_PCR0'\"]" \
    --region us-east-1 --query 'Command.CommandId' --output text
# wait, fetch output. Should show: {"claimed":N,"running_pcr0":"...","requested_old":"..."}
```

This is what Phase 4.6 of `deploy.sh` calls automatically; manual
invocation is for cases where the deploy aborted before reaching
Phase 4.6 or you want to retry.

---

## Scenario: Partial markers

### Symptom

Some users' markers are in `_migration/completed/<VERSION>/` but not
all. Auto-finalize won't fire until all enrolled users have markers
OR the deadline passes.

### Diagnosis

```bash
# Count of expected users
aws dynamodb scan --table-name <REGISTRATIONS_TABLE> --region us-east-1 \
    --select COUNT --query 'Count'

# Count of markers landed
aws s3 ls s3://vettid-vault-data-<ACCOUNT>/_migration/completed/<VERSION>/ \
    --region us-east-1 | wc -l
```

If the markers count is less than registrations, the difference is
users who haven't opened the app since the migration window opened
(or who opened the app but encountered a bug — check the parent
journal for their owner_space GUID).

### Options

- **Wait for the deadline.** The Lambda checks `mandatory_after` and
  triggers finalize when passed, regardless of marker count. Default
  is 72 hours.
- **Nudge specific users.** Push them to open the app (out of band).
  Each user must accept the migration prompt or pin-unlock at least
  once with the new app version.
- **Manual `--finalize`.** Only do this if you've explicitly decided
  that the un-migrated users get cut off (they'll need to re-enroll).
  See "Manual finalize" below.

---

## Scenario: Crashlooping OLD

### Symptom

`systemctl status vettid-parent` shows `Active: activating (auto-restart)`
on an OLD instance. Journal shows:

```
PCR value mismatch actual=<X> expected=<Y> pcr_index=0
SECURITY: Enclave attestation verification FAILED
FTL Parent process error error="failed to connect to enclave: ... PCR0 mismatch"
```

The OLD instance's enclave attests to a PCR0 that doesn't match what's
in the live SSM `/vettid/enclave/pcr/pcr0`. This usually means the
deploy promoted SSM to NEW's PCR0 but the OLD instance's parent was
restarted (manually or by systemd) after the promote and is now
reading the NEW value.

### Fix

**Do NOT** try to fix the SSM PCR0 — the live value is what NEW expects
and you'll break it.

**Do NOT** restart the OLD parent again; same crash loop.

**DO** terminate the OLD instance via the ASG:

```bash
# Drop MinSize first so the ASG allows the scale-down
aws autoscaling update-auto-scaling-group \
    --auto-scaling-group-name <ASG_NAME> --min-size 1 --region us-east-1

# Terminate the crash-looping instance
aws autoscaling terminate-instance-in-auto-scaling-group \
    --instance-id <OLD_INSTANCE_ID> --should-decrement-desired-capacity \
    --region us-east-1

# Lock to 1 to prevent replacement spawning
aws autoscaling update-auto-scaling-group \
    --auto-scaling-group-name <ASG_NAME> --max-size 1 --region us-east-1
```

NEW now serves all traffic. Users mid-session see a NATS disconnect,
their app retries, lands on NEW. KMS AnyOf is still in effect so NEW
can decrypt their OLD-bound material.

Re-fire Phase 4.6 force-reclaim if desired (see "Force-reclaim routing"
above) so users don't have to wait for OLD's lease to expire.

---

## Scenario: Auto-finalize stuck

### Symptom

All markers are in place. Deadline has passed. `_migration/config.json`
is still in S3. KMS still AnyOf. ASG still 2/2/2.

### Diagnosis

```bash
# Lambda's recent invocations
aws logs tail /aws/lambda/vettid-migration-finalize --since 30m --region us-east-1

# Schedule rule healthy
aws events describe-rule --name vettid-migration-finalize-schedule \
    --region us-east-1 --query '{Name:Name,State:State,Schedule:ScheduleExpression}'
```

Common stuck states:

| Symptom in logs | Cause | Fix |
|---|---|---|
| No invocations at all | EventBridge rule deleted (pre-2026-05-11 Lambda used to tear itself down). | `cdk deploy VettID-Nitro` re-creates the rule, or `aws events put-rule` + `put-targets` manually. |
| `Markers verification failed: signature does not match` | Marker was written by an enclave whose binary had the canonicalization bug. The marker can't be KMS-Verified by the Lambda. | Re-trigger a marker write by having the user re-unlock against an instance with the fixed code. Or `--finalize` manually. |
| `Scale ASG: ValidationError: New SetDesiredCapacity value 1 is below min value 2` | Lambda's order is scale-down → KMS tighten. If `MinSize=2` is still pinned, scale fails. | The Lambda should drop MinSize first. If it doesn't, drop MinSize manually then re-trigger. |

### Manual finalize (last resort)

```bash
cd /home/al/VettID/vettid-dev
echo y | bash enclave/scripts/deploy.sh --finalize
```

This forces the finalize sequence locally. Users who haven't migrated
get cut off and need to re-enroll. **Only use after the deadline has
passed.**

---

## Scenario: Stuck routing

### Symptom

Both instances healthy, KMS AnyOf, markers landed for SOME users.
The un-migrated users are still hitting OLD even though NEW is fully
up. The Phase 4.6 force-reclaim was never run (e.g., deploy aborted
before Phase 4.6) or didn't catch these users.

### Fix

Re-run Phase 4.6 directly. See "Force-reclaim routing" under "No
markers" above.

---

## Related code

- `enclave/migration/pcr_config.go` — signed-payload canonicalization
- `enclave/vault-manager/pin_handler.go` — F5 self-heal +
  dispatchMigrateConsent
- `enclave/parent/routing.go` — `ReclaimUsersFromPCR0`
- `enclave/parent/health.go` — `/internal/reclaim-from-pcr0` endpoint
- `enclave/scripts/deploy.sh` — Phase 4.5 / 4.6 / 5 / 6
- `cdk/lambda/handlers/scheduled/migrationFinalize.ts` — auto-finalize
- `cdk/lib/nitro-stack.ts` — KMS policy, IAM role, EventBridge rule

## Related docs

- `docs/MIGRATION-TARGET-ARCHITECTURE.md` — full design
- `docs/MIGRATION-ARCHITECT-REVIEW.md` — context for the redesign
- `docs/runbooks/enclave-update.md` — non-migration enclave updates
