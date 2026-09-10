"""
scenarios.py — 24 blind scenarios for the Universal Security Generalization
Benchmark (pilot scale — see REPORT.md for the honest scope-reduction note).

All resource/principal names are new to this project (the fictional "Halcyon
Corp" environment in halcyon_graph.py) — none are reused or renamed from
DEMO_ATTACK_SCENARIOS, eval/, or tests/ fixtures. Family and trap-case tags
are recorded per scenario so the required-diversity and >=20% trap-case rules
can be checked mechanically, not just claimed.

IMPORTANT: this file was written and frozen BEFORE any scenario was run
through the pipeline. ground_truth.py was written in the same sitting, also
before execution — see REPORT.md's integrity section for the honest caveat
on tester independence (Section 15 of the benchmark brief).
"""

FAMILIES = {
    "s3": "S3 / object-storage security",
    "iam": "IAM / identity and permissions",
    "sg": "Security groups / network exposure",
    "dynamodb": "DynamoDB / data-store permissions",
    "lambda": "Lambda / serverless permissions and trust paths",
    "cross_service": "Cross-service / multi-hop attack paths",
    "ambiguous": "Ambiguous, context-dependent, or human-review cases",
}

SCENARIOS = [
    # ---------------------------------------------------------------- S3 (4)
    {
        "scenario_id": "GB-01", "family": "s3", "trap": False,
        "event": {
            "event_id": "gb-01", "timestamp": "2026-06-14T02:10:00Z",
            "vulnerability_type": "S3 Public Access", "severity": "CRITICAL",
            "bucket_name": "halcyon-customer-pii-store", "account_id": "700100200300",
            "region": "us-east-1", "status": "NON_COMPLIANT",
            "nlp_summary": "Public access block was disabled on the customer PII store bucket at 2 AM Sunday.",
        },
    },
    {
        "scenario_id": "GB-02", "family": "s3", "trap": True,
        "note": "Broad exposure on a genuinely low-value dev/synthetic resource.",
        "event": {
            "event_id": "gb-02", "timestamp": "2026-06-10T15:20:00Z",
            "vulnerability_type": "S3 Public Access", "severity": "CRITICAL",
            "bucket_name": "halcyon-dev-scratch-bucket", "account_id": "700100200300",
            "region": "us-east-1", "status": "NON_COMPLIANT",
            "nlp_summary": "Public access block was disabled on a developer scratch bucket during normal business hours.",
        },
    },
    {
        "scenario_id": "GB-03", "family": "s3", "trap": True,
        "note": "Narrow-sounding exposure on a high-value deploy-artifacts bucket (supply-chain risk).",
        "event": {
            "event_id": "gb-03", "timestamp": "2026-06-13T03:40:00Z",
            "vulnerability_type": "S3 Public Access", "severity": "CRITICAL",
            "bucket_name": "halcyon-deploy-artifacts", "account_id": "700100200300",
            "region": "us-east-1", "status": "NON_COMPLIANT",
            "nlp_summary": "Public access block was disabled on the CI/CD build-artifacts bucket at 3:40 AM Saturday.",
        },
    },
    {
        "scenario_id": "GB-04", "family": "s3", "trap": False,
        "event": {
            "event_id": "gb-04", "timestamp": "2026-06-11T16:05:00Z",
            "vulnerability_type": "S3 Encryption", "severity": "MEDIUM",
            "bucket_name": "halcyon-partner-export-queue", "account_id": "700100200300",
            "region": "us-east-1", "status": "NON_COMPLIANT",
            "nlp_summary": "Server-side encryption is disabled on the bucket used to stage exports for a third-party partner integration.",
        },
    },

    # --------------------------------------------------------------- IAM (5)
    {
        "scenario_id": "GB-05", "family": "iam", "trap": False,
        "event": {
            "event_id": "gb-05", "timestamp": "2026-06-14T04:15:00Z",
            "vulnerability_type": "IAM Audit", "severity": "CRITICAL",
            "bucket_name": "wildcard-assume-role", "account_id": "700100200300",
            "region": "us-east-1", "status": "IAM_OVERPERMISSIVE",
            "principal": "halcyon-onboarding-role",
            "nlp_summary": "The new-hire onboarding automation role was granted unrestricted sts:AssumeRole onto the CI/CD deploy pipeline role.",
            "policy_fix_context": {
                "current_policy": {"Version": "2012-10-17", "Statement": [
                    {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::halcyon-internal-wiki-assets/*"},
                    {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"},
                ]},
                "offending_action": "sts:AssumeRole",
                "offending_resource": "arn:aws:iam::700100200300:role/halcyon-deploy-pipeline-role",
                "must_still_allow": [["s3:GetObject", "arn:aws:s3:::halcyon-internal-wiki-assets/onboarding-guide.pdf"]],
            },
        },
    },
    {
        "scenario_id": "GB-06", "family": "iam", "trap": True,
        "note": "Legitimate service role with an unrelated iam:* overreach — must be narrowed, not deleted.",
        "event": {
            "event_id": "gb-06", "timestamp": "2026-06-13T05:00:00Z",
            "vulnerability_type": "IAM Audit", "severity": "HIGH",
            "bucket_name": "iam-wildcard-billing-role", "account_id": "700100200300",
            "region": "us-east-1", "status": "IAM_OVERPERMISSIVE",
            "principal": "halcyon-billing-service-role",
            "nlp_summary": "The billing service role, which should only read billing records and secrets, was also granted iam:* — full IAM administration.",
            "policy_fix_context": {
                "current_policy": {"Version": "2012-10-17", "Statement": [
                    {"Effect": "Allow", "Action": "iam:*", "Resource": "*"},
                    {"Effect": "Allow", "Action": "dynamodb:GetItem",
                     "Resource": ["arn:aws:dynamodb:us-east-1:700100200300:table/halcyon-billing-records",
                                  "arn:aws:dynamodb:us-east-1:700100200300:table/halcyon-secrets-vault"]},
                ]},
                "offending_action": "iam:CreateUser",
                "offending_resource": "*",
                "must_still_allow": [
                    ["dynamodb:GetItem", "arn:aws:dynamodb:us-east-1:700100200300:table/halcyon-billing-records"],
                    ["dynamodb:GetItem", "arn:aws:dynamodb:us-east-1:700100200300:table/halcyon-secrets-vault"],
                ],
            },
        },
    },
    {
        "scenario_id": "GB-07", "family": "iam", "trap": True,
        "note": "Wildcard (CRITICAL by label) on a genuinely low-value marketing bucket — severity should not simply follow the label.",
        "event": {
            "event_id": "gb-07", "timestamp": "2026-06-10T13:10:00Z",
            "vulnerability_type": "IAM Audit", "severity": "CRITICAL",
            "bucket_name": "iam-wildcard-support-agent", "account_id": "700100200300",
            "region": "us-east-1", "status": "IAM_OVERPERMISSIVE",
            "principal": "halcyon-support-agent-user",
            "nlp_summary": "A support agent's account was granted s3:* on the marketing-assets bucket instead of the intended read-only access.",
            "policy_fix_context": {
                "current_policy": {"Version": "2012-10-17", "Statement": [
                    {"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::halcyon-marketing-assets/*"},
                ]},
                "offending_action": "s3:DeleteObject",
                "offending_resource": "arn:aws:s3:::halcyon-marketing-assets/*",
                "must_still_allow": [["s3:GetObject", "arn:aws:s3:::halcyon-marketing-assets/banner.png"]],
            },
        },
    },
    {
        "scenario_id": "GB-08", "family": "iam", "trap": True,
        "note": "Admin-tagged CI role with an added iam:PassRole('*') — cross-service privilege-escalation risk hiding inside an already-trusted role.",
        "event": {
            "event_id": "gb-08", "timestamp": "2026-06-14T01:30:00Z",
            "vulnerability_type": "IAM Audit", "severity": "HIGH",
            "bucket_name": "iam-passrole-deploy-pipeline", "account_id": "700100200300",
            "region": "us-east-1", "status": "IAM_OVERPERMISSIVE",
            "principal": "halcyon-deploy-pipeline-role",
            "nlp_summary": "The CI/CD deploy pipeline role, already administering build artifacts, was also granted iam:PassRole on all roles.",
            "policy_fix_context": {
                "current_policy": {"Version": "2012-10-17", "Statement": [
                    {"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::halcyon-deploy-artifacts/*"},
                    {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"},
                ]},
                "offending_action": "iam:PassRole",
                "offending_resource": "*",
                "must_still_allow": [["s3:PutObject", "arn:aws:s3:::halcyon-deploy-artifacts/build-42.zip"]],
            },
        },
    },
    {
        "scenario_id": "GB-09", "family": "iam", "trap": False,
        "event": {
            "event_id": "gb-09", "timestamp": "2026-06-13T04:50:00Z",
            "vulnerability_type": "IAM Audit", "severity": "CRITICAL",
            "bucket_name": "iam-dormant-legacy-wildcard", "account_id": "700100200300",
            "region": "us-east-1", "status": "IAM_OVERPERMISSIVE",
            "principal": "halcyon-legacy-reporting-role",
            "nlp_summary": "A dormant legacy reporting role, still active but unused for months, holds a forgotten wildcard s3:* grant.",
            "policy_fix_context": {
                "current_policy": {"Version": "2012-10-17", "Statement": [
                    {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
                    {"Effect": "Allow", "Action": "dynamodb:GetItem",
                     "Resource": "arn:aws:dynamodb:us-east-1:700100200300:table/halcyon-audit-log-archive"},
                ]},
                "offending_action": "s3:PutBucketPolicy",
                "offending_resource": "*",
                "must_still_allow": [["dynamodb:GetItem", "arn:aws:dynamodb:us-east-1:700100200300:table/halcyon-audit-log-archive"]],
            },
        },
    },

    # ---------------------------------------------------------------- SG (4)
    {
        "scenario_id": "GB-10", "family": "sg", "trap": False,
        "event": {
            "event_id": "gb-10", "timestamp": "2026-06-14T03:05:00Z",
            "vulnerability_type": "Security Group Open SSH", "severity": "HIGH",
            "bucket_name": "halcyon-web-tier-sg", "account_id": "700100200300",
            "region": "us-east-1", "status": "NON_COMPLIANT",
            "nlp_summary": "Security group halcyon-web-tier-sg was updated to allow SSH (port 22) from 0.0.0.0/0.",
        },
    },
    {
        "scenario_id": "GB-11", "family": "sg", "trap": True,
        "note": "Vulnerability label says 'Open SSH' but the narrative describes Postgres (5432) — tests whether classification reasons from context, not just the label.",
        "event": {
            "event_id": "gb-11", "timestamp": "2026-06-13T02:20:00Z",
            "vulnerability_type": "Security Group Open SSH", "severity": "HIGH",
            "bucket_name": "halcyon-db-tier-sg", "account_id": "700100200300",
            "region": "us-east-1", "status": "NON_COMPLIANT",
            "nlp_summary": "Security group halcyon-db-tier-sg was updated to allow inbound PostgreSQL (port 5432) from 0.0.0.0/0.",
        },
    },
    {
        "scenario_id": "GB-12", "family": "sg", "trap": True,
        "note": "Should NOT trigger — properly scoped to a corporate CIDR, not 0.0.0.0/0. False-positive-resistance check.",
        "event": {
            "event_id": "gb-12", "timestamp": "2026-06-10T11:15:00Z",
            "vulnerability_type": "Security Group Open SSH", "severity": "LOW",
            "bucket_name": "halcyon-internal-ci-sg", "account_id": "700100200300",
            "region": "us-east-1", "status": "COMPLIANT",
            "nlp_summary": "Security group halcyon-internal-ci-sg allows SSH (port 22) only from the corporate CIDR 10.0.5.0/24.",
        },
    },
    {
        "scenario_id": "GB-13", "family": "sg", "trap": True,
        "note": "Payment-context resource name should strongly signal prod-keyword risk even though the vuln label/port don't literally say 'payment'.",
        "event": {
            "event_id": "gb-13", "timestamp": "2026-06-14T02:45:00Z",
            "vulnerability_type": "Security Group Open SSH", "severity": "CRITICAL",
            "bucket_name": "halcyon-payment-gateway-sg", "account_id": "700100200300",
            "region": "us-east-1", "status": "NON_COMPLIANT",
            "nlp_summary": "Security group halcyon-payment-gateway-sg was updated to allow inbound RDP (port 3389) from 0.0.0.0/0.",
        },
    },

    # ----------------------------------------------------------- DynamoDB (3)
    {
        "scenario_id": "GB-14", "family": "dynamodb", "trap": True,
        "note": "MEDIUM label on a table that's actually production+payment+pii — severity-vs-label mismatch, the central test of Layer 5's design.",
        "event": {
            "event_id": "gb-14", "timestamp": "2026-06-14T03:30:00Z",
            "vulnerability_type": "DynamoDB Unencrypted", "severity": "MEDIUM",
            "bucket_name": "halcyon-billing-records", "account_id": "700100200300",
            "region": "us-east-1", "status": "NON_COMPLIANT",
            "nlp_summary": "Server-side encryption is disabled on the billing records table.",
        },
    },
    {
        "scenario_id": "GB-15", "family": "dynamodb", "trap": False,
        "event": {
            "event_id": "gb-15", "timestamp": "2026-06-11T10:40:00Z",
            "vulnerability_type": "DynamoDB Unencrypted", "severity": "MEDIUM",
            "bucket_name": "halcyon-audit-log-archive", "account_id": "700100200300",
            "region": "us-east-1", "status": "NON_COMPLIANT",
            "nlp_summary": "Server-side encryption is disabled on the compliance audit-log archive table.",
        },
    },
    {
        "scenario_id": "GB-16", "family": "dynamodb", "trap": True,
        "note": "Resource name signals 'secret'/'vault' strongly (Layer 1 keyword feature) but isn't tagged with any of Layer 3's CRITICAL_TAGS words — probes a real, disclosed tension between the two layers.",
        "event": {
            "event_id": "gb-16", "timestamp": "2026-06-14T04:00:00Z",
            "vulnerability_type": "DynamoDB Unencrypted", "severity": "MEDIUM",
            "bucket_name": "halcyon-secrets-vault", "account_id": "700100200300",
            "region": "us-east-1", "status": "NON_COMPLIANT",
            "nlp_summary": "Server-side encryption is disabled on the table storing third-party API credentials.",
        },
    },

    # -------------------------------------------------------------- Lambda (3)
    {
        "scenario_id": "GB-17", "family": "lambda", "trap": False,
        "event": {
            "event_id": "gb-17", "timestamp": "2026-06-13T03:15:00Z",
            "vulnerability_type": "IAM Audit", "severity": "CRITICAL",
            "bucket_name": "lambda-passrole-checkout-fn", "account_id": "700100200300",
            "region": "us-east-1", "status": "IAM_OVERPERMISSIVE",
            "principal": "halcyon-checkout-fn-exec-role",
            "nlp_summary": "The checkout Lambda function's execution role was granted lambda:UpdateFunctionCode('*') and iam:PassRole('*'), well beyond its billing-write needs.",
            "policy_fix_context": {
                "current_policy": {"Version": "2012-10-17", "Statement": [
                    {"Effect": "Allow", "Action": "dynamodb:PutItem",
                     "Resource": "arn:aws:dynamodb:us-east-1:700100200300:table/halcyon-billing-records"},
                    {"Effect": "Allow", "Action": "lambda:UpdateFunctionCode", "Resource": "*"},
                ]},
                "offending_action": "lambda:UpdateFunctionCode",
                "offending_resource": "*",
                "must_still_allow": [["dynamodb:PutItem", "arn:aws:dynamodb:us-east-1:700100200300:table/halcyon-billing-records"]],
            },
        },
    },
    {
        "scenario_id": "GB-18", "family": "lambda", "trap": True,
        "note": "Unnecessary dynamodb:* wildcard where only DeleteItem on one small table is actually needed.",
        "event": {
            "event_id": "gb-18", "timestamp": "2026-06-14T02:55:00Z",
            "vulnerability_type": "IAM Audit", "severity": "HIGH",
            "bucket_name": "lambda-wildcard-cleanup-fn", "account_id": "700100200300",
            "region": "us-east-1", "status": "IAM_OVERPERMISSIVE",
            "principal": "halcyon-scheduled-cleanup-fn-role",
            "nlp_summary": "A scheduled cleanup Lambda's execution role holds dynamodb:* on all tables, but only ever deletes items from one temporary cache table.",
            "policy_fix_context": {
                "current_policy": {"Version": "2012-10-17", "Statement": [
                    {"Effect": "Allow", "Action": "dynamodb:*", "Resource": "*"},
                ]},
                "offending_action": "dynamodb:DeleteTable",
                "offending_resource": "*",
                "must_still_allow": [["dynamodb:DeleteItem", "arn:aws:dynamodb:us-east-1:700100200300:table/halcyon-tmp-cache-table"]],
            },
        },
    },
    {
        "scenario_id": "GB-19", "family": "lambda", "trap": True,
        "note": "Should read as a non-issue — the role's only real permission is source-IP-restricted. False-positive-resistance check, and a fresh exercise of the Phase 7 condition-key handling.",
        "event": {
            "event_id": "gb-19", "timestamp": "2026-06-10T09:50:00Z",
            "vulnerability_type": "IAM Audit", "severity": "LOW",
            "bucket_name": "lambda-scoped-report-export-fn", "account_id": "700100200300",
            "region": "us-east-1", "status": "COMPLIANT",
            "principal": "halcyon-report-export-fn-role",
            "nlp_summary": "The report-export Lambda's execution role has s3:GetObject on marketing-assets, restricted to the corporate office IP range via a policy condition.",
        },
    },

    # ------------------------------------------------------- Cross-service (3)
    {
        "scenario_id": "GB-20", "family": "cross_service", "trap": False,
        "event": {
            "event_id": "gb-20", "timestamp": "2026-06-14T04:40:00Z",
            "vulnerability_type": "IAM Audit", "severity": "CRITICAL",
            "bucket_name": "iam-crossservice-legacy-reporting", "account_id": "700100200300",
            "region": "us-east-1", "status": "IAM_OVERPERMISSIVE",
            "principal": "halcyon-legacy-reporting-role",
            "nlp_summary": "The legacy reporting role can assume the partner-sync role, which in turn writes to the partner data-export queue — a 2-hop path from a forgotten service into partner-shared production data.",
            "policy_fix_context": {
                "current_policy": {"Version": "2012-10-17", "Statement": [
                    {"Effect": "Allow", "Action": "dynamodb:GetItem",
                     "Resource": "arn:aws:dynamodb:us-east-1:700100200300:table/halcyon-audit-log-archive"},
                    {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"},
                ]},
                "offending_action": "sts:AssumeRole",
                "offending_resource": "arn:aws:iam::700100200300:role/halcyon-partner-sync-role",
                "must_still_allow": [["dynamodb:GetItem", "arn:aws:dynamodb:us-east-1:700100200300:table/halcyon-audit-log-archive"]],
            },
        },
    },
    {
        "scenario_id": "GB-21", "family": "cross_service", "trap": False,
        "event": {
            "event_id": "gb-21", "timestamp": "2026-06-13T04:25:00Z",
            "vulnerability_type": "IAM Audit", "severity": "HIGH",
            "bucket_name": "iam-crossservice-ml-training", "account_id": "700100200300",
            "region": "us-east-1", "status": "IAM_OVERPERMISSIVE",
            "principal": "halcyon-ml-training-role",
            "nlp_summary": "The ML training role, which already reads raw customer PII for model training, was also granted iam:PassRole('*') — it could hand its data-access role to an unaudited compute resource.",
            "policy_fix_context": {
                "current_policy": {"Version": "2012-10-17", "Statement": [
                    {"Effect": "Allow", "Action": "s3:GetObject",
                     "Resource": "arn:aws:s3:::halcyon-customer-pii-store/*"},
                    {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"},
                ]},
                "offending_action": "iam:PassRole",
                "offending_resource": "*",
                "must_still_allow": [["s3:GetObject", "arn:aws:s3:::halcyon-customer-pii-store/training-set.csv"]],
            },
        },
    },
    {
        "scenario_id": "GB-22", "family": "cross_service", "trap": True,
        "note": "Principal is an external identity not present in the infra graph at all — tests honest LOW-default degradation, not a crash or a guess, while the auto-fix decision should still work fine (Layer 4 doesn't need blast radius to draft).",
        "event": {
            "event_id": "gb-22", "timestamp": "2026-06-14T01:50:00Z",
            "vulnerability_type": "IAM Audit", "severity": "CRITICAL",
            "bucket_name": "iam-external-contractor-wildcard", "account_id": "700100200300",
            "region": "us-east-1", "status": "IAM_OVERPERMISSIVE",
            "principal": "external-halcyon-contractor-2024",
            "nlp_summary": "An external contractor identity, not provisioned through the normal onboarding process, was granted a wildcard IAM policy.",
            "policy_fix_context": {
                "current_policy": {"Version": "2012-10-17", "Statement": [
                    {"Effect": "Allow", "Action": "*", "Resource": "*"},
                ]},
                "offending_action": "iam:CreateAccessKey",
                "offending_resource": "*",
                "must_still_allow": [],
            },
        },
    },

    # --------------------------------------------------------- Ambiguous (2)
    {
        "scenario_id": "GB-23", "family": "ambiguous", "trap": True,
        "note": "Context implies a possibly-legitimate temporary broad grant (declared incident window) — tests whether context nuance shifts the decision away from a blind auto-fix.",
        "event": {
            "event_id": "gb-23", "timestamp": "2026-06-13T05:30:00Z",
            "vulnerability_type": "IAM Audit", "severity": "CRITICAL",
            "bucket_name": "iam-breakglass-billing-incident", "account_id": "700100200300",
            "region": "us-east-1", "status": "IAM_OVERPERMISSIVE",
            "principal": "halcyon-billing-service-role",
            "nlp_summary": "The billing service role was granted a broad administrative policy; account activity log notes this coincides with a declared incident-response window for a payment-processing outage.",
            "policy_fix_context": {
                "current_policy": {"Version": "2012-10-17", "Statement": [
                    {"Effect": "Allow", "Action": "dynamodb:*", "Resource": "*"},
                ]},
                "offending_action": "dynamodb:DeleteTable",
                "offending_resource": "*",
                "must_still_allow": [["dynamodb:GetItem", "arn:aws:dynamodb:us-east-1:700100200300:table/halcyon-billing-records"]],
            },
        },
    },
    {
        "scenario_id": "GB-24", "family": "ambiguous", "trap": True,
        "note": "Malformed/incomplete event (no account_id/region) — robustness/graceful-degradation check, not a correctness check per se.",
        "event": {
            "event_id": "gb-24", "timestamp": "2026-06-11T12:00:00Z",
            "vulnerability_type": "DynamoDB Unencrypted", "severity": "MEDIUM",
            "bucket_name": "halcyon-tmp-cache-table",
            "nlp_summary": "Server-side encryption is disabled on a table; account and region metadata are missing from this event.",
        },
    },
]

assert len(SCENARIOS) == 24
assert len({s["scenario_id"] for s in SCENARIOS}) == 24, "duplicate scenario_id"
_trap_count = sum(1 for s in SCENARIOS if s["trap"])
assert _trap_count / len(SCENARIOS) >= 0.20, f"trap ratio {_trap_count}/{len(SCENARIOS)} below the required 20%"
