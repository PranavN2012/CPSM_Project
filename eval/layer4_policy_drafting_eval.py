"""
Layer 4 Evaluation — Autonomous Policy Drafting (propose -> test -> revise)
==============================================================================
Runs a set of vulnerable IAM policies through the REAL PolicyAgent — whichever
LLM client is actually configured (Groq/Gemini via .env), not the
RuleBasedPolicyDrafter fallback. This matters: RuleBasedPolicyDrafter always
succeeds on attempt 1 by construction (it adds an exact Deny for exactly the
offending action/resource, which trivially passes PolicyEvaluator), so it
would report a meaningless 100% first-attempt pass rate. The real LLM's
attempt distribution is the actual evidence of how good the propose-test-
revise loop is.

For each scenario, verifies (not just "test_passed" as a black box):
  - offending action/resource is actually blocked in the final policy
    (checked independently via PolicyEvaluator, not by trusting the
    PolicyDraft.test_passed flag alone)
  - every "must_still_allow" pair is still independently verifiable
  - which attempt (1, 2, or 3) produced the passing draft, or "FAILED" if none did

Reports: % passing on attempt 1, % passing within 3 attempts, % that never
pass (correctly left for human escalation).
"""

import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lambda", "shared"))

from ml.policy_agent import PolicyAgent, PolicyEvaluator

SCENARIOS = [
    {
        "name": "s3_public_access_admin_wildcard",
        "current_policy": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
        ]},
        "offending_action": "s3:PutBucketPolicy",
        "offending_resource": "arn:aws:s3:::prod-data-lake-raw",
        "must_still_allow": [["s3:GetObject", "arn:aws:s3:::prod-data-lake-raw"]],
    },
    {
        "name": "iam_create_policy_wildcard",
        "current_policy": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "iam:*", "Resource": "*"},
        ]},
        "offending_action": "iam:CreatePolicy",
        "offending_resource": "*",
        "must_still_allow": [["iam:GetRole", "*"]],
    },
    {
        "name": "dynamodb_delete_table_wildcard",
        "current_policy": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "dynamodb:*", "Resource": "arn:aws:dynamodb:us-east-1:123456789012:table/*"},
        ]},
        "offending_action": "dynamodb:DeleteTable",
        "offending_resource": "arn:aws:dynamodb:us-east-1:123456789012:table/session-tokens-table",
        "must_still_allow": [["dynamodb:GetItem", "arn:aws:dynamodb:us-east-1:123456789012:table/session-tokens-table"]],
    },
    {
        "name": "ec2_open_ingress_wildcard",
        "current_policy": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "ec2:*", "Resource": "*"},
        ]},
        "offending_action": "ec2:AuthorizeSecurityGroupIngress",
        "offending_resource": "arn:aws:ec2:us-east-1:123456789012:security-group/sg-web-public",
        "must_still_allow": [["ec2:DescribeInstances", "*"]],
    },
    {
        "name": "lambda_update_code_wildcard",
        "current_policy": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "lambda:*", "Resource": "arn:aws:lambda:us-east-1:123456789012:function:*"},
        ]},
        "offending_action": "lambda:UpdateFunctionCode",
        "offending_resource": "arn:aws:lambda:us-east-1:123456789012:function:cspm-s3-remediation",
        "must_still_allow": [["lambda:InvokeFunction", "arn:aws:lambda:us-east-1:123456789012:function:cspm-s3-remediation"]],
    },
    {
        "name": "cross_service_pass_role",
        "current_policy": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["s3:*", "iam:PassRole"], "Resource": "*"},
        ]},
        "offending_action": "iam:PassRole",
        "offending_resource": "*",
        "must_still_allow": [["s3:GetObject", "*"]],
    },
    {
        "name": "broad_resource_wildcard",
        "current_policy": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
            {"Effect": "Allow", "Action": "s3:PutBucketAcl", "Resource": "*"},
        ]},
        "offending_action": "s3:PutBucketAcl",
        "offending_resource": "*",
        "must_still_allow": [["s3:GetObject", "arn:aws:s3:::customer-reports-q1"]],
    },
    {
        "name": "multi_statement_multiple_required",
        "current_policy": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::backup-vault"},
            {"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::backup-vault/*"},
        ]},
        "offending_action": "s3:DeleteBucket",
        "offending_resource": "arn:aws:s3:::backup-vault",
        "must_still_allow": [
            ["s3:GetObject", "arn:aws:s3:::backup-vault/*"],
            ["s3:PutObject", "arn:aws:s3:::backup-vault/*"],
            ["s3:ListBucket", "arn:aws:s3:::backup-vault"],
        ],
    },
    {
        "name": "already_partially_restricted",
        "current_policy": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
            {"Effect": "Deny", "Action": "s3:DeleteBucket", "Resource": "*"},
        ]},
        "offending_action": "s3:PutBucketPublicAccessBlock",
        "offending_resource": "arn:aws:s3:::ml-training-datasets",
        "must_still_allow": [["s3:GetObject", "arn:aws:s3:::ml-training-datasets"]],
    },
    {
        "name": "empty_starting_policy",
        "current_policy": {"Version": "2012-10-17", "Statement": []},
        "offending_action": "s3:*",
        "offending_resource": "*",
        "must_still_allow": [["s3:GetObject", "arn:aws:s3:::dev-user-uploads"]],
    },
    # -- Deliberately adversarial "trap" scenarios below: a naive fix (block
    # the whole matching resource prefix, or the whole action-name prefix)
    # would ALSO break a required permission that shares that same prefix.
    # A correct fix has to be more surgical than "deny the obvious pattern". --
    {
        "name": "trap_overlapping_resource_prefix",
        "current_policy": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::prod-data-lake-raw*"},
        ]},
        "offending_action": "s3:PutBucketPolicy",
        "offending_resource": "arn:aws:s3:::prod-data-lake-raw",
        # Shares the exact same "prod-data-lake-raw*" resource prefix as the
        # offending resource — a blanket Deny on that prefix breaks this too.
        "must_still_allow": [["s3:GetObject", "arn:aws:s3:::prod-data-lake-raw/sensitive-file.csv"]],
    },
    {
        "name": "trap_similar_action_names",
        "current_policy": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "iam:Create*", "Resource": "*"},
        ]},
        "offending_action": "iam:CreateAccessKey",
        "offending_resource": "*",
        # Both share the "iam:Create*" prefix with the offending action — a
        # naive "deny iam:Create*" fix would also block these required ones.
        "must_still_allow": [["iam:CreateRole", "*"], ["iam:CreatePolicy", "*"]],
    },
]


def independently_verify(policy_json: dict, offending_action: str, offending_resource: str,
                          must_still_allow: list) -> tuple:
    """Re-checks the final draft with a FRESH PolicyEvaluator instance,
    independent of whatever the agent's own test_fix() reported — catches
    the case where PolicyDraft.test_passed was set correctly by the agent
    but we want to confirm it ourselves rather than trust a single code path."""
    evaluator = PolicyEvaluator()
    still_allows_offending = evaluator.evaluate(policy_json, offending_action, offending_resource)
    preserves_all_required = all(
        evaluator.evaluate(policy_json, action, resource) for action, resource in must_still_allow
    )
    return (not still_allows_offending), preserves_all_required


def main():
    agent = PolicyAgent()
    client_name = agent.llm_client.__class__.__name__
    print("=" * 90)
    print(f"LAYER 4 — Policy Drafting Evaluation (LLM client: {client_name})")
    print("=" * 90)
    print(f"Running {len(SCENARIOS)} vulnerable-policy scenarios through the real propose-test-revise loop...")
    print()

    attempt_counts = []  # attempt number of the passing draft, or None if never passed
    rows = []

    for i, scenario in enumerate(SCENARIOS, 1):
        incident = {
            "current_policy": scenario["current_policy"],
            "offending_action": scenario["offending_action"],
            "offending_resource": scenario["offending_resource"],
            "must_still_allow": scenario["must_still_allow"],
        }
        print(f"[{i}/{len(SCENARIOS)}] {scenario['name']} ...", flush=True)
        draft = agent.revise_and_retry(incident)

        narrowed, preserved = independently_verify(
            draft.policy_json, scenario["offending_action"], scenario["offending_resource"],
            scenario["must_still_allow"],
        )
        independently_confirmed_pass = narrowed and preserved

        result_attempt = draft.attempt_number if draft.test_passed else None
        attempt_counts.append(result_attempt)

        rows.append({
            "name": scenario["name"],
            "agent_reported_pass": draft.test_passed,
            "attempt_number": draft.attempt_number,
            "independently_confirmed_narrowed": narrowed,
            "independently_confirmed_preserved_required": preserved,
            "independently_confirmed_pass": independently_confirmed_pass,
            "agrees_with_independent_check": draft.test_passed == independently_confirmed_pass,
            "errors": draft.errors,
        })

    print()
    n = len(SCENARIOS)
    pass_attempt_1 = sum(1 for a in attempt_counts if a == 1)
    pass_within_3 = sum(1 for a in attempt_counts if a is not None)
    never_passed = n - pass_within_3
    agent_independent_agreement = sum(1 for r in rows if r["agrees_with_independent_check"])

    print(f"Passed on attempt 1:        {pass_attempt_1}/{n}  ({100*pass_attempt_1/n:.0f}%)")
    print(f"Passed within 3 attempts:   {pass_within_3}/{n}  ({100*pass_within_3/n:.0f}%)")
    print(f"Never passed (escalated):   {never_passed}/{n}  ({100*never_passed/n:.0f}%)")
    print(f"Agent's own test_passed agrees with independent re-verification: "
          f"{agent_independent_agreement}/{n}  ({100*agent_independent_agreement/n:.0f}%)")
    print()
    for r in rows:
        status = f"attempt {r['attempt_number']}" if r["agent_reported_pass"] else "FAILED (escalated)"
        agree = "OK" if r["agrees_with_independent_check"] else "DISAGREEMENT — needs manual review"
        print(f"  [{status:<20}] {r['name']:<38} independent_check={'PASS' if r['independently_confirmed_pass'] else 'FAIL'}  [{agree}]")
        if r["errors"]:
            print(f"      last errors: {r['errors']}")

    out = {
        "layer": 4, "name": "Policy Drafting", "llm_client": client_name,
        "n_scenarios": n,
        "pct_pass_attempt_1": round(100 * pass_attempt_1 / n, 1),
        "pct_pass_within_3": round(100 * pass_within_3 / n, 1),
        "pct_never_passed": round(100 * never_passed / n, 1),
        "pct_agent_agrees_with_independent_check": round(100 * agent_independent_agreement / n, 1),
        "rows": rows,
    }
    return out


if __name__ == "__main__":
    result = main()
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results_layer4.json")
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nSaved -> {out_path}")
