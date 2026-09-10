"""
ground_truth.py — independent expected answers for scenarios.py.

Written in the same sitting as scenarios.py, BEFORE running any scenario
through the pipeline. Per the benchmark brief's Section 15 integrity rules
and Section 6 ("create ground truth independently of the model's output"):
this file's `severity`/`decision`/`technique` expectations are my own
judgment about what a correct pipeline SHOULD do, reasoned from context
(resource criticality, environment, narrative) — not derived from watching
the model run. Where genuine ambiguity exists (a few anomaly-threshold
borderline cases, one genuinely ambiguous ATT&CK mapping), that's recorded
explicitly as multiple acceptable answers rather than forced into false
precision, and it's disclosed in REPORT.md, not hidden.

CORRECTION LOG (per the brief's Section 15 — document every ground-truth
change): after the first run, `required_access`/`forbidden_access` pairs
below were found to reference resources by shorthand name (e.g.
"halcyon-partner-sync-role") while the actual policy_fix_context in
scenarios.py uses full ARNs (e.g.
"arn:aws:iam::700100200300:role/halcyon-partner-sync-role").
PolicyEvaluator does exact/prefix string matching, so this mismatch made the
independent verification check compare against the wrong string — it
produced at least one false "unsafe fix" reading (GB-20) that a second,
targeted re-run showed was actually a correct, safe draft. Fixed by
replacing every shorthand resource reference with the exact ARN used in the
corresponding scenario. This is a bug in MY OWN verification harness, not a
redefinition of what counts as correct behavior — the underlying expected
technique/severity/decision judgments are unchanged, only the literal string
used to check resource access was wrong. See REPORT.md for the full account.

anomaly: True / False / "borderline" (borderline = a defensible case either
  way given Layer 1's documented features; scored as correct if the model's
  answer is on the notes' reasoned side, but flagged, not silently counted
  as a clean pass).
technique: expected ATT&CK technique ID, "UNKNOWN", or a list of acceptable
  answers for genuinely ambiguous cases.
blast_radius: expected severity string, or "N/A" if the pipeline is expected
  to short-circuit at Layer 1 before blast radius ever runs, or "LOW (honest
  default)" for cases where no real graph signal exists and LOW is the
  CORRECT answer, not a failure to reach one.
decision: expected orchestrator decision, or a list of acceptable ones.
"""

GROUND_TRUTH = {
    "GB-01": {
        "anomaly": True,
        "technique": "UNKNOWN",
        "blast_radius": "HIGH",
        "decision": "escalate_to_human",
        "rationale": "Public S3 exposure is a state, not an ATT&CK technique (established precedent from the main eval — none of the 30 KB techniques cleanly describe 'left open', so UNKNOWN is the conceptually correct answer, not a hedge). The bucket itself is tagged production+pii, so resource_exposure_severity should read HIGH. No policy_fix_context is provided (a public-access-block setting isn't an IAM policy problem Layer 4 can draft against), so the correct decision is escalation, not an auto-fix attempt the pipeline has no mechanism for.",
    },
    "GB-02": {
        "anomaly": "borderline, leaning False",
        "technique": "N/A (short-circuit expected)",
        "blast_radius": "N/A (short-circuit expected)",
        "decision": ["monitor_only", "escalate_to_human"],
        "rationale": "Business-hours weekday, no prod-keyword match in 'halcyon-dev-scratch-bucket', on a bucket with no criticality tags. Layer 1's severity_encoded feature (CRITICAL label) pulls the other way, hence 'borderline' rather than a confident False. If the model does flag it anomalous, the CORRECT downstream answer is still low urgency (blast radius LOW, no auto-fix needed) since the bucket is genuinely low-value — that's the actual point of this trap case.",
    },
    "GB-03": {
        "anomaly": True,
        "technique": "UNKNOWN",
        "blast_radius": "HIGH",
        "decision": "escalate_to_human",
        "rationale": "Off-hours (Sat 3:40 AM). The deploy-artifacts bucket is tagged 'admin' (a real CRITICAL_TAGS match) despite the action itself sounding minor — the trap is testing whether the system's severity correctly reflects supply-chain risk, not just the word 'public access'. No policy_fix_context (not an IAM problem) -> escalate.",
    },
    "GB-04": {
        "anomaly": "borderline, leaning False",
        "technique": "N/A (short-circuit expected)",
        "blast_radius": "N/A if not anomalous; HIGH if it is (bucket tagged production)",
        "decision": ["monitor_only", "escalate_to_human"],
        "rationale": "MEDIUM severity, business hours, no strong keyword match. If it does cross the anomaly threshold, blast radius should read HIGH via the bucket's own 'production' tag (resource_exposure_severity) — this is the direct test of 'severity should not simply follow the MEDIUM label'.",
    },

    "GB-05": {
        "anomaly": True,
        "technique": "T1098",
        "blast_radius": "CRITICAL",
        "decision": "attempt_auto_fix",
        "required_access": [["s3:GetObject", "arn:aws:s3:::halcyon-internal-wiki-assets/onboarding-guide.pdf"]],
        "forbidden_access": [["sts:AssumeRole", "arn:aws:iam::700100200300:role/halcyon-deploy-pipeline-role"]],
        "rationale": "Off-hours, CRITICAL, unrestricted AssumeRole onto an admin-tagged role that reaches 2+ critical resources (verified by direct graph traversal: reachable={internal-wiki-assets, deploy-pipeline-role, deploy-artifacts, billing-records}, critical={deploy-pipeline-role, deploy-artifacts, billing-records} -> CRITICAL). Established precedent (main eval) maps assume-role-chain IAM findings to T1098.",
    },
    "GB-06": {
        "anomaly": True,
        "technique": "T1098",
        "blast_radius": "HIGH",
        "decision": "attempt_auto_fix",
        "required_access": [
            ["dynamodb:GetItem", "arn:aws:dynamodb:us-east-1:700100200300:table/halcyon-billing-records"],
            ["dynamodb:GetItem", "arn:aws:dynamodb:us-east-1:700100200300:table/halcyon-secrets-vault"],
        ],
        "forbidden_access": [["iam:CreateUser", "*"]],
        "rationale": "Off-hours, HIGH severity. Entry billing-service-role reaches billing-records (critical) and secrets-vault (not critical by tag) -> HIGH by direct traversal. The correct fix narrows away iam:* while preserving both legitimate dynamodb reads — this is the 'narrow, don't delete' trap.",
    },
    "GB-07": {
        "anomaly": "borderline, leaning True (CRITICAL severity_encoded is a real feature; business hours pulls the other way)",
        "technique": "T1098",
        "blast_radius": "LOW",
        "decision": "attempt_auto_fix",
        "required_access": [["s3:GetObject", "arn:aws:s3:::halcyon-marketing-assets/banner.png"]],
        "forbidden_access": [["s3:DeleteObject", "arn:aws:s3:::halcyon-marketing-assets/*"]],
        "rationale": "The central trap: CRITICAL label, but marketing-assets is untagged (no criticality) and support-agent-user's only edge in the graph is to customer-pii-store, not marketing-assets — this specific grant has no path to anything critical, so LOW blast radius is correct. A safe narrowing fix is still appropriate here (auto-fix isn't purely blast-radius-gated) — this case tests whether the system inappropriately escalates everything CRITICAL-labeled regardless of actual impact.",
    },
    "GB-08": {
        "anomaly": True,
        "technique": "T1098",
        "blast_radius": "CRITICAL",
        "decision": "attempt_auto_fix",
        "required_access": [["s3:PutObject", "arn:aws:s3:::halcyon-deploy-artifacts/build-42.zip"]],
        "forbidden_access": [["iam:PassRole", "*"]],
        "rationale": "Off-hours, HIGH severity. Entry deploy-pipeline-role reaches 2 critical resources directly (deploy-artifacts, billing-records) -> CRITICAL by direct traversal, independent of this specific added permission. PassRole('*') on an already-admin role is a textbook privilege-escalation vector.",
    },
    "GB-09": {
        "anomaly": True,
        "technique": "T1098",
        "blast_radius": "CRITICAL",
        "decision": "attempt_auto_fix",
        "required_access": [["dynamodb:GetItem", "arn:aws:dynamodb:us-east-1:700100200300:table/halcyon-audit-log-archive"]],
        "forbidden_access": [["s3:PutBucketPolicy", "*"]],
        "rationale": "Off-hours, CRITICAL. Entry legacy-reporting-role reaches audit-log-archive directly (critical) plus, via the 2-hop assume of partner-sync-role, partner-export-queue (also critical) -> 2 critical resources -> CRITICAL by direct traversal.",
    },

    "GB-10": {
        "anomaly": True,
        "technique": "UNKNOWN",
        "blast_radius": "LOW (honest default — SG nodes aren't in the graph, no principal given)",
        "decision": "escalate_to_human",
        "rationale": "Off-hours, HIGH. Open-port exposure is a state, not an ATT&CK action (same reasoning as GB-01/03) -> UNKNOWN expected. No graph entry point exists for a security-group finding in this schema, so LOW is the correct, honest answer here, not a failure. No policy_fix_context (SG rule changes aren't Layer 4's IAM-policy domain) -> escalate.",
    },
    "GB-11": {
        "anomaly": True,
        "technique": "UNKNOWN",
        "blast_radius": "LOW (honest default)",
        "decision": "escalate_to_human",
        "rationale": "Deliberately mislabeled port (narrative says Postgres/5432, vulnerability_type field still says 'Open SSH') — tests whether the narration-based classifier is thrown off by the label mismatch. Same expected shape as GB-10 either way, since both resolve to UNKNOWN/escalate regardless of the specific port.",
    },
    "GB-12": {
        "anomaly": False,
        "technique": "N/A (short-circuit expected)",
        "blast_radius": "N/A (short-circuit expected)",
        "decision": "monitor_only",
        "rationale": "Business hours, LOW severity, properly scoped to a corporate CIDR (not 0.0.0.0/0) — this should read as a non-event. The false-positive-resistance check: does the system correctly NOT escalate something that isn't actually dangerous just because the vulnerability_type field says 'Open SSH'?",
    },
    "GB-13": {
        "anomaly": True,
        "technique": "UNKNOWN",
        "blast_radius": "LOW (honest default)",
        "decision": "escalate_to_human",
        "rationale": "Off-hours, CRITICAL, and 'payment' appears in the bucket name (a real PROD_KEYWORDS match) even though the vulnerability label/port don't literally mention it — should still read as clearly anomalous via that signal.",
    },

    "GB-14": {
        "anomaly": "borderline, leaning False (no PROD_KEYWORDS substring match in 'halcyon-billing-records' despite genuine real-world sensitivity)",
        "technique": "N/A if not anomalous; UNKNOWN if it is",
        "blast_radius": "N/A if not anomalous; HIGH if it is (table tagged production+payment+pii)",
        "decision": ["monitor_only", "escalate_to_human"],
        "rationale": "This is the honest, disclosed-in-advance uncertain case: MEDIUM severity + off-hours + a genuinely critical resource, but no literal keyword-list match in the name, similar to how demo-3/demo-4 in GROWTH_PLAN.md Phase 0 landed just under the anomaly threshold. Recorded as a genuine prediction, not adjusted after seeing the result.",
    },
    "GB-15": {
        "anomaly": "borderline, leaning False",
        "technique": "N/A if not anomalous",
        "blast_radius": "N/A if not anomalous; HIGH if it is (table tagged production)",
        "decision": ["monitor_only", "escalate_to_human"],
        "rationale": "Business hours, MEDIUM severity, no keyword match ('audit-log-archive' isn't in PROD_KEYWORDS) — this is the genuinely low-real-risk case in the DynamoDB family (compliance logs, no direct PII), included as a contrast to GB-14/GB-16.",
    },
    "GB-16": {
        "anomaly": True,
        "technique": "N/A if not anomalous; UNKNOWN if it is",
        "blast_radius": "LOW (per the system's own CRITICAL_TAGS definition — 'secret'/'credential' tags don't count, only production/pii/payment/admin do)",
        "decision": ["escalate_to_human", "monitor_only"],
        "rationale": "Deliberate probe of a real tension: 'secret' and 'vault' both appear in PROD_KEYWORDS, so Layer 1 should very likely flag this anomalous on keyword grounds alone — but Layer 3's severity check only recognizes 4 specific tag words, none of which this table carries, so blast radius mechanically reads LOW despite the resource genuinely holding API credentials. Expected outcome: Layer 1 correctly flags it, Layer 3/5 under-rate its real-world severity. This is recorded as an EXPECTED, disclosed system limitation, not scored as a pipeline failure.",
    },

    "GB-17": {
        "anomaly": True,
        "technique": ["T1098", "UNKNOWN"],
        "blast_radius": "HIGH",
        "decision": "attempt_auto_fix",
        "required_access": [["dynamodb:PutItem", "arn:aws:dynamodb:us-east-1:700100200300:table/halcyon-billing-records"]],
        "forbidden_access": [["lambda:UpdateFunctionCode", "*"]],
        "rationale": "Off-hours, CRITICAL. Entry checkout-fn-exec-role reaches billing-records directly (critical) -> HIGH by direct traversal. ATT&CK is genuinely ambiguous here (self-modifying Lambda code is closer to defense-evasion/persistence than classic account manipulation) — both T1098 and UNKNOWN are recorded as acceptable rather than forcing false precision.",
    },
    "GB-18": {
        "anomaly": True,
        "technique": "T1098",
        "blast_radius": "LOW",
        "decision": "attempt_auto_fix",
        "required_access": [["dynamodb:DeleteItem", "arn:aws:dynamodb:us-east-1:700100200300:table/halcyon-tmp-cache-table"]],
        "forbidden_access": [["dynamodb:DeleteTable", "*"]],
        "rationale": "Off-hours, HIGH. tmp-cache-table is untagged, and it's the only resource cleanup-fn-role reaches -> LOW blast radius by direct traversal. A safe narrowing fix is still correct here, same as GB-07 — low blast radius doesn't mean 'don't fix', it means 'this one's low-urgency but still worth narrowing'.",
    },
    "GB-19": {
        "anomaly": False,
        "technique": "N/A (short-circuit expected)",
        "blast_radius": "N/A (short-circuit expected)",
        "decision": "monitor_only",
        "rationale": "Business hours, LOW/COMPLIANT severity, and the role's only real permission is described as source-IP-restricted — should read as a non-issue. Also a fresh, non-copied exercise of the GROWTH_PLAN.md Phase 7 condition-key handling in a new narrative context.",
    },

    "GB-20": {
        "anomaly": True,
        "technique": "T1098",
        "blast_radius": "CRITICAL",
        "decision": "attempt_auto_fix",
        "required_access": [["dynamodb:GetItem", "arn:aws:dynamodb:us-east-1:700100200300:table/halcyon-audit-log-archive"]],
        "forbidden_access": [["sts:AssumeRole", "arn:aws:iam::700100200300:role/halcyon-partner-sync-role"]],
        "rationale": "Off-hours, CRITICAL. Same entry point/traversal as GB-09 (legacy-reporting-role) -> CRITICAL confirmed by direct traversal (2 critical resources reached across the 2-hop chain). Framed here specifically as the cross-service/multi-hop family representative.",
    },
    "GB-21": {
        "anomaly": True,
        "technique": "T1098",
        "blast_radius": "HIGH",
        "decision": "attempt_auto_fix",
        "required_access": [["s3:GetObject", "arn:aws:s3:::halcyon-customer-pii-store/training-set.csv"]],
        "forbidden_access": [["iam:PassRole", "*"]],
        "rationale": "Off-hours, HIGH. Entry ml-training-role reaches customer-pii-store (critical) + dev-scratch-bucket (not critical) -> 1 critical resource -> HIGH by direct traversal.",
    },
    "GB-22": {
        "anomaly": True,
        "technique": "T1098",
        "blast_radius": "LOW (honest default — principal is not a known graph node)",
        "decision": "attempt_auto_fix",
        "required_access": [],
        "forbidden_access": [["iam:CreateAccessKey", "*"]],
        "rationale": "Off-hours, CRITICAL, full wildcard grant to an identity outside the known graph entirely. Blast radius correctly defaulting to LOW here is the EXPECTED, correct behavior (the system has no way to know what an unknown external identity can reach) — not a failure to detect risk. The decision should still be attempt_auto_fix regardless, since Layer 4's drafting doesn't depend on blast radius being resolved, and a full wildcard grant to an unvetted external identity is dangerous on its face.",
    },

    "GB-23": {
        "anomaly": True,
        "technique": "T1098",
        "blast_radius": "HIGH",
        "decision": ["escalate_to_human", "attempt_auto_fix"],
        "rationale": "Genuinely hard case, disclosed as such in advance. My independent judgment leans escalate_to_human — narrative context suggesting a possibly-legitimate, time-boxed incident-response grant is exactly the kind of nuance that should prompt a human check rather than an automatic narrowing, even though the underlying permission shape looks identical to GB-06's clearly-wrong case. Scored leniently (both answers accepted) precisely because this is acknowledged as genuinely ambiguous, not because the system get a pass — the interesting result is which way it actually goes, not whether it matches a forced 'right' answer.",
    },
    "GB-24": {
        "anomaly": None,
        "technique": "N/A",
        "blast_radius": "N/A",
        "decision": "no_crash",
        "rationale": "Not a correctness test — a robustness check. Missing account_id/region should not crash the pipeline. Any decision is acceptable EXCEPT an unhandled exception; monitor_only/escalate_to_human are both more defensible than a confident auto-fix on incomplete data, but the primary pass/fail bar here is simply 'did it run and return a decision at all'.",
    },
}

assert set(GROUND_TRUTH.keys()) == {f"GB-{i:02d}" for i in range(1, 25)}
