# Growth Plan — Serverless CSPM → Excellent Final-Year Project

Goal: move from "solid working system with a canned demo" to "defensible research-grade
project" — generalized behavior, a real evaluation, and a sharp novelty pitch.

Reference: this plan assumes the codebase state as of 2026-09-09 — the 5-layer AI
reasoning pipeline (`lambda/shared/ml/`), the Policy Diff & Approval React view, and
the still-hardcoded demo scenarios in `scripts/local-api-server.py`.

**Locked scope decision (2026-09-10): no real AWS deployment, ever.** This project
stays LocalStack-only by deliberate choice, not oversight, and $0 will be spent on it.
Any phase item that would require a real, billable AWS account is marked cut below
rather than left ambiguous.

**Also done (2026-09-10, outside the phase numbering)**: ran an externally-supplied
"Universal Security Generalization Benchmark" — a pilot-scale (24 of the specified
120-150 scenarios), blind, previously-unseen-data test of the whole pipeline on a
brand-new fictional environment. Zero crashes, zero dangerous auto-fixes across 12
human-review-required cases, 100% independent-verification agreement on every
auto-fix attempted. Full report, including two harness bugs found and fixed along
the way and the honest tester-independence caveat: `eval/generalization_benchmark/REPORT.md`.
The benchmark's one real finding — a systematic T1098/Account-Manipulation vs.
T1484/Domain-Tenant-Policy-Modification confusion in Layer 2, also present in the
main eval — was then root-caused (near-identical KB description text for the two
techniques) and fixed by rewriting `attack_technique_kb.json`'s descriptions to make
the actual distinguishing signal (single-identity vs. org-wide scope) explicit. Main
eval: 0.913→1.000 accuracy, 0.625→1.000 macro-F1. Generalization benchmark rerun on
the same frozen scenarios: 60%→100% ATT&CK accuracy, 55%→82% Safe Auto-Fix Rate, all
safety-critical numbers (0% dangerous auto-fix, 100% correct escalation, 0 crashes)
unchanged. See the Addendum at the top of `eval/generalization_benchmark/REPORT.md`
and the Layer 2 section of `eval/EVAL_REPORT.md` for full before/after detail.

**Status as of 2026-09-10**: Phases 0-5 are all complete (see the "DONE" notes on
each). **Phase 6 is next.** Phase 7 follows it — both scoped specifically to what's
achievable solo and free (no real AWS, ever) — see `PROJECT_MASTERCLASS.md` Part
"Absolute growth scope" discussion for the full tiered reasoning behind this split.

---

## Phase 0 — Close the seams an examiner will find in 10 minutes ✅ DONE (2026-09-10)

1. ✅ **All 4 `DEMO_ATTACK_SCENARIOS` now have a `policy_fix_context`** — `demo-1`
   (dev-intern-role / unrestricted AssumeRole), `demo-3` (backup-service-role /
   unscoped `dynamodb:*` on the session-tokens table), `demo-4` (analyst-user /
   unscoped `s3:*` allowing encryption-config changes) join `demo-2`.
2. ✅ **`PolicyDiffView` now targets the actually-selected incident** — it reads
   `incident.event_id` when it's one of the 4 demo scenarios, and honestly labels
   (rather than silently substitutes) the case where a *live* incident was
   selected, since live events still don't carry policy context (that's Phase 1).
   The previously-hardcoded threat-vector title/description card was also
   S3-specific copy shown for every scenario regardless of type — now a
   per-`vulnerability_type` narrative (`THREAT_NARRATIVES` in `PolicyDiffView.jsx`).
3. ✅ **AI Insights cards now have their own "Review Policy Diff" button**, wired
   through the same `onSelectIncident` prop `App.jsx` already threads to
   `openPolicyDiff` — previously `AIInsightsView` received the prop but never
   rendered anything that used it.

**Real nuance found while verifying (not a bug, worth knowing)**: giving
`demo-3`/`demo-4` a `policy_fix_context` doesn't guarantee they show a draft —
their HIGH/MEDIUM severity means Layer 1's anomaly score sits close to the 0.46
threshold, and even once flagged anomalous, the real (Groq) reasoner often
chooses `escalate_to_human`/`gather_more_context` over `attempt_auto_fix` for
them, same as it should for a less-severe finding. Confirmed via direct pipeline
runs (not just reading code) that `demo-1`/`demo-2` (CRITICAL) reliably reach
`attempt_auto_fix` with a passing draft; `demo-3`/`demo-4` more often correctly
escalate instead. This is the "LLM proposes, sandbox/severity gates it" property
working as intended (see `PROJECT_MASTERCLASS.md` Part 6) — deliberately left
as-is rather than tuning the demo data to force an auto-fix that wouldn't be
warranted for a MEDIUM-severity finding. `PolicyDiffView`'s existing "didn't
produce a draft this run" error message already covers this case honestly.

Also nudged `demo-3`/`demo-4`'s timestamps to a genuinely off-hours weekend
slot (both `is_weekend` and `hour_of_day` are real Layer 1 features) so they
cross the anomaly threshold at all — without this they scored *below* 0.46 and
Layers 2-5 never ran for them regardless of `policy_fix_context`.

Verified: full frontend build passes, `tests/test_local_api_server.py` (5/5)
still passes, and all 4 scenarios were run through the real live orchestrator
directly (not just unit-tested) to confirm the behavior above.

---

## Phase 1 — Make blast radius and priority scoring meaningful everywhere ✅ DONE (2026-09-10)

1. ✅ **Expanded the blast-radius graph** (`lambda/shared/ml/data/blast_radius_seed.json`):
   added `external-vendor-role` and two new edges
   (`external-vendor-role→analyst-user`, `backup-service-role→ci-deploy-role`,
   both `can_assume`), producing a genuine 4-hop escalation chain —
   `external-vendor-role → analyst-user → backup-service-role → ci-deploy-role
   → {prod-data-lake-raw, customer-reports-q1, backup-vault}` — reaching 13
   resources at max depth 5, correctly computing CRITICAL. `analyst-user` and
   `backup-service-role` now also correctly compute CRITICAL (they previously
   sat at a lower severity since they only reached non-critical-tagged
   resources directly). The pre-existing `cspm-s3-remediation → lambda-exec-role
   → cspm-remediation-events` path already covered the "cross-service, Lambda
   exec role → DB" case, so nothing new was needed there.
2. ✅ **Connected live events to the graph** — turned out the natural hook point
   was **not** `policy_engine.py` itself: it's purely a YAML enable/disable
   store with no per-resource state to hang a graph lookup off (verified by
   reading it — no resource/principal field exists anywhere in it). The real
   connection point was `_map_event_for_ai` (local-api-server.py) and
   `ThreatOrchestrator._safe_blast_radius` (orchestrator.py):
   - `_map_event_for_ai` no longer checks a hand-maintained
     `_KNOWN_GRAPH_PRINCIPALS` set (deleted) — it now asks the orchestrator's
     live `InfraGraph` directly whether the resource name is a known
     IAMRole/IAMUser node, so graph expansion (item 1, or any future one)
     is picked up automatically with zero changes needed here.
   - Added `InfraGraph.resource_exposure_severity()` (`blast_radius.py`) — a
     new, separate method for when the event's resource matches a graph node
     that is *not* an identity (e.g. a live S3 Public Access finding on a
     bucket). Deliberately kept separate from `simulate_blast_radius()`
     (unchanged) since that's the exact function verified 20/20 (now 21/21)
     against an independent oracle in `eval/layer3_blast_radius_eval.py` —
     this phase must not invalidate that already-published result.
   - `_safe_blast_radius` now tries identity-based BFS first, then falls back
     to the resource-exposure check, then finally to the honest LOW default.
3. ✅ **Result, verified by direct pipeline run** (not just reading code): a
   live-style event with no `principal` field and `bucket_name:
   "prod-data-lake-raw"` now resolves `severity: HIGH` (was `LOW` before this
   phase); an event with a genuinely unmatched resource name still correctly
   defaults to `LOW`. This works today for any of `simulate-attacks.py`'s
   `BUCKET_NAMES` pool, since those names were already (coincidentally)
   chosen to match the seed graph's bucket nodes exactly.

**Known remaining gap, disclosed rather than silently left**: this fixes S3
bucket findings whose name matches a graph node. It does **not** fix IAM Audit
findings from `simulate-attacks.py`, since those generate a fresh random
username (`dev-intern-{uuid4}`) every run that will never match a fixed graph
node by exact name — a live IAM Audit finding still gets LOW. Closing that
gap would need either a stable identity-name pool (like `BUCKET_NAMES`) or
fuzzy/prefix matching, neither implemented here; noted for a future pass
rather than claimed as solved.

Verified: full test suite still 258/258 passing, Layer 3 eval re-run shows
21/21 exact match against the independent oracle (up from 20/20 — the new
node/edges are covered too), and the HIGH/LOW resolution above was confirmed
via a direct `ThreatOrchestrator.process_event()` call, not just unit tests.

---

## Phase 2 — Targeted, live, multi-actor attack simulation ✅ DONE (2026-09-10)

1. ✅ **`argparse` added to `simulate-attacks.py`**: `--type
   {s3_public,s3_encrypt,iam,sg,dynamodb} [--target NAME] [--account ID]
   [--region REGION]`. A new `run_targeted_attack()` dispatcher calls the
   existing `simulate_*` functions directly (each now accepts optional
   `target`/`account`/`region` kwargs instead of always randomizing);
   omitting `--type` still runs the original fixed demo sequence unchanged.
2. ✅ **`POST /simulate` added to `local-api-server.py`**, accepting
   `{type, target, account, region}` and dispatching to the same
   `run_targeted_attack()` (loaded via `importlib.util`, same technique the
   test suite already used for this hyphenated filename). Validates the
   `type` and JSON body before touching anything, returning a clean 400
   rather than a stack trace on either failure.
3. Skipped the "register a temporary graph node" idea — Phase 1 already
   solved the actual problem it was meant to work around (live findings
   defaulting to LOW), via the resource-exposure fallback, so a temporary
   node would have been redundant complexity for no remaining gap.

**A real bug found via direct testing, not hypothetical**: spinning up the
real server and POSTing to `/simulate` crashed with
`UnicodeEncodeError: 'charmap' codec can't encode '🪣'` — not a LocalStack
connectivity issue, but Python defaulting to a legacy Windows code page for
stdout when invoked non-interactively (as `/simulate` now does, versus
always being run from an interactive terminal before). Fixed by
reconfiguring `sys.stdout` to UTF-8 with a safe fallback at the top of
`simulate-attacks.py` — this protects every emoji `print()` in the file, not
just the new code path.

Verified: full server round-trip tested directly (real `ThreadingHTTPServer`
on an ephemeral port, real POST requests) — confirmed the 400 validation
paths work and that the encoding fix actually resolves the crash (traced
through to the point of a real, expected LocalStack connection attempt,
which this sandbox has no Docker/LocalStack to complete — that part needs
verification in an environment with LocalStack actually running). Added 3
new regression tests (`TestSimulateEndpoint` in `tests/test_local_api_server.py`)
covering unknown type, missing type, and invalid JSON body — full suite now
261/261 passing.

---

## Phase 3 — Build the evaluation you don't currently have ✅ DONE

Completed via the `eval/` harness — see `eval/EVAL_REPORT.md` for full per-layer
results and `TESTING_AND_EVALUATION_SUMMARY.md` for the consolidated writeup. The
sub-items below are kept for record; items 2-3's *baseline comparison* specifically
(propose-test-revise vs. a naive single-shot LLM draft) was **not** done and is
carried forward into Phase 6 §2.

<details>
<summary>Original plan (for record)</summary>

(4-7 days, highest grading leverage)

This is the single biggest gap versus a top-mark project. Right now there is no
quantified claim anywhere — "it runs" is not "it works better than the baseline."

1. **Define the headline contribution**: the LLM-drafted, sandbox-tested IAM policy
   remediation loop (propose → test → revise, `orchestrator.py`'s attempt_auto_fix
   path) — not the whole system. Pick one thing to be rigorous about.
2. **Build a synthetic test corpus**: N (aim for 30-50) crafted misconfiguration
   scenarios spanning the 5 vulnerability types, varied severity, varied blast-radius
   depth, some deliberately ambiguous (should escalate, not auto-fix), some
   deliberately trivial. Store as structured fixtures (extend the
   `DEMO_ATTACK_SCENARIOS` pattern into a larger, file-based corpus rather than an
   inline list).
3. **Run the pipeline over the corpus and report**:
   - Auto-fix success rate (sandbox test passed, policy correctly narrows access)
   - Correct escalation rate (cases that should NOT be auto-fixed and weren't)
   - False-fix rate (a draft that passed sandbox test but is actually still wrong —
     you'll need to hand-verify a sample)
   - Attempt count distribution (how often did it need attempt 2 or 3 of 3?)
   - Compare against a naive baseline: e.g., "revoke all access" or a single
     non-iterative LLM call with no sandbox-test-revise loop — show the propose-test-
     revise loop actually improves outcomes over a single-shot draft.
4. **This table + a short methodology paragraph is worth more to your grade than any
   additional feature.** Put it in the report as its own section.

</details>

---

## Phase 4 — Adversarial/robustness pass via an external LLM ✅ DONE

Completed across two rounds — see `TESTING_AND_EVALUATION_SUMMARY.md` for the full
bug-by-bug record (13 real bugs found and fixed, 258 tests passing).

<details>
<summary>Original plan (for record)</summary>

(parallel with Phase 3, 1-2 days to commission + review)

Use the **Testing Brief** (`TESTING_BRIEF_FOR_LLM.md`, written alongside this plan)
to have a different LLM (fresh context, no stake in the code looking good) probe the
system for bugs, edge cases, and security issues you haven't checked. Concretely:

1. Paste the brief into another LLM (or a separate Claude session with no memory of
   this project) and ask it to generate concrete test cases per section.
2. Actually run the interesting ones — edge cases in detection logic, malformed
   inputs to the API server, concurrency issues in the shared policy cache, prompt-
   injection attempts via event fields that get interpolated into LLM prompts.
3. Fix what's found; log what you decided *not* to fix and why (this is itself good
   material for a "known limitations" section, which examiners respect more than a
   report that claims zero flaws).

</details>

---

## Phase 5 — Documentation & defense prep ✅ DONE (2026-09-10)

`PROJECT_MASTERCLASS.md`, `TESTING_AND_EVALUATION_SUMMARY.md`, and `eval/EVAL_REPORT.md`
cover items 2-3 in full (novelty pitch, rehearsed viva Q&A, architecture teaching).

1. ✅ **`PROJECT_DETAILS.md` updated** — added a full new Section 5A documenting
   the 5-layer AI/ML reasoning pipeline and orchestrator (previously entirely
   missing since the doc predated that layer); rewrote Section 11 (Frontend
   Dashboard) to describe the actual React/Vite app instead of the deleted
   vanilla-JS files it still referenced; corrected Section 19's stale test
   counts (12 → 261) and Section 23's metrics table; updated the "What Makes
   This Project Unique" bullets and the closing footer to record this pass.
2. ~~Write the one-paragraph novelty pitch~~ — done, see `PROJECT_MASTERCLASS.md` Part 6.
3. ~~Prepare 3-4 likely viva questions and rehearsed answers~~ — done, see
   `PROJECT_MASTERCLASS.md` Part 6.4. Original list kept below for reference:
   - "What happens on a misconfiguration type you didn't train/design for?"
   - "How do you know the LLM's policy draft is actually correct, not just plausible?"
   - "What's your false positive/negative rate?" (this is why Phase 3 exists)
   - "Why not just use OPA/Rego like everyone else?" (policy_engine.py's YAML choice)

---

## Phase 6 — Evaluation rigor upgrade (4-7 weeks, all free, all solo)

The next real grading/credibility leverage after Phases 0-2 land, per the tiered
growth-scope discussion: scale the evaluation from "credible methodology on a small
sample" to "credible methodology at a sample size that doesn't need a caveat."

1. **Scale up every layer's eval dataset to hundreds of cases** — ⏸️ **not
   attempted this pass, deliberately**: authoring hundreds of genuinely
   meaningful (not just repetitive/padded) cases per layer, or sourcing and
   correctly re-labeling a public misconfiguration dataset into this
   project's schema, is a multi-session authoring effort in its own right,
   not something to rush inside a single continuous implementation pass
   alongside everything else here — doing it hastily would risk exactly the
   "p-hacked ground truth" failure mode Layer 2's original correction story
   was praised for avoiding. Left as the clearest remaining item for a
   dedicated future session.
2. ✅ **DONE (2026-09-10) — Baseline comparison for Layer 4**
   (`eval/layer4b_baseline_comparison_eval.py`): ran the same 12 scenarios
   through one single-shot `draft_fix()` call each (no retry), independently
   re-verified the same way as the main eval. **Result, run twice: 12/12
   (100%) both times — identical to the full loop's attempt-1 rate.**
   Reported exactly as found rather than spun: on this scenario set, this
   LLM's retry path essentially never triggers, so this comparison doesn't
   show the *retry* mechanism earning its keep (a harder scenario set or
   weaker model would be needed to see that) — but it does show the loop's
   mandatory independent-verification gate catching a real bug live during
   the very first run (see below). Full detail in `eval/EVAL_REPORT.md`'s
   "Layer 4b" section.
   - **Real bug found and fixed along the way**: the first baseline run
     crashed with `AttributeError: 'str' object has no attribute 'get'` — an
     LLM response returned `policy_json` as a JSON-encoded string
     (double-encoding) instead of an object, which `PolicyEvaluator.evaluate()`
     had no guard against. Fixed via `PolicyAgent._coerce_policy_json()` in
     `policy_agent.py` (unwrap once, fall back to the rule-based drafter if
     still malformed) — protects the real orchestrator path, not just this
     eval script. 2 regression tests added to `tests/test_policy_agent.py`;
     full suite 263/263 passing after the fix.
3. ✅ **DONE (2026-09-10) — Ablation study on Layer 5's formula**
   (`eval/layer5b_ablation_eval.py`): re-scored the same 6 scenarios with
   blast radius's 35% weight zeroed out and redistributed evenly across the
   other three. **Result: 2/6 tiers changed, 2/6 ranks changed — and
   removing the weight flips the relative order of exactly the pair it
   should matter for** (an unclassified-but-CRITICAL-blast-radius finding
   drops from P2/#3 to P4/#5, while a well-classified-but-low-impact one
   rises from P3/#5 to P3/#3 and overtakes it; the headline CRITICAL demo
   scenario also drops out of P1 entirely). This is measured evidence the
   35% weight is load-bearing, not an arbitrary choice. Full table in
   `eval/EVAL_REPORT.md`'s "Layer 5b" section.
4. **One human inter-rater check** — still open; needs someone else's time
   (a professor, a security-adjacent contact) to independently rank the
   Layer 5 scenarios by eye against the model's ranking. This is the one
   Phase 6 item that genuinely cannot be done solo — everything else above
   is now either done or explicitly deferred with reasoning, not silently
   skipped.

---

## Phase 7 — Production hardening, LocalStack-only (🟡 IN PROGRESS, started 2026-09-10)

Per the locked scope decision above, this phase deliberately excludes any real-AWS
deployment. Everything below stays inside the existing LocalStack setup.

1. ✅ **DONE — Closed one of Layer 3's stated IAM scope gaps**: condition-key
   support for `aws:SourceIp` and `aws:MultiFactorAuthPresent` in
   `blast_radius.py`'s `_resolve_statements()`/`_is_condition_restricted()`. An
   Allow gated on either is now excluded from the graph entirely rather than
   treated as an unconditional grant — reasoning: blast radius models a
   stolen-credential attacker, who typically can't satisfy an IP allowlist or
   an MFA prompt, so counting such a grant as a real edge overstated
   reachability. Deliberately scoped to just these two keys (the most
   demo-relevant per the original plan) — resource-based policies, permission
   boundaries, and SCPs remain open, honestly, in the module's own docstring.
   5 new regression tests added to `tests/test_blast_radius.py` (including
   one confirming an *unrelated* condition key is correctly left alone — not
   over-claiming more coverage than was actually built); full suite 267/267
   passing; `eval/layer3_blast_radius_eval.py` re-run and still holds.
2. **Dashboard auth/RBAC** — not started. There is currently none. Add real
   login and gate who can click "Deploy Fix" behind a role, not just a
   disabled button. Deliberately not rushed alongside everything else in this
   pass — a security-focused project's own auth layer deserves a dedicated
   design pass, not a bolt-on at the tail of a long implementation session.
3. **Wire "Deploy Fix" to something real (LocalStack only)** — not started,
   same reasoning as item 2 (depends on item 2 existing first — an approval
   flow needs someone to approve as).
4. ✅ **DONE — CI now points at the full test suite.**
   `.github/workflows/cspm-scan.yml`'s `python-tests` job now installs
   `requirements-ai.txt` + PyYAML (previously only `pytest boto3 botocore
   fpdf2`, enough for `test_compliance.py` alone) and runs `pytest tests/`
   (267 tests) instead of just that one file, with `AWS_DEFAULT_REGION` set
   and pip caching enabled. No LLM API key is configured in CI, which is
   correct — the suite is designed to fully exercise the
   `RuleBasedPolicyDrafter`/`RuleBasedReasoner` fallback and mocked LLM
   clients without one. **Not yet verified by an actual CI run** (this
   environment can't trigger GitHub Actions) — confirm on the next real push.
5. **Proper secrets handling** — not started. Move `GROQ_API_KEY`/`GEMINI_API_KEY`
   off a plain `.env` file toward something more deliberate.

---

## Suggested sequencing

Phase 0 → Phase 1 → Phase 2 (can run Phase 6's dataset-scaling in parallel once
Phase 0/1 land) → close Phase 5 item 1 (`PROJECT_DETAILS.md`) → Phase 6 → Phase 7.
Total: roughly 3-4 weeks (Phases 0-2) + 4-7 weeks (Phase 6) + 4-5 weeks (Phase 7),
so 11-16 weeks of part-time work end to end if you take the plan all the way to the
Phase 7 finish line — treat Phase 6 as the point past which further work is "bonus,"
not required, for grading purposes. Phases 0-2 and all of Phase 7 are almost pure
engineering (I can implement these directly). Phase 6 needs your judgment calls on
dataset sourcing and finding one person for the inter-rater check.
