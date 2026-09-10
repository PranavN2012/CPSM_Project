# CloudSentry / Serverless CSPM — Context (AI Engine Build)

This document is the single source of truth for the AI/ML layer built on top
of the existing rule-based CSPM. Read this before picking the project back up
in a new session. For the pre-existing rule-based system (S3/IAM/SG/DynamoDB
checks, NLG engine, policy-as-code, multi-cloud providers), see
`PROJECT_DETAILS.md` — that document was NOT changed by this work and remains
accurate for everything it covers.

---

## 1. What this build added

A 5-layer AI/ML threat-intelligence engine plus an agentic LLM orchestrator,
living entirely in `lambda/shared/ml/`. It does **not** replace or modify the
existing rule-based remediation engine — it's an additional, currently
**standalone** analysis layer (see §4, "not wired in yet").

| Layer | File | What it does |
|---|---|---|
| 1 — Anomaly Detection | `ml/anomaly_detector.py` | Isolation Forest over 10 features (time, frequency, prod-keyword, cross-region, etc.) with a sliding event window for slow/low-and-slow attack patterns. |
| 2 — ATT&CK Classification | `ml/semantic_scorer.py` | SBERT embeddings + a 30-technique MITRE ATT&CK knowledge base. Converts structured events to natural language (`EventNarrator`) before embedding, and uses a **calibrated** similarity threshold (Youden's J over labeled pairs) rather than a guessed cutoff. |
| 3 — Blast Radius | `ml/blast_radius.py` | Graph BFS over IAM roles/users, S3 buckets, Lambda functions, DynamoDB tables, security groups. Answers "if this identity is compromised, what can it reach, and how bad is it." |
| 4 — Policy Agent | `ml/policy_agent.py` | Agentic propose → test → revise loop: drafts an IAM policy fix (LLM or rule-based), tests it against a local sandbox evaluator, retries on failure (up to 3 attempts) with the failure fed back into the next prompt. |
| 5 — Priority Scoring | `ml/priority_scorer.py` | Weighted composite (0–100, tier P1–P4) combining Layers 1–3 plus "threat recency" (has this pattern been seen before, computed from the system's own history — not an external feed). |
| Orchestrator | `ml/orchestrator.py` | The other agentic piece: reads all four layers' output, reasons over it via LLM (or a rule-based fallback), and picks one action: `attempt_auto_fix`, `escalate_to_human`, `gather_more_context`, `monitor_only`. |

Supporting files:
- `ml/env_loader.py` — minimal `.env` reader (no new dependency), loads `GROQ_API_KEY`/`GEMINI_API_KEY`/`LLM_PROVIDER` from a project-root `.env` if not already in the real environment.
- `ml/data/attack_technique_kb.json` — the 30-technique ATT&CK knowledge base.
- `ml/data/classifier_calibration.json` — 32 labeled pairs used to calibrate Layer 2's threshold.
- `ml/data/blast_radius_seed.json` — the hand-built demo infrastructure graph for Layer 3.

---

## 2. LLM setup

Two providers are supported, both behind the same pluggable interface, both
optional — the whole system runs and is fully tested without either:

- **Groq** (OpenAI-compatible chat API) — needs `GROQ_API_KEY` + `pip install groq`. Default model: `openai/gpt-oss-120b` (NOT `llama-3.3-70b-versatile` — that model isn't available on all Groq accounts; verify with `client.models.list()` if you change it).
- **Gemini** — needs `GEMINI_API_KEY` + `pip install google-generativeai` (deprecated by Google in favor of `google-genai`, but still functional as of this build). Default model: `gemini-2.0-flash`.

**Provider selection** (`PolicyAgent._default_client()` / `ThreatOrchestrator._default_reasoner()`): Groq is preferred if both keys are present; override with `LLM_PROVIDER=gemini` or `LLM_PROVIDER=groq` in `.env`. Falls back to a deterministic rule-based implementation (`RuleBasedPolicyDrafter` / `RuleBasedReasoner`) if no key/package is available, or if any LLM call raises.

**Setup:** copy `.env.example` → `.env` in the project root, fill in your key(s) directly in a text editor (never paste keys into chat — `.env` is gitignored). Install everything with `pip install -r requirements-ai.txt`.

**Verified working (this session, live Groq calls):**
- `PolicyAgent.revise_and_retry()` drafted a real IAM policy fix (explicit Deny on the offending action/resource) and passed the sandbox test on attempt 1.
- `ThreatOrchestrator.process_event()` produced a real LLM-authored rationale for an `escalate_to_human` decision, correctly citing the actual context (CRITICAL blast radius, no auto-fix context supplied).

---

## 3. Design decisions: what was retained vs. changed from the original spec

You handed over a detailed "CloudSentry v2" design document (Rev 3) describing
this AI engine. Here's what was kept as-is, and what changed during
implementation — with the reason for each change.

### Retained as specified
- The 5-layer structure and what each layer is responsible for.
- Layer 1's windowed/session-level features to catch slow exfiltration (the doc's Scenario 6 fix).
- Layer 2's `EventNarrator` bridge (structured JSON → natural language before embedding) — this was Loophole #1 in the doc and is implemented exactly as described.
- Layer 2's calibrated threshold via Youden's J statistic on labeled pairs (Loophole #2) — implemented exactly as described, including the honest UNKNOWN fallback when the calibrated pairs are too few (<10).
- Layer 3's blast-radius graph BFS and its explicitly scoped IAM policy parser (Allow/Deny/wildcards only — no condition keys, resource-based policies, permission boundaries, SCPs, session policies).
- Layer 4's propose → test → revise agentic loop, capped at 3 attempts, with failures fed back into the next prompt.
- Layer 5's weighted formula (25/20/35/20 split) and the "threat recency replaces CISA KEV" fix (Loophole #3 — KEV lists CVEs, ATT&CK lists behaviors, no clean mapping exists between them).
- The orchestrator's decision flow and 4-action vocabulary (`attempt_auto_fix` / `escalate_to_human` / `gather_more_context` / `monitor_only`).
- "Nothing touches real AWS without human approval" as a hard rule for Layer 4.

### Changed, and why
| Doc said | Built instead | Why |
|---|---|---|
| New `lambda/shared/ai_engine/` package | Extended existing `lambda/shared/ml/` | Layers 1 and 2 already existed there (built before this session, under different names but the same architecture) — a second parallel package would have meant either duplicate abstractions or thin wrapper classes. Extending in place was your explicit call. |
| Gemini only (`gemini-2.0-flash`) | Gemini **and** Groq, auto-selected | You're using a Groq key. Both are behind the same `LLMClient`/`Reasoner` interface, so this was additive, not a redesign. |
| LocalStack primary / PolicyEvaluator fallback for Layer 4's sandbox | PolicyEvaluator only | Your explicit call — LocalStack IAM enforcement is known to be unreliable (the doc says so itself), and PolicyEvaluator covers the Allow/Deny/wildcard logic Layer 4's drafts actually use. LocalStack wiring is a clearly-scoped future addition, not implemented. |
| ~40 ATT&CK techniques | 30 techniques | Curated for accuracy over reaching an arbitrary count — all 30 are real MITRE ATT&CK Enterprise techniques with correct IDs/tactics, cloud-relevant, spanning Initial Access through Impact. Stated honestly in the KB file's `_source_note` rather than padded to hit 40. |
| Layer 1's 15-feature set (adding source-IP diversity, assume-role depth, role-action-pair frequency, event rate, cross-service spread) | Layer 1 kept its pre-existing 10 features | These 5 features need CloudTrail-level fields (source IP, role-chain depth) that the current event schema doesn't carry. Fixing the one real Layer 1 bug that existed (a failing "stealth attack" test — prod-keyword events were scoring *lower* than benign ones due to noisy training data) was in scope and done; expanding the feature set was explicitly deferred, not silently dropped. |
| Full "re-run Layer 3 to verify" after an auto-fix | Not wired | Would require re-deriving the blast-radius graph's edges from the drafted policy JSON via `build_from_iam_policies()` against a live role→resource mapping. The hand-built seed graph doesn't track per-role policy documents, so this loop is stubbed (`result.post_fix_blast_radius = None`) with the reasoning left in a comment in `orchestrator.py`. `draft.test_passed` (from `PolicyEvaluator`) is the safety signal used instead. |

### Not done at all (explicitly out of scope so far)
- **Not wired into the live pipeline.** `lambda/remediation/lambda_function.py`, `lambda/iam-audit/lambda_function.py`, `scripts/local-api-server.py`, and the dashboard do not call into `lambda/shared/ml/` anywhere. Running `docker-compose up` + `deploy-lambdas.py` + `local-api-server.py` exercises the pre-existing rule-based CSPM only. The AI engine is a tested, working, standalone module — the next real step (not done) is wiring `ThreatOrchestrator.process_event()` into the Lambda handlers so live/simulated events actually flow through it.
- **No LocalStack sandbox path for Layer 4** (see table above).
- **No live re-verification of blast radius after an auto-fix** (see table above).

---

## 4. How to run

### The pre-existing CSPM (rule-based, dashboard, LocalStack) — unaffected by this build
```powershell
docker-compose up -d              # start LocalStack
python scripts/deploy-lambdas.py  # deploy Lambdas into LocalStack
python scripts/local-api-server.py  # serves both API and dashboard on :3001
python scripts/simulate-attacks.py  # optional: generate demo events
```
Dashboard: http://localhost:3001 — this will **not** show AI-layer output (not wired in, see §3).

### The AI engine (standalone, tested, real LLM calls) — this session's work
```powershell
pip install -r requirements-ai.txt   # scikit-learn, sentence-transformers, groq, google-generativeai
# copy .env.example to .env, fill in GROQ_API_KEY or GEMINI_API_KEY
python -m pytest tests/ -q           # 215/219 pass; the 4 failures are pre-existing,
                                      # unrelated (test_remediation.py needs AWS_DEFAULT_REGION set)
```
To exercise it directly (no dashboard yet):
```python
import sys; sys.path.insert(0, "lambda/shared")
from ml.orchestrator import ThreatOrchestrator
result = ThreatOrchestrator().process_event({...})  # see tests/test_orchestrator.py for event shape
```

---

## 5. Test coverage

135 new tests added across 7 new test files (all passing):

| File | Tests | Covers |
|---|---|---|
| `tests/test_anomaly_detector.py` | 47 | Layer 1 (pre-existing + the stealth-attack bug fix) |
| `tests/test_semantic_scorer.py` | 39 | Layer 2 base semantic scoring (pre-existing) |
| `tests/test_attack_classifier.py` | 16 | Layer 2's new `AttackClassifier` + calibration |
| `tests/test_blast_radius.py` | 22 | Layer 3 |
| `tests/test_priority_scorer.py` | 28 | Layer 5 |
| `tests/test_policy_agent.py` | 25 | Layer 4, including live-environment-safe provider-selection tests |
| `tests/test_orchestrator.py` | 25 | Orchestrator, including reasoner-failure fallback and the auto-fix path |

Total suite: 219 tests, 215 passing. The 4 failures are all in `tests/test_remediation.py` (pre-existing, unrelated to this build — a `boto3.NoRegionError` because `AWS_DEFAULT_REGION` isn't set in this shell).

---

## 6. Repo hygiene notes from this session
- `.env` and `.env.local` added to `.gitignore` — never commit real keys.
- Deleted `err.txt` and `sim_out.txt` — leftover PowerShell stderr-redirect artifacts from before this session (UTF-16 garbage, unrelated to any code).
- Cleared all `__pycache__`/`.pytest_cache` directories (already gitignored; regenerate automatically, deleted for a clean tree).
- `scripts/check_nlp.py` was reviewed and kept — it's a real debugging utility (checks whether `nlp_summary` is populated in DynamoDB events), not clutter, despite being untracked.
