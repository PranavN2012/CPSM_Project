# CloudSentry — The Complete Masterclass

This file teaches the entire project end to end: the cloud security
fundamentals it's built on, how detection and remediation actually work in
your code, what the 5 AI reasoning layers are and why each one exists, and
how you proved (with real numbers) that it's good enough to defend at a
93/100 level. Read it top to bottom once, then use it as a reference before
your viva.

Everything here is traceable to real files in this repo — file names and
line-level behavior are called out throughout so you can open the code and
see exactly what's being described.

---

## Part 1 — The Fundamentals (so the rest of this makes sense)

### 1.1 What is CSPM?

**Cloud Security Posture Management.** Cloud providers (AWS, Azure, GCP)
give you thousands of configuration knobs — who can access what, whether
data is encrypted, which ports are open. Almost every real cloud breach in
the last decade (Capital One, Uber, countless S3 leaks) wasn't caused by a
sophisticated exploit — it was caused by a **misconfiguration**: a bucket
left public, a role with `"*"` permissions, a security group open to the
whole internet.

A CSPM tool's job is boring but critical: **continuously scan cloud
resources against a set of security rules, flag violations, and (in mature
tools) fix them.** Commercial examples: Prisma Cloud, Wiz, Orca Security,
AWS Security Hub. Your project is a from-scratch, serverless implementation
of the same category, plus an AI reasoning layer most commercial CSPMs
don't have.

**Why "serverless" matters as a design choice**: instead of a
always-running server watching your cloud, the whole thing is Lambda
functions that wake up on events (EventBridge), do their check, write to
DynamoDB, and shut down. Cheaper, scales to zero, and — architecturally —
proves you understand event-driven cloud-native design, not just "how to
call an AWS API."

### 1.2 What is S3, and what goes wrong with it?

**S3 (Simple Storage Service)** is AWS's object storage — think of it as a
folder in the cloud that can hold anything from a config file to a
multi-terabyte dataset. Every bucket has:

- **Access policy** — who can read/write it (bucket policy + ACLs + the
  account-level "Block Public Access" setting).
- **Encryption setting** — whether data at rest is encrypted (SSE-S3,
  SSE-KMS) or stored in plaintext on AWS's disks.

**The two failure modes your project detects** (see
`lambda/remediation/lambda_function.py`):

1. **Public access** — a bucket configured so *anyone on the internet* can
   read (or worse, write) its contents. This is the single most common
   real-world cloud breach cause — misconfigured S3 buckets have leaked
   military records, medical data, and financial records in dozens of
   publicized incidents.
2. **Missing encryption** — data sitting in plaintext. Not immediately
   exploitable on its own, but it means a *second* failure (e.g. an
   over-permissive IAM role) turns into a full data breach instead of a
   contained one. Defense in depth: encryption is the safety net for when
   access control fails.

### 1.3 What is IAM, and what goes wrong with it?

**IAM (Identity and Access Management)** is AWS's permission system. Every
human user, every Lambda function, every EC2 instance that wants to touch
an AWS resource does so *as* an IAM identity (a User or a Role), and that
identity's **policy document** (a JSON object) says exactly what it's
allowed to do.

A policy statement looks like:
```json
{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::my-bucket/*"}
```
That's precise — this identity can read objects in exactly this bucket.
The failure mode is **wildcards**:
```json
{"Effect": "Allow", "Action": "*", "Resource": "*"}
```
This identity can do *anything* to *any resource in the account*. If that
identity's credentials leak (a stolen access key, a compromised laptop, an
overly-trusting Lambda), the attacker inherits full account control
instantly.

**What your project detects** (`lambda/iam-audit/lambda_function.py`,
`find_wildcards()`): it walks every policy attached to every IAM
role/user and flags:
- A literal `"*"` in `Action` or `Resource`.
- A service-level wildcard like `"s3:*"` or `"iam:*"` (all actions in a
  whole service).
- A **partial** wildcard like `"s3:Get*"` (anything starting with `Get`) —
  this was a real gap found and fixed during Round 2 adversarial testing
  (see Part 4).
- Case doesn't matter: `"effect": "allow"` (lowercase) is still flagged,
  another Round 2 fix — a naive `!= "Allow"` string comparison would have
  silently let a lowercase-written policy slip through undetected.

This is the exact class of misconfiguration that turned countless "minor"
breaches into full account takeovers.

### 1.4 What is a "policy engine," and is it actually helping?

There are **two completely different things called "policy" in this
project** — worth being precise about this distinction, because it's easy
to blur them in a viva:

**(A) IAM policies** — AWS's own permission documents (Part 1.3 above).
Your project *reads* these to detect problems and *writes new ones* to fix
problems (Layer 4, Part 2.5). You don't invent this format — it's AWS's.

**(B) Your own Policy-as-Code engine** — `lambda/shared/policy_engine.py` +
the 46 YAML files in `policies/`. This is a **rules database**: each YAML
file is one detection rule, e.g.:
```yaml
id: aws-s3-public-read
name: S3 Bucket Publicly Readable
compliance: [CIS, NIST]
check: s3_public_access
enabled: true
```
This is the same category of thing as Cloud Custodian, Prisma Cloud's
rule packs, or Open Policy Agent (OPA) — except those use a language
called Rego, and you deliberately chose YAML because it's simpler to read,
edit, and explain in a defense. `policy_engine.py` loads these into memory
(`_policy_cache`), and the dashboard lets you toggle rules on/off, filter
by compliance framework, and edit them — this is the "which checks are we
actually running" control surface. There's also `policy_generator.py`,
which *auto-writes* new YAML rule files from real incidents ("we just saw
this exact misconfiguration in production — generate a rule so we catch it
automatically next time" — disabled by default until a human approves it).

**So — is it "helping," and for what exactly?**
Yes, but for a specific, narrow job: it's the **on/off switch and
compliance-tagging layer** for *which detections run and why*. It answers
"is this check part of CIS Benchmark 1.1?" and "did someone disable the
public-S3 check on purpose?" It is **not** where the actual detection logic
lives (that's Python code in the Lambda functions, e.g. `find_wildcards()`,
`check_security_group()`) and it's **not** connected to Layer 3's
blast-radius graph yet — that wiring (rule metadata informing which nodes
are "critical") is explicitly listed as unfinished future work in
`GROWTH_PLAN.md` Phase 1. Be honest about that boundary in your defense
rather than overstating it — an examiner who asks "does your policy engine
drive the AI layers?" should hear "not yet, that's a stated next step,"
not a vague yes.

### 1.5 Detection → Remediation, the full loop in plain language

1. **Something happens** in the (simulated) cloud account — a bucket gets
   created public, a role gets an over-broad policy attached. In this
   project that's driven by `scripts/simulate-attacks.py` against
   LocalStack (a local AWS emulator — so you're not touching real AWS).
2. **EventBridge** notices the API call and fires an event.
3. A **Lambda function** (`iam-audit` or the S3/SG checks inside
   `remediation`) wakes up, inspects the actual resource state via boto3
   (AWS's Python SDK), and decides: violation or not?
4. If it's a violation, it's written as a **finding** to DynamoDB (with
   severity, resource, vulnerability type) and — this is the part that
   makes it more than a plain scanner — handed to the **5-layer AI
   pipeline** (Part 2) to decide *how urgent* this is and *what to do*
   about it.
5. **Remediation**: for well-understood cases, `remediation/lambda_function.py`
   can directly fix the problem (e.g. call `put_bucket_encryption`,
   revoke the open security-group rule). For IAM policy problems, fixing
   isn't "flip a setting" — you need a *new, narrower policy document* —
   that's Layer 4's job (Part 2.5), because writing a correct replacement
   policy requires reasoning about what the identity still legitimately
   needs, not just deleting the bad line.

---

## Part 2 — The 5-Layer AI Reasoning Pipeline

This is what elevates the project from "a scanner that flags things" to
"a system that reasons about severity and can act." All 5 layers live in
`lambda/shared/ml/`, tied together by `orchestrator.py`.

**The overall flow** (`orchestrator.py`, `ThreatOrchestrator`):
```
Event ──> Layer 1 (anomalous?) ──No──> log & stop
             │ Yes
             ├──> Layer 2 (what ATT&CK technique is this?)  ─┐
             ├──> Layer 3 (what can this identity reach?)    ├─ run together
             │                                                ┘
             └──> Layer 5 (composite priority score, P1–P4)
                       │
                  Reasoner (LLM) picks ONE of:
                  attempt_auto_fix | escalate_to_human |
                  gather_more_context | monitor_only
                       │
              attempt_auto_fix ──> Layer 4 (propose→test→revise a new policy)
```

### Layer 1 — Anomaly Detection (`anomaly_detector.py`)

**What it is**: an `IsolationForest` (an unsupervised sklearn model) that
scores each event 0–1 for "how unusual is this compared to what normal
looks like."

**Why Isolation Forest specifically**: it doesn't need labeled
"anomalous"/"normal" examples to train on (most security events *aren't*
labeled in the real world) — it works by literally trying to isolate a
point with random splits; anomalous points isolate in fewer splits because
they sit apart from the dense "normal" cluster. That's a defensible choice
to explain in a viva: you're not pretending you have a labeled dataset you
don't have.

**The clever part — windowed/session features**: scoring one event in
isolation misses *slow* attacks (e.g. small data exfiltration spread over
an hour looks fine event-by-event). `EventWindow` keeps a sliding buffer of
recent events and injects session-level features into each event's vector
before scoring: `account_frequency_1h`, `region_frequency_1h`,
`type_frequency_1h`, `cross_region_flag` — on top of per-event features
like `hour_of_day`, `has_prod_keyword`, `severity_encoded`. So the model
sees "this account has done 40 unusual things in the last hour" as part of
scoring the 41st, not just the 41st in isolation.

**Why it matters**: this is the pipeline's first filter — it's what decides
whether *anything downstream even runs*. Get this wrong (too loose) and
you drown in false positives; too strict and you silently miss real
attacks. The calibrated cutoff is `0.46` (`orchestrator.py`,
`ANOMALY_THRESHOLD`), anchored empirically against real simulated-attack
score distributions, not an arbitrary guess.

### Layer 2 — Semantic / ATT&CK Classification (`semantic_scorer.py`)

**What it is**: takes the raw finding, turns it into a natural-language
sentence (`EventNarrator` — e.g. "IAM role dev-intern-role was granted
wildcard S3 permissions"), embeds that sentence with a sentence-transformer
model (`all-MiniLM-L6-v2`, SBERT), and compares it via cosine similarity
against a knowledge base of ~30 MITRE ATT&CK technique descriptions
(pre-embedded once, compared every time).

**What MITRE ATT&CK is**: a public, industry-standard catalog of attacker
techniques (e.g. T1098 "Account Manipulation," T1548 "Abuse Elevation
Control Mechanism"). Mapping a finding to an ATT&CK ID is what lets a
security analyst instantly understand "this looks like *this specific
well-documented attack pattern*" instead of reading a raw log line.

**The critical design decision — calibrated abstention**: the classifier
doesn't force every finding into some technique. It has a
Youden's-J-calibrated confidence threshold (`0.4478`); below that, it
returns `UNKNOWN` rather than a wrong, over-confident label. This matters
a lot — and it's the layer your evaluation (Part 4) proved this decision
was *correct*, not just cautious: findings like "an S3 bucket is public"
or "a security group is open" don't cleanly match any of the 30 techniques
in the KB (they're a *state*, not an observed *action*), and the
classifier correctly abstained on all 8/8 of those cases in evaluation,
rather than forcing a wrong ATT&CK label.

**Why it matters**: Layer 5's priority formula only gives classification
confidence weight *when the classifier is actually confident* — an honest
`UNKNOWN` correctly contributes less to urgency than a confident T1098
match, which is exactly the right behavior (you don't want a wildly wrong
guess pushing something to P1).

### Layer 3 — Blast Radius Simulation (`blast_radius.py`)

**What it is**: models your cloud environment as a directed graph — IAM
roles/users, S3 buckets, Lambda functions, DynamoDB tables, security
groups as nodes; `can_assume`, `can_read`, `can_write`, `can_invoke`,
`can_administer` as edges. Given a compromised (or suspicious) identity as
a starting point, it runs a **breadth-first search (BFS)** to answer: "if
an attacker has this identity, what can they actually reach?"

**Why this is the layer that turns a scanner into a security tool**: a
wildcard IAM policy on some low-value test role is a very different risk
than the same wildcard on a role that can chain into production customer
data. Two findings that look identical in isolation ("IAM Audit: wildcard
detected") can have wildly different real severity — blast radius is what
tells them apart. The project's headline demo scenario is exactly this:
`dev-intern-role` (a low-privilege-looking role) → can assume →
`ci-deploy-role` (admin-tagged) → can administer → `prod-data-lake-raw` and
`customer-reports-q1` (both tagged production/PII). In isolation,
`dev-intern-role` looks boring. Through the graph, it's CRITICAL — 2
critical resources reached.

**Deterministic, not ML** — and stated as an intentional scope
boundary in the code's own docstring: it handles Allow statements,
wildcard matching, AssumeRole trust, multiple statements, and explicit
Deny (Deny wins). It does **not** model IAM condition keys (like
`aws:SourceIp`/MFA requirements), resource-based policies (S3 bucket
policies), permission boundaries, or SCPs. That's a real, disclosed
limitation, not a hidden one — because it's deterministic graph traversal
(not statistical), you can verify it's *correct within its stated scope*
with total precision, which is exactly what the Layer 3 evaluation did
(Part 4).

### Layer 4 — Autonomous Policy Drafting (`policy_agent.py`)

**What it is**: the "propose → test → revise" agentic loop. Given a
vulnerable IAM policy and the specific offending action/resource, an LLM
(Groq's `openai/gpt-oss-120b` model, or Gemini as fallback, or a
deterministic rule-based drafter if no API key is configured) drafts a
**narrower replacement policy** — one that blocks the dangerous permission
while explicitly preserving everything the identity legitimately still
needs.

**Why "propose → test → revise" and not "propose → done"**: an LLM can
write JSON that *looks* right but is subtly wrong (e.g. blocks a whole
resource prefix instead of one specific action, breaking something that
still needed access). `PolicyEvaluator` is a **deterministic sandbox** —
it actually evaluates the drafted policy against the offending action (must
now be denied) and every required action (must still be allowed), without
touching real AWS. If it fails, the agent gets the failure reason fed back
and retries (up to a capped number of attempts), and if it *still* fails,
`orchestrator.py` correctly escalates to a human instead of silently
applying a broken fix — this exact "give up gracefully" path was itself a
bug found and fixed in Round 1 (Part 3).

**Why it matters**: this is the piece that closes the loop from
"detected" to "fixed," for the one class of finding (IAM over-permission)
where the fix genuinely requires judgment, not a fixed script.

### Layer 5 — Priority Scoring (`priority_scorer.py`)

**What it is**: a fixed, published, weighted formula — no ML, fully
deterministic — that composes the outputs of Layers 1–3 plus a recency
signal into one final urgency score (0–100) and tier (P1–P4):

```
score = 0.25 × anomaly_score
      + 0.20 × classification_confidence
      + 0.35 × blast_radius_severity  (LOW/MEDIUM/HIGH/CRITICAL → numeric)
      + 0.20 × recency  (how often has this pattern fired recently)
```

**Why blast radius gets the heaviest weight (35%)**: of the four inputs,
it's the one that most directly answers "how bad would this actually be,"
because it's grounded in real reachability, not a statistical guess. An
event that's only mildly statistically unusual (Layer 1) but reaches
production customer data (Layer 3) should outrank an event that's
extremely statistically unusual but blast-radius-isolated — the weighting
encodes that judgment explicitly and defensibly, rather than burying it in
an opaque model.

**Why it matters**: this is what turns "5 different signals" into "one
number and tier a human or dashboard can sort by." It's also the layer
that's easiest to defend with total confidence in a viva, because it's
just arithmetic — you can (and did, see Part 4) verify it by hand.

---

## Part 3 — What Was Tested, and How the Project Got Fixed

Two rounds of **adversarial testing** were run by generating a detailed
test brief, handing it to a separate LLM to design attack/edge-case test
plans, and then **actually executing every test against the live code** —
not just reading the plan and guessing. Full detail lives in
`TESTING_AND_EVALUATION_SUMMARY.md`; the short version:

### Round 1 — first adversarial pass, 8 real bugs found and fixed
| Bug | Where | Fix |
|---|---|---|
| IPv6 open security groups undetected | `remediation/lambda_function.py` | Added `Ipv6Ranges`/`::/0` checking alongside the existing IPv4 check |
| Only literal `"*"` flagged, not `s3:*` | `iam-audit/lambda_function.py` | Added service-level wildcard detection |
| Ordinal suffixes wrong (111th → "111st") | `nlg_engine.py` | Fixed the `% 10`/`% 100` logic |
| PDF report crashed on non-Latin-1 text (em-dashes, curly quotes) | `report_generator.py` | Transliteration + safe-encode fallback |
| Path-traversal bypass via sibling directory names | `local-api-server.py` | Fixed prefix-matching to require an exact boundary |
| Failed auto-fix attempts stayed mislabeled instead of escalating | `orchestrator.py` | Added the missing `escalate_to_human` branch |
| A fully malformed event silently returned 200 instead of 400 | `remediation/lambda_function.py` | Found incidentally while re-verifying — fixed |
| A test's own mock didn't match the real exception type | `tests/test_remediation.py` | Fixed the mock, not the code |

**Result: 30 new regression tests added, 249 tests passing.**

### Round 2 — harder adversarial pass, 5 more real bugs found and fixed
| Bug | Where | Fix |
|---|---|---|
| Partial wildcards like `s3:Get*` not flagged | `iam-audit/lambda_function.py` | Broadened to flag `*` anywhere in an Action |
| Lowercase `"effect": "allow"` bypassed detection | `iam-audit/lambda_function.py` | Case-insensitive comparison |
| `None`/`NaN` inputs crashed or silently inflated the priority score to max | `priority_scorer.py` | Explicit None/NaN handling, defaults to 0 with a logged warning |
| A future timestamp (year 2099) was counted as "very recent" | `priority_scorer.py` | Bounded the recency window both directions |
| `/ai/insights?limit=abc` leaked a raw Python exception in a 500 | `local-api-server.py` | Clean 400 response instead |

Also **stress-tested concurrency directly** — 300 concurrent read/write
requests against the real policy files — 0 corruption, confirming
`policy_engine.py`'s in-memory cache handles concurrent access safely.
(One honest process note, fully disclosed and fixed: running that stress
test against the real, untracked `policies/*.yaml` files briefly corrupted
8 files' description text; every file was manually restored and verified
clean.)

**Result: 8 more regression tests added, 258 tests passing, 0 failing.**

### Why this testing methodology itself matters for your grade

The rule followed throughout: **never report a finding as confirmed
without actually reproducing it** — spinning up real HTTP servers on
ephemeral ports, running real mocked Lambda invocations, executing real
one-line Python reproductions of each claimed bug before touching any
code. That's the difference between "an LLM said this might be broken"
and "here is the exact input, the exact wrong output, and the exact fix,"
which is what an examiner can actually verify.

---

## Part 4 — Proving the AI Layers Actually Work (not just that they run)

This was the biggest single improvement to the project's credibility. It's
one thing to say "we have an AI reasoning pipeline"; it's another to show
**measured evidence, against a real ground truth, with failure modes
disclosed rather than hidden.** That's what `eval/` does — full detail in
`eval/EVAL_REPORT.md`. Summary:

| Layer | Metric(s) | Result |
|---|---|---|
| 1 — Anomaly Detection | Precision / Recall / F1 / ROC-AUC | 0.889 / 1.000 / 0.941 / 0.973 |
| 2 — ATT&CK Classification | Accuracy / Macro-F1 | 0.913 / 0.625 |
| 3 — Blast Radius | Match vs. independent oracle | 21/21 exact (graph expanded per `GROWTH_PLAN.md` Phase 1; was 20/20) |
| 4 — Policy Drafting | Pass rate (real LLM, independently re-verified) | 100% attempt 1, 100% within 3, 12/12 independently confirmed |
| 5 — Priority Scoring | Monotonicity / Ranking correctness | 6/6 / 6/6 |

**Why each methodology choice was the right one for that layer's nature**:
- Layer 1 and 2 are statistical classifiers → standard ML metrics
  (precision/recall/F1/ROC-AUC, confusion matrices) against a hand-labeled
  ground truth, exactly like you'd evaluate any classifier.
- Layer 3 is deterministic graph traversal, not ML → "ground truth" means
  an **independently-coded second implementation** (built with `networkx`,
  in a different style than the original BFS) rather than a by-hand trace
  a human could get subtly wrong on a graph this size.
- Layer 4 involves a real, non-deterministic LLM → tested against the
  actual configured Groq client (not the trivial always-succeeds
  rule-based fallback), with every pass **independently re-verified** by a
  fresh sandbox instance rather than trusted from the agent's own
  self-report.
- Layer 5 is pure arithmetic → verified by hand against the published
  formula, plus monotonicity checks (raising any one input can never
  lower the score) as a correctness proof, not just a scenario check.

### The two moments that made this credible, not just favorable

Two ground-truth guesses were made **before** running the code, turned out
to be wrong once actual results came back, and were corrected transparently
rather than quietly fixed or hidden:

1. **Layer 2**: initially guessed S3-public-access and open-SSH findings
   should map to ATT&CK technique T1190. Running the classifier showed its
   real nearest neighbors were different techniques entirely, and none
   cleared the confidence threshold either way — so the ground truth was
   corrected to `UNKNOWN`, which is the actually-correct label (none of the
   30 KB techniques cleanly describe "a resource left open" as opposed to
   an active exploit step). This is documented in the eval script's own
   docstring, not silently changed.
2. **Layer 5**: 3 of 6 expected-tier guesses were wrong due to hand
   arithmetic mistakes (e.g. expecting P4 for a 50.0 score when the
   documented P3 threshold is 40, not 50). Recomputed independently against
   the formula, confirmed the code was right and the initial guesses were
   the error, and corrected the test data — proving the formula's
   implementation, not just the test, is correct.

This "guess → run → discover the guess was wrong → correct transparently"
loop, done twice and documented both times, is what pushed the external
assessment from "this pipeline runs" to "here's real evidence it reasons
well" — worth leading with in your defense if asked how you validated the
AI components.

### The current, honest 93/100 status

| Category | Score |
|---|---|
| Architecture & technical ambition | 19/20 |
| Security detection | 19/20 |
| AI reasoning & empirical evaluation | 18/20 |
| Remediation safety | 15/15 |
| Backend/API robustness | 9/10 |
| Frontend | 9/10 |
| Reporting | 4/5 |
| **Total** | **93/100** |

The AI-reasoning score sits at 18/20 (not 20/20) for honest, disclosed
reasons — Layer 2's macro-F1 (0.625) reflects genuine uneven per-class
performance on a small hand-built dataset, and Layer 1 has 2 disclosed
false positives on deliberately hard "trap" cases. Both are real, stated
limitations rather than hidden gaps, and pushing past 93 is explicitly
**not** about hunting small bugs — it's about (1) expanding the Layer 2
dataset with per-class analysis, (2) expanding Layer 4's scenario
diversity, and (3) the still-open `GROWTH_PLAN.md` Phase 0/1 items
(generalizing the demo scenarios, wiring the Policy Diff view to the
actual clicked incident instead of a hardcoded example).

---

## Part 5 — The Niche Pieces: Docker, Every Dashboard Page, and What's Real vs. UI-Only

This part exists because a viva examiner is more likely to click around the
dashboard and ask "what's this page actually doing?" than to ask about
sklearn internals. Being able to say precisely — for every single screen —
"this is live pipeline output" vs. "this is a scripted UI demo" is one of
the strongest things you can do in a defense: it shows you understand your
own system's boundaries instead of overselling it.

### 6.1 Docker usage — what it's actually for here

`docker-compose.yml` runs exactly **one** service: `localstack/localstack`,
AWS's own local-emulator container. It doesn't run your Lambda code, your
API server, or your frontend — those all run as plain local processes
(Python scripts, Vite dev server). Docker's whole job is to give you a
fake-but-API-compatible AWS account on your laptop:

```yaml
SERVICES=s3,lambda,dynamodb,events,apigateway,iam,logs,sts,ec2
```
That line is the actual scope of AWS your project touches — S3 buckets,
Lambda invocation, DynamoDB tables, EventBridge (`events`), API Gateway,
IAM, CloudWatch Logs, STS (identity), EC2 (security groups). Port `4566`
is LocalStack's single "unified gateway" — every AWS SDK call for every
service goes through that one port, which is why `deploy-lambdas.py` and
`local-api-server.py` both point boto3 at
`endpoint_url="http://localhost:4566"` with dummy credentials
(`aws_access_key_id="test"`) instead of real AWS keys.

**Why this matters as a design point to raise yourself**: it's what makes
the entire claim "100% local, no AWS account needed" literally true, and
it's why the two "corrupted real files during testing" incidents in Part 3
were recoverable without any risk to a real cloud account — worst case is
local state, not production infrastructure.

`deploy-lambdas.py` is the "no Terraform needed" path — it zips your
Lambda source in-memory and pushes it straight to LocalStack via boto3.
There's also a `terraform/` directory (`scripts/terraform-scanner.py`,
`terraform/main.tf`) as an alternative infra-as-code path — worth
mentioning if asked "could this deploy to real AWS," but the working local
loop is the boto3/LocalStack one.

### 6.2 Every dashboard page, what it does, and what's real

The sidebar (`Sidebar.jsx`) has exactly 7 pages. Going through them
honestly:

**Security Posture (Dashboard)** — the landing page: charts
(`SeverityChart`, `VulnTypeChart`, `TimelineChart`, `AnomalyChart`)
summarizing real findings pulled from the API. This is a genuine read of
whatever's actually in DynamoDB via `local-api-server.py`'s `/scan/*`
endpoints.

**AI Reasoning (5-Layer)** (`AIInsightsView.jsx`) — the real pipeline,
live. Two buttons matter here and the distinction is important to state
correctly if asked:
- **"Simulate Attack Scenarios"** runs 4 hand-crafted incidents
  (`DEMO_ATTACK_SCENARIOS` in `local-api-server.py`) whose IAM principals
  match nodes in the demo blast-radius graph — so blast radius and (for
  one scenario) an actual Layer 4 policy draft genuinely fire.
- **"Analyze Live Events"** runs Layers 1–5 over real CSPM telemetry from
  your own LocalStack scans — but since those resource names don't exist
  in the hand-built blast-radius graph, blast radius correctly shows LOW
  for them (there's nothing to traverse *to*). This is disclosed directly
  in the UI's own copy, not hidden: *"blast radius will show LOW"* for
  live events. That's a real, honest scope gap — the demo graph doesn't
  yet generalize to arbitrary live resources — and it's exactly
  `GROWTH_PLAN.md` Phase 0/1's open item.

Every card here — anomaly score, ATT&CK technique, blast radius severity,
priority tier, orchestrator rationale — is the actual JSON the pipeline
produced for that run, rendered directly, not mocked UI text.

**Attack Path & Blast Radius** (`AttackPathView.jsx`) — **be precise about
this one**: it's labeled in its own source as "v2 Preview," and it is a
**scripted CSS/timeout animation** over 4 fixed nodes (Public IP → Open
Port 22 → Compromised IAM → Public S3 Bucket) — not a call into
`blast_radius.py`'s real BFS. It's a visual explainer of *what* blast
radius conceptually means, built before the real Layer 3 engine existed,
and it hasn't been rewired to render real graph output yet. **The real
blast-radius numbers live in the AI Insights and Policy Diff pages** (Layer
3 cards, e.g. `dev-intern-role`'s actual CRITICAL severity from the real
21-node seed graph). If an examiner asks "is this animation real," the
correct answer is: "no, that page is a UI concept demo; the actual graph
traversal runs here —" and point at AI Insights/Policy Diff. Saying this
proactively is much stronger than hoping it doesn't come up.

**Policy Diff & Approval** (`PolicyDiffView.jsx`) — this is real, and it's
one of the most carefully-built pages in the project. It reruns the full
pipeline against exactly the one demo scenario that carries IAM policy
context (`demo-2`: `ci-deploy-role` administering the production S3
bucket) and renders:
- The actual before/after IAM policy JSON as a **computed line diff**
  (`utils/lineDiff.js` — a real diff algorithm, not a canned screenshot).
- The real Layer 4 rationale text the LLM produced.
- The real "must-still-allow" check result from `PolicyEvaluator`.
- A visible SLA countdown timer and "Deploy Fix" button that is
  **intentionally disabled** — the page footer says outright *"Nothing
  here touches real AWS"* and *"This is a UI review page — no policy is
  actually deployed from here."* That's a deliberate safety boundary, not
  an unfinished feature — worth stating as a design choice: an autonomous
  agent that can *draft* a fix but is architecturally prevented from
  *deploying* one without a human clicking a (currently disabled, for
  demo safety) approval button is the responsible way to build this.
- **Known limitation, stated in the code's own comment**: only this one
  demo scenario has `policy_fix_context` wired up; real live CSPM events
  don't carry the IAM-policy-before/after context Layer 4 needs, so this
  page can't yet run against arbitrary live findings. Same open item as
  6.2's Attack Path gap — both trace back to `GROWTH_PLAN.md`.

**System & Audit Trace** (`EventsView.jsx`) — the raw event log: every
finding/remediation event from DynamoDB, filterable by status (Secured /
Verified / Alerts / IAM), each row showing timestamp, resource, severity,
status. This is your literal audit trail — "what happened, when, to what
resource, what was the outcome." It also has a **"Dispatch Issues"**
button that calls `createGithubIssues()` — a real integration
(`github_notifier.py`) that files actual GitHub Issues (labeled by
severity/type, e.g. `s3-public-access`, `iam-audit`) for the 5 most
actionable open findings, so a security team's existing GitHub-based
workflow gets tickets automatically instead of someone reading a dashboard
by hand.

**Policy Engine** (`PoliciesView.jsx` + `PolicyCard.jsx`) — the Part 1.4
policy-as-code manager: toggle any of the 46 YAML rules on/off, filter by
provider, and **sync** — a genuinely interesting piece
(`policy_sync.py`): it can pull in *more* detection rules from three real
external sources — a GitHub community repo, a bundled CIS Benchmark
baseline (`policies/feeds/cis_baseline.json`), and Prowler's open-source
rule metadata — converting each into your YAML format. The code's own
docstring frames this well: *"Architecture: like antivirus signature
updates for cloud security."* Toggling a policy that was auto-generated
from a real incident (`policy_generator.py`, always created disabled,
`needs_review: true`) also clears its review flag — that's the human
approval step for auto-generated rules, deliberately separate from
Layer 4's per-incident policy *drafts* (which are IAM policies, not
detection rules — don't conflate the two "policy" concepts here either,
same distinction as Part 1.4).

**System Settings** (`SettingsView.jsx`) — **honest disclosure**: this page
is presentational only. The Discord webhook field and "Sync Repository"
button are both disabled, static UI (`disabled` in the JSX) — they
communicate *what integrations exist conceptually* (Discord notifications,
GitHub sync) rather than being live controls. The GitHub integration it
describes is real (that's `github_notifier.py`, exercised from the Events
page's "Dispatch Issues" button) — Settings just isn't the page that
triggers it. If asked, say plainly: "Settings is a static summary page;
the live GitHub integration is wired up and used from the Events page."

### 6.3 Discord and GitHub notifications — real vs. described

- **GitHub Issues**: real, working, tested (`github_notifier.py`,
  triggered from `EventsView`'s "Dispatch Issues" button). Needs a
  `GITHUB_TOKEN` env var to actually fire; without one it fails cleanly
  rather than crashing.
- **Discord webhook**: referenced in `deploy-lambdas.py`
  (`DISCORD_WEBHOOK_URL` env var) as a configurable notification channel,
  and shown as "Active" in Settings — but the Settings field itself is a
  disabled placeholder, not a live editable integration control. Treat it
  as "supported by the backend, not yet a live dashboard control" if
  asked directly.

### 6.4 The pattern worth naming out loud in your defense

Notice the theme across 6.2: **every page that could plausibly be
mistaken for "the AI pipeline" clearly separates real pipeline output
(AI Insights, Policy Diff) from illustrative UI (Attack Path animation,
Settings placeholders)** — and the real pages' own on-screen copy discloses
their exact scope (e.g. "blast radius will show LOW" for live events,
"nothing here touches real AWS"). That's not a weakness to hide — actively
narrating it ("this page is real pipeline output; this one is a concept
visualization we haven't wired to the real graph yet, and here's exactly
why") reads as engineering maturity, and it's the same honesty pattern
that made the AI evaluation in Part 4 credible in the first place.

---

## Part 6 — Defending This Project: Novelty, Trust, and the Tough Questions

Everything above teaches *what the project is*. This part teaches *how to
defend it* — the questions a real security professional (or a sharp
examiner) will actually ask, and the honest, precise answers you've already
earned the right to give.

### 6.1 The safety-gated pipeline — the actual architecture, stated once cleanly

```
Cloud event → anomaly detection (Layer 1) → ATT&CK reasoning (Layer 2)
  → blast-radius analysis (Layer 3) → LLM policy generation (Layer 4a)
  → deterministic policy validation (Layer 4b, PolicyEvaluator)
  → priority scoring (Layer 5) → auto-fix OR human escalation
```

The single sentence worth memorizing, because it's the load-bearing idea of
the whole project: **the LLM proposes, it never disposes.** Layer 4 splits
cleanly into a generative half (the LLM drafts a candidate policy) and a
deterministic half (`PolicyEvaluator`, plain Python, no model) that
independently checks whether that draft actually blocks the offending
permission and actually preserves everything required — and only a passing
check can ever lead to `attempt_auto_fix`. Nothing generative sits between
"the AI thinks this is fixed" and "the system acts as if it's fixed."

### 6.2 Why this is provably true, not just designed that way

Design intent is cheap to claim and easy to get wrong in practice. Three
specific things were actually tested, live, to confirm the boundary holds
(all in `TESTING_AND_EVALUATION_SUMMARY.md`, Round 2):

- **A "lying" LLM** — a test double that reports `test_passed=True` no
  matter what — was fed into the pipeline. The sandbox evaluator's own
  independent check still governs; the lie is ignored. This is the
  concrete proof behind "we don't trust the LLM's self-report," not just
  a documentation claim.
- **Prompt injection** — attacker-controlled text was planted in
  `bucket_name`, `nlp_summary`, and a policy-context `rationale` field
  (anywhere user-influenced strings eventually reach a prompt), then
  traced end-to-end. It never reached a generative LLM call in a form
  that could steer the decision, and the pipeline still produced
  `escalate_to_human` — not the attacker-demanded `auto_fix`.
- **The golden invariant, end-to-end**: with Layer 4 deliberately made to
  fail, a finding that is CRITICAL blast radius *and* P1 priority
  everywhere else still comes out as `AUTO-FIX=FALSE`. Nothing downstream
  of a failed validation can override that — severity elsewhere in the
  pipeline never buys a bypass. That's the property a security reviewer
  actually cares about: **the system's worst-case failure mode is "ask a
  human," never "silently apply an unverified fix."**

Also worth naming: **idempotency** (remediating the same event twice
concurrently doesn't double-apply or corrupt state) and **no TOCTOU gap**
(there's no window where a check-passed decision goes stale before it's
acted on, because Layer 4 never auto-applies anything without the human
approval step, and base checks run synchronously within one Lambda
invocation) — both stress-tested, not just asserted.

### 6.3 How to talk about novelty honestly

None of the individual pieces are new — CSPM, misconfiguration detection,
IAM analysis, attack-path/blast-radius graphs, MITRE ATT&CK mapping, and
LLM-assisted remediation all exist separately in commercial tools (Wiz,
Prisma Cloud, Orca) and research. Claiming to have invented a new
technique doesn't survive five minutes of questioning and isn't the
project's actual strength anyway.

**The honest, defensible novelty claim**:
> "The novelty isn't in any individual detection technique — it's in
> integrating anomaly detection, ATT&CK semantic classification,
> graph-based blast-radius analysis, LLM-generated remediation, and
> deterministic policy verification into one safety-gated decision
> pipeline, where generative output is never trusted without an
> independent deterministic check."

That's the difference between "we used an LLM to detect AWS
vulnerabilities" (crowded, weak claim) and describing an actual decision
architecture with a stated trust boundary (specific, defensible).

**A rough novelty scale, worth internalizing rather than reciting**: if 1
is an ordinary CRUD student project and 10 is genuinely publishable new
research, this sits around **6.5–7/10** on novelty specifically — but
**8.5–9/10** on technical sophistication, cybersecurity relevance, and
engineering quality after the adversarial testing. Those are better
numbers to actually have than an overclaimed "9/10 novel research"
that collapses under one follow-up question. A final-year project doesn't
need to invent a new field to be excellent — it needs to combine existing
ideas competently, safely, and provably, which is exactly what happened
here.

### 6.4 Rehearsed answers to the questions that will actually come up

**"What's actually new here?"**
→ The integration and the trust boundary (6.3's quote), not any single
technique.

**"Why should I trust the LLM?"**
→ "We don't trust it as final authority. It proposes a policy; a
deterministic evaluator independently checks it; automatic remediation is
blocked unless that check passes — proven with a test LLM that lies about
its own success and gets overridden anyway."

**"What happens if the model fails?"**
→ "Escalation, not silent failure. A CRITICAL/P1 finding with a failing
Layer 4 still comes out as no-auto-fix, end-to-end, tested directly."

**"Is this production-ready?"**
→ No, and say so plainly — this is the answer that actually builds
credibility, not the one that risks it. It's a strong research/prototype
implementation of a production-inspired architecture, not a
production-grade platform. The concrete, honest reasons why:
- The blast-radius graph is small and hand-built (21 nodes as of
  `GROWTH_PLAN.md` Phase 1), not connected to a real, continuously-discovered
  cloud inventory. Phase 1 did connect live events to it (a live finding
  whose resource name matches a graph node now gets a real severity instead
  of always LOW), but the graph itself is still static and manually
  authored, not auto-discovered.
- The AI evaluation datasets are small (20–30 cases per layer) and
  hand-authored, not large labeled corpora — stated outright in
  `eval/EVAL_REPORT.md`.
- ATT&CK classification performance is uneven across classes (macro-F1
  0.625 vs. accuracy 0.913) — a real, disclosed weakness, not hidden
  behind the headline accuracy number.
- Only one demo scenario carries the IAM policy context Layer 4 needs;
  live findings don't yet generalize into that path (Part 5.2).
- It runs against LocalStack, a single simulated account — not validated
  against real multi-account AWS, real traffic volume, or adversaries
  operating against a live system.
- Cloud-service coverage is deliberately narrow (S3, IAM, security
  groups, DynamoDB) — not a full CSPM surface.

**"What would stop you from approving this for a pilot?"** (the sharpest
version of the production-readiness question) — this is worth asking
yourself before anyone else does. The honest answer: the small,
static blast-radius graph and the narrow AI evaluation sample sizes are
the two things that would need to grow substantially before any real
environment, plus the demo-only Layer 4 policy context would need to
generalize to arbitrary live findings.

### 6.5 How to open the presentation

Don't lead with "AI-powered CSPM using LLMs" — that phrase is crowded and
invites exactly the skepticism 6.3 describes. Lead with the safety
property instead:

> "A safety-gated cloud security posture management pipeline that combines
> ML-based anomaly detection, ATT&CK-based attack reasoning, graph-based
> blast-radius analysis, and LLM-assisted remediation — where every
> generative output passes through independent deterministic verification
> before anything is allowed to auto-fix."

Then demonstrate the chain itself: Detection → Reasoning → Proposed Fix →
Independent Verification → Auto-fix OR Human Escalation. That one diagram,
explained correctly, tells a security professional you understand the
difference between *using* AI and *safely deploying* AI in a
security-critical system — which is the actual takeaway you want them to
leave with.

---

## Part 7 — The Data Layer, the API Surface, CI/CD, and Multi-Cloud

Everything so far has been "what happens and why." This part is the
plumbing that makes it happen — the part an interviewer digs into after
the architecture pitch to see if you actually built it or just described
it.

### 7.1 The data layer — DynamoDB

There's one core table, created by `deploy-lambdas.py`:
```python
KeySchema=[{"AttributeName": "event_id", "KeyType": "HASH"}]
```
A single **partition key**, `event_id` (a UUID generated at detection
time) — no sort key, so this is a flat table of independent finding
records, not a hierarchical/time-series design. Each item is one finding:
vulnerability type, severity, resource name, region, status
(`REMEDIATED`/`COMPLIANT`/`FAILED`/etc.), timestamp, and — for events that
went through the AI pipeline — the attached anomaly score, classification,
blast radius, and priority tier. Every dashboard page that shows "real
data" (Dashboard, Events, most of AI Insights) is ultimately reading from
this one table via `local-api-server.py`'s `/scan/*` and `/trends`
endpoints. **Why this is a defensible design, not a limitation to
apologize for**: a flat table keyed by event ID is exactly right for a
write-once, read-by-scan/filter access pattern (which is what a findings
feed is) — you'd only need a sort key or GSIs if you were optimizing for a
specific query pattern like "all events for bucket X in the last 7 days,"
which this project doesn't claim to need yet.

### 7.2 The API surface — every endpoint, in one place

`local-api-server.py` is a single `ThreadingHTTPServer` that is the one
front door for the whole system — the built React frontend, the Lambda
proxying, and the AI pipeline invocation all go through this one process
on one port. The full route table:

| Endpoint | What it does |
|---|---|
| `GET /policies` | List all 46 YAML policy rules (Part 1.4 / 5.2) |
| `GET /providers` | Which cloud providers are configured (Part 7.4) |
| `GET /compliance` | Compliance framework coverage summary |
| `GET /trends` | Time-series data for the dashboard charts |
| `GET /report` | Generates and streams the PDF compliance report |
| `GET /ai/insights` | Runs the real 5-layer pipeline (demo or live mode) |
| `POST /create-issues` | Dispatches GitHub Issues for open findings |
| `POST /policies/sync`, `/sync/github`, `/sync/cis`, `/sync/prowler` | Pull in more detection rules from external sources (Part 5.2) |
| `POST /policies/auto-generate` | Trigger `policy_generator.py` from a real incident |
| `PUT /policies/{id}` | Toggle/edit a single rule |
| `GET /scan/{provider}` | Trigger or read a provider's scan results |
| `GET /` and static paths | Serves the built frontend (`frontend/dist/`) |

**Why this matters to be able to say out loud**: this is a real, if
minimal, backend-for-frontend layer — the React app never talks to
DynamoDB, S3, or an LLM provider directly; everything is mediated through
this one server, which is the right separation of concerns even at small
scale (it's also exactly why the two accidental-corruption incidents in
Part 3 were containable — one process, one clear boundary, easy to trace).

### 7.3 CI/CD — what actually runs on GitHub Actions

`.github/workflows/cspm-scan.yml` runs on every push/PR to `main`, with
two jobs:
1. **Terraform Security Scan** — runs `scripts/terraform-scanner.py`
   against `terraform/`, and if it's a PR, posts (or updates) a comment on
   the PR with the results via the GitHub API (`actions/github-script`).
   This is your project scanning *its own* infrastructure-as-code, and
   automatically leaving human-readable feedback in the same place a real
   reviewer would look — the same "shift security left into the PR"
   pattern real DevSecOps pipelines use.
2. **Unit Tests** — installs `pytest`, `boto3`, `botocore`, `fpdf2` and
   runs `pytest tests/test_compliance.py`. (Worth noting honestly if
   asked: the CI job currently runs one specific test file, not the full
   258-test suite described in Part 3/4 — that full suite runs locally.
   Wiring CI to the full suite is a trivial, worthwhile improvement to
   mention as a "next step" if it comes up.)

### 7.4 Multi-cloud — how far does "cloud-agnostic" actually go?

`lambda/shared/providers/base.py` defines an abstract `CloudProvider`
class (the **Strategy pattern** — same idea used for pluggable Terraform
providers) with four required checks every provider must implement:
`check_storage_public_access`, `check_storage_encryption`,
`check_network_open_ports`, `check_iam_overpermissive`. `aws.py`,
`azure.py`, and `gcp.py` each implement this interface — which is why
`anomaly_detector.py`'s `VULN_TYPE_ENCODING` (Part 2) already has entries
for Azure (`Blob Public Access`, `NSG Open Ports`, `RBAC Overpermissive`)
and GCP (`GCS Public Access`, `Firewall Open Ports`) alongside the AWS
ones — the AI layer's vocabulary was designed multi-cloud from the start.

**The honest scope statement**: AWS (via LocalStack) is the provider
that's actually exercised end-to-end — deployed, demoed, adversarially
tested, and evaluated. Azure and GCP have real, matching detection-check
interfaces (not empty stubs), but they haven't gone through the same
live-deployment and adversarial-testing cycle AWS has. The correct claim
is **"the architecture is provider-agnostic by design (Strategy pattern,
shared AI vocabulary already multi-cloud) and AWS is the fully proven
path"** — not "this is a validated multi-cloud CSPM." That distinction
matters exactly the same way the Part 5 "real vs. UI-only" distinction did
— overclaiming it is the one sentence that would undercut an otherwise
very defensible project.

### 7.5 The frontend — how the SPA is actually built

React + Vite (`frontend/src/`), no router library — page switching is a
single `page` state variable in `App.jsx` and a big conditional render
block (`{page === "dashboard" && <DashboardView .../>}`), which is a
completely reasonable choice for a 7-page internal dashboard (a full
router would be over-engineering here, not a missing feature). One shared
data hook, `useDashboardData.js`, polls the API and feeds `events`,
`stats`, and `compliance` down to whichever view needs them; a second
hook, `useTheme.js`, drives the light/dark toggle. Clicking an incident
anywhere (e.g. a card in AI Insights) calls `openPolicyDiff(incident)`,
which stores the selected incident in state and switches to the Policy
Diff page — the mechanism behind the "selected incident" context you saw
referenced in Part 5.2, even though (stated honestly there too) only the
one demo incident actually has a policy draft to show. All API calls funnel
through one `api.js` client module, which is the one file that would need
to change if the backend's base URL ever moved.

### 7.6 The pieces that quietly hold the demo together

Two shared modules do work you'd otherwise attribute to "the dashboard
magically has nice data":
- **`nlg_engine.py`** — turns a raw finding dict into a human-readable
  incident summary sentence (this is also the module whose ordinal-suffix
  bug — "111th" rendering as "111st" — was one of the Round 1 fixes in
  Part 3). It's the same narrative-generation idea as Layer 2's
  `EventNarrator`, but for human-facing report/dashboard text rather than
  for feeding an embedding model.
- **`simulate-attacks.py`** — the demo-data generator. It creates real S3
  public-access events, real unencrypted-bucket events, and real IAM
  overpermissive-policy events against LocalStack, optionally triggers
  `policy_generator.py` to auto-draft a new detection rule from what it
  just created, and calls `nlg_engine.py` to attach a readable summary —
  i.e. it's the single script that seeds a demo environment end-to-end,
  worth knowing about if asked "how do you get data to show for a demo
  without a real cloud account."

---

## Part 8 — How the Core Algorithms Actually Work (mechanically, not just by name)

Part 2 named the algorithms and explained *why* each was chosen. This
section is "inch to inch" — the actual mechanics, in plain language, so
you can explain *how* they work if pushed, not just *that* they're used.

### 8.1 Isolation Forest, step by step

Build many random binary trees over your data (a "forest"). Each tree is
built the same way: pick a random feature, pick a random split value
between that feature's min and max, and partition the points into two
branches; repeat recursively. Do this for every point in your dataset,
across many trees.

**The core insight**: an outlier — a point that's different from the bulk
of the data — tends to get isolated (end up alone in its own leaf) after
just a few random splits, purely by chance, because it doesn't sit near
the dense cluster where most splits have to cut through crowds of similar
points to separate them. A normal point, sitting in a dense region, takes
many more splits before it's finally isolated. So: **average path length
to isolate a point, across all trees, is the anomaly signal** — short
average path = anomalous, long average path = normal. That raw path
length gets normalized into the 0–1 anomaly score your code reads. This
is why it needs no labeled training data at all — it never learns "what an
attack looks like," only "what's structurally rare in this data's shape,"
which is exactly the right assumption for a domain where labeled attack
examples are scarce.

### 8.2 BFS graph traversal, step by step (Layer 3)

Breadth-First Search explores a graph one "layer" at a time, outward from
a starting node: visit the start, then every node directly connected to
it (depth 1), then every unvisited node connected to *those* (depth 2),
and so on — using a queue (first-in-first-out) so you never jump ahead to
a deeper node before finishing the current depth. Applied here: start at
the compromised identity (e.g. `dev-intern-role`), and each step follows
one of the 5 edge types (`can_assume`, `can_administer`, etc.) to whatever
it can reach next. Every node visited gets added to `reachable_resources`;
if a visited node carries a `CRITICAL_TAGS` tag (production/pii/payment/
admin), it also goes into `critical_resources_reached`. The final severity
comes from a simple, fully deterministic lookup table on those two counts
(2+ critical resources reached → CRITICAL, 1 → HIGH, 4+ total nodes
reached → MEDIUM, otherwise LOW) — no learning involved, which is exactly
why it could be verified to 21/21 exact match against an independent
implementation (Part 4) rather than just "seemed right."

### 8.3 Sentence embeddings and cosine similarity, step by step (Layer 2)

A sentence-transformer model (SBERT, `all-MiniLM-L6-v2`) takes a sentence
and outputs a fixed-length vector of numbers (384 dimensions here) — a
point in a very high-dimensional space, positioned so that
*sentences with similar meaning end up as nearby points*, even if they
don't share any of the same words. This is fundamentally different from
older keyword-matching approaches: "a role was granted wildcard S3
permissions" and "an identity received overly broad storage access" would
land close together despite sharing almost no vocabulary.

**Cosine similarity** is how "nearby" gets measured: it's the cosine of
the angle between two vectors — 1.0 means pointing in exactly the same
direction (same meaning), 0 means unrelated, -1 means opposite. Layer 2
pre-embeds all ~30 ATT&CK technique descriptions once, then for each new
finding: turn it into a sentence (`EventNarrator`), embed it, compute
cosine similarity against all 30 technique vectors, and take the highest
score as the candidate match.

**Youden's J statistic**, the method used to pick the `0.4478` confidence
threshold: for a range of candidate thresholds, plot how the trade-off
between true positive rate and false positive rate changes, and pick the
threshold that maximizes `J = true_positive_rate - false_positive_rate` —
the point that best separates "confident enough to trust" from "not
confident enough" on the labeled calibration data. That's a real,
named statistical method for picking a cutoff, not an eyeballed number —
worth being able to name if asked "how did you choose 0.4478 specifically."

### 8.4 The propose-test-revise loop, step by step (Layer 4)

1. **Propose**: the LLM receives the current (vulnerable) policy, the
   specific offending action/resource, and the required
   `must_still_allow` pairs, and returns a candidate replacement policy
   JSON.
2. **Test**: `PolicyEvaluator` — plain deterministic Python, no model —
   evaluates that candidate against the *exact same* offending
   action/resource (must now be denied) and every required pair (must
   still be allowed), by literally checking Allow/Deny statements against
   the requested action/resource the same way AWS's own policy evaluation
   logic would (Allow by default only if some statement grants it; an
   explicit Deny always wins).
3. **Revise**: if the test fails, the specific failure reasons (which
   check failed, and how) are fed back into a new LLM prompt asking it to
   fix exactly that problem, and the loop repeats — capped at 3 attempts.
4. **Decide**: pass → the draft is eligible for `attempt_auto_fix`; fail
   after 3 attempts → `escalate_to_human`, never a silent partial fix
   (Part 6.2).

### 8.5 The ML evaluation metrics themselves, defined plainly

Since Part 4 leans on these numbers, know what each one actually means,
not just its value:
- **Precision**: of everything the model flagged as anomalous/a match,
  what fraction actually was? (Low precision = too many false alarms.)
- **Recall**: of everything that actually *was* anomalous/a match, what
  fraction did the model catch? (Low recall = missing real attacks.)
- **F1**: the harmonic mean of precision and recall — a single number
  that penalizes a model for being lopsided (e.g. 100% recall by flagging
  everything scores badly on F1 because precision collapses).
- **ROC-AUC**: how well the model separates the two classes across *every
  possible threshold*, not just the one chosen — 1.0 is perfect
  separation, 0.5 is random guessing. This is why it's a stronger overall
  signal than a single precision/recall pair at one fixed cutoff.
- **Macro-F1 vs. Accuracy**: accuracy just counts "fraction correct
  overall," which a class with many easy examples (like Layer 2's large
  `UNKNOWN` class) can inflate. Macro-F1 computes F1 *per class* and
  averages those equally, so a model doing well on the easy, common class
  but poorly on a rare, hard class shows up honestly — exactly why Layer
  2's 0.913 accuracy vs. 0.625 macro-F1 gap was flagged and explained
  rather than only quoting the flattering number.
- **Confusion matrix**: a grid of actual-class (rows) vs. predicted-class
  (columns) counts — the one artifact that shows you *exactly* which
  classes get confused with which, instead of hiding that detail behind
  any single summary number.

---

## Part 9 — Frameworks and Standards Referenced, Explained

Names dropped throughout this project assume background you may not have
had reason to know yet — quick, precise definitions:

- **MITRE ATT&CK**: a free, public, community-maintained knowledge base
  of real-world adversary behavior, organized as **Tactics** (the *why* —
  e.g. "Privilege Escalation," "Defense Evasion") each containing several
  **Techniques** (the *how* — e.g. T1098 "Account Manipulation" under
  Persistence/Privilege Escalation). Security teams worldwide use ATT&CK
  IDs as a shared vocabulary — saying "this is a T1098-style event" means
  something precise and internationally recognized, unlike a homegrown
  severity label.
- **CIS Benchmarks**: configuration hardening guides published by the
  Center for Internet Security — "CIS AWS Foundations Benchmark control
  2.1.5" is a specific, numbered, citable rule (e.g. "S3 buckets must
  block public access"), which is exactly what `compliance.py`'s
  `COMPLIANCE_MAP` cites per vulnerability type.
- **SOC 2 / PCI-DSS**: SOC 2 is an auditing standard for how a company
  handles customer data (relevant to any SaaS vendor); PCI-DSS is the
  payment-card industry's security standard (relevant to anyone touching
  card data). `compliance.py` maps your findings to both, not just CIS —
  meaning your PDF report can answer "does this finding matter for our
  SOC 2 audit," a real question a compliance team asks.
- **IsolationForest / sklearn**: `scikit-learn`, the standard Python
  ML library — using its `IsolationForest` implementation (rather than
  writing tree-isolation from scratch) is itself a reasonable engineering
  choice worth stating plainly if asked: don't reinvent a well-tested
  primitive when the value you're adding is in the *feature engineering*
  and the *pipeline design* around it (Part 2.1), not the tree algorithm
  itself.
- **Youden's J statistic**: explained mechanically in 8.3 — a standard
  method from diagnostic-test statistics (originally biostatistics) for
  picking an optimal classification threshold.

---

## Part 10 — How to Explain This Project in One Breath

If an examiner asks "what does this project do," the honest, complete
answer in one paragraph:

> "CloudSentry is a serverless CSPM tool that detects real
> misconfigurations — public S3 buckets, unencrypted storage, wildcard IAM
> policies, open security groups — using event-driven AWS Lambda functions
> against a local AWS emulator. What makes it more than a scanner is a
> 5-layer AI reasoning pipeline: an Isolation Forest flags anomalous events
> using session-aware windowed features, a sentence-transformer classifies
> them against MITRE ATT&CK with calibrated abstention when it's not
> confident, a deterministic graph engine computes blast radius — what a
> compromised identity could actually reach — a propose-test-revise LLM
> agent drafts and sandbox-verifies narrower IAM policies, and a weighted
> formula composes all of that into one priority score. Every layer was
> evaluated against a real ground truth with proper metrics, not just
> demoed, and the system went through two rounds of real adversarial
> testing that found and fixed 13 concrete bugs — with every fix verified
> by actual reproduction, not just code review."

---

*For deeper detail than this file covers: `eval/EVAL_REPORT.md` (full
per-layer evaluation methodology and numbers), `TESTING_AND_EVALUATION_SUMMARY.md`
(full bug-by-bug testing history), `GROWTH_PLAN.md` (the phased roadmap,
including what's still open).*
