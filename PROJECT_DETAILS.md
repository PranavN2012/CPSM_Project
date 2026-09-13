# Serverless CSPM — Complete Project Documentation

> **Purpose**: This document captures every detail of the project — from high-level architecture to individual function signatures — for use in writing an academic paper.

---

## Table of Contents

1. [Project Identity](#1-project-identity)
2. [Problem Statement & Motivation](#2-problem-statement--motivation)
3. [System Architecture](#3-system-architecture)
4. [Technology Stack (Exhaustive)](#4-technology-stack-exhaustive)
5. [Vulnerability Detection & Remediation Engine](#5-vulnerability-detection--remediation-engine)
5A. [AI/ML Reasoning Pipeline (Layers 1-5 + Orchestrator)](#5a-aiml-reasoning-pipeline-layers-1-5--orchestrator)
6. [NLP-Powered Incident Intelligence Engine](#6-nlp-powered-incident-intelligence-engine)
7. [Policy-as-Code Engine](#7-policy-as-code-engine)
8. [Multi-Cloud Provider Abstraction Layer](#8-multi-cloud-provider-abstraction-layer)
9. [Policy Feed Subscription & Sync Engine](#9-policy-feed-subscription--sync-engine)
10. [Compliance Framework Mapping](#10-compliance-framework-mapping)
11. [Frontend Dashboard](#11-frontend-dashboard)
12. [PDF Compliance Report Generator](#12-pdf-compliance-report-generator)
13. [Terraform Infrastructure-as-Code](#13-terraform-infrastructure-as-code)
14. [CI/CD Pipeline (GitHub Actions)](#14-cicd-pipeline-github-actions)
15. [Terraform Security Scanner (SAST)](#15-terraform-security-scanner-sast)
16. [Attack Simulation Engine](#16-attack-simulation-engine)
17. [Local Development Infrastructure](#17-local-development-infrastructure)
18. [Notification Systems](#18-notification-systems)
19. [Unit Testing](#19-unit-testing)
20. [DynamoDB Schema](#20-dynamodb-schema)
21. [API Design](#21-api-design)
22. [File-by-File Inventory](#22-file-by-file-inventory)
23. [Quantitative Metrics](#23-quantitative-metrics)
24. [Security Limitations & Known Flaws](#24-security-limitations--known-flaws)
25. [Blue Team / DevSecOps Classification](#25-blue-team--devsecops-classification)
26. [References to Industry Standards](#26-references-to-industry-standards)

---

## 1. Project Identity

| Field | Value |
|---|---|
| **Project Name** | Serverless CSPM (Cloud Security Posture Management) |
| **Internal Codename** | CloudSentry |
| **Repository** | `github.com/PranavN2012/CPSM_Project` |
| **License** | MIT |
| **Primary Language** | Python 3.11 |
| **Lines of Code (source files)** | ~82 files, ~450 KB total |
| **Category** | Blue Team / Defensive Security / DevSecOps |

---

## 2. Problem Statement & Motivation

### The Problem
Cloud environments (AWS, Azure, GCP) are highly complex. Developers constantly spin up resources via Infrastructure-as-Code (IaC). A single misconfiguration — such as leaving an S3 bucket public — can cause a massive data breach. Real-world examples include:
- **Capital One (2019)**: A misconfigured WAF allowed access to 106 million customer records stored in S3.
- **Twitch (2021)**: Source code and internal data leaked due to a server misconfiguration.

### The Solution
A **Cloud Security Posture Management (CSPM)** tool that:
1. Continuously monitors cloud infrastructure configurations.
2. Compares configurations against strict security baselines (CIS, SOC 2, PCI-DSS).
3. Alerts administrators in real-time.
4. **Automatically remediates** vulnerabilities within milliseconds.

### What Makes This Project Unique
- **Event-driven** (not periodic scanning) — reacts in real-time via EventBridge.
- **Multi-vulnerability** — 5 distinct vulnerability types across storage, network, database, and IAM.
- **Agentic AI reasoning pipeline** — a 5-layer ML/LLM pipeline (anomaly detection, ATT&CK classification, blast-radius graph analysis, autonomous policy drafting, priority scoring) plus an LLM orchestrator that decides whether to auto-fix, escalate, or monitor — see Section 5A. Empirically evaluated (not just demoed) against ground truth; see `eval/EVAL_REPORT.md`.
- **Safety-gated autonomous remediation** — the LLM proposes IAM policy fixes, but a deterministic sandbox evaluator independently verifies every draft before anything is allowed to auto-apply; a failing or lying LLM cannot force an unverified fix through (verified via adversarial testing, see `TESTING_AND_EVALUATION_SUMMARY.md`).
- **NLP-powered** — deterministic Natural Language Generation engine produces audit-grade incident narratives.
- **Multi-cloud** — supports AWS (live), Azure (mock/SDK), and GCP (mock/SDK).
- **Policy-as-Code** — YAML-based, cloud-agnostic policy definitions with auto-generation.
- **100% local** — entire system runs on LocalStack (no AWS billing, and a deliberate project-wide policy never to deploy against a real AWS account — see `GROWTH_PLAN.md`).

---

## 3. System Architecture

### Architecture Type
**Event-Driven Serverless Microservices** — all compute runs on AWS Lambda (stateless, ephemeral). No EC2 instances, no servers to manage.

### Data Flow (Step-by-Step)

```
1. TRIGGER:     Developer/Attacker modifies an AWS resource (e.g., creates S3 bucket)
2. CLOUDTRAIL:  AWS CloudTrail logs every API call as a JSON event
3. EVENTBRIDGE: Amazon EventBridge pattern-matches the event:
                 - source: "aws.s3"
                 - eventName: ["CreateBucket", "PutBucketPublicAccessBlock"]
4. LAMBDA:      EventBridge routes the event to the Remediation Lambda
5. INSPECT:     Lambda uses boto3 to query the resource's current configuration
6. DECIDE:      Lambda determines if the resource is non-compliant
7. REMEDIATE:   Lambda fires a remediation API call (e.g., PutPublicAccessBlock)
8. NLG:         NLG Engine generates an audit-grade incident narrative
9. LOG:         Lambda writes the event + NLG summary to DynamoDB
10. NOTIFY:     Lambda sends a Discord webhook alert and creates a GitHub Issue
11. DASHBOARD:  API Lambda reads DynamoDB → serves data to the frontend
12. PDF:        User can download a compliance report from the dashboard
```

### Architecture Diagram (ASCII)

```
┌─────────────────────────────────────────────────────────────────┐
│                        AWS Account                              │
│                                                                 │
│  ┌──────────┐    ┌─────────────┐    ┌──────────────────────┐    │
│  │ CloudTrail│───→│ EventBridge │───→│ Remediation Lambda  │    │
│  │  (audit)  │    │   (router)  │    │  ┌────────────────┐ │    │
│  └──────────┘    └─────────────┘    │  │ scan_resources │ │    │
│                                      │  │ remediate      │ │    │
│  ┌────────────┐                      │  │ log_to_dynamo  │ │    │
│  │ S3 / IAM / │←── fixes ────────────│  │ notify_discord │ │    │
│  │ EC2 / DDB  │                      │  │ nlg_engine     │ │    │
│  └────────────┘                      │  └────────────────┘ │    │
│                                      └──────────┬───────────┘    │
│                                           │           │         │
│                                     ┌─────▼────┐  ┌──▼────────┐ │
│                                     │ DynamoDB │  │  Discord  │ │
│                                     │ (events) │  │ (webhook) │ │
│                                     └─────┬────┘  └───────────┘ │
│                                           │                     │
│  ┌──────────────┐    ┌──────────┐   ┌────▼──────┐               │
│  │ S3 Website   │───→│ API GW   │──→│ API Lambda│               │
│  │ (dashboard)  │    │ (HTTP)   │   │ (read DB) │               │
│  └──────────────┘    └──────────┘   └───────────┘               │
└─────────────────────────────────────────────────────────────────┘
```

### Component Roles

| Component | AWS Service | Role in System |
|---|---|---|
| **Audit Logger** | CloudTrail | Records every API call (who, what, when, from which IP) as JSON |
| **Event Router** | EventBridge | Pattern-matches CloudTrail events and routes to Lambda |
| **Remediation Brain** | Lambda (Python 3.11) | Inspects, decides, remediates, logs, and notifies |
| **IAM Scanner** | Lambda (Python 3.11) | Scans IAM users/roles for wildcard policies |
| **API Backend** | Lambda (Python 3.11) | Reads DynamoDB, computes stats/trends/compliance |
| **Event Store** | DynamoDB | Serverless NoSQL DB storing all remediation events |
| **HTTP Gateway** | API Gateway (HTTP API) | Secure front door for dashboard API calls |
| **Dashboard Host** | S3 Static Website | Hosts HTML/CSS/JS frontend |
| **Local Emulator** | LocalStack (Docker) | Mimics all 8 AWS services locally |

---

## 4. Technology Stack (Exhaustive)

| Layer | Technology | Version | Purpose |
|---|---|---|---|
| **Language** | Python | 3.11 | All Lambda functions and scripts |
| **AWS SDK** | boto3 / botocore | Latest | Programmatic AWS API interaction |
| **HTTP Client** | urllib3 | Built-in | Discord webhooks, GitHub API calls |
| **Compute** | AWS Lambda | Python 3.11 runtime | Serverless function execution |
| **Database** | Amazon DynamoDB | On-demand | NoSQL event storage |
| **Event Bus** | Amazon EventBridge | N/A | Event routing and pattern matching |
| **API Layer** | API Gateway v2 (HTTP API) | N/A | REST API with CORS |
| **Storage** | Amazon S3 | N/A | Object storage (target + frontend hosting) |
| **Identity** | AWS IAM | N/A | Users, Roles, Policies (target + execution roles) |
| **Networking** | EC2 Security Groups | N/A | Network perimeter (target for scanning) |
| **Logging** | CloudWatch Logs | 14-day retention | Lambda execution logs |
| **Audit** | AWS CloudTrail | N/A | API call audit trail |
| **Frontend** | React 18 + Vite | ES2020+ | Dashboard UI (superseded the original vanilla HTML/CSS/JS dashboard — see Section 11) |
| **Charting** | Chart.js (via `react-chartjs-2`) | npm | Doughnut, bar, and line charts |
| **3D/Shader** | `ogl` | npm | WebGL light-ray shader on the intro splash |
| **PDF** | fpdf2 | Latest pip | Compliance report generation |
| **IaC** | Terraform | >= 1.5 | Infrastructure deployment |
| **Terraform Provider** | hashicorp/aws | ~> 5.0 | AWS resource management |
| **Terraform Provider** | hashicorp/archive | ~> 2.0 | ZIP packaging for Lambda |
| **CI/CD** | GitHub Actions | N/A | Automated testing and scanning |
| **Notifications** | Discord Webhooks | N/A | Real-time security alerts |
| **Issue Tracking** | GitHub Issues API v3 | N/A | Auto-created security tickets |
| **Containerization** | Docker | Latest | Runs LocalStack |
| **Local Emulator** | LocalStack | Latest | Emulates 8 AWS services |
| **Testing** | pytest | Latest | Unit testing framework |
| **Mocking** | unittest.mock | Built-in | Mocking boto3 clients in tests |
| **YAML Parser** | PyYAML | Latest | Policy file parsing |
| **Policy Format** | YAML | 1.2 | Cloud-agnostic policy definitions |
| **CIS Feeds** | JSON | Bundled | CIS Benchmark baseline controls |

### Python Dependencies (Lambda Runtime)
- `boto3` — pre-installed in AWS Lambda Python runtime
- `urllib3` — pre-installed in AWS Lambda Python runtime
- `fpdf2` — installed via pip for PDF generation
- `PyYAML` — optional, with fallback manual parser

---

## 5. Vulnerability Detection & Remediation Engine

### Overview
The core engine detects **5 distinct vulnerability types** and auto-remediates 4 of them. It lives in `lambda/remediation/lambda_function.py` (549 lines).

### Vulnerability #1: S3 Public Access (CRITICAL)

| Attribute | Detail |
|---|---|
| **File** | `lambda/remediation/lambda_function.py`, function `check_public_access()` (line 119) |
| **Risk** | S3 buckets with `Block Public Access` disabled allow anyone on the internet to view/download files |
| **AWS API Call for Detection** | `s3_client.get_public_access_block(Bucket=name)` |
| **Four Security Flags Checked** | `BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, `RestrictPublicBuckets` |
| **Trigger Condition** | Any of the 4 flags is `False` |
| **Remediation API Call** | `s3_client.put_public_access_block()` — sets all 4 flags to `True` |
| **Remediation Speed** | Milliseconds (same Lambda invocation) |
| **Severity** | CRITICAL |
| **Compliance** | CIS AWS 2.1.5, SOC 2 CC6.1, PCI-DSS 2.2, PCI-DSS 7.1 |
| **CloudTrail Events** | `CreateBucket`, `PutBucketPublicAccessBlock` |

**Detection Logic (Exact Code):**
```python
needs_fix = not all([
    config.get("BlockPublicAcls", False),
    config.get("IgnorePublicAcls", False),
    config.get("BlockPublicPolicy", False),
    config.get("RestrictPublicBuckets", False),
])
```

**Exception Handling:**
- `NoSuchPublicAccessConfiguration` → Treats as fully vulnerable (all flags False)
- `NoSuchBucket` → Bucket deleted before remediation; returns `None`
- `AccessDenied` → Insufficient permissions; returns `None`

### Vulnerability #2: S3 Encryption (HIGH)

| Attribute | Detail |
|---|---|
| **File** | `lambda/remediation/lambda_function.py`, function `check_encryption()` (line 174) |
| **Risk** | Data stored in plaintext on AWS physical storage media |
| **Detection API** | `s3_client.get_bucket_encryption(Bucket=name)` |
| **Trigger Condition** | `ServerSideEncryptionConfigurationNotFoundError` or `NoSuchEncryptionConfiguration` |
| **Remediation API** | `s3_client.put_bucket_encryption()` — applies `AES256` SSE with `BucketKeyEnabled: True` |
| **Severity** | HIGH |
| **Compliance** | CIS AWS 2.1.1, CIS AWS 2.1.2, SOC 2 CC6.1, SOC 2 CC6.7, PCI-DSS 3.4 |

**Remediation Payload (Exact):**
```python
s3_client.put_bucket_encryption(
    Bucket=bucket_name,
    ServerSideEncryptionConfiguration={
        "Rules": [{
            "ApplyServerSideEncryptionByDefault": {
                "SSEAlgorithm": "AES256",
            },
            "BucketKeyEnabled": True,
        }]
    },
)
```

### Vulnerability #3: IAM Overpermissive Policies (CRITICAL)

| Attribute | Detail |
|---|---|
| **File** | `lambda/iam-audit/lambda_function.py` (340 lines) |
| **Risk** | Users/Roles with `Action: "*", Resource: "*"` grant total admin control |
| **Scan Scope** | All IAM users (attached + inline policies) AND all IAM roles |
| **Detection Logic** | 1. Checks attached managed policies against a known admin ARN list, 2. Parses inline policy JSON for wildcard `"*"` in Action/Resource fields |
| **Remediation** | **Flag-only** — no auto-remediation (IAM changes are too risky to automate) |
| **Status** | `IAM_OVERPERMISSIVE` |
| **Severity** | CRITICAL (managed admin policy) or HIGH (inline wildcard) |
| **Compliance** | CIS AWS 1.16, CIS AWS 1.22, SOC 2 CC6.3, PCI-DSS 7.1, PCI-DSS 7.2 |

**Known Admin Policy ARNs:**
```python
admin_arns = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
}
```

**Wildcard Detection (function `find_wildcards()`):**
- Iterates all `Statement` blocks in the policy document
- Only examines `"Allow"` effect statements
- Checks if `Action` contains `"*"` → appends `"Action:*"`
- Checks if `Resource` contains `"*"` → appends `"Resource:*"`
- Handles both string and list formats for Action/Resource fields

**Roles Excluded:**
- AWS service-linked roles (path `/aws-service-role/`) are skipped.

### Vulnerability #4: Security Group Open SSH (HIGH)

| Attribute | Detail |
|---|---|
| **File** | `lambda/remediation/lambda_function.py`, function `check_security_group()` (line 260) |
| **Risk** | SSH (port 22) open to the entire internet (`0.0.0.0/0`) allows brute-force attacks |
| **Detection API** | `ec2_client.describe_security_groups(GroupIds=[sg_id])` |
| **Trigger Condition** | Any `IpPermission` with `FromPort=22` or `ToPort=22` and `CidrIp=0.0.0.0/0` |
| **Remediation API** | `ec2_client.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=offending)` |
| **Severity** | HIGH |
| **Compliance** | CIS AWS 5.2, SOC 2 CC6.6, PCI-DSS 1.3.2 |
| **CloudTrail Events** | `AuthorizeSecurityGroupIngress`, `CreateSecurityGroup` |

### Vulnerability #5: DynamoDB Unencrypted Tables (MEDIUM)

| Attribute | Detail |
|---|---|
| **File** | `lambda/remediation/lambda_function.py`, function `check_dynamodb_encryption()` (line 333) |
| **Risk** | NoSQL data stored without encryption — snapshot theft can expose PII/credentials |
| **Detection API** | `dynamodb_client.describe_table(TableName=name)` → checks `SSEDescription.Status` |
| **Trigger Condition** | `SSEDescription.Status` is not `"ENABLED"` |
| **Remediation API** | `dynamodb_client.update_table(SSESpecification={"Enabled": True, "SSEType": "KMS"})` |
| **Severity** | MEDIUM |
| **Compliance** | SOC 2 CC6.1, PCI-DSS 3.4 |
| **CloudTrail Events** | `CreateTable` |

### Event Routing Logic (Main Handler)
The `lambda_handler()` (line 60) uses the `eventSource` field to route:

| `eventSource` | Resource Extraction | Checks Performed |
|---|---|---|
| `s3.amazonaws.com` | `requestParameters.bucketName` or ARN | Public Access + Encryption (both) |
| `ec2.amazonaws.com` | `requestParameters.groupId` | Security Group Open SSH |
| `dynamodb.amazonaws.com` | `requestParameters.tableName` | DynamoDB Encryption |
| Any other | N/A | Returns `SKIPPED` |

---

## 5A. AI/ML Reasoning Pipeline (Layers 1-5 + Orchestrator)

### Overview
Directory: `lambda/shared/ml/` (added after the sections above were first
written — this section closes that gap). A 5-layer AI/ML threat-intelligence
pipeline plus an agentic LLM orchestrator that sits **on top of** the
detection engine in Section 5: once a finding exists, this pipeline decides
how urgent it is, what MITRE ATT&CK technique it resembles, what a
compromised identity could reach, and whether to autonomously draft and
sandbox-verify a fix or escalate to a human. It does not replace Section 5's
detection logic — it's an additional reasoning layer over its output, wired
in via `scripts/local-api-server.py`'s `GET /ai/insights` endpoint and the
`AIInsightsView`/`PolicyDiffView` React pages (Section 11).

For a full plain-language teaching walkthrough of every layer's mechanics
(including *why* each algorithm was chosen) see `PROJECT_MASTERCLASS.md`
Part 2 and Part 8. For measured evaluation results (precision/recall/F1,
independent-oracle verification, etc.) see `eval/EVAL_REPORT.md`. This
section is the concise reference version.

### Layer 1 — Anomaly Detection (`ml/anomaly_detector.py`)
Unsupervised `sklearn.ensemble.IsolationForest` over a 10-feature vector
(`hour_of_day`, `is_weekend`, `event_type_encoded`, `severity_encoded`,
`resource_name_length`, `has_prod_keyword`, plus 4 session/window features:
`account_frequency_1h`, `region_frequency_1h`, `type_frequency_1h`,
`cross_region_flag`). The windowed features (via `EventWindow`, a
time-bounded sliding buffer) are what let the model catch slow/low-and-slow
attack patterns invisible at the single-event level. Calibrated operating
threshold: `0.46` (empirically anchored against real simulated-attack score
distributions — see `ml/orchestrator.py`'s `ANOMALY_THRESHOLD` constant and
its docstring for the reasoning). Evaluated: Precision 0.889, Recall 1.000,
F1 0.941, ROC-AUC 0.973 (`eval/layer1_anomaly_eval.py`).

### Layer 2 — ATT&CK Semantic Classification (`ml/semantic_scorer.py`)
Converts a structured finding into a natural-language sentence
(`EventNarrator`), embeds it with SBERT (`all-MiniLM-L6-v2`,
`sentence-transformers`), and compares via cosine similarity against a
30-technique MITRE ATT&CK knowledge base (`ml/data/attack_technique_kb.json`).
A calibrated confidence threshold (`0.4478`, chosen via Youden's J statistic
over 32 labeled pairs in `ml/data/classifier_calibration.json`) governs
abstention: below threshold, the classifier returns `UNKNOWN` rather than
forcing a wrong label — evaluated as the empirically correct behavior for
findings that don't map cleanly onto any of the 30 techniques (e.g. "a
bucket was left public" is a state, not an observed attacker action).
Evaluated: Accuracy 0.913, Macro-F1 0.625 (`eval/layer2_attack_classification_eval.py`).

### Layer 3 — Blast Radius Simulation (`ml/blast_radius.py`)
Models cloud infrastructure as a directed graph (`InfraGraph`) — IAM
roles/users, S3 buckets, Lambda functions, DynamoDB tables, security groups
as nodes; `can_assume`/`can_read`/`can_write`/`can_invoke`/`can_administer`
as edges — and answers "if this identity is compromised, what can it
reach?" via BFS (`simulate_blast_radius()`). The demo/seed graph
(`ml/data/blast_radius_seed.json`, 21 nodes as of `GROWTH_PLAN.md` Phase 1)
is hand-built with known-correct relationships, including a 4-hop
privilege-escalation chain (`external-vendor-role → analyst-user →
backup-service-role → ci-deploy-role → {3 production/PII resources}`).
`resource_exposure_severity()` additionally lets a live finding whose
resource name matches a graph node (not necessarily an identity) get a real
severity instead of always defaulting to LOW. Deliberately explicit
non-goals, stated in the module's own docstring: no IAM condition-key
evaluation, no resource-based policies, no permission boundaries/SCPs.
Evaluated: 21/21 exact match against an independently-coded `networkx`
oracle (`eval/layer3_blast_radius_eval.py`).

### Layer 4 — Autonomous Policy Drafting (`ml/policy_agent.py`)
The "propose → test → revise" agentic loop: an LLM (`GroqLLMClient` using
`openai/gpt-oss-120b`, or `GeminiLLMClient` as fallback, or a deterministic
`RuleBasedPolicyDrafter` if no API key is configured) drafts a narrower IAM
policy given the vulnerable policy, the offending action/resource, and what
must still be allowed. `PolicyEvaluator` — a ~150-line local, deterministic
Allow/Deny/wildcard evaluator, **not** an LLM — independently tests every
draft; a failure is fed back into the next attempt (capped at 3). This is
the project's core safety property: **the LLM proposes, it never disposes**
— a draft is only eligible for auto-fix if the deterministic evaluator
passes it, verified even against a test LLM that lies about its own
`test_passed` result (see `TESTING_AND_EVALUATION_SUMMARY.md`). Evaluated
against the real Groq LLM (not the trivial rule-based fallback): 100% pass
on attempt 1, 100% within 3 attempts, 12/12 independently re-verified
(`eval/layer4_policy_drafting_eval.py`).

### Layer 5 — Priority Scoring (`ml/priority_scorer.py`)
A fixed, published, deterministic weighted formula — no ML — composing
Layers 1-3 plus a recency signal into a 0-100 score and P1-P4 tier:
`0.25 × anomaly_score + 0.20 × classification_confidence + 0.35 ×
blast_radius_severity + 0.20 × recency`. Blast radius gets the largest
single weight since it's the most direct answer to "how bad would this
actually be." Evaluated via monotonicity checks (raising any one component
never lowers the score) and ranking-consistency scenarios: 6/6 and 6/6
(`eval/layer5_priority_scoring_eval.py`).

### The Orchestrator (`ml/orchestrator.py`)
`ThreatOrchestrator.process_event()` ties Layers 1-5 together: Layer 1
gates everything (not anomalous → stop); if anomalous, Layers 2 and 3 run
in parallel (`ThreadPoolExecutor`), Layer 5 composes the priority score,
and a pluggable `Reasoner` (`GroqReasoner`/`GeminiReasoner`, or
`RuleBasedReasoner` fallback) reads a structured context packet and picks
exactly one action: `attempt_auto_fix`, `escalate_to_human`,
`gather_more_context`, or `monitor_only`, with a rationale. Only
`attempt_auto_fix` invokes Layer 4; if all 3 attempts fail, the decision is
downgraded to `escalate_to_human` rather than left misleadingly as
`attempt_auto_fix` — the pipeline's "give up gracefully" property.

### Testing & Evaluation Discipline
Both the pipeline and the API/frontend layers around it went through two
rounds of adversarial testing (13 real bugs found and fixed — see
`TESTING_AND_EVALUATION_SUMMARY.md`) and a from-scratch evaluation harness
(`eval/`) measuring each layer against a stated ground truth with sklearn
metrics, an independent oracle, or formula verification as appropriate to
that layer's nature — not just "the pipeline runs without crashing."

---

## 6. NLP-Powered Incident Intelligence Engine

### Overview
File: `lambda/shared/nlg_engine.py` (544 lines). A deterministic Natural Language Generation (NLG) engine that transforms raw JSON security events into contextual, audit-grade incident narratives. The same technique is used by enterprise SIEMs like Splunk, Datadog, and PagerDuty. **Zero external API dependencies — fully offline.**

### Feature 1: Template-Based NLG (Core Narrative)
**Technique:** Conditional slot-filling — maps each `vulnerability_type × status` combination to pre-built narrative templates.

**Output Structure (3 sentences):**
1. **What happened** — trigger verb, resource name, account, region
2. **Why it matters** — risk description, compliance frameworks violated
3. **What was done** — remediation action taken

**Trigger Verbs (7 mapped):**
| Event Name | Verb |
|---|---|
| `CreateBucket` | "created an S3 bucket" |
| `PutBucketPublicAccessBlock` | "modified the public access configuration of S3 bucket" |
| `PutBucketEncryption` | "modified the encryption configuration of S3 bucket" |
| `AuthorizeSecurityGroupIngress` | "opened an inbound rule on security group" |
| `CreateSecurityGroup` | "created a new security group" |
| `CreateTable` | "created a DynamoDB table" |
| `IAMAuditScan` | "was detected during a scheduled IAM policy audit of" |

**Action Templates (6 statuses):**
| Status | Template Excerpt |
|---|---|
| `REMEDIATED` | "CloudSentry detected the misconfiguration and auto-remediated..." |
| `ENCRYPTION_REMEDIATED` | "CloudSentry auto-remediated by enabling AES-256 server-side encryption..." |
| `REMEDIATION_FAILED` | "CloudSentry attempted auto-remediation but the operation failed..." |
| `ENCRYPTION_FAILED` | "CloudSentry attempted to enforce encryption but the API call failed..." |
| `COMPLIANT` | "CloudSentry verified the resource configuration and confirmed it meets security baseline..." |
| `IAM_OVERPERMISSIVE` | "CloudSentry flagged this as a Principle of Least Privilege violation..." |

**Vulnerability-Specific Overrides (3):**
- `(S3 Public Access, REMEDIATED)` → mentions all 4 Block Public Access flags by name
- `(Security Group Open SSH, REMEDIATED)` → mentions `RevokeSecurityGroupIngress`
- `(DynamoDB Unencrypted, ENCRYPTION_REMEDIATED)` → mentions `UpdateTable SSESpecification`

**Example Output:**
> "A configuration change in account 987654321098 created S3 bucket `prod-data-lake` in us-east-1. This poses a critical risk of unauthorized internet-wide data exposure, violating CIS AWS 2.1.5, SOC 2 CC6.1, PCI-DSS 7.1. CloudSentry auto-remediated by injecting a PutPublicAccessBlock API call, enabling BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets."

### Feature 2: Sentiment-Weighted Severity Scoring
**Technique:** Keyword-based sentiment analysis scans resource names for risk indicators.

**30+ keywords scored in 3 tiers:**

| Tier | Weight | Keywords |
|---|---|---|
| **Critical** | +3 per match | `prod`, `production`, `customer`, `pii`, `payment`, `admin`, `root`, `master`, `credential`, `secret`, `password`, `key` |
| **High** | +2 per match | `staging`, `backup`, `vault`, `session`, `user`, `data`, `export`, `report`, `analytics`, `log`, `audit` |
| **Low** | -1 per match | `dev`, `test`, `sandbox`, `temp`, `tmp`, `demo`, `sample` |

**Additional rule:** Failed remediation (`"FAILED"` in status) adds +4 to the score.

**Urgency Mapping:**
| Score | Urgency Label |
|---|---|
| ≥ 4 | "extremely high" |
| ≥ 2 | "elevated" |
| ≤ -1 | "lower (non-production)" |
| else | Default severity descriptor |

**Example:** For bucket `prod-data-lake-raw`, the engine detects `prod` (+3) and `data` (+2) = score 5 → "extremely high" urgency → output: *"Keyword analysis of the resource name detected 'prod', 'data', indicating this is a high-value production asset requiring immediate attention."*

### Feature 3: Temporal Context (Historical Pattern Analysis)
**Technique:** Queries DynamoDB for past events matching the same `account_id × vulnerability_type`.

**DynamoDB Query:**
```python
dynamodb_table.scan(
    FilterExpression="account_id = :acct AND vulnerability_type = :vtype",
    ExpressionAttributeValues={":acct": account_id, ":vtype": vulnerability_type},
    ProjectionExpression="event_id, #ts",
    ExpressionAttributeNames={"#ts": "timestamp"},
)
```

**Ordinal Suffix Logic:** Computes correct English ordinals (1st, 2nd, 3rd, 4th, 11th, 12th, 13th, 21st, etc.).

**Output Example:** *"TEMPORAL ANALYSIS: This is the 5th S3 Public Access event detected in account 123456789012. Repeated S3 misconfigurations may indicate a systemic process or training gap."*

### Feature 4: Named Entity Recognition (NER) for IAM Policies
**Technique:** Regex-based NER extracts AWS service tokens from IAM policy strings.

**Service Database (14 mapped services):**

| Short Name | Full Name |
|---|---|
| `s3` | Simple Storage Service (S3) |
| `ec2` | Elastic Compute Cloud (EC2) |
| `iam` | Identity & Access Management (IAM) |
| `lambda` | Lambda (Serverless Functions) |
| `dynamodb` | DynamoDB (NoSQL Database) |
| `rds` | Relational Database Service (RDS) |
| `sqs` | Simple Queue Service (SQS) |
| `sns` | Simple Notification Service (SNS) |
| `sts` | Security Token Service (STS) |
| `cloudwatch` | CloudWatch (Monitoring) |
| `kms` | Key Management Service (KMS) |
| `secretsmanager` | Secrets Manager |
| `cloudformation` | CloudFormation (IaC) |
| `logs` | CloudWatch Logs |

**Regex Pattern:** `r'\b{service_name}[:\.\-]'` — matches patterns like `s3:GetObject`, `ec2:*`.

**Wildcard Detection:** Checks for `"action:*"`, `'"action": "*"'`, and `"action: *"` in the policy text.

**Output Example:** *"NER analysis identified a wildcard policy (Action:*) granting unrestricted access to ALL AWS services including Simple Storage Service (S3), Elastic Compute Cloud (EC2), Lambda (Serverless Functions), and Identity & Access Management (IAM)."*

### Feature 5: Cross-Event Correlation (Attack Chain Detection)
**Technique:** Queries DynamoDB for recent events across *different* vulnerability types in the same account, then pattern-matches against known multi-step attack chains.

**4 Known Kill Chains:**

| Kill Chain Name | Step 1 | Step 2 | MITRE ATT&CK Mapping |
|---|---|---|---|
| **Lateral Movement** | IAM Privilege Escalation | Open Security Group SSH | Escalate → Move laterally |
| **Data Exfiltration** | Open SSH | S3 Public Access | Network access → Exfiltrate |
| **Full Compromise** | IAM Privilege Escalation | S3 Public Access | Escalate → Exfiltrate |
| **Persistence via Unencrypted Storage** | IAM Privilege Escalation | Unencrypted DynamoDB | Escalate → Persist in plaintext |

**Detection Algorithm:**
1. Scan DynamoDB for all events in the same `account_id`
2. Collect the set of existing `vulnerability_type` values
3. For each known kill chain: check if the current event is in the chain AND all other steps already exist in history
4. If match → append correlation alert to the narrative

**Output Example:** *"CORRELATION ALERT: An IAM privilege escalation was detected in the same account shortly before this network perimeter breach. This pattern matches a lateral movement kill chain — an attacker may have escalated IAM privileges to open SSH access."*

### NLG Assembly Pipeline
The `generate_incident_summary()` function (line 429) assembles the final narrative:
```
Sentence 1 (What happened)
+ Sentence 2 (Why it matters + severity/sentiment)
+ Sentiment Fragment (keyword insight)
+ Sentence 3 (What was done)
+ NER Fragment (IAM policy details, if applicable)
+ Temporal Fragment (historical frequency)
+ Correlation Fragment (attack chain alert)
```

---

## 7. Policy-as-Code Engine

### Overview
File: `lambda/shared/policy_engine.py` (249 lines). A YAML-based, cloud-agnostic policy management engine — the same approach used by Cloud Custodian, Prisma Cloud, and OPA, but using YAML instead of Rego for simplicity.

### YAML Policy Schema
```yaml
id: aws-s3-public-access           # Unique identifier
name: S3 Public Access Block         # Human-readable name
provider: aws                        # Cloud provider (aws, azure, gcp)
service: s3                           # AWS service
severity: CRITICAL                    # CRITICAL | HIGH | MEDIUM | LOW
enabled: true                         # Toggle on/off
description: "..."                    # Policy description
check: check_s3_public_access         # Check function name
remediation: remediate_s3_public_access  # Remediation function name
auto_remediate: true                  # Auto-fix or flag-only
compliance:                           # Framework mappings
  - framework: CIS AWS
    control: "2.1.5"
    title: "Ensure S3 Buckets are configured with Block Public Access"
  - framework: SOC 2
    control: CC6.1
  - framework: PCI-DSS
    control: "7.1"
```

### Total Policies: 46 YAML files
Covering AWS (5 custom + 12 CIS + 11 Prowler), Azure (3 CIS + 3 Prowler + 1 custom), GCP (3 CIS + 2 Prowler + 1 custom), plus 4 auto-remediation stubs.

### Core API Functions

| Function | Purpose |
|---|---|
| `load_policies(dir, force_reload)` | Loads all `*.yaml` files from the policies directory into an in-memory cache |
| `get_policy(policy_id)` | Returns a single policy by ID |
| `get_enabled_policies(provider)` | Returns all enabled policies, optionally filtered by provider |
| `get_providers()` | Returns unique cloud providers with policy counts |
| `update_policy(policy_id, updates)` | Updates a policy's fields and persists back to YAML |
| `is_check_enabled(check_name)` | Quick check if a security check is enabled |
| `policies_to_json()` | Returns all policies as JSON-serializable list |

### YAML Fallback Parser
When PyYAML is not installed, the engine includes a minimal 60-line fallback parser that handles flat key-value pairs, booleans, and simple list structures. This ensures zero-dependency operation inside Lambda.

---

## 8. Multi-Cloud Provider Abstraction Layer

### Overview
Directory: `lambda/shared/providers/` (6 files). Implements the **Strategy Design Pattern** — the same architecture used by Terraform providers.

### Base Class (`base.py`, 56 lines)
Abstract base class `CloudProvider` with 5 abstract methods:

| Method | Purpose |
|---|---|
| `check_storage_public_access(resource_id)` | Check if storage has public access |
| `check_storage_encryption(resource_id)` | Check if storage has encryption |
| `check_network_open_ports(resource_id)` | Check for dangerous open ports |
| `check_iam_overpermissive(resource_id)` | Check for overpermissive IAM |
| `remediate(check_name, resource_id)` | Execute remediation for a specific check |

### Provider Implementations

| Provider | File | Lines | SDK Used | Fallback |
|---|---|---|---|---|
| **AWS** | `aws.py` | 190 | boto3 (native) | N/A |
| **Azure** | `azure.py` | 290 | azure-identity, azure-mgmt-storage, azure-mgmt-network, azure-mgmt-authorization | Mock data |
| **GCP** | `gcp.py` | 308 | google-cloud-storage, google-cloud-compute, google-cloud-iam | Mock data |

### Mock Data System (`mock_data.py`, 348 lines)
When cloud SDKs are not installed, the providers use realistic mock data that simulates:
- **Azure:** 3 storage accounts (mixed compliance), blob containers, NSG rules with 7 security rules, 4 RBAC role assignments
- **GCP:** 3 GCS buckets, firewall rules with 6 rules, 4 IAM bindings
- **Dangerous ports list:** 22 (SSH), 3389 (RDP), 3306 (MySQL), 5432 (PostgreSQL), 27017 (MongoDB), 6379 (Redis), 9200 (Elasticsearch), 8080 (HTTP-Alt)
- **Azure dangerous roles:** Owner, Contributor
- **GCP dangerous roles:** roles/owner, roles/editor

### Provider Registry (`__init__.py`)
Maps slugs to classes: `{"aws": AWSProvider, "azure": AzureProvider, "gcp": GCPProvider}`

### Azure-Specific Checks
- **Storage Public Access:** Checks `allowBlobPublicAccess` on accounts + `publicAccess` on individual containers
- **Storage Encryption:** Checks `supportsHttpsTrafficOnly` and `minimumTlsVersion` (must be `TLS1_2`)
- **NSG Open Ports:** Iterates security rules, filters `Allow + Inbound`, checks if source is `*`, `0.0.0.0/0`, or `Internet`
- **RBAC Overpermissive:** Checks for Owner/Contributor roles at subscription scope level

---

## 9. Policy Feed Subscription & Sync Engine

### Overview
File: `lambda/shared/policy_sync.py` (437 lines). Fetches security policies from 3 external sources and converts them to CloudSentry YAML format. Architecture: like **antivirus signature updates** for cloud security.

### Source 1: GitHub Community Repos
- Uses GitHub API to list directory contents: `GET /repos/{repo}/contents/{path}?ref={branch}`
- Downloads raw YAML files
- Parses with PyYAML and saves as local policy files
- Default repo: `PranavN2012/CPSM_Project`, branch `main`, path `serverless-cspm/policies`

### Source 2: CIS Benchmarks (Bundled)
- Reads from `policies/feeds/cis_baseline.json` — a bundled JSON file with 18 CIS controls
- Covers AWS (12 controls), Azure (3 controls), GCP (3 controls)
- Converts each control to CloudSentry YAML format
- Controls include: root access keys, MFA, IAM admin policies, S3 logging, EBS encryption, RDS encryption, CloudTrail, SG SSH/RDP, Azure storage HTTPS, Azure blob access, Azure NSG RDP, GCP default network, GCS public access, Cloud SQL SSL

### Source 3: Prowler Open-Source
- Fetches check metadata JSON from Prowler's GitHub repo
- URL pattern: `https://raw.githubusercontent.com/prowler-cloud/prowler/master/prowler/providers/{provider}/services/{service}/{check_name}/{check_name}.metadata.json`
- Maps Prowler severity to CloudSentry format (INFORMATIONAL→LOW)
- Extracts compliance mappings (limited to 3 per check)
- Covers 12 AWS checks, 3 Azure checks, 2 GCP checks

### Sync API
| Function | Endpoint | Purpose |
|---|---|---|
| `sync_all()` | `POST /policies/sync` | Runs all 3 sources |
| `sync_from_github()` | `POST /policies/sync/github` | GitHub only |
| `sync_from_cis()` | `POST /policies/sync/cis` | CIS only |
| `sync_from_prowler()` | `POST /policies/sync/prowler` | Prowler only |

### Policy Auto-Generator (`policy_generator.py`, 273 lines)
When the remediation Lambda encounters a vulnerability type with no matching policy, this module auto-creates a YAML policy stub:
- Maps 17 known vulnerability patterns to policy templates
- Detects provider (AWS/Azure/GCP) from event keywords
- Checks for duplicate policy IDs and check function names
- Generated policies have `enabled: false` and `needs_review: true`
- Endpoint: `POST /policies/auto-generate`

---

## 10. Compliance Framework Mapping

### Overview
File: `lambda/shared/compliance.py` (278 lines). Maps each vulnerability type to real-world regulatory controls.

### Frameworks Covered

| Framework | Full Name | URL |
|---|---|---|
| **CIS AWS** | CIS Amazon Web Services Foundations Benchmark v2.0 | cisecurity.org |
| **SOC 2** | SOC 2 Type II - Trust Services Criteria | aicpa.org |
| **PCI-DSS** | PCI Data Security Standard v4.0 | pcisecuritystandards.org |

### Control Mappings (Complete)

| Vulnerability Type | CIS Controls | SOC 2 Controls | PCI-DSS Controls | Total |
|---|---|---|---|---|
| **S3 Public Access** | 2.1.5 | CC6.1 | 2.2, 7.1 | 4 |
| **S3 Encryption** | 2.1.1, 2.1.2 | CC6.1, CC6.7 | 3.4 | 5 |
| **IAM Audit** | 1.16, 1.22 | CC6.3 | 7.1, 7.2 | 5 |
| **Security Group Open SSH** | 5.2 | CC6.6 | 1.3.2 | 3 |
| **DynamoDB Unencrypted** | — | CC6.1 | 3.4 | 2 |
| **TOTAL** | | | | **19 controls** |

### Compliance Score Computation
```
Per-framework score = (passed_controls / total_controls) × 100
Overall score = (total_passed / total_checked) × 100
```

- `COMPLIANT`, `REMEDIATED`, `ENCRYPTION_REMEDIATED` → **PASS**
- `REMEDIATION_FAILED`, `ENCRYPTION_FAILED`, `IAM_OVERPERMISSIVE` → **FAIL**

---

## 11. Frontend Dashboard

**Superseded architecture note**: the original dashboard was a vanilla
HTML/CSS/JS Power BI-style page (`frontend/dashboard.html`, `style.css`,
`app.js`). It has since been fully replaced by a React + Vite single-page
app (`frontend/src/`) — those three legacy files are deleted from the repo.
This section describes the current React frontend.

### Structure
| Path | Purpose |
|---|---|
| `frontend/src/App.jsx` | Root component — single `page` state variable drives which view renders (no router library; reasonable at 8 pages) |
| `frontend/src/main.jsx` | Mounts `IntroGate` first; swaps to `App` only after the one-time cinematic reveal completes, so the intro sequence and its container styling never persist into the real dashboard |
| `frontend/src/components/views/` | One component per page: `DashboardView`, `AIInsightsView`, `ReviewQueueView`, `AttackPathView`, `PolicyDiffView`, `EventsView`, `PoliciesView`, `SettingsView` |
| `frontend/src/components/charts/` | `SeverityChart`, `VulnTypeChart`, `TimelineChart`, `AnomalyChart`, `VulnDonutLegend` (Chart.js) |
| `frontend/src/components/` | Shared pieces: `Sidebar`, `Topbar`, `PriorityCard`, `PolicyCard`, `Toast`, `AnimatedNumber`, plus the intro/visual set: `IntroGate`, `PixelSwap` (DOM-clone pixel-dissolve transition), `LightRays` (WebGL shader background via `ogl`), `ShapeGrid` (canvas hexagon mesh, used as the app-wide background), `DecryptedText` (scramble-to-resolve headings), `SplitFlapText` (flip-clock wordmark), `TrueFocus` (blur/focus-cycling brand text) |
| `frontend/src/hooks/useDashboardData.js` | Polls the API, feeds `events`/`stats`/`compliance` down to every view |
| `frontend/src/api.js` | The single client module every API call funnels through |
| `frontend/vite.config.js` | Dev server proxies API calls back to `local-api-server.py`; `npm run build` produces `frontend/dist/`, which is what the server actually serves |

### The 8 Dashboard Pages
1. **Security Posture** (`DashboardView`) — KPI cards, charts, and the Priority Action Queue (clicking "Review Policy Diff" on a card opens `PolicyDiffView` for that specific finding). Region pills filter every chart on the page by the event's real `region` field — all distinct regions present in the data get a pill, not a hardcoded subset.
2. **AI Reasoning (5-Layer)** (`AIInsightsView`) — runs the real Section 5A pipeline live; "Simulate Attack Scenarios" (demo, real blast radius) vs. "Analyze Live Events" (real telemetry; live findings whose resource matches a graph node also now get a real, non-LOW blast radius as of `GROWTH_PLAN.md` Phase 1).
3. **Needs Review** (`ReviewQueueView`) — incidents the orchestrator explicitly returned `escalate_to_human` or `gather_more_context` for, pulled from the same live pipeline output as page 2, filtered to just the ones waiting on a person.
4. **Attack Path & Blast Radius** (`AttackPathView`) — no longer the placeholder v2-preview animation. Given a specific incident (via "Inspect Graph Path" on a Priority Action Queue card), it runs `analyzeEvent()` and renders that incident's *real* Layer 3 BFS output; with no incident selected, it falls back to a clearly-labeled demo picker over the 4 hand-built scenarios rather than silently reusing one.
5. **Policy Diff & Approval** (`PolicyDiffView`) — reruns the real pipeline against whichever real incident was selected (via `analyzeEvent()`), rendering the actual before/after IAM policy JSON as a computed line diff, the real Layer 4 rationale, and the real `PolicyEvaluator` pass/fail result. **"Deploy Fix" is live**, not disabled: for IAM Audit findings with a resolvable inline policy, it calls `POST /policies/deploy-fix`, which applies the drafted policy via `put_user_policy`/`put_role_policy` against LocalStack IAM, re-invokes the IAM audit Lambda to confirm the finding actually cleared, and — if it did — flips any prior logged events for that identity to `COMPLIANT`. It only supports *inline* policies (a real, disclosed limitation — an identity whose overpermissive grant comes from an attached *managed* policy needs that detached manually first). With no incident selected, the page runs a reference walkthrough over the 4 demo scenarios instead, clearly labeled as such.
6. **System & Audit Trace** (`EventsView`) — the real event log, filterable by status, with a "Dispatch Issues" button that fires real GitHub Issues via `github_notifier.py`.
7. **Policy Engine** (`PoliciesView` + `PolicyCard`) — toggle/filter the 46 YAML rules; "Sync" pulls in more rules from 3 real external sources (GitHub repo, CIS baseline, Prowler) via `policy_sync.py`. Some auto-generated policies (for finding types outside the built-in checks) start disabled on purpose, pending human review before they take effect.
8. **System Settings** (`SettingsView`) — no longer presentational-only. Shows real AI pipeline status (`GET /system-info`: which LLM client is configured, calibration state, policy counts), a live-analysis event-limit control, an on-demand attack simulator (`POST /simulate`), the policy review-queue count, and integration status for GitHub/Discord (booleans only — no secrets rendered).

### Design System
- **Theme**: "AEGIS SEC-OPS" dark glassmorphism aesthetic (`glass-card` styling throughout), with a light/dark toggle (`useTheme.js`).
- **Charting**: Chart.js, themed to match light/dark mode via `chartSetup.js`.
- **Background**: an animated hexagon mesh (`ShapeGrid`, canvas-based) sits behind the entire app at a negative z-index, visible only in the gaps between opaque panels — colors adapt to light/dark mode.
- **Intro sequence**: a one-shot cinematic reveal (`IntroGate` + `PixelSwap` + `LightRays` + `SplitFlapText`) shown once before `App` mounts, then fully unmounted — it can never re-trigger or leak into any other page.
- **Responsive**: standard CSS, no separate mobile-specific breakpoint system.

---

## 12. PDF Compliance Report Generator

### Overview
File: `scripts/report_generator.py` (321 lines). Uses the `fpdf2` library to generate professional PDF compliance reports.

### PDF Structure (5 sections)

| Page | Section | Content |
|---|---|---|
| 1 | Cover Page | Title, generation date, total events, risk score circle |
| 2 | Executive Summary | Key metrics table (Total, Remediated, Failed, Compliance %) |
| 3 | Compliance Framework Analysis | Per-framework score bars (green/amber/red) |
| 4+ | Detailed Findings | Sortable table: Timestamp, Resource, Type, Severity, Status, Region |
| 5+ | Compliance Control Mapping | Lists all 19 controls with framework, control ID, title, severity |
| Last | Recommendations | 5 actionable security recommendations |

### Risk Score Badge
A colored circle on the cover page:
- Green (≥80%), Amber (60-79%), Red (<60%)
- Renders score percentage in white text centered in the circle

### Custom FPDF Class: `CSPMReport`
- Custom header: "Serverless CSPM - Compliance Report" right-aligned
- Custom footer: Page number and generation timestamp
- `section_title()`: Bold 14pt with blue underline
- `risk_score_badge()`: Renders filled ellipse with percentage text

---

## 13. Terraform Infrastructure-as-Code

### Files

| File | Lines | Purpose |
|---|---|---|
| `terraform/main.tf` | 454 | All resource definitions |
| `terraform/variables.tf` | 44 | Input variables |
| `terraform/outputs.tf` | 44 | Output values |
| `terraform/localstack.tfvars` | ~15 | LocalStack-specific variable overrides |

### Resources Defined (17 total)

| # | Resource Type | Name | Purpose |
|---|---|---|---|
| 1 | `aws_dynamodb_table` | `remediation_events` | Event storage (PAY_PER_REQUEST, hash key: `event_id`) |
| 2 | `aws_iam_role` | `remediation_lambda_role` | Execution role for remediation Lambda |
| 3 | `aws_iam_role_policy` | `remediation_lambda_policy` | S3 + DynamoDB + CloudWatch permissions |
| 4 | `aws_iam_role` | `api_lambda_role` | Execution role for API Lambda |
| 5 | `aws_iam_role_policy` | `api_lambda_policy` | DynamoDB read + CloudWatch permissions |
| 6 | `aws_lambda_function` | `remediation` | Remediation Lambda (Python 3.12, 128MB, 30s timeout) |
| 7 | `aws_lambda_function` | `api` | API Lambda (Python 3.12, 128MB, 15s timeout) |
| 8 | `aws_cloudwatch_log_group` | `remediation_logs` | 14-day retention |
| 9 | `aws_cloudwatch_log_group` | `api_logs` | 14-day retention |
| 10 | `aws_cloudwatch_event_rule` | `s3_public_access_change` | EventBridge rule matching S3 config changes |
| 11 | `aws_cloudwatch_event_target` | `invoke_remediation_lambda` | Routes events to remediation Lambda |
| 12 | `aws_lambda_permission` | `allow_eventbridge` | Grants EventBridge permission to invoke Lambda |
| 13 | `aws_apigatewayv2_api` | `dashboard_api` | HTTP API with CORS (disabled on LocalStack) |
| 14 | `aws_apigatewayv2_stage` | `default` | Auto-deploy stage |
| 15 | `aws_apigatewayv2_integration` | `api_lambda_integration` | Lambda proxy integration |
| 16-17 | `aws_apigatewayv2_route` | `get_events`, `get_stats` | Route definitions |
| 18 | `aws_s3_bucket` | `frontend` | Static website hosting |
| 19-21 | `aws_s3_object` | HTML, CSS, JS | Frontend file uploads |

### LocalStack/AWS Toggle
The Terraform uses a `var.use_localstack` boolean:
- `true`: Overrides endpoints to `http://localhost:4566`, skips credential validation, disables API Gateway and S3 frontend (uses local server instead)
- `false`: Uses real AWS credentials and creates all resources

### IAM Policies (Least Privilege)

**Remediation Lambda permissions:**
- `s3:GetBucketPublicAccessBlock`, `s3:PutBucketPublicAccessBlock` on `arn:aws:s3:::*`
- `dynamodb:PutItem` on the remediation events table only
- CloudWatch Logs for its own log group

**API Lambda permissions:**
- `dynamodb:Scan`, `dynamodb:Query`, `dynamodb:GetItem` on the events table only
- CloudWatch Logs for its own log group

---

## 14. CI/CD Pipeline (GitHub Actions)

### Workflow File: `.github/workflows/cspm-scan.yml` (100 lines)

### Triggers
- `push` to `main` or `master` branches
- `pull_request` targeting `main` or `master`

### Permissions
- `contents: read` — access to repo files
- `pull-requests: write` — ability to comment on PRs

### Job 1: Terraform Security Scan
1. Checks out code (`actions/checkout@v4`)
2. Sets up Python 3.11 (`actions/setup-python@v5`)
3. Runs `python scripts/terraform-scanner.py terraform/`
4. Appends scan results to `$GITHUB_STEP_SUMMARY`
5. On PRs: uses `actions/github-script@v7` to post/update a comment with scan results
   - Finds existing bot comment (avoids duplicates)
   - Updates in-place or creates new

### Job 2: Unit Tests
1. Checks out code
2. Sets up Python 3.11
3. Installs dependencies: `pytest`, `boto3`, `botocore`, `fpdf2`
4. Runs: `pytest tests/test_compliance.py -v --tb=short`

---

## 15. Terraform Security Scanner (SAST)

### Overview
File: `scripts/terraform-scanner.py` (263 lines). A custom Static Application Security Testing (SAST) tool that reads `.tf` files and uses regex to find missing security blocks before infrastructure is deployed.

### Scan Rules (6 rules)

| Rule ID | Severity | Title | Framework | Detection Method |
|---|---|---|---|---|
| `CSPM-S3-001` | CRITICAL | S3 bucket missing public access block | CIS 2.1.5 | Pattern match for `aws_s3_bucket` + absence of `aws_s3_bucket_public_access_block` |
| `CSPM-S3-002` | HIGH | S3 bucket missing encryption | CIS 2.1.2 | Pattern match for `aws_s3_bucket` + absence of encryption config |
| `CSPM-IAM-001` | CRITICAL | IAM policy with wildcard actions | CIS 1.16 | Regex: `"Action"\s*[=:]\s*\[?\s*"\*"` |
| `CSPM-IAM-002` | HIGH | IAM policy with wildcard resources | CIS 1.22 | Regex: `"Resource"\s*[=:]\s*\[?\s*"\*"` |
| `CSPM-NET-001` | HIGH | SG allows unrestricted ingress | CIS 5.2 | Regex: `cidr_blocks\s*=\s*\[?"0\.0\.0\.0/0"` |
| `CSPM-S3-003` | CRITICAL | S3 bucket ACL set to public | CIS 2.1.5 | Regex matches `public-read`, `public-read-write`, `authenticated-read` |

### Output Formats
- **Console**: Numbered findings with emoji severity indicators
- **Markdown**: GitHub-compatible table with findings (written to `security-scan-results.md`)
- **JSON**: Machine-readable via `format_json()`

### Exit Codes
- `0` = No findings (pipeline passes)
- `1` = Findings detected (pipeline fails)
- `2` = Invalid directory argument

### Deduplication
Uses a `(file, line, rule_id)` tuple set to prevent duplicate findings.

---

## 16. Attack Simulation Engine

### Overview
File: `scripts/simulate-attacks.py` (614 lines). Generates real security events across all vulnerability types to demonstrate the CSPM's capabilities.

### Simulation Phases (8 total)

| Phase | Attacks | Count | Description |
|---|---|---|---|
| **Phase 1** | S3 Public Access | 3 buckets | Creates buckets, disables public access block, invokes remediation Lambda |
| **Phase 2** | S3 Encryption | 2 buckets | Creates unencrypted buckets, triggers encryption check |
| **Phase 3** | IAM Overpermissive | 1 user | Creates IAM user with `Action:*, Resource:*` policy, runs IAM audit |
| **Phase 4** | Security Group + DynamoDB | 1 SG + 1 table | Creates open SSH SG and unencrypted DDB table |
| **Phase 5** | Novel Attack Types | 3 events | Simulates RDS public, Lambda public URL, EBS unencrypted (triggers auto-policy generation) |
| **Phase 6** | Azure Security Scan | 4 checks | Mock data — storage, encryption, NSG, RBAC |
| **Phase 7** | GCP Security Scan | 4 checks | Mock data — GCS, encryption, firewall, IAM |
| **Phase 8** | GitHub Issues | All events | Reads DynamoDB and creates GitHub Issues via API |

### Test Bucket Names
`prod-data-lake-raw`, `staging-logs-2026`, `dev-user-uploads`, `analytics-exports`, `ml-training-datasets`, `backup-vault`, `cdn-static-assets`, `customer-reports-q1`

### Test Accounts & Regions
- Accounts: `123456789012`, `987654321098`, `111222333444`
- Regions: `us-east-1`, `us-west-2`, `eu-west-1`, `ap-southeast-1`

### Cleanup
After simulation, all created resources are deleted: buckets, IAM users (with their policies), security groups, and DynamoDB tables.

---

## 17. Local Development Infrastructure

### Docker Compose (`docker-compose.yml`)
```yaml
services:
  localstack:
    image: localstack/localstack:latest
    container_name: cspm-localstack
    ports:
      - "4566:4566"             # Unified gateway for all AWS services
      - "4510-4559:4510-4559"   # External service port range
    environment:
      - SERVICES=s3,lambda,dynamodb,events,apigateway,iam,logs,sts
      - DEBUG=0
      - LAMBDA_EXECUTOR=local
      - DEFAULT_REGION=us-east-1
    volumes:
      - localstack-data:/var/lib/localstack
      - /var/run/docker.sock:/var/run/docker.sock
```

**8 AWS Services Emulated:** S3, Lambda, DynamoDB, EventBridge (events), API Gateway, IAM, CloudWatch Logs, STS

### Local API Server (`scripts/local-api-server.py`, 655 lines)
A custom Python HTTP server that serves everything on a single port (3001):

| Route | Method | Handler |
|---|---|---|
| `/` or `/index.html` | GET | Serves `frontend/dashboard.html` |
| `/*.css`, `/*.js` | GET | Serves static frontend files |
| `/events` | GET | Proxies to API Lambda on LocalStack |
| `/stats` | GET | Proxies to API Lambda on LocalStack |
| `/compliance` | GET | Computes compliance scores locally |
| `/trends` | GET | Computes daily trends locally |
| `/report` | GET | Generates and serves PDF |
| `/policies` | GET | Returns all YAML policies |
| `/providers` | GET | Returns cloud provider list |
| `/scan/{provider}` | GET | Runs security scan against a provider |
| `/create-issues` | POST | Creates GitHub Issues from events |
| `/policies/sync` | POST | Syncs policies from all 3 sources |
| `/policies/sync/github` | POST | Syncs from GitHub |
| `/policies/sync/cis` | POST | Syncs from CIS |
| `/policies/sync/prowler` | POST | Syncs from Prowler |
| `/policies/auto-generate` | POST | Auto-generates a policy from an event |
| `/policies/{id}` | PUT | Updates a policy |
| `OPTIONS` (any) | OPTIONS | CORS preflight |

**Security:** Directory traversal prevention via `os.path.normpath()` and path prefix check.

### Deploy Script (`scripts/deploy-lambdas.py`, 227 lines)
Deploys Lambda functions directly to LocalStack using boto3 (no Terraform needed):

1. Creates IAM execution role `cspm-lambda-role`
2. Creates DynamoDB table `cspm-remediation-events` (PAY_PER_REQUEST, hash key `event_id`)
3. Packages Lambda code into in-memory ZIP archives (including shared modules)
4. Creates or updates 3 Lambda functions:
   - `cspm-s3-remediation-remediation` (handler: `lambda_function.lambda_handler`)
   - `cspm-s3-remediation-api`
   - `cspm-s3-remediation-iam-audit`
5. Each Lambda gets: Python 3.11 runtime, 60s timeout, 256MB memory

### PowerShell Scripts
- `scripts/deploy-local.ps1` (3,859 bytes) — Alternative deployment script for Windows
- `scripts/test-remediation.ps1` (8,961 bytes) — Manual remediation testing via PowerShell

---

## 18. Notification Systems

### Discord Webhooks
**Function:** `send_discord_notification()` in both `remediation/lambda_function.py` (line 496) and `iam-audit/lambda_function.py` (line 306).

**Payload Structure:**
```json
{
  "embeds": [{
    "title": "🛡️ CSPM — S3 Public Access",
    "color": 3066993,
    "fields": [
      {"name": "🪣 Resource", "value": "`bucket-name`", "inline": true},
      {"name": "🏢 Account", "value": "`123456789012`", "inline": true},
      {"name": "🌎 Region", "value": "`us-east-1`", "inline": true},
      {"name": "📋 Status", "value": "**REMEDIATED**", "inline": true},
      {"name": "⚠️ Severity", "value": "**CRITICAL**", "inline": true},
      {"name": "🧠 AI Incident Summary", "value": "...(NLG output)...", "inline": false}
    ],
    "footer": {"text": "Serverless CSPM • Automated Remediation • NLG Engine v1.0"},
    "timestamp": "2026-06-12T04:17:52Z"
  }]
}
```

**Color Mapping:**
| Status | Hex Color | Visual |
|---|---|---|
| REMEDIATED / ENCRYPTION_REMEDIATED | `0x2ECC71` | Green |
| REMEDIATION_FAILED / ENCRYPTION_FAILED | `0xE74C3C` | Red |
| COMPLIANT | `0x3498DB` | Blue |

**Icon Mapping:** 🛡️ S3 Public Access, 🔐 S3 Encryption / DynamoDB, 👤 IAM Audit, 🔒 Security Group

### GitHub Issues
**Function:** `create_github_issue()` in `lambda/shared/github_notifier.py` (130 lines).

**Issue Body Format:** Markdown table with Resource, Account, Region, Status, Severity + Details section.

**Labels Applied:**
- Always: `cspm`, `security`
- If remediated: `auto-remediated`
- If not remediated: `needs-attention`
- Type-specific: `s3-public-access`, `s3-encryption`, `iam-audit`

**Label Colors:**
| Label | Color |
|---|---|
| `cspm` | `#0075ca` |
| `security` | `#e11d48` |
| `auto-remediated` | `#2da44e` |
| `needs-attention` | `#d93f0b` |

**API Endpoint:** `POST https://api.github.com/repos/{repo}/issues`
**Authentication:** Bearer token via `GITHUB_TOKEN` environment variable
**User-Agent:** `CSPM-Bot`

---

## 19. Unit Testing

**Current totals (as of `GROWTH_PLAN.md` Phase 2, 2026-09-10): 261 tests
passing across ~20 files in `tests/`.** The two files detailed below
(`test_remediation.py`, `test_compliance.py`) were the original two; the
rest were added across two rounds of adversarial testing and the Section 5A
AI pipeline's introduction — full history in `TESTING_AND_EVALUATION_SUMMARY.md`.
Newer additions include `test_anomaly_detector.py`, `test_semantic_scorer.py`,
`test_blast_radius.py`, `test_policy_agent.py`, `test_orchestrator.py`,
`test_priority_scorer.py`, `test_iam_audit.py`, `test_nlg_engine.py`,
`test_report_generator.py`, and `test_local_api_server.py` (which spins up
the real server on an ephemeral port for socket-level tests rather than
re-implementing its logic).

### Original Test Files (kept as a detailed example of the mocking approach)

| File | Lines | Tests | Scope |
|---|---|---|---|
| `tests/test_remediation.py` | 132 | 4 tests in 2 classes | Remediation Lambda logic |
| `tests/test_compliance.py` | 112 | 8 tests in 2 classes | Compliance mapping module |

### Test Details

**TestPublicAccessCheck (3 tests):**
1. `test_detects_public_bucket` — Mocks S3 returning all flags False → expects `REMEDIATED` status
2. `test_compliant_bucket_is_skipped` — Mocks S3 returning all flags True + encryption → expects 200
3. `test_bad_event_returns_400` — Sends empty `{detail: {}}` → expects 400

**TestEncryptionCheck (1 test):**
1. `test_detects_unencrypted_bucket` — Mocks `ClientError` with `ServerSideEncryptionConfigurationNotFoundError` → expects `ENCRYPTION_REMEDIATED`

**TestComplianceMapping (6 tests):**
1. `test_s3_public_access_has_mappings` — Verifies ≥3 controls, all 3 frameworks present
2. `test_encryption_has_mappings` — Verifies ≥2 CIS controls
3. `test_iam_audit_has_mappings` — Verifies control IDs 1.16 and 7.1
4. `test_remediated_event_passes` — REMEDIATED → PASS for all controls
5. `test_failed_event_fails` — REMEDIATION_FAILED → FAIL for all controls
6. `test_iam_overpermissive_fails` — IAM_OVERPERMISSIVE → FAIL

**TestComplianceSummary (4 tests):**
1. `test_all_passing_gives_100` — All remediated events → 100.0% score
2. `test_mixed_events_lower_score` — Mix of remediated + overpermissive → 0 < score < 100
3. `test_summary_has_all_frameworks` — Summary contains CIS AWS, SOC 2, PCI-DSS
4. `test_empty_events_gives_zero` — No events → 0% score, 0 controls checked

### Mocking Strategy
Uses `unittest.mock.patch` to mock:
- `lambda_function.s3_client` — prevents real AWS calls
- `lambda_function.dynamodb` — prevents real DynamoDB writes
- `lambda_function.send_discord_notification` — prevents real webhook calls
- `lambda_function.create_github_issue` — prevents real GitHub API calls

---

## 20. DynamoDB Schema

### Table Name: `cspm-remediation-events`

| Attribute | Type | Key | Description |
|---|---|---|---|
| `event_id` | String (S) | **Hash Key (Partition)** | UUID v4 |
| `timestamp` | String | — | ISO 8601 UTC (e.g., `2026-06-12T04:17:52+00:00`) |
| `bucket_name` | String | — | Resource identifier (bucket, SG ID, table name, IAM user) |
| `account_id` | String | — | AWS account ID |
| `region` | String | — | AWS region |
| `status` | String | — | `REMEDIATED`, `COMPLIANT`, `REMEDIATION_FAILED`, `ENCRYPTION_REMEDIATED`, `ENCRYPTION_FAILED`, `IAM_OVERPERMISSIVE` |
| `event_name` | String | — | CloudTrail event name (e.g., `CreateBucket`) |
| `vulnerability_type` | String | — | `S3 Public Access`, `S3 Encryption`, `IAM Audit`, `Security Group Open SSH`, `DynamoDB Unencrypted` |
| `severity` | String | — | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `nlp_summary` | String (optional) | — | NLG engine output text |

### Billing: PAY_PER_REQUEST (on-demand capacity)
### No GSIs or LSIs — uses `scan()` with `FilterExpression` for queries.

---

## 21. API Design

### API Lambda Routes (`lambda/api/lambda_function.py`)

| Route | Method | Function | Response |
|---|---|---|---|
| `/events` | GET | `get_events()` | `{"events": [...], "count": N}` — all events sorted by timestamp desc |
| `/stats` | GET | `get_stats()` | `{"total_events", "remediated", "compliant", "failed", "flagged", "unique_buckets", "active_regions", "last_event", "compliance_rate", "vulnerability_types", "severities"}` |
| `/compliance` | GET | `get_compliance()` | `{"overall_score", "frameworks": {"CIS AWS": {"total", "passed", "score"}...}, "controls_checked", "controls_passed"}` |
| `/trends` | GET | `get_trends()` | `{"trends": [{"date", "score", "events"}...]}` — daily compliance scores |
| `OPTIONS` (any) | OPTIONS | — | `{"message": "OK"}` with CORS headers |

### CORS Headers
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, OPTIONS
Access-Control-Allow-Headers: Content-Type
```

### Pagination
DynamoDB scan handles pagination via `LastEvaluatedKey` loop — fetches all items.

### Compliance Rate Calculation
```python
actionable = remediated + failed + flagged
compliance_rate = round((remediated / actionable * 100), 1) if actionable > 0 else 100.0
```

---

## 22. File-by-File Inventory

### Root Level
| File | Size | Purpose |
|---|---|---|
| `README.md` | 5,233 B | Project overview, architecture, quick start |
| `CSPM_Study_Guide.md` | 19,654 B | Interview/study guide with deep explanations |
| `docker-compose.yml` | 823 B | LocalStack Docker configuration |
| `.gitignore` | 479 B | Python, Docker, Terraform, IDE exclusions |
| `err.txt` | 3,160 B | Captured error output (EC2 service not enabled) |
| `sim_out.txt` | 2,424 B | Captured simulation output (Unicode encoding error) |

### `lambda/remediation/`
| File | Size | Lines | Functions |
|---|---|---|---|
| `lambda_function.py` | 21,869 B | 549 | `lambda_handler`, `check_public_access`, `check_encryption`, `check_security_group`, `check_dynamodb_encryption`, `inspect_public_access`, `remediate_public_access`, `log_event_to_dynamodb`, `send_discord_notification`, `_extract_bucket_name`, `_extract_sg_id`, `_extract_table_name` |

### `lambda/api/`
| File | Size | Lines | Functions |
|---|---|---|---|
| `lambda_function.py` | 8,424 B | 237 | `lambda_handler`, `get_events`, `get_stats`, `get_compliance`, `get_trends`, `_cors_headers`, `_response` |

### `lambda/iam-audit/`
| File | Size | Lines | Functions |
|---|---|---|---|
| `lambda_function.py` | 11,882 B | 340 | `lambda_handler`, `audit_user_policies`, `audit_role_policies`, `is_admin_policy`, `find_wildcards`, `log_event_to_dynamodb`, `send_discord_notification` |

### `lambda/shared/`
| File | Size | Lines | Functions |
|---|---|---|---|
| `compliance.py` | 10,467 B | 278 | `get_compliance_for_event`, `get_compliance_summary` + constants `FRAMEWORKS`, `COMPLIANCE_MAP` |
| `nlg_engine.py` | 21,252 B | 544 | `generate_incident_summary`, `_compute_sentiment_score`, `_build_sentiment_fragment`, `extract_iam_entities`, `_query_temporal_context`, `_detect_attack_chain`, `_format_timestamp`, `_severity_descriptor` |
| `github_notifier.py` | 3,589 B | 130 | `create_github_issue` |
| `policy_engine.py` | 8,199 B | 249 | `load_policies`, `get_policy`, `get_enabled_policies`, `get_providers`, `update_policy`, `is_check_enabled`, `policies_to_json`, `_parse_yaml`, `_write_yaml` |
| `policy_generator.py` | 10,915 B | 273 | `auto_generate_policy`, `get_pending_review_policies`, `_detect_provider`, `_detect_vulnerability_type`, `_get_existing_policy_checks` |
| `policy_sync.py` | 15,532 B | 437 | `sync_all`, `sync_from_github`, `sync_from_cis`, `sync_from_prowler`, `_fetch_url`, `_policy_exists`, `_save_policy_yaml` |

### `lambda/shared/providers/`
| File | Size | Lines | Purpose |
|---|---|---|---|
| `__init__.py` | 1,010 B | 40 | Provider registry + `get_provider()`, `list_providers()` |
| `base.py` | 1,733 B | 56 | Abstract base class `CloudProvider` |
| `aws.py` | 7,523 B | ~190 | AWS provider implementation |
| `azure.py` | 13,524 B | 290 | Azure provider (SDK + mock fallback) |
| `gcp.py` | 12,364 B | ~308 | GCP provider (SDK + mock fallback) |
| `mock_data.py` | 13,897 B | ~348 | Mock Azure/GCP resources for demo |

### `scripts/`
| File | Size | Lines | Purpose |
|---|---|---|---|
| `local-api-server.py` | 25,967 B | 655 | All-in-one dashboard server |
| `simulate-attacks.py` | 24,079 B | 614 | Multi-vulnerability attack simulator |
| `report_generator.py` | 11,096 B | 321 | PDF compliance report |
| `terraform-scanner.py` | 8,597 B | 263 | Terraform SAST scanner |
| `deploy-lambdas.py` | 7,395 B | 227 | Direct Lambda deployment |
| `deploy-local.ps1` | 3,859 B | — | PowerShell deployment script |
| `test-remediation.ps1` | 8,961 B | — | PowerShell remediation test |

### `terraform/`
| File | Size | Lines | Purpose |
|---|---|---|---|
| `main.tf` | 13,594 B | 454 | All resource definitions (17 resources) |
| `variables.tf` | 1,420 B | 44 | 6 input variables |
| `outputs.tf` | 1,574 B | 44 | 8 output values |
| `localstack.tfvars` | 448 B | — | LocalStack overrides |

### `tests/`
| File | Size | Lines | Tests |
|---|---|---|---|
| `test_remediation.py` | 4,896 B | 132 | 4 test cases |
| `test_compliance.py` | 4,490 B | 112 | 8 test cases |

### `policies/`
- 46 YAML policy files (AWS, Azure, GCP, Prowler, CIS, custom)
- 1 subdirectory `feeds/` containing `cis_baseline.json` (7,792 B, 18 CIS controls)

### `.github/workflows/`
| File | Size | Lines | Purpose |
|---|---|---|---|
| `cspm-scan.yml` | 3,022 B | 100 | CI/CD pipeline (2 jobs) |

---

## 23. Quantitative Metrics

| Metric | Value |
|---|---|
| Total source files | 82 |
| Total source code size | ~450 KB |
| Python source files | ~25 |
| Total Python lines | ~5,500+ |
| Vulnerability types detected | 5 |
| Auto-remediated vulnerability types | 4 (S3 Public Access, S3 Encryption, SG SSH, DynamoDB) |
| Flag-only vulnerability types | 1 (IAM Audit) |
| Compliance frameworks mapped | 3 (CIS AWS, SOC 2, PCI-DSS) |
| Individual compliance controls mapped | 19 |
| YAML security policies | 46 |
| CIS Benchmark baseline controls | 18 |
| Prowler checks integrated | 17 |
| Cloud providers supported | 3 (AWS, Azure, GCP) |
| NLG engine features | 5 (template NLG, sentiment, temporal, NER, correlation) |
| NLG risk keywords | 30+ |
| NLG AWS service entities | 14 |
| NLG attack chain patterns | 4 |
| Terraform security scanner rules | 6 |
| API endpoints | ~18 (local server; includes `/ai/insights` and `/simulate`, added after the original count of 17) |
| AI/ML reasoning layers | 5 (anomaly detection, ATT&CK classification, blast radius, policy drafting, priority scoring) + 1 orchestrator |
| Blast-radius graph nodes | 21 (`ml/data/blast_radius_seed.json`, expanded from 20 in `GROWTH_PLAN.md` Phase 1) |
| Unit tests | 261 (was 12 at original documentation time) |
| CI/CD jobs | 2 |
| Docker services | 1 (LocalStack) |
| AWS services emulated | 8 |
| Terraform resources defined | 17+ |
| PDF report sections | 5 |
| Discord webhook fields | 6 |
| GitHub Issue labels | 7 |
| Simulation phases | 8 |
| Simulated attacks per run | ~15 events |

---

## 24. Security Limitations & Known Flaws

1. **God-Mode Remediation Lambda**: The remediation Lambda has extremely wide permissions (`arn:aws:s3:::*`). In a real enterprise, the IAM execution role would be restricted using boundary policies.

2. **Race Conditions**: There is a microscopic gap (milliseconds) between resource creation and remediation. A hacker could theoretically read data within that gap. **Mitigation:** Use proactive SCPs (Service Control Policies) to deny unencrypted creation entirely.

3. **Local API Server**: `local-api-server.py` lacks authentication. In production, AWS API Gateway + Cognito would provide proper AuthN/AuthZ.

4. **DynamoDB Full Table Scans**: The API Lambda uses `table.scan()` which reads every item. At scale, this would be slow and expensive. **Fix:** Add GSIs on `timestamp` and `account_id`.

5. **No Encryption in Transit for Local**: LocalStack communicates over HTTP, not HTTPS. Real AWS uses TLS.

6. **Hardcoded Credentials**: LocalStack test credentials (`access_key="test"`, `secret_key="test"`) are present in deployment scripts. These are harmless for LocalStack but indicate a pattern to avoid in production.

7. **CORS Wildcard**: `Access-Control-Allow-Origin: *` is used for simplicity. Production should restrict to specific domains.

8. **No Rate Limiting**: The Discord webhook and GitHub API calls have no rate limiting — could hit API rate limits under heavy load.

---

## 25. Blue Team / DevSecOps Classification

This project falls strictly under:

- **Blue Teaming (Defensive Security):** Builds automated guardrails and monitoring systems to detect and block attacks in real-time.
- **DevSecOps (Development, Security, Operations):** Integrates security directly into the developer workflow via GitHub Actions CI/CD and Terraform IaC scanning.
- **Shift-Left Security:** Finds security flaws early in the development process — before infrastructure is even deployed — via the Terraform scanner.
- **MITRE ATT&CK Alignment:** The NLG engine's attack chain detection maps to MITRE ATT&CK tactics (Privilege Escalation, Lateral Movement, Exfiltration, Persistence).

---

## 26. References to Industry Standards

| Standard | Relevance |
|---|---|
| **CIS AWS Foundations Benchmark v2.0** | Primary compliance framework — 7 controls directly mapped |
| **SOC 2 Type II** | Trust Services Criteria — CC6.1, CC6.3, CC6.6, CC6.7 mapped |
| **PCI-DSS v4.0** | Payment card industry — Controls 1.3.2, 2.2, 3.4, 7.1, 7.2 mapped |
| **MITRE ATT&CK Framework** | Attack chain patterns map to Privilege Escalation, Lateral Movement, Exfiltration |
| **Principle of Least Privilege** | Enforced in IAM audit scanning and Terraform IAM role definitions |
| **NIST Shared Responsibility Model** | Customer responsibility for configuration management |
| **Cloud Custodian** | Policy-as-Code architecture inspiration |
| **Prisma Cloud / OPA** | YAML-based policy engine design influence |
| **Prowler** | Open-source check metadata integration |
| **Splunk / Datadog / PagerDuty** | Deterministic NLG technique reference |

---

*Document originally generated June 12, 2026, covering the rule-based detection/remediation engine, policy-as-code, and multi-cloud abstraction layer as they existed then. Updated 2026-09-10 (`GROWTH_PLAN.md` Phase 5) to add Section 5A (the AI/ML reasoning pipeline built afterward) and to correct Sections 11 and 19, which had gone stale after the frontend's React rewrite and the two rounds of adversarial testing respectively. For teaching-depth detail on the AI pipeline, see `PROJECT_MASTERCLASS.md`; for evaluation numbers, `eval/EVAL_REPORT.md`; for the full testing history, `TESTING_AND_EVALUATION_SUMMARY.md`; for the project's active roadmap, `GROWTH_PLAN.md`.*
