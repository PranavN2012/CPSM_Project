# 🛡️ CloudSentry — AI-Powered Cloud Security Posture Management

[![CSPM Security Scan](https://img.shields.io/badge/security-automated-brightgreen)](https://github.com/PranavN2012/CPSM_Project)
[![Python 3.11](https://img.shields.io/badge/python-3.11-blue)](https://python.org)
[![React](https://img.shields.io/badge/frontend-React%20%2B%20Vite-61DAFB)](https://react.dev)
[![LocalStack](https://img.shields.io/badge/local-LocalStack-orange)](https://localstack.cloud)
[![Tests](https://img.shields.io/badge/tests-279%20passing-brightgreen)](tests/)

A **multi-cloud** (AWS/Azure/GCP) Cloud Security Posture Management platform that doesn't just flag misconfigurations — it runs every finding through a **5-layer AI reasoning pipeline** (anomaly detection → ATT&CK classification → blast-radius graph traversal → LLM-drafted policy fixes → priority scoring) before deciding whether to auto-remediate, escalate to a human, or gather more context. Runs entirely on **LocalStack** — $0 cloud spend, no real AWS account required.

---

## 🧠 The 5-Layer AI Reasoning Pipeline

This is the core of the project, not a bolt-on:

| Layer | What it does | How |
|---|---|---|
| **1. Anomaly Detection** | Flags whether an event is statistically unusual | IsolationForest over event feature vectors |
| **2. ATT&CK Classification** | Maps the finding to a real MITRE ATT&CK technique | SBERT embeddings + semantic similarity against a technique knowledge base |
| **3. Blast Radius** | How far could this spread if exploited? | BFS graph traversal over IAM trust/permission relationships |
| **4. Policy Drafting** | Writes an actual IAM policy fix | LLM (Groq/Gemini) propose → sandbox-test → revise loop; a failing draft is retried, never silently accepted |
| **5. Priority Scoring** | Ranks the finding against everything else open | Weighted formula combining severity, blast radius, and classification confidence |

An **orchestrator** sits on top and decides, per finding: auto-fix, escalate to a human (surfaced in the **Needs Review** queue), or gather more context. Every layer is empirically evaluated against ground truth — see `eval/EVAL_REPORT.md` and `eval/generalization_benchmark/` — not just demoed.

## 🔍 Vulnerability Detection (13 types, 3 clouds)

| Cloud | Detects |
|---|---|
| **AWS** | S3 public access, S3 missing encryption, IAM overpermissive policies (wildcard `*`), open security groups, unencrypted DynamoDB, public RDS, public Lambda URLs, unencrypted EBS |
| **Azure** (mock provider) | Public Blob storage, open NSG ports, missing storage encryption |
| **GCP** (mock provider) | Public GCS buckets, missing CMEK encryption, open firewall rules |

S3/IAM/security-group/DynamoDB findings run against real LocalStack APIs; Azure/GCP findings run through a provider abstraction layer backed by mock data (openly disclosed, not silently passed off as live cloud calls).

## ✨ Features

- **5-layer AI reasoning** on every finding — real ML/LLM inference, not canned responses
- **Autonomous remediation with a safety gate** — the LLM drafts an IAM policy fix; a deterministic evaluator independently verifies it before "Deploy Fix" is ever allowed to apply it against LocalStack
- **Needs Review queue** — incidents the AI explicitly escalated to a human, separate from what it auto-handled
- **Attack Path & Blast Radius graph** — real BFS traversal over an IAM relationship graph, rendered per-incident
- **Policy-as-Code engine** — 46 YAML rules, syncable from GitHub/CIS baseline/Prowler feeds, with human-review gating for auto-generated policies covering novel finding types
- **Compliance mapping** — CIS AWS Benchmarks, SOC 2, PCI-DSS, scored from live event data
- **Multi-cloud** — AWS (live via LocalStack), Azure + GCP (mock providers)
- **Cinematic React dashboard** — glassmorphism UI, animated hexagon mesh background, decrypted-text headings, a WebGL light-ray + pixel-dissolve intro sequence
- **PDF compliance reports**, **GitHub Issue auto-filing**, **Discord notifications**
- **Evaluated, not just demoed** — per-layer eval scripts, a 24-scenario generalization benchmark, and ablation studies quantifying which parts of the scoring formula actually matter
- **100% local, $0 cloud spend** — LocalStack only, by deliberate project-wide policy (see `GROWTH_PLAN.md`)

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Backend compute | AWS Lambda (Python 3.11), via LocalStack |
| AI/ML | scikit-learn (anomaly detection), sentence-transformers (SBERT classification), Groq / Gemini (LLM policy drafting) |
| Storage | DynamoDB, S3 |
| Orchestration | EventBridge |
| Frontend | React 18 + Vite, Chart.js |
| PDF reports | fpdf2 |
| CI/CD | GitHub Actions (full 279-test suite on push) |
| Notifications | Discord Webhooks, GitHub Issues API |
| Local dev | LocalStack, Docker |
| Testing | pytest (279 tests across every pipeline layer + the API server) |

## 🚀 Quick Start

```bash
# 1. Clone and enter
git clone https://github.com/PranavN2012/CPSM_Project.git
cd CPSM_Project

# 2. Start LocalStack
docker-compose up -d

# 3. Deploy Lambda functions, tables, and IAM roles into LocalStack
python scripts/deploy-lambdas.py

# 4. Seed realistic findings so the dashboard isn't empty
python scripts/simulate-attacks.py

# 5. Build the React frontend
cd frontend && npm install && npm run build && cd ..

# 6. Start the server (serves the built frontend + the API)
python scripts/local-api-server.py

# 7. Open http://localhost:3001 and click through the intro
```

To use the LLM-backed policy drafting (Layer 4) instead of the rule-based fallback, copy `.env.example` to `.env` and set a `GROQ_API_KEY` or `GEMINI_API_KEY`.

## 📁 Project Structure

```
serverless-cspm/
├── lambda/
│   ├── remediation/           # S3 public access + encryption remediation
│   ├── iam-audit/             # IAM wildcard policy scanner (with rescan dedup)
│   └── shared/
│       ├── ml/                # Layers 1-5 + orchestrator (anomaly, classifier, blast radius, policy agent, priority scorer)
│       ├── providers/         # AWS/Azure/GCP abstraction layer
│       ├── compliance.py      # CIS/SOC2/PCI-DSS scoring
│       ├── policy_engine.py   # Policy-as-code manager
│       └── policy_sync.py     # Pulls rules from GitHub/CIS/Prowler feeds
├── frontend/
│   └── src/
│       ├── components/        # Sidebar, Topbar, PriorityCard, PolicyCard, and the intro sequence (IntroGate, PixelSwap, LightRays, ShapeGrid, DecryptedText, SplitFlapText, TrueFocus)
│       ├── components/views/  # One component per dashboard page (8 pages)
│       └── hooks/             # Live data polling, theme
├── eval/                      # Per-layer evaluation scripts + generalization benchmark
├── scripts/
│   ├── local-api-server.py    # All-in-one local server (serves frontend/dist + the REST API)
│   ├── deploy-lambdas.py      # Direct Lambda/table/role deployment to LocalStack
│   └── simulate-attacks.py    # Multi-vulnerability, multi-cloud attack simulator
├── policies/                  # 46 YAML policy-as-code rules
├── tests/                     # 279 pytest tests
├── .github/workflows/         # CI — runs the full test suite on push
└── docker-compose.yml         # LocalStack config
```

## 🖥️ The Dashboard (8 pages)

1. **Security Posture** — KPI overview, vulnerability split, compliance benchmarks, priority action queue
2. **AI Reasoning (5-Layer)** — the live pipeline output for every event
3. **Needs Review** — incidents the AI escalated to a human rather than auto-fixing
4. **Attack Path & Blast Radius** — real BFS graph for a selected incident
5. **Policy Diff & Approval** — the actual before/after IAM policy JSON, with a working "Deploy Fix" against LocalStack
6. **System & Audit Trace** — the full event log, filterable, exportable to GitHub Issues
7. **Policy Engine** — toggle/sync the 46 policy-as-code rules
8. **System Settings** — pipeline status, live-analysis limits, an on-demand attack simulator, integration status

## 🧪 Running Tests

```bash
pip install -r requirements-ai.txt
pytest tests/ -v
```

279 tests, covering every pipeline layer, the orchestrator, and the local API server — designed to fully exercise the rule-based fallbacks without requiring an LLM API key.

## 📄 License

MIT
