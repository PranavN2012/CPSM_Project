# Serverless CSPM (Cloud Security Posture Management)
## Comprehensive Interview & Study Guide

---

### 1. Core Concept: What is a CSPM?
**Cloud Security Posture Management (CSPM)** is a class of security tools designed to identify and remediate risks across cloud infrastructures (AWS, Azure, GCP). 
- **The Problem:** Cloud environments are highly complex. Developers constantly spin up resources via infrastructure-as-code (IaC). A single typo (like leaving an S3 bucket public) can lead to a massive data breach (e.g., the Capital One breach in 2019, or Twitch source code leak in 2021).
- **The Solution:** A CSPM continuously monitors the cloud environment, compares configurations against strict security best practices, alerts administrators, and can **automatically remediate** (fix) the vulnerabilities in real-time.
- **This Project:** We built a custom, event-driven CSPM using AWS Serverless technologies that detects vulnerabilities, maps them to regulatory frameworks, and auto-remediates them in milliseconds.

---

### 2. Is this "Blue Teaming"?
**Yes, absolutely.** This falls strictly under **Blue Teaming** (Defensive Security) and **DevSecOps** (Development, Security, and Operations).
- **Red Team (Offensive):** Tries to find misconfigurations (like public S3 buckets) to exfiltrate data or escalate privileges.
- **Blue Team (Defensive):** Builds the automated guardrails and monitoring systems (like this CSPM) to detect and block the Red Team's attempts. 
- **DevSecOps:** We are integrating security directly into the developer workflow (via GitHub Actions CI/CD) and infrastructure (via Terraform).

---

### 3. Vulnerability Detection & Remediation Engine
Our CSPM focuses on the most critical AWS vulnerabilities:

#### A. S3 Public Access (Data Exfiltration Risk)
- **The Risk:** S3 buckets hold company data. If `Block Public Access` is turned off, anyone on the internet can potentially view or download the files. AWS provides four security flags: `BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, `RestrictPublicBuckets`. If any are false, it's vulnerable.
- **The Detection:** Our Lambda function intercepts the `CreateBucket` or `PutBucketPublicAccessBlock` events.
- **The Remediation:** The Lambda uses `boto3` to immediately inject a `PutPublicAccessBlock` API call, overriding the user and securely locking the bucket.

#### B. S3 Unencrypted Buckets (Data at Rest Risk)
- **The Risk:** Without Server-Side Encryption (SSE), data is stored in plaintext on AWS physical drives. 
- **The Detection & Remediation:** We detect a lack of encryption and enforce AES-256 encryption automatically.

#### C. IAM Overpermissive Policies (Privilege Escalation Risk)
- **The Risk:** Developers often use `Action: "*", Resource: "*"` (wildcard) out of laziness. If that user's access keys are leaked, the hacker has total administrative control over the entire AWS account.
- **The Detection:** Our IAM Audit Lambda scans newly attached user policies, specifically looking for wildcard JSON blocks, and enforces the **Principle of Least Privilege**.

#### D. Security Group Open SSH (Network Perimeter Risk)
- **The Risk:** Leaving SSH (Port 22) open to the internet (`0.0.0.0/0`) allows attackers to brute-force or exploit vulnerabilities in the EC2 instance's OS, potentially gaining a foothold inside the VPC.
- **The Detection:** The Lambda intercepts `AuthorizeSecurityGroupIngress` and `CreateSecurityGroup` events.
- **The Remediation:** The Lambda uses Boto3 to instantly `revoke_security_group_ingress`, removing the overly permissive rule while leaving the rest of the Security Group intact.

#### E. DynamoDB Unencrypted Tables (Data at Rest Risk)
- **The Risk:** Storing sensitive NoSQL data without encryption means a physical breach or snapshot theft could expose PII or credentials. 
- **The Detection:** Scans `CreateTable` events for the `SSESpecification` block.
- **The Remediation:** Enforces `ServerSideEncryptionConfiguration` (KMS AES-256) via a quick API payload update.

#### Python and boto3 Exception Handling
Our remediation lambdas use boto3 (the AWS SDK). We have to gracefully handle edge cases:
- **`NoSuchBucket`**: The hacker deleted the bucket before our Lambda could remediate it.

---

### 4. NLP-Powered Incident Intelligence Engine
Our CSPM includes an in-house **Natural Language Generation (NLG) engine** (`nlg_engine.py`) that transforms raw JSON events into contextual, audit-grade incident narratives. The same deterministic NLG technique is used by enterprise SIEMs like Splunk, Datadog, and PagerDuty.

#### A. Template-Based NLG (Core Engine)
- **Technique:** Conditional slot-filling — maps each `vulnerability_type × status` combination to pre-built narrative templates.
- **Output:** A 3-sentence summary: *(What happened)* + *(Why it matters — compliance)* + *(What was done)*.
- **Example:** *"A configuration change in account 987654321098 created S3 bucket `prod-data-lake` in us-east-1. This poses a critical risk of unauthorized internet-wide data exposure, violating CIS AWS 2.1.5, SOC 2 CC6.1, PCI-DSS 7.1. CloudSentry auto-remediated by injecting a PutPublicAccessBlock API call."*

#### B. Sentiment-Weighted Severity Scoring
- **Technique:** Keyword-based sentiment analysis scans resource names for risk indicators.
- **How it works:** 30+ keywords are scored in 3 tiers — critical (`prod`, `customer`, `payment`, `credential`, `secret`), high (`backup`, `vault`, `session`, `user`), and low (`dev`, `test`, `sandbox`). The cumulative score adjusts the narrative's urgency language.
- **Example:** For bucket `prod-data-lake-raw`, the engine detects `prod` and `data`, upgrading the summary to: *"The resource name contains 'prod', 'data', suggesting this asset handles sensitive data."*

#### C. Temporal Context (Historical Pattern Analysis)
- **Technique:** The engine queries DynamoDB for past events matching the same `account_id × vulnerability_type` to build frequency context.
- **Output:** *"TEMPORAL ANALYSIS: This is the 5th S3 Public Access event detected in account 123456789012. Repeated S3 misconfigurations may indicate a systemic process or training gap."*
- **Value:** Helps detect **recidivism** — are developers in a specific account repeatedly making the same mistake?

#### D. Named Entity Recognition (NER) for IAM Policies
- **Technique:** Regex-based NER extracts AWS service tokens from IAM policy strings (e.g., `s3:GetObject`, `ec2:*`, `iam:AttachUserPolicy`).
- **Service Database:** 14 AWS services mapped to human-readable names (e.g., `s3` → *"Simple Storage Service (S3)"*).
- **Output:** *"NER analysis identified a wildcard policy (Action:*) granting unrestricted access to ALL AWS services including S3, EC2, Lambda, and IAM."*

#### E. Cross-Event Correlation (Attack Chain Detection)
- **Technique:** Queries DynamoDB for recent events across *different* vulnerability types in the same account, then pattern-matches against known multi-step attack chains.
- **Known Kill Chains:**
  - **Lateral Movement:** IAM Privilege Escalation → Open Security Group SSH
  - **Data Exfiltration:** Open SSH → S3 Public Access
  - **Full Compromise:** IAM Privilege Escalation → S3 Public Access
  - **Persistence:** IAM Privilege Escalation → Unencrypted DynamoDB
- **Output:** *"CORRELATION ALERT: An IAM privilege escalation was detected in the same account shortly before this network perimeter breach. This pattern matches a lateral movement kill chain."*

#### Interview Talking Point for NLP
> *"I built a deterministic NLG engine using template-based slot-filling, keyword sentiment analysis, regex-based Named Entity Recognition, and cross-event correlation to generate contextual, audit-grade incident narratives. Each summary maps vulnerabilities to specific CIS, SOC 2, and PCI-DSS controls and detects multi-step attack chains across the MITRE ATT&CK framework — all without any external API dependencies."*
- **`NoSuchPublicAccessConfiguration`**: The bucket has no public access block at all (most dangerous).

---

### 4. AWS Services & Network Flow Architecture

#### How it works logically (The Network Flow):
1. **Trigger:** A developer or hacker modifies an AWS resource.
2. **CloudTrail (The Logger):** Records every API call (who, what, when, where) as a JSON event in CloudTrail.
3. **EventBridge (The Router):** Routes events to our Security Lambda based on pattern-matching rules:
    ```json
    {
      "source": ["aws.s3"],
      "detail-type": ["AWS API Call via CloudTrail"],
      "detail": {
        "eventSource": ["s3.amazonaws.com"],
        "eventName": ["CreateBucket", "PutBucketPublicAccessBlock"]
      }
    }
    ```
4. **AWS Lambda (The Brains):** Serverless compute. Scans the JSON, decides if it's a threat, fires a remediation API call back to AWS.
5. **DynamoDB (The DB):** Serverless NoSQL database. We write event logs to it with a schema containing `event_id`, `timestamp`, `bucket_name`, `status`, `event_name`.
6. **API Gateway / Local Server:** Serves the frontend and answers API calls. (We used a custom Python HTTP Proxy `local-api-server.py` locally to emulate this over a single port).

#### Local Emulation vs. Real AWS:
- **Docker & LocalStack:** We used LocalStack inside a Docker container. Docker provides an isolated virtual environment. LocalStack is a Python-based emulator that perfectly mimics the real AWS cloud locally on your PC, saving us cloud billing costs while allowing full end-to-end integration tests.

---

### 5. Compliance Frameworks
Our CSPM maps every vulnerability to global regulatory standards:
1. **CIS AWS Foundations Benchmark:** The industry standard for securing AWS accounts (e.g., ensuring S3 public access is blocked `2.1.5`).
2. **SOC 2 Type II:** Auditing procedure focusing on Trust Services Criteria (Security, Availability, Confidentiality, Privacy).
3. **PCI-DSS v4.0:** Payment Card Industry rules. Required for any company handling credit card data (requires strict encryption `3.4` and access control `7.1`).

---

### 6. DevSecOps, CI/CD, and Terraform

**Shift-Left** means finding security flaws *early* in the development process.

- **Infrastructure as Code (Terraform):** We define our Lambdas, IAM Roles, and EventBridge triggers in declarative HCL files instead of clicking through the AWS console.
- **Terraform Scanner (`terraform-scanner.py`):** We built a custom static application security testing (SAST) tool that reads `.tf` files and uses Regex to find missing security blocks *before* the infrastructure is even built.
- **GitHub Actions (CI/CD):** Every time code is pushed, a runner spins up in the cloud, runs our Python `pytest` Unit Tests, and runs the Terraform scanner. If security vulnerabilities are found in the IaC, the pipeline **fails** and blocks the deployment.
- **Discord Webhooks:** DevSecOps teams need alerts. Our Lambda securely fires JSON payload alerts to a Discord channel (Green for REMEDIATED, Red for FAILED) so the team is aware of live attacks.

---

### 7. Security Flaws & Limitations in Our Project Code
If an interviewer asks, "What are the limitations of your project?" point out these real architectural flaws:

1. **God-Mode Remediation Lambda:** In this project, our remediation Lambda has extremely wide permissions to modify ANY S3 bucket or IAM user. In a real enterprise, we would restrict the Lambda's IAM Execution Role strictly, utilizing boundary policies so a compromised Lambda couldn't destroy the whole account.
2. **Race Conditions:** There is a microscopic gap between when a bucket is created and when our Lambda remediates it (milliseconds). In a highly sensitive environment, a hacker could theoretically read data within that gap (we recommend proactive SCPs to completely deny the unencrypted creation in the first place).
3. **Local API Server:** The custom `local-api-server.py` is fantastic for local dashboards, but in production, we would discard it and use a real **AWS API Gateway** with Cognito authentication to secure the dashboard.

---

### 8. Architecture Diagram

```text
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
│  │ EC2 / DDB  │                      │  └────────────────┘ │    │
│  └────────────┘                      └──────────┬───────────┘    │
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
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 9. Component Deep-Dive Breakdown

To properly explain the diagram above in an interview, here is exactly what every single component does:

#### S3 (Simple Storage Service)
S3 is Amazon's object storage service. It acts as both the **victim** and the **host** in our architecture:
- **Target:** Users create S3 buckets to store files. If configured poorly, it creates a data breach.
- **Website Host:** S3 has a feature to host static HTML/CSS/JS files, which is where our frontend CSPM dashboard is stored.

#### IAM (Identity and Access Management)
IAM manages who can do what in AWS. It deals in Users, Roles, and Policies (JSON permissions).
- **Target:** When developers create IAM users with wildcard (`*`) permissions, it creates a massive privilege escalation risk. Our IAM Audit Lambda specifically hunts for this.
- **Security Guardrail:** Every Lambda function we wrote has an execution role tightly defining its authority, following the Principle of Least Privilege.

#### AWS CloudTrail
CloudTrail is the ultimate audit logger for AWS. Every single time *anyone* or *anything* makes an API call in the AWS account (e.g., clicking a button to create an S3 bucket or run a Python script), CloudTrail records a massive JSON file detailing who did it, at what exact millisecond, from what IP address, and what the parameters were. Without CloudTrail, event-driven security is impossible.

#### Amazon EventBridge
EventBridge is a serverless event bus / router. It connects CloudTrail to our Security Lambda. We write a JSON "rule" telling EventBridge: *"If you ever see a CloudTrail event where the event name is 'CreateBucket', instantly route that JSON payload to the Remediation Lambda."* EventBridge acts as the glue.

#### Remediation Lambda (The Brain & Muscle)
This is the core Python script that acts as the active defender. When triggered by EventBridge, it runs sequentially:
1. `inspect_bucket()`: Uses Boto3 (AWS SDK) to query the bucket and check if it has encryption or public access blocks enabled.
2. `remediate()`: If a vulnerability is found, it immediately fires a `PutPublicAccessBlock` or `PutBucketEncryption` Boto3 API call to forcefully overwrite the bad configuration and lock the resource.
3. `notify_discord()`: Formats a JSON alert payload and POSTs it to a webhook URL so human security engineers are aware a threat was neutralized.
4. `log_to_dynamo()`: Packages the vulnerability details and sends them to the database.

#### Amazon DynamoDB
DynamoDB is a highly scalable Serverless NoSQL database. We use it instead of SQL because writing millions of fast, unstructured JSON events is what NoSQL excels at. We store the `timestamp`, `bucket_name`, `vulnerability_type`, and `status` (REMEDIATED vs. FAIL).

#### API Gateway (API GW)
API Gateway acts as the secure front door to our backend database. The frontend browser cannot talk directly to DynamoDB for security reasons. Instead, the browser makes an HTTP GET request to API Gateway (`/events`). API Gateway handles the routing, CORS, and throttling securely.

#### API Lambda (The Reader)
While the Remediation Lambda is the *writer*, the API Lambda is the *reader*. Triggered by the API Gateway, this simple Python function uses Boto3 to execute a `.scan()` on the DynamoDB table, retrieves all the historical vulnerability events, formats them into a clean JSON response, and sends them back to the frontend dashboard. 

---

### 10. Project Summary Pitch (For Interviews)
> *"I built an event-driven Serverless Cloud Security Posture Management (CSPM) tool. I used Python and Boto3 to create AWS Lambdas that continuously monitor architecture for high-risk misconfigurations—like public S3 buckets, unencrypted DynamoDB tables, open SSH ports, and wildcard IAM policies. When a threat is detected, the Lambda auto-remediates the vulnerability in milliseconds and records the event in DynamoDB. I integrated an NLP-powered incident intelligence engine that uses template-based NLG, keyword sentiment analysis, Named Entity Recognition, and cross-event correlation to generate audit-grade narratives and detect multi-step attack chains. To make it enterprise-ready, I mapped all vulnerabilities to CIS, SOC 2, and PCI-DSS compliance frameworks, built a real-time tracking dashboard featuring an interactive Attack Path simulation graph, and integrated a custom Terraform static scanner into a GitHub Actions CI/CD pipeline to embrace shift-left DevSecOps principles. The entire environment was developed and tested entirely offline using Docker and LocalStack."*
