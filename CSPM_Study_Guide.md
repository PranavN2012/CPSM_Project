# Serverless CSPM (Cloud Security Posture Management) — Complete Study Guide

## 1. What Is CSPM?

Cloud Security Posture Management (CSPM) is a category of security tools that continuously monitor cloud infrastructure for misconfigurations, compliance violations, and security risks. CSPM tools automatically detect when cloud resources (like storage buckets, databases, virtual machines) are configured in ways that could expose sensitive data or create attack vectors.

In production environments, companies like Palo Alto (Prisma Cloud), Wiz, and Orca Security sell CSPM solutions for thousands of dollars per month. This project builds a focused, open-source CSPM tool that specifically targets one of the most common cloud misconfigurations: publicly accessible S3 storage buckets.

### Why S3 Public Access Is Dangerous

Amazon S3 (Simple Storage Service) is the most widely used cloud storage service. When an S3 bucket is made public, anyone on the internet can access its contents. Major data breaches caused by public S3 buckets include:
- Capital One (2019): 100 million customer records exposed
- US Department of Defense: 1.8 billion social media posts exposed  
- Twitch (2021): Entire source code leaked via misconfigured storage

AWS provides four security flags to control public access on S3 buckets:
- **BlockPublicAcls**: Prevents new public ACLs from being applied
- **IgnorePublicAcls**: Ignores any existing public ACLs
- **BlockPublicPolicy**: Prevents new public bucket policies
- **RestrictPublicBuckets**: Restricts access to buckets with public policies

If any of these are set to False, the bucket could potentially be made public. Our CSPM tool detects this and automatically sets all four to True.

---

## 2. Serverless Computing

### What Is Serverless?

Serverless computing is a cloud execution model where the cloud provider (AWS, Azure, GCP) manages the server infrastructure entirely. You write code (functions), upload it, and the cloud runs it only when triggered. You pay only for the exact compute time used — no idle server costs.

### AWS Lambda

AWS Lambda is Amazon's serverless compute service. Key concepts:
- **Handler Function**: The entry point of your code (e.g., `lambda_handler(event, context)`)
- **Event**: The input data that triggers the function (JSON payload)
- **Context**: Runtime information (function name, memory, time remaining)
- **Cold Start**: The first invocation takes longer because AWS must initialize a container
- **Timeout**: Maximum execution time (default 3s, configurable up to 15 minutes)
- **Memory**: Configurable from 128 MB to 10 GB (CPU scales proportionally)

Lambda supports Python, Node.js, Java, Go, .NET, Ruby, and custom runtimes.

### How Lambda Works in This Project

We have two Lambda functions:

**Remediation Lambda** — Triggered by EventBridge when someone creates or modifies an S3 bucket. It:
1. Parses the CloudTrail event to extract the bucket name
2. Calls `s3.get_public_access_block()` to inspect the current config
3. If any flag is False, calls `s3.put_public_access_block()` to fix it
4. Logs the event to DynamoDB
5. Sends a Discord notification

**API Lambda** — Triggered by API Gateway when the dashboard makes an HTTP request. It:
1. Routes the request based on path (/events or /stats)
2. Scans DynamoDB for remediation records
3. Returns JSON with CORS headers

---

## 3. AWS Services Used

### Amazon S3 (Simple Storage Service)

S3 is object storage — you store files (objects) in containers (buckets). Key concepts:
- **Bucket**: A container with a globally unique name
- **Object**: A file stored in a bucket (identified by key/path)
- **Bucket Policy**: JSON policy controlling who can access the bucket
- **ACL (Access Control List)**: Legacy mechanism for controlling access
- **Public Access Block**: Account-level or bucket-level settings to prevent public access
- **Static Website Hosting**: S3 can serve HTML/CSS/JS as a website

In this project, S3 is used for:
- The target being monitored (S3 buckets created by users)
- Hosting the dashboard frontend as a static website

### AWS CloudTrail

CloudTrail is AWS's audit logging service. It records every API call made in your AWS account:
- Who made the call (IAM user/role)
- What API was called (e.g., `CreateBucket`, `PutBucketPublicAccessBlock`)
- When it happened (timestamp)
- Where (region, source IP)
- Request parameters and response

CloudTrail events are the foundation of our detection mechanism. Without CloudTrail, we wouldn't know when S3 changes happen.

### Amazon EventBridge

EventBridge (formerly CloudWatch Events) is a serverless event bus. It routes events from AWS services to targets (Lambda, SQS, SNS, etc.) based on pattern-matching rules.

Our EventBridge rule pattern:
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

This means: "Whenever CloudTrail sees a CreateBucket or PutBucketPublicAccessBlock API call, send the event to our Lambda."

### Amazon DynamoDB

DynamoDB is a serverless NoSQL database. Key concepts:
- **Table**: A collection of items (similar to a SQL table)
- **Item**: A record (similar to a row)
- **Partition Key (Hash Key)**: The primary identifier for each item
- **Sort Key (Range Key)**: Optional secondary key for ordering
- **Scan**: Read every item in the table (expensive, but fine for small tables)
- **Query**: Read items matching a specific partition key (efficient)
- **PAY_PER_REQUEST**: Billing mode where you pay per read/write (no provisioning)

Our DynamoDB table schema:
| Attribute | Type | Description |
|-----------|------|-------------|
| event_id | String (PK) | UUID for each remediation event |
| timestamp | String | ISO 8601 timestamp |
| bucket_name | String | Name of the affected S3 bucket |
| account_id | String | AWS account ID |
| region | String | AWS region |
| status | String | REMEDIATED, COMPLIANT, or REMEDIATION_FAILED |
| event_name | String | CloudTrail API event name |

### Amazon API Gateway

API Gateway is a managed service for creating REST/HTTP APIs. We use HTTP API (v2) which is simpler and cheaper than REST API (v1).

Our API routes:
- `GET /events` → Returns all remediation events from DynamoDB
- `GET /stats` → Returns aggregate statistics

API Gateway handles:
- CORS (Cross-Origin Resource Sharing) headers
- Request routing to Lambda
- TLS/SSL termination

### AWS IAM (Identity and Access Management)

IAM controls who can do what in AWS. Key concepts:
- **User**: A person or application with credentials
- **Role**: A set of permissions that can be assumed by services
- **Policy**: A JSON document defining allowed/denied actions
- **Principle of Least Privilege**: Grant only the minimum permissions needed

Our IAM design follows least privilege:

**Remediation Lambda Role** — can only:
- `s3:GetBucketPublicAccessBlock` (inspect buckets)
- `s3:PutBucketPublicAccessBlock` (fix buckets)
- `dynamodb:PutItem` on our specific table (log events)
- `logs:CreateLogGroup/Stream, PutLogEvents` (write its own logs)

**API Lambda Role** — can only:
- `dynamodb:Scan, Query, GetItem` on our specific table (read events)
- `logs:CreateLogGroup/Stream, PutLogEvents` (write its own logs)

Notice: The remediation Lambda cannot read DynamoDB, and the API Lambda cannot modify S3. This is intentional — if either is compromised, the blast radius is minimized.

---

## 4. Python and boto3

### What Is boto3?

boto3 is the official AWS SDK for Python. It allows Python code to interact with AWS services programmatically. Every AWS service has a corresponding boto3 client.

Key boto3 concepts:
- **Client**: Low-level interface that maps 1:1 to AWS API calls
- **Resource**: Higher-level, object-oriented interface (not available for all services)
- **Session**: Manages credentials and configuration
- **Paginator**: Handles multi-page API responses automatically
- **Waiter**: Polls a resource until it reaches a desired state

### Exception Handling with boto3

AWS API calls can fail. boto3 raises `ClientError` exceptions with error codes:
```python
from botocore.exceptions import ClientError

try:
    s3_client.get_public_access_block(Bucket="my-bucket")
except ClientError as exc:
    error_code = exc.response["Error"]["Code"]
    if error_code == "NoSuchBucket":
        # Bucket was deleted
    elif error_code == "NoSuchPublicAccessConfiguration":
        # No config exists — treat as fully open
    elif error_code == "AccessDenied":
        # Insufficient permissions
```

Our code handles these specific cases:
- **NoSuchBucket**: The bucket was deleted between the event firing and our Lambda running
- **NoSuchPublicAccessConfiguration**: The bucket has no public access block at all (most dangerous — fully open)
- **AccessDenied**: The Lambda role lacks permissions for that specific bucket

---

## 5. Discord Webhooks

A Discord webhook is a URL that accepts POST requests and posts messages to a Discord channel. It's a simple way to send notifications without building a bot.

### Webhook Payload Format

```json
{
  "embeds": [{
    "title": "🛡️ CSPM — S3 Public Access Remediation",
    "color": 3066993,
    "fields": [
      {"name": "🪣 Bucket Name", "value": "`my-bucket`", "inline": true},
      {"name": "🏢 Account ID", "value": "`123456789012`", "inline": true},
      {"name": "🌎 Region", "value": "`us-east-1`", "inline": true},
      {"name": "📋 Status", "value": "**REMEDIATED**", "inline": false}
    ],
    "timestamp": "2026-02-28T00:00:00Z"
  }]
}
```

The `color` field is a decimal integer representing the embed sidebar color:
- Green (REMEDIATED): `0x2ECC71` = `3066993`
- Red (FAILED): `0xE74C3C` = `15158332`

We use `urllib3` (pre-installed in Lambda) instead of the `requests` library to avoid adding external dependencies.

---

## 6. Infrastructure as Code (Terraform)

### What Is Terraform?

Terraform by HashiCorp is an Infrastructure as Code (IaC) tool. Instead of manually creating cloud resources through a web console, you write declarative configuration files that describe your desired infrastructure, and Terraform creates/updates/deletes resources to match.

### Key Terraform Concepts

- **Provider**: A plugin that interfaces with a cloud platform (AWS, Azure, GCP)
- **Resource**: A single infrastructure object (e.g., `aws_lambda_function`, `aws_dynamodb_table`)
- **Data Source**: Reads existing infrastructure without managing it (e.g., `data.aws_caller_identity`)
- **Variable**: Input parameters for your configuration
- **Output**: Values exported after deployment (URLs, ARNs, etc.)
- **State**: Terraform tracks what it has created in a state file (`terraform.tfstate`)
- **Plan**: Preview what Terraform will create/change/destroy
- **Apply**: Execute the changes
- **Destroy**: Delete all managed resources

### Terraform Workflow

```bash
terraform init      # Download provider plugins
terraform plan      # Preview changes (dry run)
terraform apply     # Create/update resources
terraform destroy   # Delete everything
```

### HCL (HashiCorp Configuration Language)

Terraform uses HCL, a declarative language:
```hcl
resource "aws_lambda_function" "remediation" {
  function_name = "cspm-remediation"
  runtime       = "python3.12"
  handler       = "lambda_function.lambda_handler"
  role          = aws_iam_role.remediation_role.arn
  
  environment {
    variables = {
      DISCORD_WEBHOOK_URL = var.discord_webhook_url
    }
  }
}
```

The pattern is `resource "TYPE" "LOCAL_NAME" { ... }`. You reference other resources using `TYPE.LOCAL_NAME.attribute`.

---

## 7. The Dashboard (Frontend)

### Architecture

The dashboard is a single-page application (SPA) — one HTML file with CSS and JavaScript. No framework (React, Vue, etc.) — pure vanilla JS for simplicity.

### How It Works

1. Browser loads `index.html` from S3 static website
2. `app.js` calls `GET /events` and `GET /stats` on the API Gateway
3. JavaScript renders the data into the DOM (stats cards + event table)
4. Every 30 seconds, it polls the API again for updates
5. Filter buttons (All / Remediated / Compliant / Failed) filter the table client-side

### Design Choices

- **Dark theme**: Common in security tools (SOC dashboards, SIEM interfaces)
- **Glassmorphism**: Semi-transparent cards with backdrop blur for depth
- **Monospace fonts**: Used for technical data (bucket names, account IDs, timestamps)
- **CSS animations**: Row slide-in, number count-up, pulsing status dot
- **Mock data**: When no API is configured, generates fake data for demo purposes

### Security Considerations

- **XSS Prevention**: All user-generated content is escaped via `textContent` (not `innerHTML`)
- **CORS**: API Gateway allows only GET and OPTIONS methods
- **No credentials in frontend**: The API is public — security is enforced at the IAM level

---

## 8. Security Concepts

### Defense in Depth

This project demonstrates multiple layers of security:
1. **Prevention**: S3 public access block flags prevent public exposure
2. **Detection**: CloudTrail + EventBridge detect configuration changes
3. **Response**: Lambda automatically remediates misconfigurations
4. **Notification**: Discord alerts inform the security team
5. **Audit**: DynamoDB maintains a complete event history
6. **Monitoring**: Dashboard provides continuous visibility

### Principle of Least Privilege

Every component has only the permissions it needs:
- Remediation Lambda: Can fix S3, write to DynamoDB, write logs
- API Lambda: Can read DynamoDB, write logs
- Dashboard bucket: Public read only (it's a website, not sensitive data)

### Event-Driven Security

Instead of periodically scanning all buckets (polling), we react to events in real-time:
- **Polling**: "Check every 5 minutes" → wasteful, delayed detection
- **Event-driven**: "React immediately when something changes" → instant, efficient

---

## 9. Key Topics to Study Deeper

1. **AWS Lambda execution model** — cold starts, concurrency, layers, VPC integration
2. **IAM policy language** — Effect, Action, Resource, Condition
3. **EventBridge event patterns** — content filtering, input transformation
4. **DynamoDB data modeling** — partition keys, GSIs, single-table design
5. **API Gateway** — stages, authorizers, throttling, custom domains
6. **Terraform state management** — remote backends, workspaces, modules
7. **S3 security** — bucket policies vs ACLs, encryption, versioning, access points
8. **CloudTrail** — management events vs data events, multi-region trails
9. **CSPM frameworks** — CIS Benchmarks, AWS Well-Architected Framework, SOC 2
10. **Incident response** — automated remediation vs manual approval workflows

---

## 10. Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        AWS Account                               │
│                                                                   │
│  ┌──────────┐    ┌─────────────┐    ┌──────────────────────┐    │
│  │ CloudTrail│───→│ EventBridge │───→│ Remediation Lambda   │    │
│  │  (audit)  │    │   (router)  │    │  ┌────────────────┐  │    │
│  └──────────┘    └─────────────┘    │  │ inspect_bucket │  │    │
│                                      │  │ remediate      │  │    │
│  ┌──────────┐                        │  │ log_to_dynamo  │  │    │
│  │ S3 Bucket│←── fixes ─────────────│  │ notify_discord │  │    │
│  │ (target) │                        │  └────────────────┘  │    │
│  └──────────┘                        └──────────┬───────────┘    │
│                                           │           │           │
│                                     ┌─────▼────┐  ┌──▼────────┐ │
│                                     │ DynamoDB  │  │  Discord   │ │
│                                     │ (events)  │  │ (webhook)  │ │
│                                     └─────┬────┘  └───────────┘ │
│                                           │                       │
│  ┌──────────────┐    ┌──────────┐   ┌────▼──────┐               │
│  │ S3 Website   │───→│ API GW   │──→│ API Lambda│               │
│  │ (dashboard)  │    │ (HTTP)   │   │ (read DB) │               │
│  └──────────────┘    └──────────┘   └───────────┘               │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```
