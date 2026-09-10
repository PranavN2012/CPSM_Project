"""
simulate-attacks.py — Multi-Vulnerability Attack Simulator
==========================================================
Generates real security events for all 3 vulnerability types:
  1. S3 Public Access misconfigurations
  2. S3 Unencrypted buckets
  3. IAM overpermissive policies

Usage:
    python scripts/simulate-attacks.py
        Runs the full fixed demo sequence (all phases, as before).

    python scripts/simulate-attacks.py --type {s3_public,s3_encrypt,iam,sg,dynamodb}
                                        [--target NAME] [--account ID] [--region REGION]
        Runs exactly one targeted attack and exits — lets a second actor (a
        teammate, a script, a red-team exercise) trigger a specific attack
        against a running dashboard instead of only replaying the fixed
        sequence. --account/--region are threaded into the synthetic
        CloudTrail event's account/region fields (LocalStack is a single
        real account, so this doesn't create real multi-account isolation —
        it only changes what the event *reports*, same as the fixed-sequence
        attacks already do via random.choice(ACCOUNTS)/REGIONS).
"""

import argparse
import json
import time
import uuid
import random
import os
import sys
import boto3
import urllib.request

# A legacy Windows console/pipe code page (cp1252) can't encode the emoji
# this script prints throughout (🪣, 🔓, etc.) — reconfigure stdout to UTF-8
# with a safe fallback so a print() never crashes a request. Found for real:
# invoking run_targeted_attack() from local-api-server.py's /simulate route
# (a non-interactive, possibly-redirected stdout) raised
# UnicodeEncodeError on the very first print() before this fix.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# Add shared modules to path for policy auto-generation
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.normpath(os.path.join(SCRIPT_DIR, ".."))
sys.path.insert(0, os.path.join(PROJECT_DIR, "lambda", "shared"))

try:
    from policy_generator import auto_generate_policy
    _HAS_POLICY_GENERATOR = True
except ImportError:
    _HAS_POLICY_GENERATOR = False

try:
    from providers import get_provider
    _HAS_PROVIDERS = True
except ImportError:
    _HAS_PROVIDERS = False

try:
    from nlg_engine import generate_incident_summary
    _HAS_NLG = True
except ImportError:
    def generate_incident_summary(**kwargs):
        return ""
    _HAS_NLG = False

LOCALSTACK_ENDPOINT = "http://localhost:4566"
REGION = "us-east-1"
REMEDIATION_LAMBDA = "cspm-s3-remediation-remediation"
IAM_AUDIT_LAMBDA = "cspm-s3-remediation-iam-audit"

# Discord and GitHub config — passed to Lambda via environment
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITHUB_REPO = os.environ.get("GITHUB_REPO", "PranavN2012/CPSM_Project")

kw = dict(
    endpoint_url=LOCALSTACK_ENDPOINT,
    region_name=REGION,
    aws_access_key_id="test",
    aws_secret_access_key="test",
)

s3_client = boto3.client("s3", **kw)
iam_client = boto3.client("iam", **kw)
ec2_client = boto3.client("ec2", **kw)
dynamodb_client = boto3.client("dynamodb", **kw)
dynamodb_resource = boto3.resource("dynamodb", **kw)
lambda_client = boto3.client("lambda", **kw)

BUCKET_NAMES = [
    "prod-data-lake-raw", "staging-logs-2026", "dev-user-uploads",
    "analytics-exports", "ml-training-datasets", "backup-vault",
    "cdn-static-assets", "customer-reports-q1",
]

REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]
ACCOUNTS = ["123456789012", "987654321098", "111222333444"]

auto_generated_policies = []

def check_and_auto_generate_policy(event_type, provider="aws", service="", resource_id="", detail=""):
    """Check if a policy exists for this event type. If not, auto-generate one."""
    if not _HAS_POLICY_GENERATOR:
        return None
    event = {
        "event_type": event_type,
        "provider": provider,
        "service": service,
        "resource_id": resource_id,
        "source": service,
        "detail": detail,
    }
    policy = auto_generate_policy(event)
    if policy:
        auto_generated_policies.append(policy)
        print(f"  \U0001f9e0 Auto-generated policy: {policy['id']} (Pending Review)")
    return policy


def update_lambda_env(func_name, extra_env):
    """Update a Lambda's environment variables."""
    try:
        config = lambda_client.get_function_configuration(FunctionName=func_name)
        env = config.get("Environment", {}).get("Variables", {})
        env.update(extra_env)
        lambda_client.update_function_configuration(
            FunctionName=func_name,
            Environment={"Variables": env},
        )
    except Exception as exc:
        print(f"  ⚠️  Could not update {func_name} env: {exc}")


def simulate_public_access_attack(bucket_name, account=None, region=None):
    """Create a bucket with public access disabled → trigger remediation."""
    print(f"  🪣 Creating bucket: {bucket_name}")
    try:
        s3_client.create_bucket(Bucket=bucket_name)
    except Exception:
        pass

    print(f"  🔓 Opening public access ...")
    s3_client.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": False, "IgnorePublicAcls": False,
            "BlockPublicPolicy": False, "RestrictPublicBuckets": False,
        },
    )

    event = {
        "version": "0", "id": str(uuid.uuid4()), "source": "aws.s3",
        "account": account or random.choice(ACCOUNTS), "region": region or random.choice(REGIONS),
        "detail-type": "AWS API Call via CloudTrail",
        "detail": {
            "eventSource": "s3.amazonaws.com",
            "eventName": random.choice(["CreateBucket", "PutBucketPublicAccessBlock"]),
            "recipientAccountId": account or random.choice(ACCOUNTS),
            "awsRegion": region or random.choice(REGIONS),
            "requestParameters": {"bucketName": bucket_name},
        },
    }

    print(f"  🛡️  Invoking remediation Lambda ...")
    resp = lambda_client.invoke(FunctionName=REMEDIATION_LAMBDA, Payload=json.dumps(event))
    payload = json.loads(resp["Payload"].read())
    body = json.loads(payload.get("body", "{}"))
    print(f"  ✅ Result: {body.get('status', body.get('checks', 'unknown'))}")
    return bucket_name


def simulate_iam_attack(username=None):
    """Create an IAM user with wildcard policy → trigger IAM audit."""
    username = username or f"dev-intern-{uuid.uuid4().hex[:4]}"
    print(f"  👤 Creating overpermissive IAM user: {username}")

    try:
        iam_client.create_user(UserName=username)
    except Exception:
        pass

    policy_doc = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*",
        }],
    })

    try:
        iam_client.put_user_policy(
            UserName=username,
            PolicyName="FullAdminAccess",
            PolicyDocument=policy_doc,
        )
    except Exception as exc:
        print(f"  ⚠️  Could not attach policy: {exc}")

    print(f"  🔍 Running IAM audit scan ...")
    try:
        event = {"account": "123456789012", "region": "us-east-1"}
        resp = lambda_client.invoke(FunctionName=IAM_AUDIT_LAMBDA, Payload=json.dumps(event))
        payload = json.loads(resp["Payload"].read())
        body = json.loads(payload.get("body", "{}"))
        print(f"  ✅ IAM findings: {body.get('findings_count', 0)}")
    except Exception as exc:
        print(f"  ⚠️  IAM audit Lambda failed: {exc}")

    return username


def simulate_security_group_attack(sg_name=None, account=None):
    """Create a security group with open SSH."""
    sg_name = sg_name or f"dev-ssh-{uuid.uuid4().hex[:4]}"
    print(f"  🔒 Creating vulnerable Security Group: {sg_name}")
    
    try:
        vpc_response = ec2_client.describe_vpcs()
        vpcs = vpc_response.get('Vpcs', [])
        if not vpcs:
            vpc = ec2_client.create_vpc(CidrBlock='10.0.0.0/16')
            vpc_id = vpc['Vpc']['VpcId']
        else:
            vpc_id = vpcs[0]['VpcId']

        sg_response = ec2_client.create_security_group(
            GroupName=sg_name, Description='Vulnerable SG', VpcId=vpc_id)
        sg_id = sg_response['GroupId']
        ec2_client.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            }]
        )
    except Exception as exc:
        print(f"  ⚠️  Failed to create SG: {exc}")
        return None

    event = {
        "version": "0", "id": str(uuid.uuid4()), "source": "aws.ec2",
        "account": account or random.choice(ACCOUNTS), "region": "us-east-1",
        "detail-type": "AWS API Call via CloudTrail",
        "detail": {
            "eventSource": "ec2.amazonaws.com",
            "eventName": "AuthorizeSecurityGroupIngress",
            "recipientAccountId": account or random.choice(ACCOUNTS),
            "awsRegion": "us-east-1",
            "requestParameters": {"groupId": sg_id},
        },
    }

    print(f"  🛡️  Invoking remediation Lambda ...")
    resp = lambda_client.invoke(FunctionName=REMEDIATION_LAMBDA, Payload=json.dumps(event))
    payload = json.loads(resp["Payload"].read())
    body = json.loads(payload.get("body", "{}"))
    print(f"  ✅ Result: {body.get('status', 'unknown')}")
    return sg_id


def simulate_dynamodb_attack(table_name=None, account=None):
    """Create an unencrypted DynamoDB table."""
    table_name = table_name or f"user-sessions-{uuid.uuid4().hex[:4]}"
    print(f"  🗄️ Creating unencrypted DynamoDB table: {table_name}")
    
    try:
        dynamodb_client.create_table(
            TableName=table_name,
            KeySchema=[{'AttributeName': 'id', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'id', 'AttributeType': 'S'}],
            BillingMode='PAY_PER_REQUEST'
        )
    except Exception as exc:
        print(f"  ⚠️  Failed to create DDB table: {exc}")
        return None

    event = {
        "version": "0", "id": str(uuid.uuid4()), "source": "aws.dynamodb",
        "account": account or random.choice(ACCOUNTS), "region": "us-east-1",
        "detail-type": "AWS API Call via CloudTrail",
        "detail": {
            "eventSource": "dynamodb.amazonaws.com",
            "eventName": "CreateTable",
            "recipientAccountId": account or random.choice(ACCOUNTS),
            "awsRegion": "us-east-1",
            "requestParameters": {"tableName": table_name},
        },
    }

    print(f"  🛡️  Invoking remediation Lambda ...")
    resp = lambda_client.invoke(FunctionName=REMEDIATION_LAMBDA, Payload=json.dumps(event))
    payload = json.loads(resp["Payload"].read())
    body = json.loads(payload.get("body", "{}"))
    print(f"  ✅ Result: {body.get('status', 'unknown')}")
    return table_name



TARGETED_ATTACK_TYPES = ("s3_public", "s3_encrypt", "iam", "sg", "dynamodb")


def run_targeted_attack(attack_type: str, target: str = None, account: str = None, region: str = None) -> dict:
    """Single, parameterized attack — the shared implementation behind both
    the --type/--target CLI flags and local-api-server.py's POST /simulate
    route. Distinct from main()'s fixed demo sequence: this lets a second
    actor (a teammate, a script, a red-team exercise) trigger one specific
    attack against a running dashboard on demand, rather than only replaying
    the same canned sequence every time."""
    if attack_type not in TARGETED_ATTACK_TYPES:
        raise ValueError(f"Unknown attack type {attack_type!r}, expected one of {TARGETED_ATTACK_TYPES}")

    if attack_type == "s3_public":
        name = target or f"{random.choice(BUCKET_NAMES)}-{uuid.uuid4().hex[:6]}"
        resource = simulate_public_access_attack(name, account=account, region=region)
    elif attack_type == "s3_encrypt":
        name = target or f"unencrypted-{random.choice(BUCKET_NAMES)}-{uuid.uuid4().hex[:6]}"
        resource = simulate_public_access_attack(name, account=account, region=region)
    elif attack_type == "iam":
        resource = simulate_iam_attack(username=target)
    elif attack_type == "sg":
        resource = simulate_security_group_attack(sg_name=target, account=account)
    else:  # dynamodb
        resource = simulate_dynamodb_attack(table_name=target, account=account)

    return {"type": attack_type, "resource": resource, "account": account, "region": region or REGION}


def _parse_args():
    parser = argparse.ArgumentParser(description="CSPM attack simulator")
    parser.add_argument("--type", choices=TARGETED_ATTACK_TYPES,
                         help="Run exactly one targeted attack instead of the full demo sequence.")
    parser.add_argument("--target", help="Resource name (bucket/user/SG/table). Random if omitted.")
    parser.add_argument("--account", help="Account ID reported in the synthetic CloudTrail event.")
    parser.add_argument("--region", help="Region reported in the synthetic CloudTrail event.")
    return parser.parse_args()


def cleanup(buckets, users, sgs, tables):
    """Clean up test resources."""
    print("\nCleaning up ...")
    for b in buckets:
        try: s3_client.delete_bucket(Bucket=b)
        except Exception: pass
    for u in users:
        try:
            iam_client.delete_user_policy(UserName=u, PolicyName="FullAdminAccess")
            iam_client.delete_user(UserName=u)
        except Exception: pass
    for s in sgs:
        if s:
            try: ec2_client.delete_security_group(GroupId=s)
            except Exception: pass
    for t in tables:
        if t:
            try: dynamodb_client.delete_table(TableName=t)
            except Exception: pass
    print("Done.\n")


# ---------------------------------------------------------------------------
# Direct GitHub Issue Creator (runs on host machine, bypasses LocalStack)
# ---------------------------------------------------------------------------

SEVERITY_EMOJI = {"CRITICAL": "\U0001f534", "HIGH": "\U0001f7e0", "MEDIUM": "\U0001f7e1", "LOW": "\U0001f7e2"}

def create_github_issues_from_events():
    """Read events from DynamoDB and create GitHub Issues directly."""
    if not GITHUB_TOKEN or not GITHUB_REPO:
        print("  \u26a0\ufe0f  GITHUB_TOKEN or GITHUB_REPO not set \u2014 skipping GitHub Issues.")
        return 0

    table = dynamodb_resource.Table("cspm-remediation-events")
    response = table.scan()
    events = response.get("Items", [])

    if not events:
        print("  \u26a0\ufe0f  No events found in DynamoDB.")
        return 0

    # Only create issues for non-COMPLIANT events
    actionable = [e for e in events if e.get("status") not in ("COMPLIANT",)]

    created = 0
    for e in actionable:
        vuln = e.get("vulnerability_type", "Unknown")
        resource = e.get("bucket_name", "unknown")
        status = e.get("status", "UNKNOWN")
        severity = e.get("severity", "HIGH")
        account = e.get("account_id", "000000000000")
        region = e.get("region", "us-east-1")
        nlp_summary = e.get("nlp_summary", "")

        emoji = SEVERITY_EMOJI.get(severity, "\u26aa")
        status_emoji = "\u2705" if "REMEDIATED" in status else "\u274c" if "FAILED" in status else "\u2139\ufe0f"

        title = f"{emoji} {vuln}: {resource} [{status}]"
        body = f"""## {emoji} {vuln} \u2014 Severity: {severity}

| Field | Value |
|-------|-------|
| **Resource** | `{resource}` |
| **Account** | `{account}` |
| **Region** | `{region}` |
| **Status** | {status_emoji} **{status}** |
| **Severity** | {emoji} {severity} |

### \U0001f9e0 AI Incident Summary (NLG Engine v2)
{nlp_summary or 'Detected and processed by CSPM automated pipeline.'}

---
*Auto-generated by Serverless CSPM \u2022 NLG Engine v2 \u2022 Automated Security Posture Management*
"""
        labels = ["cspm", "security"]
        if "REMEDIATED" in status:
            labels.append("auto-remediated")
        else:
            labels.append("needs-attention")

        payload = json.dumps({"title": title, "body": body, "labels": labels}).encode("utf-8")
        url = f"https://api.github.com/repos/{GITHUB_REPO}/issues"

        try:
            req = urllib.request.Request(url, data=payload, method="POST", headers={
                "Content-Type": "application/json",
                "Authorization": f"token {GITHUB_TOKEN}",
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "CSPM-Bot",
            })
            resp = urllib.request.urlopen(req)
            data = json.loads(resp.read())
            print(f"    \u2705 Issue #{data.get('number')}: {vuln} \u2014 {resource}")
            created += 1
        except Exception as exc:
            print(f"    \u274c Failed to create issue for {resource}: {exc}")

    return created


def main():
    print()
    print("=" * 60)
    print("  \U0001f6e1\ufe0f  CSPM Multi-Vulnerability Attack Simulator")
    print("=" * 60)
    print()

    # Update Lambda env with Discord + GitHub creds
    env_vars = {"DISCORD_WEBHOOK_URL": DISCORD_WEBHOOK_URL}
    if GITHUB_TOKEN:
        env_vars["GITHUB_TOKEN"] = GITHUB_TOKEN
    if GITHUB_REPO:
        env_vars["GITHUB_REPO"] = GITHUB_REPO

    print("[Setup] Configuring Lambda environment variables ...")
    update_lambda_env(REMEDIATION_LAMBDA, env_vars)
    try:
        update_lambda_env(IAM_AUDIT_LAMBDA, env_vars)
    except Exception:
        print("  \u26a0\ufe0f  IAM audit Lambda not deployed yet \u2014 skipping env update.")
    print()

    buckets = []
    users = []
    sgs = []
    tables = []

    # Phase 1: S3 Public Access attacks (3 buckets)
    print("\u2501" * 60)
    print("  Phase 1: S3 Public Access Attacks")
    print("\u2501" * 60)
    for i in range(3):
        name = f"{BUCKET_NAMES[i]}-{uuid.uuid4().hex[:6]}"
        print(f"\n[{i+1}/3] Simulating S3 public access attack:")
        buckets.append(simulate_public_access_attack(name))
        time.sleep(1.5)

    # Phase 2: S3 Encryption (the remediation Lambda now checks this too)
    print()
    print("\u2501" * 60)
    print("  Phase 2: S3 Encryption Attacks (checked by remediation)")
    print("\u2501" * 60)
    for i in range(2):
        name = f"unencrypted-{BUCKET_NAMES[3+i]}-{uuid.uuid4().hex[:6]}"
        print(f"\n[{i+1}/2] Creating unencrypted bucket:")
        buckets.append(simulate_public_access_attack(name))
        time.sleep(1.5)

    # Phase 3: IAM Audit
    print()
    print("\u2501" * 60)
    print("  Phase 3: IAM Overpermissive Policy Attack")
    print("\u2501" * 60)
    print(f"\n[1/1] Simulating IAM attack:")
    users.append(simulate_iam_attack())

    # Phase 4: NEW - Security Group & DynamoDB
    print()
    print("\u2501" * 60)
    print("  Phase 4: Expanding Coverage (SG & DynamoDB)")
    print("\u2501" * 60)
    print(f"\n[1/2] Simulating Open Security Group:")
    sgs.append(simulate_security_group_attack())
    check_and_auto_generate_policy("sg_open", service="ec2", detail="security group open ports")
    time.sleep(1.5)
    
    print(f"\n[2/2] Simulating Unencrypted DynamoDB Table:")
    tables.append(simulate_dynamodb_attack())
    check_and_auto_generate_policy("dynamodb_encrypt", service="dynamodb", detail="dynamodb encryption")

    # Phase 5: Novel/Unknown Attack Types (triggers auto-policy generation)
    print()
    print("\u2501" * 60)
    print("  Phase 5: Novel Attack Types (Auto-Policy Generation)")
    print("\u2501" * 60)

    novel_attacks = [
        {"type": "rds_public", "service": "rds", "resource": f"db-prod-{uuid.uuid4().hex[:4]}",
         "detail": "RDS instance publicly accessible", "desc": "RDS Public Exposure"},
        {"type": "lambda_public", "service": "lambda", "resource": f"fn-api-{uuid.uuid4().hex[:4]}",
         "detail": "Lambda function URL public access", "desc": "Lambda Public URL"},
        {"type": "ebs_encryption", "service": "ec2", "resource": f"vol-{uuid.uuid4().hex[:8]}",
         "detail": "EBS volume unencrypted", "desc": "EBS Unencrypted Volume"},
    ]

    for idx, attack in enumerate(novel_attacks, 1):
        print(f"\n[{idx}/{len(novel_attacks)}] Simulating {attack['desc']}:")
        print(f"  \U0001f50d Resource: {attack['resource']}")
        result = check_and_auto_generate_policy(
            attack["type"],
            service=attack["service"],
            resource_id=attack["resource"],
            detail=attack["detail"],
        )
        if not result:
            print(f"  \u2139\ufe0f  Policy already exists for {attack['type']}")
        time.sleep(0.5)

    # Phase 6: Azure Multi-Cloud Attacks
    azure_findings = []
    gcp_findings = []

    if _HAS_PROVIDERS:
        print()
        print("\u2501" * 60)
        print("  Phase 6: Azure Security Scan (Mock Data)")
        print("\u2501" * 60)

        try:
            azure = get_provider("azure")
            azure_checks = [
                ("check_storage_public_access", "devuploadstemp", "Blob Public Access"),
                ("check_storage_encryption", "devuploadstemp", "Storage Encryption"),
                ("check_network_open_ports", "nsg-web-tier", "NSG Open Ports"),
                ("check_iam_overpermissive", "all", "RBAC Overpermissive"),
            ]

            for idx, (check, resource, desc) in enumerate(azure_checks, 1):
                print(f"\n[{idx}/{len(azure_checks)}] Azure — {desc}:")
                method = getattr(azure, check)
                result = method(resource)
                status = result.get("status", "UNKNOWN")
                findings = result.get("findings", [])
                emoji = "\u274c" if status == "NON_COMPLIANT" else "\u2705"
                print(f"  {emoji} {status} — {len(findings)} finding(s)")
                for f in findings[:3]:
                    print(f"     \u2022 {f}")
                azure_findings.append(result)

                # Generate NLP summary for this finding
                resource_name = result.get("resource", resource)
                event_severity = "HIGH" if status == "NON_COMPLIANT" else "LOW"
                nlp_summary = ""
                try:
                    nlp_summary = generate_incident_summary(
                        resource_name=resource_name,
                        account_id="azure-subscription",
                        region="azure-global",
                        status=status,
                        event_name=f"Azure:{check}",
                        vulnerability_type=desc,
                        severity=event_severity,
                        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    )
                except Exception as nlg_exc:
                    print(f"     \u26a0\ufe0f  NLG generation failed: {nlg_exc}")

                # Write event to DynamoDB
                table = dynamodb_resource.Table("cspm-remediation-events")
                item = {
                    "event_id": str(uuid.uuid4()),
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "provider": "azure",
                    "vulnerability_type": desc,
                    "bucket_name": resource_name,
                    "account_id": "azure-subscription",
                    "region": "azure-global",
                    "status": status,
                    "severity": event_severity,
                    "findings": json.dumps(findings),
                    "service": result.get("service", "unknown"),
                }
                if nlp_summary:
                    item["nlp_summary"] = nlp_summary
                try:
                    table.put_item(Item=item)
                except Exception:
                    pass

                # Auto-remediate if non-compliant
                if status == "NON_COMPLIANT" and check in ("check_storage_public_access", "check_network_open_ports"):
                    print(f"  \U0001f6e1\ufe0f  Auto-remediating...")
                    rem = azure.remediate(check, resource)
                    print(f"  \u2705 {rem.get('status')}: {rem.get('action', '')}")
                    # Previously the console printed REMEDIATED here but the
                    # DynamoDB item stayed NON_COMPLIANT forever \u2014 compliance.py
                    # only counts status in (COMPLIANT, REMEDIATED,
                    # ENCRYPTION_REMEDIATED) as passing, so this finding never
                    # left the compliance score's FAIL bucket even though it
                    # was actually fixed. Overwrite the same event_id (the
                    # table's sole hash key) with the post-remediation status
                    # instead of leaving the pre-remediation write as final.
                    if rem.get("status") == "REMEDIATED":
                        item["status"] = "REMEDIATED"
                        item["severity"] = "LOW"
                        try:
                            table.put_item(Item=item)
                        except Exception:
                            pass

                time.sleep(0.5)
        except Exception as exc:
            print(f"  \u26a0\ufe0f  Azure scan failed: {exc}")

        # Phase 7: GCP Multi-Cloud Attacks
        print()
        print("\u2501" * 60)
        print("  Phase 7: GCP Security Scan (Mock Data)")
        print("\u2501" * 60)

        try:
            gcp = get_provider("gcp")
            gcp_checks = [
                ("check_storage_public_access", "dev-uploads-temp", "GCS Public Access"),
                ("check_storage_encryption", "dev-uploads-temp", "GCS Encryption (CMEK)"),
                ("check_network_open_ports", "all", "Firewall Open Ports"),
                ("check_iam_overpermissive", "all", "IAM Overpermissive"),
            ]

            for idx, (check, resource, desc) in enumerate(gcp_checks, 1):
                print(f"\n[{idx}/{len(gcp_checks)}] GCP — {desc}:")
                method = getattr(gcp, check)
                result = method(resource)
                status = result.get("status", "UNKNOWN")
                findings = result.get("findings", [])
                emoji = "\u274c" if status == "NON_COMPLIANT" else "\u2705"
                print(f"  {emoji} {status} — {len(findings)} finding(s)")
                for f in findings[:3]:
                    print(f"     \u2022 {f}")
                gcp_findings.append(result)

                # Generate NLP summary for this finding
                resource_name = result.get("resource", resource)
                event_severity = "HIGH" if status == "NON_COMPLIANT" else "LOW"
                nlp_summary = ""
                try:
                    nlp_summary = generate_incident_summary(
                        resource_name=resource_name,
                        account_id="gcp-project",
                        region="gcp-global",
                        status=status,
                        event_name=f"GCP:{check}",
                        vulnerability_type=desc,
                        severity=event_severity,
                        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    )
                except Exception as nlg_exc:
                    print(f"     \u26a0\ufe0f  NLG generation failed: {nlg_exc}")

                # Write event to DynamoDB
                table = dynamodb_resource.Table("cspm-remediation-events")
                item = {
                    "event_id": str(uuid.uuid4()),
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "provider": "gcp",
                    "vulnerability_type": desc,
                    "bucket_name": resource_name,
                    "account_id": "gcp-project",
                    "region": "gcp-global",
                    "status": status,
                    "severity": event_severity,
                    "findings": json.dumps(findings),
                    "service": result.get("service", "unknown"),
                }
                if nlp_summary:
                    item["nlp_summary"] = nlp_summary
                try:
                    table.put_item(Item=item)
                except Exception:
                    pass

                # Auto-remediate
                if status == "NON_COMPLIANT" and check in ("check_storage_public_access", "check_network_open_ports"):
                    print(f"  \U0001f6e1\ufe0f  Auto-remediating...")
                    rem = gcp.remediate(check, resource)
                    print(f"  \u2705 {rem.get('status')}: {rem.get('action', '')}")
                    # Same fix as the Azure block above: without this, the
                    # DynamoDB item stays NON_COMPLIANT forever even though
                    # it was actually remediated, permanently counting as a
                    # compliance FAIL. Overwrites the same event_id.
                    if rem.get("status") == "REMEDIATED":
                        item["status"] = "REMEDIATED"
                        item["severity"] = "LOW"
                        try:
                            table.put_item(Item=item)
                        except Exception:
                            pass

                time.sleep(0.5)
        except Exception as exc:
            print(f"  \u26a0\ufe0f  GCP scan failed: {exc}")
    else:
        print("\n  \u26a0\ufe0f  Multi-cloud providers not available — skipping Azure/GCP phases")

    # Phase 8: Create GitHub Issues directly (bypass LocalStack network)
    print()
    print("\u2501" * 60)
    print("  Phase 8: Creating GitHub Issues (Direct API)")
    print("\u2501" * 60)
    issue_count = create_github_issues_from_events()
    print(f"\n  \U0001f4dd Created {issue_count} GitHub Issues")

    print()
    print("=" * 60)
    print(f"  \u2705 Simulation Complete!")
    print(f"     \u2705 S3 buckets attacked: {len(buckets)}")
    print(f"     \u2705 IAM users flagged:   {len(users)}")
    print(f"     \u2705 Security groups:     {len([s for s in sgs if s])}")
    print(f"     \u2705 DynamoDB tables:     {len([t for t in tables if t])}")
    azure_nc = len([f for f in azure_findings if f.get('status') == 'NON_COMPLIANT'])
    gcp_nc = len([f for f in gcp_findings if f.get('status') == 'NON_COMPLIANT'])
    print(f"     \U0001f9e0 Auto-gen policies: {len(auto_generated_policies)}")
    print(f"     \U0001f535 Azure findings:   {azure_nc} non-compliant")
    print(f"     \U0001f7e0 GCP findings:     {gcp_nc} non-compliant")
    print(f"     \U0001f4dd GitHub Issues:      {issue_count}")
    print(f"     Open http://localhost:3001 to see the dashboard.")
    print("=" * 60)

    cleanup(buckets, users, sgs, tables)


if __name__ == "__main__":
    _args = _parse_args()
    if _args.type:
        _result = run_targeted_attack(_args.type, target=_args.target, account=_args.account, region=_args.region)
        print(json.dumps(_result, indent=2))
    else:
        main()
