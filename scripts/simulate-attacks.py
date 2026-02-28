"""
simulate-attacks.py — Multi-Vulnerability Attack Simulator
==========================================================
Generates real security events for all 3 vulnerability types:
  1. S3 Public Access misconfigurations
  2. S3 Unencrypted buckets
  3. IAM overpermissive policies

Usage: python scripts/simulate-attacks.py
"""

import json
import time
import uuid
import random
import os
import boto3

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
lambda_client = boto3.client("lambda", **kw)

BUCKET_NAMES = [
    "prod-data-lake-raw", "staging-logs-2026", "dev-user-uploads",
    "analytics-exports", "ml-training-datasets", "backup-vault",
    "cdn-static-assets", "customer-reports-q1",
]

REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]
ACCOUNTS = ["123456789012", "987654321098", "111222333444"]


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


def simulate_public_access_attack(bucket_name):
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
        "account": random.choice(ACCOUNTS), "region": random.choice(REGIONS),
        "detail-type": "AWS API Call via CloudTrail",
        "detail": {
            "eventSource": "s3.amazonaws.com",
            "eventName": random.choice(["CreateBucket", "PutBucketPublicAccessBlock"]),
            "recipientAccountId": random.choice(ACCOUNTS),
            "awsRegion": random.choice(REGIONS),
            "requestParameters": {"bucketName": bucket_name},
        },
    }

    print(f"  🛡️  Invoking remediation Lambda ...")
    resp = lambda_client.invoke(FunctionName=REMEDIATION_LAMBDA, Payload=json.dumps(event))
    payload = json.loads(resp["Payload"].read())
    body = json.loads(payload.get("body", "{}"))
    print(f"  ✅ Result: {body.get('status', body.get('checks', 'unknown'))}")
    return bucket_name


def simulate_iam_attack():
    """Create an IAM user with wildcard policy → trigger IAM audit."""
    username = f"dev-intern-{uuid.uuid4().hex[:4]}"
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


def cleanup(buckets, users):
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
    print("Done.\n")


def main():
    print()
    print("=" * 60)
    print("  🛡️  CSPM Multi-Vulnerability Attack Simulator")
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
        print("  ⚠️  IAM audit Lambda not deployed yet — skipping env update.")
    print()

    buckets = []
    users = []

    # Phase 1: S3 Public Access attacks (3 buckets)
    print("━" * 60)
    print("  Phase 1: S3 Public Access Attacks")
    print("━" * 60)
    for i in range(3):
        name = f"{BUCKET_NAMES[i]}-{uuid.uuid4().hex[:6]}"
        print(f"\n[{i+1}/3] Simulating S3 public access attack:")
        buckets.append(simulate_public_access_attack(name))
        time.sleep(1.5)

    # Phase 2: S3 Encryption (the remediation Lambda now checks this too)
    print()
    print("━" * 60)
    print("  Phase 2: S3 Encryption Attacks (checked by remediation)")
    print("━" * 60)
    for i in range(2):
        name = f"unencrypted-{BUCKET_NAMES[3+i]}-{uuid.uuid4().hex[:6]}"
        print(f"\n[{i+1}/2] Creating unencrypted bucket:")
        buckets.append(simulate_public_access_attack(name))
        time.sleep(1.5)

    # Phase 3: IAM Audit
    print()
    print("━" * 60)
    print("  Phase 3: IAM Overpermissive Policy Attack")
    print("━" * 60)
    print(f"\n[1/1] Simulating IAM attack:")
    users.append(simulate_iam_attack())

    print()
    print("=" * 60)
    print(f"  ✅ Simulation Complete!")
    print(f"     S3 buckets attacked: {len(buckets)}")
    print(f"     IAM users flagged:   {len(users)}")
    print(f"     Open http://localhost:3000 to see the dashboard.")
    print("=" * 60)

    cleanup(buckets, users)


if __name__ == "__main__":
    main()
