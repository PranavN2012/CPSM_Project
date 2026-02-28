"""
deploy-lambdas.py — Deploy/Update Lambda Functions on LocalStack
================================================================
Packages and deploys all Lambda code directly to LocalStack using boto3.
No Terraform needed.

Usage: python scripts/deploy-lambdas.py
"""

import json
import os
import io
import zipfile
import boto3

LOCALSTACK_ENDPOINT = "http://localhost:4566"
REGION = "us-east-1"
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Credentials
DISCORD_WEBHOOK = os.environ.get("DISCORD_WEBHOOK_URL", "")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITHUB_REPO = "PranavN2012/CPSM_Project"

kw = dict(
    endpoint_url=LOCALSTACK_ENDPOINT,
    region_name=REGION,
    aws_access_key_id="test",
    aws_secret_access_key="test",
)

lambda_client = boto3.client("lambda", **kw)
iam_client = boto3.client("iam", **kw)
dynamodb = boto3.client("dynamodb", **kw)
s3_client = boto3.client("s3", **kw)


def create_zip(files_map: dict) -> bytes:
    """Create an in-memory ZIP from a dict of {archive_path: local_path}."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for archive_name, local_path in files_map.items():
            zf.write(local_path, archive_name)
    return buf.getvalue()


def ensure_role() -> str:
    """Create or get a dummy IAM role for Lambda on LocalStack."""
    role_name = "cspm-lambda-role"
    try:
        resp = iam_client.get_role(RoleName=role_name)
        return resp["Role"]["Arn"]
    except Exception:
        pass

    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }]
    })
    resp = iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
    )
    # Attach full access (LocalStack doesn't enforce this)
    iam_client.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
    )
    return resp["Role"]["Arn"]


def ensure_dynamodb_table():
    """Create the DynamoDB table if it doesn't exist."""
    table_name = "cspm-remediation-events"
    try:
        dynamodb.describe_table(TableName=table_name)
        print(f"  ✅ DynamoDB table '{table_name}' exists.")
        return
    except Exception:
        pass

    dynamodb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "event_id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "event_id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    print(f"  ✅ Created DynamoDB table '{table_name}'.")


def deploy_lambda(name, handler, files_map, env_vars, role_arn):
    """Create or update a Lambda function."""
    zip_bytes = create_zip(files_map)

    try:
        lambda_client.get_function(FunctionName=name)
        # Update existing
        lambda_client.update_function_code(
            FunctionName=name,
            ZipFile=zip_bytes,
        )
        lambda_client.update_function_configuration(
            FunctionName=name,
            Handler=handler,
            Runtime="python3.11",
            Environment={"Variables": env_vars},
        )
        print(f"  ✅ Updated Lambda: {name}")
    except lambda_client.exceptions.ResourceNotFoundException:
        # Create new
        lambda_client.create_function(
            FunctionName=name,
            Runtime="python3.11",
            Role=role_arn,
            Handler=handler,
            Code={"ZipFile": zip_bytes},
            Environment={"Variables": env_vars},
            Timeout=60,
            MemorySize=256,
        )
        print(f"  ✅ Created Lambda: {name}")
    except Exception as exc:
        # Fallback: try create
        try:
            lambda_client.create_function(
                FunctionName=name,
                Runtime="python3.11",
                Role=role_arn,
                Handler=handler,
                Code={"ZipFile": zip_bytes},
                Environment={"Variables": env_vars},
                Timeout=60,
                MemorySize=256,
            )
            print(f"  ✅ Created Lambda: {name}")
        except Exception as exc2:
            print(f"  ❌ Failed to deploy {name}: {exc2}")


def main():
    print()
    print("=" * 60)
    print("  🚀 CSPM Lambda Deployment to LocalStack")
    print("=" * 60)
    print()

    # Shared env vars
    env = {
        "DYNAMODB_TABLE_NAME": "cspm-remediation-events",
        "DISCORD_WEBHOOK_URL": DISCORD_WEBHOOK,
        "GITHUB_TOKEN": GITHUB_TOKEN,
        "GITHUB_REPO": GITHUB_REPO,
    }

    # Ensure prerequisites
    print("[1/4] Creating IAM role ...")
    role_arn = ensure_role()

    print("[2/4] Ensuring DynamoDB table ...")
    ensure_dynamodb_table()

    # Shared module path
    shared_path = os.path.join(PROJECT_DIR, "lambda", "shared", "github_notifier.py")

    # --- Remediation Lambda ---
    print("[3/4] Deploying Remediation Lambda ...")
    remediation_files = {
        "lambda_function.py": os.path.join(PROJECT_DIR, "lambda", "remediation", "lambda_function.py"),
        "shared/github_notifier.py": shared_path,
    }
    deploy_lambda(
        name="cspm-s3-remediation-remediation",
        handler="lambda_function.lambda_handler",
        files_map=remediation_files,
        env_vars=env,
        role_arn=role_arn,
    )

    # --- API Lambda ---
    print("[3/4] Deploying API Lambda ...")
    api_files = {
        "lambda_function.py": os.path.join(PROJECT_DIR, "lambda", "api", "lambda_function.py"),
    }
    deploy_lambda(
        name="cspm-s3-remediation-api",
        handler="lambda_function.lambda_handler",
        files_map=api_files,
        env_vars=env,
        role_arn=role_arn,
    )

    # --- IAM Audit Lambda ---
    print("[4/4] Deploying IAM Audit Lambda ...")
    iam_files = {
        "lambda_function.py": os.path.join(PROJECT_DIR, "lambda", "iam-audit", "lambda_function.py"),
        "shared/github_notifier.py": shared_path,
    }
    deploy_lambda(
        name="cspm-s3-remediation-iam-audit",
        handler="lambda_function.lambda_handler",
        files_map=iam_files,
        env_vars=env,
        role_arn=role_arn,
    )

    print()
    print("=" * 60)
    print("  ✅ All Lambdas deployed!")
    print("  Next: python scripts/simulate-attacks.py")
    print("=" * 60)
    print()


if __name__ == "__main__":
    main()
