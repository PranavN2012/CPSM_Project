"""
AWS Provider — Amazon Web Services Security Checks
=====================================================

Implements CloudProvider interface using boto3.
Wraps the existing security check logic from the Lambda functions.
"""

import logging

try:
    import boto3
    from botocore.exceptions import ClientError
    _HAS_BOTO3 = True
except ImportError:
    _HAS_BOTO3 = False

from .base import CloudProvider

logger = logging.getLogger(__name__)


class AWSProvider(CloudProvider):
    """AWS implementation of the CloudProvider interface."""

    NAME = "Amazon Web Services"
    DESCRIPTION = "S3, IAM, EC2, DynamoDB security checks via boto3"

    @classmethod
    def is_configured(cls) -> bool:
        """AWS is configured if boto3 is available."""
        return _HAS_BOTO3

    def __init__(self):
        if _HAS_BOTO3:
            self.s3 = boto3.client("s3")
            self.ec2 = boto3.client("ec2")
            self.iam = boto3.client("iam")
            self.dynamodb = boto3.client("dynamodb")

    # ----- Storage: Public Access -----

    def check_storage_public_access(self, resource_id: str, **kwargs) -> dict:
        """Check S3 bucket public access block configuration."""
        if not _HAS_BOTO3:
            return {"status": "ERROR", "message": "boto3 not available"}

        try:
            response = self.s3.get_public_access_block(Bucket=resource_id)
            config = response.get("PublicAccessBlockConfiguration", {})
            is_blocked = all([
                config.get("BlockPublicAcls", False),
                config.get("IgnorePublicAcls", False),
                config.get("BlockPublicPolicy", False),
                config.get("RestrictPublicBuckets", False),
            ])
            return {
                "status": "COMPLIANT" if is_blocked else "NON_COMPLIANT",
                "resource": resource_id,
                "provider": "aws",
                "details": config,
            }
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NoSuchPublicAccessConfiguration":
                return {"status": "NON_COMPLIANT", "resource": resource_id, "provider": "aws"}
            return {"status": "ERROR", "message": str(exc)}

    # ----- Storage: Encryption -----

    def check_storage_encryption(self, resource_id: str, **kwargs) -> dict:
        """Check S3 bucket default encryption."""
        if not _HAS_BOTO3:
            return {"status": "ERROR", "message": "boto3 not available"}

        try:
            response = self.s3.get_bucket_encryption(Bucket=resource_id)
            rules = response.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            return {
                "status": "COMPLIANT" if rules else "NON_COMPLIANT",
                "resource": resource_id,
                "provider": "aws",
            }
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ServerSideEncryptionConfigurationNotFoundError",
                        "NoSuchEncryptionConfiguration"):
                return {"status": "NON_COMPLIANT", "resource": resource_id, "provider": "aws"}
            return {"status": "ERROR", "message": str(exc)}

    # ----- Network: Open Ports -----

    def check_network_open_ports(self, resource_id: str, **kwargs) -> dict:
        """Check EC2 security group for open SSH (port 22)."""
        if not _HAS_BOTO3:
            return {"status": "ERROR", "message": "boto3 not available"}

        try:
            response = self.ec2.describe_security_groups(GroupIds=[resource_id])
            sg = response["SecurityGroups"][0]
            open_ports = []

            for perm in sg.get("IpPermissions", []):
                from_port = perm.get("FromPort")
                to_port = perm.get("ToPort")
                for ipr in perm.get("IpRanges", []):
                    if ipr.get("CidrIp") == "0.0.0.0/0":
                        if from_port == 22 or to_port == 22 or (from_port is None and to_port is None):
                            open_ports.append({"port": 22, "cidr": "0.0.0.0/0"})

            return {
                "status": "NON_COMPLIANT" if open_ports else "COMPLIANT",
                "resource": resource_id,
                "provider": "aws",
                "open_ports": open_ports,
            }
        except Exception as exc:
            return {"status": "ERROR", "message": str(exc)}

    # ----- IAM: Overpermissive -----

    def check_iam_overpermissive(self, resource_id: str, **kwargs) -> dict:
        """Check IAM user/role for wildcard permissions."""
        if not _HAS_BOTO3:
            return {"status": "ERROR", "message": "boto3 not available"}

        findings = []
        # resource_id format: "User:username" or "Role:rolename"
        parts = resource_id.split(":", 1)
        if len(parts) != 2:
            return {"status": "ERROR", "message": f"Invalid resource format: {resource_id}"}

        entity_type, entity_name = parts

        try:
            if entity_type == "User":
                attached = self.iam.list_attached_user_policies(UserName=entity_name)
                for policy in attached.get("AttachedPolicies", []):
                    if "AdministratorAccess" in policy.get("PolicyArn", ""):
                        findings.append(f"Admin policy: {policy['PolicyName']}")
            elif entity_type == "Role":
                attached = self.iam.list_attached_role_policies(RoleName=entity_name)
                for policy in attached.get("AttachedPolicies", []):
                    if "AdministratorAccess" in policy.get("PolicyArn", ""):
                        findings.append(f"Admin policy: {policy['PolicyName']}")
        except Exception as exc:
            return {"status": "ERROR", "message": str(exc)}

        return {
            "status": "NON_COMPLIANT" if findings else "COMPLIANT",
            "resource": resource_id,
            "provider": "aws",
            "findings": findings,
        }

    # ----- Remediation -----

    def remediate(self, check_name: str, resource_id: str, **kwargs) -> dict:
        """Execute AWS-specific remediation."""
        if not _HAS_BOTO3:
            return {"status": "ERROR", "message": "boto3 not available"}

        if check_name == "check_s3_public_access":
            try:
                self.s3.put_public_access_block(
                    Bucket=resource_id,
                    PublicAccessBlockConfiguration={
                        "BlockPublicAcls": True, "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
                    },
                )
                return {"status": "REMEDIATED", "resource": resource_id}
            except Exception as exc:
                return {"status": "FAILED", "message": str(exc)}

        elif check_name == "check_s3_encryption":
            try:
                self.s3.put_bucket_encryption(
                    Bucket=resource_id,
                    ServerSideEncryptionConfiguration={
                        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}, "BucketKeyEnabled": True}]
                    },
                )
                return {"status": "REMEDIATED", "resource": resource_id}
            except Exception as exc:
                return {"status": "FAILED", "message": str(exc)}

        return {"status": "UNSUPPORTED", "message": f"No remediation for {check_name}"}
