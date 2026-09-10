"""
Unit Tests — Remediation Lambda
================================
Tests the S3 public access and encryption check logic.
"""

import json
import sys
import os
from unittest.mock import MagicMock, patch
from datetime import datetime
from botocore.exceptions import ClientError

# Add lambda dirs to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambda", "remediation"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambda", "shared"))


class TestPublicAccessCheck:
    """Tests for S3 public access detection and remediation."""

    def _make_event(self, bucket_name="test-bucket"):
        return {
            "version": "0",
            "id": "test-event-1",
            "source": "aws.s3",
            "account": "123456789012",
            "region": "us-east-1",
            "detail-type": "AWS API Call via CloudTrail",
            "detail": {
                "eventSource": "s3.amazonaws.com",
                "eventName": "CreateBucket",
                "requestParameters": {"bucketName": bucket_name},
            },
        }

    @patch("lambda_function.s3_client")
    @patch("lambda_function.dynamodb")
    @patch("lambda_function.send_discord_notification")
    @patch("lambda_function.create_github_issue")
    def test_detects_public_bucket(self, mock_gh, mock_discord, mock_db, mock_s3):
        """Should detect a bucket with public access disabled."""
        import lambda_function

        mock_s3.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            }
        }
        mock_s3.put_public_access_block.return_value = {}
        mock_s3.get_bucket_encryption.side_effect = ClientError(
            {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError",
                       "Message": "The server side encryption configuration was not found"}},
            "GetBucketEncryption",
        )

        mock_table = MagicMock()
        mock_db.Table.return_value = mock_table

        result = lambda_function.lambda_handler(self._make_event(), None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["status"] in ("REMEDIATED", "ENCRYPTION_REMEDIATED")

    @patch("lambda_function.s3_client")
    @patch("lambda_function.dynamodb")
    def test_compliant_bucket_is_skipped(self, mock_db, mock_s3):
        """Should mark a compliant bucket as COMPLIANT."""
        import lambda_function

        mock_s3.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }
        mock_s3.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            }
        }

        mock_table = MagicMock()
        mock_db.Table.return_value = mock_table

        result = lambda_function.lambda_handler(self._make_event(), None)
        assert result["statusCode"] == 200

    def test_bad_event_returns_400(self):
        """Should return 400 for a malformed event."""
        import lambda_function

        result = lambda_function.lambda_handler({"detail": {}}, None)
        assert result["statusCode"] == 400


class TestSecurityGroupCheck:
    """Tests for the SSH-open-to-the-world check, including IPv6."""

    def _sg_response(self, ip_ranges=None, ipv6_ranges=None):
        return {
            "SecurityGroups": [{
                "GroupId": "sg-123",
                "IpPermissions": [{
                    "FromPort": 22, "ToPort": 22, "IpProtocol": "tcp",
                    "IpRanges": ip_ranges or [],
                    "Ipv6Ranges": ipv6_ranges or [],
                }],
            }]
        }

    @patch("lambda_function.ec2_client")
    @patch("lambda_function.dynamodb")
    @patch("lambda_function.send_discord_notification")
    @patch("lambda_function.create_github_issue")
    def test_detects_open_ipv4_ssh(self, mock_gh, mock_discord, mock_db, mock_ec2):
        import lambda_function

        mock_ec2.describe_security_groups.return_value = self._sg_response(
            ip_ranges=[{"CidrIp": "0.0.0.0/0"}]
        )
        mock_ec2.revoke_security_group_ingress.return_value = {}
        mock_db.Table.return_value = MagicMock()

        result = lambda_function.check_security_group("sg-123", "123456789012", "us-east-1", "AuthorizeSecurityGroupIngress")
        assert result["status"] == "REMEDIATED"
        mock_ec2.revoke_security_group_ingress.assert_called_once()

    @patch("lambda_function.ec2_client")
    @patch("lambda_function.dynamodb")
    @patch("lambda_function.send_discord_notification")
    @patch("lambda_function.create_github_issue")
    def test_detects_open_ipv6_ssh(self, mock_gh, mock_discord, mock_db, mock_ec2):
        """IPv6 ::/0 must be treated the same as IPv4 0.0.0.0/0 — previously
        the check only inspected IpRanges and silently ignored Ipv6Ranges."""
        import lambda_function

        mock_ec2.describe_security_groups.return_value = self._sg_response(
            ipv6_ranges=[{"CidrIpv6": "::/0"}]
        )
        mock_ec2.revoke_security_group_ingress.return_value = {}
        mock_db.Table.return_value = MagicMock()

        result = lambda_function.check_security_group("sg-123", "123456789012", "us-east-1", "AuthorizeSecurityGroupIngress")
        assert result["status"] == "REMEDIATED"
        mock_ec2.revoke_security_group_ingress.assert_called_once()

    @patch("lambda_function.ec2_client")
    @patch("lambda_function.dynamodb")
    @patch("lambda_function.send_discord_notification")
    @patch("lambda_function.create_github_issue")
    def test_scoped_ipv6_is_compliant(self, mock_gh, mock_discord, mock_db, mock_ec2):
        import lambda_function

        mock_ec2.describe_security_groups.return_value = self._sg_response(
            ipv6_ranges=[{"CidrIpv6": "2001:db8::/32"}]
        )
        mock_db.Table.return_value = MagicMock()

        result = lambda_function.check_security_group("sg-123", "123456789012", "us-east-1", "AuthorizeSecurityGroupIngress")
        assert result["status"] == "COMPLIANT"
        mock_ec2.revoke_security_group_ingress.assert_not_called()


class TestEncryptionCheck:
    """Tests for S3 encryption detection."""

    @patch("lambda_function.s3_client")
    @patch("lambda_function.dynamodb")
    @patch("lambda_function.send_discord_notification")
    @patch("lambda_function.create_github_issue")
    def test_detects_unencrypted_bucket(self, mock_gh, mock_discord, mock_db, mock_s3):
        """Should detect and remediate an unencrypted bucket."""
        import lambda_function
        from botocore.exceptions import ClientError

        mock_s3.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True, "IgnorePublicAcls": True,
                "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
            }
        }
        mock_s3.get_bucket_encryption.side_effect = ClientError(
            {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError"}},
            "GetBucketEncryption"
        )
        mock_s3.put_bucket_encryption.return_value = {}

        mock_table = MagicMock()
        mock_db.Table.return_value = mock_table

        result = lambda_function.check_encryption(
            "test-bucket", "123", "us-east-1", "PutBucketEncryption"
        )

        assert result is not None
        assert result["check"] == "S3 Encryption"
        assert result["status"] == "ENCRYPTION_REMEDIATED"
