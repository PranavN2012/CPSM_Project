"""
Unit Tests — IAM Audit Lambda
==============================
Tests the wildcard-detection logic that flags overpermissive IAM policies.
"""

import sys
import os
import importlib.util

# Both lambda/remediation/ and lambda/iam-audit/ have a file literally named
# lambda_function.py — a plain `import lambda_function` after sys.path
# tricks would collide with whichever one another test module already
# cached under sys.modules["lambda_function"]. Load this one under its own
# name instead so the two never fight over the same module-cache slot.
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambda", "shared"))

_IAM_AUDIT_DIR = os.path.join(os.path.dirname(__file__), "..", "lambda", "iam-audit")
_spec = importlib.util.spec_from_file_location("iam_audit_lambda_function", os.path.join(_IAM_AUDIT_DIR, "lambda_function.py"))
iam_audit = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(iam_audit)


class TestFindWildcards:
    def test_full_wildcard_action(self):
        policy = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::x"}]}
        assert iam_audit.find_wildcards(policy) == ["Action:*"]

    def test_service_level_wildcard_action_is_flagged(self):
        """s3:* grants every S3 action — just as dangerous as a bare "*", and
        was previously missed because the check only matched the literal "*"."""
        policy = {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::x"}]}
        assert iam_audit.find_wildcards(policy) == ["Action:s3:*"]

    def test_service_level_wildcard_in_list(self):
        policy = {"Statement": [{"Effect": "Allow", "Action": ["iam:*"], "Resource": "*"}]}
        wildcards = iam_audit.find_wildcards(policy)
        assert "Action:iam:*" in wildcards
        assert "Resource:*" in wildcards

    def test_narrow_action_not_flagged(self):
        policy = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::x"}]}
        assert iam_audit.find_wildcards(policy) == []

    def test_deny_wildcard_not_flagged(self):
        """Only Allow statements grant access — a Deny wildcard is not a finding."""
        policy = {"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}
        assert iam_audit.find_wildcards(policy) == []

    def test_partial_action_wildcard_is_flagged(self):
        """A prefix wildcard like "s3:Get*" is still broader than a single
        explicit action and worth a human's attention — flagged the same way
        as a full "s3:*", not silently treated as "not really a wildcard"."""
        policy = {"Statement": [{"Effect": "Allow", "Action": "s3:Get*", "Resource": ["arn:aws:s3:::x", "*"]}]}
        wildcards = iam_audit.find_wildcards(policy)
        assert "Action:s3:Get*" in wildcards
        assert "Resource:*" in wildcards

    def test_lowercase_effect_still_flagged(self):
        """Effect is compared case-insensitively — AWS's own grammar only
        emits "Allow"/"Deny" exactly, but this tool also processes documents
        that never passed through AWS's validation, so case must not be a
        bypass."""
        policy = {"Statement": [{"Effect": "allow", "Action": "s3:*", "Resource": "*"}]}
        wildcards = iam_audit.find_wildcards(policy)
        assert "Action:s3:*" in wildcards
        assert "Resource:*" in wildcards

    def test_not_action_does_not_produce_false_action_wildcard(self):
        """NotAction is a different field from Action; the absence of "Action"
        should not spuriously match. Resource:* on the same statement should
        still be caught independently."""
        policy = {"Statement": [{"Effect": "Allow", "NotAction": "*", "Resource": "*"}]}
        assert iam_audit.find_wildcards(policy) == ["Resource:*"]

    def test_single_statement_dict_not_list(self):
        policy = {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}
        wildcards = iam_audit.find_wildcards(policy)
        assert "Action:*" in wildcards
        assert "Resource:*" in wildcards


class TestIsAdminPolicy:
    def test_administrator_access_is_admin(self):
        assert iam_audit.is_admin_policy("arn:aws:iam::aws:policy/AdministratorAccess")

    def test_read_only_is_not_admin(self):
        assert not iam_audit.is_admin_policy("arn:aws:iam::aws:policy/ReadOnlyAccess")
