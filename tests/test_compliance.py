"""
Unit Tests — Compliance Mapping
================================
Tests the CIS/SOC2/PCI-DSS compliance mapping module.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambda", "shared"))
from compliance import get_compliance_for_event, get_compliance_summary, COMPLIANCE_MAP


class TestComplianceMapping:
    """Tests for the compliance framework mapping."""

    def test_s3_public_access_has_mappings(self):
        """S3 Public Access should map to CIS, SOC2, and PCI-DSS."""
        event = {"vulnerability_type": "S3 Public Access", "status": "REMEDIATED"}
        result = get_compliance_for_event(event)

        assert result["vulnerability_type"] == "S3 Public Access"
        assert len(result["controls"]) >= 3

        frameworks = {c["framework"] for c in result["controls"]}
        assert "CIS AWS" in frameworks
        assert "SOC 2" in frameworks
        assert "PCI-DSS" in frameworks

    def test_encryption_has_mappings(self):
        """S3 Encryption should map to CIS 2.1.1/2.1.2."""
        event = {"vulnerability_type": "S3 Encryption", "status": "ENCRYPTION_REMEDIATED"}
        result = get_compliance_for_event(event)

        cis_controls = [c for c in result["controls"] if c["framework"] == "CIS AWS"]
        assert len(cis_controls) >= 2

    def test_iam_audit_has_mappings(self):
        """IAM Audit should map to CIS 1.16 and PCI-DSS 7.1."""
        event = {"vulnerability_type": "IAM Audit", "status": "IAM_OVERPERMISSIVE"}
        result = get_compliance_for_event(event)

        control_ids = {c["control_id"] for c in result["controls"]}
        assert "1.16" in control_ids
        assert "7.1" in control_ids

    def test_remediated_event_passes(self):
        """A remediated event should have PASS status."""
        event = {"vulnerability_type": "S3 Public Access", "status": "REMEDIATED"}
        result = get_compliance_for_event(event)

        assert result["status"] == "PASS"
        assert all(c["status"] == "PASS" for c in result["controls"])

    def test_failed_event_fails(self):
        """A failed event should have FAIL status."""
        event = {"vulnerability_type": "S3 Public Access", "status": "REMEDIATION_FAILED"}
        result = get_compliance_for_event(event)

        assert result["status"] == "FAIL"
        assert all(c["status"] == "FAIL" for c in result["controls"])

    def test_iam_overpermissive_fails(self):
        """An IAM_OVERPERMISSIVE event should FAIL compliance."""
        event = {"vulnerability_type": "IAM Audit", "status": "IAM_OVERPERMISSIVE"}
        result = get_compliance_for_event(event)

        assert result["status"] == "FAIL"


class TestComplianceSummary:
    """Tests for the aggregate compliance summary."""

    def test_all_passing_gives_100(self):
        """All compliant events should give 100% score."""
        events = [
            {"vulnerability_type": "S3 Public Access", "status": "REMEDIATED"},
            {"vulnerability_type": "S3 Encryption", "status": "ENCRYPTION_REMEDIATED"},
        ]
        summary = get_compliance_summary(events)

        assert summary["overall_score"] == 100.0

    def test_mixed_events_lower_score(self):
        """Mixed pass/fail should give < 100% score."""
        events = [
            {"vulnerability_type": "S3 Public Access", "status": "REMEDIATED"},
            {"vulnerability_type": "IAM Audit", "status": "IAM_OVERPERMISSIVE"},
        ]
        summary = get_compliance_summary(events)

        assert 0 < summary["overall_score"] < 100

    def test_summary_has_all_frameworks(self):
        """Summary should include CIS, SOC2, PCI-DSS."""
        events = [
            {"vulnerability_type": "S3 Public Access", "status": "REMEDIATED"},
            {"vulnerability_type": "S3 Encryption", "status": "COMPLIANT"},
            {"vulnerability_type": "IAM Audit", "status": "IAM_OVERPERMISSIVE"},
        ]
        summary = get_compliance_summary(events)

        assert "CIS AWS" in summary["frameworks"]
        assert "SOC 2" in summary["frameworks"]
        assert "PCI-DSS" in summary["frameworks"]

    def test_empty_events_gives_zero(self):
        """No events should give 0% or handle gracefully."""
        summary = get_compliance_summary([])
        assert summary["overall_score"] == 0
        assert summary["controls_checked"] == 0
