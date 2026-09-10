"""
Unit Tests — PDF Report Generator
==================================
Covers the Unicode crash regression: event-derived text (bucket names, NLG
summaries) containing an em dash, curly quotes, or non-Latin characters used
to raise FPDFUnicodeEncodingException and abort report generation entirely,
because FPDF's core "helvetica" font only supports Latin-1.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/scripts")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambda", "shared"))

import report_generator as rg  # noqa: E402


def _event(bucket_name):
    return {
        "event_id": "e1", "timestamp": "2026-01-01T00:00:00Z",
        "bucket_name": bucket_name, "account_id": "123456789012",
        "region": "us-east-1", "status": "REMEDIATED",
        "vulnerability_type": "S3 Public Access", "severity": "CRITICAL",
    }


class TestPdfSafe:
    def test_transliterates_em_dash(self):
        assert rg._pdf_safe("prod—bucket") == "prod-bucket"

    def test_transliterates_curly_quotes(self):
        assert rg._pdf_safe("‘quoted’") == "'quoted'"

    def test_non_latin1_falls_back_without_crashing(self):
        # CJK has no Latin-1 representation; must degrade gracefully, not raise.
        result = rg._pdf_safe("bucket-中文")
        assert "bucket-" in result
        assert "?" in result


class TestGenerateReportUnicodeSafety:
    def test_zero_events_succeeds(self):
        pdf_bytes = rg.generate_report([], {})
        assert len(pdf_bytes) > 0

    def test_em_dash_bucket_name_does_not_crash(self):
        pdf_bytes = rg.generate_report([_event("prod—bucket")], {"total_events": 1, "remediated": 1, "failed": 0})
        assert len(pdf_bytes) > 0

    def test_curly_quotes_bucket_name_does_not_crash(self):
        pdf_bytes = rg.generate_report([_event("prod ‘quoted’ bucket")], {"total_events": 1, "remediated": 1, "failed": 0})
        assert len(pdf_bytes) > 0

    def test_cjk_bucket_name_does_not_crash(self):
        pdf_bytes = rg.generate_report([_event("prod-bucket-中文")], {"total_events": 1, "remediated": 1, "failed": 0})
        assert len(pdf_bytes) > 0
