"""
Unit Tests — NLG Engine
========================
Covers the ordinal-suffix regression (111th/112th/113th were rendered as
111st/112nd/113rd) and the sentiment-scoring arithmetic.
"""

import sys
import os
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambda", "shared"))

import nlg_engine  # noqa: E402


def _table_with_n_items(n):
    table = MagicMock()
    table.scan.return_value = {"Items": [{"event_id": str(i), "timestamp": ""} for i in range(n)]}
    return table


class TestOrdinalSuffix:
    def _ordinal_from_count(self, count):
        fragment = nlg_engine._query_temporal_context(
            _table_with_n_items(count), "123456789012", "S3 Public Access"
        )
        # fragment looks like "... This is the {count}{suffix} S3 Public Access event ..."
        assert f"the {count}" in fragment
        return fragment.split(f"the {count}", 1)[1].split(" ", 1)[0]

    def test_basic_cases(self):
        assert self._ordinal_from_count(2) == "nd"
        assert self._ordinal_from_count(3) == "rd"
        assert self._ordinal_from_count(4) == "th"

    def test_11_12_13_are_th(self):
        assert self._ordinal_from_count(11) == "th"
        assert self._ordinal_from_count(12) == "th"
        assert self._ordinal_from_count(13) == "th"

    def test_21_22_23_follow_last_digit(self):
        assert self._ordinal_from_count(21) == "st"
        assert self._ordinal_from_count(22) == "nd"
        assert self._ordinal_from_count(23) == "rd"

    def test_111_112_113_are_th_not_st_nd_rd(self):
        """Regression: the old check compared count != 11/12/13 instead of
        count % 100 not in (11, 12, 13), so three-digit numbers ending in
        11/12/13 (111, 112, 113, 211, ...) were rendered as 111st/112nd/113rd."""
        assert self._ordinal_from_count(111) == "th"
        assert self._ordinal_from_count(112) == "th"
        assert self._ordinal_from_count(113) == "th"

    def test_101_is_st(self):
        assert self._ordinal_from_count(101) == "st"


class TestSentimentScoring:
    def test_prod_test_bucket_net_score(self):
        result = nlg_engine._compute_sentiment_score("prod-test-bucket", "S3 Public Access", "REMEDIATED")
        assert result["score"] == 2  # prod (+3) + test (-1)
        assert "prod" in result["matched"]
        assert "test" in result["matched"]
        assert result["urgency"] == "elevated"
