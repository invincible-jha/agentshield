"""Unit tests for agentshield.core.result.SecurityReport."""
from __future__ import annotations

import json

import pytest

from agentshield.core.result import SecurityReport
from agentshield.core.scanner import Finding, FindingSeverity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding(severity: FindingSeverity, category: str = "test") -> Finding:
    return Finding(
        scanner_name="test_scanner",
        severity=severity,
        category=category,
        message=f"Finding with severity {severity.value}",
    )


# ---------------------------------------------------------------------------
# Clean report (no findings)
# ---------------------------------------------------------------------------


class TestSecurityReportClean:
    def test_is_clean_when_no_findings(self) -> None:
        report = SecurityReport()
        assert report.is_clean is True

    def test_has_critical_false_when_clean(self) -> None:
        report = SecurityReport()
        assert report.has_critical is False

    def test_has_high_false_when_clean(self) -> None:
        report = SecurityReport()
        assert report.has_high is False

    def test_has_medium_false_when_clean(self) -> None:
        report = SecurityReport()
        assert report.has_medium is False

    def test_highest_severity_none_when_clean(self) -> None:
        report = SecurityReport()
        assert report.highest_severity is None

    def test_summary_says_no_findings(self) -> None:
        report = SecurityReport()
        assert report.summary == "No findings."

    def test_to_dict_findings_empty(self) -> None:
        report = SecurityReport()
        result = report.to_dict()
        assert result["findings"] == []

    def test_to_dict_summary_correct(self) -> None:
        report = SecurityReport()
        result = report.to_dict()
        assert result["summary"] == "No findings."

    def test_to_json_valid_json(self) -> None:
        report = SecurityReport()
        parsed = json.loads(report.to_json())
        assert parsed["findings"] == []


# ---------------------------------------------------------------------------
# Report with findings
# ---------------------------------------------------------------------------


class TestSecurityReportWithFindings:
    def test_is_clean_false_when_findings_present(self) -> None:
        report = SecurityReport(findings=[_finding(FindingSeverity.INFO)])
        assert report.is_clean is False

    def test_has_critical_true_when_critical_finding(self) -> None:
        report = SecurityReport(findings=[_finding(FindingSeverity.CRITICAL)])
        assert report.has_critical is True

    def test_has_critical_false_when_only_high(self) -> None:
        report = SecurityReport(findings=[_finding(FindingSeverity.HIGH)])
        assert report.has_critical is False

    def test_has_high_true_when_critical_finding(self) -> None:
        # has_high uses >= HIGH, so CRITICAL also qualifies.
        report = SecurityReport(findings=[_finding(FindingSeverity.CRITICAL)])
        assert report.has_high is True

    def test_has_high_true_when_high_finding(self) -> None:
        report = SecurityReport(findings=[_finding(FindingSeverity.HIGH)])
        assert report.has_high is True

    def test_has_high_false_when_only_medium(self) -> None:
        report = SecurityReport(findings=[_finding(FindingSeverity.MEDIUM)])
        assert report.has_high is False

    def test_has_medium_true_when_medium_finding(self) -> None:
        report = SecurityReport(findings=[_finding(FindingSeverity.MEDIUM)])
        assert report.has_medium is True

    def test_has_medium_true_when_critical_finding(self) -> None:
        report = SecurityReport(findings=[_finding(FindingSeverity.CRITICAL)])
        assert report.has_medium is True

    def test_has_medium_false_when_only_low(self) -> None:
        report = SecurityReport(findings=[_finding(FindingSeverity.LOW)])
        assert report.has_medium is False

    def test_highest_severity_single_finding(self) -> None:
        report = SecurityReport(findings=[_finding(FindingSeverity.HIGH)])
        assert report.highest_severity == FindingSeverity.HIGH

    def test_highest_severity_mixed_findings(self) -> None:
        report = SecurityReport(
            findings=[
                _finding(FindingSeverity.LOW),
                _finding(FindingSeverity.CRITICAL),
                _finding(FindingSeverity.MEDIUM),
            ]
        )
        assert report.highest_severity == FindingSeverity.CRITICAL

    def test_summary_single_high(self) -> None:
        report = SecurityReport(findings=[_finding(FindingSeverity.HIGH)])
        assert report.summary == "1 finding(s): 1 HIGH"

    def test_summary_mixed_severities(self) -> None:
        report = SecurityReport(
            findings=[
                _finding(FindingSeverity.CRITICAL),
                _finding(FindingSeverity.HIGH),
                _finding(FindingSeverity.MEDIUM),
            ]
        )
        summary = report.summary
        assert "1 CRITICAL" in summary
        assert "1 HIGH" in summary
        assert "1 MEDIUM" in summary
        assert "3 finding(s)" in summary

    def test_summary_severity_order_critical_first(self) -> None:
        report = SecurityReport(
            findings=[
                _finding(FindingSeverity.LOW),
                _finding(FindingSeverity.CRITICAL),
            ]
        )
        summary = report.summary
        # CRITICAL should appear before LOW in the string.
        assert summary.index("CRITICAL") < summary.index("LOW")

    def test_to_dict_keys(self) -> None:
        report = SecurityReport(
            findings=[_finding(FindingSeverity.HIGH)],
            phase="input",
            agent_id="test-agent",
            session_id="session-001",
            scan_duration_ms=12.5,
        )
        result = report.to_dict()
        assert set(result.keys()) == {
            "phase", "agent_id", "session_id", "scan_duration_ms", "summary", "findings"
        }

    def test_to_dict_phase_value(self) -> None:
        report = SecurityReport(phase="output")
        assert report.to_dict()["phase"] == "output"

    def test_to_dict_findings_count(self) -> None:
        report = SecurityReport(
            findings=[_finding(FindingSeverity.HIGH), _finding(FindingSeverity.LOW)]
        )
        assert len(report.to_dict()["findings"]) == 2

    def test_to_json_indent_default(self) -> None:
        report = SecurityReport(findings=[_finding(FindingSeverity.MEDIUM)])
        json_str = report.to_json()
        parsed = json.loads(json_str)
        assert parsed["findings"][0]["severity"] == "medium"

    def test_to_json_custom_indent(self) -> None:
        report = SecurityReport()
        json_str = report.to_json(indent=4)
        # With indent=4 there should be 4-space indentation.
        assert "    " in json_str

    def test_repr_contains_phase_and_finding_count(self) -> None:
        report = SecurityReport(findings=[_finding(FindingSeverity.HIGH)], phase="input")
        representation = repr(report)
        assert "input" in representation
        assert "1" in representation
