"""Tests for agentshield reporting modules:
formatters (JsonFormatter, MarkdownFormatter, HtmlFormatter),
json_reporter (JSONReporter), summary (SecuritySummary), report (SecurityReportGenerator).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentshield.core.result import SecurityReport
from agentshield.core.scanner import Finding, FindingSeverity


def _finding(
    scanner_name: str = "test_scanner",
    severity: FindingSeverity = FindingSeverity.HIGH,
    category: str = "test_category",
    message: str = "Test finding",
) -> Finding:
    return Finding(
        scanner_name=scanner_name,
        severity=severity,
        category=category,
        message=message,
        details={"key": "value"},
    )


def _report(
    findings: list[Finding] | None = None,
    phase: str = "input",
    agent_id: str = "agent-1",
    session_id: str = "sess-1",
) -> SecurityReport:
    return SecurityReport(
        findings=findings or [],
        scan_duration_ms=1.5,
        agent_id=agent_id,
        session_id=session_id,
        phase=phase,
    )


# ---------------------------------------------------------------------------
# JsonFormatter
# ---------------------------------------------------------------------------


class TestJsonFormatter:
    def test_format_returns_valid_json(self) -> None:
        from agentshield.reporting.formatters import JsonFormatter
        formatter = JsonFormatter()
        result = formatter.format([])
        parsed = json.loads(result)
        assert isinstance(parsed, dict)

    def test_format_includes_total_findings(self) -> None:
        from agentshield.reporting.formatters import JsonFormatter
        formatter = JsonFormatter()
        result = formatter.format([_finding(), _finding()])
        parsed = json.loads(result)
        assert parsed["total_findings"] == 2

    def test_format_includes_severity_counts(self) -> None:
        from agentshield.reporting.formatters import JsonFormatter
        formatter = JsonFormatter()
        result = formatter.format([_finding(severity=FindingSeverity.HIGH)])
        parsed = json.loads(result)
        assert "severity_counts" in parsed
        assert parsed["severity_counts"].get("high", 0) == 1

    def test_format_no_findings(self) -> None:
        from agentshield.reporting.formatters import JsonFormatter
        formatter = JsonFormatter()
        result = formatter.format([])
        parsed = json.loads(result)
        assert parsed["total_findings"] == 0
        assert parsed["findings"] == []

    def test_format_custom_indent(self) -> None:
        from agentshield.reporting.formatters import JsonFormatter
        formatter = JsonFormatter(indent=4)
        result = formatter.format([])
        assert "    " in result

    def test_format_includes_generated_at(self) -> None:
        from agentshield.reporting.formatters import JsonFormatter
        formatter = JsonFormatter()
        result = formatter.format([])
        parsed = json.loads(result)
        assert "generated_at" in parsed

    def test_severity_counts_excludes_zeros(self) -> None:
        from agentshield.reporting.formatters import JsonFormatter
        formatter = JsonFormatter()
        result = formatter.format([_finding(severity=FindingSeverity.CRITICAL)])
        parsed = json.loads(result)
        counts = parsed["severity_counts"]
        # Zeros should be excluded
        assert all(v > 0 for v in counts.values())


# ---------------------------------------------------------------------------
# MarkdownFormatter
# ---------------------------------------------------------------------------


class TestMarkdownFormatter:
    def test_format_empty_findings(self) -> None:
        from agentshield.reporting.formatters import MarkdownFormatter
        formatter = MarkdownFormatter()
        result = formatter.format([])
        assert "No security findings" in result

    def test_format_includes_title(self) -> None:
        from agentshield.reporting.formatters import MarkdownFormatter
        formatter = MarkdownFormatter()
        result = formatter.format([])
        assert "agentshield Security Report" in result

    def test_format_includes_finding_details(self) -> None:
        from agentshield.reporting.formatters import MarkdownFormatter
        formatter = MarkdownFormatter()
        result = formatter.format([_finding(category="test_cat", message="My test message")])
        assert "test_cat" in result
        assert "My test message" in result

    def test_format_severity_icons_included(self) -> None:
        from agentshield.reporting.formatters import MarkdownFormatter
        formatter = MarkdownFormatter()
        result = formatter.format([_finding(severity=FindingSeverity.CRITICAL)])
        assert "[CRITICAL]" in result

    def test_format_multiple_severities(self) -> None:
        from agentshield.reporting.formatters import MarkdownFormatter
        formatter = MarkdownFormatter()
        findings = [
            _finding(severity=FindingSeverity.CRITICAL),
            _finding(severity=FindingSeverity.LOW),
        ]
        result = formatter.format(findings)
        assert "[CRITICAL]" in result
        assert "[LOW]" in result

    def test_format_returns_string(self) -> None:
        from agentshield.reporting.formatters import MarkdownFormatter
        formatter = MarkdownFormatter()
        result = formatter.format([_finding()])
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# HtmlFormatter
# ---------------------------------------------------------------------------


class TestHtmlFormatter:
    def test_format_returns_html_doctype(self) -> None:
        from agentshield.reporting.formatters import HtmlFormatter
        formatter = HtmlFormatter()
        result = formatter.format([])
        assert "<!DOCTYPE html>" in result

    def test_format_empty_findings(self) -> None:
        from agentshield.reporting.formatters import HtmlFormatter
        formatter = HtmlFormatter()
        result = formatter.format([])
        assert "No security findings" in result

    def test_format_contains_findings_in_table(self) -> None:
        from agentshield.reporting.formatters import HtmlFormatter
        formatter = HtmlFormatter()
        result = formatter.format([_finding(scanner_name="test_scanner_html")])
        assert "test_scanner_html" in result

    def test_format_escapes_html(self) -> None:
        from agentshield.reporting.formatters import HtmlFormatter
        formatter = HtmlFormatter()
        malicious = _finding(message="<script>alert('xss')</script>")
        result = formatter.format([malicious])
        assert "<script>" not in result
        assert "&lt;script&gt;" in result

    def test_finding_row_has_badge_class(self) -> None:
        from agentshield.reporting.formatters import HtmlFormatter
        formatter = HtmlFormatter()
        result = formatter.format([_finding(severity=FindingSeverity.CRITICAL)])
        assert 'class="badge critical"' in result


# ---------------------------------------------------------------------------
# _count_severities and _severity_icon helpers
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_count_severities_empty(self) -> None:
        from agentshield.reporting.formatters import _count_severities
        assert _count_severities([]) == {}

    def test_count_severities_correct_counts(self) -> None:
        from agentshield.reporting.formatters import _count_severities
        findings = [
            _finding(severity=FindingSeverity.HIGH),
            _finding(severity=FindingSeverity.HIGH),
            _finding(severity=FindingSeverity.LOW),
        ]
        counts = _count_severities(findings)
        assert counts["high"] == 2
        assert counts["low"] == 1
        assert "medium" not in counts  # zeros excluded

    def test_severity_icon_returns_string(self) -> None:
        from agentshield.reporting.formatters import _severity_icon
        assert _severity_icon("critical") == "[CRITICAL]"
        assert _severity_icon("high") == "[HIGH]"
        assert _severity_icon("unknown") == ""


# ---------------------------------------------------------------------------
# JSONReporter
# ---------------------------------------------------------------------------


class TestJSONReporter:
    def test_generate_creates_file(self, tmp_path: Path) -> None:
        from agentshield.reporting.json_reporter import JSONReporter
        reporter = JSONReporter()
        output = tmp_path / "report.json"
        result = reporter.generate([_report()], output)
        assert result.exists()

    def test_generate_returns_resolved_path(self, tmp_path: Path) -> None:
        from agentshield.reporting.json_reporter import JSONReporter
        reporter = JSONReporter()
        output = tmp_path / "report.json"
        result = reporter.generate([_report()], output)
        assert result.is_absolute()

    def test_generate_valid_json(self, tmp_path: Path) -> None:
        from agentshield.reporting.json_reporter import JSONReporter
        reporter = JSONReporter()
        output = tmp_path / "report.json"
        reporter.generate([_report()], output)
        content = json.loads(output.read_text())
        assert "agentshield_report" in content

    def test_generate_includes_summary(self, tmp_path: Path) -> None:
        from agentshield.reporting.json_reporter import JSONReporter
        reporter = JSONReporter()
        output = tmp_path / "report.json"
        reporter.generate([_report()], output)
        data = json.loads(output.read_text())
        report_data = data["agentshield_report"]
        assert "summary" in report_data
        assert "scans" in report_data

    def test_generate_empty_results(self, tmp_path: Path) -> None:
        from agentshield.reporting.json_reporter import JSONReporter
        reporter = JSONReporter()
        output = tmp_path / "empty.json"
        reporter.generate([], output)
        data = json.loads(output.read_text())
        summary = data["agentshield_report"]["summary"]
        assert summary["total_scans"] == 0

    def test_summary_json_returns_valid_json(self) -> None:
        from agentshield.reporting.json_reporter import JSONReporter
        reporter = JSONReporter()
        result = reporter.summary_json([_report(findings=[_finding()])])
        parsed = json.loads(result)
        assert "total_scans" in parsed
        assert "passed" in parsed
        assert "failed" in parsed

    def test_summary_json_counts_correctly(self) -> None:
        from agentshield.reporting.json_reporter import JSONReporter
        reporter = JSONReporter()
        clean_report = _report(findings=[])
        dirty_report = _report(findings=[_finding()])
        result = reporter.summary_json([clean_report, dirty_report])
        parsed = json.loads(result)
        assert parsed["total_scans"] == 2
        assert parsed["passed"] == 1
        assert parsed["failed"] == 1


# ---------------------------------------------------------------------------
# SecuritySummary
# ---------------------------------------------------------------------------


class TestSecuritySummary:
    def test_from_results_empty(self) -> None:
        from agentshield.reporting.summary import SecuritySummary
        summary = SecuritySummary.from_results([])
        assert summary.total_scans == 0
        assert summary.passed == 0
        assert summary.failed == 0

    def test_from_results_clean_reports_all_passed(self) -> None:
        from agentshield.reporting.summary import SecuritySummary
        reports = [_report(findings=[]), _report(findings=[])]
        summary = SecuritySummary.from_results(reports)
        assert summary.total_scans == 2
        assert summary.passed == 2
        assert summary.failed == 0

    def test_from_results_dirty_reports_counted(self) -> None:
        from agentshield.reporting.summary import SecuritySummary
        reports = [
            _report(findings=[_finding(severity=FindingSeverity.HIGH)]),
            _report(findings=[]),
        ]
        summary = SecuritySummary.from_results(reports)
        assert summary.total_scans == 2
        assert summary.failed == 1
        assert summary.passed == 1

    def test_from_results_by_severity_populated(self) -> None:
        from agentshield.reporting.summary import SecuritySummary
        reports = [_report(findings=[
            _finding(severity=FindingSeverity.CRITICAL),
            _finding(severity=FindingSeverity.HIGH),
        ])]
        summary = SecuritySummary.from_results(reports)
        assert summary.by_severity.get("critical", 0) == 1
        assert summary.by_severity.get("high", 0) == 1

    def test_from_results_by_scanner_populated(self) -> None:
        from agentshield.reporting.summary import SecuritySummary
        reports = [_report(findings=[
            _finding(scanner_name="scanner_a"),
            _finding(scanner_name="scanner_a"),
            _finding(scanner_name="scanner_b"),
        ])]
        summary = SecuritySummary.from_results(reports)
        assert summary.by_scanner.get("scanner_a") == 2
        assert summary.by_scanner.get("scanner_b") == 1

    def test_from_results_by_owasp_populated_for_known_scanner(self) -> None:
        from agentshield.reporting.summary import SecuritySummary
        reports = [_report(findings=[_finding(scanner_name="regex_injection")])]
        summary = SecuritySummary.from_results(reports)
        # regex_injection maps to ASI01 and ASI10
        assert len(summary.by_owasp) > 0

    def test_to_dict_structure(self) -> None:
        from agentshield.reporting.summary import SecuritySummary
        summary = SecuritySummary.from_results([])
        d = summary.to_dict()
        assert "total_scans" in d
        assert "passed" in d
        assert "failed" in d
        assert "pass_rate" in d
        assert "by_severity" in d
        assert "by_scanner" in d
        assert "by_owasp" in d

    def test_to_dict_pass_rate_zero_scans(self) -> None:
        from agentshield.reporting.summary import SecuritySummary
        summary = SecuritySummary.from_results([])
        d = summary.to_dict()
        assert d["pass_rate"] == 1.0

    def test_to_dict_pass_rate_computed(self) -> None:
        from agentshield.reporting.summary import SecuritySummary
        reports = [_report(findings=[]), _report(findings=[_finding()])]
        summary = SecuritySummary.from_results(reports)
        d = summary.to_dict()
        assert d["pass_rate"] == 0.5


# ---------------------------------------------------------------------------
# SecurityReportGenerator
# ---------------------------------------------------------------------------


class TestSecurityReportGenerator:
    def test_generate_json(self) -> None:
        from agentshield.reporting.report import SecurityReportGenerator
        gen = SecurityReportGenerator()
        result = gen.generate_json([_finding()])
        parsed = json.loads(result)
        assert "findings" in parsed

    def test_generate_markdown(self) -> None:
        from agentshield.reporting.report import SecurityReportGenerator
        gen = SecurityReportGenerator()
        result = gen.generate_markdown([_finding()])
        assert "agentshield Security Report" in result

    def test_generate_html(self) -> None:
        from agentshield.reporting.report import SecurityReportGenerator
        gen = SecurityReportGenerator()
        result = gen.generate_html([_finding()])
        assert "<!DOCTYPE html>" in result

    def test_generate_with_json_format(self) -> None:
        from agentshield.reporting.report import SecurityReportGenerator
        gen = SecurityReportGenerator()
        result = gen.generate([_finding()], "json")
        json.loads(result)  # should not raise

    def test_generate_with_markdown_format(self) -> None:
        from agentshield.reporting.report import SecurityReportGenerator
        gen = SecurityReportGenerator()
        result = gen.generate([_finding()], "markdown")
        assert "agentshield Security Report" in result

    def test_generate_with_md_alias(self) -> None:
        from agentshield.reporting.report import SecurityReportGenerator
        gen = SecurityReportGenerator()
        result = gen.generate([_finding()], "md")
        assert "agentshield Security Report" in result

    def test_generate_with_html_format(self) -> None:
        from agentshield.reporting.report import SecurityReportGenerator
        gen = SecurityReportGenerator()
        result = gen.generate([_finding()], "html")
        assert "<!DOCTYPE html>" in result

    def test_generate_unsupported_format_raises(self) -> None:
        from agentshield.reporting.report import SecurityReportGenerator
        gen = SecurityReportGenerator()
        with pytest.raises(ValueError, match="Unsupported format"):
            gen.generate([_finding()], "pdf")

    def test_generate_empty_findings(self) -> None:
        from agentshield.reporting.report import SecurityReportGenerator
        gen = SecurityReportGenerator()
        result = gen.generate_json([])
        parsed = json.loads(result)
        assert parsed["total_findings"] == 0
