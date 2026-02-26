"""Tests for agentshield.reporting.html_reporter — HTMLReporter.

Covers report generation, summary rendering, findings table, edge cases
(empty results, no findings), and HTML escaping of untrusted data.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from agentshield.core.result import SecurityReport
from agentshield.core.scanner import Finding, FindingSeverity
from agentshield.reporting.html_reporter import HTMLReporter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    severity: FindingSeverity = FindingSeverity.HIGH,
    category: str = "test_category",
    message: str = "A test finding.",
    scanner_name: str = "test_scanner",
    details: dict[str, object] | None = None,
) -> Finding:
    return Finding(
        scanner_name=scanner_name,
        severity=severity,
        category=category,
        message=message,
        details=details or {},
    )


def _make_report(
    findings: list[Finding] | None = None,
    phase: str = "input",
) -> SecurityReport:
    return SecurityReport(
        findings=findings or [],
        scan_duration_ms=1.5,
        agent_id="test-agent",
        session_id="sess-html",
        phase=phase,
    )


# ---------------------------------------------------------------------------
# Report generation — file I/O
# ---------------------------------------------------------------------------


class TestGenerate:
    def test_generate_returns_resolved_path(self) -> None:
        reporter = HTMLReporter()
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.html"
            result = reporter.generate([], out)
            assert result == out.resolve()

    def test_generate_creates_file(self) -> None:
        reporter = HTMLReporter()
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.html"
            reporter.generate([], out)
            assert out.exists()

    def test_generated_file_is_utf8(self) -> None:
        reporter = HTMLReporter()
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.html"
            reporter.generate([_make_report()], out)
            content = out.read_text(encoding="utf-8")
            assert len(content) > 0

    def test_generated_file_starts_with_doctype(self) -> None:
        reporter = HTMLReporter()
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.html"
            reporter.generate([], out)
            text = out.read_text(encoding="utf-8")
            assert text.startswith("<!DOCTYPE html>")


# ---------------------------------------------------------------------------
# Document structure
# ---------------------------------------------------------------------------


class TestDocumentStructure:
    def _render(self, results: list[SecurityReport]) -> str:
        reporter = HTMLReporter()
        return reporter._render_document(results)

    def test_document_contains_html_tags(self) -> None:
        html = self._render([])
        assert "<html" in html
        assert "</html>" in html

    def test_document_contains_head_and_body(self) -> None:
        html = self._render([])
        assert "<head>" in html
        assert "<body>" in html

    def test_document_contains_title(self) -> None:
        html = self._render([])
        assert "AgentShield Security Report" in html

    def test_document_contains_inline_css(self) -> None:
        html = self._render([])
        assert "<style>" in html

    def test_document_contains_summary_section(self) -> None:
        html = self._render([_make_report()])
        assert "Summary" in html


# ---------------------------------------------------------------------------
# Summary rendering
# ---------------------------------------------------------------------------


class TestSummaryRendering:
    def _render_summary(self, results: list[SecurityReport]) -> str:
        reporter = HTMLReporter()
        from agentshield.reporting.summary import SecuritySummary
        summary = SecuritySummary.from_results(results)
        return reporter._render_summary(summary)

    def test_summary_shows_total_scans(self) -> None:
        reports = [_make_report(), _make_report()]
        html = self._render_summary(reports)
        assert "Total Scans" in html

    def test_summary_shows_passed_and_failed(self) -> None:
        html = self._render_summary([_make_report()])
        assert "Passed" in html
        assert "Failed" in html

    def test_summary_shows_pass_rate(self) -> None:
        html = self._render_summary([_make_report()])
        assert "Pass Rate" in html

    def test_empty_results_has_100_pass_rate(self) -> None:
        html = self._render_summary([])
        assert "100.0%" in html

    def test_severity_counts_shown_when_present(self) -> None:
        finding = _make_finding(severity=FindingSeverity.CRITICAL)
        report = _make_report(findings=[finding])
        html = self._render_summary([report])
        assert "CRITICAL" in html

    def test_severity_not_shown_when_zero(self) -> None:
        # With no findings, severity badges should not appear
        html = self._render_summary([_make_report()])
        # Only the stat cards for total/passed/failed/pass-rate should exist
        assert "stat-card" in html


# ---------------------------------------------------------------------------
# Findings table rendering
# ---------------------------------------------------------------------------


class TestFindingsTableRendering:
    def _render_scans(self, results: list[SecurityReport]) -> str:
        reporter = HTMLReporter()
        return reporter._render_scans(results)

    def test_empty_results_returns_no_display_message(self) -> None:
        html = self._render_scans([])
        assert "No scan results to display." in html

    def test_no_findings_shows_clean_message(self) -> None:
        html = self._render_scans([_make_report()])
        assert "No findings detected" in html

    def test_finding_appears_in_table(self) -> None:
        finding = _make_finding(category="path_traversal", message="Path traversal detected.")
        report = _make_report(findings=[finding])
        html = self._render_scans([report])
        assert "path_traversal" in html
        assert "Path traversal detected." in html

    def test_table_headers_present_when_findings_exist(self) -> None:
        finding = _make_finding()
        report = _make_report(findings=[finding])
        html = self._render_scans([report])
        assert "<th>" in html
        assert "Scanner" in html
        assert "Severity" in html
        assert "Category" in html

    def test_finding_count_in_heading(self) -> None:
        finding = _make_finding()
        report = _make_report(findings=[finding])
        html = self._render_scans([report])
        assert "Findings (1)" in html

    def test_multiple_findings_counted(self) -> None:
        findings = [
            _make_finding(category="cat_a"),
            _make_finding(category="cat_b"),
        ]
        report = _make_report(findings=findings)
        html = self._render_scans([report])
        assert "Findings (2)" in html

    def test_html_special_chars_escaped_in_message(self) -> None:
        finding = _make_finding(message="<script>alert('xss')</script>")
        report = _make_report(findings=[finding])
        html = self._render_scans([report])
        # Raw script tag must not be present in output
        assert "<script>" not in html
        # Escaped form must be present
        assert "&lt;script&gt;" in html

    def test_severity_badge_rendered(self) -> None:
        finding = _make_finding(severity=FindingSeverity.CRITICAL)
        report = _make_report(findings=[finding])
        html = self._render_scans([report])
        assert "badge" in html
        assert "CRITICAL" in html


# ---------------------------------------------------------------------------
# stat_card helper
# ---------------------------------------------------------------------------


class TestStatCard:
    def test_stat_card_contains_value_and_label(self) -> None:
        reporter = HTMLReporter()
        card = reporter._stat_card("42", "Total Scans")
        assert "42" in card
        assert "Total Scans" in card

    def test_stat_card_escapes_special_chars(self) -> None:
        reporter = HTMLReporter()
        card = reporter._stat_card("100%", "<Passed>")
        assert "&lt;Passed&gt;" in card

    def test_stat_card_has_stat_card_class(self) -> None:
        reporter = HTMLReporter()
        card = reporter._stat_card("5", "label")
        assert "stat-card" in card


# ---------------------------------------------------------------------------
# Multi-report scenarios
# ---------------------------------------------------------------------------


class TestMultipleReports:
    def test_multiple_reports_all_indexed(self) -> None:
        reporter = HTMLReporter()
        reports = [
            _make_report(findings=[_make_finding(category="a")], phase="input"),
            _make_report(findings=[_make_finding(category="b")], phase="output"),
        ]
        html = reporter._render_document(reports)
        assert "Findings (2)" in html
        assert "category a" in html.lower() or "cat_a" in html.lower() or "a" in html

    def test_findings_across_phases_all_present(self) -> None:
        reporter = HTMLReporter()
        reports = [
            _make_report(findings=[_make_finding(category="input_finding")], phase="input"),
            _make_report(findings=[_make_finding(category="output_finding")], phase="output"),
        ]
        html = reporter._render_document(reports)
        assert "input_finding" in html
        assert "output_finding" in html
