"""Tests for agentshield.scanners.output_safety — OutputSafetyScanner."""
from __future__ import annotations

import asyncio

import pytest

from agentshield.core.context import ScanContext
from agentshield.core.scanner import FindingSeverity, ScanPhase
from agentshield.scanners.output_safety import (
    DEFAULT_MAX_LENGTH,
    DEFAULT_MAX_LINE_LENGTH,
    DEFAULT_MAX_NON_ASCII_RATIO,
    DEFAULT_REPETITION_RATIO_THRESHOLD,
    DEFAULT_REPETITION_WINDOW,
    DEFAULT_WARN_LENGTH,
    OutputSafetyScanner,
)


def _ctx() -> ScanContext:
    return ScanContext(phase=ScanPhase.OUTPUT, agent_id="test-agent", session_id="sess-1")


def _run(coro):  # type: ignore[no-untyped-def]
    return asyncio.run(coro)


class TestDefaults:
    def test_default_thresholds(self) -> None:
        scanner = OutputSafetyScanner()
        assert scanner.max_length == DEFAULT_MAX_LENGTH
        assert scanner.warn_length == DEFAULT_WARN_LENGTH
        assert scanner.max_line_length == DEFAULT_MAX_LINE_LENGTH
        assert scanner.repetition_window == DEFAULT_REPETITION_WINDOW
        assert scanner.repetition_ratio_threshold == DEFAULT_REPETITION_RATIO_THRESHOLD
        assert scanner.max_non_ascii_ratio == DEFAULT_MAX_NON_ASCII_RATIO

    def test_custom_thresholds(self) -> None:
        scanner = OutputSafetyScanner(max_length=1000, warn_length=500)
        assert scanner.max_length == 1000
        assert scanner.warn_length == 500

    def test_scanner_name(self) -> None:
        assert OutputSafetyScanner().name == "output_safety"

    def test_scanner_phases(self) -> None:
        assert ScanPhase.OUTPUT in OutputSafetyScanner().phases


class TestLengthChecks:
    def test_clean_short_content_passes(self) -> None:
        scanner = OutputSafetyScanner()
        findings = _run(scanner.scan("Hello, world!", _ctx()))
        assert not any(f.category in {"output_length_exceeded", "output_length_warning"} for f in findings)

    def test_over_max_length_is_critical(self) -> None:
        scanner = OutputSafetyScanner(max_length=10, warn_length=5)
        findings = _run(scanner.scan("a" * 11, _ctx()))
        assert any(
            f.category == "output_length_exceeded" and f.severity == FindingSeverity.CRITICAL
            for f in findings
        )

    def test_over_warn_length_is_medium(self) -> None:
        scanner = OutputSafetyScanner(max_length=20, warn_length=10)
        findings = _run(scanner.scan("a" * 15, _ctx()))
        assert any(
            f.category == "output_length_warning" and f.severity == FindingSeverity.MEDIUM
            for f in findings
        )

    def test_exactly_at_max_length_no_finding(self) -> None:
        scanner = OutputSafetyScanner(max_length=10, warn_length=5)
        findings = _run(scanner.scan("a" * 10, _ctx()))
        assert not any(f.category == "output_length_exceeded" for f in findings)

    def test_length_finding_includes_details(self) -> None:
        scanner = OutputSafetyScanner(max_length=5, warn_length=3)
        findings = _run(scanner.scan("a" * 6, _ctx()))
        length_findings = [f for f in findings if f.category == "output_length_exceeded"]
        assert length_findings
        assert "length" in length_findings[0].details
        assert "max_length" in length_findings[0].details


class TestLineLength:
    def test_normal_lines_pass(self) -> None:
        scanner = OutputSafetyScanner()
        content = "This is a normal line.\nAnd another one."
        findings = _run(scanner.scan(content, _ctx()))
        assert not any(f.category == "overlong_line" for f in findings)

    def test_overlong_line_raises_low(self) -> None:
        scanner = OutputSafetyScanner(max_line_length=50)
        content = "a" * 51
        findings = _run(scanner.scan(content, _ctx()))
        assert any(
            f.category == "overlong_line" and f.severity == FindingSeverity.LOW
            for f in findings
        )

    def test_overlong_line_details_include_worst_line(self) -> None:
        scanner = OutputSafetyScanner(max_line_length=10)
        content = "short\n" + "a" * 20 + "\nshort"
        findings = _run(scanner.scan(content, _ctx()))
        line_findings = [f for f in findings if f.category == "overlong_line"]
        assert line_findings
        assert "worst_line_number" in line_findings[0].details
        assert "worst_line_length" in line_findings[0].details

    def test_multiple_overlong_lines_counted(self) -> None:
        scanner = OutputSafetyScanner(max_line_length=5)
        content = "a" * 10 + "\n" + "b" * 10
        findings = _run(scanner.scan(content, _ctx()))
        line_findings = [f for f in findings if f.category == "overlong_line"]
        assert line_findings
        assert line_findings[0].details.get("overlong_line_count") == 2


class TestNullBytes:
    def test_content_without_null_bytes_passes(self) -> None:
        scanner = OutputSafetyScanner()
        findings = _run(scanner.scan("normal text", _ctx()))
        assert not any(f.category == "null_byte_in_output" for f in findings)

    def test_null_byte_raises_high(self) -> None:
        scanner = OutputSafetyScanner()
        findings = _run(scanner.scan("before\x00after", _ctx()))
        assert any(
            f.category == "null_byte_in_output" and f.severity == FindingSeverity.HIGH
            for f in findings
        )

    def test_multiple_null_bytes_counted(self) -> None:
        scanner = OutputSafetyScanner()
        findings = _run(scanner.scan("a\x00b\x00c", _ctx()))
        null_findings = [f for f in findings if f.category == "null_byte_in_output"]
        assert null_findings
        assert null_findings[0].details.get("null_byte_count") == 2


class TestRepetitionDetection:
    def test_non_repetitive_passes(self) -> None:
        scanner = OutputSafetyScanner()
        text = " ".join(f"word{i}" for i in range(60))
        findings = _run(scanner.scan(text, _ctx()))
        assert not any(f.category == "repetitive_content" for f in findings)

    def test_highly_repetitive_raises_high(self) -> None:
        scanner = OutputSafetyScanner(repetition_window=10, repetition_ratio_threshold=0.5)
        content = " ".join(["repeat"] * 10)
        findings = _run(scanner.scan(content, _ctx()))
        assert any(
            f.category == "repetitive_content" and f.severity == FindingSeverity.HIGH
            for f in findings
        )

    def test_less_than_window_words_not_checked(self) -> None:
        scanner = OutputSafetyScanner(repetition_window=50)
        text = " ".join(["repeat"] * 10)
        findings = _run(scanner.scan(text, _ctx()))
        assert not any(f.category == "repetitive_content" for f in findings)

    def test_repetitive_content_details(self) -> None:
        scanner = OutputSafetyScanner(repetition_window=10, repetition_ratio_threshold=0.5)
        content = " ".join(["spam"] * 10)
        findings = _run(scanner.scan(content, _ctx()))
        rep_findings = [f for f in findings if f.category == "repetitive_content"]
        if rep_findings:
            assert "most_common_token" in rep_findings[0].details
            assert "repetition_ratio" in rep_findings[0].details


class TestNonAsciiRatio:
    def test_normal_ascii_passes(self) -> None:
        scanner = OutputSafetyScanner()
        findings = _run(scanner.scan("Hello world!", _ctx()))
        assert not any(f.category == "encoding_anomaly" for f in findings)

    def test_high_non_ascii_raises_medium(self) -> None:
        scanner = OutputSafetyScanner(max_non_ascii_ratio=0.1)
        content = "a" * 5 + "\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9"
        findings = _run(scanner.scan(content, _ctx()))
        assert any(
            f.category == "encoding_anomaly" and f.severity == FindingSeverity.MEDIUM
            for f in findings
        )

    def test_empty_content_no_encoding_finding(self) -> None:
        scanner = OutputSafetyScanner()
        findings = _run(scanner.scan("", _ctx()))
        assert not any(f.category == "encoding_anomaly" for f in findings)

    def test_encoding_anomaly_details(self) -> None:
        scanner = OutputSafetyScanner(max_non_ascii_ratio=0.1)
        content = "aa" + "\u00e9" * 10
        findings = _run(scanner.scan(content, _ctx()))
        enc_findings = [f for f in findings if f.category == "encoding_anomaly"]
        if enc_findings:
            assert "non_ascii_ratio" in enc_findings[0].details
            assert "non_ascii_count" in enc_findings[0].details


class TestControlCharacters:
    def test_normal_whitespace_passes(self) -> None:
        scanner = OutputSafetyScanner()
        findings = _run(scanner.scan("line1\nline2\ttab", _ctx()))
        assert not any(f.category == "control_character_anomaly" for f in findings)

    def test_control_character_raises_medium(self) -> None:
        scanner = OutputSafetyScanner()
        # ESC character (U+001B)
        findings = _run(scanner.scan("text\x1bmore", _ctx()))
        assert any(
            f.category == "control_character_anomaly" and f.severity == FindingSeverity.MEDIUM
            for f in findings
        )

    def test_control_character_details_include_code_points(self) -> None:
        scanner = OutputSafetyScanner()
        findings = _run(scanner.scan("text\x1b\x07more", _ctx()))
        ctrl_findings = [f for f in findings if f.category == "control_character_anomaly"]
        if ctrl_findings:
            assert "unique_code_points" in ctrl_findings[0].details
