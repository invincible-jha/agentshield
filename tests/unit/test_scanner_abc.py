"""Unit tests for agentshield.core.scanner — ABC, enums, Finding."""
from __future__ import annotations

import pytest

from agentshield.core.context import ScanContext
from agentshield.core.scanner import (
    Finding,
    FindingSeverity,
    ScanPhase,
    Scanner,
)


# ---------------------------------------------------------------------------
# ScanPhase enum
# ---------------------------------------------------------------------------


class TestScanPhase:
    def test_input_value(self) -> None:
        assert ScanPhase.INPUT.value == "input"

    def test_output_value(self) -> None:
        assert ScanPhase.OUTPUT.value == "output"

    def test_tool_call_value(self) -> None:
        assert ScanPhase.TOOL_CALL.value == "tool_call"

    def test_all_three_phases_exist(self) -> None:
        phases = {p.value for p in ScanPhase}
        assert phases == {"input", "output", "tool_call"}

    def test_is_string_enum(self) -> None:
        assert isinstance(ScanPhase.INPUT, str)


# ---------------------------------------------------------------------------
# FindingSeverity enum
# ---------------------------------------------------------------------------


class TestFindingSeverity:
    def test_info_numeric_is_zero(self) -> None:
        assert FindingSeverity.INFO.numeric == 0

    def test_low_numeric_is_one(self) -> None:
        assert FindingSeverity.LOW.numeric == 1

    def test_medium_numeric_is_two(self) -> None:
        assert FindingSeverity.MEDIUM.numeric == 2

    def test_high_numeric_is_three(self) -> None:
        assert FindingSeverity.HIGH.numeric == 3

    def test_critical_numeric_is_four(self) -> None:
        assert FindingSeverity.CRITICAL.numeric == 4

    def test_critical_greater_than_high(self) -> None:
        assert FindingSeverity.CRITICAL > FindingSeverity.HIGH

    def test_high_greater_than_medium(self) -> None:
        assert FindingSeverity.HIGH > FindingSeverity.MEDIUM

    def test_medium_greater_than_low(self) -> None:
        assert FindingSeverity.MEDIUM > FindingSeverity.LOW

    def test_low_greater_than_info(self) -> None:
        assert FindingSeverity.LOW > FindingSeverity.INFO

    def test_critical_ge_critical(self) -> None:
        assert FindingSeverity.CRITICAL >= FindingSeverity.CRITICAL

    def test_info_le_critical(self) -> None:
        assert FindingSeverity.INFO <= FindingSeverity.CRITICAL

    def test_info_lt_low(self) -> None:
        assert FindingSeverity.INFO < FindingSeverity.LOW

    def test_ge_returns_not_implemented_for_wrong_type(self) -> None:
        result = FindingSeverity.HIGH.__ge__(42)
        assert result is NotImplemented

    def test_gt_returns_not_implemented_for_wrong_type(self) -> None:
        result = FindingSeverity.HIGH.__gt__(42)
        assert result is NotImplemented

    def test_le_returns_not_implemented_for_wrong_type(self) -> None:
        result = FindingSeverity.HIGH.__le__(42)
        assert result is NotImplemented

    def test_lt_returns_not_implemented_for_wrong_type(self) -> None:
        result = FindingSeverity.HIGH.__lt__(42)
        assert result is NotImplemented

    def test_is_string_enum(self) -> None:
        assert isinstance(FindingSeverity.HIGH, str)

    def test_ordering_preserved_in_sorted_list(self) -> None:
        severities = [FindingSeverity.HIGH, FindingSeverity.INFO, FindingSeverity.CRITICAL]
        sorted_severities = sorted(severities)
        assert sorted_severities == [
            FindingSeverity.INFO,
            FindingSeverity.HIGH,
            FindingSeverity.CRITICAL,
        ]


# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------


class TestFinding:
    def _make_finding(
        self,
        scanner_name: str = "test_scanner",
        severity: FindingSeverity = FindingSeverity.MEDIUM,
        category: str = "test_category",
        message: str = "Test message",
        details: dict[str, object] | None = None,
    ) -> Finding:
        return Finding(
            scanner_name=scanner_name,
            severity=severity,
            category=category,
            message=message,
            details=details or {},
        )

    def test_scanner_name_stored(self) -> None:
        finding = self._make_finding(scanner_name="pii_detector")
        assert finding.scanner_name == "pii_detector"

    def test_severity_stored(self) -> None:
        finding = self._make_finding(severity=FindingSeverity.HIGH)
        assert finding.severity == FindingSeverity.HIGH

    def test_category_stored(self) -> None:
        finding = self._make_finding(category="pii_leak")
        assert finding.category == "pii_leak"

    def test_message_stored(self) -> None:
        finding = self._make_finding(message="PII detected")
        assert finding.message == "PII detected"

    def test_details_defaults_to_empty_dict(self) -> None:
        finding = Finding(
            scanner_name="s",
            severity=FindingSeverity.INFO,
            category="c",
            message="m",
        )
        assert finding.details == {}

    def test_details_stored(self) -> None:
        finding = self._make_finding(details={"key": "value", "count": 3})
        assert finding.details["key"] == "value"
        assert finding.details["count"] == 3

    def test_to_dict_keys(self) -> None:
        finding = self._make_finding()
        result = finding.to_dict()
        assert set(result.keys()) == {
            "scanner_name", "severity", "category", "message", "details"
        }

    def test_to_dict_severity_is_string(self) -> None:
        finding = self._make_finding(severity=FindingSeverity.HIGH)
        result = finding.to_dict()
        assert result["severity"] == "high"

    def test_to_dict_details_preserved(self) -> None:
        finding = self._make_finding(details={"offset": 42})
        result = finding.to_dict()
        assert result["details"] == {"offset": 42}

    def test_to_dict_scanner_name_preserved(self) -> None:
        finding = self._make_finding(scanner_name="my_scanner")
        assert finding.to_dict()["scanner_name"] == "my_scanner"


# ---------------------------------------------------------------------------
# Scanner ABC
# ---------------------------------------------------------------------------


class _ConcreteScanner(Scanner):
    """Minimal concrete implementation for testing."""

    name: str = "concrete_test"
    phases: list[ScanPhase] = [ScanPhase.INPUT]

    async def scan(self, content: str, context: ScanContext) -> list[Finding]:
        return []


class _MultiPhaseScanner(Scanner):
    name: str = "multi_phase_test"
    phases: list[ScanPhase] = [ScanPhase.INPUT, ScanPhase.OUTPUT]

    async def scan(self, content: str, context: ScanContext) -> list[Finding]:
        return []


class TestScannerABC:
    def test_cannot_instantiate_abc_directly(self) -> None:
        with pytest.raises(TypeError):
            Scanner()  # type: ignore[abstract]

    def test_concrete_scanner_instantiates(self) -> None:
        scanner = _ConcreteScanner()
        assert scanner is not None

    def test_name_attribute(self) -> None:
        scanner = _ConcreteScanner()
        assert scanner.name == "concrete_test"

    def test_phases_attribute(self) -> None:
        scanner = _ConcreteScanner()
        assert ScanPhase.INPUT in scanner.phases

    def test_multi_phase_scanner_has_both_phases(self) -> None:
        scanner = _MultiPhaseScanner()
        assert ScanPhase.INPUT in scanner.phases
        assert ScanPhase.OUTPUT in scanner.phases

    def test_repr_contains_name(self) -> None:
        scanner = _ConcreteScanner()
        assert "concrete_test" in repr(scanner)

    def test_repr_contains_phases(self) -> None:
        scanner = _ConcreteScanner()
        assert "ScanPhase.INPUT" in repr(scanner)

    async def test_scan_returns_empty_list_for_clean_input(self) -> None:
        scanner = _ConcreteScanner()
        context = ScanContext(phase=ScanPhase.INPUT)
        results = await scanner.scan("clean content", context)
        assert results == []
