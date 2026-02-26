"""Tests for agentshield.scanners.pii_detector — PiiDetectorScanner.

Covers the scan() coroutine, all built-in PII pattern categories,
extra_patterns injection, and finding structure validation.
"""
from __future__ import annotations

import asyncio
import re

import pytest

from agentshield.core.context import ScanContext
from agentshield.core.scanner import FindingSeverity, ScanPhase
from agentshield.scanners.pii_detector import (
    PiiDetectorScanner,
    PiiPattern,
    _PII_PATTERNS,
)


def _ctx() -> ScanContext:
    return ScanContext(
        phase=ScanPhase.OUTPUT,
        agent_id="test-agent",
        session_id="sess-pii",
    )


def _run(coro):  # type: ignore[no-untyped-def]
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------


class TestInit:
    def test_scanner_name(self) -> None:
        scanner = PiiDetectorScanner()
        assert scanner.name == "pii_detector"

    def test_scanner_phase_is_output(self) -> None:
        scanner = PiiDetectorScanner()
        assert ScanPhase.OUTPUT in scanner.phases

    def test_default_pattern_count(self) -> None:
        scanner = PiiDetectorScanner()
        assert len(scanner.pattern_names) == len(_PII_PATTERNS)

    def test_extra_patterns_extend_defaults(self) -> None:
        extra = PiiPattern(
            name="custom_id",
            pattern=re.compile(r"CUSTID-\d{6}"),
            severity=FindingSeverity.MEDIUM,
            label="Custom ID",
        )
        scanner = PiiDetectorScanner(extra_patterns=[extra])
        assert "custom_id" in scanner.pattern_names
        assert len(scanner.pattern_names) == len(_PII_PATTERNS) + 1

    def test_none_extra_patterns(self) -> None:
        scanner = PiiDetectorScanner(extra_patterns=None)
        assert len(scanner.pattern_names) == len(_PII_PATTERNS)


# ---------------------------------------------------------------------------
# Clean content
# ---------------------------------------------------------------------------


class TestCleanContent:
    def test_plain_text_no_findings(self) -> None:
        scanner = PiiDetectorScanner()
        findings = _run(scanner.scan("The answer to everything is 42.", _ctx()))
        assert findings == []

    def test_empty_string_no_findings(self) -> None:
        scanner = PiiDetectorScanner()
        findings = _run(scanner.scan("", _ctx()))
        assert findings == []


# ---------------------------------------------------------------------------
# SSN detection
# ---------------------------------------------------------------------------


class TestSsnDetection:
    def test_ssn_with_dashes_detected(self) -> None:
        scanner = PiiDetectorScanner()
        content = "SSN: 123-45-6789"
        findings = _run(scanner.scan(content, _ctx()))
        names = [f.details["pii_category"] for f in findings]
        assert "us_ssn" in names

    def test_ssn_without_dashes_detected(self) -> None:
        scanner = PiiDetectorScanner()
        content = "SSN: 123456789"
        findings = _run(scanner.scan(content, _ctx()))
        names = [f.details["pii_category"] for f in findings]
        assert "us_ssn" in names

    def test_invalid_ssn_group_000_not_detected(self) -> None:
        scanner = PiiDetectorScanner()
        # 000 area group is invalid per pattern
        content = "000-45-6789"
        findings = _run(scanner.scan(content, _ctx()))
        names = [f.details["pii_category"] for f in findings]
        assert "us_ssn" not in names


# ---------------------------------------------------------------------------
# Email detection
# ---------------------------------------------------------------------------


class TestEmailDetection:
    def test_email_address_detected(self) -> None:
        scanner = PiiDetectorScanner()
        content = "Contact us at user@example.com for support."
        findings = _run(scanner.scan(content, _ctx()))
        names = [f.details["pii_category"] for f in findings]
        assert "email_address" in names

    def test_email_with_plus_detected(self) -> None:
        scanner = PiiDetectorScanner()
        content = "Email: user+tag@domain.co.uk"
        findings = _run(scanner.scan(content, _ctx()))
        names = [f.details["pii_category"] for f in findings]
        assert "email_address" in names

    def test_severity_is_medium_for_email(self) -> None:
        scanner = PiiDetectorScanner()
        content = "Email: test@example.com"
        findings = _run(scanner.scan(content, _ctx()))
        email_findings = [f for f in findings if f.details["pii_category"] == "email_address"]
        assert email_findings
        assert email_findings[0].severity == FindingSeverity.MEDIUM


# ---------------------------------------------------------------------------
# Phone detection
# ---------------------------------------------------------------------------


class TestPhoneDetection:
    def test_us_phone_dashes_detected(self) -> None:
        scanner = PiiDetectorScanner()
        content = "Call us: 555-867-5309"
        findings = _run(scanner.scan(content, _ctx()))
        names = [f.details["pii_category"] for f in findings]
        assert "us_phone" in names

    def test_us_phone_parens_detected(self) -> None:
        scanner = PiiDetectorScanner()
        content = "Phone: (555) 867-5309"
        findings = _run(scanner.scan(content, _ctx()))
        names = [f.details["pii_category"] for f in findings]
        assert "us_phone" in names

    def test_e164_international_phone_detected(self) -> None:
        scanner = PiiDetectorScanner()
        content = "International: +447911123456"
        findings = _run(scanner.scan(content, _ctx()))
        names = [f.details["pii_category"] for f in findings]
        assert "international_phone_e164" in names


# ---------------------------------------------------------------------------
# Credit card detection
# ---------------------------------------------------------------------------


class TestCreditCardDetection:
    def test_visa_card_detected(self) -> None:
        scanner = PiiDetectorScanner()
        content = "Card: 4532 0151 1283 0366"
        findings = _run(scanner.scan(content, _ctx()))
        names = [f.details["pii_category"] for f in findings]
        assert "credit_card_visa" in names

    def test_mastercard_detected(self) -> None:
        scanner = PiiDetectorScanner()
        content = "Card: 5425 2334 3010 9903"
        findings = _run(scanner.scan(content, _ctx()))
        names = [f.details["pii_category"] for f in findings]
        assert "credit_card_mastercard" in names

    def test_amex_card_detected(self) -> None:
        scanner = PiiDetectorScanner()
        content = "AMEX: 3714 496353 98431"
        findings = _run(scanner.scan(content, _ctx()))
        names = [f.details["pii_category"] for f in findings]
        assert "credit_card_amex" in names

    def test_severity_is_critical_for_credit_card(self) -> None:
        scanner = PiiDetectorScanner()
        content = "Card: 4532 0151 1283 0366"
        findings = _run(scanner.scan(content, _ctx()))
        visa_findings = [f for f in findings if f.details["pii_category"] == "credit_card_visa"]
        if visa_findings:
            assert visa_findings[0].severity == FindingSeverity.CRITICAL


# ---------------------------------------------------------------------------
# IPv4 and date detection
# ---------------------------------------------------------------------------


class TestIpv4Detection:
    def test_ipv4_address_detected(self) -> None:
        scanner = PiiDetectorScanner()
        content = "Server at 192.168.1.100 is reachable."
        findings = _run(scanner.scan(content, _ctx()))
        names = [f.details["pii_category"] for f in findings]
        assert "ipv4_address" in names

    def test_ipv4_severity_is_low(self) -> None:
        scanner = PiiDetectorScanner()
        content = "IP: 10.0.0.1"
        findings = _run(scanner.scan(content, _ctx()))
        ipv4_findings = [f for f in findings if f.details["pii_category"] == "ipv4_address"]
        if ipv4_findings:
            assert ipv4_findings[0].severity == FindingSeverity.LOW


class TestDateDetection:
    def test_mdy_date_detected(self) -> None:
        scanner = PiiDetectorScanner()
        content = "DOB: 01/15/1990"
        findings = _run(scanner.scan(content, _ctx()))
        names = [f.details["pii_category"] for f in findings]
        assert "date_of_birth_mdy" in names

    def test_iso_date_detected(self) -> None:
        scanner = PiiDetectorScanner()
        content = "Date of birth: 1990-01-15"
        findings = _run(scanner.scan(content, _ctx()))
        names = [f.details["pii_category"] for f in findings]
        assert "date_of_birth_iso" in names


# ---------------------------------------------------------------------------
# Finding structure
# ---------------------------------------------------------------------------


class TestFindingStructure:
    def test_finding_category_is_pii_leak(self) -> None:
        scanner = PiiDetectorScanner()
        content = "Email: user@example.com"
        findings = _run(scanner.scan(content, _ctx()))
        assert any(f.category == "pii_leak" for f in findings)

    def test_finding_details_have_required_keys(self) -> None:
        scanner = PiiDetectorScanner()
        content = "user@example.com"
        findings = _run(scanner.scan(content, _ctx()))
        pii_findings = [f for f in findings if f.category == "pii_leak"]
        assert pii_findings
        details = pii_findings[0].details
        assert "pii_category" in details
        assert "occurrence_count" in details
        assert "first_offset" in details

    def test_occurrence_count_for_multiple_emails(self) -> None:
        scanner = PiiDetectorScanner()
        content = "Emails: a@example.com and b@example.com"
        findings = _run(scanner.scan(content, _ctx()))
        email_findings = [f for f in findings if f.details.get("pii_category") == "email_address"]
        assert email_findings
        assert email_findings[0].details["occurrence_count"] == 2

    def test_first_offset_points_to_first_match(self) -> None:
        scanner = PiiDetectorScanner()
        content = "prefix text user@example.com more text"
        findings = _run(scanner.scan(content, _ctx()))
        email_findings = [f for f in findings if f.details.get("pii_category") == "email_address"]
        assert email_findings
        offset = email_findings[0].details["first_offset"]
        # Offset should be within the content bounds
        assert 0 <= offset < len(content)

    def test_scanner_name_in_finding(self) -> None:
        scanner = PiiDetectorScanner()
        findings = _run(scanner.scan("user@example.com", _ctx()))
        for finding in findings:
            assert finding.scanner_name == "pii_detector"


# ---------------------------------------------------------------------------
# Extra pattern injection
# ---------------------------------------------------------------------------


class TestExtraPatterns:
    def test_custom_pattern_detected(self) -> None:
        extra = PiiPattern(
            name="employee_id",
            pattern=re.compile(r"EMP-\d{6}"),
            severity=FindingSeverity.MEDIUM,
            label="Employee ID",
        )
        scanner = PiiDetectorScanner(extra_patterns=[extra])
        content = "Employee ID: EMP-123456"
        findings = _run(scanner.scan(content, _ctx()))
        names = [f.details["pii_category"] for f in findings]
        assert "employee_id" in names

    def test_custom_pattern_not_triggered_by_unrelated(self) -> None:
        extra = PiiPattern(
            name="employee_id",
            pattern=re.compile(r"EMP-\d{6}"),
            severity=FindingSeverity.MEDIUM,
            label="Employee ID",
        )
        scanner = PiiDetectorScanner(extra_patterns=[extra])
        findings = _run(scanner.scan("nothing relevant here", _ctx()))
        names = [f.details["pii_category"] for f in findings]
        assert "employee_id" not in names


# ---------------------------------------------------------------------------
# Pattern names property
# ---------------------------------------------------------------------------


class TestPatternNames:
    def test_pattern_names_returns_list_of_strings(self) -> None:
        scanner = PiiDetectorScanner()
        names = scanner.pattern_names
        assert isinstance(names, list)
        assert all(isinstance(n, str) for n in names)

    def test_pattern_names_includes_known_categories(self) -> None:
        scanner = PiiDetectorScanner()
        names = scanner.pattern_names
        assert "us_ssn" in names
        assert "email_address" in names
        assert "credit_card_visa" in names
        assert "ipv4_address" in names
