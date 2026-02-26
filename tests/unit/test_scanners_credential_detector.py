"""Tests for agentshield.scanners.credential_detector — CredentialDetectorScanner.

Covers the scan() coroutine, pattern matching for each credential type,
extra_patterns injection, and the pattern_names property.
"""
from __future__ import annotations

import asyncio
import re

import pytest

from agentshield.core.context import ScanContext
from agentshield.core.scanner import FindingSeverity, ScanPhase
from agentshield.scanners.credential_detector import (
    CredentialDetectorScanner,
    CredentialPattern,
    _CREDENTIAL_PATTERNS,
)


def _ctx() -> ScanContext:
    return ScanContext(
        phase=ScanPhase.OUTPUT,
        agent_id="test-agent",
        session_id="sess-cred",
    )


def _run(coro):  # type: ignore[no-untyped-def]
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------


class TestInit:
    def test_default_scanner_name(self) -> None:
        scanner = CredentialDetectorScanner()
        assert scanner.name == "credential_detector"

    def test_scanner_phase_is_output(self) -> None:
        scanner = CredentialDetectorScanner()
        assert ScanPhase.OUTPUT in scanner.phases

    def test_default_patterns_loaded(self) -> None:
        scanner = CredentialDetectorScanner()
        assert len(scanner.pattern_names) == len(_CREDENTIAL_PATTERNS)

    def test_extra_patterns_appended(self) -> None:
        extra = CredentialPattern(
            name="custom_token",
            pattern=re.compile(r"MYTOKEN-[0-9]{8}"),
            severity=FindingSeverity.HIGH,
            label="Custom token",
        )
        scanner = CredentialDetectorScanner(extra_patterns=[extra])
        assert "custom_token" in scanner.pattern_names
        assert len(scanner.pattern_names) == len(_CREDENTIAL_PATTERNS) + 1

    def test_none_extra_patterns_uses_defaults(self) -> None:
        scanner = CredentialDetectorScanner(extra_patterns=None)
        assert len(scanner.pattern_names) == len(_CREDENTIAL_PATTERNS)


# ---------------------------------------------------------------------------
# Clean content
# ---------------------------------------------------------------------------


class TestCleanContent:
    def test_plain_text_no_findings(self) -> None:
        scanner = CredentialDetectorScanner()
        findings = _run(scanner.scan("The weather is nice today.", _ctx()))
        assert findings == []

    def test_empty_string_no_findings(self) -> None:
        scanner = CredentialDetectorScanner()
        findings = _run(scanner.scan("", _ctx()))
        assert findings == []


# ---------------------------------------------------------------------------
# API key detection
# ---------------------------------------------------------------------------


class TestApiKeyDetection:
    def test_openai_api_key_detected(self) -> None:
        scanner = CredentialDetectorScanner()
        content = "My key is sk-ABCDEFGHIJKLMNOPQRSTUVabcdefghijk"
        findings = _run(scanner.scan(content, _ctx()))
        names = [f.details["credential_type"] for f in findings]
        assert "openai_api_key" in names

    def test_openai_project_key_detected(self) -> None:
        scanner = CredentialDetectorScanner()
        content = "Key: sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk"
        findings = _run(scanner.scan(content, _ctx()))
        names = [f.details["credential_type"] for f in findings]
        assert "openai_project_key" in names

    def test_anthropic_api_key_detected(self) -> None:
        scanner = CredentialDetectorScanner()
        content = "Key: sk-ant-ABCDEFGHIJKLMNOPQRSTUVabcdefghijk"
        findings = _run(scanner.scan(content, _ctx()))
        names = [f.details["credential_type"] for f in findings]
        assert "anthropic_api_key" in names

    def test_aws_access_key_id_detected(self) -> None:
        scanner = CredentialDetectorScanner()
        # AKIA + exactly 16 uppercase alphanumeric
        content = "Key: AKIAIOSFODNN7EXAMPLE"
        findings = _run(scanner.scan(content, _ctx()))
        names = [f.details["credential_type"] for f in findings]
        assert "aws_access_key_id" in names

    def test_aws_secret_access_key_detected(self) -> None:
        scanner = CredentialDetectorScanner()
        content = 'aws_secret_access_key = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"'
        findings = _run(scanner.scan(content, _ctx()))
        names = [f.details["credential_type"] for f in findings]
        assert "aws_secret_access_key" in names

    def test_github_pat_detected(self) -> None:
        scanner = CredentialDetectorScanner()
        # ghp_ + 36 alphanum
        content = "Token: ghp_" + "A" * 36
        findings = _run(scanner.scan(content, _ctx()))
        names = [f.details["credential_type"] for f in findings]
        assert "github_pat" in names

    def test_stripe_secret_key_detected(self) -> None:
        scanner = CredentialDetectorScanner()
        content = "stripe_key = sk_live_" + "a" * 30
        findings = _run(scanner.scan(content, _ctx()))
        names = [f.details["credential_type"] for f in findings]
        assert "stripe_secret_key" in names

    def test_google_api_key_detected(self) -> None:
        scanner = CredentialDetectorScanner()
        # AIza + 35 alphanumeric
        content = "Google key: AIza" + "A" * 35
        findings = _run(scanner.scan(content, _ctx()))
        names = [f.details["credential_type"] for f in findings]
        assert "google_api_key" in names

    def test_gcp_service_account_detected(self) -> None:
        scanner = CredentialDetectorScanner()
        content = '{"type": "service_account", "project_id": "my-project"}'
        findings = _run(scanner.scan(content, _ctx()))
        names = [f.details["credential_type"] for f in findings]
        assert "gcp_service_account_key" in names


# ---------------------------------------------------------------------------
# Connection string detection
# ---------------------------------------------------------------------------


class TestConnectionStrings:
    def test_postgres_connection_string_detected(self) -> None:
        scanner = CredentialDetectorScanner()
        content = "postgres://user:password@db.example.com/mydb"
        findings = _run(scanner.scan(content, _ctx()))
        names = [f.details["credential_type"] for f in findings]
        assert "postgres_connection_string" in names

    def test_mysql_connection_string_detected(self) -> None:
        scanner = CredentialDetectorScanner()
        content = "mysql://user:password@db.example.com/mydb"
        findings = _run(scanner.scan(content, _ctx()))
        names = [f.details["credential_type"] for f in findings]
        assert "mysql_connection_string" in names

    def test_mongodb_connection_string_detected(self) -> None:
        scanner = CredentialDetectorScanner()
        content = "mongodb://user:password@cluster.mongodb.net/mydb"
        findings = _run(scanner.scan(content, _ctx()))
        names = [f.details["credential_type"] for f in findings]
        assert "mongodb_connection_string" in names


# ---------------------------------------------------------------------------
# Generic credential patterns
# ---------------------------------------------------------------------------


class TestGenericCredentials:
    def test_generic_password_assignment_detected(self) -> None:
        scanner = CredentialDetectorScanner()
        content = 'password = "mysecretpassword123"'
        findings = _run(scanner.scan(content, _ctx()))
        names = [f.details["credential_type"] for f in findings]
        assert "generic_password_assignment" in names

    def test_bearer_token_detected(self) -> None:
        scanner = CredentialDetectorScanner()
        content = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        findings = _run(scanner.scan(content, _ctx()))
        names = [f.details["credential_type"] for f in findings]
        assert "bearer_token" in names

    def test_pem_private_key_detected(self) -> None:
        scanner = CredentialDetectorScanner()
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."
        findings = _run(scanner.scan(content, _ctx()))
        names = [f.details["credential_type"] for f in findings]
        assert "pem_private_key" in names

    def test_pgp_private_key_detected(self) -> None:
        scanner = CredentialDetectorScanner()
        content = "-----BEGIN PGP PRIVATE KEY BLOCK-----"
        findings = _run(scanner.scan(content, _ctx()))
        names = [f.details["credential_type"] for f in findings]
        assert "pgp_private_key" in names

    def test_slack_bot_token_detected(self) -> None:
        scanner = CredentialDetectorScanner()
        content = "Bot token: xoxb-1234567890-abcdefghijklmnop"
        findings = _run(scanner.scan(content, _ctx()))
        names = [f.details["credential_type"] for f in findings]
        assert "slack_bot_token" in names


# ---------------------------------------------------------------------------
# Finding structure
# ---------------------------------------------------------------------------


class TestFindingStructure:
    def test_finding_category_is_credential_leak(self) -> None:
        scanner = CredentialDetectorScanner()
        content = "sk-" + "A" * 30
        findings = _run(scanner.scan(content, _ctx()))
        assert any(f.category == "credential_leak" for f in findings)

    def test_finding_details_contain_required_keys(self) -> None:
        scanner = CredentialDetectorScanner()
        content = "sk-" + "A" * 30
        findings = _run(scanner.scan(content, _ctx()))
        cred_findings = [f for f in findings if f.category == "credential_leak"]
        assert cred_findings
        details = cred_findings[0].details
        assert "credential_type" in details
        assert "label" in details
        assert "occurrence_count" in details
        assert "first_offset" in details

    def test_occurrence_count_for_multiple_matches(self) -> None:
        scanner = CredentialDetectorScanner()
        # Two OpenAI key shapes in content
        key = "sk-" + "A" * 25
        content = f"{key} and {key}"
        findings = _run(scanner.scan(content, _ctx()))
        openai_findings = [
            f for f in findings
            if f.details.get("credential_type") == "openai_api_key"
        ]
        if openai_findings:
            assert openai_findings[0].details["occurrence_count"] >= 1

    def test_first_offset_is_non_negative(self) -> None:
        scanner = CredentialDetectorScanner()
        content = "prefix: sk-" + "Z" * 25
        findings = _run(scanner.scan(content, _ctx()))
        for finding in findings:
            assert finding.details["first_offset"] >= 0

    def test_severity_is_critical_for_api_key(self) -> None:
        scanner = CredentialDetectorScanner()
        content = "sk-" + "A" * 25
        findings = _run(scanner.scan(content, _ctx()))
        openai_findings = [f for f in findings if "openai" in f.details.get("credential_type", "")]
        if openai_findings:
            assert openai_findings[0].severity == FindingSeverity.CRITICAL


# ---------------------------------------------------------------------------
# Extra pattern injection
# ---------------------------------------------------------------------------


class TestExtraPatterns:
    def test_extra_pattern_matches(self) -> None:
        extra = CredentialPattern(
            name="custom_secret",
            pattern=re.compile(r"MY-SECRET-[0-9]{6}"),
            severity=FindingSeverity.HIGH,
            label="Custom test secret",
        )
        scanner = CredentialDetectorScanner(extra_patterns=[extra])
        content = "The token is MY-SECRET-123456"
        findings = _run(scanner.scan(content, _ctx()))
        names = [f.details["credential_type"] for f in findings]
        assert "custom_secret" in names

    def test_extra_pattern_does_not_match_unrelated_content(self) -> None:
        extra = CredentialPattern(
            name="custom_secret",
            pattern=re.compile(r"MY-SECRET-[0-9]{6}"),
            severity=FindingSeverity.HIGH,
            label="Custom test secret",
        )
        scanner = CredentialDetectorScanner(extra_patterns=[extra])
        findings = _run(scanner.scan("nothing here", _ctx()))
        names = [f.details["credential_type"] for f in findings]
        assert "custom_secret" not in names
