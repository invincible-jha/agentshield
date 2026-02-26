"""Tests for agentshield.scanners.output_validator — OutputValidator."""
from __future__ import annotations

import asyncio

import pytest

from agentshield.core.context import ScanContext
from agentshield.core.scanner import FindingSeverity, ScanPhase
from agentshield.scanners.output_validator import OutputValidator, _FORBIDDEN_PATTERN_REGISTRY


def _ctx() -> ScanContext:
    return ScanContext(phase=ScanPhase.OUTPUT, agent_id="test-agent", session_id="sess-1")


def _run(coro):  # type: ignore[no-untyped-def]
    return asyncio.run(coro)


class TestOutputValidatorInit:
    def test_default_initialisation(self) -> None:
        validator = OutputValidator()
        assert validator.max_output_length == 16_384
        assert validator.check_credential_leakage is True
        assert len(validator.active_pattern_names) == len(_FORBIDDEN_PATTERN_REGISTRY)

    def test_custom_max_output_length(self) -> None:
        validator = OutputValidator(max_output_length=1000)
        assert validator.max_output_length == 1000

    def test_empty_forbidden_patterns(self) -> None:
        validator = OutputValidator(forbidden_patterns=[])
        assert validator.active_pattern_names == []

    def test_specific_forbidden_patterns(self) -> None:
        validator = OutputValidator(forbidden_patterns=["openai_key_shape", "aws_key_shape"])
        assert "openai_key_shape" in validator.active_pattern_names
        assert "aws_key_shape" in validator.active_pattern_names
        assert len(validator.active_pattern_names) == 2

    def test_unknown_pattern_name_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown forbidden pattern"):
            OutputValidator(forbidden_patterns=["nonexistent_pattern"])

    def test_active_pattern_names_returns_copy(self) -> None:
        validator = OutputValidator(forbidden_patterns=["openai_key_shape"])
        names = validator.active_pattern_names
        names.append("extra")
        assert len(validator.active_pattern_names) == 1


class TestLengthCheck:
    def test_short_content_no_findings(self) -> None:
        validator = OutputValidator(max_output_length=100)
        findings = _run(validator.scan("hello", _ctx()))
        assert not any(f.category == "output_length_exceeded" for f in findings)

    def test_over_limit_raises_high(self) -> None:
        validator = OutputValidator(max_output_length=10)
        findings = _run(validator.scan("a" * 11, _ctx()))
        assert any(
            f.category == "output_length_exceeded" and f.severity == FindingSeverity.HIGH
            for f in findings
        )

    def test_exactly_at_limit_passes(self) -> None:
        validator = OutputValidator(max_output_length=10)
        findings = _run(validator.scan("a" * 10, _ctx()))
        assert not any(f.category == "output_length_exceeded" for f in findings)

    def test_length_finding_includes_details(self) -> None:
        validator = OutputValidator(max_output_length=5)
        findings = _run(validator.scan("a" * 10, _ctx()))
        assert findings
        assert "length" in findings[0].details
        assert "max_output_length" in findings[0].details


class TestForbiddenPatterns:
    def test_clean_content_no_findings(self) -> None:
        validator = OutputValidator()
        findings = _run(validator.scan("The weather is sunny today.", _ctx()))
        assert not any(f.category == "data_leakage" for f in findings)

    def test_openai_key_shape_detected(self) -> None:
        validator = OutputValidator()
        content = "The key is sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        findings = _run(validator.scan(content, _ctx()))
        assert any(
            f.category == "data_leakage"
            and f.details.get("pattern_name") == "openai_key_shape"
            and f.severity == FindingSeverity.CRITICAL
            for f in findings
        )

    def test_aws_key_shape_detected(self) -> None:
        validator = OutputValidator()
        # AWS key shape: AKIA + exactly 16 uppercase alphanumeric chars.
        content = "AWS key: AKIAIOSFODNN7EXAMPLE"
        findings = _run(validator.scan(content, _ctx()))
        assert any(
            f.details.get("pattern_name") == "aws_key_shape"
            for f in findings
        )

    def test_pem_private_key_detected(self) -> None:
        validator = OutputValidator()
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQ..."
        findings = _run(validator.scan(content, _ctx()))
        assert any(
            f.details.get("pattern_name") == "pem_private_key_header"
            for f in findings
        )

    def test_internal_ip_disclosure(self) -> None:
        validator = OutputValidator()
        content = "The server is at 192.168.1.100 for internal use."
        findings = _run(validator.scan(content, _ctx()))
        assert any(
            f.details.get("pattern_name") == "internal_ip_disclosure"
            for f in findings
        )

    def test_stack_trace_disclosure(self) -> None:
        validator = OutputValidator()
        content = "Traceback (most recent call last):\n  File 'app.py', line 42"
        findings = _run(validator.scan(content, _ctx()))
        assert any(
            f.details.get("pattern_name") == "stack_trace_disclosure"
            for f in findings
        )

    def test_password_in_output(self) -> None:
        validator = OutputValidator()
        content = 'password = "mysecretpassword123"'
        findings = _run(validator.scan(content, _ctx()))
        assert any(
            f.details.get("pattern_name") == "password_in_output"
            for f in findings
        )

    def test_disabled_patterns_not_checked(self) -> None:
        validator = OutputValidator(forbidden_patterns=[])
        content = "The key is sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        findings = _run(validator.scan(content, _ctx()))
        assert not any(f.category == "data_leakage" for f in findings)

    def test_selective_pattern_checking(self) -> None:
        validator = OutputValidator(forbidden_patterns=["pem_private_key_header"])
        # OpenAI key should not be flagged
        content = "key: sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        findings = _run(validator.scan(content, _ctx()))
        assert not any(
            f.details.get("pattern_name") == "openai_key_shape"
            for f in findings
        )

    def test_finding_includes_match_offsets(self) -> None:
        validator = OutputValidator(forbidden_patterns=["openai_key_shape"])
        content = "The key is sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        findings = _run(validator.scan(content, _ctx()))
        if findings:
            assert "match_start" in findings[0].details
            assert "match_end" in findings[0].details


class TestForbiddenPatternRegistry:
    def test_registry_has_expected_keys(self) -> None:
        expected = {
            "openai_key_shape",
            "openai_project_key_shape",
            "anthropic_key_shape",
            "aws_key_shape",
            "github_pat_shape",
            "pem_private_key_header",
            "password_in_output",
            "bearer_token_in_output",
            "internal_ip_disclosure",
            "stack_trace_disclosure",
        }
        assert expected == set(_FORBIDDEN_PATTERN_REGISTRY.keys())

    def test_registry_entries_have_correct_structure(self) -> None:
        for name, (description, severity, pattern) in _FORBIDDEN_PATTERN_REGISTRY.items():
            assert isinstance(description, str)
            assert isinstance(severity, FindingSeverity)
            import re
            assert isinstance(pattern, re.Pattern)

    def test_scanner_name(self) -> None:
        assert OutputValidator().name == "output_validator"

    def test_scanner_phases(self) -> None:
        from agentshield.core.scanner import ScanPhase
        assert ScanPhase.OUTPUT in OutputValidator().phases
