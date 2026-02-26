"""Unit tests for agentshield.core.exceptions."""
from __future__ import annotations

import pytest

from agentshield.core.exceptions import AgentShieldError, ConfigError, SecurityBlockError
from agentshield.core.result import SecurityReport
from agentshield.core.scanner import Finding, FindingSeverity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_report() -> SecurityReport:
    finding = Finding(
        scanner_name="test_scanner",
        severity=FindingSeverity.CRITICAL,
        category="test_category",
        message="Test finding",
    )
    return SecurityReport(findings=[finding], phase="input")


# ---------------------------------------------------------------------------
# AgentShieldError
# ---------------------------------------------------------------------------


class TestAgentShieldError:
    def test_is_exception_subclass(self) -> None:
        error = AgentShieldError("base error")
        assert isinstance(error, Exception)

    def test_message_preserved(self) -> None:
        error = AgentShieldError("something went wrong")
        assert str(error) == "something went wrong"


# ---------------------------------------------------------------------------
# SecurityBlockError
# ---------------------------------------------------------------------------


class TestSecurityBlockError:
    def test_inherits_agentshield_error(self) -> None:
        error = SecurityBlockError("blocked")
        assert isinstance(error, AgentShieldError)

    def test_message_attribute(self) -> None:
        error = SecurityBlockError("execution blocked")
        assert error.message == "execution blocked"

    def test_str_matches_message(self) -> None:
        error = SecurityBlockError("execution blocked")
        assert str(error) == "execution blocked"

    def test_report_none_by_default(self) -> None:
        error = SecurityBlockError("blocked")
        assert error.report is None

    def test_report_attached_when_provided(self) -> None:
        report = _make_report()
        error = SecurityBlockError("blocked by policy", report=report)
        assert error.report is report

    def test_repr_contains_message(self) -> None:
        error = SecurityBlockError("blocked!")
        assert "blocked!" in repr(error)

    def test_can_be_raised_and_caught(self) -> None:
        with pytest.raises(SecurityBlockError) as exc_info:
            raise SecurityBlockError("critical finding", report=_make_report())
        assert exc_info.value.message == "critical finding"
        assert exc_info.value.report is not None

    def test_is_catchable_as_agentshield_error(self) -> None:
        with pytest.raises(AgentShieldError):
            raise SecurityBlockError("blocked")


# ---------------------------------------------------------------------------
# ConfigError
# ---------------------------------------------------------------------------


class TestConfigError:
    def test_inherits_agentshield_error(self) -> None:
        error = ConfigError("bad config")
        assert isinstance(error, AgentShieldError)

    def test_reason_attribute(self) -> None:
        error = ConfigError("invalid field")
        assert error.reason == "invalid field"

    def test_path_none_by_default(self) -> None:
        error = ConfigError("bad config")
        assert error.path is None

    def test_path_preserved_when_provided(self) -> None:
        error = ConfigError("parse error", path="/etc/shield.yaml")
        assert error.path == "/etc/shield.yaml"

    def test_str_includes_reason(self) -> None:
        error = ConfigError("missing required key")
        assert "missing required key" in str(error)

    def test_str_includes_path_when_provided(self) -> None:
        error = ConfigError("bad value", path="shield.yaml")
        message = str(error)
        assert "shield.yaml" in message
        assert "bad value" in message

    def test_str_omits_path_when_none(self) -> None:
        error = ConfigError("missing key")
        assert "path=" not in str(error)

    def test_repr_contains_reason_and_path(self) -> None:
        error = ConfigError("bad yaml", path="cfg.yaml")
        representation = repr(error)
        assert "bad yaml" in representation
        assert "cfg.yaml" in representation

    def test_can_be_raised_and_caught(self) -> None:
        with pytest.raises(ConfigError) as exc_info:
            raise ConfigError("field error", path="shield.yaml")
        assert exc_info.value.reason == "field error"
        assert exc_info.value.path == "shield.yaml"
