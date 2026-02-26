"""Tests for agentshield.scanners.tool_call_checker — ToolCallChecker."""
from __future__ import annotations

import asyncio
import json
import time

import pytest

from agentshield.core.context import ScanContext
from agentshield.core.scanner import FindingSeverity, ScanPhase
from agentshield.scanners.tool_call_checker import ToolCallChecker


def _ctx(tool_name: str = "read_file", session_id: str = "sess-1") -> ScanContext:
    return ScanContext(
        phase=ScanPhase.TOOL_CALL,
        agent_id="test-agent",
        session_id=session_id,
        tool_name=tool_name,
    )


def _args(**kwargs: object) -> str:
    return json.dumps(kwargs)


def _run(coro):  # type: ignore[no-untyped-def]
    return asyncio.run(coro)


class TestAllowlist:
    def test_allowed_tool_passes(self) -> None:
        checker = ToolCallChecker(allowed_tools={"read_file", "write_file"})
        findings = _run(checker.scan(_args(path="data.csv"), _ctx("read_file")))
        cats = [f.category for f in findings]
        assert "tool_not_allowed" not in cats

    def test_disallowed_tool_raises_high(self) -> None:
        checker = ToolCallChecker(allowed_tools={"read_file"})
        findings = _run(checker.scan(_args(), _ctx("delete_file")))
        assert any(
            f.category == "tool_not_allowed" and f.severity == FindingSeverity.HIGH
            for f in findings
        )

    def test_empty_allowlist_permits_all(self) -> None:
        checker = ToolCallChecker(allowed_tools=set())
        findings = _run(checker.scan(_args(), _ctx("anything")))
        assert not any(f.category == "tool_not_allowed" for f in findings)

    def test_default_allowlist_permits_all(self) -> None:
        checker = ToolCallChecker()
        findings = _run(checker.scan(_args(), _ctx("anything_at_all")))
        assert not any(f.category == "tool_not_allowed" for f in findings)

    def test_finding_contains_allowed_tools_list(self) -> None:
        checker = ToolCallChecker(allowed_tools={"a", "b"})
        findings = _run(checker.scan(_args(), _ctx("c")))
        assert findings
        assert "allowed_tools" in findings[0].details


class TestArgsStructure:
    def test_valid_json_object_passes(self) -> None:
        checker = ToolCallChecker()
        findings = _run(checker.scan('{"path": "file.txt"}', _ctx()))
        assert not any(f.category == "tool_arg_parse_error" for f in findings)

    def test_invalid_json_returns_medium(self) -> None:
        checker = ToolCallChecker()
        findings = _run(checker.scan("not json at all", _ctx()))
        assert any(
            f.category == "tool_arg_parse_error" and f.severity == FindingSeverity.MEDIUM
            for f in findings
        )

    def test_json_array_returns_low(self) -> None:
        checker = ToolCallChecker()
        findings = _run(checker.scan("[1, 2, 3]", _ctx()))
        assert any(
            f.category == "tool_arg_format" and f.severity == FindingSeverity.LOW
            for f in findings
        )

    def test_invalid_json_stops_further_checks(self) -> None:
        # rate limit and chain depth should not fire when parse fails
        checker = ToolCallChecker(max_calls_per_minute=1, max_chain_depth=1)
        findings = _run(checker.scan("bad json", _ctx()))
        # Only the parse error, no rate/chain findings
        categories = [f.category for f in findings]
        assert "rate_limit_exceeded" not in categories
        assert "chain_depth_exceeded" not in categories


class TestRateLimit:
    def test_within_limit_no_finding(self) -> None:
        checker = ToolCallChecker(max_calls_per_minute=5)
        checker.reset_rate_counters()
        for _ in range(5):
            findings = _run(checker.scan(_args(), _ctx("tool")))
        assert not any(f.category == "rate_limit_exceeded" for f in findings)

    def test_over_limit_raises_high(self) -> None:
        checker = ToolCallChecker(max_calls_per_minute=2)
        checker.reset_rate_counters()
        for _ in range(3):
            findings = _run(checker.scan(_args(), _ctx("mytool")))
        assert any(
            f.category == "rate_limit_exceeded" and f.severity == FindingSeverity.HIGH
            for f in findings
        )

    def test_zero_max_calls_disables_rate_limit(self) -> None:
        checker = ToolCallChecker(max_calls_per_minute=0)
        for _ in range(20):
            findings = _run(checker.scan(_args(), _ctx("tool")))
        assert not any(f.category == "rate_limit_exceeded" for f in findings)

    def test_reset_rate_counters_clears_state(self) -> None:
        checker = ToolCallChecker(max_calls_per_minute=2)
        for _ in range(3):
            _run(checker.scan(_args(), _ctx("tool")))
        checker.reset_rate_counters()
        # After reset, first call should pass
        findings = _run(checker.scan(_args(), _ctx("tool")))
        assert not any(f.category == "rate_limit_exceeded" for f in findings)

    def test_different_tools_have_independent_rate_windows(self) -> None:
        checker = ToolCallChecker(max_calls_per_minute=1)
        checker.reset_rate_counters()
        # First call to each tool should pass
        findings_a = _run(checker.scan(_args(), _ctx("tool_a")))
        findings_b = _run(checker.scan(_args(), _ctx("tool_b")))
        assert not any(f.category == "rate_limit_exceeded" for f in findings_a)
        assert not any(f.category == "rate_limit_exceeded" for f in findings_b)


class TestChainDepth:
    def test_within_depth_no_finding(self) -> None:
        checker = ToolCallChecker(max_chain_depth=5)
        ctx = _ctx(session_id="depth-session")
        checker.reset_session("depth-session")
        for _ in range(5):
            findings = _run(checker.scan(_args(), ctx))
        assert not any(f.category == "chain_depth_exceeded" for f in findings)

    def test_over_depth_raises_high(self) -> None:
        checker = ToolCallChecker(max_chain_depth=2)
        ctx = _ctx(session_id="over-session")
        checker.reset_session("over-session")
        for _ in range(3):
            findings = _run(checker.scan(_args(), ctx))
        assert any(
            f.category == "chain_depth_exceeded" and f.severity == FindingSeverity.HIGH
            for f in findings
        )

    def test_zero_max_depth_disables_check(self) -> None:
        checker = ToolCallChecker(max_chain_depth=0)
        ctx = _ctx(session_id="unlimited")
        for _ in range(50):
            findings = _run(checker.scan(_args(), ctx))
        assert not any(f.category == "chain_depth_exceeded" for f in findings)

    def test_reset_session_clears_depth(self) -> None:
        checker = ToolCallChecker(max_chain_depth=2)
        ctx = _ctx(session_id="reset-depth-session")
        checker.reset_session("reset-depth-session")
        for _ in range(3):
            _run(checker.scan(_args(), ctx))
        checker.reset_session("reset-depth-session")
        findings = _run(checker.scan(_args(), ctx))
        assert not any(f.category == "chain_depth_exceeded" for f in findings)

    def test_different_sessions_independent_depth(self) -> None:
        checker = ToolCallChecker(max_chain_depth=2)
        checker.reset_session("s1")
        checker.reset_session("s2")
        for _ in range(2):
            _run(checker.scan(_args(), _ctx(session_id="s1")))
        # s2 is fresh
        findings = _run(checker.scan(_args(), _ctx(session_id="s2")))
        assert not any(f.category == "chain_depth_exceeded" for f in findings)

    def test_finding_includes_session_id(self) -> None:
        checker = ToolCallChecker(max_chain_depth=1)
        checker.reset_session("test-sess")
        ctx = _ctx(session_id="test-sess")
        _run(checker.scan(_args(), ctx))
        findings = _run(checker.scan(_args(), ctx))
        assert any(
            f.category == "chain_depth_exceeded"
            and f.details.get("session_id") == "test-sess"
            for f in findings
        )


class TestCombined:
    def test_allowlist_and_chain_depth_combined(self) -> None:
        checker = ToolCallChecker(
            allowed_tools={"allowed"},
            max_chain_depth=2,
        )
        ctx = _ctx("not_allowed", session_id="combo")
        checker.reset_session("combo")
        findings = _run(checker.scan(_args(), ctx))
        cats = [f.category for f in findings]
        assert "tool_not_allowed" in cats

    def test_scanner_name(self) -> None:
        checker = ToolCallChecker()
        assert checker.name == "tool_call_checker"

    def test_phases(self) -> None:
        checker = ToolCallChecker()
        from agentshield.core.scanner import ScanPhase
        assert ScanPhase.TOOL_CALL in checker.phases
