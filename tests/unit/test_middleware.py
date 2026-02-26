"""Tests for agentshield.middleware.hooks and agentshield.middleware.wrapper."""
from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agentshield.core.context import ScanContext
from agentshield.core.result import SecurityReport
from agentshield.core.scanner import Finding, FindingSeverity, ScanPhase
from agentshield.middleware.hooks import (
    PostExecutionHook,
    PreExecutionHook,
    ToolCallHook,
    _extract_text,
)


def _run(coro):  # type: ignore[no-untyped-def]
    return asyncio.run(coro)


def _clean_report() -> SecurityReport:
    return SecurityReport(findings=[], phase="input", agent_id="agent", session_id="sess")


def _dirty_report() -> SecurityReport:
    return SecurityReport(
        findings=[Finding(
            scanner_name="test",
            severity=FindingSeverity.HIGH,
            category="test",
            message="test",
        )],
        phase="input",
        agent_id="agent",
        session_id="sess",
    )


# ---------------------------------------------------------------------------
# _extract_text helper
# ---------------------------------------------------------------------------


class TestExtractText:
    def test_extracts_string_values(self) -> None:
        payload = {"input": "hello", "other": "world"}
        result = _extract_text(payload)
        assert "hello" in result
        assert "world" in result

    def test_skips_non_string_values(self) -> None:
        payload = {"count": 42, "flag": True, "text": "hello"}
        result = _extract_text(payload)
        assert result == "hello"

    def test_extracts_strings_from_list_values(self) -> None:
        payload = {"messages": ["first", "second"]}
        result = _extract_text(payload)
        assert "first" in result
        assert "second" in result

    def test_skips_non_strings_in_list(self) -> None:
        payload = {"items": [42, "text", None]}
        result = _extract_text(payload)
        assert "text" in result

    def test_empty_payload(self) -> None:
        result = _extract_text({})
        assert result == ""

    def test_no_string_values(self) -> None:
        result = _extract_text({"a": 1, "b": [2, 3]})
        assert result == ""

    def test_joins_with_space(self) -> None:
        result = _extract_text({"a": "hello", "b": "world"})
        assert " " in result


# ---------------------------------------------------------------------------
# PreExecutionHook
# ---------------------------------------------------------------------------


class TestPreExecutionHook:
    def test_calls_scan_input(self) -> None:
        hook = PreExecutionHook()
        mock_pipeline = MagicMock()
        mock_pipeline.scan_input = AsyncMock(return_value=_clean_report())
        result = _run(hook(mock_pipeline, {"input": "hello"}, session_id=None, metadata={}))
        mock_pipeline.scan_input.assert_called_once()
        assert isinstance(result, SecurityReport)

    def test_passes_text_to_pipeline(self) -> None:
        hook = PreExecutionHook()
        mock_pipeline = MagicMock()
        mock_pipeline.scan_input = AsyncMock(return_value=_clean_report())
        _run(hook(mock_pipeline, {"input": "test message"}, session_id=None, metadata={}))
        call_args = mock_pipeline.scan_input.call_args
        assert "test message" in call_args.args[0]

    def test_passes_session_id(self) -> None:
        hook = PreExecutionHook()
        mock_pipeline = MagicMock()
        mock_pipeline.scan_input = AsyncMock(return_value=_clean_report())
        _run(hook(mock_pipeline, {"input": "text"}, session_id="my-session", metadata={}))
        call_kwargs = mock_pipeline.scan_input.call_args.kwargs
        assert call_kwargs.get("session_id") == "my-session"

    def test_passes_metadata(self) -> None:
        hook = PreExecutionHook()
        mock_pipeline = MagicMock()
        mock_pipeline.scan_input = AsyncMock(return_value=_clean_report())
        _run(hook(mock_pipeline, {"input": "text"}, session_id=None, metadata={"key": "val"}))
        call_kwargs = mock_pipeline.scan_input.call_args.kwargs
        assert call_kwargs.get("metadata") is not None

    def test_returns_security_report(self) -> None:
        hook = PreExecutionHook()
        mock_pipeline = MagicMock()
        mock_pipeline.scan_input = AsyncMock(return_value=_clean_report())
        result = _run(hook(mock_pipeline, {}, session_id=None, metadata=None))
        assert isinstance(result, SecurityReport)


# ---------------------------------------------------------------------------
# PostExecutionHook
# ---------------------------------------------------------------------------


class TestPostExecutionHook:
    def test_calls_scan_output(self) -> None:
        hook = PostExecutionHook()
        mock_pipeline = MagicMock()
        mock_pipeline.scan_output = AsyncMock(return_value=_clean_report())
        result = _run(hook(mock_pipeline, {"output": "response"}, session_id=None, metadata={}))
        mock_pipeline.scan_output.assert_called_once()
        assert isinstance(result, SecurityReport)

    def test_passes_text_to_scan_output(self) -> None:
        hook = PostExecutionHook()
        mock_pipeline = MagicMock()
        mock_pipeline.scan_output = AsyncMock(return_value=_clean_report())
        _run(hook(mock_pipeline, {"output": "agent response text"}, session_id=None, metadata={}))
        call_args = mock_pipeline.scan_output.call_args
        assert "agent response text" in call_args.args[0]


# ---------------------------------------------------------------------------
# ToolCallHook
# ---------------------------------------------------------------------------


class TestToolCallHook:
    def test_calls_scan_tool_call(self) -> None:
        hook = ToolCallHook()
        mock_pipeline = MagicMock()
        mock_pipeline.scan_tool_call = AsyncMock(return_value=_clean_report())
        payload = {"tool_name": "read_file", "args": {"path": "data.txt"}}
        result = _run(hook(mock_pipeline, payload, session_id=None, metadata={}))
        mock_pipeline.scan_tool_call.assert_called_once()
        assert isinstance(result, SecurityReport)

    def test_extracts_tool_name(self) -> None:
        hook = ToolCallHook()
        mock_pipeline = MagicMock()
        mock_pipeline.scan_tool_call = AsyncMock(return_value=_clean_report())
        payload = {"tool_name": "search_web", "args": {"query": "hello"}}
        _run(hook(mock_pipeline, payload, session_id=None, metadata={}))
        call_args = mock_pipeline.scan_tool_call.call_args
        assert call_args.args[0] == "search_web"

    def test_defaults_tool_name_to_unknown(self) -> None:
        hook = ToolCallHook()
        mock_pipeline = MagicMock()
        mock_pipeline.scan_tool_call = AsyncMock(return_value=_clean_report())
        _run(hook(mock_pipeline, {}, session_id=None, metadata={}))
        call_args = mock_pipeline.scan_tool_call.call_args
        assert call_args.args[0] == "unknown"

    def test_defaults_args_to_empty_dict(self) -> None:
        hook = ToolCallHook()
        mock_pipeline = MagicMock()
        mock_pipeline.scan_tool_call = AsyncMock(return_value=_clean_report())
        _run(hook(mock_pipeline, {"tool_name": "tool"}, session_id=None, metadata={}))
        call_args = mock_pipeline.scan_tool_call.call_args
        assert call_args.args[1] == {}

    def test_non_dict_args_defaults_to_empty(self) -> None:
        hook = ToolCallHook()
        mock_pipeline = MagicMock()
        mock_pipeline.scan_tool_call = AsyncMock(return_value=_clean_report())
        _run(hook(mock_pipeline, {"tool_name": "tool", "args": "not a dict"}, session_id=None, metadata={}))
        call_args = mock_pipeline.scan_tool_call.call_args
        assert call_args.args[1] == {}

    def test_non_string_tool_name_defaults_to_unknown(self) -> None:
        hook = ToolCallHook()
        mock_pipeline = MagicMock()
        mock_pipeline.scan_tool_call = AsyncMock(return_value=_clean_report())
        _run(hook(mock_pipeline, {"tool_name": 42, "args": {}}, session_id=None, metadata={}))
        call_args = mock_pipeline.scan_tool_call.call_args
        assert call_args.args[0] == "unknown"


# ---------------------------------------------------------------------------
# AgentWrapper
# ---------------------------------------------------------------------------


class TestAgentWrapper:
    def _make_pipeline(self) -> MagicMock:
        pipeline = MagicMock()
        pipeline.scan_input = AsyncMock(return_value=_clean_report())
        pipeline.scan_output = AsyncMock(return_value=_clean_report())
        pipeline.scan_tool_call = AsyncMock(return_value=_clean_report())
        return pipeline

    def test_wrap_async_callable(self) -> None:
        from agentshield.middleware.wrapper import AgentWrapper

        pipeline = self._make_pipeline()
        wrapper = AgentWrapper(pipeline)

        async def my_agent(payload: dict) -> dict:
            return {"output": "hello"}

        secured = wrapper.wrap(my_agent)
        result = _run(secured({"input": "hi"}))
        assert result["output"] == "hello"

    def test_wrap_sync_callable(self) -> None:
        from agentshield.middleware.wrapper import AgentWrapper

        pipeline = self._make_pipeline()
        wrapper = AgentWrapper(pipeline)

        def my_sync_agent(payload: dict) -> dict:
            return {"output": "sync result"}

        secured = wrapper.wrap(my_sync_agent)
        result = _run(secured({"input": "hello"}))
        assert result["output"] == "sync result"

    def test_wrap_calls_pre_and_post_hooks(self) -> None:
        from agentshield.middleware.wrapper import AgentWrapper

        pipeline = self._make_pipeline()
        wrapper = AgentWrapper(pipeline)

        async def agent(payload: dict) -> dict:
            return {"output": "out"}

        secured = wrapper.wrap(agent)
        _run(secured({"input": "in"}))
        pipeline.scan_input.assert_called_once()
        pipeline.scan_output.assert_called_once()

    def test_wrap_scans_tool_calls_when_present(self) -> None:
        from agentshield.middleware.wrapper import AgentWrapper

        pipeline = self._make_pipeline()
        wrapper = AgentWrapper(pipeline, scan_tool_calls=True)

        async def agent(payload: dict) -> dict:
            return {
                "output": "result",
                "tool_calls": [{"tool_name": "read_file", "args": {"path": "f.txt"}}],
            }

        secured = wrapper.wrap(agent)
        _run(secured({"input": "in"}))
        pipeline.scan_tool_call.assert_called_once()

    def test_wrap_skips_tool_calls_when_disabled(self) -> None:
        from agentshield.middleware.wrapper import AgentWrapper

        pipeline = self._make_pipeline()
        wrapper = AgentWrapper(pipeline, scan_tool_calls=False)

        async def agent(payload: dict) -> dict:
            return {
                "output": "result",
                "tool_calls": [{"tool_name": "read_file", "args": {}}],
            }

        secured = wrapper.wrap(agent)
        _run(secured({"input": "in"}))
        pipeline.scan_tool_call.assert_not_called()

    def test_wrap_skips_non_dict_tool_calls(self) -> None:
        from agentshield.middleware.wrapper import AgentWrapper

        pipeline = self._make_pipeline()
        wrapper = AgentWrapper(pipeline, scan_tool_calls=True)

        async def agent(payload: dict) -> dict:
            return {
                "output": "result",
                "tool_calls": ["not-a-dict", 42],
            }

        secured = wrapper.wrap(agent)
        _run(secured({"input": "in"}))
        pipeline.scan_tool_call.assert_not_called()

    def test_wrap_returns_agent_result(self) -> None:
        from agentshield.middleware.wrapper import AgentWrapper

        pipeline = self._make_pipeline()
        wrapper = AgentWrapper(pipeline)

        async def agent(payload: dict) -> dict:
            return {"answer": 42, "text": "done"}

        secured = wrapper.wrap(agent)
        result = _run(secured({"input": "q"}))
        assert result["answer"] == 42

    def test_wrap_secured_name_includes_agent_name(self) -> None:
        from agentshield.middleware.wrapper import AgentWrapper

        pipeline = self._make_pipeline()
        wrapper = AgentWrapper(pipeline)

        async def my_special_agent(payload: dict) -> dict:
            return {}

        secured = wrapper.wrap(my_special_agent)
        assert "my_special_agent" in secured.__name__

    def test_wrap_sync_creates_sync_function(self) -> None:
        from agentshield.middleware.wrapper import AgentWrapper

        pipeline = self._make_pipeline()
        wrapper = AgentWrapper(pipeline)

        def my_agent(payload: dict) -> dict:
            return {"result": "done"}

        secured_sync = wrapper.wrap_sync(my_agent)
        # wrap_sync returns a sync callable
        assert callable(secured_sync)

    def test_session_id_passed_to_hooks(self) -> None:
        from agentshield.middleware.wrapper import AgentWrapper

        pipeline = self._make_pipeline()
        wrapper = AgentWrapper(pipeline, session_id="fixed-session")

        async def agent(payload: dict) -> dict:
            return {"output": "res"}

        secured = wrapper.wrap(agent)
        _run(secured({"input": "in"}))
        # session_id should be passed to scan_input
        call_kwargs = pipeline.scan_input.call_args.kwargs
        assert call_kwargs.get("session_id") == "fixed-session"
