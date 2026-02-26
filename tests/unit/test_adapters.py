"""Tests for agentshield adapters.

Tests cover the generic shield/shield_sync decorators, the AutoGen hook,
CrewAI middleware, MCP shield, and OpenAI Agents guardrail — all with a
mocked SecurityPipeline to avoid framework dependencies.

The LangChain adapter requires langchain at instantiation; it is tested
separately by patching _get_base_callback_handler to avoid the import.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agentshield.core.exceptions import SecurityBlockError
from agentshield.core.result import SecurityReport
from agentshield.core.scanner import Finding, FindingSeverity


# ---------------------------------------------------------------------------
# Helpers — build clean and critical reports
# ---------------------------------------------------------------------------


def _clean_report(phase: str = "input") -> SecurityReport:
    return SecurityReport(findings=[], phase=phase, agent_id="test", session_id="s1")


def _critical_report(phase: str = "input") -> SecurityReport:
    finding = Finding(
        scanner_name="test",
        severity=FindingSeverity.CRITICAL,
        category="test",
        message="Critical!",
        details={},
    )
    return SecurityReport(findings=[finding], phase=phase, agent_id="test", session_id="s1")


def _high_report(phase: str = "output") -> SecurityReport:
    finding = Finding(
        scanner_name="test",
        severity=FindingSeverity.HIGH,
        category="test",
        message="High finding.",
        details={},
    )
    return SecurityReport(findings=[finding], phase=phase, agent_id="test", session_id="s1")


def _make_pipeline(
    input_report: SecurityReport | None = None,
    output_report: SecurityReport | None = None,
    tool_call_report: SecurityReport | None = None,
) -> MagicMock:
    """Return a mock SecurityPipeline with configurable reports."""
    pipeline = MagicMock()
    pipeline.scan_input = AsyncMock(return_value=input_report or _clean_report("input"))
    pipeline.scan_output = AsyncMock(return_value=output_report or _clean_report("output"))
    pipeline.scan_tool_call = AsyncMock(return_value=tool_call_report or _clean_report("tool_call"))
    pipeline.scan_input_sync = MagicMock(return_value=input_report or _clean_report("input"))
    pipeline.scan_output_sync = MagicMock(return_value=output_report or _clean_report("output"))
    pipeline.scan_tool_call_sync = MagicMock(
        return_value=tool_call_report or _clean_report("tool_call")
    )
    return pipeline


# ===========================================================================
# Generic adapter — shield and shield_sync
# ===========================================================================


class TestGenericShieldDecorator:
    def test_shield_wraps_async_function(self) -> None:
        from agentshield.adapters.generic import shield

        pipeline = _make_pipeline()

        @shield(pipeline)
        async def agent(payload: dict) -> dict:
            return {"output": "hello"}

        result = asyncio.run(agent({"input": "hi"}))
        assert "output" in result

    def test_shield_wraps_sync_function(self) -> None:
        from agentshield.adapters.generic import shield

        pipeline = _make_pipeline()

        @shield(pipeline)
        def agent(payload: dict) -> dict:  # type: ignore[misc]
            return {"output": "hello"}

        result = asyncio.run(agent({"input": "hi"}))  # type: ignore[arg-type]
        assert "output" in result

    def test_shield_with_session_id(self) -> None:
        from agentshield.adapters.generic import shield

        pipeline = _make_pipeline()

        @shield(pipeline, session_id="my-session")
        async def agent(payload: dict) -> dict:
            return {"output": "hello"}

        asyncio.run(agent({"input": "hi"}))
        # scan_input should have been called with the session_id
        pipeline.scan_input.assert_called_once()

    def test_shield_preserves_function_name(self) -> None:
        from agentshield.adapters.generic import shield

        pipeline = _make_pipeline()

        @shield(pipeline)
        async def my_named_agent(payload: dict) -> dict:
            return {"output": "hello"}

        assert my_named_agent.__name__ == "my_named_agent"

    def test_shield_scan_tool_calls_false(self) -> None:
        from agentshield.adapters.generic import shield

        pipeline = _make_pipeline()

        @shield(pipeline, scan_tool_calls=False)
        async def agent(payload: dict) -> dict:
            return {"output": "hello"}

        asyncio.run(agent({"input": "test"}))
        # Even with scan_tool_calls=False, scan_input should still be called
        pipeline.scan_input.assert_called_once()


class TestShieldSyncDecorator:
    def test_shield_sync_wraps_sync_function(self) -> None:
        from agentshield.adapters.generic import shield_sync

        pipeline = _make_pipeline()

        @shield_sync(pipeline)
        def agent(payload: dict) -> dict:
            return {"output": "sync result"}

        result = agent({"input": "test"})
        assert "output" in result

    def test_shield_sync_preserves_function_name(self) -> None:
        from agentshield.adapters.generic import shield_sync

        pipeline = _make_pipeline()

        @shield_sync(pipeline)
        def my_sync_agent(payload: dict) -> dict:
            return {}

        assert my_sync_agent.__name__ == "my_sync_agent"


# ===========================================================================
# AutoGen adapter
# ===========================================================================


class TestAutoGenHook:
    def _make_hook(
        self,
        input_report: SecurityReport | None = None,
        output_report: SecurityReport | None = None,
        block: bool = True,
    ):
        from agentshield.adapters.autogen import AgentShieldAutoGenHook

        pipeline = _make_pipeline(
            input_report=input_report,
            output_report=output_report,
        )
        return AgentShieldAutoGenHook(pipeline, block_on_critical=block), pipeline

    def test_process_incoming_clean_message_returns_message(self) -> None:
        hook, _ = self._make_hook()
        message = {"content": "Hello, agent!"}
        result = hook.process_incoming_message(message)
        assert result == message

    def test_process_incoming_critical_blocks(self) -> None:
        hook, _ = self._make_hook(input_report=_critical_report())
        message = {"content": "malicious input"}
        with pytest.raises(SecurityBlockError):
            hook.process_incoming_message(message)

    def test_process_incoming_critical_no_block_when_disabled(self) -> None:
        hook, _ = self._make_hook(input_report=_critical_report(), block=False)
        message = {"content": "malicious input"}
        result = hook.process_incoming_message(message)
        assert result == message

    def test_process_outgoing_clean_message_returns_message(self) -> None:
        hook, _ = self._make_hook()
        message = {"content": "Agent response text"}
        result = hook.process_outgoing_message(message)
        assert result == message

    def test_process_outgoing_critical_blocks(self) -> None:
        hook, _ = self._make_hook(output_report=_critical_report("output"))
        message = {"content": "leaked key sk-" + "A" * 30}
        with pytest.raises(SecurityBlockError):
            hook.process_outgoing_message(message)

    def test_install_patches_receive_method(self) -> None:
        from agentshield.adapters.autogen import AgentShieldAutoGenHook

        pipeline = _make_pipeline()
        hook = AgentShieldAutoGenHook(pipeline)

        class FakeAgent:
            name = "agent"
            received: list[dict] = []

            def receive(
                self,
                message: dict,
                sender: object,
                request_reply: bool | None = None,
                silent: bool = False,
            ) -> None:
                self.received.append(message)

        agent = FakeAgent()
        hook.install(agent)

        # patched_receive should call the hook then the original
        agent.receive({"content": "hello"}, sender=None)
        assert len(agent.received) == 1

    def test_install_generate_patches_generate_reply(self) -> None:
        from agentshield.adapters.autogen import AgentShieldAutoGenHook

        pipeline = _make_pipeline()
        hook = AgentShieldAutoGenHook(pipeline)

        class FakeAgent:
            name = "agent"

            def generate_reply(
                self,
                messages: list | None = None,
                sender: object = None,
                **kwargs: object,
            ) -> dict:
                return {"content": "reply"}

        agent = FakeAgent()
        hook.install_generate(agent)
        result = agent.generate_reply(messages=[], sender=None)
        assert result == {"content": "reply"}

    def test_extract_message_text_from_string_content(self) -> None:
        from agentshield.adapters.autogen import _extract_message_text

        result = _extract_message_text({"content": "hello world"})
        assert result == "hello world"

    def test_extract_message_text_from_list_content(self) -> None:
        from agentshield.adapters.autogen import _extract_message_text

        result = _extract_message_text({"content": ["hello", "world"]})
        assert "hello" in result

    def test_extract_message_text_from_dict_text_parts(self) -> None:
        from agentshield.adapters.autogen import _extract_message_text

        parts = [{"text": "part1"}, {"text": "part2"}]
        result = _extract_message_text({"content": parts})
        assert "part1" in result and "part2" in result

    def test_extract_message_text_fallback(self) -> None:
        from agentshield.adapters.autogen import _extract_message_text

        result = _extract_message_text({"no_content": "here"})
        assert isinstance(result, str)


# ===========================================================================
# CrewAI adapter
# ===========================================================================


class TestCrewAIMiddleware:
    def _make_middleware(
        self,
        output_report: SecurityReport | None = None,
        input_report: SecurityReport | None = None,
    ):
        from agentshield.adapters.crewai import AgentShieldCrewMiddleware

        pipeline = _make_pipeline(
            input_report=input_report,
            output_report=output_report,
        )
        return AgentShieldCrewMiddleware(pipeline), pipeline

    def test_task_callback_clean_output_no_exception(self) -> None:
        middleware, _ = self._make_middleware()
        middleware.task_callback("clean output text")

    def test_task_callback_critical_raises(self) -> None:
        middleware, _ = self._make_middleware(output_report=_critical_report("output"))
        with pytest.raises(SecurityBlockError):
            middleware.task_callback("malicious output")

    def test_task_callback_empty_string_output_skipped(self) -> None:
        # _extract_crew_output on a plain empty string returns "", so task_callback
        # should early-return without scanning.
        middleware, pipeline = self._make_middleware()
        middleware.task_callback("")
        pipeline.scan_output.assert_not_called()

    def test_task_callback_with_dict_output(self) -> None:
        middleware, pipeline = self._make_middleware()
        middleware.task_callback({"result": "some text", "code": 0})
        pipeline.scan_output.assert_called_once()

    def test_before_kickoff_clean_inputs(self) -> None:
        middleware, _ = self._make_middleware()
        asyncio.run(middleware.before_kickoff({"task": "summarise the document"}))

    def test_before_kickoff_critical_raises(self) -> None:
        middleware, _ = self._make_middleware(input_report=_critical_report())
        with pytest.raises(SecurityBlockError):
            asyncio.run(middleware.before_kickoff({"task": "malicious prompt"}))

    def test_before_kickoff_empty_inputs_skipped(self) -> None:
        middleware, pipeline = self._make_middleware()
        asyncio.run(middleware.before_kickoff({}))
        pipeline.scan_input.assert_not_called()

    def test_step_callback_string_output(self) -> None:
        middleware, pipeline = self._make_middleware()
        middleware.step_callback("some step output")
        pipeline.scan_output.assert_called_once()

    def test_extract_crew_output_uses_raw_attr(self) -> None:
        from agentshield.adapters.crewai import _extract_crew_output

        class FakeOutput:
            raw = "crew raw result"

        result = _extract_crew_output(FakeOutput())
        assert result == "crew raw result"

    def test_extract_crew_output_uses_result_attr(self) -> None:
        from agentshield.adapters.crewai import _extract_crew_output

        class FakeOutput:
            result = "crew result"

        result = _extract_crew_output(FakeOutput())
        assert result == "crew result"

    def test_extract_crew_output_string_passthrough(self) -> None:
        from agentshield.adapters.crewai import _extract_crew_output

        result = _extract_crew_output("direct string")
        assert result == "direct string"

    def test_extract_crew_output_dict_joins_strings(self) -> None:
        from agentshield.adapters.crewai import _extract_crew_output

        result = _extract_crew_output({"a": "hello", "b": "world"})
        assert "hello" in result and "world" in result

    def test_handle_report_clean_does_not_raise(self) -> None:
        from agentshield.adapters.crewai import _handle_report

        _handle_report("test_phase", _clean_report())

    def test_handle_report_critical_raises(self) -> None:
        from agentshield.adapters.crewai import _handle_report

        with pytest.raises(SecurityBlockError):
            _handle_report("test_phase", _critical_report())


# ===========================================================================
# MCP Shield adapter
# ===========================================================================


class TestMCPShield:
    def _make_shield(
        self,
        tool_call_report: SecurityReport | None = None,
        output_report: SecurityReport | None = None,
        block: bool = True,
    ):
        from agentshield.adapters.mcp import MCPShield

        pipeline = _make_pipeline(
            tool_call_report=tool_call_report,
            output_report=output_report,
        )
        return MCPShield(pipeline, block_on_critical=block), pipeline

    def test_init_stores_pipeline(self) -> None:
        from agentshield.adapters.mcp import MCPShield

        pipeline = _make_pipeline()
        shield = MCPShield(pipeline)
        assert shield.pipeline is pipeline

    def test_intercept_tool_call_clean_returns_report(self) -> None:
        shield, _ = self._make_shield()
        report = asyncio.run(
            shield.intercept_tool_call("list_dir", {"path": "/tmp"})
        )
        assert report.is_clean

    def test_intercept_tool_call_critical_blocks(self) -> None:
        shield, _ = self._make_shield(tool_call_report=_critical_report("tool_call"))
        with pytest.raises(SecurityBlockError):
            asyncio.run(shield.intercept_tool_call("evil_tool", {"path": "../../etc"}))

    def test_intercept_tool_call_no_block_when_disabled(self) -> None:
        shield, _ = self._make_shield(
            tool_call_report=_critical_report("tool_call"), block=False
        )
        report = asyncio.run(
            shield.intercept_tool_call("evil_tool", {"path": "../../etc"})
        )
        assert report.has_critical

    def test_intercept_response_clean_returns_report(self) -> None:
        shield, _ = self._make_shield()
        report = asyncio.run(
            shield.intercept_response("list_dir", "file1.txt\nfile2.txt")
        )
        assert isinstance(report, SecurityReport)

    def test_intercept_response_critical_blocks(self) -> None:
        shield, _ = self._make_shield(output_report=_critical_report("output"))
        with pytest.raises(SecurityBlockError):
            asyncio.run(shield.intercept_response("read_file", "leaked: sk-" + "A" * 30))

    def test_intercept_tool_call_sync(self) -> None:
        shield, pipeline = self._make_shield()
        report = shield.intercept_tool_call_sync("safe_tool", {"key": "value"})
        pipeline.scan_tool_call_sync.assert_called_once()
        assert isinstance(report, SecurityReport)

    def test_intercept_response_sync(self) -> None:
        shield, pipeline = self._make_shield()
        report = shield.intercept_response_sync("safe_tool", "clean output")
        pipeline.scan_output_sync.assert_called_once()
        assert isinstance(report, SecurityReport)

    def test_from_mcp_message_valid_message(self) -> None:
        shield, _ = self._make_shield()
        message = {
            "method": "tools/call",
            "params": {
                "name": "read_resource",
                "arguments": {"uri": "file:///tmp/data"},
            },
        }
        tool_name, arguments = shield.from_mcp_message(message)
        assert tool_name == "read_resource"
        assert arguments == {"uri": "file:///tmp/data"}

    def test_from_mcp_message_missing_params_raises(self) -> None:
        shield, _ = self._make_shield()
        with pytest.raises(ValueError, match="params"):
            shield.from_mcp_message({"method": "tools/call"})

    def test_from_mcp_message_invalid_name_raises(self) -> None:
        shield, _ = self._make_shield()
        with pytest.raises(ValueError, match="name"):
            shield.from_mcp_message({"params": {"name": "", "arguments": {}}})

    def test_from_mcp_message_invalid_arguments_raises(self) -> None:
        shield, _ = self._make_shield()
        with pytest.raises(ValueError, match="arguments"):
            shield.from_mcp_message(
                {"params": {"name": "my_tool", "arguments": "not-a-dict"}}
            )

    def test_from_mcp_message_defaults_arguments_to_empty_dict(self) -> None:
        shield, _ = self._make_shield()
        message = {"params": {"name": "my_tool"}}
        _, arguments = shield.from_mcp_message(message)
        assert arguments == {}

    def test_intercept_response_with_metadata(self) -> None:
        shield, pipeline = self._make_shield()
        asyncio.run(
            shield.intercept_response(
                "read_file", "output text", metadata={"source": "mcp"}
            )
        )
        pipeline.scan_output.assert_called_once()

    def test_session_id_forwarded_on_tool_call(self) -> None:
        from agentshield.adapters.mcp import MCPShield

        pipeline = _make_pipeline()
        shield = MCPShield(pipeline, session_id="my-session")
        asyncio.run(shield.intercept_tool_call("safe", {}))
        call_kwargs = pipeline.scan_tool_call.call_args
        assert call_kwargs.kwargs.get("session_id") == "my-session"


# ===========================================================================
# OpenAI Agents guardrail adapter
# ===========================================================================


class TestOpenAIAgentsGuardrail:
    def _make_guardrail(
        self,
        input_report: SecurityReport | None = None,
        output_report: SecurityReport | None = None,
        block_on_high: bool = True,
    ):
        from agentshield.adapters.openai_agents import AgentShieldGuardrail

        pipeline = _make_pipeline(
            input_report=input_report,
            output_report=output_report,
        )
        return AgentShieldGuardrail(pipeline, block_on_high=block_on_high), pipeline

    def test_init_stores_pipeline_and_settings(self) -> None:
        from agentshield.adapters.openai_agents import AgentShieldGuardrail

        pipeline = _make_pipeline()
        guardrail = AgentShieldGuardrail(pipeline, session_id="s1", block_on_high=False)
        assert guardrail.pipeline is pipeline
        assert guardrail.session_id == "s1"
        assert guardrail.block_on_high is False

    def test_run_clean_input_no_tripwire(self) -> None:
        guardrail, _ = self._make_guardrail()
        result = asyncio.run(guardrail.run(None, None, "Hello agent!"))
        assert result.tripwire_triggered is False

    def test_run_high_severity_triggers_tripwire_by_default(self) -> None:
        guardrail, _ = self._make_guardrail(input_report=_high_report("input"))
        result = asyncio.run(guardrail.run(None, None, "malicious input"))
        assert result.tripwire_triggered is True

    def test_run_high_no_tripwire_when_block_on_high_false(self) -> None:
        guardrail, _ = self._make_guardrail(
            input_report=_high_report("input"), block_on_high=False
        )
        result = asyncio.run(guardrail.run(None, None, "input with high finding"))
        # Only CRITICAL triggers when block_on_high=False
        assert result.tripwire_triggered is False

    def test_run_critical_triggers_tripwire_even_without_block_on_high(self) -> None:
        guardrail, _ = self._make_guardrail(
            input_report=_critical_report("input"), block_on_high=False
        )
        result = asyncio.run(guardrail.run(None, None, "critical input"))
        assert result.tripwire_triggered is True

    def test_run_report_is_security_report(self) -> None:
        guardrail, _ = self._make_guardrail()
        result = asyncio.run(guardrail.run(None, None, "text"))
        assert isinstance(result.report, SecurityReport)

    def test_run_output_clean_no_tripwire(self) -> None:
        guardrail, _ = self._make_guardrail()
        result = asyncio.run(guardrail.run_output(None, None, "clean output"))
        assert result.tripwire_triggered is False

    def test_run_output_high_triggers_tripwire(self) -> None:
        guardrail, _ = self._make_guardrail(output_report=_high_report("output"))
        result = asyncio.run(guardrail.run_output(None, None, "bad output"))
        assert result.tripwire_triggered is True

    def test_run_sync_returns_guardrail_result(self) -> None:
        guardrail, _ = self._make_guardrail()
        from agentshield.adapters.openai_agents import GuardrailResult

        result = guardrail.run_sync(None, None, "text")
        assert isinstance(result, GuardrailResult)

    def test_run_output_sync_returns_guardrail_result(self) -> None:
        guardrail, _ = self._make_guardrail()
        from agentshield.adapters.openai_agents import GuardrailResult

        result = guardrail.run_output_sync(None, None, "text")
        assert isinstance(result, GuardrailResult)

    def test_extract_text_from_string(self) -> None:
        from agentshield.adapters.openai_agents import _extract_text

        assert _extract_text("hello") == "hello"

    def test_extract_text_from_list_of_strings(self) -> None:
        from agentshield.adapters.openai_agents import _extract_text

        result = _extract_text(["hello", "world"])
        assert "hello" in result and "world" in result

    def test_extract_text_from_list_with_content_objects(self) -> None:
        from agentshield.adapters.openai_agents import _extract_text

        class Item:
            content = "item content"

        result = _extract_text([Item()])
        assert "item content" in result

    def test_extract_text_from_object_with_content_attr(self) -> None:
        from agentshield.adapters.openai_agents import _extract_text

        class Obj:
            content = "obj content"

        result = _extract_text(Obj())
        assert result == "obj content"

    def test_extract_text_fallback_str(self) -> None:
        from agentshield.adapters.openai_agents import _extract_text

        result = _extract_text(42)  # type: ignore[arg-type]
        assert result == "42"


# ===========================================================================
# LangChain adapter — tested by mocking _get_base_callback_handler
# ===========================================================================


class TestLangChainCallback:
    def _make_callback(
        self,
        input_report: SecurityReport | None = None,
        output_report: SecurityReport | None = None,
        tool_report: SecurityReport | None = None,
    ):
        """Build an AgentShieldCallback with the base class mocked."""
        with patch(
            "agentshield.adapters.langchain._get_base_callback_handler",
            return_value=object,
        ):
            from agentshield.adapters.langchain import AgentShieldCallback

            pipeline = _make_pipeline(
                input_report=input_report,
                output_report=output_report,
                tool_call_report=tool_report,
            )
            return AgentShieldCallback(pipeline), pipeline

    def test_on_llm_start_clean_no_raise(self) -> None:
        callback, _ = self._make_callback()
        callback.on_llm_start({}, ["Hello LLM"])

    def test_on_llm_start_critical_raises(self) -> None:
        callback, _ = self._make_callback(input_report=_critical_report())
        with pytest.raises(SecurityBlockError):
            callback.on_llm_start({}, ["malicious prompt"])

    def test_on_tool_start_clean_no_raise(self) -> None:
        callback, _ = self._make_callback()
        callback.on_tool_start({"name": "search"}, "query text")

    def test_on_tool_start_with_list_id(self) -> None:
        callback, pipeline = self._make_callback()
        callback.on_tool_start({"id": ["tools", "search"]}, "query")
        pipeline.scan_tool_call.assert_called_once()

    def test_on_tool_start_critical_raises(self) -> None:
        callback, _ = self._make_callback(tool_report=_critical_report("tool_call"))
        with pytest.raises(SecurityBlockError):
            callback.on_tool_start({"name": "danger"}, "malicious")

    def test_on_llm_end_clean_no_raise(self) -> None:
        callback, pipeline = self._make_callback()

        class Gen:
            text = "Nice response"

        class Response:
            generations = [[Gen()]]

        callback.on_llm_end(Response())
        pipeline.scan_output.assert_called_once()

    def test_on_llm_end_empty_generations_skipped(self) -> None:
        callback, pipeline = self._make_callback()

        class Response:
            generations: list = []

        callback.on_llm_end(Response())
        pipeline.scan_output.assert_not_called()

    def test_on_llm_end_critical_raises(self) -> None:
        callback, _ = self._make_callback(output_report=_critical_report("output"))

        class Gen:
            text = "leaked: sk-" + "A" * 30

        class Response:
            generations = [[Gen()]]

        with pytest.raises(SecurityBlockError):
            callback.on_llm_end(Response())

    def test_session_id_stored(self) -> None:
        with patch(
            "agentshield.adapters.langchain._get_base_callback_handler",
            return_value=object,
        ):
            from agentshield.adapters.langchain import AgentShieldCallback

            pipeline = _make_pipeline()
            callback = AgentShieldCallback(pipeline, session_id="lc-session")
            assert callback.session_id == "lc-session"
