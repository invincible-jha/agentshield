"""Unit tests for the new agentshield adapters.

Covers:
- adapters.anthropic_sdk  — AnthropicShield wrap, scan, and block logic
- adapters.microsoft_agents — MicrosoftAgentShield install and scan logic
"""
from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agentshield.core.exceptions import SecurityBlockError
from agentshield.core.result import SecurityReport
from agentshield.core.scanner import Finding, FindingSeverity


# ---------------------------------------------------------------------------
# Report helpers (mirror agentshield/tests/unit/test_adapters.py pattern)
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


def _make_pipeline(
    input_report: SecurityReport | None = None,
    output_report: SecurityReport | None = None,
) -> MagicMock:
    pipeline = MagicMock()
    pipeline.scan_input = AsyncMock(return_value=input_report or _clean_report("input"))
    pipeline.scan_output = AsyncMock(return_value=output_report or _clean_report("output"))
    pipeline.scan_input_sync = MagicMock(return_value=input_report or _clean_report("input"))
    pipeline.scan_output_sync = MagicMock(return_value=output_report or _clean_report("output"))
    return pipeline


# ===========================================================================
# AnthropicShield
# ===========================================================================


class TestAnthropicShieldInit:
    def test_init_stores_pipeline(self) -> None:
        from agentshield.adapters.anthropic_sdk import AnthropicShield

        pipeline = _make_pipeline()
        shield = AnthropicShield(pipeline)
        assert shield.pipeline is pipeline

    def test_init_stores_session_id(self) -> None:
        from agentshield.adapters.anthropic_sdk import AnthropicShield

        pipeline = _make_pipeline()
        shield = AnthropicShield(pipeline, session_id="session-abc")
        assert shield.session_id == "session-abc"

    def test_init_block_on_critical_default_true(self) -> None:
        from agentshield.adapters.anthropic_sdk import AnthropicShield

        pipeline = _make_pipeline()
        shield = AnthropicShield(pipeline)
        assert shield.block_on_critical is True

    def test_init_block_on_critical_false(self) -> None:
        from agentshield.adapters.anthropic_sdk import AnthropicShield

        pipeline = _make_pipeline()
        shield = AnthropicShield(pipeline, block_on_critical=False)
        assert shield.block_on_critical is False


class TestAnthropicShieldWrap:
    def _make_client(self) -> MagicMock:
        client = MagicMock()
        client.messages = MagicMock()
        client.messages.create = MagicMock(return_value=MagicMock(content=[]))
        return client

    def test_wrap_returns_client(self) -> None:
        from agentshield.adapters.anthropic_sdk import AnthropicShield

        pipeline = _make_pipeline()
        shield = AnthropicShield(pipeline)
        client = self._make_client()
        result = shield.wrap(client)
        assert result is client

    def test_wrap_raises_when_no_messages_attribute(self) -> None:
        from agentshield.adapters.anthropic_sdk import AnthropicShield

        pipeline = _make_pipeline()
        shield = AnthropicShield(pipeline)
        with pytest.raises(AttributeError, match="messages"):
            shield.wrap(object())

    def test_wrap_patches_messages_create(self) -> None:
        from agentshield.adapters.anthropic_sdk import AnthropicShield

        pipeline = _make_pipeline()
        shield = AnthropicShield(pipeline)
        client = self._make_client()
        original_create = client.messages.create
        shield.wrap(client)
        # After wrap the create method should be the patched closure, not the original mock
        assert client.messages.create is not original_create

    def test_patched_create_scans_input(self) -> None:
        from agentshield.adapters.anthropic_sdk import AnthropicShield

        pipeline = _make_pipeline()
        shield = AnthropicShield(pipeline)
        client = self._make_client()
        shield.wrap(client)

        client.messages.create(
            messages=[{"role": "user", "content": "hello"}],
            model="claude-opus-4-6",
            max_tokens=100,
        )

        pipeline.scan_input.assert_called_once()

    def test_patched_create_scans_output(self) -> None:
        from agentshield.adapters.anthropic_sdk import AnthropicShield

        text_block = MagicMock()
        text_block.type = "text"
        text_block.text = "Agent response text"

        mock_response = MagicMock()
        mock_response.content = [text_block]

        pipeline = _make_pipeline()
        shield = AnthropicShield(pipeline)

        client = self._make_client()
        client.messages.create.return_value = mock_response
        shield.wrap(client)

        client.messages.create(messages=[{"role": "user", "content": "hi"}])
        pipeline.scan_output.assert_called_once()

    def test_patched_create_blocks_on_critical_input(self) -> None:
        from agentshield.adapters.anthropic_sdk import AnthropicShield

        pipeline = _make_pipeline(input_report=_critical_report("input"))
        shield = AnthropicShield(pipeline, block_on_critical=True)
        client = self._make_client()
        shield.wrap(client)

        with pytest.raises(SecurityBlockError):
            client.messages.create(messages=[{"role": "user", "content": "malicious"}])

    def test_patched_create_no_block_when_block_on_critical_false(self) -> None:
        from agentshield.adapters.anthropic_sdk import AnthropicShield

        pipeline = _make_pipeline(input_report=_critical_report("input"))
        shield = AnthropicShield(pipeline, block_on_critical=False)
        client = self._make_client()
        shield.wrap(client)

        # Should not raise
        client.messages.create(messages=[{"role": "user", "content": "content"}])


class TestAnthropicShieldScanMessages:
    def test_scan_messages_calls_scan_input(self) -> None:
        from agentshield.adapters.anthropic_sdk import AnthropicShield

        pipeline = _make_pipeline()
        shield = AnthropicShield(pipeline)
        messages = [{"role": "user", "content": "test message"}]
        shield.scan_messages(messages)
        pipeline.scan_input.assert_called_once()

    def test_scan_messages_returns_security_report(self) -> None:
        from agentshield.adapters.anthropic_sdk import AnthropicShield

        pipeline = _make_pipeline()
        shield = AnthropicShield(pipeline)
        messages = [{"role": "user", "content": "hello"}]
        report = shield.scan_messages(messages)
        assert isinstance(report, SecurityReport)

    def test_scan_messages_async_returns_security_report(self) -> None:
        from agentshield.adapters.anthropic_sdk import AnthropicShield

        pipeline = _make_pipeline()
        shield = AnthropicShield(pipeline)
        messages = [{"role": "user", "content": "hello async"}]

        async def run() -> SecurityReport:
            return await shield.scan_messages_async(messages)

        report = asyncio.run(run())
        assert isinstance(report, SecurityReport)

    def test_scan_messages_ignores_assistant_messages(self) -> None:
        from agentshield.adapters.anthropic_sdk import AnthropicShield

        pipeline = _make_pipeline()
        shield = AnthropicShield(pipeline)
        messages = [{"role": "assistant", "content": "I am the assistant"}]
        shield.scan_messages(messages)
        # scan_input is still called but with empty/no user text
        pipeline.scan_input.assert_called_once()


class TestAnthropicShieldHelpers:
    def test_messages_to_text_extracts_user_content(self) -> None:
        from agentshield.adapters.anthropic_sdk import _messages_to_text

        messages = [{"role": "user", "content": "user message"}]
        result = _messages_to_text(messages)
        assert "user message" in result

    def test_messages_to_text_skips_assistant_role(self) -> None:
        from agentshield.adapters.anthropic_sdk import _messages_to_text

        messages = [{"role": "assistant", "content": "assistant reply"}]
        result = _messages_to_text(messages)
        assert "assistant reply" not in result

    def test_extract_input_text_from_kwargs(self) -> None:
        from agentshield.adapters.anthropic_sdk import _extract_input_text

        kwargs = {"messages": [{"role": "user", "content": "hello"}], "model": "x"}
        result = _extract_input_text(kwargs)
        assert "hello" in result

    def test_extract_output_text_from_text_block(self) -> None:
        from agentshield.adapters.anthropic_sdk import _extract_output_text

        text_block = MagicMock()
        text_block.type = "text"
        text_block.text = "Claude's answer"

        response = MagicMock()
        response.content = [text_block]

        result = _extract_output_text(response)
        assert result == "Claude's answer"

    def test_handle_report_clean_does_not_raise(self) -> None:
        from agentshield.adapters.anthropic_sdk import _handle_report

        _handle_report("test_phase", _clean_report(), block_on_critical=True)

    def test_handle_report_critical_raises_when_block_true(self) -> None:
        from agentshield.adapters.anthropic_sdk import _handle_report

        with pytest.raises(SecurityBlockError):
            _handle_report("test_phase", _critical_report(), block_on_critical=True)

    def test_handle_report_critical_no_raise_when_block_false(self) -> None:
        from agentshield.adapters.anthropic_sdk import _handle_report

        _handle_report("test_phase", _critical_report(), block_on_critical=False)


# ===========================================================================
# MicrosoftAgentShield
# ===========================================================================


class TestMicrosoftAgentShieldInit:
    def test_init_stores_pipeline(self) -> None:
        from agentshield.adapters.microsoft_agents import MicrosoftAgentShield

        pipeline = _make_pipeline()
        shield = MicrosoftAgentShield(pipeline)
        assert shield.pipeline is pipeline

    def test_init_stores_session_id(self) -> None:
        from agentshield.adapters.microsoft_agents import MicrosoftAgentShield

        pipeline = _make_pipeline()
        shield = MicrosoftAgentShield(pipeline, session_id="ms-session-1")
        assert shield.session_id == "ms-session-1"

    def test_init_block_on_critical_default_true(self) -> None:
        from agentshield.adapters.microsoft_agents import MicrosoftAgentShield

        pipeline = _make_pipeline()
        shield = MicrosoftAgentShield(pipeline)
        assert shield.block_on_critical is True

    def test_init_block_on_critical_false(self) -> None:
        from agentshield.adapters.microsoft_agents import MicrosoftAgentShield

        pipeline = _make_pipeline()
        shield = MicrosoftAgentShield(pipeline, block_on_critical=False)
        assert shield.block_on_critical is False


class TestMicrosoftAgentShieldInstall:
    def _make_bot(self) -> MagicMock:
        bot = MagicMock()
        bot.name = "test-bot"
        bot.on_message_activity = AsyncMock()
        bot.on_turn = AsyncMock()
        return bot

    def test_install_raises_when_no_handlers(self) -> None:
        from agentshield.adapters.microsoft_agents import MicrosoftAgentShield

        pipeline = _make_pipeline()
        shield = MicrosoftAgentShield(pipeline)
        with pytest.raises(AttributeError, match="on_message_activity"):
            shield.install(object())

    def test_install_patches_on_message_activity(self) -> None:
        from agentshield.adapters.microsoft_agents import MicrosoftAgentShield

        pipeline = _make_pipeline()
        shield = MicrosoftAgentShield(pipeline)
        bot = self._make_bot()
        original = bot.on_message_activity
        shield.install(bot)
        assert bot.on_message_activity is not original

    def test_install_patches_on_turn(self) -> None:
        from agentshield.adapters.microsoft_agents import MicrosoftAgentShield

        pipeline = _make_pipeline()
        shield = MicrosoftAgentShield(pipeline)
        bot = self._make_bot()
        original = bot.on_turn
        shield.install(bot)
        assert bot.on_turn is not original

    def test_on_message_activity_scans_input(self) -> None:
        from agentshield.adapters.microsoft_agents import MicrosoftAgentShield

        pipeline = _make_pipeline()
        shield = MicrosoftAgentShield(pipeline)
        bot = self._make_bot()
        shield.install(bot)

        mock_context = MagicMock()
        mock_context.activity.text = "Hello!"
        asyncio.run(bot.on_message_activity(mock_context))

        pipeline.scan_input.assert_called_once()

    def test_on_message_activity_blocks_critical_input(self) -> None:
        from agentshield.adapters.microsoft_agents import MicrosoftAgentShield

        pipeline = _make_pipeline(input_report=_critical_report("input"))
        shield = MicrosoftAgentShield(pipeline, block_on_critical=True)
        bot = self._make_bot()
        shield.install(bot)

        mock_context = MagicMock()
        mock_context.activity.text = "malicious prompt"
        with pytest.raises(SecurityBlockError):
            asyncio.run(bot.on_message_activity(mock_context))

    def test_on_message_activity_no_block_when_disabled(self) -> None:
        from agentshield.adapters.microsoft_agents import MicrosoftAgentShield

        pipeline = _make_pipeline(input_report=_critical_report("input"))
        shield = MicrosoftAgentShield(pipeline, block_on_critical=False)
        bot = self._make_bot()
        shield.install(bot)

        mock_context = MagicMock()
        mock_context.activity.text = "content"
        # Should not raise
        asyncio.run(bot.on_message_activity(mock_context))


class TestMicrosoftAgentShieldScanMethods:
    def test_scan_activity_calls_scan_input(self) -> None:
        from agentshield.adapters.microsoft_agents import MicrosoftAgentShield

        pipeline = _make_pipeline()
        shield = MicrosoftAgentShield(pipeline)
        activity = MagicMock()
        activity.text = "user input"
        shield.scan_activity(activity)
        pipeline.scan_input.assert_called_once()

    def test_scan_activity_returns_security_report(self) -> None:
        from agentshield.adapters.microsoft_agents import MicrosoftAgentShield

        pipeline = _make_pipeline()
        shield = MicrosoftAgentShield(pipeline)
        activity = MagicMock()
        activity.text = "input"
        report = shield.scan_activity(activity)
        assert isinstance(report, SecurityReport)

    def test_scan_activity_async_returns_security_report(self) -> None:
        from agentshield.adapters.microsoft_agents import MicrosoftAgentShield

        pipeline = _make_pipeline()
        shield = MicrosoftAgentShield(pipeline)
        activity = MagicMock()
        activity.text = "async input"

        async def run() -> SecurityReport:
            return await shield.scan_activity_async(activity)

        report = asyncio.run(run())
        assert isinstance(report, SecurityReport)

    def test_scan_outgoing_text_calls_scan_output(self) -> None:
        from agentshield.adapters.microsoft_agents import MicrosoftAgentShield

        pipeline = _make_pipeline()
        shield = MicrosoftAgentShield(pipeline)
        shield.scan_outgoing_text("bot response text")
        pipeline.scan_output.assert_called_once()


class TestMicrosoftAgentShieldHelpers:
    def test_extract_activity_text_from_context(self) -> None:
        from agentshield.adapters.microsoft_agents import _extract_activity_text

        context = MagicMock()
        context.activity.text = "Hello bot"
        result = _extract_activity_text(context)
        assert result == "Hello bot"

    def test_extract_activity_text_no_activity(self) -> None:
        from agentshield.adapters.microsoft_agents import _extract_activity_text

        context = MagicMock(spec=[])  # no activity attribute
        result = _extract_activity_text(context)
        assert result == ""

    def test_extract_text_from_activity_string_passthrough(self) -> None:
        from agentshield.adapters.microsoft_agents import _extract_text_from_activity

        result = _extract_text_from_activity("plain string")
        assert result == "plain string"

    def test_extract_text_from_activity_object_with_text(self) -> None:
        from agentshield.adapters.microsoft_agents import _extract_text_from_activity

        activity = MagicMock()
        activity.text = "activity text"
        result = _extract_text_from_activity(activity)
        assert result == "activity text"

    def test_handle_report_clean_does_not_raise(self) -> None:
        from agentshield.adapters.microsoft_agents import _handle_report

        _handle_report("test_phase", _clean_report(), block_on_critical=True)

    def test_handle_report_critical_raises_when_block_true(self) -> None:
        from agentshield.adapters.microsoft_agents import _handle_report

        with pytest.raises(SecurityBlockError):
            _handle_report("test_phase", _critical_report(), block_on_critical=True)

    def test_handle_report_critical_no_raise_when_block_false(self) -> None:
        from agentshield.adapters.microsoft_agents import _handle_report

        _handle_report("test_phase", _critical_report(), block_on_critical=False)
