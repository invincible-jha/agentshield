"""Anthropic SDK security adapter for agentshield.

Provides :class:`AnthropicShield`, which wraps an ``anthropic.Anthropic``
(or ``anthropic.AsyncAnthropic``) client to intercept ``messages.create``
calls and scan inputs and outputs through the agentshield pipeline.

The Anthropic SDK is an optional dependency.  This module does not import
``anthropic`` at module level — the adapter works with any client object
that exposes a ``messages.create`` interface via duck-typing.

Example
-------
::

    from agentshield import SecurityPipeline
    from agentshield.adapters.anthropic_sdk import AnthropicShield
    import anthropic

    pipeline = SecurityPipeline.default()
    shield = AnthropicShield(pipeline)

    client = anthropic.Anthropic()
    protected_client = shield.wrap(client)

    # messages.create is now scanned on every call
    response = protected_client.messages.create(
        model="claude-opus-4-6",
        max_tokens=1024,
        messages=[{"role": "user", "content": "Hello!"}],
    )
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from agentshield.core.exceptions import SecurityBlockError
from agentshield.core.pipeline import SecurityPipeline
from agentshield.core.result import SecurityReport

logger = logging.getLogger(__name__)


class AnthropicShield:
    """Anthropic SDK middleware that scans messages through agentshield.

    This class wraps an Anthropic client's ``messages.create`` (and
    ``messages.acreate`` when present) with input / output security scanning.

    Parameters
    ----------
    pipeline:
        An active :class:`~agentshield.core.pipeline.SecurityPipeline`.
    session_id:
        Optional session identifier forwarded to scanners.
    block_on_critical:
        When ``True`` (default), raise
        :class:`~agentshield.core.exceptions.SecurityBlockError` if a
        CRITICAL finding is detected.  When ``False``, log a warning instead.

    Example
    -------
    ::

        shield = AnthropicShield(pipeline)
        protected_client = shield.wrap(anthropic.Anthropic())
    """

    def __init__(
        self,
        pipeline: SecurityPipeline,
        session_id: str | None = None,
        block_on_critical: bool = True,
    ) -> None:
        self.pipeline = pipeline
        self.session_id = session_id
        self.block_on_critical = block_on_critical

    def wrap(self, client: object) -> object:
        """Patch *client*'s ``messages.create`` with security scanning.

        Parameters
        ----------
        client:
            An ``anthropic.Anthropic`` or ``anthropic.AsyncAnthropic``
            client instance.

        Returns
        -------
        object
            The same client with a patched ``messages.create`` (and
            ``messages.acreate`` if present).

        Raises
        ------
        AttributeError
            If the client has no ``messages`` attribute.
        """
        messages_api = getattr(client, "messages", None)
        if messages_api is None:
            raise AttributeError(
                f"AnthropicShield.wrap() received {type(client).__name__!r} which "
                "has no 'messages' attribute. Pass an anthropic.Anthropic() client."
            )
        shield = self

        # Patch synchronous messages.create
        if hasattr(messages_api, "create"):
            original_create = messages_api.create

            def patched_create(*args: object, **kwargs: object) -> Any:  # noqa: ANN401
                input_text = _extract_input_text(kwargs)
                if input_text:
                    report = asyncio.run(
                        shield.pipeline.scan_input(
                            input_text, session_id=shield.session_id
                        )
                    )
                    _handle_report("messages.create input", report, shield.block_on_critical)

                response = original_create(*args, **kwargs)

                output_text = _extract_output_text(response)
                if output_text:
                    out_report = asyncio.run(
                        shield.pipeline.scan_output(
                            output_text, session_id=shield.session_id
                        )
                    )
                    _handle_report(
                        "messages.create output", out_report, shield.block_on_critical
                    )

                return response

            messages_api.create = patched_create  # type: ignore[method-assign]

        # Patch asynchronous messages.acreate when present
        if hasattr(messages_api, "acreate"):
            original_acreate = messages_api.acreate

            async def patched_acreate(*args: object, **kwargs: object) -> Any:  # noqa: ANN401
                input_text = _extract_input_text(kwargs)
                if input_text:
                    report = await shield.pipeline.scan_input(
                        input_text, session_id=shield.session_id
                    )
                    _handle_report(
                        "messages.acreate input", report, shield.block_on_critical
                    )

                response = await original_acreate(*args, **kwargs)

                output_text = _extract_output_text(response)
                if output_text:
                    out_report = await shield.pipeline.scan_output(
                        output_text, session_id=shield.session_id
                    )
                    _handle_report(
                        "messages.acreate output", out_report, shield.block_on_critical
                    )

                return response

            messages_api.acreate = patched_acreate  # type: ignore[method-assign]

        return client

    def scan_messages(self, messages: list[dict[str, object]]) -> SecurityReport:
        """Scan a list of Anthropic-format messages for security findings.

        This is a convenience method for scanning messages synchronously
        without wrapping the client.

        Parameters
        ----------
        messages:
            A list of ``{"role": ..., "content": ...}`` dicts.

        Returns
        -------
        SecurityReport
            The report produced by scanning all user-role message content.
        """
        text = _messages_to_text(messages)
        return asyncio.run(
            self.pipeline.scan_input(text, session_id=self.session_id)
        )

    async def scan_messages_async(
        self, messages: list[dict[str, object]]
    ) -> SecurityReport:
        """Async variant of :meth:`scan_messages`.

        Parameters
        ----------
        messages:
            A list of ``{"role": ..., "content": ...}`` dicts.

        Returns
        -------
        SecurityReport
        """
        text = _messages_to_text(messages)
        return await self.pipeline.scan_input(text, session_id=self.session_id)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _messages_to_text(messages: list[dict[str, object]]) -> str:
    """Concatenate user-role message content into a single string."""
    parts: list[str] = []
    for message in messages:
        role = message.get("role", "")
        if role != "user":
            continue
        content = message.get("content", "")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict):
                    text = block.get("text")
                    if isinstance(text, str):
                        parts.append(text)
                elif isinstance(block, str):
                    parts.append(block)
    return " ".join(parts)


def _extract_input_text(kwargs: dict[str, Any]) -> str:
    """Extract user message text from ``messages.create`` keyword arguments."""
    messages = kwargs.get("messages")
    if not isinstance(messages, list):
        return ""
    return _messages_to_text(messages)


def _extract_output_text(response: object) -> str:
    """Best-effort text extraction from an Anthropic ``Message`` response."""
    content = getattr(response, "content", None)
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if getattr(block, "type", None) == "text":
                text = getattr(block, "text", "")
                if isinstance(text, str) and text:
                    parts.append(text)
        if parts:
            return " ".join(parts)
    completion = getattr(response, "completion", None)
    if isinstance(completion, str):
        return completion
    return ""


def _handle_report(
    phase: str, report: SecurityReport, block_on_critical: bool
) -> None:
    if report.has_critical and block_on_critical:
        raise SecurityBlockError(
            f"Anthropic {phase} blocked by agentshield: {report.summary}",
            report=report,
        )
    if not report.is_clean:
        logger.warning("agentshield [anthropic:%s] %s", phase, report.summary)
