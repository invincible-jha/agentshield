"""OpenAI Agents SDK guardrail adapter.

Provides :class:`AgentShieldGuardrail`, which implements the OpenAI Agents
SDK ``Guardrail`` protocol so that agentshield can participate in the
agents SDK's built-in guardrail chain.

The OpenAI Agents SDK is an optional dependency.  This module uses lazy
imports and a compatibility shim so that agentshield stays importable
without the SDK installed.

Example
-------
::

    from agentshield import SecurityPipeline
    from agentshield.adapters.openai_agents import AgentShieldGuardrail
    from agents import Agent, Runner

    pipeline = SecurityPipeline.default()
    guardrail = AgentShieldGuardrail(pipeline)

    agent = Agent(
        name="my_agent",
        instructions="You are a helpful assistant.",
        input_guardrails=[guardrail],
        output_guardrails=[guardrail],
    )
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

from agentshield.core.exceptions import SecurityBlockError
from agentshield.core.pipeline import SecurityPipeline
from agentshield.core.result import SecurityReport

logger = logging.getLogger(__name__)


@dataclass
class GuardrailResult:
    """Result returned by :meth:`AgentShieldGuardrail.run`.

    Attributes
    ----------
    tripwire_triggered:
        ``True`` when the guardrail wants to halt execution.
    report:
        The :class:`~agentshield.core.result.SecurityReport` from this scan.
    """

    tripwire_triggered: bool
    report: SecurityReport


class AgentShieldGuardrail:
    """OpenAI Agents SDK guardrail backed by agentshield.

    This class implements the conceptual guardrail interface used by the
    OpenAI Agents SDK (``InputGuardrail`` / ``OutputGuardrail`` protocols):

    .. code-block:: python

        async def run(self, ctx, agent, input_or_output) -> GuardrailResult: ...

    The ``ctx`` and ``agent`` parameters are accepted but ignored; only the
    text content is scanned.

    Parameters
    ----------
    pipeline:
        An active :class:`~agentshield.core.pipeline.SecurityPipeline`.
    session_id:
        Optional session identifier.
    block_on_high:
        When ``True`` (default), set ``tripwire_triggered=True`` for any
        finding at HIGH or CRITICAL severity.  When ``False``, only
        CRITICAL findings trigger the tripwire.
    """

    def __init__(
        self,
        pipeline: SecurityPipeline,
        session_id: str | None = None,
        block_on_high: bool = True,
    ) -> None:
        self.pipeline = pipeline
        self.session_id = session_id
        self.block_on_high = block_on_high

    async def run(
        self,
        ctx: object,
        agent: object,
        input_or_output: str | list[object] | object,
    ) -> GuardrailResult:
        """Evaluate the guardrail against an input or output value.

        Parameters
        ----------
        ctx:
            RunContext supplied by the agents SDK (not used by this adapter).
        agent:
            The active ``Agent`` instance (not used by this adapter).
        input_or_output:
            The text to scan.  Can be a plain string, a list of strings, or
            any object with a ``content`` attribute.

        Returns
        -------
        GuardrailResult
            Contains the SecurityReport and whether the tripwire fired.
        """
        text = _extract_text(input_or_output)

        # Determine whether this is an input or output guardrail by checking
        # whether the content looks like it came from the user or the model.
        # Since the same class handles both, we run input scan first; the
        # caller should register input and output guardrails independently.
        report = await self.pipeline.scan_input(text, session_id=self.session_id)

        if self.block_on_high:
            tripwire = report.has_high
        else:
            tripwire = report.has_critical

        if tripwire:
            logger.warning(
                "agentshield [openai_agents guardrail] tripwire triggered: %s",
                report.summary,
            )

        return GuardrailResult(tripwire_triggered=tripwire, report=report)

    async def run_output(
        self,
        ctx: object,
        agent: object,
        output: str | list[object] | object,
    ) -> GuardrailResult:
        """Evaluate the guardrail against an agent output value.

        Use this method when you need output-specific scanning (PII,
        credentials, output safety checks).

        Parameters
        ----------
        ctx:
            RunContext supplied by the agents SDK (not used).
        agent:
            The active ``Agent`` instance (not used).
        output:
            The text to scan.

        Returns
        -------
        GuardrailResult
        """
        text = _extract_text(output)
        report = await self.pipeline.scan_output(text, session_id=self.session_id)

        if self.block_on_high:
            tripwire = report.has_high
        else:
            tripwire = report.has_critical

        if tripwire:
            logger.warning(
                "agentshield [openai_agents guardrail output] tripwire triggered: %s",
                report.summary,
            )

        return GuardrailResult(tripwire_triggered=tripwire, report=report)

    # Synchronous convenience wrappers -------------------------------------

    def run_sync(
        self,
        ctx: object,
        agent: object,
        input_or_output: str | list[object] | object,
    ) -> GuardrailResult:
        """Synchronous wrapper around :meth:`run`."""
        return asyncio.run(self.run(ctx, agent, input_or_output))

    def run_output_sync(
        self,
        ctx: object,
        agent: object,
        output: str | list[object] | object,
    ) -> GuardrailResult:
        """Synchronous wrapper around :meth:`run_output`."""
        return asyncio.run(self.run_output(ctx, agent, output))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_text(value: str | list[object] | object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts: list[str] = []
        for item in value:
            if isinstance(item, str):
                parts.append(item)
            else:
                content = getattr(item, "content", None)
                if isinstance(content, str):
                    parts.append(content)
        return " ".join(parts)
    content = getattr(value, "content", None)
    if isinstance(content, str):
        return content
    return str(value)
