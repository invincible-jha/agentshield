"""Microsoft Agents SDK security adapter for agentshield.

Provides :class:`MicrosoftAgentShield`, which patches a Microsoft Agents SDK
``ActivityHandler`` (or compatible bot) to intercept incoming activities and
outgoing send_activity calls, scanning them through the agentshield pipeline.

The Microsoft Agents SDK is an optional dependency.  This module uses
duck-typing and lazy imports so that agentshield remains importable without
the SDK installed.

Example
-------
::

    from agentshield import SecurityPipeline
    from agentshield.adapters.microsoft_agents import MicrosoftAgentShield

    pipeline = SecurityPipeline.default()
    shield = MicrosoftAgentShield(pipeline)

    # Patch an existing ActivityHandler instance
    shield.install(my_activity_handler)
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from agentshield.core.exceptions import SecurityBlockError
from agentshield.core.pipeline import SecurityPipeline
from agentshield.core.result import SecurityReport

logger = logging.getLogger(__name__)


class MicrosoftAgentShield:
    """Microsoft Agents SDK security middleware for agentshield.

    This class patches a bot's ``on_turn`` or ``on_message_activity`` method
    so that every incoming activity is scanned for injection attacks, and
    every outgoing ``send_activity`` call is scanned for data leakage.

    Parameters
    ----------
    pipeline:
        An active :class:`~agentshield.core.pipeline.SecurityPipeline`.
    session_id:
        Optional stable identifier for the conversation session.
    block_on_critical:
        When ``True`` (default), raise
        :class:`~agentshield.core.exceptions.SecurityBlockError` on CRITICAL
        findings.  When ``False``, log a warning and allow processing to
        continue.

    Example
    -------
    ::

        shield = MicrosoftAgentShield(pipeline)
        shield.install(bot)
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

    def install(self, agent: object) -> None:
        """Monkey-patch *agent* to run security scans on every turn.

        Patches the following methods when present:

        * ``on_message_activity`` — scans incoming message text.
        * ``on_turn`` — wraps the full turn with lifecycle scanning.

        Parameters
        ----------
        agent:
            Any Microsoft Agents SDK ``ActivityHandler``-compatible object.

        Raises
        ------
        AttributeError
            If *agent* has neither ``on_message_activity`` nor ``on_turn``.
        """
        has_message = hasattr(agent, "on_message_activity")
        has_turn = hasattr(agent, "on_turn")

        if not has_message and not has_turn:
            raise AttributeError(
                f"MicrosoftAgentShield.install() received {type(agent).__name__!r} "
                "which has neither 'on_message_activity' nor 'on_turn'. "
                "Pass a valid ActivityHandler instance."
            )

        shield = self

        if has_message:
            original_on_message = agent.on_message_activity

            async def patched_on_message_activity(turn_context: object) -> None:
                text = _extract_activity_text(turn_context)
                if text:
                    report = await shield.pipeline.scan_input(
                        text, session_id=shield.session_id
                    )
                    _handle_report("on_message_activity", report, shield.block_on_critical)
                await original_on_message(turn_context)

            agent.on_message_activity = (  # type: ignore[method-assign]
                patched_on_message_activity
            )
            logger.debug(
                "MicrosoftAgentShield installed on_message_activity on %r.",
                getattr(agent, "name", agent),
            )

        if has_turn:
            original_on_turn = agent.on_turn

            async def patched_on_turn(turn_context: object) -> None:
                # Wrap send_activity to scan outgoing messages
                _install_send_activity_hook(turn_context, shield)
                await original_on_turn(turn_context)

            agent.on_turn = patched_on_turn  # type: ignore[method-assign]
            logger.debug(
                "MicrosoftAgentShield installed on_turn on %r.",
                getattr(agent, "name", agent),
            )

    def scan_activity(self, activity: object) -> SecurityReport:
        """Scan an incoming activity synchronously.

        Parameters
        ----------
        activity:
            A Microsoft Agents SDK ``Activity`` (or any object with a ``text``
            attribute) to scan.

        Returns
        -------
        SecurityReport
        """
        text = _extract_text_from_activity(activity)
        return asyncio.run(
            self.pipeline.scan_input(text, session_id=self.session_id)
        )

    async def scan_activity_async(self, activity: object) -> SecurityReport:
        """Async variant of :meth:`scan_activity`.

        Parameters
        ----------
        activity:
            A Microsoft Agents SDK ``Activity`` to scan.

        Returns
        -------
        SecurityReport
        """
        text = _extract_text_from_activity(activity)
        return await self.pipeline.scan_input(text, session_id=self.session_id)

    def scan_outgoing_text(self, text: str) -> SecurityReport:
        """Scan outgoing bot response text synchronously.

        Parameters
        ----------
        text:
            The response text the bot is about to send.

        Returns
        -------
        SecurityReport
        """
        return asyncio.run(
            self.pipeline.scan_output(text, session_id=self.session_id)
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_activity_text(turn_context: object) -> str:
    """Extract user message text from a TurnContext object."""
    activity = getattr(turn_context, "activity", None)
    if activity is None:
        return ""
    return _extract_text_from_activity(activity)


def _extract_text_from_activity(activity: object) -> str:
    """Extract text from a Microsoft Agents SDK Activity or similar object."""
    if isinstance(activity, str):
        return activity
    text = getattr(activity, "text", None)
    if isinstance(text, str):
        return text
    return str(activity)


def _install_send_activity_hook(turn_context: object, shield: MicrosoftAgentShield) -> None:
    """Monkey-patch ``turn_context.send_activity`` to scan outgoing messages."""
    if not hasattr(turn_context, "send_activity"):
        return

    original_send = turn_context.send_activity  # type: ignore[union-attr]

    async def patched_send_activity(activity: Any) -> Any:  # noqa: ANN401
        text: str = ""
        if isinstance(activity, str):
            text = activity
        else:
            text = getattr(activity, "text", "") or ""

        if text:
            report = await shield.pipeline.scan_output(
                text, session_id=shield.session_id
            )
            _handle_report("send_activity", report, shield.block_on_critical)

        return await original_send(activity)

    turn_context.send_activity = patched_send_activity  # type: ignore[method-assign]


def _handle_report(
    phase: str, report: SecurityReport, block_on_critical: bool
) -> None:
    if report.has_critical and block_on_critical:
        raise SecurityBlockError(
            f"Microsoft agent {phase} blocked by agentshield: {report.summary}",
            report=report,
        )
    if not report.is_clean:
        logger.warning(
            "agentshield [microsoft_agents:%s] %s", phase, report.summary
        )
