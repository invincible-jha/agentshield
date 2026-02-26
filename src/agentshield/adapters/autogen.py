"""AutoGen message filter adapter.

Provides :class:`AgentShieldAutoGenHook`, a message hook that can be
registered with an AutoGen ``ConversableAgent`` to scan messages passing
through the agent's ``process_message`` pipeline.

AutoGen is an optional dependency — this module uses duck-typing and
lazy imports so that agentshield remains importable without AutoGen.

Example
-------
::

    from agentshield import SecurityPipeline
    from agentshield.adapters.autogen import AgentShieldAutoGenHook

    pipeline = SecurityPipeline.default()
    hook = AgentShieldAutoGenHook(pipeline)

    # Register the hook as a message pre-processor:
    agent = autogen.ConversableAgent(
        "my_agent",
        ...
    )
    # Wrap the agent's receive method:
    hook.install(agent)
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from agentshield.core.exceptions import SecurityBlockError
from agentshield.core.pipeline import SecurityPipeline
from agentshield.core.result import SecurityReport

logger = logging.getLogger(__name__)

# AutoGen message structure type alias (avoid importing autogen at module level).
AutoGenMessage = dict[str, object]


class AgentShieldAutoGenHook:
    """AutoGen message filter that scans incoming and outgoing messages.

    Parameters
    ----------
    pipeline:
        An active :class:`~agentshield.core.pipeline.SecurityPipeline`.
    session_id:
        Optional stable identifier for the conversation session.
    block_on_critical:
        When ``True`` (default), raise :class:`~agentshield.core.exceptions.SecurityBlockError`
        if a CRITICAL finding is detected, regardless of the pipeline's
        own ``on_finding`` setting.

    Example
    -------
    ::

        hook = AgentShieldAutoGenHook(pipeline)
        hook.install(agent)          # monkey-patches agent.receive
        hook.install_generate(agent) # monkey-patches agent.generate_reply
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

    def process_incoming_message(self, message: AutoGenMessage) -> AutoGenMessage:
        """Scan an incoming message before the agent processes it.

        Call this at the top of a custom ``receive`` override, or use
        :meth:`install` to apply it automatically.

        Parameters
        ----------
        message:
            AutoGen message dict — typically contains ``"content"`` (str)
            and optionally ``"role"`` (str).

        Returns
        -------
        AutoGenMessage
            The original message, unmodified.  (Filtering is out-of-scope
            for this adapter; use SecurityBlockError to halt processing.)

        Raises
        ------
        SecurityBlockError
            If a critical finding is detected and :attr:`block_on_critical`
            is ``True``.
        """
        text = _extract_message_text(message)
        report = asyncio.run(
            self.pipeline.scan_input(text, session_id=self.session_id)
        )
        _handle_report("incoming", report, self.block_on_critical)
        return message

    def process_outgoing_message(self, message: AutoGenMessage) -> AutoGenMessage:
        """Scan an outgoing message before it is sent.

        Parameters
        ----------
        message:
            AutoGen message dict being sent to another agent or the user.

        Returns
        -------
        AutoGenMessage
            The original message, unmodified.

        Raises
        ------
        SecurityBlockError
            If a critical finding is detected and :attr:`block_on_critical`
            is ``True``.
        """
        text = _extract_message_text(message)
        report = asyncio.run(
            self.pipeline.scan_output(text, session_id=self.session_id)
        )
        _handle_report("outgoing", report, self.block_on_critical)
        return message

    def install(self, agent: object) -> None:
        """Monkey-patch ``agent.receive`` to run the incoming message hook.

        Parameters
        ----------
        agent:
            Any AutoGen agent object that has a ``receive`` method.

        Raises
        ------
        AttributeError
            If the agent does not have a ``receive`` method.
        """
        original_receive = getattr(agent, "receive")
        hook = self

        def patched_receive(
            message: AutoGenMessage,
            sender: object,
            request_reply: bool | None = None,
            silent: bool = False,
        ) -> None:
            hook.process_incoming_message(message)
            original_receive(message, sender, request_reply, silent)

        agent.receive = patched_receive  # type: ignore[method-assign]
        logger.debug(
            "AgentShieldAutoGenHook installed on agent %r (receive).",
            getattr(agent, "name", agent),
        )

    def install_generate(self, agent: object) -> None:
        """Monkey-patch ``agent.generate_reply`` to run the outgoing message hook.

        Parameters
        ----------
        agent:
            Any AutoGen agent object that has a ``generate_reply`` method.
        """
        original_generate = getattr(agent, "generate_reply")
        hook = self

        def patched_generate_reply(
            messages: list[AutoGenMessage] | None = None,
            sender: object = None,
            **kwargs: object,
        ) -> AutoGenMessage | str | None:
            result = original_generate(messages=messages, sender=sender, **kwargs)
            if isinstance(result, dict):
                hook.process_outgoing_message(result)
            elif isinstance(result, str):
                hook.process_outgoing_message({"content": result})
            return result

        agent.generate_reply = patched_generate_reply  # type: ignore[method-assign]
        logger.debug(
            "AgentShieldAutoGenHook installed on agent %r (generate_reply).",
            getattr(agent, "name", agent),
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_message_text(message: AutoGenMessage) -> str:
    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for part in content:
            if isinstance(part, str):
                parts.append(part)
            elif isinstance(part, dict):
                text_val = part.get("text")
                if isinstance(text_val, str):
                    parts.append(text_val)
        return " ".join(parts)
    return str(message)


def _handle_report(
    phase: str, report: SecurityReport, block_on_critical: bool
) -> None:
    if report.has_critical and block_on_critical:
        raise SecurityBlockError(
            f"AutoGen {phase} message blocked by agentshield: {report.summary}",
            report=report,
        )
    if not report.is_clean:
        logger.warning(
            "agentshield [autogen:%s] %s", phase, report.summary
        )
