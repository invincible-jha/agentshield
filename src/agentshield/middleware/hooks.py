"""Pre/post execution hooks for the AgentWrapper.

Hooks are thin callable wrappers that invoke specific pipeline scan phases
at defined points in an agent's execution lifecycle.  They are framework-
agnostic and operate solely through the :class:`~agentshield.core.pipeline.SecurityPipeline`
interface.
"""
from __future__ import annotations

import logging
from typing import Protocol, runtime_checkable

from agentshield.core.pipeline import SecurityPipeline
from agentshield.core.result import SecurityReport

logger = logging.getLogger(__name__)


@runtime_checkable
class HookProtocol(Protocol):
    """Structural protocol every hook satisfies."""

    async def __call__(
        self,
        pipeline: SecurityPipeline,
        payload: dict[str, object],
        session_id: str | None,
        metadata: dict[str, object] | None,
    ) -> SecurityReport: ...


class PreExecutionHook:
    """Run an input scan before the agent executes.

    The hook serialises the *payload* dictionary to a plain string
    representation by joining all string-typed values.  This is a
    best-effort heuristic; for richer input representations consider
    implementing a custom hook.

    Example
    -------
    ::

        hook = PreExecutionHook()
        report = await hook(pipeline, {"input": "user text"}, session_id=None, metadata={})
    """

    async def __call__(
        self,
        pipeline: SecurityPipeline,
        payload: dict[str, object],
        session_id: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> SecurityReport:
        """Scan the agent's input payload.

        Parameters
        ----------
        pipeline:
            The active security pipeline.
        payload:
            The agent's input dictionary.  All string values are
            concatenated with a space separator and passed to the
            scanner chain.
        session_id:
            Optional session identifier.
        metadata:
            Arbitrary key-value metadata forwarded to the context.

        Returns
        -------
        SecurityReport
            Report from the INPUT phase scan.
        """
        text = _extract_text(payload)
        logger.debug("PreExecutionHook: scanning %d chars of input.", len(text))
        return await pipeline.scan_input(
            text, session_id=session_id, metadata=metadata
        )


class PostExecutionHook:
    """Run an output scan after the agent produces a result.

    Example
    -------
    ::

        hook = PostExecutionHook()
        report = await hook(pipeline, {"output": "agent response"}, session_id=None, metadata={})
    """

    async def __call__(
        self,
        pipeline: SecurityPipeline,
        payload: dict[str, object],
        session_id: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> SecurityReport:
        """Scan the agent's output payload.

        Parameters
        ----------
        pipeline:
            The active security pipeline.
        payload:
            The agent's output dictionary.  All string values are
            concatenated and scanned.
        session_id:
            Optional session identifier.
        metadata:
            Arbitrary key-value metadata forwarded to the context.

        Returns
        -------
        SecurityReport
            Report from the OUTPUT phase scan.
        """
        text = _extract_text(payload)
        logger.debug("PostExecutionHook: scanning %d chars of output.", len(text))
        return await pipeline.scan_output(
            text, session_id=session_id, metadata=metadata
        )


class ToolCallHook:
    """Run a tool-call scan before a tool is dispatched.

    Example
    -------
    ::

        hook = ToolCallHook()
        report = await hook(
            pipeline,
            {"tool_name": "read_file", "args": {"path": "/tmp/data.txt"}},
            session_id=None,
            metadata={},
        )
    """

    async def __call__(
        self,
        pipeline: SecurityPipeline,
        payload: dict[str, object],
        session_id: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> SecurityReport:
        """Scan a tool invocation payload.

        Parameters
        ----------
        pipeline:
            The active security pipeline.
        payload:
            Must contain ``"tool_name"`` (str) and ``"args"``
            (``dict[str, object]``).  Both keys are required; missing or
            incorrectly typed values are silently defaulted.
        session_id:
            Optional session identifier.
        metadata:
            Arbitrary key-value metadata forwarded to the context.

        Returns
        -------
        SecurityReport
            Report from the TOOL_CALL phase scan.
        """
        tool_name_raw = payload.get("tool_name")
        tool_name = tool_name_raw if isinstance(tool_name_raw, str) else "unknown"
        args_raw = payload.get("args")
        args: dict[str, object] = args_raw if isinstance(args_raw, dict) else {}
        logger.debug("ToolCallHook: scanning tool call to '%s'.", tool_name)
        return await pipeline.scan_tool_call(
            tool_name, args, session_id=session_id, metadata=metadata
        )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _extract_text(payload: dict[str, object]) -> str:
    """Concatenate all string values in *payload* to a single string."""
    parts: list[str] = []
    for value in payload.values():
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, (list, tuple)):
            for item in value:
                if isinstance(item, str):
                    parts.append(item)
    return " ".join(parts)
