"""AgentWrapper — universal callable wrapper for any agent function.

The wrapper intercepts input before execution, output after execution, and
(optionally) tool calls that appear in the output via a ``"tool_calls"``
key in the returned dictionary.

Any callable that accepts ``dict[str, object]`` and returns
``dict[str, object]`` — synchronous or asynchronous — can be wrapped.
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Coroutine
from typing import TypeVar, overload

from agentshield.core.exceptions import SecurityBlockError
from agentshield.core.pipeline import SecurityPipeline
from agentshield.core.result import SecurityReport
from agentshield.middleware.hooks import PostExecutionHook, PreExecutionHook, ToolCallHook

logger = logging.getLogger(__name__)

AgentInput = dict[str, object]
AgentOutput = dict[str, object]

SyncAgentCallable = Callable[[AgentInput], AgentOutput]
AsyncAgentCallable = Callable[[AgentInput], Coroutine[object, object, AgentOutput]]
AnyAgentCallable = SyncAgentCallable | AsyncAgentCallable

_T = TypeVar("_T")


class AgentWrapper:
    """Wrap any agent callable with agentshield security scanning.

    The wrapper adds three scan points:

    1. **Pre-execution** — the input dictionary is scanned before the agent
       runs.
    2. **Post-execution** — the output dictionary is scanned after the agent
       returns.
    3. **Tool-call** — if the output contains a ``"tool_calls"`` key (a list
       of ``{"tool_name": str, "args": dict}`` items), each tool call is
       scanned individually.

    If any scan raises :class:`~agentshield.core.exceptions.SecurityBlockError`
    the error propagates to the caller; the agent result is not returned.

    Example
    -------
    ::

        pipeline = SecurityPipeline.default()
        wrapper  = AgentWrapper(pipeline)

        async def my_agent(payload: dict) -> dict:
            return {"output": "Hello, world!"}

        secured = wrapper.wrap(my_agent)
        result  = await secured({"input": "user message"})
    """

    def __init__(
        self,
        pipeline: SecurityPipeline,
        *,
        session_id: str | None = None,
        scan_tool_calls: bool = True,
    ) -> None:
        self.pipeline = pipeline
        self.session_id = session_id
        self.scan_tool_calls = scan_tool_calls
        self._pre_hook = PreExecutionHook()
        self._post_hook = PostExecutionHook()
        self._tool_hook = ToolCallHook()

    def wrap(
        self, agent_callable: AnyAgentCallable
    ) -> Callable[[AgentInput], Coroutine[object, object, AgentOutput]]:
        """Return a secured async version of *agent_callable*.

        If *agent_callable* is synchronous it is run in a thread executor to
        avoid blocking the event loop.

        Parameters
        ----------
        agent_callable:
            The original agent function (sync or async).

        Returns
        -------
        Callable[[AgentInput], Coroutine[..., AgentOutput]]
            An async function with the same signature as the original.
        """
        is_coro = asyncio.iscoroutinefunction(agent_callable)

        async def secured(payload: AgentInput) -> AgentOutput:
            metadata: dict[str, object] = {"wrapped_callable": getattr(agent_callable, "__name__", "unknown")}

            # --- 1. Input scan -------------------------------------------
            input_report = await self._pre_hook(
                self.pipeline, payload, self.session_id, metadata
            )
            _log_report("input", input_report)

            # --- 2. Agent execution --------------------------------------
            if is_coro:
                async_fn = agent_callable  # type: ignore[assignment]
                result: AgentOutput = await async_fn(payload)
            else:
                loop = asyncio.get_event_loop()
                sync_fn = agent_callable  # type: ignore[assignment]
                result = await loop.run_in_executor(None, sync_fn, payload)

            # --- 3. Output scan ------------------------------------------
            output_report = await self._post_hook(
                self.pipeline, result, self.session_id, metadata
            )
            _log_report("output", output_report)

            # --- 4. Tool-call scans (optional) ---------------------------
            if self.scan_tool_calls and "tool_calls" in result:
                tool_calls_raw = result.get("tool_calls")
                if isinstance(tool_calls_raw, list):
                    for tool_call in tool_calls_raw:
                        if not isinstance(tool_call, dict):
                            continue
                        tc_report = await self._tool_hook(
                            self.pipeline, tool_call, self.session_id, metadata
                        )
                        _log_report("tool_call", tc_report)

            return result

        secured.__name__ = f"agentshield_secured_{getattr(agent_callable, '__name__', 'agent')}"
        secured.__qualname__ = secured.__name__
        return secured

    def wrap_sync(self, agent_callable: SyncAgentCallable) -> SyncAgentCallable:
        """Return a secured synchronous wrapper using :func:`asyncio.run`.

        Only use this when the caller's environment cannot use ``await``.
        This wrapper is not safe to call from within a running event loop.

        Parameters
        ----------
        agent_callable:
            A synchronous agent function.

        Returns
        -------
        SyncAgentCallable
            A synchronous function with the same signature.
        """
        async_secured = self.wrap(agent_callable)

        def secured_sync(payload: AgentInput) -> AgentOutput:
            return asyncio.run(async_secured(payload))

        secured_sync.__name__ = f"agentshield_sync_{getattr(agent_callable, '__name__', 'agent')}"
        return secured_sync


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _log_report(phase: str, report: SecurityReport) -> None:
    if not report.is_clean:
        logger.warning(
            "agentshield [%s] %s | session=%s",
            phase,
            report.summary,
            report.session_id,
        )
