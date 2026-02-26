"""Generic function decorator adapter.

Provides :func:`shield` — a decorator that wraps any callable (sync or
async) with agentshield input/output scanning without requiring a specific
framework.

Example
-------
::

    from agentshield import SecurityPipeline
    from agentshield.adapters.generic import shield

    pipeline = SecurityPipeline.default()

    @shield(pipeline)
    async def my_agent_fn(payload: dict) -> dict:
        return {"output": "Hello!"}

    result = await my_agent_fn({"input": "user text"})
"""
from __future__ import annotations

import asyncio
import functools
import logging
from collections.abc import Callable, Coroutine
from typing import TypeVar, overload

from agentshield.core.pipeline import SecurityPipeline
from agentshield.middleware.wrapper import AgentWrapper

logger = logging.getLogger(__name__)

AgentInput = dict[str, object]
AgentOutput = dict[str, object]

_SyncFn = Callable[[AgentInput], AgentOutput]
_AsyncFn = Callable[[AgentInput], Coroutine[object, object, AgentOutput]]
_AnyFn = _SyncFn | _AsyncFn


def shield(
    pipeline: SecurityPipeline,
    *,
    session_id: str | None = None,
    scan_tool_calls: bool = True,
) -> Callable[[_AnyFn], Callable[[AgentInput], Coroutine[object, object, AgentOutput]]]:
    """Decorate an agent function with agentshield scanning.

    The decorated function is always async.  If the original function is
    synchronous it is wrapped with a thread-executor call to avoid blocking
    the event loop.

    Parameters
    ----------
    pipeline:
        An active :class:`~agentshield.core.pipeline.SecurityPipeline`.
    session_id:
        Optional stable session identifier forwarded to every
        :class:`~agentshield.core.context.ScanContext`.
    scan_tool_calls:
        Whether to scan ``"tool_calls"`` entries in the output dictionary.
        Defaults to ``True``.

    Returns
    -------
    Callable
        A decorator that wraps the target function.

    Example
    -------
    ::

        @shield(pipeline, session_id="user-abc")
        async def agent(payload: dict) -> dict:
            return {"output": "response"}
    """

    def decorator(
        fn: _AnyFn,
    ) -> Callable[[AgentInput], Coroutine[object, object, AgentOutput]]:
        wrapper = AgentWrapper(
            pipeline,
            session_id=session_id,
            scan_tool_calls=scan_tool_calls,
        )
        secured = wrapper.wrap(fn)
        # Preserve original function metadata.
        functools.update_wrapper(secured, fn)  # type: ignore[arg-type]
        return secured

    return decorator


def shield_sync(
    pipeline: SecurityPipeline,
    *,
    session_id: str | None = None,
    scan_tool_calls: bool = True,
) -> Callable[[_SyncFn], _SyncFn]:
    """Decorate a *synchronous* agent function with agentshield scanning.

    Unlike :func:`shield`, this returns a synchronous callable that uses
    :func:`asyncio.run` internally.  Do not use this inside an already-
    running event loop.

    Parameters
    ----------
    pipeline:
        An active :class:`~agentshield.core.pipeline.SecurityPipeline`.
    session_id:
        Optional session identifier.
    scan_tool_calls:
        Whether to scan ``"tool_calls"`` entries in the output.

    Returns
    -------
    Callable
        A synchronous decorator.

    Example
    -------
    ::

        @shield_sync(pipeline)
        def agent(payload: dict) -> dict:
            return {"output": "response"}

        result = agent({"input": "hello"})
    """

    def decorator(fn: _SyncFn) -> _SyncFn:
        wrapper = AgentWrapper(
            pipeline,
            session_id=session_id,
            scan_tool_calls=scan_tool_calls,
        )
        secured_sync = wrapper.wrap_sync(fn)
        functools.update_wrapper(secured_sync, fn)
        return secured_sync

    return decorator
