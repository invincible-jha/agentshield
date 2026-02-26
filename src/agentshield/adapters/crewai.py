"""CrewAI middleware adapter.

Provides :class:`AgentShieldCrewMiddleware`, a task callback that can be
registered with a CrewAI ``Task`` (or ``Crew``) to scan task inputs and
outputs through the agentshield pipeline.

CrewAI is an optional dependency.  This module does not import CrewAI at
module level — the adapter works with any object that exposes the expected
callback interface, and performs lazy validation at instantiation.

Example
-------
::

    from agentshield import SecurityPipeline
    from agentshield.adapters.crewai import AgentShieldCrewMiddleware
    from crewai import Task, Crew

    pipeline = SecurityPipeline.default()
    middleware = AgentShieldCrewMiddleware(pipeline)

    task = Task(
        description="Summarise the document.",
        callback=middleware.task_callback,
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


class AgentShieldCrewMiddleware:
    """CrewAI task middleware that scans task I/O via agentshield.

    This middleware exposes:

    * :meth:`task_callback` — a synchronous callback compatible with
      CrewAI's ``Task(callback=...)`` parameter.  Scans the task output.
    * :meth:`before_kickoff` — an async hook for scanning the crew's
      initial input before execution begins.

    Parameters
    ----------
    pipeline:
        An active :class:`~agentshield.core.pipeline.SecurityPipeline`.
    session_id:
        Optional session identifier.
    """

    def __init__(
        self,
        pipeline: SecurityPipeline,
        session_id: str | None = None,
    ) -> None:
        self.pipeline = pipeline
        self.session_id = session_id

    def task_callback(self, output: object) -> None:
        """Scan the output produced by a CrewAI task.

        This method is designed to be passed directly to
        ``Task(callback=middleware.task_callback)``.

        Parameters
        ----------
        output:
            The ``TaskOutput`` object emitted by CrewAI.  The method
            extracts text via the ``raw`` or ``result`` attribute using
            duck-typing.

        Raises
        ------
        SecurityBlockError
            If the pipeline is configured to block and a critical finding
            is detected.
        """
        text = _extract_crew_output(output)
        if not text:
            return
        report = asyncio.run(
            self.pipeline.scan_output(text, session_id=self.session_id)
        )
        _handle_report("task_callback", report)

    async def before_kickoff(
        self, inputs: dict[str, object]
    ) -> None:
        """Scan crew inputs before the crew starts executing.

        Parameters
        ----------
        inputs:
            The crew's initial input dictionary.

        Raises
        ------
        SecurityBlockError
            If the pipeline blocks on critical findings.
        """
        text_parts: list[str] = [
            value for value in inputs.values() if isinstance(value, str)
        ]
        text = " ".join(text_parts)
        if not text:
            return
        report = await self.pipeline.scan_input(text, session_id=self.session_id)
        _handle_report("before_kickoff", report)

    def step_callback(self, agent_output: object) -> None:
        """Scan an intermediate agent step output.

        Compatible with CrewAI's ``step_callback`` parameter on a ``Crew``
        or ``Agent`` instance.

        Parameters
        ----------
        agent_output:
            An ``AgentAction`` or ``AgentFinish`` instance (duck-typed).
        """
        text = _extract_crew_output(agent_output)
        if not text:
            return
        report = asyncio.run(
            self.pipeline.scan_output(text, session_id=self.session_id)
        )
        _handle_report("step_callback", report)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_crew_output(output: object) -> str:
    """Best-effort text extraction from CrewAI output objects."""
    for attribute in ("raw", "result", "output", "text", "content"):
        value = getattr(output, attribute, None)
        if isinstance(value, str) and value:
            return value
    if isinstance(output, str):
        return output
    if isinstance(output, dict):
        parts: list[str] = [v for v in output.values() if isinstance(v, str)]
        return " ".join(parts)
    return str(output)


def _handle_report(phase: str, report: SecurityReport) -> None:
    if report.has_critical:
        raise SecurityBlockError(
            f"CrewAI {phase} blocked by agentshield: {report.summary}",
            report=report,
        )
    if not report.is_clean:
        logger.warning("agentshield [crewai:%s] %s", phase, report.summary)
