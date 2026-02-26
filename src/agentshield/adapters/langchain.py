"""LangChain callback adapter.

Integrates agentshield into a LangChain agent by implementing
``BaseCallbackHandler``.  Register an instance of
:class:`AgentShieldCallback` in the LangChain callbacks list to
automatically scan LLM inputs, tool calls, and LLM outputs.

LangChain is an optional dependency.  This module raises
:class:`ImportError` only when the class is instantiated, not at import
time, so that the rest of agentshield remains usable without LangChain
installed.

Example
-------
::

    from agentshield import SecurityPipeline
    from agentshield.adapters.langchain import AgentShieldCallback

    pipeline = SecurityPipeline.default()
    callback = AgentShieldCallback(pipeline)

    chain = LLMChain(llm=llm, prompt=prompt, callbacks=[callback])
"""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from agentshield.core.exceptions import SecurityBlockError
from agentshield.core.pipeline import SecurityPipeline

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


def _get_base_callback_handler() -> type:
    """Lazy import of LangChain's BaseCallbackHandler.

    Raises
    ------
    ImportError
        If ``langchain`` is not installed.
    """
    try:
        from langchain.callbacks.base import BaseCallbackHandler

        return BaseCallbackHandler
    except ImportError as exc:
        raise ImportError(
            "langchain is required for AgentShieldCallback. "
            "Install it with: pip install langchain"
        ) from exc


class AgentShieldCallback:
    """LangChain callback handler that scans LLM events via agentshield.

    Inherits from ``langchain.callbacks.base.BaseCallbackHandler`` at
    instantiation time (lazy import) so that this module can be imported
    without LangChain installed.

    Parameters
    ----------
    pipeline:
        An active :class:`~agentshield.core.pipeline.SecurityPipeline`.
    session_id:
        Optional session identifier embedded in every
        :class:`~agentshield.core.context.ScanContext`.

    Raises
    ------
    SecurityBlockError
        On LLM start or tool start when a CRITICAL/HIGH finding is
        produced and the pipeline is configured to block.
    """

    def __new__(cls, pipeline: SecurityPipeline, session_id: str | None = None) -> AgentShieldCallback:
        base = _get_base_callback_handler()
        # Dynamically create the class with the correct base at first instantiation.
        if not issubclass(cls, base):
            # Create a specialised subclass on-the-fly.
            dynamic_cls = type("AgentShieldCallback", (base,), dict(cls.__dict__))
            instance = object.__new__(dynamic_cls)
        else:
            instance = object.__new__(cls)
        return instance  # type: ignore[return-value]

    def __init__(
        self, pipeline: SecurityPipeline, session_id: str | None = None
    ) -> None:
        try:
            super().__init__()  # type: ignore[call-arg]
        except TypeError:
            pass
        self.pipeline = pipeline
        self.session_id = session_id

    # ------------------------------------------------------------------
    # LangChain callback interface
    # ------------------------------------------------------------------

    def on_llm_start(
        self,
        serialized: dict[str, object],
        prompts: list[str],
        **kwargs: object,
    ) -> None:
        """Scan prompts before they reach the LLM.

        Parameters
        ----------
        serialized:
            LangChain serialised LLM configuration (not scanned).
        prompts:
            The list of prompt strings about to be sent to the LLM.
        """
        combined = "\n".join(prompts)
        report = asyncio.run(
            self.pipeline.scan_input(combined, session_id=self.session_id)
        )
        if report.has_critical:
            raise SecurityBlockError(
                f"LLM input blocked by agentshield: {report.summary}",
                report=report,
            )
        if not report.is_clean:
            logger.warning("agentshield [on_llm_start] %s", report.summary)

    def on_tool_start(
        self,
        serialized: dict[str, object],
        input_str: str,
        **kwargs: object,
    ) -> None:
        """Scan tool input before the tool runs.

        Parameters
        ----------
        serialized:
            LangChain serialised tool metadata — provides the tool name.
        input_str:
            The raw string input to the tool.
        """
        tool_name_raw = serialized.get("name") or serialized.get("id") or ["unknown"]
        tool_name = (
            tool_name_raw[-1]
            if isinstance(tool_name_raw, list)
            else str(tool_name_raw)
        )
        args: dict[str, object] = {"input": input_str}
        report = asyncio.run(
            self.pipeline.scan_tool_call(
                tool_name, args, session_id=self.session_id
            )
        )
        if report.has_critical:
            raise SecurityBlockError(
                f"Tool call '{tool_name}' blocked by agentshield: {report.summary}",
                report=report,
            )
        if not report.is_clean:
            logger.warning("agentshield [on_tool_start] %s", report.summary)

    def on_llm_end(self, response: object, **kwargs: object) -> None:
        """Scan LLM output after generation.

        Parameters
        ----------
        response:
            A ``langchain.schema.LLMResult`` object.  The generations are
            extracted via duck-typing to avoid a hard import.
        """
        text_parts: list[str] = []
        generations_attr = getattr(response, "generations", None)
        if isinstance(generations_attr, list):
            for batch in generations_attr:
                if isinstance(batch, list):
                    for gen in batch:
                        text_val = getattr(gen, "text", None)
                        if isinstance(text_val, str):
                            text_parts.append(text_val)
        combined = "\n".join(text_parts)
        if not combined:
            return
        report = asyncio.run(
            self.pipeline.scan_output(combined, session_id=self.session_id)
        )
        if report.has_critical:
            raise SecurityBlockError(
                f"LLM output blocked by agentshield: {report.summary}",
                report=report,
            )
        if not report.is_clean:
            logger.warning("agentshield [on_llm_end] %s", report.summary)
