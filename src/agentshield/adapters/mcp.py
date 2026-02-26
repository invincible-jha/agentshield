"""MCP (Model Context Protocol) integration adapter.

Provides :class:`MCPShield`, a middleware wrapper for the Model Context
Protocol message format.  It intercepts tool calls and server responses
before they are forwarded to the backing MCP server or returned to the
client.

The MCP SDK is an optional dependency.  This module uses duck-typing and
does not import MCP packages at module level.

Example
-------
::

    from agentshield import SecurityPipeline
    from agentshield.adapters.mcp import MCPShield

    pipeline = SecurityPipeline.default()
    mcp_shield = MCPShield(pipeline)

    # Intercept a tool call before dispatching it:
    report = await mcp_shield.intercept_tool_call(
        tool_name="read_resource",
        arguments={"uri": "file:///etc/passwd"},
    )

    # Intercept a server response before returning it to the client:
    report = await mcp_shield.intercept_response(
        tool_name="read_resource",
        response_text="Resource contents...",
    )
"""
from __future__ import annotations

import json
import logging

from agentshield.core.exceptions import SecurityBlockError
from agentshield.core.pipeline import SecurityPipeline
from agentshield.core.result import SecurityReport

logger = logging.getLogger(__name__)


class MCPShield:
    """Agentshield middleware for the Model Context Protocol (MCP).

    This class wraps a :class:`~agentshield.core.pipeline.SecurityPipeline`
    and provides two interception points aligned with the MCP message flow:

    * :meth:`intercept_tool_call` — scans an outgoing tool invocation
      (``tools/call`` request) before it is dispatched to the MCP server.
    * :meth:`intercept_response` — scans the tool result text returned by
      the MCP server before it is forwarded to the model.

    Parameters
    ----------
    pipeline:
        An active :class:`~agentshield.core.pipeline.SecurityPipeline`.
    session_id:
        Optional stable identifier for the current MCP session.  When
        not supplied, the pipeline generates a fresh UUID per scan.
    block_on_critical:
        When ``True`` (default), raise
        :class:`~agentshield.core.exceptions.SecurityBlockError` if any
        CRITICAL finding is detected, regardless of the pipeline's own
        ``on_finding`` action.

    Example
    -------
    ::

        shield = MCPShield(pipeline, block_on_critical=True)
        await shield.intercept_tool_call("list_directory", {"path": "/tmp"})
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

    async def intercept_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, object],
        *,
        metadata: dict[str, object] | None = None,
    ) -> SecurityReport:
        """Scan a tool call before it is dispatched to the MCP server.

        Parameters
        ----------
        tool_name:
            The name of the MCP tool being invoked (e.g. ``"read_resource"``).
        arguments:
            The tool argument dictionary from the ``tools/call`` request.
        metadata:
            Optional key-value metadata forwarded to the scan context.

        Returns
        -------
        SecurityReport
            The scan report.  Inspect :attr:`~SecurityReport.is_clean` or
            :attr:`~SecurityReport.has_critical` to decide how to proceed.

        Raises
        ------
        SecurityBlockError
            If :attr:`block_on_critical` is ``True`` and any CRITICAL
            finding is produced.
        """
        report = await self.pipeline.scan_tool_call(
            tool_name,
            arguments,
            session_id=self.session_id,
            metadata=metadata,
        )
        self._handle_report("intercept_tool_call", tool_name, report)
        return report

    async def intercept_response(
        self,
        tool_name: str,
        response_text: str,
        *,
        metadata: dict[str, object] | None = None,
    ) -> SecurityReport:
        """Scan an MCP server response before returning it to the model.

        Parameters
        ----------
        tool_name:
            The name of the MCP tool that produced this response.  Used
            to annotate the scan context.
        response_text:
            The textual content of the MCP tool result.
        metadata:
            Optional key-value metadata forwarded to the scan context.

        Returns
        -------
        SecurityReport
            The scan report.

        Raises
        ------
        SecurityBlockError
            If :attr:`block_on_critical` is ``True`` and any CRITICAL
            finding is produced.
        """
        effective_metadata: dict[str, object] = dict(metadata or {})
        effective_metadata["mcp_tool_name"] = tool_name

        report = await self.pipeline.scan_output(
            response_text,
            session_id=self.session_id,
            metadata=effective_metadata,
        )
        self._handle_report("intercept_response", tool_name, report)
        return report

    def intercept_tool_call_sync(
        self,
        tool_name: str,
        arguments: dict[str, object],
        *,
        metadata: dict[str, object] | None = None,
    ) -> SecurityReport:
        """Synchronous wrapper around :meth:`intercept_tool_call`.

        Parameters
        ----------
        tool_name:
            The MCP tool name.
        arguments:
            The tool argument dictionary.
        metadata:
            Optional scan context metadata.

        Returns
        -------
        SecurityReport
        """
        return self.pipeline.scan_tool_call_sync(
            tool_name,
            arguments,
            session_id=self.session_id,
            metadata=metadata,
        )

    def intercept_response_sync(
        self,
        tool_name: str,
        response_text: str,
        *,
        metadata: dict[str, object] | None = None,
    ) -> SecurityReport:
        """Synchronous wrapper around :meth:`intercept_response`.

        Parameters
        ----------
        tool_name:
            The MCP tool name.
        response_text:
            The tool result text to scan.
        metadata:
            Optional scan context metadata.

        Returns
        -------
        SecurityReport
        """
        effective_metadata: dict[str, object] = dict(metadata or {})
        effective_metadata["mcp_tool_name"] = tool_name
        return self.pipeline.scan_output_sync(
            response_text,
            session_id=self.session_id,
            metadata=effective_metadata,
        )

    def from_mcp_message(
        self,
        message: dict[str, object],
    ) -> tuple[str, dict[str, object]]:
        """Extract tool name and arguments from a raw MCP ``tools/call`` message.

        This helper parses the standard MCP JSON-RPC request format so that
        callers can pass raw message dictionaries directly.

        Parameters
        ----------
        message:
            A dict representing a ``tools/call`` JSON-RPC request.  Expected
            shape::

                {
                    "method": "tools/call",
                    "params": {
                        "name": "<tool_name>",
                        "arguments": { ... }
                    }
                }

        Returns
        -------
        tuple[str, dict[str, object]]
            ``(tool_name, arguments)`` ready to pass to
            :meth:`intercept_tool_call`.

        Raises
        ------
        ValueError
            If the message does not conform to the expected MCP shape.
        """
        params = message.get("params")
        if not isinstance(params, dict):
            raise ValueError(
                "MCP message missing 'params' mapping. "
                f"Got: {type(params).__name__!r}"
            )
        tool_name_raw = params.get("name")
        if not isinstance(tool_name_raw, str) or not tool_name_raw:
            raise ValueError(
                "MCP message 'params.name' must be a non-empty string. "
                f"Got: {tool_name_raw!r}"
            )
        arguments_raw = params.get("arguments", {})
        if not isinstance(arguments_raw, dict):
            raise ValueError(
                "MCP message 'params.arguments' must be a mapping. "
                f"Got: {type(arguments_raw).__name__!r}"
            )
        return tool_name_raw, arguments_raw

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _handle_report(
        self, phase: str, tool_name: str, report: SecurityReport
    ) -> None:
        if self.block_on_critical and report.has_critical:
            raise SecurityBlockError(
                f"MCP {phase} for tool '{tool_name}' blocked by agentshield: "
                f"{report.summary}",
                report=report,
            )
        if not report.is_clean:
            logger.warning(
                "agentshield [mcp:%s] tool=%r %s",
                phase,
                tool_name,
                report.summary,
            )
