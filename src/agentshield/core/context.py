"""Per-request scan context.

A :class:`ScanContext` instance is created at the start of each pipeline
invocation and passed to every scanner in the chain.  It carries
identifiers that allow correlated findings to be grouped in reports, and
accumulates findings across multiple scanner runs within the same logical
request.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from agentshield.core.scanner import Finding, ScanPhase


@dataclass
class ScanContext:
    """Mutable context shared across all scanners within one pipeline run.

    Attributes
    ----------
    phase:
        The current :class:`~agentshield.core.scanner.ScanPhase`.
    agent_id:
        Stable identifier for the agent instance.  Used to correlate
        findings across requests in the report.
    session_id:
        Identifier for the current user or conversation session.
        Defaults to a fresh UUID when not supplied.
    tool_name:
        Only set during :attr:`~agentshield.core.scanner.ScanPhase.TOOL_CALL`
        scans — the name of the tool being invoked.
    metadata:
        Arbitrary key-value pairs supplied by the caller (framework
        adapter, wrapper, etc.).  Useful for passing request IDs, user
        roles, environment labels, and so on.
    accumulated_findings:
        Findings appended by scanners as they run.  The pipeline reads
        this list to build the final :class:`~agentshield.core.result.SecurityReport`.

    Example
    -------
    ::

        ctx = ScanContext(
            phase=ScanPhase.INPUT,
            agent_id="order-agent-v2",
            session_id="user-abc123",
            metadata={"environment": "production"},
        )
    """

    phase: ScanPhase
    agent_id: str = "default"
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tool_name: str | None = None
    metadata: dict[str, object] = field(default_factory=dict)
    accumulated_findings: list[Finding] = field(default_factory=list)

    def add_findings(self, findings: list[Finding]) -> None:
        """Append *findings* to the accumulated list.

        Parameters
        ----------
        findings:
            One or more findings produced by a scanner.
        """
        self.accumulated_findings.extend(findings)

    def for_phase(self, phase: ScanPhase) -> ScanContext:
        """Return a shallow copy of this context with *phase* updated.

        The :attr:`accumulated_findings` list is **shared** (same object
        reference) so findings written in the new context are visible in
        the original.

        Parameters
        ----------
        phase:
            The new scan phase.

        Returns
        -------
        ScanContext
            A new context object with the phase changed.
        """
        return ScanContext(
            phase=phase,
            agent_id=self.agent_id,
            session_id=self.session_id,
            tool_name=self.tool_name,
            metadata=dict(self.metadata),
            accumulated_findings=self.accumulated_findings,
        )

    def clone_for_tool(self, tool_name: str) -> ScanContext:
        """Return a shallow copy configured for a tool-call scan.

        Parameters
        ----------
        tool_name:
            The name of the tool being invoked.

        Returns
        -------
        ScanContext
            A new context object with :attr:`phase` set to
            :attr:`~agentshield.core.scanner.ScanPhase.TOOL_CALL` and
            :attr:`tool_name` set.
        """
        return ScanContext(
            phase=ScanPhase.TOOL_CALL,
            agent_id=self.agent_id,
            session_id=self.session_id,
            tool_name=tool_name,
            metadata=dict(self.metadata),
            accumulated_findings=self.accumulated_findings,
        )
