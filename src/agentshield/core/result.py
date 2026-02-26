"""Security report produced by a pipeline scan.

Each call to :meth:`~agentshield.core.pipeline.SecurityPipeline.scan_input`,
:meth:`~agentshield.core.pipeline.SecurityPipeline.scan_output`, or
:meth:`~agentshield.core.pipeline.SecurityPipeline.scan_tool_call` returns
a :class:`SecurityReport` that summarises what the scanner chain found.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from agentshield.core.scanner import Finding, FindingSeverity


@dataclass
class SecurityReport:
    """Immutable snapshot of findings from one pipeline invocation.

    Attributes
    ----------
    findings:
        Ordered list of all :class:`~agentshield.core.scanner.Finding`
        objects produced during this scan.
    scan_duration_ms:
        Wall-clock time in milliseconds from pipeline entry to completion.
    agent_id:
        The agent identifier copied from the :class:`~agentshield.core.context.ScanContext`.
    session_id:
        The session identifier copied from the context.
    phase:
        The scan phase (``"input"``, ``"output"``, or ``"tool_call"``).

    Example
    -------
    ::

        report = await pipeline.scan_input("some text")
        if report.has_critical:
            raise SecurityBlockError("Critical finding", report=report)
        print(report.summary)
    """

    findings: list[Finding] = field(default_factory=list)
    scan_duration_ms: float = 0.0
    agent_id: str = "default"
    session_id: str = ""
    phase: str = "input"

    # ------------------------------------------------------------------
    # Convenience predicates
    # ------------------------------------------------------------------

    @property
    def has_critical(self) -> bool:
        """Return ``True`` if any finding has CRITICAL severity."""
        return any(f.severity == FindingSeverity.CRITICAL for f in self.findings)

    @property
    def has_high(self) -> bool:
        """Return ``True`` if any finding has HIGH or CRITICAL severity."""
        return any(f.severity >= FindingSeverity.HIGH for f in self.findings)

    @property
    def has_medium(self) -> bool:
        """Return ``True`` if any finding is at least MEDIUM severity."""
        return any(f.severity >= FindingSeverity.MEDIUM for f in self.findings)

    @property
    def is_clean(self) -> bool:
        """Return ``True`` when no findings were produced."""
        return len(self.findings) == 0

    @property
    def highest_severity(self) -> FindingSeverity | None:
        """Return the highest :class:`FindingSeverity` across all findings.

        Returns ``None`` when :attr:`findings` is empty.
        """
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: f.severity.numeric).severity

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    @property
    def summary(self) -> str:
        """Return a one-line human-readable summary of the scan results.

        Returns
        -------
        str
            A string like ``"2 finding(s): 1 HIGH, 1 MEDIUM"`` or
            ``"No findings."`` when clean.
        """
        if self.is_clean:
            return "No findings."
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.severity.value.upper()] = (
                counts.get(finding.severity.value.upper(), 0) + 1
            )
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        parts = [
            f"{counts[sev]} {sev}" for sev in severity_order if sev in counts
        ]
        total = len(self.findings)
        return f"{total} finding(s): {', '.join(parts)}"

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, object]:
        """Serialise the report to a plain Python dictionary.

        Returns
        -------
        dict[str, object]
            All fields with nested enum values converted to strings.
        """
        return {
            "phase": self.phase,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "scan_duration_ms": self.scan_duration_ms,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialise the report to a JSON string.

        Parameters
        ----------
        indent:
            Number of spaces to use for JSON indentation.

        Returns
        -------
        str
            A valid JSON document.
        """
        return json.dumps(self.to_dict(), indent=indent)

    def __repr__(self) -> str:
        return (
            f"SecurityReport(phase={self.phase!r}, "
            f"findings={len(self.findings)}, "
            f"highest_severity={self.highest_severity!r})"
        )
