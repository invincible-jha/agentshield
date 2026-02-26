"""Scanner ABC and shared finding types.

All scanner implementations must subclass :class:`Scanner` and implement
:meth:`Scanner.scan`.  The pipeline discovers scanners via the
:data:`~agentshield.plugins.registry.scanner_registry` and wires them
into the execution chain based on their declared :attr:`Scanner.phases`.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agentshield.core.context import ScanContext


class ScanPhase(str, Enum):
    """The pipeline phase during which a scanner runs.

    Attributes
    ----------
    INPUT:
        Text arriving from the external environment (user message, tool
        response fed back to the model, etc.).
    OUTPUT:
        Text being emitted by the agent to downstream systems or end-users.
    TOOL_CALL:
        A structured tool invocation before it is dispatched to the
        backing service.
    """

    INPUT = "input"
    OUTPUT = "output"
    TOOL_CALL = "tool_call"


class FindingSeverity(str, Enum):
    """Severity levels aligned with the CVSSv3 qualitative scale.

    Attributes
    ----------
    INFO:
        Informational — no immediate risk, but worth noting.
    LOW:
        Low risk — unlikely to cause harm without additional factors.
    MEDIUM:
        Moderate risk — should be reviewed before deployment.
    HIGH:
        High risk — likely to cause harm; consider blocking.
    CRITICAL:
        Critical risk — block execution and alert immediately.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def numeric(self) -> int:
        """Return an integer weight suitable for comparison.

        Returns
        -------
        int
            0 (INFO) through 4 (CRITICAL).
        """
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, FindingSeverity):
            return NotImplemented
        return self.numeric >= other.numeric

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, FindingSeverity):
            return NotImplemented
        return self.numeric > other.numeric

    def __le__(self, other: object) -> bool:
        if not isinstance(other, FindingSeverity):
            return NotImplemented
        return self.numeric <= other.numeric

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, FindingSeverity):
            return NotImplemented
        return self.numeric < other.numeric


@dataclass
class Finding:
    """A single security observation produced by a scanner.

    Attributes
    ----------
    scanner_name:
        The :attr:`Scanner.name` of the scanner that produced this finding.
    severity:
        How severe the finding is.
    category:
        A machine-readable category string, e.g. ``"prompt_injection"``,
        ``"pii_leak"``, ``"credential_leak"``.
    message:
        A human-readable description of what was detected.
    details:
        Arbitrary structured metadata — matched pattern names, offsets,
        sanitised excerpts, etc.  No raw sensitive data should appear here.

    Example
    -------
    ::

        finding = Finding(
            scanner_name="regex_injection",
            severity=FindingSeverity.HIGH,
            category="prompt_injection",
            message="Possible role-override attempt detected.",
            details={"matched_pattern": "role_override_direct"},
        )
    """

    scanner_name: str
    severity: FindingSeverity
    category: str
    message: str
    details: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        """Serialise the finding to a plain dictionary.

        Returns
        -------
        dict[str, object]
            All fields with enum values converted to their string form.
        """
        return {
            "scanner_name": self.scanner_name,
            "severity": self.severity.value,
            "category": self.category,
            "message": self.message,
            "details": self.details,
        }


class Scanner(ABC):
    """Abstract base class for all agentshield scanner implementations.

    Subclasses **must**:

    * Set :attr:`name` to a unique, stable slug (``"regex_injection"``).
    * Set :attr:`phases` to the subset of :class:`ScanPhase` values that
      the scanner handles.
    * Implement :meth:`scan`.

    The pipeline calls :meth:`scan` only when the current
    :attr:`~agentshield.core.context.ScanContext.phase` is in
    :attr:`phases`.

    Example
    -------
    ::

        class MyScanner(Scanner):
            name = "my_scanner"
            phases = [ScanPhase.INPUT]

            async def scan(
                self, content: str, context: ScanContext
            ) -> list[Finding]:
                if "forbidden" in content.lower():
                    return [
                        Finding(
                            scanner_name=self.name,
                            severity=FindingSeverity.HIGH,
                            category="custom_violation",
                            message="Forbidden term detected.",
                        )
                    ]
                return []
    """

    name: str = ""
    phases: list[ScanPhase] = []

    @abstractmethod
    async def scan(self, content: str, context: ScanContext) -> list[Finding]:
        """Scan ``content`` and return any findings.

        Parameters
        ----------
        content:
            The text to scan.  For :attr:`ScanPhase.TOOL_CALL` the
            pipeline serialises the tool arguments to a JSON string before
            passing them here.
        context:
            Per-request metadata including the current phase, agent/session
            identifiers, and accumulated prior findings.

        Returns
        -------
        list[Finding]
            Zero or more findings.  Return an empty list when the content
            is clean.
        """

    def __repr__(self) -> str:
        return f"{type(self).__name__}(name={self.name!r}, phases={self.phases!r})"
