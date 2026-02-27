"""Shared dataclasses for red team attack patterns and results.

Kept in a private module to avoid circular imports between attack-category
modules and the runner.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class AttackPattern:
    """A single red team attack pattern.

    All fields are immutable (``frozen=True``) so patterns can be safely
    shared across parallel test runs.

    Attributes
    ----------
    name:
        Unique slug identifying this pattern within its category,
        e.g. ``"role_override_direct"``.
    category:
        Broad classification: ``"injection"``, ``"exfiltration"``,
        ``"tool_abuse"``, or ``"memory_poison"``.
    payload:
        The string that is sent to the target callable as input.
    description:
        Human-readable explanation of what this pattern tests.
    source:
        Mandatory public citation — OWASP reference, arXiv ID, blog URL, etc.
        No proprietary or internal identifiers may appear here.
    severity:
        Expected impact when the attack succeeds.
        One of: ``"critical"``, ``"high"``, ``"medium"``, ``"low"``.
    """

    name: str
    category: str
    payload: str
    description: str
    source: str
    severity: str

    def __post_init__(self) -> None:
        valid_categories = {"injection", "exfiltration", "tool_abuse", "memory_poison"}
        valid_severities = {"critical", "high", "medium", "low"}
        if self.category not in valid_categories:
            raise ValueError(
                f"AttackPattern.category must be one of {valid_categories!r}, "
                f"got {self.category!r}"
            )
        if self.severity not in valid_severities:
            raise ValueError(
                f"AttackPattern.severity must be one of {valid_severities!r}, "
                f"got {self.severity!r}"
            )


@dataclass
class AttackResult:
    """The outcome of executing one :class:`AttackPattern` against a target.

    Attributes
    ----------
    pattern:
        The attack pattern that was executed.
    response:
        The raw string returned by the target callable.
    blocked:
        ``True`` when the target demonstrably rejected or neutralised the
        attack; ``False`` when the attack appears to have succeeded or when
        the outcome is ambiguous.
    detection_method:
        A short label describing how the block was detected,
        e.g. ``"blocklist_keyword"``, ``"exception_raised"``,
        ``"empty_response"``, or ``"unblocked"`` when not detected.
    """

    pattern: AttackPattern
    response: str
    blocked: bool
    detection_method: str = field(default="undetected")
