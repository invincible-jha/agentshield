"""Attack pattern registry for the red team engine.

This module exposes all attack categories and provides helpers for
querying and filtering patterns.

Public API
----------
``ALL_PATTERNS``
    Flat list of every :class:`~agentshield.redteam.attacks._base.AttackPattern`
    across all categories.

``CATEGORIES``
    Tuple of valid category name strings.

``get_patterns_by_category``
    Filter the global registry by category name.

Sources for all patterns are documented in the individual category modules.
No proprietary, internal, or confidential identifiers are used anywhere in
this package.
"""
from __future__ import annotations

from agentshield.redteam.attacks._base import AttackPattern, AttackResult
from agentshield.redteam.attacks.exfiltration import EXFILTRATION_PATTERNS
from agentshield.redteam.attacks.injection import INJECTION_PATTERNS
from agentshield.redteam.attacks.memory_poison import MEMORY_POISON_PATTERNS
from agentshield.redteam.attacks.tool_abuse import TOOL_ABUSE_PATTERNS

CATEGORIES: tuple[str, ...] = ("injection", "exfiltration", "tool_abuse", "memory_poison")

ALL_PATTERNS: list[AttackPattern] = (
    INJECTION_PATTERNS
    + EXFILTRATION_PATTERNS
    + TOOL_ABUSE_PATTERNS
    + MEMORY_POISON_PATTERNS
)

_CATEGORY_INDEX: dict[str, list[AttackPattern]] = {
    category: [p for p in ALL_PATTERNS if p.category == category]
    for category in CATEGORIES
}


def get_patterns_by_category(category: str) -> list[AttackPattern]:
    """Return all patterns that belong to *category*.

    Parameters
    ----------
    category:
        One of ``"injection"``, ``"exfiltration"``, ``"tool_abuse"``,
        or ``"memory_poison"``.

    Returns
    -------
    list[AttackPattern]
        A new list containing all patterns for the given category.

    Raises
    ------
    ValueError
        If *category* is not a recognised category name.
    """
    if category not in _CATEGORY_INDEX:
        raise ValueError(
            f"Unknown category {category!r}. "
            f"Valid categories: {list(CATEGORIES)}"
        )
    return list(_CATEGORY_INDEX[category])


__all__ = [
    "ALL_PATTERNS",
    "CATEGORIES",
    "AttackPattern",
    "AttackResult",
    "INJECTION_PATTERNS",
    "EXFILTRATION_PATTERNS",
    "TOOL_ABUSE_PATTERNS",
    "MEMORY_POISON_PATTERNS",
    "get_patterns_by_category",
]
