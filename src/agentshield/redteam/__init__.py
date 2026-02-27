"""Red team testing engine for AI agent callables.

This package provides automated adversarial testing against AI agents and
agent pipelines using publicly documented attack patterns.

All attack patterns are sourced from public security research only:
- OWASP Agentic Security Inventory (ASI)
- OASIS Coalition for Secure AI (CoSAI) Agentic AI Threat Taxonomy
- Published CVEs and academic papers (cited by arXiv ID)
- Simon Willison's prompt injection research (public blog)
- WithSecure, Barracuda, Trail of Bits published reports
- Anthropic published safety research

Quick start
-----------
::

    from agentshield.redteam import RedTeamRunner

    # Test an echo agent (blocks nothing — should score F)
    runner = RedTeamRunner(target=lambda prompt: prompt)
    report = runner.run_all()
    print(report.grade)          # "F"
    print(report.to_json())

    # Run only injection and exfiltration categories
    results = runner.run_categories(["injection", "exfiltration"])

Public API
----------
The stable public surface of this package is everything listed in
``__all__``.  Internal modules (prefixed with ``_``) are private.
"""
from __future__ import annotations

from agentshield.redteam.attacks import (
    ALL_PATTERNS,
    CATEGORIES,
    EXFILTRATION_PATTERNS,
    INJECTION_PATTERNS,
    MEMORY_POISON_PATTERNS,
    TOOL_ABUSE_PATTERNS,
    AttackPattern,
    AttackResult,
    get_patterns_by_category,
)
from agentshield.redteam.report import RedTeamReport
from agentshield.redteam.runner import RedTeamRunner, create_runner

__all__ = [
    # Runner
    "RedTeamRunner",
    "create_runner",
    # Report
    "RedTeamReport",
    # Attack types
    "AttackPattern",
    "AttackResult",
    # Registries
    "ALL_PATTERNS",
    "CATEGORIES",
    "INJECTION_PATTERNS",
    "EXFILTRATION_PATTERNS",
    "TOOL_ABUSE_PATTERNS",
    "MEMORY_POISON_PATTERNS",
    "get_patterns_by_category",
]
