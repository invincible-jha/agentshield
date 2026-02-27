"""Tiered adversarial red team runner for agentshield.

Extends the existing red team capability with a 5-tier scenario
classification system matching the robustness tiers in agent-eval.
All scenarios use defensive framing only — no real attack payloads.
"""
from __future__ import annotations

from agentshield.redteam_tiers.scenarios import (
    Scenario,
    ScenarioTier,
    BUILT_IN_SCENARIOS,
    get_scenarios_for_tier,
)
from agentshield.redteam_tiers.runner import (
    TieredRedTeamRunner,
    TieredRunResult,
    TieredRedTeamReport,
)

__all__ = [
    "Scenario",
    "ScenarioTier",
    "BUILT_IN_SCENARIOS",
    "get_scenarios_for_tier",
    "TieredRedTeamRunner",
    "TieredRunResult",
    "TieredRedTeamReport",
]
