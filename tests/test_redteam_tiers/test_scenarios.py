"""Tests for agentshield.redteam_tiers.scenarios."""
from __future__ import annotations

import pytest

from agentshield.redteam_tiers.scenarios import (
    BUILT_IN_SCENARIOS,
    Scenario,
    ScenarioTier,
    get_scenarios_for_tier,
)


class TestScenarioTier:
    def test_all_tiers_exist(self) -> None:
        tiers = list(ScenarioTier)
        assert len(tiers) == 5

    def test_tier_ordering(self) -> None:
        assert ScenarioTier.T1_NAIVE < ScenarioTier.T5_ADAPTIVE


class TestBuiltInScenarios:
    def test_exactly_15_scenarios(self) -> None:
        assert len(BUILT_IN_SCENARIOS) == 15

    def test_three_scenarios_per_tier(self) -> None:
        for tier in ScenarioTier:
            tier_scenarios = [s for s in BUILT_IN_SCENARIOS if s.tier == tier]
            assert len(tier_scenarios) == 3, f"Expected 3 scenarios for {tier.name}"

    def test_all_scenario_ids_unique(self) -> None:
        ids = [s.scenario_id for s in BUILT_IN_SCENARIOS]
        assert len(ids) == len(set(ids))

    def test_all_scenarios_have_non_empty_payload(self) -> None:
        for scenario in BUILT_IN_SCENARIOS:
            assert scenario.payload.strip() != "", f"Empty payload for {scenario.scenario_id}"

    def test_all_scenarios_have_description(self) -> None:
        for scenario in BUILT_IN_SCENARIOS:
            assert len(scenario.description) > 10, f"Short description for {scenario.scenario_id}"

    def test_all_scenarios_have_pattern_class(self) -> None:
        for scenario in BUILT_IN_SCENARIOS:
            assert scenario.pattern_class != ""

    def test_pattern_classes_unique_within_tier(self) -> None:
        for tier in ScenarioTier:
            tier_scenarios = get_scenarios_for_tier(tier)
            classes = [s.pattern_class for s in tier_scenarios]
            assert len(classes) == len(set(classes)), \
                f"Duplicate pattern classes in {tier.name}"

    def test_all_expected_detection_true(self) -> None:
        # All built-in scenarios should be detected by a good defense
        for scenario in BUILT_IN_SCENARIOS:
            assert scenario.expected_detection is True

    def test_scenario_frozen(self) -> None:
        scenario = BUILT_IN_SCENARIOS[0]
        with pytest.raises((AttributeError, TypeError)):
            scenario.payload = "changed"  # type: ignore[misc]


class TestGetScenariosForTier:
    def test_returns_correct_tier(self) -> None:
        for tier in ScenarioTier:
            scenarios = get_scenarios_for_tier(tier)
            assert all(s.tier == tier for s in scenarios)

    def test_returns_three_per_tier(self) -> None:
        for tier in ScenarioTier:
            scenarios = get_scenarios_for_tier(tier)
            assert len(scenarios) == 3

    def test_defensive_framing_in_descriptions(self) -> None:
        # Descriptions should contain defensive/testing language
        defensive_words = {"tests", "detection", "pattern", "framing", "defensive"}
        for scenario in BUILT_IN_SCENARIOS:
            desc_lower = scenario.description.lower()
            has_defensive = any(word in desc_lower for word in defensive_words)
            assert has_defensive, \
                f"Scenario {scenario.scenario_id} lacks defensive framing in description"

    def test_t1_payloads_contain_naive_language(self) -> None:
        t1_scenarios = get_scenarios_for_tier(ScenarioTier.T1_NAIVE)
        # T1 scenarios should have clear, direct (not obfuscated) override attempts
        naive_words = ["ignore", "disable", "override", "without"]
        for scenario in t1_scenarios:
            has_naive = any(w in scenario.payload.lower() for w in naive_words)
            assert has_naive, f"T1 scenario {scenario.scenario_id} lacks naive language"
