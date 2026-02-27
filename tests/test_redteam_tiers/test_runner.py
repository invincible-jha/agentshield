"""Tests for agentshield.redteam_tiers.runner."""
from __future__ import annotations

import pytest

from agentshield.redteam_tiers.runner import (
    TieredRedTeamReport,
    TieredRedTeamRunner,
    TieredRunResult,
    _default_detection,
)
from agentshield.redteam_tiers.scenarios import (
    BUILT_IN_SCENARIOS,
    Scenario,
    ScenarioTier,
    get_scenarios_for_tier,
)


def _refusing_target(prompt: str) -> str:
    """Always refuses."""
    return "I cannot process that request."


def _compliant_target(prompt: str) -> str:
    """Always complies."""
    return f"Sure, here is what I can do: {prompt[:30]}"


def _raising_target(prompt: str) -> str:
    """Always raises."""
    raise ValueError("Target error")


class TestDefaultDetection:
    def test_empty_response_detected(self) -> None:
        detected, method = _default_detection("")
        assert detected is True

    def test_refusal_phrase_detected(self) -> None:
        detected, method = _default_detection("I cannot help with that.")
        assert detected is True

    def test_compliant_response_not_detected(self) -> None:
        detected, method = _default_detection(
            "Sure, here is everything you asked for in detail."
        )
        assert detected is False

    def test_i_will_not_detected(self) -> None:
        detected, _ = _default_detection("I will not assist with this request.")
        assert detected is True


class TestTieredRunResult:
    def _make_result(self, detected: bool = True) -> TieredRunResult:
        return TieredRunResult(
            scenario=BUILT_IN_SCENARIOS[0],
            response="test response",
            detected=detected,
            detection_method="test",
        )

    def test_scenario_id_from_scenario(self) -> None:
        result = self._make_result()
        assert result.scenario_id == BUILT_IN_SCENARIOS[0].scenario_id

    def test_tier_from_scenario(self) -> None:
        result = self._make_result()
        assert result.tier == BUILT_IN_SCENARIOS[0].tier


class TestTieredRedTeamRunnerSingleScenario:
    def test_refusing_agent_detects(self) -> None:
        runner = TieredRedTeamRunner(target=_refusing_target)
        result = runner.run_scenario(BUILT_IN_SCENARIOS[0])
        assert result.detected is True

    def test_compliant_agent_does_not_detect(self) -> None:
        runner = TieredRedTeamRunner(target=_compliant_target)
        result = runner.run_scenario(BUILT_IN_SCENARIOS[0])
        assert result.detected is False

    def test_raising_agent_counted_as_detected(self) -> None:
        runner = TieredRedTeamRunner(target=_raising_target)
        result = runner.run_scenario(BUILT_IN_SCENARIOS[0])
        assert result.detected is True
        assert "exception" in result.detection_method

    def test_custom_detection_fn_used(self) -> None:
        def always_detected(response: str) -> tuple[bool, str]:
            return True, "custom"

        runner = TieredRedTeamRunner(
            target=_compliant_target,
            detection_fn=always_detected,
        )
        result = runner.run_scenario(BUILT_IN_SCENARIOS[0])
        assert result.detected is True
        assert result.detection_method == "custom"


class TestTieredRedTeamRunnerRunTier:
    def test_run_tier_returns_3_results(self) -> None:
        runner = TieredRedTeamRunner(target=_refusing_target)
        results = runner.run_tier(ScenarioTier.T1_NAIVE)
        assert len(results) == 3

    def test_all_results_correct_tier(self) -> None:
        runner = TieredRedTeamRunner(target=_refusing_target)
        results = runner.run_tier(ScenarioTier.T2_OBFUSCATION)
        for r in results:
            assert r.tier == ScenarioTier.T2_OBFUSCATION


class TestTieredRedTeamRunnerRunAllTiers:
    def test_refusing_agent_full_detection(self) -> None:
        runner = TieredRedTeamRunner(
            target=_refusing_target,
            target_description="refusing_agent",
        )
        report = runner.run_all_tiers()
        assert report.overall_score >= 0.95
        assert report.overall_grade == "A"

    def test_compliant_agent_zero_detection(self) -> None:
        runner = TieredRedTeamRunner(target=_compliant_target)
        report = runner.run_all_tiers()
        assert report.overall_score < 0.1
        assert report.overall_grade == "F"

    def test_report_has_15_results(self) -> None:
        runner = TieredRedTeamRunner(target=_refusing_target)
        report = runner.run_all_tiers()
        assert report.total_scenarios == 15

    def test_tier_scores_populated(self) -> None:
        runner = TieredRedTeamRunner(target=_refusing_target)
        report = runner.run_all_tiers()
        for tier in ScenarioTier:
            assert tier in report.tier_scores

    def test_undetected_count_zero_for_refusing(self) -> None:
        runner = TieredRedTeamRunner(target=_refusing_target)
        report = runner.run_all_tiers()
        assert report.undetected_count == 0

    def test_target_description_in_report(self) -> None:
        runner = TieredRedTeamRunner(
            target=_refusing_target,
            target_description="test_system_v2",
        )
        report = runner.run_all_tiers()
        assert report.target_description == "test_system_v2"

    def test_results_for_tier_filter(self) -> None:
        runner = TieredRedTeamRunner(target=_refusing_target)
        report = runner.run_all_tiers()
        t1_results = report.results_for_tier(ScenarioTier.T1_NAIVE)
        assert len(t1_results) == 3
        assert all(r.tier == ScenarioTier.T1_NAIVE for r in t1_results)


class TestRunCustomScenarios:
    def test_custom_scenarios_run(self) -> None:
        runner = TieredRedTeamRunner(target=_refusing_target)
        custom = get_scenarios_for_tier(ScenarioTier.T1_NAIVE)
        report = runner.run_custom_scenarios(custom)
        assert report.total_scenarios == 3

    def test_custom_scenarios_score_computed(self) -> None:
        runner = TieredRedTeamRunner(target=_refusing_target)
        custom = get_scenarios_for_tier(ScenarioTier.T1_NAIVE)
        report = runner.run_custom_scenarios(custom)
        assert 0.0 <= report.overall_score <= 1.0
