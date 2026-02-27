"""Tests for agentshield.anomaly.baseline."""
from __future__ import annotations

import math

import pytest

from agentshield.anomaly.baseline import (
    AgentRun,
    BaselineStats,
    BehaviorBaseline,
)


def _make_run(
    run_id: str = "r1",
    actions: list[str] | None = None,
    response_time_ms: float = 100.0,
    tool_calls: list[str] | None = None,
    output_length: int = 200,
) -> AgentRun:
    return AgentRun(
        run_id=run_id,
        actions=actions or ["search", "respond"],
        response_time_ms=response_time_ms,
        tool_calls=tool_calls or ["web_search"],
        output_length=output_length,
    )


class TestBaselineStats:
    def test_update_increments_count(self) -> None:
        stats = BaselineStats()
        stats.update(1.0)
        stats.update(2.0)
        assert stats.count == 2

    def test_mean_computed(self) -> None:
        stats = BaselineStats()
        for v in [1.0, 2.0, 3.0]:
            stats.update(v)
        assert abs(stats.mean - 2.0) < 0.001

    def test_variance_bessel_corrected(self) -> None:
        stats = BaselineStats()
        for v in [1.0, 2.0, 3.0]:
            stats.update(v)
        # Population variance = 2/3; sample variance = 1.0
        assert abs(stats.variance - 1.0) < 0.001

    def test_std_computed(self) -> None:
        stats = BaselineStats()
        for v in [1.0, 2.0, 3.0]:
            stats.update(v)
        assert abs(stats.std - 1.0) < 0.001

    def test_minimum_maximum_tracked(self) -> None:
        stats = BaselineStats()
        for v in [5.0, 2.0, 8.0, 1.0]:
            stats.update(v)
        assert stats.minimum == 1.0
        assert stats.maximum == 8.0

    def test_z_score_zero_for_mean(self) -> None:
        stats = BaselineStats()
        for v in [1.0, 2.0, 3.0]:
            stats.update(v)
        assert abs(stats.z_score(2.0)) < 0.001

    def test_z_score_positive_above_mean(self) -> None:
        stats = BaselineStats()
        for v in [1.0, 2.0, 3.0]:
            stats.update(v)
        assert stats.z_score(3.0) > 0

    def test_z_score_zero_when_std_is_zero(self) -> None:
        stats = BaselineStats()
        stats.update(5.0)  # Only one point, std=0
        assert stats.z_score(10.0) == 0.0

    def test_single_observation_variance_zero(self) -> None:
        stats = BaselineStats()
        stats.update(42.0)
        assert stats.variance == 0.0


class TestBehaviorBaseline:
    def test_run_count_increments(self) -> None:
        baseline = BehaviorBaseline()
        assert baseline.run_count == 0
        baseline.add_run(_make_run("r1"))
        assert baseline.run_count == 1

    def test_is_ready_below_min(self) -> None:
        baseline = BehaviorBaseline()
        for i in range(4):
            baseline.add_run(_make_run(f"r{i}"))
        assert baseline.is_ready is False

    def test_is_ready_at_min(self) -> None:
        baseline = BehaviorBaseline()
        for i in range(BehaviorBaseline.MIN_RUNS):
            baseline.add_run(_make_run(f"r{i}"))
        assert baseline.is_ready is True

    def test_response_time_stats_tracked(self) -> None:
        baseline = BehaviorBaseline()
        times = [100.0, 110.0, 120.0, 130.0, 140.0]
        for i, t in enumerate(times):
            baseline.add_run(_make_run(f"r{i}", response_time_ms=t))
        assert abs(baseline.response_time_stats.mean - 120.0) < 0.1

    def test_tool_call_count_stats_tracked(self) -> None:
        baseline = BehaviorBaseline()
        for i in range(5):
            baseline.add_run(_make_run(f"r{i}", tool_calls=["search"] * (i + 1)))
        assert baseline.tool_call_count_stats.count == 5

    def test_output_length_stats_tracked(self) -> None:
        baseline = BehaviorBaseline()
        for i in range(5):
            baseline.add_run(_make_run(f"r{i}", output_length=200 * (i + 1)))
        assert baseline.output_length_stats.mean > 0

    def test_action_frequency_tracked(self) -> None:
        baseline = BehaviorBaseline()
        for i in range(5):
            baseline.add_run(_make_run(f"r{i}", actions=["search", "respond"]))
        freq = baseline.action_frequency("search")
        assert 0 < freq <= 1.0

    def test_action_frequency_zero_for_unseen(self) -> None:
        baseline = BehaviorBaseline()
        for i in range(5):
            baseline.add_run(_make_run(f"r{i}", actions=["respond"]))
        assert baseline.action_frequency("admin_action") == 0.0

    def test_tool_frequency_tracked(self) -> None:
        baseline = BehaviorBaseline()
        for i in range(5):
            baseline.add_run(_make_run(f"r{i}", tool_calls=["web_search", "calculator"]))
        freq = baseline.tool_frequency("web_search")
        assert 0 < freq <= 1.0

    def test_most_common_actions(self) -> None:
        baseline = BehaviorBaseline()
        for i in range(5):
            baseline.add_run(_make_run(f"r{i}", actions=["search", "search", "respond"]))
        common = baseline.most_common_actions(2)
        assert len(common) <= 2
        assert common[0][0] == "search"

    def test_most_common_tools(self) -> None:
        baseline = BehaviorBaseline()
        for i in range(5):
            baseline.add_run(_make_run(f"r{i}", tool_calls=["search", "search", "calc"]))
        common = baseline.most_common_tools(1)
        assert common[0][0] == "search"

    def test_stats_for_feature_valid_name(self) -> None:
        baseline = BehaviorBaseline()
        baseline.add_run(_make_run())
        stats = baseline.stats_for_feature("response_time_ms")
        assert stats is not None

    def test_stats_for_feature_invalid_name(self) -> None:
        baseline = BehaviorBaseline()
        baseline.add_run(_make_run())
        assert baseline.stats_for_feature("nonexistent_feature") is None

    def test_agent_run_properties(self) -> None:
        run = _make_run(tool_calls=["a", "b", "c"], actions=["x", "y"])
        assert run.tool_call_count == 3
        assert run.action_count == 2
