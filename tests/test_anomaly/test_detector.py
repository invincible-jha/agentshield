"""Tests for agentshield.anomaly.detector."""
from __future__ import annotations

import pytest

from agentshield.anomaly.baseline import AgentRun, BehaviorBaseline
from agentshield.anomaly.detector import (
    AnomalyDetector,
    AnomalyLevel,
    AnomalyResult,
    FeatureDeviation,
)


def _build_baseline(
    n_runs: int = 10,
    response_time_ms: float = 100.0,
    tool_calls: list[str] | None = None,
    output_length: int = 200,
    actions: list[str] | None = None,
) -> BehaviorBaseline:
    baseline = BehaviorBaseline()
    for i in range(n_runs):
        baseline.add_run(
            AgentRun(
                run_id=f"r{i}",
                actions=actions or ["search", "respond"],
                response_time_ms=response_time_ms + (i % 3) * 5,
                tool_calls=tool_calls or ["web_search"],
                output_length=output_length + (i % 4) * 10,
            )
        )
    return baseline


class TestAnomalyDetectorNormal:
    def test_normal_run_score_low(self) -> None:
        baseline = _build_baseline(n_runs=20)
        detector = AnomalyDetector(baseline)
        normal_run = AgentRun(
            run_id="test",
            actions=["search", "respond"],
            response_time_ms=103.0,
            tool_calls=["web_search"],
            output_length=210,
        )
        result = detector.detect(normal_run)
        assert result.anomaly_score < 0.5
        assert result.anomaly_level == AnomalyLevel.NORMAL

    def test_is_not_anomalous_for_normal(self) -> None:
        baseline = _build_baseline(n_runs=20)
        detector = AnomalyDetector(baseline)
        normal_run = AgentRun(
            run_id="test",
            actions=["search", "respond"],
            response_time_ms=100.0,
            tool_calls=["web_search"],
            output_length=200,
        )
        result = detector.detect(normal_run)
        assert result.is_anomalous is False


class TestAnomalyDetectorAbnormal:
    def test_extreme_response_time_detected(self) -> None:
        baseline = _build_baseline(n_runs=20, response_time_ms=100.0)
        detector = AnomalyDetector(baseline)
        # Response time 100x baseline
        suspicious_run = AgentRun(
            run_id="suspicious",
            actions=["search", "respond"],
            response_time_ms=10000.0,
            tool_calls=["web_search"],
            output_length=200,
        )
        result = detector.detect(suspicious_run)
        assert result.is_anomalous is True

    def test_extreme_tool_call_count_detected(self) -> None:
        baseline = _build_baseline(n_runs=20, tool_calls=["web_search"])
        detector = AnomalyDetector(baseline)
        many_tools = AgentRun(
            run_id="tools_heavy",
            actions=["search", "respond"],
            response_time_ms=100.0,
            tool_calls=["t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "t9", "t10"],
            output_length=200,
        )
        result = detector.detect(many_tools)
        assert result.anomaly_score > 0

    def test_unusual_action_detected(self) -> None:
        baseline = _build_baseline(n_runs=20, actions=["search", "respond"])
        detector = AnomalyDetector(baseline, unusual_action_threshold=0.01)
        run_with_new_action = AgentRun(
            run_id="new_action",
            actions=["admin_escalate", "system_exec"],
            response_time_ms=100.0,
            tool_calls=["web_search"],
            output_length=200,
        )
        result = detector.detect(run_with_new_action)
        assert len(result.unusual_actions) > 0

    def test_unusual_tool_detected(self) -> None:
        baseline = _build_baseline(n_runs=20, tool_calls=["web_search"])
        detector = AnomalyDetector(baseline, unusual_tool_threshold=0.01)
        run_with_new_tool = AgentRun(
            run_id="new_tool",
            actions=["search", "respond"],
            response_time_ms=100.0,
            tool_calls=["exec_shell", "network_scan"],
            output_length=200,
        )
        result = detector.detect(run_with_new_tool)
        assert len(result.unusual_tools) > 0


class TestAnomalyDetectorResult:
    def test_result_has_run_id(self) -> None:
        baseline = _build_baseline()
        detector = AnomalyDetector(baseline)
        run = AgentRun(run_id="test_run", response_time_ms=100.0, output_length=200)
        result = detector.detect(run)
        assert result.run_id == "test_run"

    def test_feature_deviations_present(self) -> None:
        baseline = _build_baseline()
        detector = AnomalyDetector(baseline)
        run = AgentRun(run_id="test", response_time_ms=100.0, output_length=200)
        result = detector.detect(run)
        assert len(result.feature_deviations) > 0

    def test_feature_deviation_fields(self) -> None:
        baseline = _build_baseline()
        detector = AnomalyDetector(baseline)
        run = AgentRun(run_id="test", response_time_ms=100.0, output_length=200)
        result = detector.detect(run)
        for dev in result.feature_deviations:
            assert isinstance(dev, FeatureDeviation)
            assert dev.feature != ""
            assert isinstance(dev.z_score, float)

    def test_anomaly_score_bounded(self) -> None:
        baseline = _build_baseline()
        detector = AnomalyDetector(baseline)
        for response_time in [50.0, 100.0, 200.0, 5000.0]:
            run = AgentRun(run_id="t", response_time_ms=response_time, output_length=200)
            result = detector.detect(run)
            assert 0.0 <= result.anomaly_score <= 1.0

    def test_baseline_not_ready_flagged(self) -> None:
        baseline = BehaviorBaseline()
        baseline.add_run(AgentRun(run_id="r1", response_time_ms=100.0))
        detector = AnomalyDetector(baseline)
        run = AgentRun(run_id="test", response_time_ms=100.0, output_length=200)
        result = detector.detect(run)
        assert result.baseline_ready is False

    def test_anomaly_level_critical_for_extreme(self) -> None:
        baseline = _build_baseline(n_runs=30, response_time_ms=100.0)
        detector = AnomalyDetector(baseline)
        extreme = AgentRun(run_id="extreme", response_time_ms=50000.0, output_length=200)
        result = detector.detect(extreme)
        assert result.anomaly_level == AnomalyLevel.CRITICAL
