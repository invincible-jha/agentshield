"""AnomalyDetector: compare current behavior against a BehaviorBaseline.

Uses z-score deviation for numeric features and relative frequency drop
for categorical features (action types, tool calls).

Anomaly score: 0.0 = perfectly normal; 1.0 = maximally anomalous.
Score is normalized from the maximum z-score across features.
"""
from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from enum import Enum

from agentshield.anomaly.baseline import AgentRun, BehaviorBaseline

logger = logging.getLogger(__name__)

# Threshold z-scores for anomaly level classification
_Z_WARN: float = 2.0
_Z_HIGH: float = 3.0
_Z_CRITICAL: float = 4.5

# Maximum z-score for normalization
_Z_MAX_NORM: float = 6.0


class AnomalyLevel(str, Enum):
    """Severity level of a detected anomaly."""

    NORMAL = "normal"       # z < 2.0
    WARN = "warn"           # 2.0 <= z < 3.0
    HIGH = "high"           # 3.0 <= z < 4.5
    CRITICAL = "critical"   # z >= 4.5


@dataclass(frozen=True)
class FeatureDeviation:
    """Deviation of a single feature from baseline.

    Attributes
    ----------
    feature:
        Feature name (e.g., "response_time_ms").
    observed_value:
        Value from the observed run.
    baseline_mean:
        Mean from the baseline.
    baseline_std:
        Standard deviation from the baseline.
    z_score:
        Standardized deviation.
    anomaly_level:
        Classification based on z-score.
    """

    feature: str
    observed_value: float
    baseline_mean: float
    baseline_std: float
    z_score: float
    anomaly_level: AnomalyLevel


@dataclass
class AnomalyResult:
    """Result of anomaly detection for a single agent run.

    Attributes
    ----------
    run_id:
        The run identifier.
    anomaly_score:
        Normalized anomaly score in [0, 1]. 0 = normal, 1 = maximally anomalous.
    anomaly_level:
        Overall anomaly level based on the highest-scoring feature.
    feature_deviations:
        Per-feature deviation details.
    unusual_actions:
        Action types that appear in this run but rarely in the baseline.
    unusual_tools:
        Tool names that appear in this run but rarely in the baseline.
    baseline_ready:
        Whether the baseline had enough observations for reliable detection.
    """

    run_id: str
    anomaly_score: float
    anomaly_level: AnomalyLevel
    feature_deviations: list[FeatureDeviation] = field(default_factory=list)
    unusual_actions: list[str] = field(default_factory=list)
    unusual_tools: list[str] = field(default_factory=list)
    baseline_ready: bool = True

    @property
    def is_anomalous(self) -> bool:
        """True if the anomaly level is WARN or higher."""
        return self.anomaly_level != AnomalyLevel.NORMAL


class AnomalyDetector:
    """Detects behavioral anomalies by comparing runs against a baseline.

    Usage
    -----
    ::

        baseline = BehaviorBaseline()
        for run in training_runs:
            baseline.add_run(run)

        detector = AnomalyDetector(baseline)
        result = detector.detect(new_run)
        if result.is_anomalous:
            print(f"Anomaly detected: {result.anomaly_level.value}")
    """

    def __init__(
        self,
        baseline: BehaviorBaseline,
        *,
        unusual_action_threshold: float = 0.02,
        unusual_tool_threshold: float = 0.02,
    ) -> None:
        """Initialise the detector.

        Parameters
        ----------
        baseline:
            The pre-built behavioral baseline.
        unusual_action_threshold:
            Frequency below which an action is considered unusual.
        unusual_tool_threshold:
            Frequency below which a tool call is considered unusual.
        """
        self.baseline = baseline
        self.unusual_action_threshold = unusual_action_threshold
        self.unusual_tool_threshold = unusual_tool_threshold

    def detect(self, run: AgentRun) -> AnomalyResult:
        """Detect anomalies in a single agent run.

        Parameters
        ----------
        run:
            The observed agent run to evaluate.

        Returns
        -------
        AnomalyResult
        """
        if not self.baseline.is_ready:
            logger.warning(
                "Baseline has only %d runs (min=%d). Detection may be unreliable.",
                self.baseline.run_count,
                BehaviorBaseline.MIN_RUNS,
            )

        feature_deviations = self._compute_feature_deviations(run)
        unusual_actions = self._find_unusual_actions(run)
        unusual_tools = self._find_unusual_tools(run)

        # Overall anomaly score: normalized max z-score
        if feature_deviations:
            max_z = max(abs(d.z_score) for d in feature_deviations)
        else:
            max_z = 0.0

        # Boost score for unusual actions/tools
        categorical_boost = min(
            0.3 * (len(unusual_actions) + len(unusual_tools)), 0.5
        )

        raw_score = min(max_z / _Z_MAX_NORM, 1.0) + categorical_boost
        anomaly_score = min(raw_score, 1.0)

        # Overall anomaly level
        if max_z >= _Z_CRITICAL or anomaly_score >= 0.75:
            overall_level = AnomalyLevel.CRITICAL
        elif max_z >= _Z_HIGH or anomaly_score >= 0.5:
            overall_level = AnomalyLevel.HIGH
        elif max_z >= _Z_WARN or anomaly_score >= 0.25:
            overall_level = AnomalyLevel.WARN
        else:
            overall_level = AnomalyLevel.NORMAL

        return AnomalyResult(
            run_id=run.run_id,
            anomaly_score=round(anomaly_score, 4),
            anomaly_level=overall_level,
            feature_deviations=feature_deviations,
            unusual_actions=unusual_actions,
            unusual_tools=unusual_tools,
            baseline_ready=self.baseline.is_ready,
        )

    def _compute_feature_deviations(
        self, run: AgentRun
    ) -> list[FeatureDeviation]:
        features = {
            "response_time_ms": run.response_time_ms,
            "tool_call_count": float(run.tool_call_count),
            "output_length": float(run.output_length),
            "action_count": float(run.action_count),
        }

        deviations: list[FeatureDeviation] = []
        for feature_name, observed in features.items():
            stats = self.baseline.stats_for_feature(feature_name)
            if stats is None or stats.count == 0:
                continue

            z = stats.z_score(observed)
            abs_z = abs(z)

            if abs_z >= _Z_CRITICAL:
                level = AnomalyLevel.CRITICAL
            elif abs_z >= _Z_HIGH:
                level = AnomalyLevel.HIGH
            elif abs_z >= _Z_WARN:
                level = AnomalyLevel.WARN
            else:
                level = AnomalyLevel.NORMAL

            deviations.append(
                FeatureDeviation(
                    feature=feature_name,
                    observed_value=observed,
                    baseline_mean=stats.mean,
                    baseline_std=stats.std,
                    z_score=z,
                    anomaly_level=level,
                )
            )

        return deviations

    def _find_unusual_actions(self, run: AgentRun) -> list[str]:
        unusual: list[str] = []
        for action in set(run.actions):
            freq = self.baseline.action_frequency(action)
            if freq < self.unusual_action_threshold:
                unusual.append(action)
        return unusual

    def _find_unusual_tools(self, run: AgentRun) -> list[str]:
        unusual: list[str] = []
        for tool in set(run.tool_calls):
            freq = self.baseline.tool_frequency(tool)
            if freq < self.unusual_tool_threshold:
                unusual.append(tool)
        return unusual
