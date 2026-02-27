"""BehaviorBaseline: build statistical baselines from agent run observations.

Tracks:
- Action type frequency distribution
- Response time distribution (mean, std)
- Tool usage patterns (tool call count per run)
- Output length distribution

Uses Welford's online algorithm for numerically stable incremental
statistics — a standard textbook method (D. Knuth, TAOCP vol. 2).
"""
from __future__ import annotations

import math
import logging
from collections import Counter
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class AgentRun:
    """A single observed agent run for baseline construction.

    Attributes
    ----------
    run_id:
        Unique identifier for this run.
    actions:
        List of action type labels performed (e.g., ["search", "read", "respond"]).
    response_time_ms:
        Total response time in milliseconds.
    tool_calls:
        List of tool names called during this run.
    output_length:
        Character length of the agent's final output.
    metadata:
        Optional additional observation data.
    """

    run_id: str
    actions: list[str] = field(default_factory=list)
    response_time_ms: float = 0.0
    tool_calls: list[str] = field(default_factory=list)
    output_length: int = 0
    metadata: dict[str, object] = field(default_factory=dict)

    @property
    def tool_call_count(self) -> int:
        """Number of tool calls in this run."""
        return len(self.tool_calls)

    @property
    def action_count(self) -> int:
        """Number of actions in this run."""
        return len(self.actions)


@dataclass
class BaselineStats:
    """Statistical summary for a single numeric feature in the baseline.

    Uses Welford's online algorithm for incremental computation.

    Attributes
    ----------
    count:
        Number of observations.
    mean:
        Running mean.
    m2:
        Running sum of squared differences (for variance computation).
    minimum:
        Minimum observed value.
    maximum:
        Maximum observed value.
    """

    count: int = 0
    mean: float = 0.0
    m2: float = 0.0
    minimum: float = float("inf")
    maximum: float = float("-inf")

    def update(self, value: float) -> None:
        """Update stats with a new observation (Welford's algorithm).

        Parameters
        ----------
        value:
            The new observation to incorporate.
        """
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        delta2 = value - self.mean
        self.m2 += delta * delta2

        if value < self.minimum:
            self.minimum = value
        if value > self.maximum:
            self.maximum = value

    @property
    def variance(self) -> float:
        """Sample variance (Bessel-corrected, 0 if < 2 observations)."""
        if self.count < 2:
            return 0.0
        return self.m2 / (self.count - 1)

    @property
    def std(self) -> float:
        """Sample standard deviation."""
        return math.sqrt(self.variance)

    def z_score(self, value: float) -> float:
        """Compute the z-score of *value* relative to this baseline.

        Parameters
        ----------
        value:
            The value to score.

        Returns
        -------
        float
            Z-score. 0.0 if std is 0.
        """
        if self.std == 0:
            return 0.0
        return (value - self.mean) / self.std


class BehaviorBaseline:
    """Builds a behavioral baseline from multiple agent run observations.

    The baseline captures statistical profiles for key behavioral signals:
    - response_time_ms: distribution of response times
    - tool_call_count: distribution of tool call counts per run
    - output_length: distribution of output lengths
    - action_count: distribution of action counts per run

    Action frequency and tool usage are tracked as frequency counters
    so callers can detect unusual action type distributions.

    Usage
    -----
    ::

        baseline = BehaviorBaseline()
        for run in training_runs:
            baseline.add_run(run)
        print(baseline.is_ready)   # True after MIN_RUNS observations
    """

    MIN_RUNS: int = 5

    def __init__(self) -> None:
        self._runs: list[AgentRun] = []
        self._response_time_stats = BaselineStats()
        self._tool_call_count_stats = BaselineStats()
        self._output_length_stats = BaselineStats()
        self._action_count_stats = BaselineStats()
        self._action_freq: Counter[str] = Counter()
        self._tool_freq: Counter[str] = Counter()

    @property
    def run_count(self) -> int:
        """Number of observations incorporated into this baseline."""
        return len(self._runs)

    @property
    def is_ready(self) -> bool:
        """True when the baseline has enough observations to be useful."""
        return self.run_count >= self.MIN_RUNS

    @property
    def response_time_stats(self) -> BaselineStats:
        """Stats for response time distribution."""
        return self._response_time_stats

    @property
    def tool_call_count_stats(self) -> BaselineStats:
        """Stats for tool call count distribution."""
        return self._tool_call_count_stats

    @property
    def output_length_stats(self) -> BaselineStats:
        """Stats for output length distribution."""
        return self._output_length_stats

    @property
    def action_count_stats(self) -> BaselineStats:
        """Stats for action count distribution."""
        return self._action_count_stats

    def add_run(self, run: AgentRun) -> None:
        """Incorporate a new agent run observation into the baseline.

        Parameters
        ----------
        run:
            The observed agent run to add.
        """
        self._runs.append(run)
        self._response_time_stats.update(run.response_time_ms)
        self._tool_call_count_stats.update(float(run.tool_call_count))
        self._output_length_stats.update(float(run.output_length))
        self._action_count_stats.update(float(run.action_count))

        for action in run.actions:
            self._action_freq[action] += 1
        for tool in run.tool_calls:
            self._tool_freq[tool] += 1

        logger.debug(
            "Added run %r to baseline (total=%d)", run.run_id, self.run_count
        )

    def action_frequency(self, action: str) -> float:
        """Return the relative frequency (0-1) of *action* in the baseline.

        Parameters
        ----------
        action:
            The action type label to query.

        Returns
        -------
        float
            Fraction of runs that included this action type (at least once).
        """
        if self.run_count == 0:
            return 0.0
        total_action_events = sum(self._action_freq.values())
        if total_action_events == 0:
            return 0.0
        return self._action_freq.get(action, 0) / total_action_events

    def tool_frequency(self, tool_name: str) -> float:
        """Return the relative frequency (0-1) of *tool_name* in the baseline.

        Parameters
        ----------
        tool_name:
            The tool name to query.

        Returns
        -------
        float
        """
        total = sum(self._tool_freq.values())
        if total == 0:
            return 0.0
        return self._tool_freq.get(tool_name, 0) / total

    def most_common_actions(self, n: int = 10) -> list[tuple[str, int]]:
        """Return the N most common action types.

        Parameters
        ----------
        n:
            Number of top actions to return.

        Returns
        -------
        list[tuple[str, int]]
        """
        return self._action_freq.most_common(n)

    def most_common_tools(self, n: int = 10) -> list[tuple[str, int]]:
        """Return the N most common tool calls.

        Parameters
        ----------
        n:
            Number of top tools to return.

        Returns
        -------
        list[tuple[str, int]]
        """
        return self._tool_freq.most_common(n)

    def stats_for_feature(self, feature: str) -> BaselineStats | None:
        """Return the BaselineStats object for a named feature.

        Parameters
        ----------
        feature:
            One of: "response_time_ms", "tool_call_count",
            "output_length", "action_count".

        Returns
        -------
        BaselineStats | None
        """
        mapping = {
            "response_time_ms": self._response_time_stats,
            "tool_call_count": self._tool_call_count_stats,
            "output_length": self._output_length_stats,
            "action_count": self._action_count_stats,
        }
        return mapping.get(feature)
