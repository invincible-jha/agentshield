"""Inter-layer signal passing and sensitivity amplification.

When a defense layer detects a partial threat, the FeedbackLoop
carries that signal forward to subsequent layers, amplifying their
sensitivity thresholds so weaker signals get caught.

Design
------
- Each layer receives the accumulated FeedbackSignal from all prior layers.
- Sensitivity is amplified by a configurable multiplier per partial detection.
- Signals decay after configurable number of layers (to prevent over-triggering).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class SensitivityLevel(str, Enum):
    """Current sensitivity level of a defense layer."""

    NORMAL = "normal"       # No upstream signal
    ELEVATED = "elevated"   # Partial threat upstream
    HIGH = "high"           # Strong partial threat upstream
    MAXIMUM = "maximum"     # Critical signal upstream


@dataclass(frozen=True)
class FeedbackSignal:
    """A signal passed from one defense layer to the next.

    Attributes
    ----------
    threat_score:
        Aggregated threat confidence from upstream layers (0.0-1.0).
    partial_detections:
        Number of upstream layers that flagged partial threats.
    sensitivity_level:
        Current sensitivity amplification level for this signal.
    source_layer:
        Name of the layer that emitted the highest-scoring signal.
    amplification_factor:
        Factor by which detection thresholds should be tightened.
    context:
        Arbitrary context passed between layers.
    """

    threat_score: float = 0.0
    partial_detections: int = 0
    sensitivity_level: SensitivityLevel = SensitivityLevel.NORMAL
    source_layer: str = ""
    amplification_factor: float = 1.0
    context: dict[str, object] = field(default_factory=dict)


def _compute_sensitivity_level(threat_score: float) -> SensitivityLevel:
    if threat_score >= 0.75:
        return SensitivityLevel.MAXIMUM
    if threat_score >= 0.5:
        return SensitivityLevel.HIGH
    if threat_score >= 0.25:
        return SensitivityLevel.ELEVATED
    return SensitivityLevel.NORMAL


def _compute_amplification(
    threat_score: float,
    partial_detections: int,
    base_amplification: float = 1.5,
    max_amplification: float = 4.0,
) -> float:
    """Compute the sensitivity amplification factor.

    Parameters
    ----------
    threat_score:
        Current aggregated threat score.
    partial_detections:
        Number of layers that flagged partial threats.
    base_amplification:
        Base multiplier per partial detection.
    max_amplification:
        Cap on the amplification factor.

    Returns
    -------
    float
        Amplification factor >= 1.0.
    """
    if partial_detections == 0:
        return 1.0

    # Exponential-like amplification capped at max
    factor = 1.0 + (base_amplification - 1.0) * partial_detections * (1 + threat_score)
    return min(factor, max_amplification)


class FeedbackLoop:
    """Manages inter-layer signal accumulation and sensitivity amplification.

    Usage
    -----
    ::

        loop = FeedbackLoop()
        signal = loop.current_signal()

        # After layer 1 detects partial threat:
        loop.record_partial_detection("input_validator", threat_score=0.4)
        signal = loop.current_signal()
        print(signal.amplification_factor)  # > 1.0

    The FeedbackLoop is stateful — one instance per request/chain execution.
    """

    def __init__(
        self,
        base_amplification: float = 1.5,
        max_amplification: float = 4.0,
        decay_after_n_clean_layers: int = 3,
    ) -> None:
        """Initialise the feedback loop.

        Parameters
        ----------
        base_amplification:
            Base multiplier applied per partial detection.
        max_amplification:
            Maximum amplification factor.
        decay_after_n_clean_layers:
            Number of consecutive clean layers before the signal decays.
        """
        self._base_amplification = base_amplification
        self._max_amplification = max_amplification
        self._decay_threshold = decay_after_n_clean_layers
        self._max_threat_score = 0.0
        self._partial_detections = 0
        self._clean_layer_count = 0
        self._source_layer = ""
        self._context: dict[str, object] = {}

    def record_partial_detection(
        self,
        layer_name: str,
        threat_score: float,
        context: dict[str, object] | None = None,
    ) -> None:
        """Record that a layer detected a partial threat.

        Parameters
        ----------
        layer_name:
            The defense layer name.
        threat_score:
            The threat confidence from this layer (0.0-1.0).
        context:
            Optional context data to pass forward.
        """
        threat_score = max(0.0, min(1.0, threat_score))
        self._partial_detections += 1
        self._clean_layer_count = 0  # Reset decay counter

        if threat_score > self._max_threat_score:
            self._max_threat_score = threat_score
            self._source_layer = layer_name

        if context:
            self._context.update(context)

        logger.debug(
            "Partial detection from layer=%r threat_score=%.2f total_detections=%d",
            layer_name,
            threat_score,
            self._partial_detections,
        )

    def record_clean(self, layer_name: str) -> None:
        """Record that a layer found no threat.

        Increments the clean counter; once the decay threshold is reached,
        the threat signal is reduced.

        Parameters
        ----------
        layer_name:
            The defense layer name.
        """
        self._clean_layer_count += 1
        if self._clean_layer_count >= self._decay_threshold:
            self._decay_signal()
            logger.debug(
                "Signal decayed after %d clean layers (last=%r)",
                self._clean_layer_count,
                layer_name,
            )

    def current_signal(self) -> FeedbackSignal:
        """Return the current feedback signal state.

        Returns
        -------
        FeedbackSignal
        """
        amplification = _compute_amplification(
            threat_score=self._max_threat_score,
            partial_detections=self._partial_detections,
            base_amplification=self._base_amplification,
            max_amplification=self._max_amplification,
        )
        sensitivity = _compute_sensitivity_level(self._max_threat_score)

        return FeedbackSignal(
            threat_score=self._max_threat_score,
            partial_detections=self._partial_detections,
            sensitivity_level=sensitivity,
            source_layer=self._source_layer,
            amplification_factor=amplification,
            context=dict(self._context),
        )

    def set_initial_context(self, context: dict[str, object]) -> None:
        """Pre-populate the feedback loop context before any layer runs.

        Parameters
        ----------
        context:
            Key/value pairs to merge into the initial context state.
        """
        self._context.update(context)

    def reset(self) -> None:
        """Reset the feedback loop state (call between requests)."""
        self._max_threat_score = 0.0
        self._partial_detections = 0
        self._clean_layer_count = 0
        self._source_layer = ""
        self._context = {}

    def _decay_signal(self) -> None:
        """Decay the accumulated threat signal by half."""
        self._max_threat_score *= 0.5
        self._partial_detections = max(0, self._partial_detections - 1)
        self._clean_layer_count = 0
