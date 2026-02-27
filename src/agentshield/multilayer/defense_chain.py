"""DefenseChain: ordered multi-layer defense with inter-layer feedback.

Layers execute in sequence:
1. Input validation
2. Content analysis
3. Behavioral check
4. Output filtering

Each layer receives the FeedbackSignal from all previous layers.
The chain short-circuits on BLOCK decisions; WARN continues with
elevated sensitivity for subsequent layers.
"""
from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum

from agentshield.multilayer.feedback_loop import FeedbackLoop, FeedbackSignal

logger = logging.getLogger(__name__)


class DefenseDecision(str, Enum):
    """Decision produced by a defense layer."""

    PASS = "pass"
    WARN = "warn"
    BLOCK = "block"


@dataclass
class LayerResult:
    """Result produced by a single defense layer.

    Attributes
    ----------
    layer_name:
        Name of the layer that produced this result.
    decision:
        PASS, WARN, or BLOCK.
    threat_score:
        Confidence that the input is a threat (0.0-1.0).
    reason:
        Human-readable explanation of the decision.
    signals:
        Named signals produced by this layer (for feedback passing).
    metadata:
        Arbitrary metadata from this layer.
    duration_ms:
        Time taken by this layer in milliseconds.
    """

    layer_name: str
    decision: DefenseDecision
    threat_score: float = 0.0
    reason: str = ""
    signals: dict[str, object] = field(default_factory=dict)
    metadata: dict[str, object] = field(default_factory=dict)
    duration_ms: float = 0.0


@dataclass
class DefenseOutcome:
    """Overall outcome of a DefenseChain execution.

    Attributes
    ----------
    final_decision:
        The chain's final PASS/WARN/BLOCK decision.
    layer_results:
        Ordered results from each layer that executed.
    final_feedback:
        The FeedbackSignal state after all layers completed.
    total_duration_ms:
        Total chain execution time in milliseconds.
    blocked_at_layer:
        Name of the layer that issued the BLOCK, if any.
    """

    final_decision: DefenseDecision
    layer_results: list[LayerResult] = field(default_factory=list)
    final_feedback: FeedbackSignal | None = None
    total_duration_ms: float = 0.0
    blocked_at_layer: str | None = None

    @property
    def is_blocked(self) -> bool:
        """True if the chain issued a BLOCK decision."""
        return self.final_decision == DefenseDecision.BLOCK

    @property
    def has_warnings(self) -> bool:
        """True if any layer issued a WARN."""
        return any(r.decision == DefenseDecision.WARN for r in self.layer_results)

    @property
    def max_threat_score(self) -> float:
        """Maximum threat score across all layers."""
        if not self.layer_results:
            return 0.0
        return max(r.threat_score for r in self.layer_results)


class DefenseLayer(ABC):
    """Abstract base class for defense chain layers.

    Each layer must implement :meth:`analyze` which receives the
    current input payload and the accumulated FeedbackSignal from
    upstream layers.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique name for this defense layer."""
        ...

    @abstractmethod
    def analyze(
        self,
        payload: str,
        feedback: FeedbackSignal,
    ) -> LayerResult:
        """Analyze the payload with awareness of upstream feedback.

        Parameters
        ----------
        payload:
            The input text to analyze.
        feedback:
            The accumulated feedback signal from all prior layers.

        Returns
        -------
        LayerResult
        """
        ...


class DefenseChain:
    """Orchestrates an ordered sequence of defense layers with feedback.

    Built-in layer ordering convention (callers may use any names):
    1. input_validator — structural/format validation
    2. content_analyzer — content-level threat signals
    3. behavioral_checker — behavioral consistency checks
    4. output_filter — output sanitization

    Usage
    -----
    ::

        chain = DefenseChain()
        chain.add_layer(InputValidatorLayer())
        chain.add_layer(ContentAnalyzerLayer())
        outcome = chain.execute("User input text")
        if outcome.is_blocked:
            raise SecurityError("Blocked by defense chain")
    """

    #: Threat score assigned to a layer result when that layer raises an
    #: unhandled exception. A WARN decision is issued so execution can
    #: continue (the chain does not silently pass a broken layer). Override
    #: via the ``layer_error_threat_score`` constructor argument.
    _DEFAULT_LAYER_ERROR_THREAT_SCORE: float = 0.3

    def __init__(
        self,
        *,
        short_circuit_on_block: bool = True,
        warn_threat_threshold: float = 0.3,
        block_threat_threshold: float = 0.7,
        layer_error_threat_score: float = _DEFAULT_LAYER_ERROR_THREAT_SCORE,
    ) -> None:
        """Initialise the defense chain.

        Parameters
        ----------
        short_circuit_on_block:
            If True, stop executing layers after the first BLOCK.
        warn_threat_threshold:
            Threat score above which a PASS is upgraded to WARN.
        block_threat_threshold:
            Threat score above which a WARN is upgraded to BLOCK.
        layer_error_threat_score:
            Threat score assigned when a layer raises an unhandled exception.
            Defaults to :attr:`_DEFAULT_LAYER_ERROR_THREAT_SCORE` (0.3).
            A WARN decision is always issued for error results regardless of
            this value; only the score is configurable.
        """
        self._layers: list[DefenseLayer] = []
        self.short_circuit_on_block = short_circuit_on_block
        self.warn_threat_threshold = warn_threat_threshold
        self.block_threat_threshold = block_threat_threshold
        self.layer_error_threat_score = layer_error_threat_score

    def add_layer(self, layer: DefenseLayer) -> "DefenseChain":
        """Append a defense layer to the chain.

        Parameters
        ----------
        layer:
            The layer to add.

        Returns
        -------
        DefenseChain
            Self, for method chaining.
        """
        self._layers.append(layer)
        logger.debug("Added defense layer: %r", layer.name)
        return self

    def layer_count(self) -> int:
        """Return the number of layers in the chain."""
        return len(self._layers)

    def execute(
        self,
        payload: str,
        *,
        initial_context: dict[str, object] | None = None,
    ) -> DefenseOutcome:
        """Execute the defense chain on the given payload.

        Parameters
        ----------
        payload:
            The input text to defend against.
        initial_context:
            Optional initial context to pre-populate the feedback loop.

        Returns
        -------
        DefenseOutcome
        """
        feedback_loop = FeedbackLoop()
        if initial_context:
            feedback_loop.set_initial_context(initial_context)

        layer_results: list[LayerResult] = []
        chain_start = time.monotonic()
        final_decision = DefenseDecision.PASS
        blocked_at: str | None = None

        for layer in self._layers:
            feedback_signal = feedback_loop.current_signal()
            layer_start = time.monotonic()

            try:
                result = layer.analyze(payload, feedback_signal)
            except Exception as exc:
                logger.error(
                    "Defense layer %r raised an exception: %s", layer.name, exc
                )
                result = LayerResult(
                    layer_name=layer.name,
                    decision=DefenseDecision.WARN,
                    threat_score=self.layer_error_threat_score,
                    reason=f"Layer error: {type(exc).__name__}",
                )

            result.duration_ms = (time.monotonic() - layer_start) * 1000.0
            layer_results.append(result)

            # Update feedback loop
            if result.decision in (DefenseDecision.WARN, DefenseDecision.BLOCK):
                feedback_loop.record_partial_detection(
                    layer_name=layer.name,
                    threat_score=result.threat_score,
                    context=result.signals,
                )
            else:
                feedback_loop.record_clean(layer.name)

            # Escalate final decision
            if result.decision == DefenseDecision.BLOCK:
                final_decision = DefenseDecision.BLOCK
                blocked_at = layer.name
                if self.short_circuit_on_block:
                    logger.debug(
                        "Chain short-circuited at layer %r (BLOCK)", layer.name
                    )
                    break
            elif result.decision == DefenseDecision.WARN:
                if final_decision == DefenseDecision.PASS:
                    final_decision = DefenseDecision.WARN
            elif result.threat_score >= self.block_threat_threshold:
                final_decision = DefenseDecision.BLOCK
                blocked_at = layer.name
                if self.short_circuit_on_block:
                    break
            elif result.threat_score >= self.warn_threat_threshold:
                if final_decision == DefenseDecision.PASS:
                    final_decision = DefenseDecision.WARN

        total_duration = (time.monotonic() - chain_start) * 1000.0

        return DefenseOutcome(
            final_decision=final_decision,
            layer_results=layer_results,
            final_feedback=feedback_loop.current_signal(),
            total_duration_ms=total_duration,
            blocked_at_layer=blocked_at,
        )

    @classmethod
    def default(cls) -> "DefenseChain":
        """Create a chain with the four standard built-in layers.

        Returns
        -------
        DefenseChain
            Chain with InputValidatorLayer, ContentAnalyzerLayer,
            BehavioralCheckerLayer, OutputFilterLayer.
        """
        chain = cls()
        chain.add_layer(InputValidatorLayer())
        chain.add_layer(ContentAnalyzerLayer())
        chain.add_layer(BehavioralCheckerLayer())
        chain.add_layer(OutputFilterLayer())
        return chain


# ---------------------------------------------------------------------------
# Built-in commodity defense layers
# ---------------------------------------------------------------------------


class InputValidatorLayer(DefenseLayer):
    """Layer 1: Structural and format validation.

    Checks: input length, null bytes, encoding anomalies, known
    injection structural patterns (without real payloads).
    """

    _MAX_NORMAL_LENGTH = 50_000
    _STRUCTURAL_PATTERNS: list[str] = [
        "\x00",          # Null byte
        "\\u0000",       # Unicode null escape
        "\r\n\r\n",      # Double CRLF (HTTP header injection pattern)
    ]

    @property
    def name(self) -> str:
        return "input_validator"

    def analyze(self, payload: str, feedback: FeedbackSignal) -> LayerResult:
        threat_score = 0.0
        signals: dict[str, object] = {}

        # Adjust threshold based on upstream feedback
        length_threshold = self._MAX_NORMAL_LENGTH / feedback.amplification_factor

        if len(payload) > length_threshold:
            threat_score = max(threat_score, 0.3)
            signals["oversized_input"] = True

        for pattern in self._STRUCTURAL_PATTERNS:
            if pattern in payload:
                threat_score = max(threat_score, 0.6)
                signals["structural_pattern_detected"] = pattern
                break

        decision = DefenseDecision.PASS
        if threat_score >= 0.6:
            decision = DefenseDecision.WARN

        return LayerResult(
            layer_name=self.name,
            decision=decision,
            threat_score=threat_score,
            reason="Input structure validation" if threat_score == 0 else "Structural anomaly detected",
            signals=signals,
        )


class ContentAnalyzerLayer(DefenseLayer):
    """Layer 2: Content-level threat signal detection.

    Checks for prompt injection indicators, role assignment attempts,
    and instruction override patterns. Threshold lowered when upstream
    feedback indicates a partial threat.
    """

    _BASE_INJECTION_SIGNALS: list[str] = [
        "ignore all previous",
        "ignore your previous",
        "disregard your instructions",
        "bypass your",
        "forget your",
        "override your",
        "new instructions",
        "act as if",
        "pretend you are",
        "you are now",
    ]

    @property
    def name(self) -> str:
        return "content_analyzer"

    def analyze(self, payload: str, feedback: FeedbackSignal) -> LayerResult:
        lowered = payload.lower()
        threat_score = 0.0
        found_signals: list[str] = []

        # Lower detection threshold when upstream flagged a partial threat
        effective_threshold = max(0.1, 0.5 / feedback.amplification_factor)

        for signal in self._BASE_INJECTION_SIGNALS:
            if signal in lowered:
                found_signals.append(signal)
                threat_score = max(threat_score, 0.65)

        decision = DefenseDecision.PASS
        if threat_score >= effective_threshold:
            if threat_score >= 0.65:
                decision = DefenseDecision.BLOCK
            else:
                decision = DefenseDecision.WARN

        return LayerResult(
            layer_name=self.name,
            decision=decision,
            threat_score=threat_score,
            reason=(
                f"Content signals detected: {found_signals}"
                if found_signals
                else "Content analysis clean"
            ),
            signals={"matched_signals": found_signals},
        )


class BehavioralCheckerLayer(DefenseLayer):
    """Layer 3: Behavioral consistency check.

    Looks for unusual behavioral patterns: excessive questions,
    instruction sequences, or repeated override attempts.
    Sensitivity amplified by upstream feedback.
    """

    @property
    def name(self) -> str:
        return "behavioral_checker"

    def analyze(self, payload: str, feedback: FeedbackSignal) -> LayerResult:
        threat_score = 0.0
        signals: dict[str, object] = {}

        # Count question marks and instruction sequences
        question_count = payload.count("?")
        instruction_count = sum(
            1 for word in ["step 1", "step 2", "first,", "then,", "finally,"]
            if word in payload.lower()
        )

        # Base thresholds amplified by feedback
        question_threshold = max(3, int(10 / feedback.amplification_factor))
        instruction_threshold = max(1, int(4 / feedback.amplification_factor))

        if question_count > question_threshold:
            threat_score = max(threat_score, 0.35)
            signals["excessive_questions"] = question_count

        if instruction_count >= instruction_threshold:
            threat_score = max(threat_score, 0.35)
            signals["instruction_sequence"] = instruction_count

        decision = DefenseDecision.PASS
        if threat_score >= 0.3:
            decision = DefenseDecision.WARN

        return LayerResult(
            layer_name=self.name,
            decision=decision,
            threat_score=threat_score,
            reason=(
                f"Behavioral signals: {signals}"
                if signals
                else "Behavioral check clean"
            ),
            signals=signals,
        )


class OutputFilterLayer(DefenseLayer):
    """Layer 4: Output sanitization and exfiltration check.

    Checks for patterns that suggest the output might contain
    sensitive data or instruction leakage.
    """

    _OUTPUT_RISK_PATTERNS: list[str] = [
        "system prompt",
        "my instructions are",
        "i was told to",
        "my training data",
        "confidential",
        "secret",
    ]

    @property
    def name(self) -> str:
        return "output_filter"

    def analyze(self, payload: str, feedback: FeedbackSignal) -> LayerResult:
        lowered = payload.lower()
        threat_score = 0.0
        found: list[str] = []

        for pattern in self._OUTPUT_RISK_PATTERNS:
            if pattern in lowered:
                found.append(pattern)
                # Amplify based on upstream signals
                base_score = 0.3
                threat_score = max(
                    threat_score, base_score * feedback.amplification_factor
                )

        threat_score = min(threat_score, 1.0)

        decision = DefenseDecision.PASS
        if threat_score >= 0.7:
            decision = DefenseDecision.BLOCK
        elif threat_score >= 0.25:
            decision = DefenseDecision.WARN

        return LayerResult(
            layer_name=self.name,
            decision=decision,
            threat_score=threat_score,
            reason=(
                f"Output risk patterns: {found}" if found else "Output filter clean"
            ),
            signals={"risk_patterns": found},
        )
