"""Tests for agentshield.multilayer.feedback_loop."""
from __future__ import annotations

import pytest

from agentshield.multilayer.feedback_loop import (
    FeedbackLoop,
    FeedbackSignal,
    SensitivityLevel,
    _compute_amplification,
    _compute_sensitivity_level,
)


class TestComputeSensitivityLevel:
    def test_normal_below_025(self) -> None:
        assert _compute_sensitivity_level(0.1) == SensitivityLevel.NORMAL

    def test_elevated_025_to_05(self) -> None:
        assert _compute_sensitivity_level(0.3) == SensitivityLevel.ELEVATED

    def test_high_05_to_075(self) -> None:
        assert _compute_sensitivity_level(0.6) == SensitivityLevel.HIGH

    def test_maximum_above_075(self) -> None:
        assert _compute_sensitivity_level(0.9) == SensitivityLevel.MAXIMUM


class TestComputeAmplification:
    def test_zero_detections_returns_1(self) -> None:
        assert _compute_amplification(0.0, 0) == 1.0

    def test_one_detection_returns_above_1(self) -> None:
        factor = _compute_amplification(0.5, 1)
        assert factor > 1.0

    def test_many_detections_capped(self) -> None:
        factor = _compute_amplification(1.0, 100, max_amplification=4.0)
        assert factor <= 4.0

    def test_higher_threat_higher_amplification(self) -> None:
        low = _compute_amplification(0.1, 1)
        high = _compute_amplification(0.9, 1)
        assert high >= low


class TestFeedbackLoop:
    def test_initial_signal_is_normal(self) -> None:
        loop = FeedbackLoop()
        signal = loop.current_signal()
        assert signal.threat_score == 0.0
        assert signal.partial_detections == 0
        assert signal.sensitivity_level == SensitivityLevel.NORMAL
        assert signal.amplification_factor == 1.0

    def test_record_partial_detection_increases_threat(self) -> None:
        loop = FeedbackLoop()
        loop.record_partial_detection("layer1", threat_score=0.6)
        signal = loop.current_signal()
        assert signal.threat_score == 0.6
        assert signal.partial_detections == 1

    def test_source_layer_set_to_highest(self) -> None:
        loop = FeedbackLoop()
        loop.record_partial_detection("layer1", threat_score=0.3)
        loop.record_partial_detection("layer2", threat_score=0.7)
        signal = loop.current_signal()
        assert signal.source_layer == "layer2"

    def test_amplification_increases_with_detections(self) -> None:
        loop = FeedbackLoop()
        initial_amp = loop.current_signal().amplification_factor
        loop.record_partial_detection("layer1", threat_score=0.5)
        after_amp = loop.current_signal().amplification_factor
        assert after_amp > initial_amp

    def test_context_passed_through(self) -> None:
        loop = FeedbackLoop()
        loop.record_partial_detection("l1", 0.5, context={"key": "value"})
        signal = loop.current_signal()
        assert signal.context.get("key") == "value"

    def test_record_clean_increments_counter(self) -> None:
        loop = FeedbackLoop()
        loop.record_partial_detection("l1", 0.5)
        loop.record_clean("l2")
        # Clean counter incremented
        assert loop._clean_layer_count == 1

    def test_signal_decays_after_clean_layers(self) -> None:
        loop = FeedbackLoop(decay_after_n_clean_layers=2)
        loop.record_partial_detection("l1", threat_score=0.8)
        initial_score = loop.current_signal().threat_score
        loop.record_clean("l2")
        loop.record_clean("l3")  # Decay threshold reached
        decayed_score = loop.current_signal().threat_score
        assert decayed_score < initial_score

    def test_reset_clears_state(self) -> None:
        loop = FeedbackLoop()
        loop.record_partial_detection("l1", threat_score=0.9)
        loop.reset()
        signal = loop.current_signal()
        assert signal.threat_score == 0.0
        assert signal.partial_detections == 0

    def test_sensitivity_level_elevated_on_moderate_threat(self) -> None:
        loop = FeedbackLoop()
        loop.record_partial_detection("l1", threat_score=0.35)
        signal = loop.current_signal()
        assert signal.sensitivity_level == SensitivityLevel.ELEVATED

    def test_sensitivity_level_maximum_on_high_threat(self) -> None:
        loop = FeedbackLoop()
        loop.record_partial_detection("l1", threat_score=0.9)
        signal = loop.current_signal()
        assert signal.sensitivity_level == SensitivityLevel.MAXIMUM

    def test_threat_score_clamped_to_1(self) -> None:
        loop = FeedbackLoop()
        loop.record_partial_detection("l1", threat_score=2.5)
        signal = loop.current_signal()
        assert signal.threat_score <= 1.0


class TestFeedbackSignal:
    def test_frozen(self) -> None:
        signal = FeedbackSignal(threat_score=0.5)
        with pytest.raises((AttributeError, TypeError)):
            signal.threat_score = 0.9  # type: ignore[misc]
