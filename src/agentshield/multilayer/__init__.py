"""Multi-layer defense chain with inter-layer feedback for agentshield.

Provides an ordered defense pipeline where each layer receives signals
from previous layers and amplifies sensitivity when partial threats are detected.
"""
from __future__ import annotations

from agentshield.multilayer.defense_chain import (
    DefenseChain,
    DefenseLayer,
    DefenseOutcome,
    LayerResult,
    DefenseDecision,
)
from agentshield.multilayer.feedback_loop import (
    FeedbackSignal,
    FeedbackLoop,
    SensitivityLevel,
)

__all__ = [
    "DefenseChain",
    "DefenseLayer",
    "DefenseOutcome",
    "LayerResult",
    "DefenseDecision",
    "FeedbackSignal",
    "FeedbackLoop",
    "SensitivityLevel",
]
