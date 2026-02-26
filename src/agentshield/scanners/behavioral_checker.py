"""BehavioralChecker — detects anomalous agent behavioral patterns.

Tracks the history of recent agent actions within a session and flags:

* Repetitive request patterns — the same normalised request appearing
  more than *max_repetitions* times in the session history.
* Goal drift — the cosine similarity of the request's character-frequency
  vector against the session's established intent baseline falls below
  *intent_similarity_threshold*, suggesting the agent has been redirected.
* Resource usage anomalies — unusually long or structurally dense inputs
  that may indicate prompt stuffing or context flooding.

All history is maintained in memory (no external state).  History is
bounded to the last *history_window* entries.

Runs during both INPUT and OUTPUT phases so that behavioral drift is
detectable whether it occurs on the request or response side.
"""
from __future__ import annotations

import collections
import hashlib
import math
import re

from agentshield.core.context import ScanContext
from agentshield.core.scanner import Finding, FindingSeverity, ScanPhase, Scanner

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_MAX_REPETITIONS: int = 3
_DEFAULT_INTENT_SIMILARITY_THRESHOLD: float = 0.35
_DEFAULT_HISTORY_WINDOW: int = 20
_RESOURCE_ANOMALY_THRESHOLD_CHARS: int = 8_192


def _normalise_request(text: str) -> str:
    """Return a normalised form of *text* suitable for repetition comparison.

    Lowercases, strips leading/trailing whitespace, and collapses internal
    whitespace runs to single spaces.
    """
    return re.sub(r"\s+", " ", text.strip().lower())


def _char_frequency_vector(text: str) -> dict[str, float]:
    """Compute a character-frequency unit vector for *text*.

    Parameters
    ----------
    text:
        Input string.  Only printable ASCII characters are counted.

    Returns
    -------
    dict[str, float]
        Mapping from character to its normalised frequency (L2-normalised).
    """
    counts: dict[str, int] = collections.Counter(
        ch for ch in text.lower() if ch.isascii() and ch.isprintable()
    )
    if not counts:
        return {}
    magnitude = math.sqrt(sum(v * v for v in counts.values()))
    if magnitude == 0.0:
        return {}
    return {ch: count / magnitude for ch, count in counts.items()}


def _cosine_similarity(
    vec_a: dict[str, float], vec_b: dict[str, float]
) -> float:
    """Return the cosine similarity between two sparse frequency vectors.

    Parameters
    ----------
    vec_a, vec_b:
        Normalised frequency vectors as produced by
        :func:`_char_frequency_vector`.

    Returns
    -------
    float
        A value in ``[0.0, 1.0]``.  Returns ``1.0`` if both vectors are
        empty (no data to distinguish).
    """
    if not vec_a or not vec_b:
        return 1.0
    shared_keys = vec_a.keys() & vec_b.keys()
    return sum(vec_a[k] * vec_b[k] for k in shared_keys)


def _content_hash(text: str) -> str:
    """Return a short SHA-256 hex digest of the normalised content."""
    normalised = _normalise_request(text)
    return hashlib.sha256(normalised.encode("utf-8", errors="replace")).hexdigest()[:16]


class BehavioralChecker(Scanner):
    """Detect behavioral anomalies in agent request/response streams.

    Attributes
    ----------
    max_repetitions:
        Maximum times the same normalised request may appear in the
        session history before a MEDIUM finding is raised.
    intent_similarity_threshold:
        Cosine similarity floor between a new request and the session's
        baseline intent vector.  Requests that fall below this threshold
        raise a MEDIUM finding (goal drift).  Set to ``0.0`` to disable.
    history_window:
        Maximum number of historical entries retained per session.

    Example
    -------
    ::

        checker = BehavioralChecker(max_repetitions=3, intent_similarity_threshold=0.35)
        report = await pipeline.scan_input(user_message)
    """

    name: str = "behavioral_checker"
    phases: list[ScanPhase] = [ScanPhase.INPUT, ScanPhase.OUTPUT]

    def __init__(
        self,
        max_repetitions: int = _DEFAULT_MAX_REPETITIONS,
        intent_similarity_threshold: float = _DEFAULT_INTENT_SIMILARITY_THRESHOLD,
        history_window: int = _DEFAULT_HISTORY_WINDOW,
    ) -> None:
        if max_repetitions < 1:
            raise ValueError("max_repetitions must be >= 1.")
        if not (0.0 <= intent_similarity_threshold <= 1.0):
            raise ValueError(
                "intent_similarity_threshold must be in the range [0.0, 1.0]."
            )
        if history_window < 1:
            raise ValueError("history_window must be >= 1.")

        self.max_repetitions = max_repetitions
        self.intent_similarity_threshold = intent_similarity_threshold
        self.history_window = history_window

        # Per-session history: session_id -> deque of normalised content strings.
        self._session_history: dict[str, collections.deque[str]] = (
            collections.defaultdict(lambda: collections.deque(maxlen=history_window))
        )
        # Per-session cumulative intent vector (running average of char-freq vectors).
        self._session_intent_vector: dict[str, dict[str, float]] = {}
        # Per-session entry count (used to compute running average weight).
        self._session_entry_count: dict[str, int] = collections.defaultdict(int)

    async def scan(self, content: str, context: ScanContext) -> list[Finding]:
        """Check *content* for behavioral anomalies.

        Parameters
        ----------
        content:
            The text to evaluate.
        context:
            Current scan context.

        Returns
        -------
        list[Finding]
            Zero or more findings for behavioral anomalies detected.
        """
        findings: list[Finding] = []
        session_id = context.session_id
        normalised = _normalise_request(content)

        # 1. Resource anomaly check (before updating history).
        findings.extend(self._check_resource_anomaly(content, context))

        # 2. Repetition check.
        findings.extend(
            self._check_repetition(normalised, session_id)
        )

        # 3. Goal drift check (uses existing baseline, then updates).
        if self.intent_similarity_threshold > 0.0:
            findings.extend(
                self._check_goal_drift(content, normalised, session_id, context)
            )

        # 4. Update session history and intent vector.
        self._update_history(content, normalised, session_id)

        return findings

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def _check_resource_anomaly(
        self, content: str, context: ScanContext
    ) -> list[Finding]:
        length = len(content)
        if length <= _RESOURCE_ANOMALY_THRESHOLD_CHARS:
            return []
        return [
            Finding(
                scanner_name=self.name,
                severity=FindingSeverity.MEDIUM,
                category="resource_anomaly",
                message=(
                    f"Content length {length:,} characters exceeds the behavioral "
                    f"anomaly threshold of {_RESOURCE_ANOMALY_THRESHOLD_CHARS:,}. "
                    "Unusually large inputs may indicate context flooding."
                ),
                details={
                    "content_length": length,
                    "threshold": _RESOURCE_ANOMALY_THRESHOLD_CHARS,
                    "phase": context.phase.value,
                },
            )
        ]

    def _check_repetition(
        self, normalised: str, session_id: str
    ) -> list[Finding]:
        history = self._session_history[session_id]
        repetition_count = sum(1 for entry in history if entry == normalised)

        if repetition_count >= self.max_repetitions:
            content_hash = _content_hash(normalised)
            return [
                Finding(
                    scanner_name=self.name,
                    severity=FindingSeverity.MEDIUM,
                    category="repetitive_behavior",
                    message=(
                        f"The same request pattern has appeared {repetition_count + 1} "
                        f"time(s) in this session (limit: {self.max_repetitions}). "
                        "Repetitive patterns may indicate a stuck agent loop."
                    ),
                    details={
                        "repetition_count": repetition_count + 1,
                        "max_repetitions": self.max_repetitions,
                        "content_hash": content_hash,
                        "session_id": session_id,
                    },
                )
            ]
        return []

    def _check_goal_drift(
        self,
        content: str,
        normalised: str,
        session_id: str,
        context: ScanContext,
    ) -> list[Finding]:
        # Need at least one prior entry to compare against.
        if session_id not in self._session_intent_vector:
            return []
        baseline = self._session_intent_vector[session_id]
        if not baseline:
            return []

        current_vector = _char_frequency_vector(content)
        similarity = _cosine_similarity(baseline, current_vector)

        if similarity < self.intent_similarity_threshold:
            content_hash = _content_hash(normalised)
            return [
                Finding(
                    scanner_name=self.name,
                    severity=FindingSeverity.MEDIUM,
                    category="goal_drift",
                    message=(
                        f"Detected potential goal drift: intent similarity "
                        f"{similarity:.3f} is below the threshold of "
                        f"{self.intent_similarity_threshold:.3f}. "
                        "The agent's current request differs significantly from its "
                        "established session intent and may have been redirected."
                    ),
                    details={
                        "similarity_score": round(similarity, 4),
                        "threshold": self.intent_similarity_threshold,
                        "content_hash": content_hash,
                        "session_id": session_id,
                        "phase": context.phase.value,
                    },
                )
            ]
        return []

    def _update_history(
        self, content: str, normalised: str, session_id: str
    ) -> None:
        """Append *normalised* to session history and update the intent vector."""
        self._session_history[session_id].append(normalised)

        # Update rolling intent vector using an incremental mean.
        current_vector = _char_frequency_vector(content)
        count = self._session_entry_count[session_id]

        if count == 0 or session_id not in self._session_intent_vector:
            self._session_intent_vector[session_id] = dict(current_vector)
        else:
            baseline = self._session_intent_vector[session_id]
            # Incremental mean: new_mean = old_mean + (new_val - old_mean) / (n + 1)
            new_count = count + 1
            all_keys = baseline.keys() | current_vector.keys()
            updated: dict[str, float] = {}
            for key in all_keys:
                old_val = baseline.get(key, 0.0)
                new_val = current_vector.get(key, 0.0)
                updated[key] = old_val + (new_val - old_val) / new_count
            self._session_intent_vector[session_id] = updated

        self._session_entry_count[session_id] += 1

    def clear_session(self, session_id: str) -> None:
        """Remove all history and intent data for *session_id*.

        Parameters
        ----------
        session_id:
            The session identifier to clear.
        """
        self._session_history.pop(session_id, None)
        self._session_intent_vector.pop(session_id, None)
        self._session_entry_count.pop(session_id, None)

    def clear_all(self) -> None:
        """Remove all in-memory behavioral history.

        Useful between test runs or when the scanner is reused across
        logically independent agent deployments.
        """
        self._session_history.clear()
        self._session_intent_vector.clear()
        self._session_entry_count.clear()
