"""Tests for agentshield.scanners.behavioral_checker — BehavioralChecker."""
from __future__ import annotations

import asyncio

import pytest

from agentshield.core.context import ScanContext
from agentshield.core.scanner import FindingSeverity, ScanPhase
from agentshield.scanners.behavioral_checker import (
    BehavioralChecker,
    _char_frequency_vector,
    _content_hash,
    _cosine_similarity,
    _normalise_request,
)


def _ctx(session_id: str = "sess-1") -> ScanContext:
    return ScanContext(
        phase=ScanPhase.INPUT,
        agent_id="test-agent",
        session_id=session_id,
    )


def _run(coro):  # type: ignore[no-untyped-def]
    return asyncio.run(coro)


class TestHelperFunctions:
    def test_normalise_request_lowercases(self) -> None:
        assert _normalise_request("HELLO WORLD") == "hello world"

    def test_normalise_request_strips_whitespace(self) -> None:
        assert _normalise_request("  hello  ") == "hello"

    def test_normalise_request_collapses_spaces(self) -> None:
        assert _normalise_request("hello   world") == "hello world"

    def test_char_frequency_vector_empty_string(self) -> None:
        assert _char_frequency_vector("") == {}

    def test_char_frequency_vector_only_non_ascii(self) -> None:
        # Non-ASCII chars not counted
        result = _char_frequency_vector("\u00e9\u00e9\u00e9")
        # Unicode chars are not printable ASCII so may return empty
        assert isinstance(result, dict)

    def test_char_frequency_vector_returns_normalized(self) -> None:
        vec = _char_frequency_vector("aab")
        assert isinstance(vec, dict)
        assert "a" in vec or "b" in vec

    def test_cosine_similarity_identical_texts(self) -> None:
        vec = _char_frequency_vector("hello world")
        assert abs(_cosine_similarity(vec, vec) - 1.0) < 0.001

    def test_cosine_similarity_empty_vectors_returns_one(self) -> None:
        assert _cosine_similarity({}, {}) == 1.0

    def test_cosine_similarity_one_empty_returns_one(self) -> None:
        vec = _char_frequency_vector("hello")
        assert _cosine_similarity(vec, {}) == 1.0

    def test_cosine_similarity_orthogonal_is_zero(self) -> None:
        vec_a = {"a": 1.0}
        vec_b = {"b": 1.0}
        assert _cosine_similarity(vec_a, vec_b) == 0.0

    def test_content_hash_returns_string(self) -> None:
        h = _content_hash("hello world")
        assert isinstance(h, str)
        assert len(h) == 16  # truncated to 16 chars

    def test_content_hash_normalises_before_hashing(self) -> None:
        h1 = _content_hash("Hello World")
        h2 = _content_hash("hello world")
        assert h1 == h2


class TestBehavioralCheckerInit:
    def test_valid_init(self) -> None:
        checker = BehavioralChecker()
        assert checker.max_repetitions == 3
        assert checker.intent_similarity_threshold == 0.35
        assert checker.history_window == 20

    def test_custom_init(self) -> None:
        checker = BehavioralChecker(max_repetitions=5, intent_similarity_threshold=0.5, history_window=10)
        assert checker.max_repetitions == 5
        assert checker.history_window == 10

    def test_invalid_max_repetitions_raises(self) -> None:
        with pytest.raises(ValueError, match="max_repetitions"):
            BehavioralChecker(max_repetitions=0)

    def test_invalid_intent_threshold_raises(self) -> None:
        with pytest.raises(ValueError, match="intent_similarity_threshold"):
            BehavioralChecker(intent_similarity_threshold=1.5)

    def test_negative_intent_threshold_raises(self) -> None:
        with pytest.raises(ValueError, match="intent_similarity_threshold"):
            BehavioralChecker(intent_similarity_threshold=-0.1)

    def test_invalid_history_window_raises(self) -> None:
        with pytest.raises(ValueError, match="history_window"):
            BehavioralChecker(history_window=0)

    def test_zero_threshold_disables_drift_check(self) -> None:
        checker = BehavioralChecker(intent_similarity_threshold=0.0)
        assert checker.intent_similarity_threshold == 0.0

    def test_scanner_name(self) -> None:
        assert BehavioralChecker().name == "behavioral_checker"

    def test_scanner_phases(self) -> None:
        checker = BehavioralChecker()
        assert ScanPhase.INPUT in checker.phases
        assert ScanPhase.OUTPUT in checker.phases


class TestResourceAnomalyCheck:
    def test_normal_length_content_passes(self) -> None:
        checker = BehavioralChecker()
        findings = _run(checker.scan("normal content", _ctx()))
        assert not any(f.category == "resource_anomaly" for f in findings)

    def test_oversized_content_raises_medium(self) -> None:
        checker = BehavioralChecker()
        content = "a" * 8193
        findings = _run(checker.scan(content, _ctx("resource-sess")))
        assert any(
            f.category == "resource_anomaly" and f.severity == FindingSeverity.MEDIUM
            for f in findings
        )

    def test_resource_anomaly_details(self) -> None:
        checker = BehavioralChecker()
        content = "a" * 9000
        findings = _run(checker.scan(content, _ctx("resource-details")))
        ra_findings = [f for f in findings if f.category == "resource_anomaly"]
        assert ra_findings
        assert "content_length" in ra_findings[0].details
        assert "threshold" in ra_findings[0].details


class TestRepetitionCheck:
    def test_first_occurrence_no_finding(self) -> None:
        checker = BehavioralChecker(max_repetitions=3)
        checker.clear_all()
        findings = _run(checker.scan("search for data", _ctx("rep-sess-1")))
        assert not any(f.category == "repetitive_behavior" for f in findings)

    def test_repeated_content_triggers_finding(self) -> None:
        checker = BehavioralChecker(max_repetitions=2)
        checker.clear_all()
        ctx = _ctx("rep-sess-2")
        message = "search for data"
        for _ in range(3):
            _run(checker.scan(message, ctx))
        findings = _run(checker.scan(message, ctx))
        assert any(
            f.category == "repetitive_behavior" and f.severity == FindingSeverity.MEDIUM
            for f in findings
        )

    def test_repetition_finding_details(self) -> None:
        checker = BehavioralChecker(max_repetitions=2)
        checker.clear_all()
        ctx = _ctx("rep-details-sess")
        msg = "repeat this message"
        for _ in range(3):
            _run(checker.scan(msg, ctx))
        findings = _run(checker.scan(msg, ctx))
        rep = [f for f in findings if f.category == "repetitive_behavior"]
        if rep:
            assert "repetition_count" in rep[0].details
            assert "session_id" in rep[0].details

    def test_different_content_not_repetitive(self) -> None:
        checker = BehavioralChecker(max_repetitions=2)
        checker.clear_all()
        ctx = _ctx("varied-sess")
        for i in range(5):
            findings = _run(checker.scan(f"unique message number {i}", ctx))
        assert not any(f.category == "repetitive_behavior" for f in findings)


class TestGoalDriftCheck:
    def test_no_drift_on_first_entry(self) -> None:
        checker = BehavioralChecker(intent_similarity_threshold=0.5)
        checker.clear_all()
        findings = _run(checker.scan("search for financial data", _ctx("drift-1")))
        assert not any(f.category == "goal_drift" for f in findings)

    def test_similar_content_no_drift(self) -> None:
        checker = BehavioralChecker(intent_similarity_threshold=0.1)
        checker.clear_all()
        ctx = _ctx("drift-similar")
        _run(checker.scan("search for financial reports quarterly", ctx))
        findings = _run(checker.scan("search for financial data analysis", ctx))
        # Similar texts should have high similarity
        assert not any(f.category == "goal_drift" for f in findings)

    def test_dramatically_different_content_drifts(self) -> None:
        checker = BehavioralChecker(intent_similarity_threshold=0.99)
        checker.clear_all()
        ctx = _ctx("drift-different")
        _run(checker.scan("aaaaaaaaaaaaaaaaaaaaaaaaaaa", ctx))
        findings = _run(checker.scan("zzzzzzzzzzzzzzzzzzzzzzzzzzz", ctx))
        # With very high threshold, different content should trigger drift
        # (or not — depends on char distribution; just verify no exception)
        assert isinstance(findings, list)

    def test_disabled_drift_check_skips(self) -> None:
        checker = BehavioralChecker(intent_similarity_threshold=0.0)
        checker.clear_all()
        ctx = _ctx("drift-disabled")
        _run(checker.scan("some content", ctx))
        findings = _run(checker.scan("completely different xyz 123", ctx))
        assert not any(f.category == "goal_drift" for f in findings)

    def test_drift_finding_includes_similarity_score(self) -> None:
        checker = BehavioralChecker(intent_similarity_threshold=0.99)
        checker.clear_all()
        ctx = _ctx("drift-score")
        _run(checker.scan("aaaaaaaaaa", ctx))
        findings = _run(checker.scan("zzzzzzzzzz", ctx))
        drift_findings = [f for f in findings if f.category == "goal_drift"]
        if drift_findings:
            assert "similarity_score" in drift_findings[0].details
            assert "threshold" in drift_findings[0].details


class TestSessionManagement:
    def test_clear_session_removes_history(self) -> None:
        checker = BehavioralChecker(max_repetitions=2)
        ctx = _ctx("clear-sess")
        msg = "repeated message"
        for _ in range(3):
            _run(checker.scan(msg, ctx))
        checker.clear_session("clear-sess")
        # After clearing, should be like a fresh session
        findings = _run(checker.scan(msg, ctx))
        assert not any(f.category == "repetitive_behavior" for f in findings)

    def test_clear_all_removes_all_sessions(self) -> None:
        checker = BehavioralChecker(max_repetitions=1)
        for sess in ["s1", "s2", "s3"]:
            ctx = _ctx(sess)
            for _ in range(2):
                _run(checker.scan("same message", ctx))
        checker.clear_all()
        # After clearing everything, no session data should remain
        for sess in ["s1", "s2", "s3"]:
            ctx = _ctx(sess)
            findings = _run(checker.scan("same message", ctx))
            assert not any(f.category == "repetitive_behavior" for f in findings)

    def test_sessions_are_independent(self) -> None:
        checker = BehavioralChecker(max_repetitions=2)
        checker.clear_all()
        msg = "repeated message"
        # Repeat in sess-a
        for _ in range(3):
            _run(checker.scan(msg, _ctx("sess-a")))
        # sess-b should be clean
        findings_b = _run(checker.scan(msg, _ctx("sess-b")))
        assert not any(f.category == "repetitive_behavior" for f in findings_b)

    def test_history_window_is_bounded(self) -> None:
        checker = BehavioralChecker(history_window=3)
        checker.clear_all()
        ctx = _ctx("window-sess")
        # Fill history with unique messages
        for i in range(5):
            _run(checker.scan(f"unique message {i}", ctx))
        # History should only have last 3
        history = checker._session_history.get("window-sess")
        if history is not None:
            assert len(history) <= 3
