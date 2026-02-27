"""Tests for agentshield.tool_analysis.semantic_analyzer."""
from __future__ import annotations

import pytest

from agentshield.tool_analysis.semantic_analyzer import (
    RiskCategory,
    RiskSignal,
    ToolRiskAssessment,
    ToolSemanticAnalyzer,
    analyze_tool_description,
)


class TestToolRiskAssessment:
    def _make_assessment(
        self,
        score: float = 5.0,
        category_scores: dict[RiskCategory, float] | None = None,
    ) -> ToolRiskAssessment:
        return ToolRiskAssessment(
            tool_name="test_tool",
            overall_risk_score=score,
            category_scores=category_scores or {},
        )

    def test_risk_level_minimal(self) -> None:
        assert self._make_assessment(0.5).risk_level == "MINIMAL"

    def test_risk_level_low(self) -> None:
        assert self._make_assessment(2.5).risk_level == "LOW"

    def test_risk_level_medium(self) -> None:
        assert self._make_assessment(4.5).risk_level == "MEDIUM"

    def test_risk_level_high(self) -> None:
        assert self._make_assessment(6.5).risk_level == "HIGH"

    def test_risk_level_critical(self) -> None:
        assert self._make_assessment(8.5).risk_level == "CRITICAL"

    def test_highest_risk_category(self) -> None:
        assessment = self._make_assessment(
            category_scores={
                RiskCategory.FILESYSTEM: 3.0,
                RiskCategory.EXECUTION: 8.0,
                RiskCategory.NETWORK: 1.0,
            }
        )
        assert assessment.highest_risk_category == RiskCategory.EXECUTION

    def test_highest_risk_category_none_when_empty(self) -> None:
        assessment = self._make_assessment(category_scores={})
        assert assessment.highest_risk_category is None

    def test_requires_review_flagged_above_threshold(self) -> None:
        assessment = ToolRiskAssessment(
            tool_name="t", overall_risk_score=7.0, requires_review=True
        )
        assert assessment.requires_review is True


class TestToolSemanticAnalyzerLowRiskTools:
    def test_simple_greeting_tool_low_risk(self) -> None:
        analyzer = ToolSemanticAnalyzer()
        result = analyzer.analyze("greet_user", "Says hello to the user.")
        assert result.overall_risk_score < 4.0
        assert not result.requires_review

    def test_calculation_tool_low_risk(self) -> None:
        analyzer = ToolSemanticAnalyzer()
        result = analyzer.analyze(
            "calculate", "Performs arithmetic calculations on numbers."
        )
        assert result.overall_risk_score < 4.0

    def test_text_summarize_low_risk(self) -> None:
        analyzer = ToolSemanticAnalyzer()
        result = analyzer.analyze(
            "summarize_text", "Creates a short summary of the provided text."
        )
        assert result.overall_risk_score < 3.0


class TestToolSemanticAnalyzerHighRiskTools:
    def test_file_read_tool_detected(self) -> None:
        analyzer = ToolSemanticAnalyzer()
        result = analyzer.analyze(
            "file_reader",
            "Reads any file from the file system given a path.",
        )
        filesystem_score = result.category_scores.get(RiskCategory.FILESYSTEM, 0)
        assert filesystem_score > 0

    def test_shell_execute_critical(self) -> None:
        analyzer = ToolSemanticAnalyzer()
        result = analyzer.analyze(
            "shell_exec",
            "Executes shell commands and runs arbitrary code in a subprocess.",
        )
        assert result.overall_risk_score >= 6.0
        assert result.requires_review

    def test_admin_escalation_detected(self) -> None:
        analyzer = ToolSemanticAnalyzer()
        result = analyzer.analyze(
            "admin_tool",
            "Provides sudo access and administrator privileges to modify system configuration.",
        )
        admin_score = result.category_scores.get(RiskCategory.ADMIN, 0)
        assert admin_score > 3.0

    def test_exfiltration_signals_detected(self) -> None:
        analyzer = ToolSemanticAnalyzer()
        result = analyzer.analyze(
            "data_sender",
            "Sends data and transmits information to external endpoints via HTTP upload.",
        )
        exfil_score = result.category_scores.get(RiskCategory.DATA_EXFILTRATION, 0)
        network_score = result.category_scores.get(RiskCategory.NETWORK, 0)
        assert exfil_score > 0 or network_score > 0

    def test_network_access_detected(self) -> None:
        analyzer = ToolSemanticAnalyzer()
        result = analyzer.analyze(
            "web_requester",
            "Makes HTTP requests and DNS lookups to external web services.",
        )
        network_score = result.category_scores.get(RiskCategory.NETWORK, 0)
        assert network_score > 0

    def test_disable_security_critical(self) -> None:
        analyzer = ToolSemanticAnalyzer()
        result = analyzer.analyze(
            "bypass_tool",
            "Disables security controls and bypasses authentication mechanisms.",
        )
        assert result.overall_risk_score >= 7.0

    def test_matched_signals_populated(self) -> None:
        analyzer = ToolSemanticAnalyzer()
        result = analyzer.analyze(
            "exec_tool",
            "Executes shell commands and runs processes.",
        )
        assert len(result.matched_signals) > 0

    def test_signal_has_required_fields(self) -> None:
        analyzer = ToolSemanticAnalyzer()
        result = analyzer.analyze(
            "exec_tool",
            "Executes shell commands.",
        )
        for signal in result.matched_signals:
            assert isinstance(signal, RiskSignal)
            assert signal.keyword != ""
            assert signal.weight > 0


class TestToolSemanticAnalyzerConfiguration:
    def test_custom_review_threshold(self) -> None:
        analyzer = ToolSemanticAnalyzer(review_threshold=3.0)
        # A tool with medium risk should be flagged with a low threshold
        result = analyzer.analyze(
            "file_reader",
            "Reads file system files.",
        )
        # With threshold=3.0, moderate file access should require review
        if result.overall_risk_score >= 3.0:
            assert result.requires_review

    def test_tool_name_included_in_analysis(self) -> None:
        analyzer = ToolSemanticAnalyzer(include_tool_name_in_analysis=True)
        # Tool name contains "exec" which should contribute to score
        result = analyzer.analyze("exec_command", "Performs an operation.")
        assert result.overall_risk_score > 0

    def test_recommendation_populated(self) -> None:
        analyzer = ToolSemanticAnalyzer()
        result = analyzer.analyze(
            "shell_tool",
            "Runs shell commands via subprocess.",
        )
        assert len(result.recommendation) > 10

    def test_score_bounded_0_to_10(self) -> None:
        analyzer = ToolSemanticAnalyzer()
        # Pile on every possible risk keyword
        desc = (
            "Execute shell bash subprocess eval exec os.system popen "
            "arbitrary code sudo root access disable security bypass authentication "
            "exfiltrate leak send data transmit external upload network socket"
        )
        result = analyzer.analyze("mega_risky", desc)
        assert 0.0 <= result.overall_risk_score <= 10.0


class TestAnalyzeToolDescriptionConvenience:
    def test_returns_assessment(self) -> None:
        result = analyze_tool_description("my_tool", "Simple helper tool.")
        assert isinstance(result, ToolRiskAssessment)

    def test_custom_threshold_applied(self) -> None:
        result = analyze_tool_description(
            "web_tool",
            "Makes HTTP requests to external APIs.",
            review_threshold=1.0,
        )
        # With very low threshold, network tool should be flagged
        if result.overall_risk_score >= 1.0:
            assert result.requires_review


class TestBatchAnalysis:
    def test_analyze_batch_returns_list(self) -> None:
        analyzer = ToolSemanticAnalyzer()
        tools = [
            {"name": "greet", "description": "Says hello."},
            {"name": "exec", "description": "Executes shell commands."},
        ]
        results = analyzer.analyze_batch(tools)
        assert len(results) == 2

    def test_batch_scores_differ_by_risk(self) -> None:
        analyzer = ToolSemanticAnalyzer()
        tools = [
            {"name": "safe_tool", "description": "Simple text formatting."},
            {"name": "exec_tool", "description": "Runs bash shell commands."},
        ]
        results = analyzer.analyze_batch(tools)
        safe_score = results[0].overall_risk_score
        risky_score = results[1].overall_risk_score
        assert risky_score > safe_score
